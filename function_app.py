import os
import json
import logging
import base64
import datetime
import jwt
from guard import authenticate
from helper_functions import validate_json, user_exists, check_password, validate_password, table_service, is_valid_email, hash_password
import azure.functions as func
from queue_triggers import bp
from azure.storage.queue import QueueServiceClient


# Create the QueueServiceClient and Define the queue client for your specific queue
ACTION_QUEUE = "user-action-queue"
SECRET_KEY = os.getenv("SECRET_KEY")
USERS_TABLE = "Users"
connection_string = os.getenv("AzureWebJobsStorage")
queue_service_client = QueueServiceClient.from_connection_string(conn_str=connection_string)
user_client = table_service.get_table_client(table_name=USERS_TABLE)
# BLACKLIST = "Blacklist"
# blacklist_client = table_service.get_table_client(table_name=BLACKLIST)

# Initialize the function app
app = func.FunctionApp()
app.register_functions(bp) 

@app.function_name(name="register")
@app.route(route="register", methods=["POST"])
async def register(req: func.HttpRequest) -> func.HttpResponse:
    """
    Register a new user by sending data to the queue for processing.

    This function validates input JSON data for user registration,
    checks for existing users, and if validation passes,
    it sends the user data to the user registration queue.

    Args:
        req (func.HttpRequest): The incoming HTTP request containing user data.

    Returns:
        func.HttpResponse: A JSON response indicating the result of the operation.
                           - 202 Accepted if registration is in process.
                           - 409 Conflict if the username or email already exists.
                           - 400 Bad Request if validation fails.
                           - 500 Internal Server Error if sending to the queue fails.
    """
    logging.info("Registering a new user.")
    
    # Parse input data
    data = req.get_json()

    # Validate input JSON
    error = validate_json(data, 'username', 'email', 'password', 'first_name', 'last_name')
    if error:
        logging.warning("Validation error: %s", error)
        return func.HttpResponse(json.dumps(error), status_code=error[1])
    
    username = data['username']
    email = data['email']

    # Validate email format
    if not is_valid_email(email):
        logging.warning("Invalid email format: %s", email)
        return func.HttpResponse(
            json.dumps({"error": "Invalid email format"}),
            status_code=400
        )

    # Check if the user exists and prepare user data
    user_exists_result, partition_key, user_data = user_exists(username, email)
    if user_exists_result:
        logging.warning("User  already exists: %s", username)
        return func.HttpResponse(
            json.dumps({"error": "Username or Email already exists"}), 
            status_code=409
        )

    # Validate password
    if not validate_password(data['password']):
        logging.warning("Password does not meet requirements")
        return func.HttpResponse(
            json.dumps({"error": "Password does not meet requirements"}),
            status_code=400
        )
    # Prepare user_data with values from the request
    user_data = {
        'username': username,
        'email': email,
        'first_name': data['first_name'],
        'last_name': data['last_name'],
        'password': hash_password(data['password']),
        'action': 'signup'
    }
    
    # Send user data to the queue
    try:
        queue_client = queue_service_client.get_queue_client(ACTION_QUEUE)
        encoded_message = base64.b64encode(json.dumps(user_data).encode('utf-8')).decode('utf-8')
        queue_client.send_message(encoded_message)
        
        logging.info("User registration data sent to queue: %s", user_data)
        return func.HttpResponse(json.dumps({"message": "User registration successful"}), status_code=202)
    except Exception as e:
        logging.error("Failed to send message to the queue: %s", str(e))
        return func.HttpResponse(
            json.dumps({"error": "Failed to send message to the queue", "message": str(e)}),
            status_code=500
        )


# implement rate limiting for login function
@app.function_name(name="login")
@app.route(route="login", methods=["POST"])
async def login(req: func.HttpRequest) -> func.HttpResponse:
    """
    User login function for Azure Table Storage.

    This function validates the username and password provided in the login request.
    If valid, it generates a JWT token, sends a login success message to the login queue, 
    and returns the token in the Authorization header.
    If invalid, it returns an error message.

    Args:
        req (func.HttpRequest): The incoming HTTP request containing username and password.

    Returns:
        func.HttpResponse: A JSON response indicating the result of the login attempt.
                           - 200 OK if login is successful, with JWT token in the headers.
                           - 401 Unauthorized if the username or password is invalid.
                           - 400 Bad Request if validation fails.
    """
    logging.info("User login attempt.")
    
    try:
        # Parse input data
        data = req.get_json()

        # Validate input JSON
        error = validate_json(data, 'username', 'password')
        if error:
            logging.warning("Validation error: %s", error)
            return func.HttpResponse(json.dumps(error), status_code=error[1])
        
        username = data['username']
        password = data['password']
        
        # Check if the user exists and validate the password
        exists, partition_key, user_data = user_exists(username)

        if exists and check_password(username, password):
            logging.info("Login successful for user: %s", username)
            
            # Check if the user has an active token in the Blacklist table
            try:

                blacklist_client = table_service.get_table_client(table_name="Blacklist")
                active_tokens = blacklist_client.query_entities(
                    query_filter=f"PartitionKey eq '{username}' and active eq true".format(username)
                )
                active_token = next(active_tokens, None)
                if active_token:
                    logging.info(f"User  {username} has an active token: {active_token['RowKey']}")
                    token = active_token['RowKey']
                else:
                    # Generate a new JWT token
                    payload = {
                        'sub': username,  # Subject: the username
                        'iat': datetime.datetime.utcnow(),  # Issued at
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)  # Expiration time
                    }
                    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
                    logging.info(f"Generated JWT token for user: {username}")
            except Exception as e:
                logging.error(f"Error checking for active token: {str(e)}")
                return func.HttpResponse(
                    json.dumps({"error": "Internal server error", "message": str(e)}),
                    status_code=500
                )

            # Create a dictionary with the necessary data to pass to the queue
            queue_data = {
                'username': username,
                'active': True,
                'token': token,
                'action':  'login'
            }

            # Send the queue data to the login queue
            queue_client = queue_service_client.get_queue_client(ACTION_QUEUE)
            encoded_message = base64.b64encode(json.dumps(queue_data).encode('utf-8')).decode('utf-8')
            queue_client.send_message(encoded_message)

            # Include the token in the response headers
            headers = {
                'Authorization': f'Bearer {token}'  # Adding Authorization header
            }
            return func.HttpResponse(
                json.dumps({"message": "Login successful.", "user_data": user_data}),
                status_code=200,
                headers=headers  # Include the headers
            )
        else:
            logging.warning("Invalid login attempt for user: %s", username)
            return func.HttpResponse(json.dumps({"error": "Invalid username or password."}), status_code=401)
    except Exception as e:
        logging.error(f"Exception during login for user '{username}': {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": "Internal server error", "message": str(e)}),
            status_code=500
        )
    

@app.function_name(name="logout")
@app.route(route="logout", methods=["POST"])
@authenticate
async def logout(req: func.HttpRequest) -> func.HttpResponse:
    """
    User logout function for Azure Table Storage.

    This function receives a token, and sends the logout data to a queue for processing.

    Args:
        req (func.HttpRequest): The incoming HTTP request containing the token.

    Returns:
        func.HttpResponse: A JSON response indicating the result of the logout attempt.
                           - 200 OK if logout is successful.
                           - 400 Bad Request if validation fails.
    """
    try:

        # Fetch authenticated data from the request
        current_user = req.user
        token = req.token
        username = current_user['username']

        # Prepare data to send to the logout queue
        logout_data = {
            'username': username,
            'token': token,
            'action': 'logout',
            'active':  False
        }

        # Send the logout data to the logout queue
        queue_client = queue_service_client.get_queue_client(ACTION_QUEUE)  # Define your logout queue name
        encoded_message = base64.b64encode(json.dumps(logout_data).encode('utf-8')).decode('utf-8')
        queue_client.send_message(encoded_message)

        return func.HttpResponse(json.dumps({"message": "Logout successful."}), status_code=200)
    except Exception as e:
        logging.error(f"Exception during logout: {str(e)}")
        return func.HttpResponse(json.dumps({"error": "Internal server error", "message": str(e)}), status_code=500)


@app.function_name(name="get_user")
@app.route(route="get_user/{username}", methods=["GET"])
async def get_user(req: func.HttpRequest) -> func.HttpResponse:
    """
    Retrieve user data if the user exists in the table.

    This function checks if the specified user exists in the Azure Table Storage.
    If the user is found, it returns the user's data along with the PartitionKey.
    If not, it returns a message indicating that the user was not found.

    Args:
        req (func.HttpRequest): The incoming HTTP request containing the username.

    Returns:
        func.HttpResponse: A JSON response with user data or a message indicating
                           the user was not found.
                           - 200 OK with user data if found.
                           - 404 Not Found if the user does not exist.
    """
    
    username = req.route_params.get("username")
    logging.info("Fetching user data for username: %s", username)
    
    # Check if the user exists and fetch user data
    exists, partition_key, user_data = user_exists(username)

    if exists and not user_data.get('is_deleted'):
        logging.info("User found: %s", username)
        # Return the user data along with the PartitionKey
        response = {
            "exists": True,
            "partition_key": partition_key,
            "user_data": user_data
        }
        return func.HttpResponse(json.dumps(response), status_code=200)
    else:
        logging.warning("User not found or deleted: %s", username)
        # Return a message indicating the user was not found or deleted
        response = {"exists": False, "message": "User not found or deleted"}
        return func.HttpResponse(json.dumps(response), status_code=404)
    

@app.function_name(name="get_all_users")
@app.route(route="users", methods=["GET"])
async def get_all_users(req: func.HttpRequest) -> func.HttpResponse:
    """
    Get all users stored in the Azure Table Storage.

    This function retrieves all user entities from the 'Users' table 
    and returns them as a JSON response.

    Args:
        req (func.HttpRequest): The incoming HTTP GET request.

    Returns:
        func.HttpResponse: A JSON response containing all users' data.
                           - 200 OK if users are successfully retrieved.
                           - 500 Internal Server Error if an error occurs.
    """
    logging.info("Retrieving all users.")

    try:
        # Query all entities in the 'Users' table
        users = []
        entities = user_client.list_entities()
        
        # Iterate through each entity and append to the list
        for entity in entities:
            if entity.get('is_deleted'):
                continue
            
            user_data = {
                'username': entity['RowKey'],  # Assuming RowKey is username
                'email': entity['email'],
                'first_name': entity['first_name'],
                'last_name': entity['last_name']
                # Add more fields as needed, but avoid returning sensitive data like passwords
            }
            users.append(user_data)

        logging.info(f"Total users retrieved: {len(users)}")
        
        # Return the list of users as a JSON response
        return func.HttpResponse(
            json.dumps({"users": users}),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error retrieving users: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": "Failed to retrieve users", "message": str(e)}),
            status_code=500
        )


@app.function_name(name="delete_user")
@app.route(route="delete_user/{username}", methods=["DELETE"])
async def delete_user(req: func.HttpRequest) -> func.HttpResponse:
    """
    Mark a user as deleted in the Azure Table Storage.

    This function checks if the specified user exists in the Azure Table Storage.
    If the user is found, it updates the user's data to mark them as deleted and returns a success message.
    If not, it returns a message indicating that the user was not found.

    Args:
        req (func.HttpRequest): The incoming HTTP request containing the username.

    Returns:
        func.HttpResponse: A JSON response indicating the result of the deletion attempt.
                           - 200 OK if the user was successfully marked as deleted.
                           - 404 Not Found if the user does not exist.
                           - 500 Internal Server Error if an error occurs during deletion.
    """
    
    username = req.route_params.get("username")
    logging.info("Attempting to delete user: %s", username)
    
    # Check if the user exists
    exists, partition_key, user_data = user_exists(username)

    if exists:
        try:
            # Update the user's data to mark them as deleted
            user_data['is_deleted'] = True
            user_client.update_entity(partition_key=partition_key, row_key=username, entity={'is_deleted': user_data['is_deleted']})
            logging.info("User   marked as deleted successfully: %s", username)
            return func.HttpResponse(json.dumps({"message": "User   marked as deleted successfully."}), status_code=200)
        except Exception as e:
            logging.error(f"Error marking user '{username}' as deleted: {str(e)}")
            return func.HttpResponse(
                json.dumps({"error": "Failed to mark user as deleted", "message": str(e)}),
                status_code=500
            )
    else:
        logging.warning("User not found for deletion: %s", username)
        return func.HttpResponse(json.dumps({"error": "User   not found."}), status_code=404)
