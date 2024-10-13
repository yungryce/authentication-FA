import os
import json
import logging
import base64
import datetime
import jwt
from helper_functions import validate_json, user_exists, check_password, validate_password
import azure.functions as func
from queue_triggers import bp
from azure.storage.queue import QueueServiceClient


# Create the QueueServiceClient and Define the queue client for your specific queue
ACTION_QUEUE = "user-action-queue"
SECRET_KEY = os.getenv("SECRET_KEY")
connection_string = os.getenv("AzureWebJobsStorage")
queue_service_client = QueueServiceClient.from_connection_string(conn_str=connection_string)

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

    # Check if the user exists and prepare user data
    user_exists_result, partition_key, user_data = user_exists(username)


    if validate_password(data['password']) == False:
        logging.warning("Password does not meet requirements")
        return func.HttpResponse(
            json.dumps({"error": "Password does not meet requirements"}),
            status_code=400
        )
    elif user_exists_result:
        logging.warning("User already exists: %s", username)
        return func.HttpResponse(
            json.dumps({"error": "Username or Email already exists"}), 
            status_code=409
        )
    else:
        # Prepare user_data with values from the request
        user_data = {}
        user_data['username'] = username
        user_data['email'] = data['email']
        user_data['first_name'] = data['first_name']
        user_data['last_name'] = data['last_name']
        user_data['password'] = data['password']
        user_data['action'] = 'signup'
    
    
    # Send user data to the queue
    try:
        # Send the login message to the queue
        queue_client = queue_service_client.get_queue_client(ACTION_QUEUE)
        
       # Convert user_data to JSON string before encoding
        encoded_message = base64.b64encode(json.dumps(user_data).encode('utf-8')).decode('utf-8')
        
        # Send message to the queue without awaiting
        queue_client.send_message(encoded_message)
        
        logging.info("User registration data sent to queue: %s", user_data)
        return func.HttpResponse(json.dumps({"message": "User registration successful"}), status_code=202)
    except Exception as e:
        logging.error("Failed to send message to the queue: %s", str(e))
        return func.HttpResponse(
            json.dumps({"error": "Failed to send message to the queue", "message": str(e)}),
            status_code=500
        )


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

    if exists:
        logging.info("User found: %s", username)
        # Return the user data along with the PartitionKey
        response = {
            "exists": True,
            "partition_key": partition_key,
            "user_data": user_data
        }
        return func.HttpResponse(json.dumps(response), status_code=200)
    else:
        logging.warning("User not found: %s", username)
        # Return a message indicating the user was not found
        response = {"exists": False, "message": "User not found"}
        return func.HttpResponse(json.dumps(response), status_code=404)
    

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
        logging.debug(f"Login request data: {data}")

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
            
            user_data['action'] = 'login'
            user_data['timestamp'] = datetime.datetime.now().isoformat()
            user_data['status'] = "success" if exists and check_password(username, password) else "failure"
            
            # Generate JWT token
            payload = {
                'sub': username,  # Subject: the username
                'iat': datetime.datetime.utcnow(),  # Issued at
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Expiration time
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
            logging.info(f"Generated JWT token for user: {username}")

            # Send the login message to the queue
            queue_client = queue_service_client.get_queue_client(ACTION_QUEUE)
            
        # Convert user_data to JSON string before encoding
            encoded_message = base64.b64encode(json.dumps(user_data).encode('utf-8')).decode('utf-8')
            
            # Send message to the queue without awaiting
            queue_client.send_message(encoded_message)
            logging.info(f"Sent login data to the queue for user: {username}")
            
            # Include the token in the response headers
            headers = {
                'Authorization': f'Bearer {token}'  # Adding Authorization header
            }
            
            return func.HttpResponse(
                json.dumps({"message": "Login successful."}),
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