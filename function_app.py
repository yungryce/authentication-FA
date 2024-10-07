import os
import hashlib
import json
import azure.functions as func
from azure.data.tables import TableServiceClient

# Use AzureWebJobsStorage connection string from environment variables
connection_string = os.getenv("AzureWebJobsStorage")
TABLE_NAME = "Users"

# Connect to the Azure Table Storage
table_service = TableServiceClient.from_connection_string(conn_str=connection_string)
table_client = table_service.get_table_client(table_name=TABLE_NAME)

# Initialize the function app
app = func.FunctionApp()

def validate_json(data, *fields):
    """Validate if required fields are present in the request JSON."""
    for field in fields:
        if field not in data:
            return {"error": f"Missing field {field}"}, 400
    return None

def hash_password(password):
    """Hash the password using SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()

@app.function_name(name="register")
@app.route(route="register", methods=["POST"])
async def register(req: func.HttpRequest) -> func.HttpResponse:
    """
    Register a new user in Azure Table Storage.

    Returns:
        JSON response with the created user, or error response if validation fails.
    """
    # Parse input data
    data = req.get_json()

    # Validate input JSON
    error = validate_json(data, 'username', 'email', 'password', 'first_name', 'last_name')
    if error:
        return func.HttpResponse(json.dumps(error), status_code=error[1])
    
    username = data['username']
    email = data['email']
    password = hash_password(data['password'])
    first_name = data['first_name']
    last_name = data['last_name']

    # Check if the username or email already exists in Azure Table Storage
    existing_user = None
    try:
        existing_user = table_client.query_entities(
            filter=f"PartitionKey eq 'Users' and (RowKey eq '{username}' or email eq '{email}')"
        )
    except Exception as e:
        return func.HttpResponse(
            json.dumps({"error": "Error querying the database", "message": str(e)}), 
            status_code=500
        )

    if any(existing_user):  # Check if the query returned any results
        return func.HttpResponse(
            json.dumps({"error": "Username or Email already exists"}), 
            status_code=409
        )

    # Proceed to create a new user since neither the username nor email are taken
    new_user = {
        'PartitionKey': 'Users',  # Group all users by PartitionKey
        'RowKey': username,       # Use username as the RowKey
        'email': email,
        'password': password,
        'first_name': first_name,
        'last_name': last_name
    }

    # Save the new user to Azure Table Storage
    try:
        await table_client.create_entity(entity=new_user)  # Using await for async operation
        return func.HttpResponse(json.dumps({"message": "User registered successfully"}), status_code=201)
    except Exception as e:
        return func.HttpResponse(
            json.dumps({"error": "Failed to register user", "message": str(e)}), 
            status_code=500
        )
