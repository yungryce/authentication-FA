import os
import hashlib
import re
import logging
from azure.data.tables import TableServiceClient

# Use AzureWebJobsStorage connection string from environment variables
connection_string = os.getenv("AzureWebJobsStorage")
USERS_TABLE = "Users"
# QUEUE_NAME = "user-registration-queue"

# Connect to the Azure Table Storage
table_service = TableServiceClient.from_connection_string(conn_str=connection_string)
user_table_client = table_service.get_table_client(table_name=USERS_TABLE)

def validate_json(data, *fields):
    """Validate if required fields are present in the request JSON."""
    for field in fields:
        if field not in data:
            return {"error": f"Missing field {field}"}, 400
    return None

def hash_password(password):
    """Hash the password using SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()

def is_valid_email(email):
    """Validate the email format using a regular expression."""
    email_regex = r'^[a-zA-Z0-9_.+-]{3,}@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None

def user_exists(username: str, email: str = None):
    """
    Check if a user exists in the 'Users' table by their username (RowKey) and email.
    If the user exists, fetch and return the PartitionKey along with the user data.

    Args:
        username (str): The username of the user to check.
        email (str): The email of the user to check. (optional)

    Returns:
        tuple: (True, PartitionKey, user_data) if the user exists, 
               (False, None, None) otherwise.
    """

    try:
        # Query the Users table for the specified username and email
        if email:
            query_filter = f"RowKey eq '{username}' or email eq '{email}'"
        else:
            query_filter = f"RowKey eq '{username}'"
        user_entities = user_table_client.query_entities(query_filter)

        # If the user exists, prepare user data and return
        for user_entity in user_entities:
            if user_entity['is_deleted']:
                return False, None, None
            user_data = {
                'username': user_entity['RowKey'],  # assuming RowKey is username
                'email': user_entity['email'],
                'first_name': user_entity['first_name'],
                'last_name': user_entity['last_name'],
                # Password should not be returned for security reasons
            }
            return True, user_entity['PartitionKey'], user_data

        # If no user is found, return False and None
        return False, None, None

    except Exception as e:
        # For any exception, raise it
        raise e
        
        
def check_password(username: str, user_input_password: str):
    """
    Check if the provided password matches the stored password hash
    for the specified user.

    Args:
        username (str): The username to query in the storage.
        user_input_password (str): The plain text password provided by the user.

    Returns:
        bool: True if the passwords match, False otherwise.
    """
    try:
        # Query the Users table for the specified username
        query_filter = f"RowKey eq '{username}'"
        user_entities = user_table_client.query_entities(query_filter)

        # Fetch the first matching user entity
        user_entity = next(user_entities, None)

        if user_entity:
            # Fetch the stored password hash from the user entity and Compare the stored hash with the hash of the user input password
            stored_password_hash = user_entity['password']  # Assuming the hashed password is stored as 'password'
            return stored_password_hash == hash_password(user_input_password)

    except Exception as e:
        # Handle exceptions (e.g., user not found)
        if "ResourceNotFound" in str(e):
            return False  # User does not exist
        else:
            # For any other exception, raise it
            raise e


def validate_password(password: str) -> bool:
    """
    Validate the strength of a password based on defined criteria.

    Args:
        password (str): The password to validate.

    Returns:
        bool: True if the password is strong, False otherwise.
    """
    # Check password length
    if len(password) < 8:
        return False

    # Check for uppercase letters
    if not re.search(r'[A-Z]', password):
        return False

    # Check for lowercase letters
    if not re.search(r'[a-z]', password):
        return False

    # Check for digits
    if not re.search(r'[0-9]', password):
        return False

    # Check for special characters
    if not re.search(r'[@$!%*?&]', password):
        return False

    # Optionally check against a list of common passwords
    common_passwords = [
        "password", "123456", "12345678", "qwerty", "abc123", 
        "letmein", "welcome", "admin", "user", "passw0rd"
    ]
    if password in common_passwords:
        return False

    return True

