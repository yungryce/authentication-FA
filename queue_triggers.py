# queue_trigger.py

import json
import logging
import datetime
import uuid
import azure.functions as func
from helper_functions import table_service
from azure.core.exceptions import ResourceNotFoundError


# Create a blueprint for queue triggers
bp = func.Blueprint() 

USERS_TABLE = "Users"
BLACKLIST = "Blacklist"
user_client = table_service.get_table_client(table_name=USERS_TABLE)
blacklist_client = table_service.get_table_client(table_name=BLACKLIST)

@bp.function_name(name="process_user_action")
@bp.queue_trigger(arg_name="msg", queue_name="user-action-queue", connection="AzureWebJobsStorage")
async def process_user_action(msg: func.QueueMessage) -> None:
    """Process user actions from the queue (register, login, etc.)."""
    message = json.loads(msg.get_body().decode())

    action = message.get('action')

    if action == 'signup':
        await process_user_registration(message)
    elif action == 'login':
        await process_user_login(message)
    elif  action == 'logout':
        await process_user_logout(message)
    else:
        logging.warning(f"Unknown action: {action}")


async def process_user_registration(message):
    """Process user registration from the queue and store in Azure Table Storage."""

    new_user = {
        "PartitionKey": message['username'],
        'RowKey': message['username'],  # Using username as RowKey
        'email': message['email'],
        'password': message['password'],  # Store hashed password in production
        'first_name': message['first_name'],
        'last_name': message['last_name'],
        'is_deleted': False
    }
        
    try:
        user_client.create_entity(entity=new_user)
        logging.info(f"User {message['username']} registered successfully.")
    except Exception as e:
        logging.error(f"Failed to register user {message['username']}: {str(e)}")

        

async def process_user_login(message):
    """Process user login from the queue."""

    blacklist_entity = {
        "PartitionKey": message['username'],
        'RowKey': message['token'],
        'expires_in': datetime.datetime.utcnow() + datetime.timedelta(days=1),
        'active': message['active']
    }

    try:
        # Check if the token exists in the blacklist table
        try:
            existing_entity = blacklist_client.get_entity(
                partition_key=blacklist_entity['PartitionKey'], 
                row_key=blacklist_entity['RowKey']
            )
            logging.info(f"Found existing entity for user {blacklist_entity['PartitionKey']}")

            if existing_entity['active'] != blacklist_entity['active']:
                # Update the 'active' field with the new value
                existing_entity['active'] = blacklist_entity['active']
                blacklist_client.update_entity(entity=existing_entity)
                logging.info(f"Updated active status for user {blacklist_entity['PartitionKey']}")
            else:
                logging.info(f"User {blacklist_entity['PartitionKey']} is already logged in.")

        except ResourceNotFoundError:
            # If the entity is not found, create it
            blacklist_client.create_entity(entity=blacklist_entity)
            logging.info(f"Created new entity for user {blacklist_entity['PartitionKey']}")

    except Exception as e:
        logging.error(f"Failed to login user {message['username']}: {str(e)}")


async def process_user_logout(message):
    """Process user logout from the HTTP request."""

    blacklist_entity = {
        "PartitionKey": message['username'],
        'RowKey': message['token'],
        'active': message['active']
    }

    try:
        # Check if token exists in the blacklist table
        existing_entity = blacklist_client.get_entity(
            partition_key=blacklist_entity['PartitionKey'],
            row_key=blacklist_entity['RowKey']
        )
        logging.warning(f"exist|: {existing_entity['RowKey']}, {existing_entity['PartitionKey']}, {existing_entity['active']}")
        if existing_entity['RowKey'] == blacklist_entity['RowKey']:
            # Update the 'active' field with the returned value
            existing_entity['active'] = blacklist_entity['active']
            blacklist_client.update_entity(entity=existing_entity)
            logging.info(f"User {message['token']} logged out successfully.")
        else:
            logging.warning(f"Token mismatch for user {message['token']}.")
    except Exception as e:
        logging.error(f"Failed to logout user {message['token']}: {str(e)}")


