# queue_trigger.py

import json
import logging
import azure.functions as func
from helper_functions import table_client


# Create a blueprint for queue triggers
bp = func.Blueprint() 
        
@bp.function_name(name="process_user_action")
@bp.queue_trigger(arg_name="msg", queue_name="user-action-queue", connection="AzureWebJobsStorage")
async def process_user_action(msg: func.QueueMessage) -> None:
    """Process user actions from the queue (register, login, etc.)."""
    user_data = json.loads(msg.get_body().decode())

    action = user_data.get('action')

    if action == 'signup':
        await process_user_registration(user_data)
    elif action == 'login':
        await process_user_login(user_data)
    else:
        logging.warning(f"Unknown action: {action}")


async def process_user_registration(user_data):
    """Process user registration from the queue and store in Azure Table Storage."""

    new_user = {
        'PartitionKey': 'Users',
        'RowKey': user_data['username'],  # Using username as RowKey
        'email': user_data['email'],
        'password': user_data['password'],  # Store hashed password in production
        'first_name': user_data['first_name'],
        'last_name': user_data['last_name'],
    }
        
    try:
        await table_client.create_entity(entity=new_user)
        logging.info(f"User {user_data['username']} registered successfully.")
    except Exception as e:
        logging.error(f"Failed to register user {user_data['username']}: {str(e)}")

        

async def process_user_login(user_data):
    """Process user login from the queue."""

    username = user_data['username']
    status = user_data['status']
    timestamp = user_data['timestamp']

    # Here, you can log the login attempts, update user stats, etc.
    logging.info(f"User {username} attempted to login at {timestamp} with status: {status}")
