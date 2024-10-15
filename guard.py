from functools import wraps
from helper_functions import BlacklistToken, SECRET_KEY, table_service
from azure.core.exceptions import ResourceNotFoundError
import json
import jwt


def authenticate(func):
    @wraps(func)
    def wrapper(req, *args, **kwargs):
        """
        Authenticate the user by verifying the JWT token in the request headers.
        If the token is valid, it will be added to the blacklist to prevent replay attacks.
        """

        if "Authorization" in req.headers:
            token = req.headers["Authorization"].split(" ")[1]

            try:
                # Decode and verify token before using it
                payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
                username = payload.get('sub')

                # Check if token is blacklisted in the Blacklist table
                try:
                    blacklist_client = table_service.get_table_client(table_name="Blacklist")
                    blacklist_entity = blacklist_client.get_entity(partition_key=username, row_key=token)
                    if blacklist_entity['active'] == False:
                        return func.HttpResponse(
                            json.dumps({'error': 'Token is blacklisted'}),
                            status_code=401
                        )
                except ResourceNotFoundError:
                    pass

            except jwt.ExpiredSignatureError:
                return func.HttpResponse(
                    json.dumps({'error': 'Token has expired'}),
                    status_code=401
                )
            except jwt.InvalidTokenError:
                return func.HttpResponse(
                    json.dumps({'error': 'Invalid token'}),
                    status_code=401
                )
        else:
            return func.HttpResponse(
                json.dumps({'error': 'Token is missing or invalid'}),
                status_code=401
            )
        
        try:
            # Fetch user from database using username
            user_client = table_service.get_table_client(table_name="Users")
            user_entity = user_client.get_entity(partition_key=username, row_key=username)
            try:
                # Check if the account is deleted
                if user_entity.get('is_deleted', False):
                    return func.HttpResponse(
                        json.dumps({'error': 'User account is deleted'}),
                        status_code=401
                    )
                user_data = {
                    'username': user_entity['RowKey'],
                    'email': user_entity['email'],
                    'first_name': user_entity['first_name'],
                    'last_name': user_entity['last_name']
                }
            except ResourceNotFoundError:
                return func.HttpResponse(
                    json.dumps({'error': 'User not found'}),
                    status_code=404
                )

            # Attach user object to request for later use
            req.user = user_data
            req.token = token
            
        except Exception as e:
            return func.HttpResponse(
                json.dumps({'error': 'An error occurred', 'message': str(e)}),
                status_code=500
            )

        # Call the original function with any provided arguments
        return func(req, *args, **kwargs)

    return wrapper
