import pytest
from ..function_app import register,  login, logout, get_user_data, get_user_friends, get_user_friends_count, get_user_posts


def test_register_valid(mocker):
    mock_table_client = mocker.patch('helper_functions.table_client')
    mock_table_client.insert_entity.return_value = True  # Simulate successful registration

    data = {
        "username": "testuser",
        "password": "testpass",
        "email": "testuser@example.com",
        "first_name": "Test",
        "last_name": "User"
    }
    assert register(data) is True

def test_register_invalid(mocker):
    mock_table_client = mocker.patch('helper_functions.table_client')
    mock_table_client.insert_entity.side_effect = Exception("Registration failed")  # Simulate registration failure

    data = {
        "username": "testuser",
        "password": "testpass",
        "email": "testuser@example.com",
        "first_name": "Test",
        "last_name": "User"
    }
    assert register(data) is False

def test_register_existing_user(mocker):
    mock_table_client = mocker.patch('helper_functions.table_client')
    mock_table_client.insert_entity.side_effect = Exception("User already exists")  # Simulate existing user

    data = {
        "username": "testuser",
        "password": "testpass",
        "email": "testuser@example.com",
        "first_name": "Test",
        "last_name": "User"
    }
    assert register(data) is False