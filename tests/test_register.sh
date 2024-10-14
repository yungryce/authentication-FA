#!/usr/bin/env bash

# Base URL for the API
BASE_URL="http://localhost:7071/api"  # Adjust the port and host as needed

# Test data for registering a user
USERNAME="testuser"
PASSWORD="testP@ssword9"
EMAIL="testuser@example.com"
FIRST_NAME="Test"
LAST_NAME="User"

# Register a new user
echo "Registering a new user..."
curl -X POST "$BASE_URL/register" \
     -H "Content-Type: application/json" \
     -d '{
           "username": "testuser",
           "password": "testP@ssword9",
           "email": "testuser@example.com",
           "first_name": "Test",
           "last_name": "User"
         }'
sleep 3
echo -e "\n"

# Attempt to register the same user again (should fail)
echo "Attempting to register the same user again..."
curl -X POST "$BASE_URL/register" \
     -H "Content-Type: application/json" \
     -d '{
           "username": "'"$USERNAME"'",
           "password": "'"$PASSWORD"'",
           "email": "'"$EMAIL"'",
           "first_name": "'"$FIRST_NAME"'",
           "last_name": "'"$LAST_NAME"'"
         }'

echo -e "\n"

# Attempt to register user with an existing email
echo "Attempting to register a user with an existing email..."
curl -X POST "$BASE_URL/register" \
     -H "Content-Type: application/json" \
     -d '{
           "username": "anotheruser",
           "password": "'"$PASSWORD"'",
           "email": "'"$EMAIL"'",
           "first_name": "'"$FIRST_NAME"'",
           "last_name": "'"$LAST_NAME"'"
         }'

echo -e "\n"

# Register a user with missing fields (should fail)
echo "Attempting to register a user with missing fields..."
curl -X POST "$BASE_URL/register" \
     -H "Content-Type: application/json" \
     -d '{
           "username": "fakeuser",
           "password": "'"$PASSWORD"'",
           "email": "fake@example.com"
         }'

echo -e "\n"


# Register a user with invalid email (should fail)
echo "Attempting to register a user with invalid email..."
curl -X POST "$BASE_URL/register" \
     -H "Content-Type: application/json" \
     -d '{
           "username": "anotheruser",
           "password": "'"$PASSWORD"'",
           "email": "invalid-email-format",
           "first_name": "'"$FIRST_NAME"'",
           "last_name": "'"$LAST_NAME"'"
         }'

echo -e "\n"


# Register a user with invalid password format (should fail)
echo "Attempting to register a user with invalid email..."
curl -X POST "$BASE_URL/register" \
     -H "Content-Type: application/json" \
     -d '{
           "username": "anotheruser",
           "password": "anotherpassword",
           "email": "fake@example.com",
           "first_name": "'"$FIRST_NAME"'",
           "last_name": "'"$LAST_NAME"'"
         }'

echo -e "\n"


# curl -X POST "http://localhost:7071/api/register" \
#      -H "Content-Type: application/json" \
#      -d '{
#            "username": "testuser",
#            "password": "testP@ssword9",
#            "email": "testuser@example.com",
#            "first_name": "Test",
#            "last_name": "User"
#          }'