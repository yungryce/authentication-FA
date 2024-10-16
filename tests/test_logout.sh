#!/usr/bin/env bash

echo "Registering a new user..."
curl POST "http://localhost:7071/api/register" \
     -H "Content-Type: application/json" \
     -d '{
           "username": "testuser",
           "password": "testP@ssword9",
           "email": "testuser@example.com",
           "first_name": "Test",
           "last_name": "User "
         }'

sleep 3
echo -e "\n"

echo "Logging in with valid credentials..."
curl -v -X POST "http://localhost:7071/api/login" \
     -H "Content-Type: application/json" \
     -d '{
           "username": "testuser",
           "password": "testP@ssword9"
         }'

sleep 1
echo -e "\n"

token=$(echo "$login_response" | jq -r '.token')

echo "Logging out..."
curl -v POST "http://localhost:7071/api/logout" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $token" \
  -d '{
     "username": "testuser"
      }'

sleep 1
echo -e "\n"

echo "Trying to login again after logout..."
curl POST "http://localhost:7071/api/login" \
     -H "Content-Type: application/json" \
     -d '{
           "username": "testuser",
           "password": "testP@ssword9"
         }'

sleep 1
echo -e "\n"