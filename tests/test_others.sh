curl -X POST "http://localhost:7071/api/verify_email" \
-H "Content-Type: application/json" \
-d '{
    "email_token": "your-email-token-here"
}'
