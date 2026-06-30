#!/usr/bin/bash

# For running end to end tests locally

set -e

echo "Starting e2e tests..."

BUILD_TYPE="Release"
WORKSPACE_DIR="$(pwd)"
BUILD_DIR="${WORKSPACE_DIR}/build"

# If the user already exists this won't work
echo "=== Create Account ==="
RESPONSE=$(curl -s -f -X POST http://localhost:8080/auth/login -d 'username=alice&password=foobar')

AUTH_TOKEN=$(echo "$RESPONSE" | jq -r '.token')

echo "The token is: ${AUTH_TOKEN}"

echo "=== Login with invalid user ==="
! curl -s -f -X POST http://localhost:8080/auth/login -d 'username=alice&password=bazquux'
echo "Unable to login with bad username and password (this is good)"

# This won't work if the object already exists
echo "=== Upload object ==="
UPLOAD_RESPONSE=$(curl -s -f -X POST http://localhost:8080/objects \
-H "Authorization: Bearer ${AUTH_TOKEN}" \
-H 'X-Filename: hello.txt' \
-H 'X-Category: documents' \
-H 'X-Extension: txt' \
-d 'Hello, World!')

echo "=== List owned objects ==="
LIST_RESPONSE=$(curl -H "Authorization: Bearer ${AUTH_TOKEN}" \
-X GET "http://localhost:8080/objects")

echo "Owned objects: $LIST_RESPONSE"

EXPECTED_ID=$(echo "${UPLOAD_RESPONSE}" | jq -r '.id')

if ! echo "$LIST_RESPONSE" | jq --arg id "$EXPECTED_ID" '.objects[] | select(.id == $id)' | grep -q "$EXPECTED_ID"; then
    echo "Error: Uploaded object not found in owned objects."
    exit 1
fi

echo "=== Access object with good auth ==="
ID=$(echo "${UPLOAD_RESPONSE}" | jq -r '.id')
ACCESS_RESPONSE=$(curl -s -f -X GET "http://localhost:8080/objects/$ID" \
-H "Authorization: Bearer ${AUTH_TOKEN}")

echo "Accessed object: $ACCESS_RESPONSE"

if [[ "$ACCESS_RESPONSE" == "Hello, World!" ]]; then
    echo "Successfully accessed the object with good auth."
else
    echo "Error: Unable to access the object with good auth."
    exit 1
fi

echo "=== Access object with bad auth ==="
ID=$(echo "${UPLOAD_RESPONSE}" | jq -r '.id')
! curl -s -f -X GET "http://localhost:8080/objects/$ID"
echo "Unable to access object (this is good)."

echo "=== Log out ==="
curl -s -f -X POST http://localhost:8080/auth/logout \
-H "Authorization: Bearer ${AUTH_TOKEN}"

echo "=== Access file with expired token ==="
ID=$(echo "${UPLOAD_RESPONSE}" | jq -r '.id')
! curl -s -f -X GET "http://localhost:8080/objects/$ID" \
-H "Authorization: Bearer ${AUTH_TOKEN}"
echo "Unable to access object (this is good)."