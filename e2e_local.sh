#!/usr/bin/bash

# For running end to end tests locally

set -e

echo "Starting e2e tests..."

BUILD_TYPE="Release"
WORKSPACE_DIR="$(pwd)"
BUILD_DIR="${WORKSPACE_DIR}/build"

# If the user already exists this won't work
echo "=== Create Account ==="
RESPONSE=$(curl -s -f -X POST http://localhost:8080/auth/register -d 'username=alice&password=foobar')

AUTH_TOKEN=$(echo "$RESPONSE" | jq -r '.token')
REFRESH_TOKEN=$(echo "$RESPONSE" | jq -r '.refresh_token')

echo "The token is: ${AUTH_TOKEN:0:20}..."
echo "The refresh token is: ${REFRESH_TOKEN:0:20}..."

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
-H 'X-Metadata-Author: Alice' \
-H 'X-Metadata-Version: 2' \
-d 'Hello, World!')

echo "Uploaded object: $UPLOAD_RESPONSE"

echo "=== List owned objects ==="
LIST_RESPONSE=$(curl -H "Authorization: Bearer ${AUTH_TOKEN}" \
-X GET "http://localhost:8080/objects")

echo "Owned objects: $LIST_RESPONSE"

EXPECTED_ID=$(echo "${UPLOAD_RESPONSE}" | jq -r '.id')

if ! echo "$LIST_RESPONSE" | jq --arg id "$EXPECTED_ID" '.objects[] | select(.id == $id)' | grep -q "$EXPECTED_ID"; then
    echo "Error: Uploaded object not found in owned objects."
    exit 1
fi

echo "=== Verify metadata in list response ==="
META_AUTHOR=$(echo "$LIST_RESPONSE" | jq -r --arg id "$EXPECTED_ID" '.objects[] | select(.id == $id) | .metadata.Author')
if [ "$META_AUTHOR" != "Alice" ]; then
    echo "Error: Expected metadata Author=Alice, got '$META_AUTHOR'"
    exit 1
fi

META_VERSION=$(echo "$LIST_RESPONSE" | jq -r --arg id "$EXPECTED_ID" '.objects[] | select(.id == $id) | .metadata.Version')
if [ "$META_VERSION" != "2" ]; then
    echo "Error: Expected metadata Version=2, got '$META_VERSION'"
    exit 1
fi

echo "=== Filter by metadata_key ==="
FILTER_RESPONSE=$(curl -H "Authorization: Bearer ${AUTH_TOKEN}" \
-X GET "http://localhost:8080/objects?metadata_key=Author&metadata_value=Alice")
if ! echo "$FILTER_RESPONSE" | jq --arg id "$EXPECTED_ID" '.objects[] | select(.id == $id)' | grep -q "$EXPECTED_ID"; then
    echo "Error: Filter by metadata_key=Author did not find the object."
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

echo "=== Refresh token ==="
REFRESH_RESPONSE=$(curl -s -f -X POST http://localhost:8080/auth/refresh \
-d "refresh_token=${REFRESH_TOKEN}")
NEW_AUTH_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.token')
NEW_REFRESH_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.refresh_token')
echo "Token refreshed."

echo "=== Access object with refreshed token ==="
ID=$(echo "${UPLOAD_RESPONSE}" | jq -r '.id')
curl -s -f -X GET "http://localhost:8080/objects/$ID" \
-H "Authorization: Bearer ${NEW_AUTH_TOKEN}"
echo "Accessed object with refreshed token."

echo "=== Old refresh token is invalid after rotation ==="
! curl -s -f -X POST http://localhost:8080/auth/refresh \
-d "refresh_token=${REFRESH_TOKEN}"
echo "Old refresh token rejected (this is good)."