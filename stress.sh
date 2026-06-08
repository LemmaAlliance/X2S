#!/usr/bin/env bash
set -euo pipefail

BASE_URL="http://localhost:8080"
USERNAME="stress_user_$(date +%s)"
PASSWORD="secret123"
CONCURRENCY=10
REQUESTS_PER_WORKER=50

echo "[1/5] Registering user..."
curl -s -X POST "$BASE_URL/auth/register" \
  -d "username=$USERNAME&password=$PASSWORD" >/dev/null || true

echo "[2/5] Logging in..."
TOKEN=$(curl -s -X POST "$BASE_URL/auth/login" \
  -d "username=$USERNAME&password=$PASSWORD" | jq -r '.token')

if [[ "$TOKEN" == "null" || -z "$TOKEN" ]]; then
  echo "Failed to obtain token"
  exit 1
fi

echo "Token acquired: ${TOKEN:0:10}..."

upload_download_cycle() {
  for i in $(seq 1 "$REQUESTS_PER_WORKER"); do
    CONTENT="hello-from-$RANDOM-$i"

    # Upload
    RESP=$(curl -s -X PUT "$BASE_URL/objects" \
      -H "Authorization: Bearer $TOKEN" \
      -H "X-Filename: stress_$i.txt" \
      -d "$CONTENT")

    ID=$(echo "$RESP" | jq -r '.id')

    if [[ "$ID" == "null" || -z "$ID" ]]; then
      echo "[ERROR] upload failed"
      continue
    fi

    # Download
    curl -s -H "Authorization: Bearer $TOKEN" \
      "$BASE_URL/objects/$ID" >/dev/null

    # Delete
    curl -s -X DELETE \
      -H "Authorization: Bearer $TOKEN" \
      "$BASE_URL/objects/$ID" >/dev/null

    echo "[worker $$] cycle $i done"
  done
}

echo "[3/5] Starting stress test: ${CONCURRENCY} workers × ${REQUESTS_PER_WORKER} cycles"

for _ in $(seq 1 "$CONCURRENCY"); do
  upload_download_cycle &
done

wait

echo "[4/5] Done"

echo "[5/5] Test complete"