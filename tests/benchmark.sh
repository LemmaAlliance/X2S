#!/usr/bin/bash
# Performance benchmark script for X2S
# Measures request throughput, upload/download speeds, and memory usage

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <auth_token>"
    exit 1
fi

AUTH_TOKEN="$1"
BASE_URL="http://localhost:8080"
RESULTS_FILE="benchmark-results.txt"

echo "=== X2S Performance Benchmarks ===" | tee "$RESULTS_FILE"
echo "Date: $(date)" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Helper function to measure time
measure_time() {
    local description="$1"
    local iterations="$2"
    shift 2
    
    local start=$(date +%s.%N)
    
    for ((i=1; i<=$iterations; i++)); do
        "$@" > /dev/null 2>&1
    done
    
    local end=$(date +%s.%N)
    local duration=$(echo "$end - $start" | bc)
    local avg=$(echo "scale=4; $duration / $iterations" | bc)
    local rps=$(echo "scale=2; $iterations / $duration" | bc)
    
    echo "$description:" | tee -a "$RESULTS_FILE"
    echo "  Total: ${duration}s for $iterations requests" | tee -a "$RESULTS_FILE"
    echo "  Average: ${avg}s per request" | tee -a "$RESULTS_FILE"
    echo "  Throughput: ${rps} requests/second" | tee -a "$RESULTS_FILE"
    echo "" | tee -a "$RESULTS_FILE"
}

# 1. Authentication throughput
echo "## 1. Authentication Performance" | tee -a "$RESULTS_FILE"
measure_time "Login requests" 50 curl -s -X POST "$BASE_URL/auth/login" -d "username=bench_user&password=benchpass123"

# 2. Small file upload (100 bytes)
echo "## 2. Small File Upload (100 bytes)" | tee -a "$RESULTS_FILE"
SMALL_DATA=$(head -c 100 /dev/urandom | base64)
measure_time "Upload 100-byte files" 20 curl -s -X POST "$BASE_URL/objects" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "X-Filename: bench_small.bin" \
    -H "X-Category: benchmark" \
    -H "X-Extension: bin" \
    -d "$SMALL_DATA"

# 3. Medium file upload (10 KB)
echo "## 3. Medium File Upload (10 KB)" | tee -a "$RESULTS_FILE"
MEDIUM_DATA=$(head -c 10240 /dev/urandom | base64)
UPLOAD_RESPONSE=$(curl -s -X POST "$BASE_URL/objects" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "X-Filename: bench_medium.bin" \
    -H "X-Category: benchmark" \
    -H "X-Extension: bin" \
    -d "$MEDIUM_DATA")
MEDIUM_ID=$(echo "$UPLOAD_RESPONSE" | jq -r '.id')

measure_time "Upload 10KB files" 10 curl -s -X POST "$BASE_URL/objects" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "X-Filename: bench_medium.bin" \
    -H "X-Category: benchmark" \
    -H "X-Extension: bin" \
    -d "$MEDIUM_DATA"

# 4. File download performance
echo "## 4. File Download Performance" | tee -a "$RESULTS_FILE"
measure_time "Download 10KB files" 50 curl -s -H "Authorization: Bearer $AUTH_TOKEN" \
    "$BASE_URL/objects/$MEDIUM_ID"

# 5. List objects performance
echo "## 5. List Objects Performance" | tee -a "$RESULTS_FILE"
measure_time "List objects" 100 curl -s -H "Authorization: Bearer $AUTH_TOKEN" \
    "$BASE_URL/objects"

# 6. Concurrent requests test
echo "## 6. Concurrent Request Handling" | tee -a "$RESULTS_FILE"
echo "Testing 10 concurrent requests..." | tee -a "$RESULTS_FILE"

START=$(date +%s.%N)
for i in {1..10}; do
    curl -s -H "Authorization: Bearer $AUTH_TOKEN" "$BASE_URL/objects" &
done
wait
END=$(date +%s.%N)
CONCURRENT_DURATION=$(echo "$END - $START" | bc)
echo "  Time for 10 concurrent requests: ${CONCURRENT_DURATION}s" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# 7. Memory usage
echo "## 7. Server Memory Usage" | tee -a "$RESULTS_FILE"
PID=$(pgrep x2s || echo "")
if [ -n "$PID" ]; then
    MEM_KB=$(ps -o rss= -p "$PID")
    MEM_MB=$(echo "scale=2; $MEM_KB / 1024" | bc)
    echo "  Current RSS: ${MEM_MB} MB" | tee -a "$RESULTS_FILE"
else
    echo "  Server not running" | tee -a "$RESULTS_FILE"
fi
echo "" | tee -a "$RESULTS_FILE"

# 8. Deduplication check
echo "## 8. Deduplication Verification" | tee -a "$RESULTS_FILE"
DUP_DATA="duplicate_test_data_12345"

# Upload same data twice
RESP1=$(curl -s -X POST "$BASE_URL/objects" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "X-Filename: dup1.txt" \
    -d "$DUP_DATA")
RESP2=$(curl -s -X POST "$BASE_URL/objects" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "X-Filename: dup2.txt" \
    -d "$DUP_DATA")

ID1=$(echo "$RESP1" | jq -r '.id')
ID2=$(echo "$RESP2" | jq -r '.id')

if [ "$ID1" != "$ID2" ]; then
    echo "  ✓ Deduplication working: Different metadata IDs for same content" | tee -a "$RESULTS_FILE"
else
    echo "  ⚠ Unexpected: Same ID returned" | tee -a "$RESULTS_FILE"
fi
echo "" | tee -a "$RESULTS_FILE"

echo "=== Benchmark Complete ===" | tee -a "$RESULTS_FILE"
echo "Results saved to $RESULTS_FILE"
