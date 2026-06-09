# X2S — eXtremely Simple Storage

A lightweight, RESTful blob storage server written in C11. Upload and retrieve binary objects identified by their SHA-256 content hash, with per-object ACLs and user authentication.

## Quick start

```bash
# install dependencies (Debian/Ubuntu)
sudo apt install build-essential cmake libmicrohttpd-dev libssl-dev

# build
cmake -S . -B build && cmake --build build

# run
./build/x2s

```

```
Listening on http://0.0.0.0:8080
  POST  /auth/register      register a new user
  POST  /auth/login          authenticate and get a token
  POST  /auth/logout         invalidate a token
  POST  /objects             upload an object
  GET   /objects             list accessible objects with filters
  GET   /objects/<id>        retrieve an object
  DELETE /objects/<id>       remove an object
  POST  /objects/<id>/share  grant object permissions to another user

```

## API

### Authentication

Register a user and obtain a bearer token. All authentication endpoints use `application/x-www-form-urlencoded` bodies.

```bash
# register
curl -X POST http://localhost:8080/auth/register \
  -d 'username=alice&password=secret123'

# login
curl -X POST http://localhost:8080/auth/login \
  -d 'username=alice&password=secret123'
# → {"token":"<64-hex>","user_id":"<32-hex>"}

# logout
curl -X POST http://localhost:8080/auth/logout \
  -H 'Authorization: Bearer <token>'

```

Passwords are hashed with **PBKDF2-HMAC-SHA256** (100,000 iterations, random 16-byte salt, max 1024 bytes). The server stores only the salted hash — never the plaintext password. Password hashes and session tokens are compared using **constant-time** (`CRYPTO_memcmp`) to prevent timing side-channel attacks.

### Object operations

Include the bearer token in the `Authorization` header. The token's user identity is used for ACL permission checks. Authentication is optional — requests without a token are treated as the `anonymous` user and have no access to any objects.

#### ACL model & Deduplication

X2S employs a **Content-Addressable Storage (CAS)** paradigm where file contents are structurally isolated from access metadata:

* **Upload isolation:** When a user uploads a file, a unique tracking identifier is generated for them by mixing their `user_id` with the object's properties. This means if two separate users upload the exact same file, they receive **independent tracking objects** with distinct owners, separate filenames, and completely isolated Access Control Lists (ACLs).
* **Storage Deduplication:** On disk, the unique metadata file points to a shared data blob named strictly after the SHA-256 hash of the raw bytes. If multiple users upload the same file, it will only be stored **once on disk**, drastically reducing storage consumption.
* **Sharing:** An owner can dynamically grant permissions to another user via the `/share` endpoint.

```bash
# upload
curl -X POST http://localhost:8080/objects \
  -H 'Authorization: Bearer <token>' \
  -H 'X-Filename: hello.txt' \
  -H 'X-Category: documents' \
  -H 'X-Extension: txt' \
  -d 'Hello, World!'
# → {"id":"63a46a45f4bcc89a04adfefccdfdbb5b66a659d92cb54dd2bdb4e1705d06996a"}

# list all files you have access to (with optional query filters)
curl -H 'Authorization: Bearer <token>' \
  "http://localhost:8080/objects?category=documents&extension=txt"
# → {"objects":[{"id":"63a46a45...","category":"documents","filename":"hello.txt","extension":"txt","size":13}]}

# download
curl -H 'Authorization: Bearer <token>' \
  http://localhost:8080/objects/63a46a45f4bcc89a04adfefccdfdbb5b66a659d92cb54dd2bdb4e1705d06996a

# share object with another user (granting read permission: 1)
curl -X POST http://localhost:8080/objects/63a46a45f4bcc89a04adfefccdfdbb5b66a659d92cb54dd2bdb4e1705d06996a/share \
  -H 'Authorization: Bearer <token>' \
  -d 'user_id=b0fca315c89a04adfe123456789abcde&permissions=1'

# delete
curl -X DELETE -H 'Authorization: Bearer <token>' \
  http://localhost:8080/objects/63a46a45f4bcc89a04adfefccdfdbb5b66a659d92cb54dd2bdb4e1705d06996a

```

#### Listing & Filtering (`GET /objects`)

Returns a JSON collection of all object tracking wrappers that the authenticated user has explicit read access (`PERM_READ`) to view.

You can filter results by appending optional URL query strings:

* `category`: Filters items by exact string equality against their `X-Category` metadata properties.
* `filename`: Filters items by exact string equality against their original `X-Filename` properties.
* `extension`: Filters items by exact string equality against their `X-Extension` metadata properties.

#### Reference-Checked Deletion (`DELETE /objects/<id>`)

Because data payloads are shared across multiple metadata entries, deletion operates using a safety-first reference-counting model:

1. When a user requests a deletion, their specific metadata tracking file (which stores their permissions and filenames) is wiped from disk immediately.
2. The server scans the internal index to see if *any other tracking entries* are pointing to that shared data blob.
3. If other users are still referencing that file content, the shared data blob is preserved so their access remains undisturbed.
4. The moment the **last user** referencing that content deletes their object, the reference count drops to zero, and the actual raw data payload file is purged from disk.

#### Dynamic Sharing (`POST /objects/<id>/share`)

Allows the object **owner** to append or update access permissions for a specific user ID. The request uses `application/x-www-form-urlencoded` format parameters:

| Parameter | Type | Description |
| --- | --- | --- |
| `user_id` | Hex String (32 chars) | The target 16-byte raw user ID to update permissions for. |
| `permissions` | Integer | A bitmask of granted capabilities: `1` (Read), `2` (Write), `4` (Delete). |

*Returns `204 No Content` on successful update. Returns `403 Forbidden` if a non-owner tries to execute the share request.*

#### Optional upload headers

| Header | Description |
| --- | --- |
| `X-Category` | Arbitrary category tag used for indexing and filtering discovery results |
| `X-Extension` | File extension (no dot); used for query filtering and evaluating `Content-Type` on download |
| `X-Filename` | Original filename string used for filtering discovery lists |

## Error responses

All errors return JSON:

```json
{"error":"<message>"}

```

| Status | Meaning |
| --- | --- |
| 200 | Success (returns data array or file payload stream) |
| 201 | Object created |
| 204 | Success (no body) |
| 400 | Bad request / Missing parameter fields |
| 401 | Authentication failed |
| 403 | Access denied / Only the owner can share this object |
| 404 | Object not found |
| 405 | Method not allowed |
| 409 | Username taken |
| 413 | Body exceeds 64 MiB limit |
| 500 | Internal server error |

## Storage

All persistent storage files live in `./x2s_data/` and adhere to a split model layout:

* **Metadata Tracking Files (`./x2s_data/<object_id>`)**: Named by a 64-character hex hash that is unique per user upload. The binary layout stores data length, metadata lengths, owner ID (16 bytes), ACL structures, a **32-byte SHA-256 pointer hash of the data content block**, and user metadata strings.
* **Shared Data Blobs (`./x2s_data/data_<data_hash>`)**: Named with a `data_` prefix followed by the 64-character hex hash of the *raw contents alone*. This file is decoupled from usernames, access tokens, and access patterns.
* **In-memory index**: A chained hash table (FNV-1a) maps object tracking IDs to lightweight entries. Resizes when load factor exceeds 0.75. Persisted atomically (temp file + rename) to `./x2s_data/__index`. Modifying object ACLs rewrites the associated object metadata file and updates this volatile cache.
* **User accounts**: Stored as binary at `./x2s_data/__users`. Survive server restarts. Sessions are ephemeral and lost on restart (re-login required).
* **Atomic writes**: Both the object index and user database use a write-then-rename strategy to prevent corruption on crash.

## Build

### Dependencies

* **CMake** ≥ 3.15
* **libmicrohttpd** (embedded HTTP server)
* **OpenSSL** `libcrypto` (SHA-256, PBKDF2, random bytes, constant-time comparison)
* A C11 compiler (GCC, Clang)

### Compile

```bash
cmake -S . -B build && cmake --build build

```

### Run on a custom port

```bash
./build/x2s 9090

```

## Design notes

* **Single-threaded** — libmicrohttpd internal polling thread handles all I/O. No locking, no concurrent access safety.
* **No TLS** — intended for trusted/internal networks. **It is highly recommended to pair this with a reverse proxy like Nginx**
* **Content-addressed & Deduplicated** — payload contents are identified via unique data hashes. Multiple metadata targets reference identical chunks on disk, achieving file deduplication across users while preserving access control sandboxing.
* **Metadata query discovery** — indexes user spaces globally in real-time by crawling local hash-node buckets to enforce precise sandbox filtering constraints quickly.
* **Constant-time comparisons** — password hashes and session tokens are compared with `CRYPTO_memcmp` to mitigate timing attacks.
* **No session expiry** — bearer tokens live until server restart. Re-authentication is required after restart. (This is a future feature)
* **Maximum password length** — 1024 bytes.
* **Maximum object size** — 64 MiB (hardcoded as `MAX_UPLOAD_SIZE` in `api_server.c`).
* **No rate limiting** — `/auth/login` accepts unlimited requests; pair with external rate limiting for brute-force protection. (This is a future feature)

For now, use a reverse proxy to rate limit and add TLS