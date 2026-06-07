# X2S — eXtremely Simple Storage

A lightweight, HTTP-based blob storage server written in C11. Upload and retrieve binary objects identified by their SHA-256 content hash, with per-object ACLs and user authentication.

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
  PUT   /objects             upload an object
  GET   /objects/<id>        retrieve an object
  DELETE /objects/<id>       remove an object
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

#### ACL model

When an object is uploaded, the uploading user is set as the **owner** and granted read, write, and delete permissions. Other users have **no access** unless the ACL is modified (currently no API to modify ACLs — this is a future extension). Duplicate uploads (same content hash) silently succeed but preserve the **original owner and ACL**.

```bash
# upload
curl -X PUT http://localhost:8080/objects \
  -H 'Authorization: Bearer <token>' \
  -H 'X-Filename: hello.txt' \
  -d 'Hello, World!'
# → {"id":"63a46a45f4bcc89a04adfefccdfdbb5b66a659d92cb54dd2bdb4e1705d06996a"}

# download
curl -H 'Authorization: Bearer <token>' \
  http://localhost:8080/objects/63a46a45f4bcc89a04adfefccdfdbb5b66a659d92cb54dd2bdb4e1705d06996a

# delete
curl -X DELETE -H 'Authorization: Bearer <token>' \
  http://localhost:8080/objects/63a46a45f4bcc89a04adfefccdfdbb5b66a659d92cb54dd2bdb4e1705d06996a
```

#### Optional upload headers

| Header | Description |
|--------|-------------|
| `X-Category` | Arbitrary category tag |
| `X-Extension` | File extension (no dot); used for `Content-Type` on download |
| `X-Filename` | Original filename |

### Error responses

All errors return JSON:

```json
{"error":"<message>"}
```

| Status | Meaning |
|--------|---------|
| 201 | Object created |
| 204 | Success (no body) |
| 400 | Bad request |
| 401 | Authentication failed |
| 403 | Access denied |
| 404 | Not found |
| 405 | Method not allowed |
| 409 | Username taken |
| 413 | Body exceeds 64 MiB limit |
| 500 | Internal server error |

## Storage

- **On-disk**: Each object is a file in `./x2s_data/` named by its 64-character hex SHA-256 hash. The binary format stores data length, metadata lengths, owner ID (16 bytes), ACL entries, raw data, and metadata strings.
- **In-memory index**: A chained hash table (FNV-1a) maps object IDs to lightweight entries. Resizes when load factor exceeds 0.75. Persisted atomically (temp file + rename) to `./x2s_data/__index`.
- **User accounts**: Stored as binary at `./x2s_data/__users`. Survive server restarts. Sessions are ephemeral and lost on restart (re-login required).
- **Atomic writes**: Both the object index and user database use a write-then-rename strategy to prevent corruption on crash.

## Build

### Dependencies

- **CMake** ≥ 3.15
- **libmicrohttpd** (embedded HTTP server)
- **OpenSSL** `libcrypto` (SHA-256, PBKDF2, random bytes, constant-time comparison)
- A C11 compiler (GCC, Clang)

### Compile

```bash
cmake -S . -B build && cmake --build build
```

### Run on a custom port

```bash
./build/x2s 9090
```

## Design notes

- **Single-threaded** — libmicrohttpd internal polling thread handles all I/O. No locking, no concurrent access safety.
- **No TLS** — intended for trusted/internal networks. Pair with a reverse proxy (nginx, Caddy) for TLS termination.
- **Content-addressed** — object IDs are SHA-256 hashes of data + metadata. Duplicate uploads silently return the existing ID and preserve the original owner/ACL.
- **Constant-time comparisons** — password hashes and session tokens are compared with `CRYPTO_memcmp` to mitigate timing attacks.
- **No session expiry** — bearer tokens live until server restart. Re-authentication is required after restart.
- **Maximum password length** — 1024 bytes.
- **Maximum object size** — 64 MiB (hardcoded as `MAX_UPLOAD_SIZE` in `api_server.c`).
- **No rate limiting** — `/auth/login` accepts unlimited requests; pair with external rate limiting for brute-force protection.
