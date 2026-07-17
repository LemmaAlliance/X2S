#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <time.h>
#include "auth/auth.h"
#include "core/format.h"
#include "core/format_registry.h"
#include "core/hex_utils.h"
#include "crypto/encryption.h"
#include "storage/object_io.h"

#define PBKDF2_ITERATIONS 400000
#define PATH_MAX_LEN 4096
#define TOKEN_EXPIRY_SECONDS 1800 /* 30 min token expiry */

void hash_password(const char* password, const unsigned char salt[SALT_SIZE],
                   unsigned char out[HASH_SIZE])
{
    PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, SALT_SIZE, PBKDF2_ITERATIONS,
                      EVP_sha256(), HASH_SIZE, out);
}

static int generate_random(void* buf, size_t len)
{
    return RAND_bytes((unsigned char*)buf, (int)len) == 1;
}


UserStore* user_store_create(size_t initial_capacity)
{
    UserStore* store = malloc(sizeof(UserStore));
    if (!store)
        return NULL;

    store->capacity = (initial_capacity < 8) ? 8 : initial_capacity;
    store->count    = 0;
    store->accounts = calloc(store->capacity, sizeof(UserAccount));
    if (!store->accounts) {
        free(store);
        return NULL;
    }

    return store;
}

void user_store_free(UserStore* store)
{
    if (!store)
        return;
    free(store->accounts);
    free(store);
}

static int user_store_grow(UserStore* store)
{
    size_t       new_cap = store->capacity * 2;
    UserAccount* tmp     = realloc(store->accounts, new_cap * sizeof(UserAccount));
    if (!tmp)
        return 0;
    memset(tmp + store->capacity, 0, (new_cap - store->capacity) * sizeof(UserAccount));
    store->accounts = tmp;
    store->capacity = new_cap;
    return 1;
}

int user_store_register(UserStore* store, const char* username, const char* password,
                        unsigned char user_id_out[16])
{
    if (!store || !username || !password)
        return 0;
    if (strlen(username) == 0 || strlen(username) > MAX_USERNAME)
        return 0;
    if (strlen(password) == 0 || strlen(password) > MAX_PASSWORD)
        return 0;

    for (size_t i = 0; i < store->count; i++) {
        if (strcmp(store->accounts[i].username, username) == 0)
            return 0;
    }

    if (store->count == store->capacity) {
        if (!user_store_grow(store))
            return 0;
    }

    UserAccount* acct = &store->accounts[store->count];

    snprintf(acct->username, sizeof(acct->username), "%s", username);

    if (!generate_random(acct->user_id, 16))
        return 0;
    if (!generate_random(acct->salt, SALT_SIZE))
        return 0;

    hash_password(password, acct->salt, acct->password_hash);

    memcpy(user_id_out, acct->user_id, 16);
    store->count++;
    return 1;
}

int user_store_authenticate(UserStore* store, const char* username, const char* password,
                            unsigned char user_id_out[16])
{
    if (!store || !username || !password)
        return 0;

    for (size_t i = 0; i < store->count; i++) {
        if (strcmp(store->accounts[i].username, username) == 0) {
            unsigned char check[HASH_SIZE];
            hash_password(password, store->accounts[i].salt, check);

            if (CRYPTO_memcmp(check, store->accounts[i].password_hash, HASH_SIZE) == 0) {
                memcpy(user_id_out, store->accounts[i].user_id, 16);
                return 1;
            }
            return 0;
        }
    }

    return 0;
}

void user_store_get_username(UserStore* store, const unsigned char user_id[16], char* out,
                             size_t out_size)
{
    if (!store || !out || out_size == 0)
        return;
    out[0] = '\0';

    for (size_t i = 0; i < store->count; i++) {
        if (memcmp(store->accounts[i].user_id, user_id, 16) == 0) {
            snprintf(out, out_size, "%s", store->accounts[i].username);
            return;
        }
    }
}

static int write_users_v1_body(FILE* f, UserStore* store)
{
    const FormatVtable* fmt = lookup_format(X2S_FORMAT_VERSION_1);
    return fmt && fmt->write_users && fmt->write_users(f, store);
}

int user_store_save(UserStore* store, const char* path)
{
    char file_path[PATH_MAX_LEN + 16];
    char tmp_path[PATH_MAX_LEN + 32];

    snprintf(file_path, sizeof(file_path), "%s/__users", path);
    snprintf(tmp_path, sizeof(tmp_path), "%s/__users.tmp", path);

    FILE* f = fopen(tmp_path, "wb");
    if (!f)
        return 0;

    if (!try_write_header(f, X2S_FILE_TYPE_USERS)) {
        fclose(f);
        remove(tmp_path);
        return 0;
    }

    int ok;
    if (encryption_is_active()) {
        char*  body     = NULL;
        size_t body_len = 0;
        FILE*  buf      = open_memstream(&body, &body_len);
        if (!buf) {
            fclose(f);
            remove(tmp_path);
            return 0;
        }
        ok = write_users_v1_body(buf, store);
        fclose(buf);

        if (ok)
            ok = write_encrypted_body(f, (unsigned char*)body, body_len);
        free(body);
    } else {
        const FormatVtable* fmt = latest_format();
        ok                      = fmt && fmt->write_users && fmt->write_users(f, store);
    }

    fclose(f);

    if (!ok) {
        remove(tmp_path);
        return 0;
    }

    if (rename(tmp_path, file_path) != 0) {
        remove(tmp_path);
        return 0;
    }

    return 1;
}

int user_store_load(UserStore* store, const char* path)
{
    char file_path[PATH_MAX_LEN + 16];
    snprintf(file_path, sizeof(file_path), "%s/__users", path);

    FILE* f = fopen(file_path, "rb");
    if (!f)
        return 0;

    uint8_t version = 0;
    int     hret    = try_read_header(f, X2S_FILE_TYPE_USERS, &version);
    if (hret == -1) {
        fclose(f);
        return -1;
    }

    if (version == X2S_FORMAT_VERSION_2) {
        if (!encryption_is_active()) {
            fclose(f);
            return -1;
        }
        DecryptedStream ds = decrypt_file_to_mem(f);
        fclose(f);
        if (!ds.stream)
            return -1;

        const FormatVtable* fmt = lookup_format(X2S_FORMAT_VERSION_1);
        store->count            = 0;
        int ok                  = fmt && fmt->read_users && fmt->read_users(ds.stream, store);
        close_decrypted_stream(&ds);
        return ok ? 1 : -1;
    }

    const FormatVtable* fmt = lookup_format(version);
    if (!fmt || !fmt->read_users) {
        fclose(f);
        return 0;
    }

    store->count = 0;
    int ret      = fmt->read_users(f, store);
    fclose(f);
    return ret;
}

SessionStore* session_store_create(size_t initial_capacity)
{
    SessionStore* store = malloc(sizeof(SessionStore));
    if (!store)
        return NULL;

    store->capacity = (initial_capacity < 16) ? 16 : initial_capacity;
    store->count    = 0;
    store->sessions = calloc(store->capacity, sizeof(Session));
    if (!store->sessions) {
        free(store);
        return NULL;
    }

    return store;
}

void session_store_free(SessionStore* store)
{
    if (!store)
        return;
    free(store->sessions);
    free(store);
}

static int session_store_grow(SessionStore* store)
{
    size_t   new_cap = store->capacity * 2;
    Session* tmp     = realloc(store->sessions, new_cap * sizeof(Session));
    if (!tmp)
        return 0;
    memset(tmp + store->capacity, 0, (new_cap - store->capacity) * sizeof(Session));
    store->sessions = tmp;
    store->capacity = new_cap;
    return 1;
}

char* session_create(SessionStore* store, const unsigned char user_id[16])
{
    if (!store || !user_id)
        return NULL;

    if (store->count == store->capacity) {
        if (!session_store_grow(store))
            return NULL;
    }

    Session* s = &store->sessions[store->count];

    if (!generate_random(s->token, TOKEN_SIZE))
        return NULL;
    memcpy(s->user_id, user_id, 16);

    char* hex = malloc(TOKEN_SIZE * 2 + 1);
    if (!hex)
        return NULL;
    bytes_to_hex(s->token, TOKEN_SIZE, hex);

    time_t now = time(NULL);
    s->expiry  = now + TOKEN_EXPIRY_SECONDS;
    store->count++;
    return hex;
}

int session_lookup(SessionStore* store, const unsigned char token[TOKEN_SIZE],
                   unsigned char user_id_out[16])
{
    if (!store || !token)
        return 0;

    for (size_t i = 0; i < store->count; i++) {
        if (CRYPTO_memcmp(store->sessions[i].token, token, TOKEN_SIZE) == 0) {
            memcpy(user_id_out, store->sessions[i].user_id, 16);
            return 1;
        }
    }

    return 0;
}

void session_destroy(SessionStore* store, const unsigned char token[TOKEN_SIZE])
{
    if (!store || !token)
        return;

    for (size_t i = 0; i < store->count; i++) {
        if (CRYPTO_memcmp(store->sessions[i].token, token, TOKEN_SIZE) == 0) {
            if (i < store->count - 1) {
                memmove(&store->sessions[i], &store->sessions[i + 1],
                        (store->count - i - 1) * sizeof(Session));
            }
            store->count--;
            return;
        }
    }
}

void check_token_expiry(SessionStore* store)
{
    if (!store || store->count == 0)
        return;

    time_t now         = time(NULL);
    size_t write_index = 0;

    for (size_t read_index = 0; read_index < store->count; read_index++) {
        if (store->sessions[read_index].expiry > now) {
            if (write_index != read_index) {
                store->sessions[write_index] = store->sessions[read_index];
            }
            write_index++;
        } else {
            // Clear memory of expired token for safety
            memset(&store->sessions[read_index], 0, sizeof(Session));
        }
    }

    store->count = write_index;
}