#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include "auth/refresh_token.h"
#include "core/format.h"
#include "core/hex_utils.h"

#define PATH_MAX_LEN 4096

static int generate_random(void* buf, size_t len)
{
    return RAND_bytes((unsigned char*)buf, (int)len) == 1;
}

RefreshTokenStore* refresh_token_store_create(size_t initial_capacity)
{
    RefreshTokenStore* store = malloc(sizeof(RefreshTokenStore));
    if (!store)
        return NULL;

    store->capacity = (initial_capacity < 16) ? 16 : initial_capacity;
    store->count    = 0;
    store->tokens   = calloc(store->capacity, sizeof(RefreshToken));
    if (!store->tokens) {
        free(store);
        return NULL;
    }

    return store;
}

void refresh_token_store_free(RefreshTokenStore* store)
{
    if (!store)
        return;
    free(store->tokens);
    free(store);
}

static int refresh_token_store_grow(RefreshTokenStore* store)
{
    size_t        new_cap = store->capacity * 2;
    RefreshToken* tmp = realloc(store->tokens, new_cap * sizeof(RefreshToken));
    if (!tmp)
        return 0;
    memset(tmp + store->capacity, 0,
           (new_cap - store->capacity) * sizeof(RefreshToken));
    store->tokens   = tmp;
    store->capacity = new_cap;
    return 1;
}

char* refresh_token_create(RefreshTokenStore*  store,
                           const unsigned char user_id[16])
{
    if (!store || !user_id)
        return NULL;

    if (store->count == store->capacity) {
        if (!refresh_token_store_grow(store))
            return NULL;
    }

    RefreshToken* rt = &store->tokens[store->count];

    if (!generate_random(rt->token, REFRESH_TOKEN_SIZE))
        return NULL;
    memcpy(rt->user_id, user_id, 16);
    rt->expiry = time(NULL) + REFRESH_TOKEN_EXPIRY_SECONDS;

    char* hex = malloc(REFRESH_TOKEN_SIZE * 2 + 1);
    if (!hex)
        return NULL;
    bytes_to_hex(rt->token, REFRESH_TOKEN_SIZE, hex);

    store->count++;
    return hex;
}

int refresh_token_validate(RefreshTokenStore* store,
                           const char*        hex_token,
                           unsigned char      user_id_out[16])
{
    if (!store || !hex_token)
        return 0;

    if (strlen(hex_token) != REFRESH_TOKEN_SIZE * 2)
        return 0;

    unsigned char bin[REFRESH_TOKEN_SIZE];
    if (!hex_to_bytes(hex_token, bin, REFRESH_TOKEN_SIZE))
        return 0;

    time_t now = time(NULL);

    for (size_t i = 0; i < store->count; i++) {
        if (store->tokens[i].expiry > now &&
            CRYPTO_memcmp(store->tokens[i].token, bin, REFRESH_TOKEN_SIZE) == 0) {
            memcpy(user_id_out, store->tokens[i].user_id, 16);
            return 1;
        }
    }

    return 0;
}

char* refresh_token_rotate(RefreshTokenStore* store,
                           const char*        hex_token,
                           unsigned char      user_id_out[16])
{
    if (!store || !hex_token)
        return NULL;

    if (strlen(hex_token) != REFRESH_TOKEN_SIZE * 2)
        return NULL;

    unsigned char bin[REFRESH_TOKEN_SIZE];
    if (!hex_to_bytes(hex_token, bin, REFRESH_TOKEN_SIZE))
        return NULL;

    time_t now = time(NULL);
    size_t found = store->count;

    for (size_t i = 0; i < store->count; i++) {
        if (store->tokens[i].expiry > now &&
            CRYPTO_memcmp(store->tokens[i].token, bin, REFRESH_TOKEN_SIZE) == 0) {
            found = i;
            break;
        }
    }

    if (found == store->count)
        return NULL;

    unsigned char user_id[16];
    memcpy(user_id, store->tokens[found].user_id, 16);

    if (found < store->count - 1) {
        memmove(&store->tokens[found], &store->tokens[found + 1],
                (store->count - found - 1) * sizeof(RefreshToken));
    }
    store->count--;

    char* new_hex = refresh_token_create(store, user_id);
    if (new_hex)
        memcpy(user_id_out, user_id, 16);

    return new_hex;
}

void refresh_token_revoke(RefreshTokenStore* store, const char* hex_token)
{
    if (!store || !hex_token)
        return;

    if (strlen(hex_token) != REFRESH_TOKEN_SIZE * 2)
        return;

    unsigned char bin[REFRESH_TOKEN_SIZE];
    if (!hex_to_bytes(hex_token, bin, REFRESH_TOKEN_SIZE))
        return;

    for (size_t i = 0; i < store->count; i++) {
        if (CRYPTO_memcmp(store->tokens[i].token, bin, REFRESH_TOKEN_SIZE) == 0) {
            if (i < store->count - 1) {
                memmove(&store->tokens[i], &store->tokens[i + 1],
                        (store->count - i - 1) * sizeof(RefreshToken));
            }
            store->count--;
            return;
        }
    }
}

void refresh_token_cleanup(RefreshTokenStore* store)
{
    if (!store || store->count == 0)
        return;

    time_t now         = time(NULL);
    size_t write_index = 0;

    for (size_t read_index = 0; read_index < store->count; read_index++) {
        if (store->tokens[read_index].expiry > now) {
            if (write_index != read_index) {
                store->tokens[write_index] = store->tokens[read_index];
            }
            write_index++;
        } else {
            memset(&store->tokens[read_index], 0, sizeof(RefreshToken));
        }
    }

    store->count = write_index;
}

int refresh_token_store_save(RefreshTokenStore* store, const char* data_path)
{
    char file_path[PATH_MAX_LEN + 32];
    char tmp_path[PATH_MAX_LEN + 40];

    snprintf(file_path, sizeof(file_path), "%s/__refresh_tokens", data_path);
    snprintf(tmp_path, sizeof(tmp_path), "%s/__refresh_tokens.tmp", data_path);

    FILE* f = fopen(tmp_path, "wb");
    if (!f)
        return 0;

    if (!try_write_header(f, X2S_FILE_TYPE_REFRESH)) {
        fclose(f);
        remove(tmp_path);
        return 0;
    }

    if (fwrite(&store->count, sizeof(size_t), 1, f) != 1) {
        fclose(f);
        remove(tmp_path);
        return 0;
    }

    if (store->count > 0) {
        if (fwrite(store->tokens, sizeof(RefreshToken), store->count, f) !=
            store->count) {
            fclose(f);
            remove(tmp_path);
            return 0;
        }
    }

    fclose(f);

    if (rename(tmp_path, file_path) != 0) {
        remove(tmp_path);
        return 0;
    }

    return 1;
}

int refresh_token_store_load(RefreshTokenStore* store, const char* data_path)
{
    char file_path[PATH_MAX_LEN + 32];
    snprintf(file_path, sizeof(file_path), "%s/__refresh_tokens", data_path);

    FILE* f = fopen(file_path, "rb");
    if (!f)
        return 0;

    uint8_t version = 0;
    int     hret    = try_read_header(f, X2S_FILE_TYPE_REFRESH, &version);
    if (hret == -1) {
        fclose(f);
        return -1;
    }
    if (hret == 0) {
        fclose(f);
        return 0;
    }

    size_t count = 0;
    if (fread(&count, sizeof(size_t), 1, f) != 1) {
        fclose(f);
        return 0;
    }

    store->count = 0;

    for (size_t i = 0; i < count; i++) {
        if (store->count == store->capacity) {
            if (!refresh_token_store_grow(store)) {
                fclose(f);
                return 0;
            }
        }

        RefreshToken rt;
        if (fread(&rt, sizeof(RefreshToken), 1, f) != 1) {
            fclose(f);
            return 0;
        }

        if (rt.expiry > time(NULL)) {
            memcpy(&store->tokens[store->count], &rt, sizeof(RefreshToken));
            store->count++;
        }
    }

    fclose(f);
    return 1;
}
