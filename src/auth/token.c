#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include "auth/token.h"

static const char B64URL[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int generate_hmac_key(unsigned char key[HMAC_KEY_SIZE])
{
    return RAND_bytes(key, HMAC_KEY_SIZE) == 1;
}

static void pack_payload(const unsigned char user_id[16], time_t expiry,
                         unsigned char out[TOKEN_PAYLOAD_SIZE])
{
    uint64_t t = (uint64_t)expiry;
    memcpy(out, user_id, 16);
    out[16] = (unsigned char)(t >> 56);
    out[17] = (unsigned char)(t >> 48);
    out[18] = (unsigned char)(t >> 40);
    out[19] = (unsigned char)(t >> 32);
    out[20] = (unsigned char)(t >> 24);
    out[21] = (unsigned char)(t >> 16);
    out[22] = (unsigned char)(t >> 8);
    out[23] = (unsigned char)(t);
}

static void unpack_payload(const unsigned char in[TOKEN_PAYLOAD_SIZE],
                           unsigned char user_id[16], time_t* expiry)
{
    uint64_t t;
    memcpy(user_id, in, 16);
    t  = (uint64_t)in[16] << 56;
    t |= (uint64_t)in[17] << 48;
    t |= (uint64_t)in[18] << 40;
    t |= (uint64_t)in[19] << 32;
    t |= (uint64_t)in[20] << 24;
    t |= (uint64_t)in[21] << 16;
    t |= (uint64_t)in[22] << 8;
    t |= (uint64_t)in[23];
    *expiry = (time_t)t;
}

static void base64url_encode(const unsigned char* in, size_t in_len, char* out)
{
    for (size_t i = 0; i < in_len; i += 3) {
        unsigned int val = (unsigned int)in[i] << 16;
        if (i + 1 < in_len)
            val |= (unsigned int)in[i + 1] << 8;
        if (i + 2 < in_len)
            val |= (unsigned int)in[i + 2];

        *out++ = B64URL[(val >> 18) & 0x3F];
        *out++ = B64URL[(val >> 12) & 0x3F];
        if (i + 1 < in_len)
            *out++ = B64URL[(val >> 6) & 0x3F];
        if (i + 2 < in_len)
            *out++ = B64URL[val & 0x3F];
    }
    *out = '\0';
}

static int base64url_char_val(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '-')
        return 62;
    if (c == '_')
        return 63;
    return -1;
}

static int base64url_decode(const char* in, size_t in_len, unsigned char* out)
{
    size_t out_len = 0;
    for (size_t i = 0; i + 3 < in_len; i += 4) {
        int a = base64url_char_val(in[i]);
        int b = base64url_char_val(in[i + 1]);
        int c = base64url_char_val(in[i + 2]);
        int d = base64url_char_val(in[i + 3]);

        if (a < 0 || b < 0 || c < 0 || d < 0)
            return -1;

        unsigned int val = ((unsigned int)a << 18) | ((unsigned int)b << 12) |
                           ((unsigned int)c << 6) | (unsigned int)d;

        out[out_len++] = (unsigned char)(val >> 16);
        out[out_len++] = (unsigned char)(val >> 8);
        out[out_len++] = (unsigned char)(val);
    }
    return (int)out_len;
}

char* access_token_create(const unsigned char hmac_key[HMAC_KEY_SIZE],
                          const unsigned char user_id[16],
                          time_t              expiry)
{
    unsigned char payload[TOKEN_PAYLOAD_SIZE];
    pack_payload(user_id, expiry, payload);

    char b64_payload[PAYLOAD_B64_SIZE + 1];
    base64url_encode(payload, TOKEN_PAYLOAD_SIZE, b64_payload);

    unsigned char sig[EVP_MAX_MD_SIZE];
    unsigned int  sig_len = 0;
    HMAC(EVP_sha256(), hmac_key, HMAC_KEY_SIZE, payload, TOKEN_PAYLOAD_SIZE,
         sig, &sig_len);
    if (sig_len != 32)
        return NULL;

    char b64_sig[SIG_B64_SIZE + 1];
    base64url_encode(sig, 32, b64_sig);

    char* token = malloc(ACCESS_TOKEN_MAX_SIZE);
    if (!token)
        return NULL;

    snprintf(token, ACCESS_TOKEN_MAX_SIZE, "%s.%s", b64_payload, b64_sig);
    return token;
}

int access_token_verify(const unsigned char hmac_key[HMAC_KEY_SIZE],
                        const char*           token,
                        unsigned char         user_id_out[16])
{
    if (!token)
        return 0;

    const char* dot = strchr(token, '.');
    if (!dot)
        return 0;

    size_t b64_payload_len = (size_t)(dot - token);
    if (b64_payload_len != PAYLOAD_B64_SIZE)
        return 0;

    const char* b64_sig = dot + 1;
    size_t b64_sig_len = strlen(b64_sig);
    if (b64_sig_len != SIG_B64_SIZE)
        return 0;

    unsigned char payload[TOKEN_PAYLOAD_SIZE];
    if (base64url_decode(token, b64_payload_len, payload) != TOKEN_PAYLOAD_SIZE)
        return 0;

    time_t expiry;
    unpack_payload(payload, user_id_out, &expiry);

    if (expiry <= time(NULL))
        return 0;

    unsigned char expected_sig[32];
    unsigned int  sig_len = 0;
    HMAC(EVP_sha256(), hmac_key, HMAC_KEY_SIZE, payload, TOKEN_PAYLOAD_SIZE,
         expected_sig, &sig_len);
    if (sig_len != 32)
        return 0;

    unsigned char actual_sig[32];
    if (base64url_decode(b64_sig, b64_sig_len, actual_sig) != 32)
        return 0;

    if (CRYPTO_memcmp(expected_sig, actual_sig, 32) != 0)
        return 0;

    return 1;
}

static int get_token_hash(const char* token, unsigned char hash_out[32],
                          time_t* expiry_out)
{
    const char* dot = strchr(token, '.');
    if (!dot)
        return 0;

    unsigned char payload[TOKEN_PAYLOAD_SIZE];
    if (base64url_decode(token, (size_t)(dot - token), payload) !=
        TOKEN_PAYLOAD_SIZE)
        return 0;

    unsigned char dummy[16];
    unpack_payload(payload, dummy, expiry_out);

    unsigned char sig_bin[32];
    if (base64url_decode(dot + 1, strlen(dot + 1), sig_bin) != 32)
        return 0;

    unsigned char full_token[ACCESS_TOKEN_MAX_SIZE];
    size_t token_len = strlen(token);
    if (token_len >= ACCESS_TOKEN_MAX_SIZE)
        return 0;
    memcpy(full_token, token, token_len + 1);

    if (!EVP_Digest((const unsigned char*)full_token, token_len,
                    hash_out, NULL, EVP_sha256(), NULL))
        return 0;

    return 1;
}

RevocationStore* revocation_store_create(size_t initial_capacity)
{
    RevocationStore* store = malloc(sizeof(RevocationStore));
    if (!store)
        return NULL;

    store->capacity = (initial_capacity < 16) ? 16 : initial_capacity;
    store->count    = 0;
    store->entries  = calloc(store->capacity, sizeof(RevocationEntry));
    if (!store->entries) {
        free(store);
        return NULL;
    }

    return store;
}

void revocation_store_destroy(RevocationStore* store)
{
    if (!store)
        return;
    free(store->entries);
    free(store);
}

int revocation_store_revoke(RevocationStore* store, const char* token)
{
    if (!store || !token)
        return 0;

    unsigned char hash[32];
    time_t        expiry;
    if (!get_token_hash(token, hash, &expiry))
        return 0;

    if (store->count == store->capacity) {
        size_t          new_cap = store->capacity * 2;
        RevocationEntry* tmp =
            realloc(store->entries, new_cap * sizeof(RevocationEntry));
        if (!tmp)
            return 0;
        memset(tmp + store->capacity, 0,
               (new_cap - store->capacity) * sizeof(RevocationEntry));
        store->entries  = tmp;
        store->capacity = new_cap;
    }

    memcpy(store->entries[store->count].hash, hash, 32);
    store->entries[store->count].expiry = expiry;
    store->count++;
    return 1;
}

int revocation_store_is_revoked(RevocationStore* store, const char* token)
{
    if (!store || !token)
        return 0;

    unsigned char hash[32];
    time_t        expiry;
    if (!get_token_hash(token, hash, &expiry))
        return 0;

    for (size_t i = 0; i < store->count; i++) {
        if (CRYPTO_memcmp(store->entries[i].hash, hash, 32) == 0)
            return 1;
    }

    return 0;
}

void revocation_store_cleanup(RevocationStore* store)
{
    if (!store || store->count == 0)
        return;

    time_t now     = time(NULL);
    size_t write_index = 0;

    for (size_t read_index = 0; read_index < store->count; read_index++) {
        if (store->entries[read_index].expiry > now) {
            if (write_index != read_index) {
                store->entries[write_index] = store->entries[read_index];
            }
            write_index++;
        } else {
            memset(&store->entries[read_index], 0, sizeof(RevocationEntry));
        }
    }

    store->count = write_index;
}
