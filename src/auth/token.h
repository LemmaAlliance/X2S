#ifndef TOKEN_H
#define TOKEN_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#define ACCESS_TOKEN_EXPIRY_SECONDS 900
#define HMAC_KEY_SIZE 32
#define TOKEN_PAYLOAD_SIZE 24

#define PAYLOAD_B64_SIZE 32
#define SIG_B64_SIZE 43
#define ACCESS_TOKEN_MAX_SIZE (PAYLOAD_B64_SIZE + 1 + SIG_B64_SIZE + 1)

typedef struct
{
    unsigned char hash[32];
    time_t        expiry;
} RevocationEntry;

typedef struct RevocationStore
{
    RevocationEntry* entries;
    size_t           count;
    size_t           capacity;
} RevocationStore;

int generate_hmac_key(unsigned char key[HMAC_KEY_SIZE]);

char* access_token_create(const unsigned char hmac_key[HMAC_KEY_SIZE],
                          const unsigned char user_id[16],
                          time_t              expiry);

int access_token_verify(const unsigned char hmac_key[HMAC_KEY_SIZE],
                        const char*           token,
                        unsigned char         user_id_out[16]);

RevocationStore* revocation_store_create(size_t initial_capacity);
void             revocation_store_destroy(RevocationStore* store);
int              revocation_store_revoke(RevocationStore* store, const char* token);
int              revocation_store_is_revoked(RevocationStore* store, const char* token);
void             revocation_store_cleanup(RevocationStore* store);

#endif
