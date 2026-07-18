#ifndef AUTH_H
#define AUTH_H

/*
 * User authentication, session management, and password hashing.
 *
 * Manages UserAccount and Session lifecycle: registration, authentication,
 * token-based session creation/lookup/destruction, and periodic expiry.
 * Password hashing uses PBKDF2-SHA256; sessions expire after 30 minutes.
 */

#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#define SALT_SIZE 16
#define HASH_SIZE 32
#define MAX_USERNAME 63
#define MAX_PASSWORD 1024

typedef struct
{
    char          username[MAX_USERNAME + 1];
    unsigned char user_id[16];
    unsigned char password_hash[HASH_SIZE];
    unsigned char salt[SALT_SIZE];
} UserAccount;

typedef struct UserStore
{
    UserAccount* accounts;
    size_t       count;
    size_t       capacity;
} UserStore;

typedef struct RefreshTokenStore RefreshTokenStore;
typedef struct RevocationStore RevocationStore;

typedef struct TokenStore
{
    UserStore*         users;
    RefreshTokenStore* refresh_tokens;
    RevocationStore*   revoked_access;
    unsigned char      hmac_key[32];
} TokenStore;

UserStore* user_store_create(size_t initial_capacity);
void       user_store_free(UserStore* store);
int        user_store_register(UserStore* store, const char* username, const char* password,
                               unsigned char user_id_out[16]);
int        user_store_authenticate(UserStore* store, const char* username, const char* password,
                                   unsigned char user_id_out[16]);
void       user_store_get_username(UserStore* store, const unsigned char user_id[16], char* out,
                                   size_t out_size);
int        user_store_save(UserStore* store, const char* path);
int        user_store_load(UserStore* store, const char* path);

void hash_password(const char* password, const unsigned char salt[SALT_SIZE],
                   unsigned char out[HASH_SIZE]);

#endif
