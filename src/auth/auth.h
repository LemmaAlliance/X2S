#ifndef AUTH_H
#define AUTH_H

#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#define SALT_SIZE 16
#define HASH_SIZE 32
#define TOKEN_SIZE 32
#define MAX_USERNAME 63
#define MAX_PASSWORD 1024

typedef struct {
    char username[MAX_USERNAME + 1];
    unsigned char user_id[16];
    unsigned char password_hash[HASH_SIZE];
    unsigned char salt[SALT_SIZE];
} UserAccount;

typedef struct {
    UserAccount *accounts;
    size_t count;
    size_t capacity;
} UserStore;

typedef struct {
    unsigned char token[TOKEN_SIZE];
    unsigned char user_id[16];
    time_t expiry;
} Session;

typedef struct {
    Session *sessions;
    size_t count;
    size_t capacity;
} SessionStore;

typedef struct {
    UserStore *users;
    SessionStore *sessions;
} TokenStore;

UserStore *user_store_create(size_t initial_capacity);
void user_store_free(UserStore *store);
int user_store_register(UserStore *store, const char *username,
                        const char *password, unsigned char user_id_out[16]);
int user_store_authenticate(UserStore *store, const char *username,
                            const char *password, unsigned char user_id_out[16]);
void user_store_get_username(UserStore *store, const unsigned char user_id[16],
                             char *out, size_t out_size);
int user_store_save(UserStore *store, const char *path);
int user_store_load(UserStore *store, const char *path);

SessionStore *session_store_create(size_t initial_capacity);
void session_store_free(SessionStore *store);
char *session_create(SessionStore *store, const unsigned char user_id[16]);
int session_lookup(SessionStore *store, const unsigned char token[TOKEN_SIZE],
                   unsigned char user_id_out[16]);
void session_destroy(SessionStore *store, const unsigned char token[TOKEN_SIZE]);

void hash_password(const char *password, const unsigned char salt[SALT_SIZE],
                   unsigned char out[HASH_SIZE]);

int hex_to_bytes(const char *hex, unsigned char *out, size_t out_len);
void bytes_to_hex(const unsigned char *bytes, size_t len, char *out);

void check_token_expiry(SessionStore *store);

#endif
