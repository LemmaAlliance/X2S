#ifndef REFRESH_TOKEN_H
#define REFRESH_TOKEN_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#define REFRESH_TOKEN_SIZE 32
#define REFRESH_TOKEN_EXPIRY_SECONDS 604800

typedef struct
{
    unsigned char token[REFRESH_TOKEN_SIZE];
    unsigned char user_id[16];
    time_t        expiry;
} RefreshToken;

typedef struct RefreshTokenStore
{
    RefreshToken* tokens;
    size_t        count;
    size_t        capacity;
} RefreshTokenStore;

RefreshTokenStore* refresh_token_store_create(size_t initial_capacity);
void               refresh_token_store_free(RefreshTokenStore* store);

char* refresh_token_create(RefreshTokenStore*       store,
                           const unsigned char      user_id[16]);

int   refresh_token_validate(RefreshTokenStore*       store,
                             const char*               hex_token,
                             unsigned char             user_id_out[16]);

char* refresh_token_rotate(RefreshTokenStore*       store,
                           const char*               hex_token,
                           unsigned char             user_id_out[16]);

void  refresh_token_revoke(RefreshTokenStore* store, const char* hex_token);
void  refresh_token_cleanup(RefreshTokenStore* store);

int   refresh_token_store_save(RefreshTokenStore* store, const char* data_path);
int   refresh_token_store_load(RefreshTokenStore* store, const char* data_path);

#endif
