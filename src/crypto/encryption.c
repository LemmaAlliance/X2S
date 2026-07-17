#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "crypto/encryption.h"

static unsigned char master_key[X2S_KEY_SIZE];
static int           key_loaded = 0;

int encryption_init(const unsigned char key[X2S_KEY_SIZE])
{
    if (!key)
        return 0;
    memcpy(master_key, key, X2S_KEY_SIZE);
    key_loaded = 1;
    return 1;
}

int encryption_is_active(void)
{
    return key_loaded;
}

int encrypt(const unsigned char* plaintext, size_t plaintext_len,
            unsigned char** output, size_t* output_len)
{
    if (!key_loaded || !plaintext || !output || !output_len)
        return 0;

    unsigned char nonce[X2S_NONCE_SIZE];
    if (RAND_bytes(nonce, X2S_NONCE_SIZE) != 1)
        return 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return 0;

    int ok = 0;
    *output_len = X2S_NONCE_SIZE + plaintext_len + X2S_GCM_TAG_SIZE;
    *output = malloc(*output_len);
    if (!*output)
        goto cleanup;

    memcpy(*output, nonce, X2S_NONCE_SIZE);

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        goto cleanup;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, X2S_NONCE_SIZE, NULL))
        goto cleanup;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, master_key, nonce))
        goto cleanup;

    int len = 0;
    if (!EVP_EncryptUpdate(ctx, *output + X2S_NONCE_SIZE, &len, plaintext, plaintext_len))
        goto cleanup;
    size_t ct_len = len;

    if (!EVP_EncryptFinal_ex(ctx, *output + X2S_NONCE_SIZE + ct_len, &len))
        goto cleanup;
    ct_len += len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, X2S_GCM_TAG_SIZE,
                             *output + X2S_NONCE_SIZE + ct_len))
        goto cleanup;
    ct_len += X2S_GCM_TAG_SIZE;

    *output_len = X2S_NONCE_SIZE + ct_len;
    ok = 1;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        free(*output);
        *output = NULL;
        *output_len = 0;
    }
    return ok;
}

int decrypt(const unsigned char* input, size_t input_len,
            unsigned char** plaintext, size_t* plaintext_len)
{
    if (!key_loaded || !input || !plaintext || !plaintext_len)
        return 0;
    if (input_len < X2S_NONCE_SIZE + X2S_GCM_TAG_SIZE)
        return 0;

    *plaintext_len = input_len - X2S_NONCE_SIZE - X2S_GCM_TAG_SIZE;
    *plaintext = malloc(*plaintext_len);
    if (!*plaintext)
        return 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(*plaintext);
        *plaintext = NULL;
        return 0;
    }

    int ok = 0;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        goto cleanup;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, X2S_NONCE_SIZE, NULL))
        goto cleanup;
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, master_key, input))
        goto cleanup;

    int len = 0;
    size_t ct_len = input_len - X2S_NONCE_SIZE - X2S_GCM_TAG_SIZE;
    if (!EVP_DecryptUpdate(ctx, *plaintext, &len, input + X2S_NONCE_SIZE, ct_len))
        goto cleanup;
    size_t pt_len = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, X2S_GCM_TAG_SIZE,
                             (void*)(input + X2S_NONCE_SIZE + ct_len)))
        goto cleanup;

    if (!EVP_DecryptFinal_ex(ctx, *plaintext + pt_len, &len))
        goto cleanup;
    pt_len += len;

    *plaintext_len = pt_len;
    ok = 1;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        free(*plaintext);
        *plaintext = NULL;
        *plaintext_len = 0;
    }
    return ok;
}
