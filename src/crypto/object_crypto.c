#include <string.h>
#include <openssl/evp.h>
#include "core/object_types.h"
#include "crypto/object_crypto.h"

static int digest_update_str(EVP_MD_CTX* ctx, const char* s)
{
    if (!s)
        return 1;
    return EVP_DigestUpdate(ctx, s, strlen(s));
}

int compute_object_id(User* user, Object* obj, unsigned char out[32])
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        return 0;

    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    if (user) {
        if (!EVP_DigestUpdate(ctx, user->user_id, 16)) {
            EVP_MD_CTX_free(ctx);
            return 0;
        }
    }

    if (obj->data && obj->size > 0) {
        if (!EVP_DigestUpdate(ctx, obj->data, obj->size)) {
            EVP_MD_CTX_free(ctx);
            return 0;
        }
    }

    if (obj->metadata) {
        if (!digest_update_str(ctx, obj->metadata->category) ||
            !digest_update_str(ctx, obj->metadata->extension) ||
            !digest_update_str(ctx, obj->metadata->filename)) {
            EVP_MD_CTX_free(ctx);
            return 0;
        }
        for (size_t i = 0; i < obj->metadata->metadata_count; i++) {
            if (!digest_update_str(ctx, obj->metadata->metadata_keys[i]) ||
                !digest_update_str(ctx, obj->metadata->metadata_values[i])) {
                EVP_MD_CTX_free(ctx);
                return 0;
            }
        }
    }

    unsigned int len = 32;
    if (!EVP_DigestFinal_ex(ctx, out, &len)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    EVP_MD_CTX_free(ctx);
    return 1;
}

int compute_data_hash(const unsigned char* data, size_t size, unsigned char out[32])
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        return 0;

    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    if (data && size > 0) {
        if (!EVP_DigestUpdate(ctx, data, size)) {
            EVP_MD_CTX_free(ctx);
            return 0;
        }
    }

    unsigned int len = 0;
    if (!EVP_DigestFinal_ex(ctx, out, &len)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    EVP_MD_CTX_free(ctx);
    return 1;
}
