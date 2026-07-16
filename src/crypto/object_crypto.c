#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include "core/object_types.h"
#include "crypto/object_crypto.h"

static int hash_file_stream(EVP_MD_CTX *ctx, FILE *file) {
    unsigned char buffer[4096];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (!EVP_DigestUpdate(ctx, buffer, bytes_read)) return 0;
    }
    return !ferror(file);
}

int compute_object_id(User *user, Object *obj, unsigned char out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

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
        if (fseek(obj->data, 0, SEEK_SET) != 0) {
            EVP_MD_CTX_free(ctx);
            return 0;
        }

        if (!hash_file_stream(ctx, obj->data)) {
            EVP_MD_CTX_free(ctx);
            return 0;
        }

        if (ferror(obj->data)) {
            EVP_MD_CTX_free(ctx);
            return 0;
        }

        if (fseek(obj->data, 0, SEEK_SET) != 0) {
            EVP_MD_CTX_free(ctx);
            return 0;
        }
    }

    if (obj->metadata) {
        if (obj->metadata->category &&
            !EVP_DigestUpdate(ctx, obj->metadata->category,
                              strlen(obj->metadata->category))) {
            EVP_MD_CTX_free(ctx);
            return 0;
        }
        if (obj->metadata->extension &&
            !EVP_DigestUpdate(ctx, obj->metadata->extension,
                              strlen(obj->metadata->extension))) {
            EVP_MD_CTX_free(ctx);
            return 0;
        }
        if (obj->metadata->filename &&
            !EVP_DigestUpdate(ctx, obj->metadata->filename,
                              strlen(obj->metadata->filename))) {
            EVP_MD_CTX_free(ctx);
            return 0;
        }
        for (size_t i = 0; i < obj->metadata->metadata_count; i++) {
            if (obj->metadata->metadata_keys[i] &&
                !EVP_DigestUpdate(ctx, obj->metadata->metadata_keys[i],
                                  strlen(obj->metadata->metadata_keys[i]))) {
                EVP_MD_CTX_free(ctx);
                return 0;
            }
            if (obj->metadata->metadata_values[i] &&
                !EVP_DigestUpdate(ctx, obj->metadata->metadata_values[i],
                                  strlen(obj->metadata->metadata_values[i]))) {
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

int compute_data_hash(FILE *file, unsigned char out[32]) {
    if (!file) return 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    if (!hash_file_stream(ctx, file)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    if (ferror((FILE *)file)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    unsigned int len = 0;
    if (!EVP_DigestFinal_ex(ctx, out, &len)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    EVP_MD_CTX_free(ctx);
    return 1;
}
