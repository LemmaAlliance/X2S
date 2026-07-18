#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "core/format.h"
#include "core/format_registry.h"
#include "crypto/encryption.h"
#include "format/format_v2.h"

static int read_encrypted_body(FILE* f, unsigned char** out, size_t* out_len)
{
    long pos = ftell(f);
    fseek(f, 0, SEEK_END);
    long remaining = ftell(f) - pos;
    fseek(f, pos, SEEK_SET);
    if (remaining < (long)(X2S_NONCE_SIZE + X2S_GCM_TAG_SIZE))
        return 0;

    unsigned char* encrypted = malloc(remaining);
    if (!encrypted)
        return 0;
    if (fread(encrypted, 1, remaining, f) != (size_t)remaining) {
        free(encrypted);
        return 0;
    }

    if (!decrypt(encrypted, remaining, out, out_len)) {
        free(encrypted);
        return 0;
    }
    free(encrypted);
    return 1;
}

static int write_encrypted_body(FILE* f, const unsigned char* plain, size_t plain_len)
{
    unsigned char* encrypted = NULL;
    size_t         enc_len  = 0;
    if (!encrypt(plain, plain_len, &encrypted, &enc_len))
        return 0;

    int ok = fwrite(encrypted, 1, enc_len, f) == enc_len;
    free(encrypted);
    return ok;
}

static const FormatVtable* v1(void)
{
    return lookup_format(X2S_FORMAT_VERSION_1);
}

int read_metadata_v2(FILE* f, Object* out)
{
    if (!encryption_is_active())
        return 0;

    unsigned char* plain     = NULL;
    size_t         plain_len = 0;
    if (!read_encrypted_body(f, &plain, &plain_len))
        return 0;

    FILE* mem = fmemopen(plain, plain_len, "r");
    if (!mem) {
        free(plain);
        return 0;
    }

    const FormatVtable* fmt = v1();
    int ok = fmt && fmt->read_metadata && fmt->read_metadata(mem, out);
    fclose(mem);
    free(plain);
    return ok;
}

int write_metadata_v2(FILE* f, Object* obj)
{
    const FormatVtable* fmt = v1();
    if (!fmt || !fmt->write_metadata)
        return 0;

    char*  body     = NULL;
    size_t body_len = 0;
    FILE*  buf      = open_memstream(&body, &body_len);
    if (!buf)
        return 0;

    int ok = fmt->write_metadata(buf, obj);
    fclose(buf);

    if (ok)
        ok = write_encrypted_body(f, (unsigned char*)body, body_len);
    free(body);
    return ok;
}

int read_index_v2(FILE* f, size_t* capacity, size_t* count, unsigned char** ids)
{
    if (!encryption_is_active())
        return 0;

    unsigned char* plain     = NULL;
    size_t         plain_len = 0;
    if (!read_encrypted_body(f, &plain, &plain_len))
        return 0;

    FILE* mem = fmemopen(plain, plain_len, "r");
    if (!mem) {
        free(plain);
        return 0;
    }

    const FormatVtable* fmt = v1();
    int ok = fmt && fmt->read_index && fmt->read_index(mem, capacity, count, ids);
    fclose(mem);
    free(plain);
    return ok;
}

int write_index_v2(FILE* f, size_t capacity, size_t count, unsigned char* ids)
{
    const FormatVtable* fmt = v1();
    if (!fmt || !fmt->write_index)
        return 0;

    char*  body     = NULL;
    size_t body_len = 0;
    FILE*  buf      = open_memstream(&body, &body_len);
    if (!buf)
        return 0;

    int ok = fmt->write_index(buf, capacity, count, ids);
    fclose(buf);

    if (ok)
        ok = write_encrypted_body(f, (unsigned char*)body, body_len);
    free(body);
    return ok;
}

int read_users_v2(FILE* f, UserStore* store)
{
    if (!encryption_is_active())
        return 0;

    unsigned char* plain     = NULL;
    size_t         plain_len = 0;
    if (!read_encrypted_body(f, &plain, &plain_len))
        return 0;

    FILE* mem = fmemopen(plain, plain_len, "r");
    if (!mem) {
        free(plain);
        return 0;
    }

    const FormatVtable* fmt = v1();
    int ok = fmt && fmt->read_users && fmt->read_users(mem, store);
    fclose(mem);
    free(plain);
    return ok;
}

int write_users_v2(FILE* f, UserStore* store)
{
    const FormatVtable* fmt = v1();
    if (!fmt || !fmt->write_users)
        return 0;

    char*  body     = NULL;
    size_t body_len = 0;
    FILE*  buf      = open_memstream(&body, &body_len);
    if (!buf)
        return 0;

    int ok = fmt->write_users(buf, store);
    fclose(buf);

    if (ok)
        ok = write_encrypted_body(f, (unsigned char*)body, body_len);
    free(body);
    return ok;
}

int read_data_hash_v2(FILE* f, unsigned char hash[32])
{
    if (!encryption_is_active())
        return 0;

    unsigned char* plain     = NULL;
    size_t         plain_len = 0;
    if (!read_encrypted_body(f, &plain, &plain_len))
        return 0;

    FILE* mem = fmemopen(plain, plain_len, "r");
    if (!mem) {
        free(plain);
        return 0;
    }

    const FormatVtable* fmt = v1();
    int ok = fmt && fmt->read_data_hash && fmt->read_data_hash(mem, hash);
    fclose(mem);
    free(plain);
    return ok;
}
