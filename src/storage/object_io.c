#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include "core/hex_utils.h"
#include "core/object_types.h"
#include "crypto/object_crypto.h"
#include "crypto/encryption.h"
#include "storage/object_serialization.h"
#include "storage/object_io.h"
#include "core/format.h"
#include "core/format_registry.h"

#define PATH_MAX_LEN 4096

void free_metadata(Metadata* metadata)
{
    if (!metadata)
        return;
    free(metadata->category);
    free(metadata->extension);
    free(metadata->filename);
    for (size_t i = 0; i < metadata->metadata_count; i++) {
        free(metadata->metadata_keys ? metadata->metadata_keys[i] : NULL);
        free(metadata->metadata_values ? metadata->metadata_values[i] : NULL);
    }
    free(metadata->metadata_keys);
    free(metadata->metadata_values);
    free(metadata);
}

DecryptedStream decrypt_file_to_mem(FILE* f)
{
    DecryptedStream result = {NULL, NULL};

    long pos = ftell(f);
    fseek(f, 0, SEEK_END);
    long remaining = ftell(f) - pos;
    fseek(f, pos, SEEK_SET);
    if (remaining < (long)(X2S_NONCE_SIZE + X2S_GCM_TAG_SIZE))
        return result;

    unsigned char* encrypted = malloc(remaining);
    if (!encrypted)
        return result;
    if (fread(encrypted, 1, remaining, f) != (size_t)remaining) {
        free(encrypted);
        return result;
    }

    unsigned char* plaintext     = NULL;
    size_t         plaintext_len = 0;
    if (!decrypt(encrypted, remaining, &plaintext, &plaintext_len)) {
        free(encrypted);
        return result;
    }
    free(encrypted);

    result.buffer = plaintext;
    result.stream = fmemopen(plaintext, plaintext_len, "r");
    if (!result.stream) {
        free(plaintext);
        result.buffer = NULL;
    }
    return result;
}

void close_decrypted_stream(DecryptedStream* ds)
{
    if (!ds)
        return;
    if (ds->stream)
        fclose(ds->stream);
    free(ds->buffer);
    ds->stream = NULL;
    ds->buffer = NULL;
}

int write_encrypted_body(FILE* f, const unsigned char* body, size_t body_len)
{
    unsigned char* encrypted     = NULL;
    size_t         encrypted_len = 0;
    if (!encrypt(body, body_len, &encrypted, &encrypted_len))
        return 0;

    int ok = fwrite(encrypted, 1, encrypted_len, f) == encrypted_len;
    free(encrypted);
    return ok;
}

void object_path(ObjectStore* store, const unsigned char id[OBJECT_ID_SIZE], char* out,
                 size_t out_len)
{
    char hex[OBJECT_ID_HEX_SIZE];
    bytes_to_hex(id, OBJECT_ID_SIZE, hex);
    hex[OBJECT_ID_SIZE * 2] = '\0';
    snprintf(out, out_len, "%s/%s", store->store_path, hex);
}

static int write_data_blob(ObjectStore* store, Object* obj)
{
    if (obj->size == 0 || !obj->data)
        return 1;

    char data_hex[OBJECT_ID_HEX_SIZE];
    bytes_to_hex(obj->data_hash, OBJECT_ID_SIZE, data_hex);
    data_hex[OBJECT_ID_SIZE * 2] = '\0';

    char data_path[PATH_MAX_LEN + 128];
    snprintf(data_path, sizeof(data_path), "%s/data_%s", store->store_path, data_hex);

    FILE* df = fopen(data_path, "rb");
    if (df) {
        fclose(df);
        return 1;
    }

    df = fopen(data_path, "wb");
    if (!df)
        return 0;

    int ok;
    if (encryption_is_active()) {
        unsigned char hdr[4] = {X2S_MAGIC_0, X2S_MAGIC_1, X2S_FILE_TYPE_DATA, 1};
        ok = fwrite(hdr, 1, 4, df) == 4 && write_encrypted_body(df, obj->data, obj->size);
    } else {
        ok = fwrite(obj->data, 1, obj->size, df) == obj->size;
    }
    fclose(df);
    return ok;
}

int write_object_file(ObjectStore* store, Object* obj)
{
    char path[PATH_MAX_LEN + 128];
    object_path(store, obj->id, path, sizeof(path));

    if (!compute_data_hash(obj->data, obj->size, obj->data_hash))
        return 0;

    FILE* f = fopen(path, "wb");
    if (!f)
        return 0;

    if (!try_write_header(f, X2S_FILE_TYPE_METADATA)) {
        fclose(f);
        return 0;
    }

    uint8_t             wver = encryption_is_active() ? X2S_FORMAT_VERSION_2 : X2S_FORMAT_VERSION_1;
    const FormatVtable* fmt  = lookup_format(wver);
    if (!fmt || !fmt->write_metadata || !fmt->write_metadata(f, obj)) {
        fclose(f);
        return 0;
    }

    fclose(f);
    return write_data_blob(store, obj);
}

static void free_object_partial(Object* out)
{
    if (out->acl) {
        free(out->acl->entries);
        free(out->acl);
    }
    free_metadata(out->metadata);
}

static int read_data_blob(ObjectStore* store, Object* out)
{
    if (out->size == 0)
        return 1;

    char data_path[PATH_MAX_LEN + 128];
    char data_hex[OBJECT_ID_HEX_SIZE];
    bytes_to_hex(out->data_hash, OBJECT_ID_SIZE, data_hex);
    data_hex[OBJECT_ID_SIZE * 2] = '\0';
    snprintf(data_path, sizeof(data_path), "%s/data_%s", store->store_path, data_hex);

    FILE* df = fopen(data_path, "rb");
    if (!df)
        return 0;

    int encrypted_blob = 0;
    if (encryption_is_active()) {
        unsigned char peek[4];
        if (fread(peek, 1, 4, df) == 4 && peek[0] == X2S_MAGIC_0 && peek[1] == X2S_MAGIC_1 &&
            peek[2] == X2S_FILE_TYPE_DATA && peek[3] == 1) {
            encrypted_blob = 1;
        } else {
            fseek(df, 0, SEEK_SET);
        }
    }

    if (encrypted_blob) {
        DecryptedStream ds = decrypt_file_to_mem(df);
        fclose(df);
        if (!ds.stream)
            return 0;

        out->data = malloc(out->size);
        if (!out->data) {
            close_decrypted_stream(&ds);
            return 0;
        }
        size_t n = fread(out->data, 1, out->size, ds.stream);
        close_decrypted_stream(&ds);
        if (n != out->size) {
            free(out->data);
            out->data = NULL;
            return 0;
        }
        return 1;
    }

    out->data = malloc(out->size);
    if (!out->data || fread(out->data, 1, out->size, df) != out->size) {
        free(out->data);
        out->data = NULL;
        fclose(df);
        return 0;
    }
    fclose(df);
    return 1;
}

int read_object_file(ObjectStore* store, const unsigned char id[OBJECT_ID_SIZE], Object* out)
{
    char path[PATH_MAX_LEN + 128];
    object_path(store, id, path, sizeof(path));

    FILE* f = fopen(path, "rb");
    if (!f)
        return 0;

    uint8_t version = 0;
    int     hret    = try_read_header(f, X2S_FILE_TYPE_METADATA, &version);
    if (hret == -1) {
        fclose(f);
        return 0;
    }

    const FormatVtable* fmt = lookup_format(version);
    if (!fmt || !fmt->read_metadata) {
        fclose(f);
        return 0;
    }
    if (!fmt->read_metadata(f, out)) {
        fclose(f);
        return 0;
    }
    fclose(f);

    memcpy(out->id, id, OBJECT_ID_SIZE);
    out->data = NULL;

    if (!read_data_blob(store, out)) {
        free_object_partial(out);
        return 0;
    }

    return 1;
}

void delete_metadata_file(ObjectStore* store, const unsigned char id[32])
{
    char path[PATH_MAX_LEN + 128];
    object_path(store, id, path, sizeof(path));
    remove(path);
}

int read_metadata_data_hash(const char* path, unsigned char hash[OBJECT_ID_SIZE])
{
    FILE* f = fopen(path, "rb");
    if (!f)
        return 0;

    uint8_t version = 0;
    int     hret    = try_read_header(f, X2S_FILE_TYPE_METADATA, &version);
    if (hret != 1) {
        fclose(f);
        return 0;
    }

    const FormatVtable* fmt = lookup_format(version);
    if (!fmt || !fmt->read_data_hash) {
        fclose(f);
        return 0;
    }
    int result = fmt->read_data_hash(f, hash) ? 1 : 0;
    fclose(f);
    return result;
}

void delete_data_blob_file(ObjectStore* store, const unsigned char data_hash[32])
{
    char data_path[PATH_MAX_LEN + 128];
    char data_hex[65];
    bytes_to_hex(data_hash, 32, data_hex);
    data_hex[64] = '\0';
    snprintf(data_path, sizeof(data_path), "%s/data_%s", store->store_path, data_hex);
    remove(data_path);
}

int count_data_blob_references(ObjectStore* store, const unsigned char target_data_hash[32],
                               const unsigned char current_meta_id[32])
{
    int reference_count = 0;

    for (size_t i = 0; i < store->capacity; i++) {
        ObjectNode* node = store->buckets[i];
        while (node) {
            if (memcmp(node->obj->id, current_meta_id, 32) != 0) {
                char path[PATH_MAX_LEN + 128];
                object_path(store, node->obj->id, path, sizeof(path));
                unsigned char check_hash[32];
                if (read_metadata_data_hash(path, check_hash) &&
                    memcmp(check_hash, target_data_hash, 32) == 0) {
                    reference_count++;
                }
            }
            node = node->next;
        }
    }
    return reference_count;
}
