#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include "obj_structs.h"
#include "format.h"
#include "format_registry.h"

#define PATH_MAX_LEN 4096

/* ACL Helper */
int has_permission(Object *obj, unsigned char user_id[16], uint32_t perm) {
    if (!obj->acl) return 0;

    for (size_t i = 0; i < obj->acl->count; i++) {
        ACLEntry *e = &obj->acl->entries[i];

        if (memcmp(e->user_id, user_id, 16) == 0) {
            return (e->permissions & perm) != 0;
        }
    }

    return 0;
}

/* Metadata helpers */

void free_metadata(Metadata *metadata) {
    if (!metadata) return;
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

/* SHA-256 object hashing */

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
        /* obj->data is a FILE* stream (data is now streamed to/from disk),
         * not an in-memory buffer, so it must be hashed in chunks like
         * compute_data_hash() does below -- not passed directly to
         * EVP_DigestUpdate, which would hash the bytes at the FILE*
         * pointer's address instead of the file's contents. */
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

        /* Rewind so downstream code (e.g. write_object_file's call to
         * compute_data_hash) reads the stream from the start too. */
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

/* Hash table hashing (reduce SHA-256 -> index) */

size_t hash_id(const unsigned char id[32]) {
    size_t h = 1469598103934665603ULL; // FNV offset basis

    for (int i = 0; i < 32; i++) {
        h ^= id[i];
        h *= 1099511628211ULL;
    }

    return h;
}

size_t index_for(ObjectStore *store, const unsigned char id[32]) {
    return hash_id(id) % store->capacity;
}

int check_object_permission(ObjectStore *store, const unsigned char id[32],
                             unsigned char user_id[16], uint32_t perm) {
    if (!store || !id) return -1;

    size_t index = index_for(store, id);
    ObjectNode *node = store->buckets[index];

    while (node) {
        if (memcmp(node->obj->id, id, 32) == 0)
            return has_permission(node->obj, user_id, perm) ? 1 : 0;
        node = node->next;
    }

    return -1;
}

/* Convert 32-byte binary ID to 64-char hex string (+ null terminator) */

void id_to_hex(const unsigned char id[32], char out[65]) {
    for (int i = 0; i < 32; i++) {
        snprintf(out + i * 2, 3, "%02x", id[i]);
    }
    out[64] = '\0';
}

/* Build the full path for an object file: <store_path>/<hex_id> */

void object_path(ObjectStore *store, const unsigned char id[32],
                        char *out, size_t out_len) {
    char hex[65];
    id_to_hex(id, hex);
    snprintf(out, out_len, "%s/%s", store->store_path, hex);
}

int count_data_blob_references(ObjectStore *store, const unsigned char target_data_hash[32], const unsigned char current_meta_id[32]) {
    int reference_count = 0;

    for (size_t i = 0; i < store->capacity; i++) {
        ObjectNode *node = store->buckets[i];
        while (node) {
            /* Skip the metadata file we are currently trying to delete */
            if (memcmp(node->obj->id, current_meta_id, 32) != 0) {
                
                /* Open the metadata file to read its embedded data reference hash */
                char path[PATH_MAX_LEN + 128];
                object_path(store, node->obj->id, path, sizeof(path));
                FILE *f = fopen(path, "rb");
                if (f) {
                    uint8_t version = 0;
                    int hret = try_read_header(f, X2S_FILE_TYPE_METADATA, &version);
                    if (hret == -1) { fclose(f); goto next_node; }

                    size_t data_len, cat_len, ext_len, file_len;
                    if (fread(&data_len, sizeof(size_t), 1, f) == 1 &&
                        fread(&cat_len, sizeof(size_t), 1, f) == 1 &&
                        fread(&ext_len, sizeof(size_t), 1, f) == 1 &&
                        fread(&file_len, sizeof(size_t), 1, f) == 1) {
                        
                        fseek(f, 16, SEEK_CUR); // Skip owner uuid
                        size_t acl_count = 0;
                        if (fread(&acl_count, sizeof(size_t), 1, f) == 1) {
                            fseek(f, acl_count * (16 + sizeof(uint32_t)), SEEK_CUR); // Skip ACL entry array
                            
                            unsigned char check_hash[32];
                            if (fread(check_hash, 1, 32, f) == 32) {
                                if (memcmp(check_hash, target_data_hash, 32) == 0) {
                                    reference_count++;
                                }
                            }
                        }
                    }
                    fclose(f);
                }
            }
next_node:
            node = node->next;
        }
    }
    return reference_count;
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

    /* Check if we had a file error */
    if (ferror((FILE *)file)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    /* Hash final part */
    unsigned int len = 0;
    if (!EVP_DigestFinal_ex(ctx, out, &len)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    /* Clean up mem */
    EVP_MD_CTX_free(ctx);
    return 1;
}


/* Disk I/O
 *
 * File layout (binary):
 *   [size_t data_len]
 *   [size_t category_len]  (excludes null terminator)
 *   [size_t extension_len]
 *   [size_t filename_len]
 *   [uint8_t data[data_len]]
 *   [char category[category_len]]
 *   [char extension[extension_len]]
 *   [char filename[filename_len]]
 *   [size_t metadata_count]
 *   for each KV pair:
 *     [size_t key_len][char key[key_len]]
 *     [size_t value_len][char value[value_len]]
 */

int write_object_file(ObjectStore *store, Object *obj) {
    char path[PATH_MAX_LEN + 128];
    object_path(store, obj->id, path, sizeof(path));

    const FormatVtable *fmt = latest_format();
    if (!fmt || !fmt->write_metadata) return 0;

    if (!compute_data_hash(obj->data, obj->data_hash)) return 0;

    FILE *f = fopen(path, "wb");
    if (!f) return 0;

    if (!try_write_header(f, X2S_FILE_TYPE_METADATA)) {
        fclose(f); return 0;
    }

    if (!fmt->write_metadata(f, obj)) {
        fclose(f); return 0;
    }

    fclose(f);

    /*  WRITE SHARED DATA BLOB ONLY IF IT DOES NOT EXIST  */
    char data_path[PATH_MAX_LEN + 128];
    char data_hex[65];
    id_to_hex(obj->data_hash, data_hex);
    snprintf(data_path, sizeof(data_path), "%s/data_%s", store->store_path, data_hex);

    FILE *df = fopen(data_path, "rb");
    if (df) {
        fclose(df);
    } else {
        df = fopen(data_path, "wb");
        if (df) {
            if (obj->size > 0 && obj->data) {
                fseek(obj->data, 0, SEEK_SET);
                char buffer[4096];
                size_t bytes_to_read = obj->size;
                while (bytes_to_read > 0) {
                    size_t chunk = (bytes_to_read < sizeof(buffer)) ? bytes_to_read : sizeof(buffer);
                    size_t n = fread(buffer, 1, chunk, obj->data);
                    if (n == 0) break;
                    fwrite(buffer, 1, n, df);
                    bytes_to_read -= n;
                }
            }
            fclose(df);
        }
    }

    return 1;
}

/* Read a length-prefixed string field from a file into a heap-allocated buffer */

char *read_string_field(FILE *f, size_t len) {
    if (len == 0) return NULL;

    char *buf = malloc(len + 1);
    if (!buf) return NULL;

    if (fread(buf, 1, len, f) != len) {
        free(buf);
        return NULL;
    }

    buf[len] = '\0';
    return buf;
}

int read_object_file(ObjectStore *store, const unsigned char id[32], Object *out) {
    char path[PATH_MAX_LEN + 128];
    object_path(store, id, path, sizeof(path));

    FILE *f = fopen(path, "rb");
    if (!f) return 0;

    uint8_t version = 0;
    int hret = try_read_header(f, X2S_FILE_TYPE_METADATA, &version);
    if (hret == -1) { fclose(f); return 0; }

    const FormatVtable *fmt = lookup_format(version);
    if (!fmt || !fmt->read_metadata) { fclose(f); return 0; }

    if (!fmt->read_metadata(f, out)) { fclose(f); return 0; }
    fclose(f);

    memcpy(out->id, id, 32);
    out->data = NULL;

    if (out->size > 0) {
        char data_path[PATH_MAX_LEN + 128];
        char data_hex[65];
        id_to_hex(out->data_hash, data_hex);
        snprintf(data_path, sizeof(data_path), "%s/data_%s", store->store_path, data_hex);

        FILE *df = fopen(data_path, "rb");
        if (!df) {
            if (out->acl && out->acl->entries) free(out->acl->entries);
            free(out->acl);
            free_metadata(out->metadata);
            return 0;
        }

        out->data = malloc(out->size);
        if (!out->data || fread(out->data, 1, out->size, df) != out->size) {
            free(out->data); out->data = NULL;
            fclose(df);
            if (out->acl && out->acl->entries) free(out->acl->entries);
            free(out->acl);
            free_metadata(out->metadata);
            return 0;
        }
        fclose(df);
    }

    return 1;
}

void delete_metadata_file(ObjectStore *store, const unsigned char id[32]) {
    char path[PATH_MAX_LEN + 128];
    object_path(store, id, path, sizeof(path));
    remove(path);
}

void delete_data_blob_file(ObjectStore *store, const unsigned char data_hash[32]) {
    char data_path[PATH_MAX_LEN + 128];
    char data_hex[65];
    id_to_hex(data_hash, data_hex);
    snprintf(data_path, sizeof(data_path), "%s/data_%s", store->store_path, data_hex);
    remove(data_path);
}

int try_read_header(FILE *f, uint8_t expected_type, uint8_t *out_version) {
    x2s_file_header_t hdr;
    long start = ftell(f);

    if (fread(&hdr, sizeof(hdr), 1, f) != 1) {
        clearerr(f);
        fseek(f, start, SEEK_SET);
        return 0;
    }

    if (hdr.magic[0] == X2S_MAGIC_0 && hdr.magic[1] == X2S_MAGIC_1 &&
        hdr.file_type == expected_type) {
        if (hdr.version > X2S_FORMAT_VERSION_1) {
            return -1;
        }
        *out_version = hdr.version;
        return 1;
    }

    fseek(f, start, SEEK_SET);
    return 0;
}

int try_write_header(FILE *f, uint8_t file_type) {
    return write_header(f, file_type, X2S_FORMAT_VERSION_1);
}

int load_index(ObjectStore *store) {
    char index_path[PATH_MAX_LEN + 16];
    snprintf(index_path, sizeof(index_path),
             "%s/__index", store->store_path);

    FILE *f = fopen(index_path, "rb");
    if (!f) return 0;

    uint8_t version = 0;
    int hret = try_read_header(f, X2S_FILE_TYPE_INDEX, &version);
    if (hret == -1) { fclose(f); return -1; }

    const FormatVtable *fmt = lookup_format(version);
    if (!fmt || !fmt->read_index) { fclose(f); return 0; }

    size_t capacity = 0;
    size_t count = 0;
    unsigned char *ids = NULL;

    if (!fmt->read_index(f, &capacity, &count, &ids)) {
        fclose(f);
        return 0;
    }
    fclose(f);

    if (capacity != store->capacity) {
        ObjectNode **new_buckets = calloc(capacity, sizeof(ObjectNode *));
        if (!new_buckets) { free(ids); return 0; }
        free(store->buckets);
        store->buckets = new_buckets;
        store->capacity = capacity;
    }

    store->count = 0;

    for (size_t i = 0; i < count; i++) {
        unsigned char *id = ids + i * 32;

        Object *index_obj = calloc(1, sizeof(Object));
        if (!index_obj) { free(ids); return 0; }

        Object temporary_load = {0};
        if (read_object_file(store, id, &temporary_load)) {
            memcpy(index_obj->id, id, 32);
            memcpy(index_obj->owner, temporary_load.owner, 16);
            index_obj->acl = temporary_load.acl;
            index_obj->size = temporary_load.size;
            free(temporary_load.data);
            free_metadata(temporary_load.metadata);
        } else {
            memcpy(index_obj->id, id, 32);
        }

        ObjectNode *node = malloc(sizeof(ObjectNode));
        if (!node) {
            if (index_obj->acl) {
                free(index_obj->acl->entries);
                free(index_obj->acl);
            }
            free(index_obj);
            free(ids);
            return 0;
        }

        size_t idx = index_for(store, id);
        node->obj = index_obj;
        node->next = store->buckets[idx];
        store->buckets[idx] = node;
        store->count++;
    }

    free(ids);
    return 1;
}