#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include "obj_structs.h"

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
                    size_t data_len, cat_len, ext_len, file_len;
                    /* Skip lengths and security headers to find the hash */
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

    FILE *f = fopen(path, "wb");
    if (!f) return 0;

    size_t category_len  = (obj->metadata && obj->metadata->category) ? strlen(obj->metadata->category)  : 0;
    size_t extension_len = (obj->metadata && obj->metadata->extension) ? strlen(obj->metadata->extension) : 0;
    size_t filename_len  = (obj->metadata && obj->metadata->filename) ? strlen(obj->metadata->filename)  : 0;

    /*  basic lengths  */
    if (fwrite(&obj->size, sizeof(size_t), 1, f) != 1 ||
        fwrite(&category_len, sizeof(size_t), 1, f) != 1 ||
        fwrite(&extension_len, sizeof(size_t), 1, f) != 1 ||
        fwrite(&filename_len, sizeof(size_t), 1, f) != 1) {
        fclose(f);
        return 0;
    }

    /*  OWNER  */
    if (fwrite(obj->owner, 1, 16, f) != 16) { fclose(f); return 0; }

    /*  ACL  */
    size_t acl_count = (obj->acl) ? obj->acl->count : 0;
    if (fwrite(&acl_count, sizeof(size_t), 1, f) != 1) { fclose(f); return 0; }
    if (obj->acl && acl_count > 0) {
        for (size_t i = 0; i < acl_count; i++) {
            ACLEntry *e = &obj->acl->entries[i];
            if (fwrite(e->user_id, 1, 16, f) != 16 || fwrite(&e->permissions, sizeof(uint32_t), 1, f) != 1) {
                fclose(f); return 0;
            }
        }
    }

    /*  WRITE DATA REFERENCE  */
    unsigned char data_hash[32];
    // TODO: Data hash is possibly redundant when we have more than one reference?
    if (!compute_data_hash(obj->data, data_hash)) { fclose(f); return 0; }
    if (fwrite(data_hash, 1, 32, f) != 32) { fclose(f); return 0; }

    /*  METADATA (Strings)  */
    if (category_len > 0 && fwrite(obj->metadata->category, 1, category_len, f) != category_len) { fclose(f); return 0; }
    if (extension_len > 0 && fwrite(obj->metadata->extension, 1, extension_len, f) != extension_len) { fclose(f); return 0; }
    if (filename_len > 0 && fwrite(obj->metadata->filename, 1, filename_len, f) != filename_len) { fclose(f); return 0; }

    /*  METADATA (KV pairs)  */
    size_t metadata_count = 0;
    if (obj->metadata) metadata_count = obj->metadata->metadata_count;
    if (fwrite(&metadata_count, sizeof(size_t), 1, f) != 1) { fclose(f); return 0; }
    for (size_t i = 0; i < metadata_count; i++) {
        size_t key_len   = strlen(obj->metadata->metadata_keys[i]);
        size_t value_len = strlen(obj->metadata->metadata_values[i]);
        if (fwrite(&key_len, sizeof(size_t), 1, f) != 1 ||
            fwrite(obj->metadata->metadata_keys[i], 1, key_len, f) != key_len ||
            fwrite(&value_len, sizeof(size_t), 1, f) != 1 ||
            fwrite(obj->metadata->metadata_values[i], 1, value_len, f) != value_len) {
            fclose(f); return 0;
        }
    }

    fclose(f);

    /*  WRITE SHARED DATA BLOB ONLY IF IT DOES NOT EXIST  */
    char data_path[PATH_MAX_LEN + 128];
    char data_hex[65];
    id_to_hex(data_hash, data_hex);
    snprintf(data_path, sizeof(data_path), "%s/data_%s", store->store_path, data_hex);

    FILE *df = fopen(data_path, "rb");
    if (df) {
        fclose(df); // Content already exists on disk! Storage saved.
    } else {
        df = fopen(data_path, "wb");
        if (df) {
            if (obj->size > 0 && obj->data) {
                fseek(obj->data, 0, SEEK_SET);

                char buffer[4096];
                size_t bytes_to_read = obj->size;
                size_t bytes_read;

                /* Basically we iterate in chunks of 4096 over file */
                while (bytes_to_read > 0 &&
                        (bytes_read = fread(buffer, 1, 
                        (bytes_to_read < sizeof(buffer)) ? 
                        bytes_to_read : sizeof(buffer), obj->data)) > 0) {
                    fwrite(buffer, 1, bytes_read, df);
                    bytes_to_read -= bytes_read;
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

    size_t data_len = 0, category_len = 0, extension_len = 0, filename_len = 0;

    if (fread(&data_len, sizeof(size_t), 1, f) != 1 ||
        fread(&category_len, sizeof(size_t), 1, f) != 1 ||
        fread(&extension_len, sizeof(size_t), 1, f) != 1 ||
        fread(&filename_len, sizeof(size_t), 1, f) != 1) {
        fclose(f); return 0;
    }

    if (fread(out->owner, 1, 16, f) != 16) { fclose(f); return 0; }

    /*  ACL  */
    size_t acl_count = 0;
    if (fread(&acl_count, sizeof(size_t), 1, f) != 1) { fclose(f); return 0; }
    out->acl = calloc(1, sizeof(ACL));
    if (acl_count > 0) {
        out->acl->entries = calloc(acl_count, sizeof(ACLEntry));
        out->acl->count = acl_count;
        for (size_t i = 0; i < acl_count; i++) {
            ACLEntry *e = &out->acl->entries[i];
            if (fread(e->user_id, 1, 16, f) != 16 || fread(&e->permissions, sizeof(uint32_t), 1, f) != 1) {
                free(out->acl->entries); free(out->acl); fclose(f); return 0;
            }
        }
    }

    /*  READ DATA HASH REFERENCE  */
    unsigned char data_hash[32];
    if (fread(data_hash, 1, 32, f) != 32) {
        if (out->acl->entries) { 
            free(out->acl->entries); 
        } 
        free(out->acl); 
        fclose(f); 
        return 0;
    }

    /*  METADATA  */
    Metadata *metadata = calloc(1, sizeof(Metadata));
    metadata->category  = read_string_field(f, category_len);
    metadata->extension = read_string_field(f, extension_len);
    metadata->filename  = read_string_field(f, filename_len);

    /*  METADATA (KV pairs) — optional; gracefully handle old-format files  */
    size_t metadata_count = 0;
    if (fread(&metadata_count, sizeof(size_t), 1, f) != 1) {
        if (feof(f)) {
            metadata_count = 0; /* EOF: old format with no KV metadata */
        } else {
            free_metadata(metadata);
            fclose(f);
            return 0;
        }
    }
    if (metadata_count > 0) {
        metadata->metadata_keys   = calloc(metadata_count, sizeof(char *));
        metadata->metadata_values = calloc(metadata_count, sizeof(char *));
        if (!metadata->metadata_keys || !metadata->metadata_values) {
            free_metadata(metadata); fclose(f); return 0;
        }
        metadata->metadata_count = metadata_count;
        for (size_t i = 0; i < metadata_count; i++) {
            size_t key_len = 0;
            if (fread(&key_len, sizeof(size_t), 1, f) != 1) {
                free_metadata(metadata); fclose(f); return 0;
            }
            metadata->metadata_keys[i] = read_string_field(f, key_len);
            if (!metadata->metadata_keys[i]) {
                free_metadata(metadata); fclose(f); return 0;
            }
            size_t value_len = 0;
            if (fread(&value_len, sizeof(size_t), 1, f) != 1) {
                free_metadata(metadata); fclose(f); return 0;
            }
            metadata->metadata_values[i] = read_string_field(f, value_len);
            if (!metadata->metadata_values[i]) {
                free_metadata(metadata); fclose(f); return 0;
            }
        }
    }
    fclose(f);

    /*  READ THE ACTUAL BLOB FROM DEDUPLICATED STORAGE  */
    void *data = NULL;
    if (data_len > 0) {
        char data_path[PATH_MAX_LEN + 128];
        char data_hex[65];
        id_to_hex(data_hash, data_hex);
        snprintf(data_path, sizeof(data_path), "%s/data_%s", store->store_path, data_hex);

        FILE *df = fopen(data_path, "rb");
        if (!df) {
            if (out->acl->entries) { 
                free(out->acl->entries); 
            } 
            free(out->acl); 
            free_metadata(metadata); 
            return 0;
        }
        
        data = malloc(data_len);
        if (!data || fread(data, 1, data_len, df) != data_len) {
            free(data); 
            fclose(df); 
            if (out->acl->entries) { 
                free(out->acl->entries); 
            } 
            free(out->acl); 
            free_metadata(metadata); 
            return 0;
        }
        fclose(df);
    }

    /*  finalize object  */
    memcpy(out->id, id, 32);
    out->size = data_len;
    out->data = data;
    out->metadata = metadata;
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

int load_index(ObjectStore *store) {
    char index_path[PATH_MAX_LEN + 16];
    snprintf(index_path, sizeof(index_path),
             "%s/__index", store->store_path);

    FILE *f = fopen(index_path, "rb");
    if (!f) return 0; // first run, no index yet

    size_t capacity = 0;
    size_t count = 0;

    if (fread(&capacity, sizeof(size_t), 1, f) != 1 ||
        fread(&count, sizeof(size_t), 1, f) != 1) {
        fclose(f);
        return 0;
    }

    // If stored capacity differs, adjust store BEFORE inserting
    if (capacity != store->capacity) {
        ObjectNode **new_buckets =
            calloc(capacity, sizeof(ObjectNode *));
        if (!new_buckets) {
            fclose(f);
            return 0;
        }

        free(store->buckets);
        store->buckets = new_buckets;
        store->capacity = capacity;
    }

    store->count = 0; // we'll recompute safely

    for (size_t i = 0; i < count; i++) {
        unsigned char id[32];

        if (fread(id, 1, 32, f) != 32) {
            fclose(f);
            return 0;
        }

        Object *index_obj = calloc(1, sizeof(Object));
        if (!index_obj) {
            fclose(f);
            return 0;
        }

        /* Read the object file to populate the index's security fields */
        Object temporary_load = {0};
        if (read_object_file(store, id, &temporary_load)) {
            // Copy security permissions into the index item
            memcpy(index_obj->owner, temporary_load.owner, 16);
            index_obj->acl = temporary_load.acl;
            index_obj->size = temporary_load.size;
            
            // Free the data and strings we don't need in the lightweight index
            free(temporary_load.data);
            free_metadata(temporary_load.metadata);
        } else {
            // Fallback if file is corrupted/missing
            memcpy(index_obj->id, id, 32);
        }

        ObjectNode *node = malloc(sizeof(ObjectNode));
        if (!node) {
            if (index_obj->acl) {
                free(index_obj->acl->entries);
                free(index_obj->acl);
            }
            free(index_obj);
            fclose(f);
            return 0;
        }

        size_t index = index_for(store, id);

        node->obj = index_obj;
        node->next = store->buckets[index];
        store->buckets[index] = node;

        store->count++;
    }

    fclose(f);
    return 1;
}