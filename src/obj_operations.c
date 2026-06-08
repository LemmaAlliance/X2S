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
    free(metadata);
}

/* SHA-256 object hashing */

static int compute_object_id(User *user, Object *obj, unsigned char out[32]) {
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
        if (!EVP_DigestUpdate(ctx, obj->data, obj->size)) {
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

static size_t hash_id(const unsigned char id[32]) {
    size_t h = 1469598103934665603ULL; // FNV offset basis

    for (int i = 0; i < 32; i++) {
        h ^= id[i];
        h *= 1099511628211ULL;
    }

    return h;
}

static size_t index_for(ObjectStore *store, const unsigned char id[32]) {
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

static int load_index(ObjectStore *store) {
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

        memcpy(index_obj->id, id, 32);

        ObjectNode *node = malloc(sizeof(ObjectNode));
        if (!node) {
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

/* Convert 32-byte binary ID to 64-char hex string (+ null terminator) */

static void id_to_hex(const unsigned char id[32], char out[65]) {
    for (int i = 0; i < 32; i++) {
        snprintf(out + i * 2, 3, "%02x", id[i]);
    }
    out[64] = '\0';
}

/* Build the full path for an object file: <store_path>/<hex_id> */

static void object_path(ObjectStore *store, const unsigned char id[32],
                        char *out, size_t out_len) {
    char hex[65];
    id_to_hex(id, hex);
    snprintf(out, out_len, "%s/%s", store->store_path, hex);
}

static int count_data_blob_references(ObjectStore *store, const unsigned char target_data_hash[32], const unsigned char current_meta_id[32]) {
    int reference_count = 0;

    for (size_t i = 0; i < store->capacity; i++) {
        ObjectNode *node = store->buckets[i];
        while (node) {
            /* Skip the metadata file we are currently trying to delete */
            if (memcmp(node->obj->id, current_meta_id, 32) != 0) {
                
                /* Open the metadata file to read its embedded data reference hash */
                char path[4096 + 128];
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

static int compute_data_hash(const void *data, size_t size, unsigned char out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

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

    unsigned int len = 32;
    if (!EVP_DigestFinal_ex(ctx, out, &len)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

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
 */

static int write_object_file(ObjectStore *store, Object *obj) {
    char path[512];
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

    /*  WRITE DATA REFERENCE INSTEAD OF RAW DATA  */
    unsigned char data_hash[32];
    if (!compute_data_hash(obj->data, obj->size, data_hash)) { fclose(f); return 0; }
    if (fwrite(data_hash, 1, 32, f) != 32) { fclose(f); return 0; }

    /*  METADATA (Strings)  */
    if (category_len > 0 && fwrite(obj->metadata->category, 1, category_len, f) != category_len) { fclose(f); return 0; }
    if (extension_len > 0 && fwrite(obj->metadata->extension, 1, extension_len, f) != extension_len) { fclose(f); return 0; }
    if (filename_len > 0 && fwrite(obj->metadata->filename, 1, filename_len, f) != filename_len) { fclose(f); return 0; }

    fclose(f);

    /*  WRITE SHARED DATA BLOB ONLY IF IT DOES NOT EXIST  */
    char data_path[4096 + 128];
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
                fwrite(obj->data, 1, obj->size, df);
            }
            fclose(df);
        }
    }

    return 1;
}

/* Read a length-prefixed string field from a file into a heap-allocated buffer */

static char *read_string_field(FILE *f, size_t len) {
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

static int read_object_file(ObjectStore *store, const unsigned char id[32], Object *out) {
    char path[512];
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
    fclose(f);

    /*  READ THE ACTUAL BLOB FROM DEDUPLICATED STORAGE  */
    void *data = NULL;
    if (data_len > 0) {
        char data_path[4096 + 128];
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

static void delete_metadata_file(ObjectStore *store, const unsigned char id[32]) {
    char path[4096 + 128];
    object_path(store, id, path, sizeof(path));
    remove(path);
}

static void delete_data_blob_file(ObjectStore *store, const unsigned char data_hash[32]) {
    char data_path[4096 + 128];
    char data_hex[65];
    id_to_hex(data_hash, data_hex);
    snprintf(data_path, sizeof(data_path), "%s/data_%s", store->store_path, data_hex);
    remove(data_path);
}

/* Create store */

ObjectStore *create_store(size_t initial_capacity, const char *path) {
    if (!path) return NULL;

    ObjectStore *store = malloc(sizeof(ObjectStore));
    if (!store) return NULL;

    store->capacity = (initial_capacity < 8) ? 8 : initial_capacity;
    store->count = 0;

    snprintf(store->store_path, sizeof(store->store_path), "%s", path);

    if (mkdir(store->store_path, 0755) != 0 && errno != EEXIST) {
        free(store);
        return NULL;
    }

    store->buckets = calloc(store->capacity, sizeof(ObjectNode *));
    if (!store->buckets) {
        free(store);
        return NULL;
    }

    // Try to restore previous index (if it exists)
    load_index(store);

    return store;
}

/* Free store (in-memory structures only; files persist on disk) */

void free_store(ObjectStore *store) {
    if (!store) return;

    for (size_t i = 0; i < store->capacity; i++) {
        ObjectNode *node = store->buckets[i];

        while (node) {
            ObjectNode *next = node->next;
            free(node->obj->data);
            if (node->obj->acl) {
                free(node->obj->acl->entries);
                free(node->obj->acl);
            }
            free_metadata(node->obj->metadata);
            free(node->obj);
            free(node);
            node = next;
        }
    }

    free(store->buckets);
    free(store);
}

/* Resize + rehash */

static int resize_store(ObjectStore *store) {
    size_t new_capacity = store->capacity * 2;

    ObjectNode **new_buckets = calloc(new_capacity, sizeof(ObjectNode *));
    if (!new_buckets) return 0;

    for (size_t i = 0; i < store->capacity; i++) {
        ObjectNode *node = store->buckets[i];

        while (node) {
            ObjectNode *next = node->next;

            size_t new_index = hash_id(node->obj->id) % new_capacity;
            node->next = new_buckets[new_index];
            new_buckets[new_index] = node;

            node = next;
        }
    }

    free(store->buckets);
    store->buckets = new_buckets;
    store->capacity = new_capacity;

    return 1;
}

/* Persist the in-memory index to disk as a simple binary file.
 * Format: [size_t count] then count × 32-byte IDs.
 * Written atomically via a temp file + rename. */

static int write_index(ObjectStore *store) {
    char index_path[4096 + 16];
    char tmp_path[4096 + 32];

    snprintf(index_path, sizeof(index_path),
             "%s/__index", store->store_path);

    snprintf(tmp_path, sizeof(tmp_path),
             "%s/__index.tmp", store->store_path);

    FILE *f = fopen(tmp_path, "wb");
    if (!f) return 0;

    // Write capacity first (NEW)
    if (fwrite(&store->capacity, sizeof(size_t), 1, f) != 1) {
        fclose(f);
        remove(tmp_path);
        return 0;
    }

    // Then count
    if (fwrite(&store->count, sizeof(size_t), 1, f) != 1) {
        fclose(f);
        remove(tmp_path);
        return 0;
    }

    // Write all IDs
    for (size_t i = 0; i < store->capacity; i++) {
        ObjectNode *node = store->buckets[i];

        while (node) {
            if (fwrite(node->obj->id, 32, 1, f) != 1) {
                fclose(f);
                remove(tmp_path);
                return 0;
            }
            node = node->next;
        }
    }

    fclose(f);

    if (rename(tmp_path, index_path) != 0) {
        remove(tmp_path);
        return 0;
    }

    return 1;
}

/* Insert — writes data to disk, stores a lightweight index entry in memory */

int put_object(ObjectStore *store, User *user, Object *obj) {
    if (!store || !obj || !user) return 0;

    if (!compute_object_id(user, obj, obj->id)) return 0;

    /*  Ownership assignment  */
    memcpy(obj->owner, user->user_id, 16);

    /*  Default ACL setup  */
    obj->acl = calloc(1, sizeof(ACL));
    if (!obj->acl) return 0;

    obj->acl->entries = malloc(sizeof(ACLEntry));
    if (!obj->acl->entries) {
        free(obj->acl);
        return 0;
    }

    obj->acl->count = 1;

    memcpy(obj->acl->entries[0].user_id, user->user_id, 16);
    obj->acl->entries[0].permissions = PERM_READ | PERM_WRITE | PERM_DELETE;

    /*  Duplicate check  */
    size_t index = index_for(store, obj->id);
    ObjectNode *existing = store->buckets[index];
    while (existing) {
        if (memcmp(existing->obj->id, obj->id, 32) == 0) {
            free(obj->acl->entries);
            free(obj->acl);
            obj->acl = NULL;
            return 1;
        }
        existing = existing->next;
    }

    /*  Write to disk  */
    if (!write_object_file(store, obj)) goto cleanup;

    /*  Resize if needed  */
    if ((double)store->count / store->capacity > 0.75) {
        if (!resize_store(store)) goto cleanup;
        if (!write_index(store)) goto cleanup;
        index = index_for(store, obj->id);
    }

    /*  Index allocation  */
    Object *index_obj = calloc(1, sizeof(Object));
    if (!index_obj) goto cleanup;

    memcpy(index_obj->id, obj->id, 32);
    index_obj->size = obj->size;
    index_obj->data = NULL;
    index_obj->metadata = NULL;

    /* IMPORTANT: carry security metadata in memory index too */
    memcpy(index_obj->owner, obj->owner, 16);
    index_obj->acl = obj->acl;

    ObjectNode *node = malloc(sizeof(ObjectNode));
    if (!node) {
        free(index_obj);
        goto cleanup;
    }

    node->obj = index_obj;
    node->next = store->buckets[index];
    store->buckets[index] = node;

    store->count++;

    /*  Persist index  */
    if (!write_index(store)) {
        store->buckets[index] = node->next;
        store->count;
        obj->acl = NULL;
        free(node->obj->acl->entries);
        free(node->obj->acl);
        free(node->obj);
        free(node);
        return 0;
    }

    return 1;

cleanup:
    free(obj->acl->entries);
    free(obj->acl);
    obj->acl = NULL;
    return 0;
}

/* Lookup — finds the index entry, loads data from disk, returns a heap-allocated Object */

Object *get_object(ObjectStore *store, User *user, const unsigned char id[32]) {
    if (!store || !id) return NULL;

    size_t index = index_for(store, id);
    ObjectNode *node = store->buckets[index];

    while (node) {
        if (memcmp(node->obj->id, id, 32) == 0) {
            Object *obj = malloc(sizeof(Object));
            if (!obj) return NULL;

            if (!read_object_file(store, id, obj)) {
                free(obj);
                return NULL;
            }

            if (!has_permission(obj, user->user_id, PERM_READ)) {
                free(obj->data);
                if (obj->acl) {
                    free(obj->acl->entries);
                    free(obj->acl);
                }
                free_metadata(obj->metadata);
                free(obj);
                return NULL;
            }

            return obj;
        }
        node = node->next;
    }

    return NULL;
}

/* Delete — removes from the in-memory index and deletes the file (if no other users own it) */

int remove_object(ObjectStore *store, User *user, const unsigned char id[32]) {
    if (!store || !id || !user) return 0;

    size_t index = index_for(store, id);

    ObjectNode *node = store->buckets[index];
    ObjectNode *prev = NULL;

    while (node) {
        if (memcmp(node->obj->id, id, 32) == 0) {
            /* 1. Enforce permission mapping */
            if (!has_permission(node->obj, user->user_id, PERM_DELETE)) {
                return 0;
            }

            /* 2. Extract the data hash reference from the metadata file before deleting it */
            unsigned char data_hash[32];
            int hash_read_success = 0;
            char path[4096 + 128];
            object_path(store, id, path, sizeof(path));
            
            FILE *f = fopen(path, "rb");
            if (f) {
                size_t d_len, c_len, e_len, f_len;
                if (fread(&d_len, sizeof(size_t), 1, f) == 1 &&
                    fread(&c_len, sizeof(size_t), 1, f) == 1 &&
                    fread(&e_len, sizeof(size_t), 1, f) == 1 &&
                    fread(&f_len, sizeof(size_t), 1, f) == 1) {
                    
                    fseek(f, 16, SEEK_CUR); // Skip owner
                    size_t acl_count = 0;
                    if (fread(&acl_count, sizeof(size_t), 1, f) == 1) {
                        fseek(f, acl_count * (16 + sizeof(uint32_t)), SEEK_CUR); // Skip ACLs
                        if (fread(data_hash, 1, 32, f) == 32) {
                            hash_read_success = 1;
                        }
                    }
                }
                fclose(f);
            }

            /* 3. Un-link from the in-memory indexing bucket sequence */
            if (prev) {
                prev->next = node->next;
            } else {
                store->buckets[index] = node->next;
            }

            /* 4. Delete this specific user's metadata file */
            delete_metadata_file(store, id);

            /* 5. Safe Deduplication Check: Only delete blob if NO ONE else links to it */
            if (hash_read_success) {
                int shared_refs = count_data_blob_references(store, data_hash, id);
                if (shared_refs == 0) {
                    delete_data_blob_file(store, data_hash);
                }
            }

            /* 6. Free up in-memory structural representations */
            free(node->obj->data);
            if (node->obj->acl) {
                free(node->obj->acl->entries);
                free(node->obj->acl);
            }
            free_metadata(node->obj->metadata);
            free(node->obj);
            free(node);

            store->count;

            write_index(store); // Re-sync index
            return 1;
        }

        prev = node;
        node = node->next;
    }

    return 0;
}

// Share an object given permissions
int share_object(ObjectStore *store, User *requester, const unsigned char id[32], 
                 unsigned char target_user_id[16], uint32_t permissions) {
    if (!store || !requester || !id) return 0;

    size_t index = index_for(store, id);
    ObjectNode *node = store->buckets[index];

    while (node) {
        if (memcmp(node->obj->id, id, 32) == 0) {
            // 1. Enforce that only the true owner can alter permissions
            if (memcmp(node->obj->owner, requester->user_id, 16) != 0) {
                return -2; // Return custom sentinel for HTTP 403 Forbidden
            }

            // 2. Read the full object data out from the disk file first 
            // so we can rewrite it fully with the updated ACLs.
            Object full_obj = {0};
            if (!read_object_file(store, id, &full_obj)) {
                return 0;
            }

            // 3. Search to see if target user already exists in full_obj.acl
            int found = 0;
            if (full_obj.acl) {
                for (size_t i = 0; i < full_obj.acl->count; i++) {
                    if (memcmp(full_obj.acl->entries[i].user_id, target_user_id, 16) == 0) {
                        full_obj.acl->entries[i].permissions = permissions;
                        found = 1;
                        break;
                    }
                }
            }

            // 4. If target user was not found, grow the ACL list entry array
            if (!found) {
                size_t old_count = full_obj.acl ? full_obj.acl->count : 0;
                size_t new_count = old_count + 1;
                
                ACLEntry *new_entries = realloc(full_obj.acl ? full_obj.acl->entries : NULL, 
                                                new_count * sizeof(ACLEntry));
                if (!new_entries) {
                    free(full_obj.data);
                    if (full_obj.acl) { free(full_obj.acl->entries); free(full_obj.acl); }
                    free_metadata(full_obj.metadata);
                    return 0;
                }

                if (!full_obj.acl) {
                    full_obj.acl = calloc(1, sizeof(ACL));
                    if (!full_obj.acl) {
                        free(new_entries);
                        free(full_obj.data);
                        free_metadata(full_obj.metadata);
                        return 0;
                    }
                }

                full_obj.acl->entries = new_entries;
                full_obj.acl->count = new_count;

                memcpy(full_obj.acl->entries[old_count].user_id, target_user_id, 16);
                full_obj.acl->entries[old_count].permissions = permissions;
            }

            // 5. Commit updated object format back down to disk file layout
            if (!write_object_file(store, &full_obj)) {
                free(full_obj.data);
                free(full_obj.acl->entries);
                free(full_obj.acl);
                free_metadata(full_obj.metadata);
                return 0;
            }

            // 6. Free up memory associated with the disk file payload variables
            free(full_obj.data);
            free_metadata(full_obj.metadata);

            // 7. Update the in-memory cache index entry representation as well
            if (node->obj->acl) {
                free(node->obj->acl->entries);
                free(node->obj->acl);
            }
            node->obj->acl = full_obj.acl;

            return 1; // Success
        }
        node = node->next;
    }

    return -1; // Return custom sentinel for HTTP 404 Not Found
}