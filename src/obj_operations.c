#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include "obj_structs.h"
#include "obj_helpers.h"

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
            /* 1. Free ACL structural allocations */
            if (obj->acl) {
                free(obj->acl->entries);
                free(obj->acl);
                obj->acl = NULL;
            }
            
            /* 2. Free the binary blob data buffer payload */
            if (obj->data) {
                free(obj->data);
                obj->data = NULL;
            }

            /* 3. Free the complex heap-allocated metadata layout */
            if (obj->metadata) {
                free_metadata(obj->metadata);
                obj->metadata = NULL;
            }

            return 1; // Content matches existing item, return successfully
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
    if (obj->metadata) {
        index_obj->metadata = calloc(1, sizeof(Metadata));
        if (index_obj->metadata) {
            index_obj->metadata->category = obj->metadata->category ? strdup(obj->metadata->category) : NULL;
            index_obj->metadata->extension = obj->metadata->extension ? strdup(obj->metadata->extension) : NULL;
            index_obj->metadata->filename = obj->metadata->filename ? strdup(obj->metadata->filename) : NULL;
        }
    } else {
        index_obj->metadata = NULL;
    }

    /* Carry security metadata in memory index too */
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
        store->count--;
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

            store->count--;

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

/* Find and list all objects accessible by a user, with optional metadata filters */
int list_user_objects(ObjectStore *store, User *user, 
                      const char *filter_category, const char *filter_filename,
                      const char *filter_extension,
                      Object ***out_objects, size_t *out_count) {
    if (!store || !user || !out_objects || !out_count) return 0;

    size_t capacity = 16;
    size_t count = 0;
    Object **list = malloc(capacity * sizeof(Object *));
    if (!list) return 0;

    for (size_t i = 0; i < store->capacity; i++) {
        ObjectNode *node = store->buckets[i];
        while (node) {
            if (has_permission(node->obj, user->user_id, PERM_READ)) {
                Object *full_obj = malloc(sizeof(Object));
                if (full_obj) {
                    if (read_object_file(store, node->obj->id, full_obj)) {
                        int matches = 1;

                        // Apply optional category filter
                        if (filter_category && strlen(filter_category) > 0) {
                            if (!full_obj->metadata || !full_obj->metadata->category ||
                                strcmp(full_obj->metadata->category, filter_category) != 0) {
                                matches = 0;
                            }
                        }

                        // Apply optional filename filter
                        if (filter_filename && strlen(filter_filename) > 0) {
                            if (!full_obj->metadata || !full_obj->metadata->filename ||
                                strcmp(full_obj->metadata->filename, filter_filename) != 0) {
                                matches = 0;
                            }
                        }

                        // Apply optional extension filter
                        if (filter_extension && strlen(filter_extension) > 0) {
                            if (!full_obj->metadata || !full_obj->metadata->extension ||
                                strcmp(full_obj->metadata->extension, filter_extension) != 0) {
                                matches = 0;
                            }
                        }

                        if (matches) {
                            if (count >= capacity) {
                                capacity *= 2;
                                Object **tmp = realloc(list, capacity * sizeof(Object *));
                                if (!tmp) {
                                    for (size_t j = 0; j < count; j++) {
                                        free(list[j]->data);
                                        if (list[j]->acl) { free(list[j]->acl->entries); free(list[j]->acl); }
                                        free_metadata(list[j]->metadata);
                                        free(list[j]);
                                    }
                                    free(list);
                                    free(full_obj->data);
                                    if (full_obj->acl) { free(full_obj->acl->entries); free(full_obj->acl); }
                                    free_metadata(full_obj->metadata);
                                    free(full_obj);
                                    return 0;
                                }
                                list = tmp;
                            }
                            list[count++] = full_obj;
                        } else {
                            free(full_obj->data);
                            if (full_obj->acl) { free(full_obj->acl->entries); free(full_obj->acl); }
                            free_metadata(full_obj->metadata);
                            free(full_obj);
                        }
                    } else {
                        free(full_obj);
                    }
                }
            }
            node = node->next;
        }
    }

    *out_objects = list;
    *out_count = count;
    return 1;
}