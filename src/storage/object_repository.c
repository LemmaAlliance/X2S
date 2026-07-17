#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include "core/object_types.h"
#include "storage/object_permissions.h"
#include "storage/object_index.h"
#include "storage/object_io.h"
#include "crypto/object_crypto.h"
#include "storage/object_serialization.h"
#include "storage/object_repository.h"
#include "core/format.h"
#include "core/format_registry.h"

#define LOAD_FACTOR_THRESHOLD 0.75
#define PATH_MAX_LEN 4096
#define MIN_CAPACITY 8

static int resize_store(ObjectStore* store)
{
    size_t new_capacity = store->capacity * 2;

    ObjectNode** new_buckets = calloc(new_capacity, sizeof(ObjectNode*));
    if (!new_buckets)
        return 0;

    for (size_t i = 0; i < store->capacity; i++) {
        ObjectNode* node = store->buckets[i];

        while (node) {
            ObjectNode* next = node->next;

            size_t new_index       = hash_id(node->obj->id) % new_capacity;
            node->next             = new_buckets[new_index];
            new_buckets[new_index] = node;

            node = next;
        }
    }

    free(store->buckets);
    store->buckets  = new_buckets;
    store->capacity = new_capacity;

    return 1;
}

static int write_index(ObjectStore* store)
{
    char index_path[PATH_MAX_LEN + 16];
    char tmp_path[PATH_MAX_LEN + 32];

    snprintf(index_path, sizeof(index_path), "%s/__index", store->store_path);
    snprintf(tmp_path, sizeof(tmp_path), "%s/__index.tmp", store->store_path);

    const FormatVtable* fmt = latest_format();
    if (!fmt || !fmt->write_index)
        return 0;

    unsigned char* ids = NULL;
    if (store->count > 0) {
        ids = malloc(store->count * 32);
        if (!ids)
            return 0;
        size_t pos = 0;
        for (size_t i = 0; i < store->capacity; i++) {
            ObjectNode* node = store->buckets[i];
            while (node) {
                memcpy(ids + pos * 32, node->obj->id, 32);
                pos++;
                node = node->next;
            }
        }
    }

    FILE* f = fopen(tmp_path, "wb");
    if (!f) {
        free(ids);
        return 0;
    }

    if (!try_write_header(f, X2S_FILE_TYPE_INDEX)) {
        fclose(f);
        remove(tmp_path);
        free(ids);
        return 0;
    }

    int ok = fmt->write_index(f, store->capacity, store->count, ids);
    fclose(f);
    free(ids);

    if (!ok) {
        remove(tmp_path);
        return 0;
    }

    if (rename(tmp_path, index_path) != 0) {
        remove(tmp_path);
        return 0;
    }

    return 1;
}

int load_index(ObjectStore* store)
{
    char index_path[PATH_MAX_LEN + 16];
    snprintf(index_path, sizeof(index_path), "%s/__index", store->store_path);

    FILE* f = fopen(index_path, "rb");
    if (!f)
        return 0;

    uint8_t version = 0;
    int     hret    = try_read_header(f, X2S_FILE_TYPE_INDEX, &version);
    if (hret == -1) {
        fclose(f);
        return -1;
    }

    const FormatVtable* fmt = lookup_format(version);
    if (!fmt || !fmt->read_index) {
        fclose(f);
        return 0;
    }

    size_t         capacity = 0;
    size_t         count    = 0;
    unsigned char* ids      = NULL;

    if (!fmt->read_index(f, &capacity, &count, &ids)) {
        fclose(f);
        return 0;
    }
    fclose(f);

    if (capacity != store->capacity) {
        ObjectNode** new_buckets = calloc(capacity, sizeof(ObjectNode*));
        if (!new_buckets) {
            free(ids);
            return 0;
        }
        free(store->buckets);
        store->buckets  = new_buckets;
        store->capacity = capacity;
    }

    store->count = 0;

    for (size_t i = 0; i < count; i++) {
        unsigned char* id = ids + i * 32;

        Object* index_obj = calloc(1, sizeof(Object));
        if (!index_obj) {
            free(ids);
            return 0;
        }

        Object temporary_load = {0};
        if (read_object_file(store, id, &temporary_load)) {
            memcpy(index_obj->id, id, 32);
            memcpy(index_obj->owner, temporary_load.owner, 16);
            index_obj->acl  = temporary_load.acl;
            index_obj->size = temporary_load.size;
            free(temporary_load.data);
            free_metadata(temporary_load.metadata);
        } else {
            memcpy(index_obj->id, id, 32);
        }

        ObjectNode* node = malloc(sizeof(ObjectNode));
        if (!node) {
            if (index_obj->acl) {
                free(index_obj->acl->entries);
                free(index_obj->acl);
            }
            free(index_obj);
            free(ids);
            return 0;
        }

        size_t idx          = index_for(store, id);
        node->obj           = index_obj;
        node->next          = store->buckets[idx];
        store->buckets[idx] = node;
        store->count++;
    }

    free(ids);
    return 1;
}

ObjectStore* create_store(size_t initial_capacity, const char* path)
{
    if (!path)
        return NULL;

    ObjectStore* store = malloc(sizeof(ObjectStore));
    if (!store)
        return NULL;

    store->capacity = (initial_capacity < MIN_CAPACITY) ? MIN_CAPACITY : initial_capacity;
    store->count    = 0;

    snprintf(store->store_path, sizeof(store->store_path), "%s", path);

    if (mkdir(store->store_path, 0755) != 0 && errno != EEXIST) {
        free(store);
        return NULL;
    }

    store->buckets = calloc(store->capacity, sizeof(ObjectNode*));
    if (!store->buckets) {
        free(store);
        return NULL;
    }

    int lr = load_index(store);
    if (lr == -1) {
        fprintf(stderr, "error: __index has an unrecognized format version. "
                        "Run x2s-migrate to upgrade.\n");
        free_store(store);
        return NULL;
    }

    return store;
}

void free_store(ObjectStore* store)
{
    if (!store)
        return;

    for (size_t i = 0; i < store->capacity; i++) {
        ObjectNode* node = store->buckets[i];

        while (node) {
            ObjectNode* next = node->next;
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

static int handle_existing_dedup(Object* obj)
{
    if (obj->acl) {
        free(obj->acl->entries);
        free(obj->acl);
        obj->acl = NULL;
    }
    free(obj->data);
    obj->data = NULL;
    return 1;
}

static ObjectNode* create_index_entry(Object* obj)
{
    Object* index_obj = calloc(1, sizeof(Object));
    if (!index_obj)
        return NULL;

    memcpy(index_obj->id, obj->id, 32);
    index_obj->size = obj->size;
    index_obj->data = NULL;

    if (obj->metadata) {
        index_obj->metadata = calloc(1, sizeof(Metadata));
        if (index_obj->metadata) {
            index_obj->metadata->category =
                obj->metadata->category ? strdup(obj->metadata->category) : NULL;
            index_obj->metadata->extension =
                obj->metadata->extension ? strdup(obj->metadata->extension) : NULL;
            index_obj->metadata->filename =
                obj->metadata->filename ? strdup(obj->metadata->filename) : NULL;
            index_obj->metadata->metadata_count = 0;
            if (obj->metadata->metadata_count > 0) {
                index_obj->metadata->metadata_keys =
                    calloc(obj->metadata->metadata_count, sizeof(char*));
                index_obj->metadata->metadata_values =
                    calloc(obj->metadata->metadata_count, sizeof(char*));
                if (index_obj->metadata->metadata_keys && index_obj->metadata->metadata_values) {
                    for (size_t i = 0; i < obj->metadata->metadata_count; i++) {
                        index_obj->metadata->metadata_keys[i] =
                            obj->metadata->metadata_keys[i] ?
                                strdup(obj->metadata->metadata_keys[i]) :
                                NULL;
                        index_obj->metadata->metadata_values[i] =
                            obj->metadata->metadata_values[i] ?
                                strdup(obj->metadata->metadata_values[i]) :
                                NULL;
                    }
                    index_obj->metadata->metadata_count = obj->metadata->metadata_count;
                } else {
                    free(index_obj->metadata->metadata_keys);
                    free(index_obj->metadata->metadata_values);
                    index_obj->metadata->metadata_keys   = NULL;
                    index_obj->metadata->metadata_values = NULL;
                }
            }
        }
    }

    memcpy(index_obj->owner, obj->owner, 16);
    index_obj->acl = obj->acl;

    ObjectNode* node = malloc(sizeof(ObjectNode));
    if (!node) {
        free_metadata(index_obj->metadata);
        free(index_obj);
        return NULL;
    }

    node->obj = index_obj;
    node->next = NULL;
    return node;
}

int put_object(ObjectStore* store, User* user, Object* obj)
{
    if (!store || !obj || !user)
        return 0;

    if (!compute_object_id(user, obj, obj->id))
        return 0;

    memcpy(obj->owner, user->user_id, 16);

    obj->acl = calloc(1, sizeof(ACL));
    if (!obj->acl)
        return 0;

    obj->acl->entries = malloc(sizeof(ACLEntry));
    if (!obj->acl->entries) {
        free(obj->acl);
        return 0;
    }

    obj->acl->count = 1;

    memcpy(obj->acl->entries[0].user_id, user->user_id, 16);
    obj->acl->entries[0].permissions = PERM_READ | PERM_WRITE | PERM_DELETE;

    size_t      index    = index_for(store, obj->id);
    ObjectNode* existing = store->buckets[index];
    while (existing) {
        if (memcmp(existing->obj->id, obj->id, 32) == 0)
            return handle_existing_dedup(obj);
        existing = existing->next;
    }

    if (!write_object_file(store, obj))
        goto cleanup;

    if ((double)store->count / store->capacity > LOAD_FACTOR_THRESHOLD) {
        if (!resize_store(store))
            goto cleanup;
        if (!write_index(store))
            goto cleanup;
        index = index_for(store, obj->id);
    }

    ObjectNode* node = create_index_entry(obj);
    if (!node)
        goto cleanup;

    node->next            = store->buckets[index];
    store->buckets[index] = node;

    store->count++;

    if (!write_index(store)) {
        store->buckets[index] = node->next;
        store->count--;
        free(node->obj->acl->entries);
        free(node->obj->acl);
        obj->acl = NULL;
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

Object* get_object(ObjectStore* store, User* user, const unsigned char id[32])
{
    if (!store || !id)
        return NULL;

    size_t      index = index_for(store, id);
    ObjectNode* node  = store->buckets[index];

    while (node) {
        if (memcmp(node->obj->id, id, 32) == 0) {
            Object* obj = malloc(sizeof(Object));
            if (!obj)
                return NULL;

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

int check_object_permission(ObjectStore* store, const unsigned char id[32],
                            unsigned char user_id[16], uint32_t perm)
{
    if (!store || !id)
        return -1;

    size_t      index = index_for(store, id);
    ObjectNode* node  = store->buckets[index];

    while (node) {
        if (memcmp(node->obj->id, id, 32) == 0)
            return has_permission(node->obj, user_id, perm) ? 1 : 0;
        node = node->next;
    }

    return -1;
}

int remove_object(ObjectStore* store, User* user, const unsigned char id[32])
{
    if (!store || !id || !user)
        return 0;

    size_t index = index_for(store, id);

    ObjectNode* node = store->buckets[index];
    ObjectNode* prev = NULL;

    while (node) {
        if (memcmp(node->obj->id, id, 32) == 0) {
            if (!has_permission(node->obj, user->user_id, PERM_DELETE)) {
                return 0;
            }

            unsigned char data_hash[32];
            int           hash_read_success = 0;
            char          path[PATH_MAX_LEN + 128];
            object_path(store, id, path, sizeof(path));

            FILE* f = fopen(path, "rb");
            if (f) {
                uint8_t version = 0;
                int     hret    = try_read_header(f, X2S_FILE_TYPE_METADATA, &version);
                if (hret == -1) {
                    fclose(f);
                    goto skip_data_blob;
                }

                const FormatVtable* fmt = lookup_format(version);
                if (fmt && fmt->read_data_hash && fmt->read_data_hash(f, data_hash)) {
                    hash_read_success = 1;
                }
                fclose(f);
            }

        skip_data_blob:
            if (prev) {
                prev->next = node->next;
            } else {
                store->buckets[index] = node->next;
            }

            delete_metadata_file(store, id);

            if (hash_read_success) {
                int shared_refs = count_data_blob_references(store, data_hash, id);
                if (shared_refs == 0) {
                    delete_data_blob_file(store, data_hash);
                }
            }

            free(node->obj->data);
            if (node->obj->acl) {
                free(node->obj->acl->entries);
                free(node->obj->acl);
            }
            free_metadata(node->obj->metadata);
            free(node->obj);
            free(node);

            store->count--;

            write_index(store);
            return 1;
        }

        prev = node;
        node = node->next;
    }

    return 0;
}

int share_object(ObjectStore* store, User* requester, const unsigned char id[32],
                 unsigned char target_user_id[16], uint32_t permissions)
{
    if (!store || !requester || !id)
        return 0;

    size_t      index = index_for(store, id);
    ObjectNode* node  = store->buckets[index];

    while (node) {
        if (memcmp(node->obj->id, id, 32) == 0) {
            if (memcmp(node->obj->owner, requester->user_id, 16) != 0) {
                return -2;
            }

            Object full_obj = {0};
            if (!read_object_file(store, id, &full_obj)) {
                return 0;
            }

            int found = 0;
            if (full_obj.acl) {
                for (size_t i = 0; i < full_obj.acl->count; i++) {
                    if (memcmp(full_obj.acl->entries[i].user_id, target_user_id, 16) == 0) {
                        full_obj.acl->entries[i].permissions = permissions;
                        found                                = 1;
                        break;
                    }
                }
            }

            if (!found) {
                size_t old_count = full_obj.acl ? full_obj.acl->count : 0;
                size_t new_count = old_count + 1;

                ACLEntry* new_entries = realloc(full_obj.acl ? full_obj.acl->entries : NULL,
                                                new_count * sizeof(ACLEntry));
                if (!new_entries) {
                    free(full_obj.data);
                    if (full_obj.acl) {
                        free(full_obj.acl->entries);
                        free(full_obj.acl);
                    }
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
                full_obj.acl->count   = new_count;

                memcpy(full_obj.acl->entries[old_count].user_id, target_user_id, 16);
                full_obj.acl->entries[old_count].permissions = permissions;
            }

            if (!write_object_file(store, &full_obj)) {
                free(full_obj.data);
                free(full_obj.acl->entries);
                free(full_obj.acl);
                free_metadata(full_obj.metadata);
                return 0;
            }

            free(full_obj.data);
            free_metadata(full_obj.metadata);

            if (node->obj->acl) {
                free(node->obj->acl->entries);
                free(node->obj->acl);
            }
            node->obj->acl = full_obj.acl;

            return 1;
        }
        node = node->next;
    }

    return -1;
}

static int object_matches_filters(Object* obj, const char* filter_category,
                                   const char* filter_filename, const char* filter_extension,
                                   const char* filter_metadata_key,
                                   const char* filter_metadata_value)
{
    if (filter_category && strlen(filter_category) > 0) {
        if (!obj->metadata || !obj->metadata->category ||
            strcmp(obj->metadata->category, filter_category) != 0)
            return 0;
    }

    if (filter_filename && strlen(filter_filename) > 0) {
        if (!obj->metadata || !obj->metadata->filename ||
            strcmp(obj->metadata->filename, filter_filename) != 0)
            return 0;
    }

    if (filter_extension && strlen(filter_extension) > 0) {
        if (!obj->metadata || !obj->metadata->extension ||
            strcmp(obj->metadata->extension, filter_extension) != 0)
            return 0;
    }

    if (filter_metadata_key && strlen(filter_metadata_key) > 0) {
        int found = 0;
        if (obj->metadata && obj->metadata->metadata_count > 0) {
            for (size_t m = 0; m < obj->metadata->metadata_count; m++) {
                if (obj->metadata->metadata_keys[m] && obj->metadata->metadata_values[m] &&
                    strcmp(obj->metadata->metadata_keys[m], filter_metadata_key) == 0) {
                    if (!filter_metadata_value || strlen(filter_metadata_value) == 0 ||
                        strcmp(obj->metadata->metadata_values[m], filter_metadata_value) == 0) {
                        found = 1;
                        break;
                    }
                }
            }
        }
        if (!found)
            return 0;
    }

    return 1;
}

int list_user_objects(ObjectStore* store, User* user, const char* filter_category,
                      const char* filter_filename, const char* filter_extension,
                      const char* filter_metadata_key, const char* filter_metadata_value,
                      Object*** out_objects, size_t* out_count)
{
    if (!store || !user || !out_objects || !out_count)
        return 0;

    size_t   capacity = 16;
    size_t   count    = 0;
    Object** list     = malloc(capacity * sizeof(Object*));
    if (!list)
        return 0;

    for (size_t i = 0; i < store->capacity; i++) {
        ObjectNode* node = store->buckets[i];
        while (node) {
            if (has_permission(node->obj, user->user_id, PERM_READ)) {
                Object* full_obj = malloc(sizeof(Object));
                if (!full_obj) {
                    node = node->next;
                    continue;
                }

                if (!read_object_file(store, node->obj->id, full_obj)) {
                    free(full_obj);
                    node = node->next;
                    continue;
                }

                if (!object_matches_filters(full_obj, filter_category, filter_filename,
                                            filter_extension, filter_metadata_key,
                                            filter_metadata_value)) {
                    free(full_obj->data);
                    if (full_obj->acl) {
                        free(full_obj->acl->entries);
                        free(full_obj->acl);
                    }
                    free_metadata(full_obj->metadata);
                    free(full_obj);
                    node = node->next;
                    continue;
                }

                if (count >= capacity) {
                    capacity *= 2;
                    Object** tmp = realloc(list, capacity * sizeof(Object*));
                    if (!tmp) {
                        for (size_t j = 0; j < count; j++) {
                            free(list[j]->data);
                            if (list[j]->acl) {
                                free(list[j]->acl->entries);
                                free(list[j]->acl);
                            }
                            free_metadata(list[j]->metadata);
                            free(list[j]);
                        }
                        free(list);
                        free(full_obj->data);
                        if (full_obj->acl) {
                            free(full_obj->acl->entries);
                            free(full_obj->acl);
                        }
                        free_metadata(full_obj->metadata);
                        free(full_obj);
                        return 0;
                    }
                    list = tmp;
                }
                list[count++] = full_obj;
            }
            node = node->next;
        }
    }

    *out_objects = list;
    *out_count   = count;
    return 1;
}
