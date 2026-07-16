#include <string.h>
#include "format.h"
#include "format_registry.h"
#include "obj_helpers.h"

/* ========== Metadata body (shared by v0 + v1) ========== */

static int read_metadata_body(FILE *f, Object *out) {
    size_t data_len, category_len, extension_len, filename_len;

    if (fread(&data_len, sizeof(size_t), 1, f) != 1 ||
        fread(&category_len, sizeof(size_t), 1, f) != 1 ||
        fread(&extension_len, sizeof(size_t), 1, f) != 1 ||
        fread(&filename_len, sizeof(size_t), 1, f) != 1)
        return 0;

    if (fread(out->owner, 1, 16, f) != 16) return 0;

    size_t acl_count = 0;
    if (fread(&acl_count, sizeof(size_t), 1, f) != 1) return 0;
    out->acl = calloc(1, sizeof(ACL));
    if (!out->acl) return 0;
    if (acl_count > 0) {
        out->acl->entries = calloc(acl_count, sizeof(ACLEntry));
        if (!out->acl->entries) { free(out->acl); return 0; }
        out->acl->count = acl_count;
        for (size_t i = 0; i < acl_count; i++) {
            ACLEntry *e = &out->acl->entries[i];
            if (fread(e->user_id, 1, 16, f) != 16 ||
                fread(&e->permissions, sizeof(uint32_t), 1, f) != 1) {
                free(out->acl->entries); free(out->acl); return 0;
            }
        }
    }

    if (fread(out->data_hash, 1, 32, f) != 32) {
        if (out->acl->entries) free(out->acl->entries);
        free(out->acl); return 0;
    }

    Metadata *metadata = calloc(1, sizeof(Metadata));
    if (!metadata) {
        if (out->acl->entries) free(out->acl->entries);
        free(out->acl); return 0;
    }
    metadata->category  = read_string_field(f, category_len);
    metadata->extension = read_string_field(f, extension_len);
    metadata->filename  = read_string_field(f, filename_len);

    size_t metadata_count = 0;
    if (fread(&metadata_count, sizeof(size_t), 1, f) != 1) {
        if (feof(f)) {
            metadata_count = 0;
        } else {
            free_metadata(metadata);
            if (out->acl->entries) free(out->acl->entries);
            free(out->acl); return 0;
        }
    }

    if (metadata_count > 0) {
        metadata->metadata_keys   = calloc(metadata_count, sizeof(char *));
        metadata->metadata_values = calloc(metadata_count, sizeof(char *));
        if (!metadata->metadata_keys || !metadata->metadata_values) {
            free_metadata(metadata);
            if (out->acl->entries) free(out->acl->entries);
            free(out->acl); return 0;
        }
        metadata->metadata_count = metadata_count;
        for (size_t i = 0; i < metadata_count; i++) {
            size_t key_len = 0;
            if (fread(&key_len, sizeof(size_t), 1, f) != 1) {
                free_metadata(metadata);
                if (out->acl->entries) free(out->acl->entries);
                free(out->acl); return 0;
            }
            metadata->metadata_keys[i] = read_string_field(f, key_len);
            if (!metadata->metadata_keys[i]) {
                free_metadata(metadata);
                if (out->acl->entries) free(out->acl->entries);
                free(out->acl); return 0;
            }
            size_t value_len = 0;
            if (fread(&value_len, sizeof(size_t), 1, f) != 1) {
                free_metadata(metadata);
                if (out->acl->entries) free(out->acl->entries);
                free(out->acl); return 0;
            }
            metadata->metadata_values[i] = read_string_field(f, value_len);
            if (!metadata->metadata_values[i]) {
                free_metadata(metadata);
                if (out->acl->entries) free(out->acl->entries);
                free(out->acl); return 0;
            }
        }
    }

    out->metadata = metadata;
    out->size = data_len;
    return 1;
}

static int write_metadata_body(FILE *f, Object *obj) {
    size_t category_len  = (obj->metadata && obj->metadata->category)  ? strlen(obj->metadata->category)  : 0;
    size_t extension_len = (obj->metadata && obj->metadata->extension) ? strlen(obj->metadata->extension) : 0;
    size_t filename_len  = (obj->metadata && obj->metadata->filename)  ? strlen(obj->metadata->filename)  : 0;

    if (fwrite(&obj->size, sizeof(size_t), 1, f) != 1) return 0;
    if (fwrite(&category_len, sizeof(size_t), 1, f) != 1) return 0;
    if (fwrite(&extension_len, sizeof(size_t), 1, f) != 1) return 0;
    if (fwrite(&filename_len, sizeof(size_t), 1, f) != 1) return 0;

    if (fwrite(obj->owner, 1, 16, f) != 16) return 0;

    size_t acl_count = (obj->acl) ? obj->acl->count : 0;
    if (fwrite(&acl_count, sizeof(size_t), 1, f) != 1) return 0;
    if (obj->acl && acl_count > 0) {
        for (size_t i = 0; i < acl_count; i++) {
            ACLEntry *e = &obj->acl->entries[i];
            if (fwrite(e->user_id, 1, 16, f) != 16) return 0;
            if (fwrite(&e->permissions, sizeof(uint32_t), 1, f) != 1) return 0;
        }
    }

    if (fwrite(obj->data_hash, 1, 32, f) != 32) return 0;

    if (category_len > 0 && obj->metadata && obj->metadata->category)
        if (fwrite(obj->metadata->category, 1, category_len, f) != category_len) return 0;
    if (extension_len > 0 && obj->metadata && obj->metadata->extension)
        if (fwrite(obj->metadata->extension, 1, extension_len, f) != extension_len) return 0;
    if (filename_len > 0 && obj->metadata && obj->metadata->filename)
        if (fwrite(obj->metadata->filename, 1, filename_len, f) != filename_len) return 0;

    size_t metadata_count = (obj->metadata) ? obj->metadata->metadata_count : 0;
    if (fwrite(&metadata_count, sizeof(size_t), 1, f) != 1) return 0;
    for (size_t i = 0; i < metadata_count; i++) {
        const char *k = obj->metadata->metadata_keys ? obj->metadata->metadata_keys[i] : NULL;
        const char *v = obj->metadata->metadata_values ? obj->metadata->metadata_values[i] : NULL;
        if (!k || !v) return 0;
        size_t key_len = strlen(k);
        size_t value_len = strlen(v);
        if (fwrite(&key_len, sizeof(size_t), 1, f) != 1) return 0;
        if (fwrite(k, 1, key_len, f) != key_len) return 0;
        if (fwrite(&value_len, sizeof(size_t), 1, f) != 1) return 0;
        if (fwrite(v, 1, value_len, f) != value_len) return 0;
    }

    return 1;
}

/* ========== Index body ========== */

static int read_index_body(FILE *f, size_t *capacity, size_t *count, unsigned char **ids) {
    if (fread(capacity, sizeof(size_t), 1, f) != 1) return 0;
    if (fread(count, sizeof(size_t), 1, f) != 1) return 0;
    if (*count == 0) { *ids = NULL; return 1; }
    *ids = malloc(*count * 32);
    if (!*ids) return 0;
    if (fread(*ids, 32, *count, f) != *count) {
        free(*ids); *ids = NULL; return 0;
    }
    return 1;
}

static int write_index_body(FILE *f, size_t capacity, size_t count, unsigned char *ids) {
    if (fwrite(&capacity, sizeof(size_t), 1, f) != 1) return 0;
    if (fwrite(&count, sizeof(size_t), 1, f) != 1) return 0;
    if (count > 0 && ids)
        if (fwrite(ids, 32, count, f) != count) return 0;
    return 1;
}

/* ========== Users body ========== */

static int read_users_body(FILE *f, UserStore *store) {
    size_t count = 0;
    if (fread(&count, sizeof(size_t), 1, f) != 1) return 0;
    store->count = 0;
    for (size_t i = 0; i < count; i++) {
        if (store->count == store->capacity) {
            size_t new_cap = store->capacity * 2;
            UserAccount *tmp = realloc(store->accounts, new_cap * sizeof(UserAccount));
            if (!tmp) return 0;
            memset(tmp + store->capacity, 0, (new_cap - store->capacity) * sizeof(UserAccount));
            store->accounts = tmp;
            store->capacity = new_cap;
        }
        UserAccount *acct = &store->accounts[store->count];
        if (fread(acct->username, 1, MAX_USERNAME + 1, f) != MAX_USERNAME + 1 ||
            fread(acct->user_id, 1, 16, f) != 16 ||
            fread(acct->password_hash, 1, HASH_SIZE, f) != HASH_SIZE ||
            fread(acct->salt, 1, SALT_SIZE, f) != SALT_SIZE)
            return 0;
        store->count++;
    }
    return 1;
}

static int write_users_body(FILE *f, UserStore *store) {
    if (fwrite(&store->count, sizeof(size_t), 1, f) != 1) return 0;
    for (size_t i = 0; i < store->count; i++) {
        UserAccount *acct = &store->accounts[i];
        if (fwrite(acct->username, 1, MAX_USERNAME + 1, f) != MAX_USERNAME + 1 ||
            fwrite(acct->user_id, 1, 16, f) != 16 ||
            fwrite(acct->password_hash, 1, HASH_SIZE, f) != HASH_SIZE ||
            fwrite(acct->salt, 1, SALT_SIZE, f) != SALT_SIZE)
            return 0;
    }
    return 1;
}

/* ========== Registry ========== */

const FormatVtable format_registry[] = {
    {0, "legacy",
        read_metadata_body, NULL,
        read_index_body,    NULL,
        read_users_body,    NULL},
    {1, "v1",
        read_metadata_body, write_metadata_body,
        read_index_body,    write_index_body,
        read_users_body,    write_users_body},
};

const size_t format_registry_count = sizeof(format_registry) / sizeof(format_registry[0]);

const FormatVtable *lookup_format(uint8_t version) {
    for (size_t i = 0; i < format_registry_count; i++) {
        if (format_registry[i].version == version)
            return &format_registry[i];
    }
    return NULL;
}

const FormatVtable *latest_format(void) {
    return &format_registry[format_registry_count - 1];
}
