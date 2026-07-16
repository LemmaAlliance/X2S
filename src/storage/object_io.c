#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include "core/object_types.h"
#include "crypto/object_crypto.h"
#include "storage/object_serialization.h"
#include "storage/object_io.h"
#include "core/format.h"
#include "core/format_registry.h"

#define PATH_MAX_LEN 4096

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

void id_to_hex(const unsigned char id[32], char out[65]) {
    for (int i = 0; i < 32; i++) {
        snprintf(out + i * 2, 3, "%02x", id[i]);
    }
    out[64] = '\0';
}

void object_path(ObjectStore *store, const unsigned char id[32],
                        char *out, size_t out_len) {
    char hex[65];
    id_to_hex(id, hex);
    snprintf(out, out_len, "%s/%s", store->store_path, hex);
}

int write_object_file(ObjectStore *store, Object *obj) {
    char path[PATH_MAX_LEN + 128];
    object_path(store, obj->id, path, sizeof(path));

    const FormatVtable *fmt = latest_format();
    if (!fmt || !fmt->write_metadata) return 0;

    if (!compute_data_hash(obj->data, obj->size, obj->data_hash)) return 0;

    FILE *f = fopen(path, "wb");
    if (!f) return 0;

    if (!try_write_header(f, X2S_FILE_TYPE_METADATA)) {
        fclose(f); return 0;
    }

    if (!fmt->write_metadata(f, obj)) {
        fclose(f); return 0;
    }

    fclose(f);

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
                if (fwrite(obj->data, 1, obj->size, df) != obj->size) {
                    fclose(df);
                    return 0;
                }
            }
            fclose(df);
        }
    }

    return 1;
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

int count_data_blob_references(ObjectStore *store, const unsigned char target_data_hash[32], const unsigned char current_meta_id[32]) {
    int reference_count = 0;

    for (size_t i = 0; i < store->capacity; i++) {
        ObjectNode *node = store->buckets[i];
        while (node) {
            if (memcmp(node->obj->id, current_meta_id, 32) != 0) {
                char path[PATH_MAX_LEN + 128];
                object_path(store, node->obj->id, path, sizeof(path));
                FILE *f = fopen(path, "rb");
                if (f) {
                    uint8_t version = 0;
                    int hret = try_read_header(f, X2S_FILE_TYPE_METADATA, &version);
                    if (hret == -1) { fclose(f); goto next_node; }

                    const FormatVtable *fmt = lookup_format(version);
                    if (fmt && fmt->read_data_hash) {
                        unsigned char check_hash[32];
                        if (fmt->read_data_hash(f, check_hash) &&
                            memcmp(check_hash, target_data_hash, 32) == 0) {
                            reference_count++;
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
