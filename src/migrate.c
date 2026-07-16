#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "format.h"
#include "format_registry.h"
#include "obj_helpers.h"

#define CHUNK_SIZE 65536

static int is_hex_char(char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static int is_metadata_filename(const char *name) {
    size_t len = strlen(name);
    if (len != 64) return 0;
    for (size_t i = 0; i < len; i++) {
        if (!is_hex_char(name[i])) return 0;
    }
    return 1;
}

static int migrate_metadata(const char *path, const FormatVtable *from) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;

    Object obj = {0};
    int ok = from->read_metadata(f, &obj);
    fclose(f);
    if (!ok) return -1;

    char bak_path[4096];
    snprintf(bak_path, sizeof(bak_path), "%s.bak", path);
    if (rename(path, bak_path) != 0) {
        if (obj.metadata) free_metadata(obj.metadata);
        if (obj.acl) { free(obj.acl->entries); free(obj.acl); }
        return -1;
    }

    const FormatVtable *to = latest_format();
    f = fopen(path, "wb");
    if (!f || !try_write_header(f, X2S_FILE_TYPE_METADATA) ||
        !to->write_metadata(f, &obj)) {
        fclose(f);
        remove(path); rename(bak_path, path);
        if (obj.metadata) free_metadata(obj.metadata);
        if (obj.acl) { free(obj.acl->entries); free(obj.acl); }
        return -1;
    }
    fclose(f);

    if (obj.metadata) free_metadata(obj.metadata);
    if (obj.acl) { free(obj.acl->entries); free(obj.acl); }
    fprintf(stderr, "  [migrated]  %s  ->  %s\n", path, bak_path);
    return 1;
}

static int migrate_index(const char *path, const FormatVtable *from) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;

    size_t capacity, count;
    unsigned char *ids = NULL;
    int ok = from->read_index(f, &capacity, &count, &ids);
    fclose(f);
    if (!ok) return -1;

    char bak_path[4096];
    snprintf(bak_path, sizeof(bak_path), "%s.bak", path);
    if (rename(path, bak_path) != 0) { free(ids); return -1; }

    const FormatVtable *to = latest_format();
    f = fopen(path, "wb");
    if (!f || !try_write_header(f, X2S_FILE_TYPE_INDEX) ||
        !to->write_index(f, capacity, count, ids)) {
        fclose(f); free(ids);
        remove(path); rename(bak_path, path);
        return -1;
    }
    fclose(f);

    free(ids);
    fprintf(stderr, "  [migrated]  %s  ->  %s\n", path, bak_path);
    return 1;
}

static int migrate_users(const char *path, const FormatVtable *from) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;

    UserStore store;
    store.accounts = malloc(8 * sizeof(UserAccount));
    if (!store.accounts) { fclose(f); return -1; }
    store.count = 0;
    store.capacity = 8;
    memset(store.accounts, 0, 8 * sizeof(UserAccount));

    int ok = from->read_users(f, &store);
    fclose(f);
    if (!ok) { free(store.accounts); return -1; }

    char bak_path[4096];
    snprintf(bak_path, sizeof(bak_path), "%s.bak", path);
    if (rename(path, bak_path) != 0) { free(store.accounts); return -1; }

    const FormatVtable *to = latest_format();
    f = fopen(path, "wb");
    if (!f || !try_write_header(f, X2S_FILE_TYPE_USERS) ||
        !to->write_users(f, &store)) {
        fclose(f); free(store.accounts);
        remove(path); rename(bak_path, path);
        return -1;
    }
    fclose(f);

    free(store.accounts);
    fprintf(stderr, "  [migrated]  %s  ->  %s\n", path, bak_path);
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <data_directory>\n", argv[0]);
        return 1;
    }

    const char *data_dir = argv[1];
    struct stat st;
    if (stat(data_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "error: %s is not a valid directory\n", data_dir);
        return 1;
    }

    int migrated_count = 0;
    int skipped_count = 0;
    int users_migrated = 0, index_migrated = 0, metadata_migrated = 0;

    char path[4096];
    uint8_t version = 0;

    /* Phase 1: __index */
    snprintf(path, sizeof(path), "%s/__index", data_dir);
    FILE *f = fopen(path, "rb");
    if (f) {
        int hret = try_read_header(f, X2S_FILE_TYPE_INDEX, &version);
        fclose(f);
        if (hret == -1) {
            fprintf(stderr, "  [skip]  %s: unknown version\n", path);
        } else if (hret == 1 && version == latest_format()->version) {
            skipped_count++;
        } else {
            const FormatVtable *fmt = lookup_format(version);
            if (fmt && fmt->read_index) {
                int ret = migrate_index(path, fmt);
                if (ret > 0) { migrated_count++; index_migrated = 1; }
                else if (ret == 0) skipped_count++;
            }
        }
    }

    /* Phase 2: __users */
    snprintf(path, sizeof(path), "%s/__users", data_dir);
    f = fopen(path, "rb");
    if (f) {
        int hret = try_read_header(f, X2S_FILE_TYPE_USERS, &version);
        fclose(f);
        if (hret == -1) {
            fprintf(stderr, "  [skip]  %s: unknown version\n", path);
        } else if (hret == 1 && version == latest_format()->version) {
            skipped_count++;
        } else {
            const FormatVtable *fmt = lookup_format(version);
            if (fmt && fmt->read_users) {
                int ret = migrate_users(path, fmt);
                if (ret > 0) { migrated_count++; users_migrated = 1; }
                else if (ret == 0) skipped_count++;
            }
        }
    }

    /* Phase 3: metadata files */
    DIR *dir = opendir(data_dir);
    if (!dir) {
        fprintf(stderr, "error: could not open %s: %s\n", data_dir, strerror(errno));
        return 1;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!is_metadata_filename(entry->d_name)) continue;

        snprintf(path, sizeof(path), "%s/%s", data_dir, entry->d_name);
        f = fopen(path, "rb");
        if (!f) continue;

        int hret = try_read_header(f, X2S_FILE_TYPE_METADATA, &version);
        fclose(f);

        if (hret == -1) {
            fprintf(stderr, "  [skip]  %s: unknown version\n", path);
        } else if (hret == 1 && version == latest_format()->version) {
            skipped_count++;
        } else {
            const FormatVtable *fmt = lookup_format(version);
            if (fmt && fmt->read_metadata) {
                int ret = migrate_metadata(path, fmt);
                if (ret > 0) { migrated_count++; metadata_migrated = 1; }
                else if (ret == 0) skipped_count++;
            }
        }
    }
    closedir(dir);

    printf("Migration complete: %d file(s) upgraded", migrated_count);
    if (users_migrated) printf(", 1 users");
    if (index_migrated) printf(", 1 index");
    if (metadata_migrated) printf(", %d metadata", migrated_count - users_migrated - index_migrated);
    printf("\n%d file(s) skipped (already at latest version)\n", skipped_count);

    return 0;
}
