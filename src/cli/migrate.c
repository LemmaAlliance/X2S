#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "core/format.h"
#include "core/format_registry.h"
#include "storage/object_serialization.h"
#include "storage/object_io.h"

/* ========== Generic migration engine ========== */

typedef int (*migrate_read_fn)(FILE *, const FormatVtable *, void *);
typedef int (*migrate_write_fn)(FILE *, const FormatVtable *, void *);
typedef void (*migrate_free_fn)(void *);

static int do_migrate(const char *path, uint8_t file_type,
                      const FormatVtable *from,
                      migrate_read_fn reader, migrate_write_fn writer,
                      migrate_free_fn freer, void *ctx)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;

    int ok = reader(f, from, ctx);
    fclose(f);
    if (!ok) return -1;

    char bak_path[4096];
    snprintf(bak_path, sizeof(bak_path), "%s.bak", path);
    if (rename(path, bak_path) != 0) { freer(ctx); return -1; }

    const FormatVtable *to = latest_format();
    f = fopen(path, "wb");
    if (!f) {
        freer(ctx);
        remove(path);
        rename(bak_path, path);
        return -1;
    }

    if (!try_write_header(f, file_type) || !writer(f, to, ctx)) {
        fclose(f);
        remove(path);
        rename(bak_path, path);
        freer(ctx);
        return -1;
    }
    fclose(f);

    freer(ctx);
    fprintf(stderr, "  [migrated]  %s  ->  %s\n", path, bak_path);
    return 1;
}

/* ========== Metadata ========== */

struct metadata_ctx { Object obj; };

static int metadata_reader(FILE *f, const FormatVtable *fmt, void *v) {
    return fmt->read_metadata(f, &((struct metadata_ctx *)v)->obj);
}

static int metadata_writer(FILE *f, const FormatVtable *fmt, void *v) {
    return fmt->write_metadata(f, &((struct metadata_ctx *)v)->obj);
}

static void metadata_freer(void *v) {
    struct metadata_ctx *c = v;
    free_metadata(c->obj.metadata);
    if (c->obj.acl) { free(c->obj.acl->entries); free(c->obj.acl); }
}

static int migrate_metadata(const char *path, const FormatVtable *from) {
    struct metadata_ctx ctx = {0};
    return do_migrate(path, X2S_FILE_TYPE_METADATA, from,
                      metadata_reader, metadata_writer, metadata_freer, &ctx);
}

/* ========== Index ========== */

struct index_ctx { size_t capacity; size_t count; unsigned char *ids; };

static int index_reader(FILE *f, const FormatVtable *fmt, void *v) {
    struct index_ctx *c = v;
    return fmt->read_index(f, &c->capacity, &c->count, &c->ids);
}

static int index_writer(FILE *f, const FormatVtable *fmt, void *v) {
    struct index_ctx *c = v;
    return fmt->write_index(f, c->capacity, c->count, c->ids);
}

static void index_freer(void *v) {
    free(((struct index_ctx *)v)->ids);
}

static int migrate_index(const char *path, const FormatVtable *from) {
    struct index_ctx ctx = {0};
    return do_migrate(path, X2S_FILE_TYPE_INDEX, from,
                      index_reader, index_writer, index_freer, &ctx);
}

/* ========== Users ========== */

struct users_ctx { UserStore store; };

static int users_reader(FILE *f, const FormatVtable *fmt, void *v) {
    struct users_ctx *c = v;
    c->store.accounts = malloc(8 * sizeof(UserAccount));
    if (!c->store.accounts) return 0;
    c->store.count = 0;
    c->store.capacity = 8;
    memset(c->store.accounts, 0, 8 * sizeof(UserAccount));
    int ret = fmt->read_users(f, &c->store);
    if (!ret) { free(c->store.accounts); c->store.accounts = NULL; }
    return ret;
}

static int users_writer(FILE *f, const FormatVtable *fmt, void *v) {
    return fmt->write_users(f, &((struct users_ctx *)v)->store);
}

static void users_freer(void *v) {
    free(((struct users_ctx *)v)->store.accounts);
}

static int migrate_users(const char *path, const FormatVtable *from) {
    struct users_ctx ctx = {0};
    return do_migrate(path, X2S_FILE_TYPE_USERS, from,
                      users_reader, users_writer, users_freer, &ctx);
}

/* ========== Helpers ========== */

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

/* ========== Main ========== */

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
    int users_migrated = 0, index_migrated = 0, metadata_count = 0;

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
                if (ret > 0) { migrated_count++; metadata_count++; }
                else if (ret == 0) skipped_count++;
            }
        }
    }
    closedir(dir);

    printf("Migration complete: %d file(s) upgraded", migrated_count);
    if (users_migrated) printf(", 1 users");
    if (index_migrated) printf(", 1 index");
    if (metadata_count > 0) printf(", %d metadata", metadata_count);
    printf("\n%d file(s) skipped (already at latest version)\n", skipped_count);

    return 0;
}
