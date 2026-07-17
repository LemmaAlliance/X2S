#define _POSIX_C_SOURCE 200809L /* for strcasecmp */
#include "api_server.h"
#include "auth/auth.h"
#include "core/hex_utils.h"
#include "storage/object_repository.h"
#include "core/object_types.h"
#include "server/mime_types.h"
#include "server/http_utils.h"
#include "storage/object_io.h"
#include <microhttpd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* CORS support */

#define CORS_METHODS "GET, POST, DELETE, OPTIONS"
#define CORS_HEADERS                                                                               \
    "Authorization, Content-Type, X-Filename, X-Category, X-Extension, X-Metadata-*"

/*
 * Attach CORS headers dynamically based on the configured server origin.
 */
static void add_cors_headers(struct MHD_Response* resp, const char* cors_origin)
{
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", cors_origin ? cors_origin : "*");
    MHD_add_response_header(resp, "Access-Control-Allow-Methods", CORS_METHODS);
    MHD_add_response_header(resp, "Access-Control-Allow-Headers", CORS_HEADERS);
}

/*
 * Dynamic error response with CORS support.
 */
static enum MHD_Result send_error_cors(struct MHD_Connection* conn, const char* cors_origin,
                                       unsigned int status, const char* msg)
{
    size_t msg_len  = strlen(msg);
    size_t json_len = msg_len + 12;
    char*  json     = malloc(json_len + 1);
    if (!json)
        return MHD_NO;
    snprintf(json, json_len + 1, "{\"error\":\"%s\"}", msg);

    struct MHD_Response* resp =
        MHD_create_response_from_buffer(strlen(json), json, MHD_RESPMEM_MUST_FREE);
    if (!resp) {
        free(json);
        return MHD_NO;
    }

    MHD_add_response_header(resp, "Content-Type", "application/json");
    add_cors_headers(resp, cors_origin);
    enum MHD_Result ret = MHD_queue_response(conn, status, resp);
    MHD_destroy_response(resp);
    return ret;
}

/* Route helpers */

static int parse_objects_route(const char* url, char extracted_id[65], int* is_share_route)
{
    const char* hex_id = url + 9;
    size_t      id_len = strlen(hex_id);

    if (id_len > 6 && strcmp(hex_id + id_len - 6, "/share") == 0) {
        *is_share_route = 1;
        if (id_len - 6 >= 65)
            return 0;
        memcpy(extracted_id, hex_id, id_len - 6);
    } else {
        *is_share_route = 0;
        if (id_len >= 65)
            return 0;
        strcpy(extracted_id, hex_id);
    }
    return 1;
}

static enum MHD_Result upload_buffer_accumulate(UploadBuffer* ub, const char* data,
                                                 size_t data_size, size_t max_body_size,
                                                 struct MHD_Connection* conn,
                                                 const char* cors_origin)
{
    if (ub->len + data_size > max_body_size)
        return send_error_cors(conn, cors_origin, MHD_HTTP_BAD_REQUEST, "body too large");

    if (ub->len + data_size > ub->cap) {
        size_t new_cap = (ub->cap == 0) ? data_size : ub->cap;
        while (new_cap < ub->len + data_size)
            new_cap *= 2;
        char* tmp = realloc(ub->buf, new_cap);
        if (!tmp)
            return MHD_NO;
        ub->buf = tmp;
        ub->cap = new_cap;
    }

    memcpy(ub->buf + ub->len, data, data_size);
    ub->len += data_size;
    return MHD_YES;
}

/* Route handlers */

#define X_METADATA_PREFIX "X-Metadata-"
#define X_METADATA_PREFIX_LEN 11 /* strlen("X-Metadata-") */

/* Callback context for collecting X-Metadata-* headers */
typedef struct
{
    char** keys;
    char** values;
    size_t idx;
} MetadataCollectCtx;

static void free_metadata_kv(char** keys, char** values, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        free(keys[i]);
        free(values[i]);
    }
    free(keys);
    free(values);
}

static enum MHD_Result count_metadata_headers(void* cls, enum MHD_ValueKind kind, const char* key,
                                              const char* value)
{
    (void)kind;
    (void)value;
    if (strncasecmp(key, X_METADATA_PREFIX, X_METADATA_PREFIX_LEN) == 0)
        (*(size_t*)cls)++;
    return MHD_YES;
}

static enum MHD_Result collect_metadata_headers(void* cls, enum MHD_ValueKind kind, const char* key,
                                                const char* value)
{
    (void)kind;
    if (strncasecmp(key, X_METADATA_PREFIX, X_METADATA_PREFIX_LEN) != 0)
        return MHD_YES;
    MetadataCollectCtx* ctx = cls;
    ctx->keys[ctx->idx]     = strdup(key + X_METADATA_PREFIX_LEN);
    ctx->values[ctx->idx]   = strdup(value ? value : "");
    ctx->idx++;
    return MHD_YES;
}

/*
 * PUT /objects
 *
 * This handler is called multiple times per request:
 *   - First call:  *con_cls == NULL  → allocate an UploadBuffer
 *   - Mid calls:   upload_data_size > 0 → append to buffer
 *   - Final call:  upload_data_size == 0 → process and respond
 */
static enum MHD_Result finalize_put(struct MHD_Connection* conn, ApiServer* server,
                                    FileUploadBuffer* ub)
{
    rewind(ub->fp);
    unsigned char* data_buf = malloc(ub->len);
    if (!data_buf) {
        fclose(ub->fp);
        return MHD_NO;
    }
    if (fread(data_buf, 1, ub->len, ub->fp) != ub->len) {
        free(data_buf);
        fclose(ub->fp);
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_INTERNAL_SERVER_ERROR,
                               "failed to read upload data");
    }
    fclose(ub->fp);
    ub->fp = NULL;

    const char* category  = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "X-Category");
    const char* extension = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "X-Extension");
    const char* filename  = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "X-Filename");

    size_t meta_kv_count = 0;
    MHD_get_connection_values(conn, MHD_HEADER_KIND, count_metadata_headers, &meta_kv_count);

    char** meta_kv_keys   = NULL;
    char** meta_kv_values = NULL;
    if (meta_kv_count > 0) {
        meta_kv_keys   = malloc(meta_kv_count * sizeof(char*));
        meta_kv_values = malloc(meta_kv_count * sizeof(char*));
        if (meta_kv_keys && meta_kv_values) {
            MetadataCollectCtx collect_ctx = {
                .keys = meta_kv_keys, .values = meta_kv_values, .idx = 0};
            MHD_get_connection_values(conn, MHD_HEADER_KIND, collect_metadata_headers,
                                      &collect_ctx);
        } else {
            free(meta_kv_keys);
            free(meta_kv_values);
            meta_kv_keys   = NULL;
            meta_kv_values = NULL;
            meta_kv_count  = 0;
        }
    }

    Metadata meta = {
        .category        = (char*)category,
        .extension       = (char*)extension,
        .filename        = (char*)filename,
        .metadata_keys   = meta_kv_keys,
        .metadata_values = meta_kv_values,
        .metadata_count  = meta_kv_count,
    };

    Object obj   = {0};
    obj.data     = data_buf;
    obj.size     = ub->len;
    obj.metadata = (category || extension || filename || meta_kv_count > 0) ? &meta : NULL;

    User user;
    get_user_from_request(conn, &user, server->tokens);

    if (!put_object(server->store, &user, &obj)) {
        if (obj.data)
            free(obj.data);
        free_metadata_kv(meta_kv_keys, meta_kv_values, meta_kv_count);
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_INTERNAL_SERVER_ERROR,
                               "failed to store object");
    }

    free_metadata_kv(meta_kv_keys, meta_kv_values, meta_kv_count);

    if (obj.data)
        free(obj.data);

    char      json[80];
    snprintf(json, sizeof(json), "{\"id\":\"%02x%02x%02x%02x%02x%02x%02x%02x"
                                  "%02x%02x%02x%02x%02x%02x%02x%02x"
                                  "%02x%02x%02x%02x%02x%02x%02x%02x"
                                  "%02x%02x%02x%02x%02x%02x%02x%02x\"}",
             obj.id[0], obj.id[1], obj.id[2], obj.id[3],
             obj.id[4], obj.id[5], obj.id[6], obj.id[7],
             obj.id[8], obj.id[9], obj.id[10], obj.id[11],
             obj.id[12], obj.id[13], obj.id[14], obj.id[15],
             obj.id[16], obj.id[17], obj.id[18], obj.id[19],
             obj.id[20], obj.id[21], obj.id[22], obj.id[23],
             obj.id[24], obj.id[25], obj.id[26], obj.id[27],
             obj.id[28], obj.id[29], obj.id[30], obj.id[31]);
    size_t json_len = strlen(json);
    char* json_copy = malloc(json_len + 1);
    if (!json_copy)
        return MHD_NO;
    memcpy(json_copy, json, json_len + 1);

    struct MHD_Response* resp =
        MHD_create_response_from_buffer(json_len, json_copy, MHD_RESPMEM_MUST_FREE);
    if (!resp) {
        free(json_copy);
        return MHD_NO;
    }

    MHD_add_response_header(resp, "Content-Type", "application/json");
    add_cors_headers(resp, server->cors_origin);
    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_CREATED, resp);
    MHD_destroy_response(resp);
    return ret;
}

static enum MHD_Result handle_put(struct MHD_Connection* conn, ApiServer* server,
                                  const char* upload_data, size_t* upload_data_size, void** con_cls)
{
    if (!*con_cls) {
        FileUploadBuffer* ub = calloc(1, sizeof(FileUploadBuffer));
        if (!ub)
            return MHD_NO;
        ub->type = BUFFER_TYPE_FILE_UPLOAD;
        *con_cls = ub;
        return MHD_YES;
    }

    FileUploadBuffer* ub = *con_cls;

    if (*upload_data_size > 0) {
        size_t incoming = *upload_data_size;

        if (ub->fp == NULL) {
            char template[4096];
            int  n = snprintf(template, sizeof(template), "%s/upload_XXXXXX",
                              server->temporary_directory);
            if (n < 0 || (size_t)n >= sizeof(template)) {
                return send_error_cors(conn, server->cors_origin, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                       "Temporary directory path too long");
            }
            int fd = mkstemp(template);
            if (fd == -1) {
                return send_error_cors(conn, server->cors_origin, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                       "Failed to create temporary file");
            }

            unlink(template);

            ub->fp = fdopen(fd, "wb+");
            if (!ub->fp) {
                close(fd);
                return MHD_NO;
            }

            ub->len = 0;
        }

        size_t written = fwrite(upload_data, 1, incoming, ub->fp);
        if (written < incoming) {
            return send_error_cors(conn, server->cors_origin, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                   "Disk write failure");
        }

        ub->len += written;
        *upload_data_size = 0;

        return MHD_YES;
    }

    if (ub->len == 0)
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST, "empty body");

    return finalize_put(conn, server, ub);
}

/*
 * GET /objects/<hex-id>
 */
static enum MHD_Result handle_get(struct MHD_Connection* conn, ApiServer* server,
                                  const char* hex_id)
{
    unsigned char id[32];
    if (!parse_hex_id(hex_id, id))
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST,
                               "invalid object id");

    User user;
    get_user_from_request(conn, &user, server->tokens);

    int perm = check_object_permission(server->store, id, user.user_id, PERM_READ);
    if (perm == -1)
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_NOT_FOUND, "object not found");
    if (perm == 0)
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_FORBIDDEN, "access denied");

    Object* obj = get_object(server->store, &user, id);
    if (!obj)
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_NOT_FOUND, "object not found");

    struct MHD_Response* resp =
        MHD_create_response_from_buffer(obj->size, obj->data, MHD_RESPMEM_MUST_FREE);
    if (!resp) {
        free(obj->data);
        if (obj->acl) {
            free(obj->acl->entries);
            free(obj->acl);
        }
        free_metadata(obj->metadata);
        free(obj);
        return MHD_NO;
    }

    const char* mime = mime_for_extension(obj->metadata ? obj->metadata->extension : NULL);
    MHD_add_response_header(resp, "Content-Type", mime);
    add_cors_headers(resp, server->cors_origin);

    if (obj->acl) {
        free(obj->acl->entries);
        free(obj->acl);
    }
    free_metadata(obj->metadata);
    free(obj);

    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);
    return ret;
}

/*
 * DELETE /objects/<hex-id>
 */
static enum MHD_Result handle_delete(struct MHD_Connection* conn, ApiServer* server,
                                     const char* hex_id)
{
    unsigned char id[32];
    if (!parse_hex_id(hex_id, id))
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST,
                               "invalid object id");

    User user;
    get_user_from_request(conn, &user, server->tokens);

    int perm = check_object_permission(server->store, id, user.user_id, PERM_DELETE);
    if (perm == -1)
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_NOT_FOUND, "object not found");
    if (perm == 0)
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_FORBIDDEN, "access denied");

    if (!remove_object(server->store, &user, id))
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_NOT_FOUND, "object not found");

    struct MHD_Response* resp = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
    if (!resp)
        return MHD_NO;

    add_cors_headers(resp, server->cors_origin);
    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_NO_CONTENT, resp);
    MHD_destroy_response(resp);
    return ret;
}

static char* build_metadata_json(Object* obj, size_t* out_len)
{
    if (!obj->metadata || obj->metadata->metadata_count == 0) {
        if (out_len)
            *out_len = 0;
        return NULL;
    }

    size_t cap = 256;
    for (size_t m = 0; m < obj->metadata->metadata_count; m++) {
        if (obj->metadata->metadata_keys[m])
            cap += 6 * strlen(obj->metadata->metadata_keys[m]) + 8;
        if (obj->metadata->metadata_values[m])
            cap += 6 * strlen(obj->metadata->metadata_values[m]) + 8;
    }

    char* meta_json = malloc(cap);
    if (!meta_json)
        return NULL;

    size_t pos = 0;
    pos += snprintf(meta_json + pos, cap - pos, "{");
    for (size_t m = 0; m < obj->metadata->metadata_count; m++) {
        if (!obj->metadata->metadata_keys[m])
            continue;
        char* ek = json_escape(obj->metadata->metadata_keys[m]);
        char* ev = json_escape(obj->metadata->metadata_values[m]);
        int   n  = snprintf(meta_json + pos, cap - pos, "%s\"%s\":\"%s\"",
                            (pos > 1) ? "," : "", ek ? ek : "", ev ? ev : "");
        if (n > 0)
            pos += (size_t)n;
        free(ek);
        free(ev);
    }
    snprintf(meta_json + pos, cap - pos, "}");
    if (out_len)
        *out_len = strlen(meta_json);
    return meta_json;
}

static void free_object_list(Object** objects, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        free(objects[i]->data);
        if (objects[i]->acl) {
            free(objects[i]->acl->entries);
            free(objects[i]->acl);
        }
        free_metadata(objects[i]->metadata);
        free(objects[i]);
    }
    free(objects);
}

static enum MHD_Result handle_list_objects(struct MHD_Connection* conn, ApiServer* server)
{
    User user;
    get_user_from_request(conn, &user, server->tokens);

    const char* category  = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "category");
    const char* filename  = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "filename");
    const char* extension = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "extension");
    const char* metadata_key =
        MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "metadata_key");
    const char* metadata_value =
        MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "metadata_value");

    Object** objects = NULL;
    size_t   count   = 0;

    if (!list_user_objects(server->store, &user, category, filename, extension, metadata_key,
                           metadata_value, &objects, &count)) {
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_INTERNAL_SERVER_ERROR,
                               "failed to read index files");
    }

    size_t json_cap = 4096;
    char*  json     = malloc(json_cap);
    if (!json) {
        free_object_list(objects, count);
        return MHD_NO;
    }

    strcpy(json, "{\"objects\":[");
    size_t json_len = strlen(json);

    for (size_t i = 0; i < count; i++) {
        char hex_id[65] = {0};
        bytes_to_hex(objects[i]->id, 32, hex_id);

        const char* obj_cat = (objects[i]->metadata && objects[i]->metadata->category) ?
                                  objects[i]->metadata->category :
                                  "";
        const char* obj_fn  = (objects[i]->metadata && objects[i]->metadata->filename) ?
                                  objects[i]->metadata->filename :
                                  "";
        const char* obj_ext = (objects[i]->metadata && objects[i]->metadata->extension) ?
                                  objects[i]->metadata->extension :
                                  "";

        char *ecat = json_escape(obj_cat), *efn = json_escape(obj_fn), *eext = json_escape(obj_ext);
        char* meta_json = build_metadata_json(objects[i], NULL);

        size_t obj_entry_len = 200 + strlen(hex_id) + (ecat ? strlen(ecat) : 0) +
                               (efn ? strlen(efn) : 0) + (eext ? strlen(eext) : 0) +
                               (meta_json ? strlen(meta_json) : 0);

        if (json_len + obj_entry_len + 1 >= json_cap) {
            json_cap = json_len + obj_entry_len + 4096;
            char* tmp = realloc(json, json_cap);
            if (!tmp) {
                free_object_list(objects, count);
                free(json);
                free(ecat);
                free(efn);
                free(eext);
                free(meta_json);
                return MHD_NO;
            }
            json = tmp;
        }

        int res = snprintf(json + json_len, json_cap - json_len,
                           "%s{\"id\":\"%s\",\"category\":\"%s\",\"filename\":\"%s\","
                           "\"extension\":\"%s\",\"size\":%zu,\"metadata\":%s}",
                           (i > 0) ? "," : "", hex_id,
                           ecat ? ecat : "", efn ? efn : "", eext ? eext : "",
                           objects[i]->size, meta_json ? meta_json : "{}");

        free(meta_json);
        free(ecat);
        free(efn);
        free(eext);

        if (res > 0)
            json_len += (size_t)res;
    }

    if (json_len + 3 > json_cap) {
        json_cap = json_len + 3;
        char* tmp = realloc(json, json_cap);
        if (!tmp) {
            free_object_list(objects, count);
            free(json);
            return MHD_NO;
        }
        json = tmp;
    }
    memcpy(json + json_len, "]}", 3);
    json_len += 2;

    free_object_list(objects, count);

    struct MHD_Response* resp =
        MHD_create_response_from_buffer(json_len, json, MHD_RESPMEM_MUST_FREE);
    if (!resp) {
        free(json);
        return MHD_NO;
    }

    MHD_add_response_header(resp, "Content-Type", "application/json");
    add_cors_headers(resp, server->cors_origin);
    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);
    return ret;
}

/* Auth route handlers */

/*
 * Common handler for POST /auth/register and POST /auth/login.
 * Follows the same body-accumulation pattern as handle_put.
 */
static enum MHD_Result handle_auth_register(struct MHD_Connection* conn, ApiServer* server,
                                             const char* upload_data, size_t* upload_data_size,
                                             void** con_cls)
{
    if (!*con_cls) {
        UploadBuffer* ub = calloc(1, sizeof(UploadBuffer));
        if (!ub)
            return MHD_NO;
        ub->type = BUFFER_TYPE_UPLOAD;
        *con_cls = ub;
        return MHD_YES;
    }

    UploadBuffer* ub = *con_cls;

    if (*upload_data_size > 0) {
        enum MHD_Result ret = upload_buffer_accumulate(ub, upload_data, *upload_data_size, 4096,
                                                        conn, server->cors_origin);
        if (ret != MHD_YES)
            return ret;
        *upload_data_size = 0;
        return MHD_YES;
    }

    if (ub->len == 0)
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST, "empty body");

    char username[64]  = {0};
    char password[256] = {0};

    if (!parse_form_field(ub->buf, "username", username, sizeof(username)) ||
        !parse_form_field(ub->buf, "password", password, sizeof(password)))
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST,
                               "missing username or password");

    if (strlen(username) == 0 || strlen(password) == 0)
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST,
                               "username and password required");

    unsigned char user_id[16];
    if (!user_store_register(server->tokens->users, username, password, user_id))
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_CONFLICT,
                               "username already taken or invalid");

    char* token_hex = session_create(server->tokens->sessions, user_id);
    if (!token_hex)
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_INTERNAL_SERVER_ERROR,
                               "failed to create session");

    if (!user_store_save(server->tokens->users, server->store->store_path)) {
        free(token_hex);
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_INTERNAL_SERVER_ERROR,
                               "failed to persist users");
    }

    char user_id_hex[33] = {0};
    bytes_to_hex(user_id, 16, user_id_hex);

    size_t json_len = strlen(token_hex) + strlen(user_id_hex) + 40;
    char*  json     = malloc(json_len + 1);
    if (!json) {
        free(token_hex);
        return MHD_NO;
    }

    snprintf(json, json_len + 1, "{\"token\":\"%s\",\"user_id\":\"%s\"}", token_hex, user_id_hex);
    free(token_hex);

    struct MHD_Response* resp =
        MHD_create_response_from_buffer(strlen(json), json, MHD_RESPMEM_MUST_FREE);
    if (!resp) {
        free(json);
        return MHD_NO;
    }

    MHD_add_response_header(resp, "Content-Type", "application/json");
    add_cors_headers(resp, server->cors_origin);
    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_CREATED, resp);
    MHD_destroy_response(resp);
    return ret;
}

static enum MHD_Result handle_auth_login(struct MHD_Connection* conn, ApiServer* server,
                                          const char* upload_data, size_t* upload_data_size,
                                          void** con_cls)
{
    if (!*con_cls) {
        UploadBuffer* ub = calloc(1, sizeof(UploadBuffer));
        if (!ub)
            return MHD_NO;
        ub->type = BUFFER_TYPE_UPLOAD;
        *con_cls = ub;
        return MHD_YES;
    }

    UploadBuffer* ub = *con_cls;

    if (*upload_data_size > 0) {
        enum MHD_Result ret = upload_buffer_accumulate(ub, upload_data, *upload_data_size, 4096,
                                                        conn, server->cors_origin);
        if (ret != MHD_YES)
            return ret;
        *upload_data_size = 0;
        return MHD_YES;
    }

    if (ub->len == 0)
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST, "empty body");

    char username[64]  = {0};
    char password[256] = {0};

    if (!parse_form_field(ub->buf, "username", username, sizeof(username)) ||
        !parse_form_field(ub->buf, "password", password, sizeof(password)))
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST,
                               "missing username or password");

    unsigned char user_id[16];
    if (!user_store_authenticate(server->tokens->users, username, password, user_id))
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_UNAUTHORIZED,
                               "invalid username or password");

    char* token_hex = session_create(server->tokens->sessions, user_id);
    if (!token_hex)
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_INTERNAL_SERVER_ERROR,
                               "failed to create session");

    char user_id_hex[33] = {0};
    bytes_to_hex(user_id, 16, user_id_hex);

    size_t json_len = strlen(token_hex) + strlen(user_id_hex) + 40;
    char*  json     = malloc(json_len + 1);
    if (!json) {
        free(token_hex);
        return MHD_NO;
    }

    snprintf(json, json_len + 1, "{\"token\":\"%s\",\"user_id\":\"%s\"}", token_hex, user_id_hex);
    free(token_hex);

    struct MHD_Response* resp =
        MHD_create_response_from_buffer(strlen(json), json, MHD_RESPMEM_MUST_FREE);
    if (!resp) {
        free(json);
        return MHD_NO;
    }

    MHD_add_response_header(resp, "Content-Type", "application/json");
    add_cors_headers(resp, server->cors_origin);
    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);
    return ret;
}

static enum MHD_Result handle_auth_logout(struct MHD_Connection* conn, ApiServer* server)
{
    const char* auth = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Authorization");
    if (!auth || strncmp(auth, "Bearer ", 7) != 0)
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_UNAUTHORIZED,
                               "missing bearer token");

    const char* hex_token = auth + 7;
    if (strlen(hex_token) != TOKEN_SIZE * 2)
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_UNAUTHORIZED, "invalid token");

    unsigned char token_bin[TOKEN_SIZE];
    if (!hex_to_bytes(hex_token, token_bin, TOKEN_SIZE))
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_UNAUTHORIZED, "invalid token");

    session_destroy(server->tokens->sessions, token_bin);

    struct MHD_Response* resp = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
    if (!resp)
        return MHD_NO;

    add_cors_headers(resp, server->cors_origin);
    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_NO_CONTENT, resp);
    MHD_destroy_response(resp);
    return ret;
}

static enum MHD_Result handle_share(struct MHD_Connection* conn, ApiServer* server,
                                     const char* hex_id, const char* upload_data,
                                     size_t* upload_data_size, void** con_cls)
{
    if (!*con_cls) {
        UploadBuffer* ub = calloc(1, sizeof(UploadBuffer));
        if (!ub)
            return MHD_NO;
        ub->type = BUFFER_TYPE_UPLOAD;
        *con_cls = ub;
        return MHD_YES;
    }

    UploadBuffer* ub = *con_cls;

    if (*upload_data_size > 0) {
        enum MHD_Result ret = upload_buffer_accumulate(ub, upload_data, *upload_data_size, 4096,
                                                        conn, server->cors_origin);
        if (ret != MHD_YES)
            return ret;
        *upload_data_size = 0;
        return MHD_YES;
    }

    if (ub->len == 0)
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST, "empty body");

    unsigned char id[32];
    if (!parse_hex_id(hex_id, id))
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST,
                               "invalid object id");

    User user;
    get_user_from_request(conn, &user, server->tokens);

    char target_uid_hex[33] = {0};
    char perm_str[16]       = {0};

    if (!parse_form_field(ub->buf, "user_id", target_uid_hex, sizeof(target_uid_hex)) ||
        !parse_form_field(ub->buf, "permissions", perm_str, sizeof(perm_str))) {
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST,
                               "missing user_id or permissions");
    }

    unsigned char target_uid_bin[16];
    if (!hex_to_bytes(target_uid_hex, target_uid_bin, 16)) {
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST,
                               "invalid target user_id format");
    }

    uint32_t permissions = (uint32_t)strtoul(perm_str, NULL, 10);

    int res = share_object(server->store, &user, id, target_uid_bin, permissions);
    if (res == -1)
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_NOT_FOUND, "object not found");
    if (res == -2)
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_FORBIDDEN,
                               "only the owner can share this object");
    if (res == 0)
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_INTERNAL_SERVER_ERROR,
                               "failed to update permissions");

    struct MHD_Response* resp = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
    if (!resp)
        return MHD_NO;

    add_cors_headers(resp, server->cors_origin);
    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_NO_CONTENT, resp);
    MHD_destroy_response(resp);
    return ret;
}

/* Main MHD access callback — router */

static enum MHD_Result access_handler(void* cls, struct MHD_Connection* conn, const char* url,
                                       const char* method, const char* version,
                                       const char* upload_data, size_t* upload_data_size,
                                       void** con_cls)
{
    (void)version;

    ApiServer* server = cls;

    if (strcmp(method, "OPTIONS") == 0) {
        struct MHD_Response* resp =
            MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
        if (!resp)
            return MHD_NO;
        add_cors_headers(resp, server->cors_origin);
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_NO_CONTENT, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    if (strcmp(url, "/auth/register") == 0) {
        if (strcmp(method, "POST") == 0)
            return handle_auth_register(conn, server, upload_data, upload_data_size, con_cls);
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_METHOD_NOT_ALLOWED,
                               "only POST is accepted on /auth/register");
    }

    if (strcmp(url, "/auth/login") == 0) {
        if (strcmp(method, "POST") == 0)
            return handle_auth_login(conn, server, upload_data, upload_data_size, con_cls);
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_METHOD_NOT_ALLOWED,
                               "only POST is accepted on /auth/login");
    }

    if (strcmp(url, "/auth/logout") == 0) {
        if (strcmp(method, "POST") == 0)
            return handle_auth_logout(conn, server);
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_METHOD_NOT_ALLOWED,
                               "only POST is accepted on /auth/logout");
    }

    if (strcmp(url, "/objects") == 0) {
        if (strcmp(method, "POST") == 0)
            return handle_put(conn, server, upload_data, upload_data_size, con_cls);
        if (strcmp(method, "GET") == 0)
            return handle_list_objects(conn, server);
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_METHOD_NOT_ALLOWED,
                               "only POST and GET are accepted on /objects");
    }

    if (strncmp(url, "/objects/", 9) == 0) {
        char extracted_id[65] = {0};
        int  is_share_route   = 0;

        if (!parse_objects_route(url, extracted_id, &is_share_route))
            return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST,
                                   "invalid object id");

        if (is_share_route) {
            if (strcmp(method, "POST") == 0)
                return handle_share(conn, server, extracted_id, upload_data, upload_data_size,
                                    con_cls);
            return send_error_cors(conn, server->cors_origin, MHD_HTTP_METHOD_NOT_ALLOWED,
                                   "only POST is accepted on /objects/<id>/share");
        }

        if (!*con_cls) {
            *con_cls = (void*)1;
            return MHD_YES;
        }

        if (strcmp(method, "GET") == 0)
            return handle_get(conn, server, extracted_id);
        if (strcmp(method, "DELETE") == 0)
            return handle_delete(conn, server, extracted_id);

        return send_error_cors(conn, server->cors_origin, MHD_HTTP_METHOD_NOT_ALLOWED,
                               "only GET and DELETE are accepted on /objects/<id>");
    }

    return send_error_cors(conn, server->cors_origin, MHD_HTTP_NOT_FOUND, "unknown route");
}

/* Completed callback — free per-request state */

static void request_completed(void* cls, struct MHD_Connection* conn, void** con_cls,
                              enum MHD_RequestTerminationCode toe)
{
    (void)cls;
    (void)conn;
    (void)toe;

    if (!con_cls || !*con_cls)
        return;

    /*
   * GET/DELETE/logout use the sentinel value 1.
   */
    if (*con_cls == (void*)1) {
        *con_cls = NULL;
        return;
    }

    /*
   * Safely distinguish between UploadBuffer and FileUploadBuffer using type tag.
   * Both structures have BufferType as their first field.
   */
    BufferType* type_ptr = (BufferType*)*con_cls;

    if (*type_ptr == BUFFER_TYPE_UPLOAD) {
        /* This is an UploadBuffer (auth handlers) */
        UploadBuffer* ub = (UploadBuffer*)*con_cls;
        free(ub->buf);
        free(ub);
    } else if (*type_ptr == BUFFER_TYPE_FILE_UPLOAD) {
        /* This is a FileUploadBuffer (file uploads) */
        FileUploadBuffer* fub = (FileUploadBuffer*)*con_cls;
        if (fub->fp != NULL) {
            fclose(fub->fp);
        }
        free(fub);
    }

    *con_cls = NULL;
}

/* Public API */

ApiServer* api_server_start(unsigned int port, const char* cors_origin,
                            const char* temporary_directory, ObjectStore* store, TokenStore* tokens)
{
    if (!store)
        return NULL;

    ApiServer* server = malloc(sizeof(ApiServer));
    if (!server)
        return NULL;

    server->store               = store;
    server->tokens              = tokens;
    server->cors_origin         = cors_origin; /* Track dynamic value safely here */
    server->temporary_directory = temporary_directory;

    /*
   * MHD_USE_INTERNAL_POLLING_THREAD: MHD manages its own thread so
   * the caller doesn't need to drive a select/epoll loop.
   * MHD_USE_ERROR_LOG: write MHD-internal errors to stderr.
   */
    server->daemon =
        MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG, (uint16_t)port, NULL,
                         NULL, access_handler, server, MHD_OPTION_NOTIFY_COMPLETED,
                         request_completed, NULL, MHD_OPTION_END);

    if (!server->daemon) {
        free(server);
        return NULL;
    }

    return server;
}

void api_server_stop(ApiServer* server)
{
    if (!server)
        return;
    MHD_stop_daemon(server->daemon);
    free(server);
}
