#define _POSIX_C_SOURCE 200809L /* for strcasecmp */
#include "api_server.h"
#include "auth.h"
#include "obj_operations.h"
#include "obj_structs.h"
#include "api_helpers.h"
#include <microhttpd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Note: The full definition of struct ApiServer is defined in api_helpers.h,
   but we just need to ensure your api_helpers.h definition includes:
   const char *cors_origin;
   If it doesn't, add "const char *cors_origin;" inside the struct in api_helpers.h! */

/* -------------------------------------------------------------------------
 * CORS support
 * ---------------------------------------------------------------------- */

#define CORS_METHODS "GET, POST, DELETE, OPTIONS"
#define CORS_HEADERS "Authorization, Content-Type, X-Filename, X-Category, X-Extension"

/*
 * Attach CORS headers dynamically based on the configured server origin.
 */
static void add_cors_headers(struct MHD_Response *resp, const char *cors_origin) {
  MHD_add_response_header(resp, "Access-Control-Allow-Origin",  cors_origin ? cors_origin : "*");
  MHD_add_response_header(resp, "Access-Control-Allow-Methods", CORS_METHODS);
  MHD_add_response_header(resp, "Access-Control-Allow-Headers", CORS_HEADERS);
}

/*
 * Dynamic error response with CORS support.
 */
static enum MHD_Result send_error_cors(struct MHD_Connection *conn, const char *cors_origin,
                                       unsigned int status, const char *msg) {
  size_t msg_len = strlen(msg);
  size_t json_len = msg_len + 12;
  char *json = malloc(json_len + 1);
  if (!json)
    return MHD_NO;
  snprintf(json, json_len + 1, "{\"error\":\"%s\"}", msg);

  struct MHD_Response *resp = MHD_create_response_from_buffer(
      strlen(json), json, MHD_RESPMEM_MUST_FREE);
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

/* -------------------------------------------------------------------------
 * Route handlers
 * ---------------------------------------------------------------------- */
/*
 * PUT /objects
 *
 * This handler is called multiple times per request:
 *   - First call:  *con_cls == NULL  → allocate an UploadBuffer
 *   - Mid calls:   upload_data_size > 0 → append to buffer
 *   - Final call:  upload_data_size == 0 → process and respond
 */
static enum MHD_Result handle_put(struct MHD_Connection *conn,
                                  ApiServer *server, const char *upload_data,
                                  size_t *upload_data_size, void **con_cls) {
  /* First call — initialise the accumulation buffer */
  if (!*con_cls) {
    UploadBuffer *ub = calloc(1, sizeof(UploadBuffer));
    if (!ub)
      return MHD_NO;
    *con_cls = ub;
    return MHD_YES;
  }

  UploadBuffer *ub = *con_cls;

  /* Accumulate body chunks */
  if (*upload_data_size > 0) {
    size_t incoming = *upload_data_size;

    if (ub->len + incoming > MAX_UPLOAD_SIZE)
      return send_error_cors(conn, server->cors_origin, MHD_HTTP_CONTENT_TOO_LARGE,
                        "body exceeds 64 MiB limit");

    /* Grow buffer if needed */
    if (ub->len + incoming > ub->cap) {
      size_t new_cap = (ub->cap == 0) ? incoming : ub->cap;
      while (new_cap < ub->len + incoming)
        new_cap *= 2;
      char *tmp = realloc(ub->buf, new_cap);
      if (!tmp)
        return MHD_NO;
      ub->buf = tmp;
      ub->cap = new_cap;
    }

    memcpy(ub->buf + ub->len, upload_data, incoming);
    ub->len += incoming;
    *upload_data_size = 0;
    return MHD_YES;
  }

  if (ub->len == 0)
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST, "empty body");

    /* Read optional metadata headers */
  const char *category = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "X-Category");
  const char *extension = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "X-Extension");
  const char *filename = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "X-Filename");

  Metadata meta = {
      .category = (char *)category,
      .extension = (char *)extension,
      .filename = (char *)filename,
  };

  Object obj = {0};
  obj.data = ub->buf;
  obj.size = ub->len;
  obj.metadata = (category || extension || filename) ? &meta : NULL;

  User user;
  get_user_from_request(conn, &user, server->tokens);

  if (!put_object(server->store, &user, &obj))
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_INTERNAL_SERVER_ERROR,
                      "failed to store object");

  /* Build response: {"id":"<64 hex chars>"}*/
  char json[80];
  snprintf(json, sizeof(json), "{\"id\":\"");
  for (int i = 0; i < 32; i++)
    snprintf(json + 7 + i * 2, 3, "%02x", obj.id[i]);
  snprintf(json + 71, sizeof(json) - 71, "\"}");

  size_t json_len = strlen(json);
  char *json_copy = malloc(json_len + 1);
  if (!json_copy)
    return MHD_NO;
  memcpy(json_copy, json, json_len + 1);

  struct MHD_Response *resp = MHD_create_response_from_buffer(
      json_len, json_copy, MHD_RESPMEM_MUST_FREE);
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

/*
 * GET /objects/<hex-id>
 */
static enum MHD_Result handle_get(struct MHD_Connection *conn,
                                  ApiServer *server, const char *hex_id) {
  unsigned char id[32];
  if (!parse_hex_id(hex_id, id))
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST, "invalid object id");

  User user;
  get_user_from_request(conn, &user, server->tokens);

  int perm = check_object_permission(server->store, id, user.user_id, PERM_READ);
  if (perm == -1)
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_NOT_FOUND, "object not found");
  if (perm == 0)
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_FORBIDDEN, "access denied");

  Object *obj = get_object(server->store, &user, id);
  if (!obj)
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_NOT_FOUND, "object not found");

  struct MHD_Response *resp = MHD_create_response_from_buffer(
      obj->size, obj->data, MHD_RESPMEM_MUST_FREE);
  if (!resp) {
    free(obj->data);
    if (obj->acl) { free(obj->acl->entries); free(obj->acl); }
    free_metadata(obj->metadata);
    free(obj);
    return MHD_NO;
  }

  const char *mime = mime_for_extension(obj->metadata ? obj->metadata->extension : NULL);
  MHD_add_response_header(resp, "Content-Type", mime);
  add_cors_headers(resp, server->cors_origin);

  if (obj->acl) { free(obj->acl->entries); free(obj->acl); }
  free_metadata(obj->metadata);
  free(obj);

  enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
  MHD_destroy_response(resp);
  return ret;
}

/*
 * DELETE /objects/<hex-id>
 */
static enum MHD_Result handle_delete(struct MHD_Connection *conn,
                                     ApiServer *server, const char *hex_id) {
  unsigned char id[32];
  if (!parse_hex_id(hex_id, id))
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST, "invalid object id");

  User user;
  get_user_from_request(conn, &user, server->tokens);

  int perm = check_object_permission(server->store, id, user.user_id, PERM_DELETE);
  if (perm == -1)
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_NOT_FOUND, "object not found");
  if (perm == 0)
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_FORBIDDEN, "access denied");

  if (!remove_object(server->store, &user, id))
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_NOT_FOUND, "object not found");

  struct MHD_Response *resp = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
  if (!resp)
    return MHD_NO;

  add_cors_headers(resp, server->cors_origin);
  enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_NO_CONTENT, resp);
  MHD_destroy_response(resp);
  return ret;
}

static enum MHD_Result handle_list_objects(struct MHD_Connection *conn, ApiServer *server) {
    User user;
    get_user_from_request(conn, &user, server->tokens);

    const char *category = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "category");
    const char *filename = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "filename");
    const char *extension = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "extension");

    Object **objects = NULL;
    size_t count = 0;

    if (!list_user_objects(server->store, &user, category, filename, extension, &objects, &count)) {
        return send_error_cors(conn, server->cors_origin, MHD_HTTP_INTERNAL_SERVER_ERROR, "failed to read index files");
    }

    size_t json_cap = 1024;
    char *json = malloc(json_cap);
    if (!json) {
        for (size_t i = 0; i < count; i++) {
            free(objects[i]->data);
            if (objects[i]->acl) { free(objects[i]->acl->entries); free(objects[i]->acl); }
            free_metadata(objects[i]->metadata);
            free(objects[i]);
        }
        free(objects);
        return MHD_NO;
    }

    strcpy(json, "{\"objects\":[");
    size_t json_len = strlen(json);

    for (size_t i = 0; i < count; i++) {
        char hex_id[65] = {0};
        for (int j = 0; j < 32; j++) {
            snprintf(hex_id + j * 2, 3, "%02x", objects[i]->id[j]);
        }

        const char *obj_cat = (objects[i]->metadata && objects[i]->metadata->category) ? objects[i]->metadata->category : "";
        const char *obj_fn = (objects[i]->metadata && objects[i]->metadata->filename) ? objects[i]->metadata->filename : "";
        const char *obj_ext = (objects[i]->metadata && objects[i]->metadata->extension) ? objects[i]->metadata->extension : "";

        size_t needed = strlen(hex_id) + strlen(obj_cat) + strlen(obj_fn) + strlen(obj_ext) + 160;

        if (json_len + needed >= json_cap) {
            json_cap *= 2;
            char *tmp = realloc(json, json_cap);
            if (!tmp) {
                for (size_t k = 0; k < count; k++) {
                    free(objects[k]->data);
                    if (objects[k]->acl) { free(objects[k]->acl->entries); free(objects[k]->acl); }
                    free_metadata(objects[k]->metadata);
                    free(objects[k]);
                }
                free(objects);
                free(json);
                return MHD_NO;
            }
            json = tmp;
        }

        /* Output format now tracks the extension key:
        {"id":"...","category":"...","filename":"...","extension":"...","size":123} */
        size_t written = snprintf(json + json_len, json_cap - json_len,
            "%s{\"id\":\"%s\",\"category\":\"%s\",\"filename\":\"%s\",\"extension\":\"%s\",\"size\":%zu}",
            (i > 0) ? "," : "", hex_id, obj_cat, obj_fn, obj_ext, objects[i]->size);
        
        json_len += written;
    }

    strcat(json, "]}");
    json_len = strlen(json);

    for (size_t i = 0; i < count; i++) {
        free(objects[i]->data);
        if (objects[i]->acl) { free(objects[i]->acl->entries); free(objects[i]->acl); }
        free_metadata(objects[i]->metadata);
        free(objects[i]);
    }
    free(objects);

    struct MHD_Response *resp = MHD_create_response_from_buffer(json_len, json, MHD_RESPMEM_MUST_FREE);
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

/* -------------------------------------------------------------------------
 * Auth route handlers
 * ---------------------------------------------------------------------- */

/*
 * Common handler for POST /auth/register and POST /auth/login.
 * Follows the same body-accumulation pattern as handle_put.
 */
static enum MHD_Result handle_auth_register(struct MHD_Connection *conn,
                                            ApiServer *server,
                                            const char *upload_data,
                                            size_t *upload_data_size,
                                            void **con_cls) {
  if (!*con_cls) {
    UploadBuffer *ub = calloc(1, sizeof(UploadBuffer));
    if (!ub)
      return MHD_NO;
    *con_cls = ub;
    return MHD_YES;
  }

  UploadBuffer *ub = *con_cls;

  if (*upload_data_size > 0) {
    size_t incoming = *upload_data_size;
    if (ub->len + incoming > 4096)
      return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST, "body too large");

    if (ub->len + incoming > ub->cap) {
      size_t new_cap = (ub->cap == 0) ? incoming : ub->cap;
      while (new_cap < ub->len + incoming)
        new_cap *= 2;
      char *tmp = realloc(ub->buf, new_cap);
      if (!tmp)
        return MHD_NO;
      ub->buf = tmp;
      ub->cap = new_cap;
    }

    memcpy(ub->buf + ub->len, upload_data, incoming);
    ub->len += incoming;
    *upload_data_size = 0;
    return MHD_YES;
  }

  if (ub->len == 0)
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST, "empty body");

  char username[64] = {0};
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

  char *token_hex = session_create(server->tokens->sessions, user_id);
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
  char *json = malloc(json_len + 1);
  if (!json) {
    free(token_hex);
    return MHD_NO;
  }

  snprintf(json, json_len + 1, "{\"token\":\"%s\",\"user_id\":\"%s\"}",
           token_hex, user_id_hex);
  free(token_hex);

  struct MHD_Response *resp = MHD_create_response_from_buffer(
      strlen(json), json, MHD_RESPMEM_MUST_FREE);
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

static enum MHD_Result handle_auth_login(struct MHD_Connection *conn,
                                         ApiServer *server,
                                         const char *upload_data,
                                         size_t *upload_data_size,
                                         void **con_cls) {
  if (!*con_cls) {
    UploadBuffer *ub = calloc(1, sizeof(UploadBuffer));
    if (!ub)
      return MHD_NO;
    *con_cls = ub;
    return MHD_YES;
  }

  UploadBuffer *ub = *con_cls;

  if (*upload_data_size > 0) {
    size_t incoming = *upload_data_size;
    if (ub->len + incoming > 4096)
      return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST, "body too large");

    if (ub->len + incoming > ub->cap) {
      size_t new_cap = (ub->cap == 0) ? incoming : ub->cap;
      while (new_cap < ub->len + incoming)
        new_cap *= 2;
      char *tmp = realloc(ub->buf, new_cap);
      if (!tmp)
        return MHD_NO;
      ub->buf = tmp;
      ub->cap = new_cap;
    }

    memcpy(ub->buf + ub->len, upload_data, incoming);
    ub->len += incoming;
    *upload_data_size = 0;
    return MHD_YES;
  }

  if (ub->len == 0)
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST, "empty body");

  char username[64] = {0};
  char password[256] = {0};

  if (!parse_form_field(ub->buf, "username", username, sizeof(username)) ||
      !parse_form_field(ub->buf, "password", password, sizeof(password)))
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST,
                      "missing username or password");

  unsigned char user_id[16];
  if (!user_store_authenticate(server->tokens->users, username, password, user_id))
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_UNAUTHORIZED,
                      "invalid username or password");

  char *token_hex = session_create(server->tokens->sessions, user_id);
  if (!token_hex)
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_INTERNAL_SERVER_ERROR,
                      "failed to create session");

  char user_id_hex[33] = {0};
  bytes_to_hex(user_id, 16, user_id_hex);

  size_t json_len = strlen(token_hex) + strlen(user_id_hex) + 40;
  char *json = malloc(json_len + 1);
  if (!json) {
    free(token_hex);
    return MHD_NO;
  }

  snprintf(json, json_len + 1, "{\"token\":\"%s\",\"user_id\":\"%s\"}",
           token_hex, user_id_hex);
  free(token_hex);

  struct MHD_Response *resp = MHD_create_response_from_buffer(
      strlen(json), json, MHD_RESPMEM_MUST_FREE);
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

static enum MHD_Result handle_auth_logout(struct MHD_Connection *conn,
                                          ApiServer *server) {
  const char *auth = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Authorization");
  if (!auth || strncmp(auth, "Bearer ", 7) != 0)
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_UNAUTHORIZED, "missing bearer token");

  const char *hex_token = auth + 7;
  if (strlen(hex_token) != TOKEN_SIZE * 2)
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_UNAUTHORIZED, "invalid token");

  unsigned char token_bin[TOKEN_SIZE];
  if (!hex_to_bytes(hex_token, token_bin, TOKEN_SIZE))
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_UNAUTHORIZED, "invalid token");

  session_destroy(server->tokens->sessions, token_bin);

  struct MHD_Response *resp = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
  if (!resp)
    return MHD_NO;

  add_cors_headers(resp, server->cors_origin);
  enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_NO_CONTENT, resp);
  MHD_destroy_response(resp);
  return ret;
}

static enum MHD_Result handle_share(struct MHD_Connection *conn,
                                   ApiServer *server, const char *hex_id,
                                   const char *upload_data,
                                   size_t *upload_data_size, void **con_cls) {
  if (!*con_cls) {
    UploadBuffer *ub = calloc(1, sizeof(UploadBuffer));
    if (!ub) return MHD_NO;
    *con_cls = ub;
    return MHD_YES;
  }

  UploadBuffer *ub = *con_cls;

  if (*upload_data_size > 0) {
    size_t incoming = *upload_data_size;
    if (ub->len + incoming > 4096)
      return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST, "body too large");

    if (ub->len + incoming > ub->cap) {
      size_t new_cap = (ub->cap == 0) ? incoming : ub->cap;
      while (new_cap < ub->len + incoming) new_cap *= 2;
      char *tmp = realloc(ub->buf, new_cap);
      if (!tmp) return MHD_NO;
      ub->buf = tmp;
      ub->cap = new_cap;
    }

    memcpy(ub->buf + ub->len, upload_data, incoming);
    ub->len += incoming;
    *upload_data_size = 0;
    return MHD_YES;
  }

  if (ub->len == 0)
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST, "empty body");

  unsigned char id[32];
  if (!parse_hex_id(hex_id, id))
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST, "invalid object id");

  User user;
  get_user_from_request(conn, &user, server->tokens);

  char target_uid_hex[33] = {0};
  char perm_str[16] = {0};

  if (!parse_form_field(ub->buf, "user_id", target_uid_hex, sizeof(target_uid_hex)) ||
      !parse_form_field(ub->buf, "permissions", perm_str, sizeof(perm_str))) {
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST, "missing user_id or permissions");
  }

  unsigned char target_uid_bin[16];
  if (!hex_to_bytes(target_uid_hex, target_uid_bin, 16)) {
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_BAD_REQUEST, "invalid target user_id format");
  }

  uint32_t permissions = (uint32_t)strtoul(perm_str, NULL, 10);

  int res = share_object(server->store, &user, id, target_uid_bin, permissions);
  if (res == -1)
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_NOT_FOUND, "object not found");
  if (res == -2)
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_FORBIDDEN, "only the owner can share this object");
  if (res == 0)
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_INTERNAL_SERVER_ERROR, "failed to update permissions");

  struct MHD_Response *resp = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
  if (!resp) return MHD_NO;

  add_cors_headers(resp, server->cors_origin);
  enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_NO_CONTENT, resp);
  MHD_destroy_response(resp);
  return ret;
}

/* -------------------------------------------------------------------------
 * Main MHD access callback — router
 * ---------------------------------------------------------------------- */

static enum MHD_Result
access_handler(void *cls, struct MHD_Connection *conn, const char *url,
               const char *method, const char *version, const char *upload_data,
               size_t *upload_data_size, void **con_cls) {
  (void)version;

  ApiServer *server = cls;

  if (strcmp(method, "OPTIONS") == 0) {
    struct MHD_Response *resp = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
    if (!resp)
      return MHD_NO;
    add_cors_headers(resp, server->cors_origin);
    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_NO_CONTENT, resp);
    MHD_destroy_response(resp);
    return ret;
  }

  /*
   * Route: /auth/register   → POST only
   *        /auth/login      → POST only
   *        /auth/logout     → POST only
   *        /objects          → PUT only
   *        /objects/<hex-id> → GET or DELETE
   */
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
    if (strcmp(method, "POST") == 0) {
      return handle_put(conn, server, upload_data, upload_data_size, con_cls);
    }
    if (strcmp(method, "GET") == 0) {
      return handle_list_objects(conn, server);
    }
    return send_error_cors(conn, server->cors_origin, MHD_HTTP_METHOD_NOT_ALLOWED,
                      "only POST and GET are accepted on /objects");
  }

  /* Prefix match: /objects/<id> & /objects/<id>/share*/
  if (strncmp(url, "/objects/", 9) == 0) {
    const char *hex_id = url + 9;
    size_t id_len = strlen(hex_id);
    int is_share_route = 0;
    char extracted_id[65] = {0};

    if (id_len > 6 && strcmp(hex_id + id_len - 6, "/share") == 0) {
      is_share_route = 1;
      if (id_len - 6 < 65) {
        memcpy(extracted_id, hex_id, id_len - 6);
      }
    } else {
      if (id_len < 65) {
        strcpy(extracted_id, hex_id);
      }
    }

    if (is_share_route) {
      if (strcmp(method, "POST") == 0) {
        return handle_share(conn, server, extracted_id, upload_data, upload_data_size, con_cls);
      }
      return send_error_cors(conn, server->cors_origin, MHD_HTTP_METHOD_NOT_ALLOWED, "only POST is accepted on /objects/<id>/share");
    }

    if (!*con_cls) {
      *con_cls = (void *)1;
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

/* -------------------------------------------------------------------------
 * Completed callback — free per-request state
 * ---------------------------------------------------------------------- */

static void request_completed(void *cls, struct MHD_Connection *conn,
                              void **con_cls,
                              enum MHD_RequestTerminationCode toe) {
  (void)cls;
  (void)conn;
  (void)toe;

  if (!con_cls || !*con_cls)
    return;

  /*
   * Only PUT and POST auth requests allocate a real UploadBuffer.
   * GET/DELETE/logout use the sentinel value 1.
   */
  if (*con_cls == (void *)1) {
    *con_cls = NULL;
    return;
  }

  UploadBuffer *ub = *con_cls;
  free(ub->buf);
  free(ub);
  *con_cls = NULL;
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

ApiServer *api_server_start(unsigned int port, const char *cors_origin, ObjectStore *store,
                            TokenStore *tokens) {
  if (!store)
    return NULL;

  ApiServer *server = malloc(sizeof(ApiServer));
  if (!server)
    return NULL;

  server->store = store;
  server->tokens = tokens;
  server->cors_origin = cors_origin; /* Track dynamic value safely here */

  /*
   * MHD_USE_INTERNAL_POLLING_THREAD: MHD manages its own thread so
   * the caller doesn't need to drive a select/epoll loop.
   * MHD_USE_ERROR_LOG: write MHD-internal errors to stderr.
   */
  server->daemon = MHD_start_daemon(
      MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG, (uint16_t)port, NULL,
      NULL,
      access_handler, server,
      MHD_OPTION_NOTIFY_COMPLETED, request_completed,
      NULL,
      MHD_OPTION_END);

  if (!server->daemon) {
    free(server);
    return NULL;
  }

  return server;
}

void api_server_stop(ApiServer *server) {
  if (!server)
    return;
  MHD_stop_daemon(server->daemon);
  free(server);
}
