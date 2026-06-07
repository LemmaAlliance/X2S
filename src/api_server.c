#define _POSIX_C_SOURCE 200809L  /* for strcasecmp */
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <microhttpd.h>
#include "obj_structs.h"
#include "obj_operations.h"
#include "api_server.h"

/* -------------------------------------------------------------------------
 * Internal types
 * ---------------------------------------------------------------------- */

struct ApiServer {
    struct MHD_Daemon *daemon;
    ObjectStore       *store;
};

/*
 * Accumulates the request body for PUT uploads.
 * Allocated on first upload_data chunk, freed by the completed callback.
 */
typedef struct {
    char   *buf;
    size_t  len;
    size_t  cap;
} UploadBuffer;

/* Maximum accepted request body size: 64 MiB */
#define MAX_UPLOAD_SIZE (64u * 1024u * 1024u)

/* -------------------------------------------------------------------------
 * MIME type lookup
 * ---------------------------------------------------------------------- */

static const char *mime_for_extension(const char *ext) {
    if (!ext) return "application/octet-stream";

    static const struct { const char *ext; const char *mime; } table[] = {
        { "txt",  "text/plain"                },
        { "html", "text/html"                 },
        { "htm",  "text/html"                 },
        { "css",  "text/css"                  },
        { "js",   "application/javascript"    },
        { "json", "application/json"          },
        { "xml",  "application/xml"           },
        { "csv",  "text/csv"                  },
        { "png",  "image/png"                 },
        { "jpg",  "image/jpeg"                },
        { "jpeg", "image/jpeg"                },
        { "gif",  "image/gif"                 },
        { "webp", "image/webp"                },
        { "svg",  "image/svg+xml"             },
        { "pdf",  "application/pdf"           },
        { "zip",  "application/zip"           },
        { "gz",   "application/gzip"          },
        { "mp3",  "audio/mpeg"                },
        { "mp4",  "video/mp4"                 },
        { NULL,   NULL                        }
    };

    for (int i = 0; table[i].ext; i++) {
        if (strcasecmp(ext, table[i].ext) == 0)
            return table[i].mime;
    }

    return "application/octet-stream";
}

/* -------------------------------------------------------------------------
 * Response helpers
 * ---------------------------------------------------------------------- */

/*
 * Send a JSON error body: {"error":"<msg>"}
 * Allocates a small heap buffer so the caller doesn't have to.
 */
static enum MHD_Result send_error(struct MHD_Connection *conn,
                                  unsigned int status,
                                  const char *msg) {
    /* {"error":"<msg>"} — msg is internal so no escaping needed */
    size_t json_len = strlen(msg) + 12; /* {"error":""} = 12 chars */
    char *json = malloc(json_len + 1);
    if (!json) return MHD_NO;

    snprintf(json, json_len + 1, "{\"error\":\"%s\"}", msg);

    struct MHD_Response *resp =
        MHD_create_response_from_buffer(json_len, json, MHD_RESPMEM_MUST_FREE);
    if (!resp) {
        free(json);
        return MHD_NO;
    }

    MHD_add_response_header(resp, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(conn, status, resp);
    MHD_destroy_response(resp);
    return ret;
}

/* -------------------------------------------------------------------------
 * Hex parsing
 * ---------------------------------------------------------------------- */

static int hex_char(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/*
 * Parse a 64-character hex string into a 32-byte binary ID.
 * Returns 1 on success, 0 if the string is malformed.
 */
static int parse_hex_id(const char *hex, unsigned char out[32]) {
    if (strlen(hex) != 64) return 0;
    for (int i = 0; i < 32; i++) {
        int hi = hex_char(hex[i * 2]);
        int lo = hex_char(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
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
                                  ApiServer *server,
                                  const char *upload_data,
                                  size_t *upload_data_size,
                                  void **con_cls) {
    /* First call — initialise the accumulation buffer */
    if (!*con_cls) {
        UploadBuffer *ub = calloc(1, sizeof(UploadBuffer));
        if (!ub) return MHD_NO;
        *con_cls = ub;
        return MHD_YES;
    }

    UploadBuffer *ub = *con_cls;

    /* Accumulate body chunks */
    if (*upload_data_size > 0) {
        size_t incoming = *upload_data_size;

        if (ub->len + incoming > MAX_UPLOAD_SIZE)
            return send_error(conn, MHD_HTTP_CONTENT_TOO_LARGE,
                              "body exceeds 64 MiB limit");

        /* Grow buffer if needed */
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

    /* Final call — upload_data_size == 0, process the complete body */
    if (ub->len == 0)
        return send_error(conn, MHD_HTTP_BAD_REQUEST, "empty body");

    /* Read optional metadata headers */
    const char *category  = MHD_lookup_connection_value(conn, MHD_HEADER_KIND,
                                                        "X-Category");
    const char *extension = MHD_lookup_connection_value(conn, MHD_HEADER_KIND,
                                                        "X-Extension");
    const char *filename  = MHD_lookup_connection_value(conn, MHD_HEADER_KIND,
                                                        "X-Filename");

    Metadata meta = {
        .category  = (char *)category,   /* cast away const — put_object */
        .extension = (char *)extension,  /* only reads these pointers    */
        .filename  = (char *)filename,
    };

    Object obj = {0};
    obj.data     = ub->buf;
    obj.size     = ub->len;
    obj.metadata = (category || extension || filename) ? &meta : NULL;

    if (!put_object(server->store, &obj))
        return send_error(conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
                          "failed to store object");

    /* Build response: {"id":"<64 hex chars>"} */
    char json[80]; /* {"id":"" + 64 chars + "}"} = 73 bytes */
    snprintf(json, sizeof(json), "{\"id\":\"");
    for (int i = 0; i < 32; i++)
        snprintf(json + 7 + i * 2, 3, "%02x", obj.id[i]);
    snprintf(json + 71, sizeof(json) - 71, "\"}");

    size_t json_len = strlen(json);
    char *json_copy = malloc(json_len + 1);
    if (!json_copy) return MHD_NO;
    memcpy(json_copy, json, json_len + 1);

    struct MHD_Response *resp =
        MHD_create_response_from_buffer(json_len, json_copy,
                                        MHD_RESPMEM_MUST_FREE);
    if (!resp) {
        free(json_copy);
        return MHD_NO;
    }

    MHD_add_response_header(resp, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_CREATED, resp);
    MHD_destroy_response(resp);
    return ret;
}

/*
 * GET /objects/<hex-id>
 */
static enum MHD_Result handle_get(struct MHD_Connection *conn,
                                  ApiServer *server,
                                  const char *hex_id) {
    unsigned char id[32];
    if (!parse_hex_id(hex_id, id))
        return send_error(conn, MHD_HTTP_BAD_REQUEST, "invalid object id");

    Object *obj = get_object(server->store, id);
    if (!obj)
        return send_error(conn, MHD_HTTP_NOT_FOUND, "object not found");

    /* obj->data is heap-allocated by get_object; pass ownership to MHD */
    struct MHD_Response *resp =
        MHD_create_response_from_buffer(obj->size, obj->data,
                                        MHD_RESPMEM_MUST_FREE);
    if (!resp) {
        free(obj->data);
        free_metadata(obj->metadata);
        free(obj);
        return MHD_NO;
    }

    /* obj->data now owned by MHD; free the rest ourselves */
    const char *mime = mime_for_extension(
        obj->metadata ? obj->metadata->extension : NULL);
    MHD_add_response_header(resp, "Content-Type", mime);

    free_metadata(obj->metadata);
    free(obj);   /* data already handed off; do NOT free(obj->data) here */

    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);
    return ret;
}

/*
 * DELETE /objects/<hex-id>
 */
static enum MHD_Result handle_delete(struct MHD_Connection *conn,
                                     ApiServer *server,
                                     const char *hex_id) {
    unsigned char id[32];
    if (!parse_hex_id(hex_id, id))
        return send_error(conn, MHD_HTTP_BAD_REQUEST, "invalid object id");

    if (!remove_object(server->store, id))
        return send_error(conn, MHD_HTTP_NOT_FOUND, "object not found");

    /* 204 No Content — no body */
    struct MHD_Response *resp =
        MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
    if (!resp) return MHD_NO;

    enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_NO_CONTENT, resp);
    MHD_destroy_response(resp);
    return ret;
}

/* -------------------------------------------------------------------------
 * Main MHD access callback — router
 * ---------------------------------------------------------------------- */

static enum MHD_Result access_handler(void *cls,
                                      struct MHD_Connection *conn,
                                      const char *url,
                                      const char *method,
                                      const char *version,
                                      const char *upload_data,
                                      size_t *upload_data_size,
                                      void **con_cls) {
    (void)version; /* unused */

    ApiServer *server = cls;

    /*
     * Route: /objects          → PUT only
     *        /objects/<hex-id> → GET or DELETE
     */
    if (strcmp(url, "/objects") == 0) {
        if (strcmp(method, "PUT") == 0)
            return handle_put(conn, server, upload_data,
                              upload_data_size, con_cls);
        return send_error(conn, MHD_HTTP_METHOD_NOT_ALLOWED,
                          "only PUT is accepted on /objects");
    }

    /* Prefix match: /objects/<id> */
    if (strncmp(url, "/objects/", 9) == 0) {
        const char *hex_id = url + 9;

        /* Initialise con_cls for the first call on non-PUT routes */
        if (!*con_cls) {
            *con_cls = (void *)1; /* sentinel — no buffer needed */
            return MHD_YES;
        }

        if (strcmp(method, "GET") == 0)
            return handle_get(conn, server, hex_id);
        if (strcmp(method, "DELETE") == 0)
            return handle_delete(conn, server, hex_id);

        return send_error(conn, MHD_HTTP_METHOD_NOT_ALLOWED,
                          "only GET and DELETE are accepted on /objects/<id>");
    }

    return send_error(conn, MHD_HTTP_NOT_FOUND, "unknown route");
}

/* -------------------------------------------------------------------------
 * Completed callback — free per-request state
 * ---------------------------------------------------------------------- */

static void request_completed(void *cls,
                               struct MHD_Connection *conn,
                               void **con_cls,
                               enum MHD_RequestTerminationCode toe) {
    (void)cls;
    (void)conn;
    (void)toe;

    if (!con_cls || !*con_cls) return;

    /*
     * Only PUT requests allocate a real UploadBuffer. GET/DELETE use the
     * sentinel value 1 — detect by checking pointer plausibility.
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

ApiServer *api_server_start(unsigned int port, ObjectStore *store) {
    if (!store) return NULL;

    ApiServer *server = malloc(sizeof(ApiServer));
    if (!server) return NULL;

    server->store = store;

    /*
     * MHD_USE_INTERNAL_POLLING_THREAD: MHD manages its own thread so
     * the caller doesn't need to drive a select/epoll loop.
     * MHD_USE_ERROR_LOG: write MHD-internal errors to stderr.
     */
    server->daemon = MHD_start_daemon(
        MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG,
        (uint16_t)port,
        NULL, NULL,                   /* accept policy callback — allow all */
        access_handler, server,       /* request handler + closure          */
        MHD_OPTION_NOTIFY_COMPLETED,
            request_completed, NULL,  /* cleanup callback                   */
        MHD_OPTION_END
    );

    if (!server->daemon) {
        free(server);
        return NULL;
    }

    return server;
}

void api_server_stop(ApiServer *server) {
    if (!server) return;
    MHD_stop_daemon(server->daemon);
    free(server);
}