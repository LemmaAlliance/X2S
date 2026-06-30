#include <stdint.h>
#include <string.h>
#include <microhttpd.h>
#include <stdio.h>
#include "auth.h"
#include "obj_structs.h"

/* Maximum accepted request body size: 64 MiB */
#define MAX_UPLOAD_SIZE (64u * 1024u * 1024u)

/* -------------------------------------------------------------------------
 * MIME type lookup
 * ---------------------------------------------------------------------- */

const char *mime_for_extension(const char *ext) {
  if (!ext)
    return "application/octet-stream";

  const struct {
    const char *ext;
    const char *mime;
  } table[] = {{"txt", "text/plain"},
               {"html", "text/html"},
               {"htm", "text/html"},
               {"css", "text/css"},
               {"js", "application/javascript"},
               {"json", "application/json"},
               {"xml", "application/xml"},
               {"csv", "text/csv"},
               {"png", "image/png"},
               {"jpg", "image/jpeg"},
               {"jpeg", "image/jpeg"},
               {"gif", "image/gif"},
               {"webp", "image/webp"},
               {"svg", "image/svg+xml"},
               {"pdf", "application/pdf"},
               {"zip", "application/zip"},
               {"gz", "application/gzip"},
               {"mp3", "audio/mpeg"},
               {"mp4", "video/mp4"},
               {NULL, NULL}};

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
enum MHD_Result send_error(struct MHD_Connection *conn,
                                  unsigned int status, const char *msg) {
  /* {"error":"<msg>"} — msg is internal so no escaping needed */
  size_t json_len = strlen(msg) + 12; /* {"error":""} = 12 chars */
  char *json = malloc(json_len + 1);
  if (!json)
    return MHD_NO;

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

int hex_char(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

/*
 * Parse a 64-character hex string into a 32-byte binary ID.
 * Returns 1 on success, 0 if the string is malformed.
 */
int parse_hex_id(const char *hex, unsigned char out[32]) {
  if (strlen(hex) != 64)
    return 0;
  for (int i = 0; i < 32; i++) {
    int hi = hex_char(hex[i * 2]);
    int lo = hex_char(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0)
      return 0;
    out[i] = (unsigned char)((hi << 4) | lo);
  }
  return 1;
}

/*
 * Parse a value from URL-encoded form data.
 * Returns 1 if the field was found and copied, 0 otherwise.
 */
int parse_form_field(const char *body, const char *field, char *out,
                            size_t out_size) {
  if (!body || !field || !out || out_size == 0)
    return 0;
  out[0] = '\0';

  size_t field_len = strlen(field);
  const char *start = body;

  while ((start = strstr(start, field)) != NULL) {
    if (start == body || start[-1] == '&') {
      start += field_len;
      if (*start == '=') {
        start++;
        size_t val_len = 0;
        while (start[val_len] && start[val_len] != '&')
          val_len++;
        size_t copy = (val_len < out_size - 1) ? val_len : out_size - 1;
        memcpy(out, start, copy);
        out[copy] = '\0';
        return 1;
      }
    }
    start++;
  }

  return 0;
}

/*
 * Extract a User identity from request headers or bearer token.
 * Falls back to a zeroed-out anonymous user when no headers are present.
 *   Authorization: Bearer <64-hex-char-token>
 *   X-User-Id: 32 hex chars → 16-byte user_id
 *   X-Username: plain text name (max 63 chars)
 */
void get_user_from_request(struct MHD_Connection *conn, User *user,
                           TokenStore *tokens) {
  // 1. Initialize to a safe baseline default (Anonymous)
  memset(user, 0, sizeof(User));
  // TODO: What if a user is actually called anonymous??
  snprintf(user->username, sizeof(user->username), "anonymous");

  const char *auth =
      MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Authorization");
  
  // 2. If an Authorization header is attempted, strictly validate it
  if (auth) {
    if (strncmp(auth, "Bearer ", 7) == 0 && tokens) {
      const char *hex_token = auth + 7;
      if (strlen(hex_token) == TOKEN_SIZE * 2) {
        unsigned char token_bin[TOKEN_SIZE];
        if (hex_to_bytes(hex_token, token_bin, TOKEN_SIZE)) {
          unsigned char uid[16];
          if (session_lookup(tokens->sessions, token_bin, uid)) {
            // Token is verified and valid
            memcpy(user->user_id, uid, 16);
            user_store_get_username(tokens->users, uid, user->username,
                                    sizeof(user->username));
            return; // Successfully authenticated
          }
        }
      }
    }
  }

  return;
}