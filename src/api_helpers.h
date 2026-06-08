#ifndef API_HELPERS_H
#define API_HELPERS_H

#include <microhttpd.h>
#include "auth.h"
#include "obj_structs.h"

#define MAX_UPLOAD_SIZE (64u * 1024u * 1024u)

/* -------------------------------------------------------------------------
 * Internal types
 * ---------------------------------------------------------------------- */

struct ApiServer {
  struct MHD_Daemon *daemon;
  ObjectStore *store;
  TokenStore *tokens;
};

/*
 * Accumulates the request body for PUT uploads.
 * Allocated on first upload_data chunk, freed by the completed callback.
 */
typedef struct {
  char *buf;
  size_t len;
  size_t cap;
} UploadBuffer;

const char *mime_for_extension(const char *ext);
enum MHD_Result send_error(struct MHD_Connection *conn,
                                  unsigned int status, const char *msg);
int hex_char(char c);
int parse_hex_id(const char *hex, unsigned char out[32]);
int parse_form_field(const char *body, const char *field, char *out,
                            size_t out_size);
void get_user_from_request(struct MHD_Connection *conn, User *user,
                                  TokenStore *tokens);

#endif