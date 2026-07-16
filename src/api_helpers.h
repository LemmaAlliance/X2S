#ifndef API_HELPERS_H
#define API_HELPERS_H

#include <microhttpd.h>
#include "auth.h"
#include "obj_structs.h"

#define MAX_UPLOAD_SIZE (64u * 1024u * 1024u)

/* -------------------------------------------------------------------------
 * Internal types
 * ---------------------------------------------------------------------- */

typedef enum {
  BUFFER_TYPE_UPLOAD,      /* UploadBuffer: in-memory buffer for auth requests */
  BUFFER_TYPE_FILE_UPLOAD  /* FileUploadBuffer: temporary file for object uploads */
} BufferType;

struct ApiServer {
  struct MHD_Daemon *daemon;
  ObjectStore *store;
  TokenStore *tokens;
  const char *cors_origin;
  const char *temporary_directory;
};

/*
 * Accumulates the request body for PUT uploads.
 * Allocated on first upload_data chunk, freed by the completed callback.
 */
typedef struct {
  BufferType type;  /* MUST be first field */
  char *buf;
  size_t len;
  size_t cap;
} UploadBuffer;

typedef struct {
  BufferType type;  /* MUST be first field */
  FILE *fp;
  size_t len;
} FileUploadBuffer;

char *json_escape(const char *s);
const char *mime_for_extension(const char *ext);
enum MHD_Result send_error(struct MHD_Connection *conn,
                                  unsigned int status, const char *msg);
int hex_char(char c);
int parse_hex_id(const char *hex, unsigned char out[32]);
int parse_form_field(const char *body, const char *field, char *out,
                            size_t out_size);
void get_user_from_request(struct MHD_Connection *conn, User *user,
                                  TokenStore *tokens);
int read_object_file(ObjectStore *store, const unsigned char id[32], Object *out);

#endif