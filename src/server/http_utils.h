#ifndef HTTP_UTILS_H
#define HTTP_UTILS_H

#include <microhttpd.h>
#include "auth/auth.h"
#include "core/object_types.h"

#define MAX_UPLOAD_SIZE (64u * 1024u * 1024u)

typedef enum {
    BUFFER_TYPE_UPLOAD,
    BUFFER_TYPE_FILE_UPLOAD
} BufferType;

struct ApiServer {
    struct MHD_Daemon *daemon;
    ObjectStore *store;
    TokenStore *tokens;
    const char *cors_origin;
    const char *temporary_directory;
};

typedef struct {
    BufferType type;
    char *buf;
    size_t len;
    size_t cap;
} UploadBuffer;

typedef struct {
    BufferType type;
    FILE *fp;
    size_t len;
} FileUploadBuffer;

char *json_escape(const char *s);
enum MHD_Result send_error(struct MHD_Connection *conn,
                                  unsigned int status, const char *msg);
int hex_char(char c);
int parse_hex_id(const char *hex, unsigned char out[32]);
int parse_form_field(const char *body, const char *field, char *out,
                            size_t out_size);
void get_user_from_request(struct MHD_Connection *conn, User *user,
                                  TokenStore *tokens);

#endif
