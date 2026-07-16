#include <stdint.h>
#include <string.h>
#include <microhttpd.h>
#include <stdio.h>
#include <stdlib.h>
#include "auth/auth.h"
#include "core/object_types.h"
#include "server/http_utils.h"

char *json_escape(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s);
    char *out = malloc(6 * len + 1);
    if (!out) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = s[i];
        switch (c) {
        case '"':  out[j++] = '\\'; out[j++] = '"';  break;
        case '\\': out[j++] = '\\'; out[j++] = '\\'; break;
        case '\n': out[j++] = '\\'; out[j++] = 'n';  break;
        case '\t': out[j++] = '\\'; out[j++] = 't';  break;
        case '\r': out[j++] = '\\'; out[j++] = 'r';  break;
        default:
            if (c < 0x20) {
                j += snprintf(out + j, 7, "\\u%04x", c);
            } else {
                out[j++] = c;
            }
        }
    }
    out[j] = '\0';
    return out;
}

int hex_char(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

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

void get_user_from_request(struct MHD_Connection *conn, User *user,
                           TokenStore *tokens) {
    memset(user, 0, sizeof(User));
    snprintf(user->username, sizeof(user->username), "anonymous");

    const char *auth =
        MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Authorization");

    if (auth) {
        if (strncmp(auth, "Bearer ", 7) == 0 && tokens) {
            const char *hex_token = auth + 7;
            if (strlen(hex_token) == TOKEN_SIZE * 2) {
                unsigned char token_bin[TOKEN_SIZE];
                if (hex_to_bytes(hex_token, token_bin, TOKEN_SIZE)) {
                    unsigned char uid[16];
                    if (session_lookup(tokens->sessions, token_bin, uid)) {
                        memcpy(user->user_id, uid, 16);
                        user_store_get_username(tokens->users, uid, user->username,
                                                sizeof(user->username));
                        return;
                    }
                }
            }
        }
    }

    return;
}
