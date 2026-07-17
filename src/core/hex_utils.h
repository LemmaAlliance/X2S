#ifndef HEX_UTILS_H
#define HEX_UTILS_H

#include <stddef.h>

int  hex_char(char c);
int  hex_to_bytes(const char* hex, unsigned char* out, size_t out_len);
void bytes_to_hex(const unsigned char* bytes, size_t len, char* out);

#endif
