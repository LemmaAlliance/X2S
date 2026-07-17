#include <stdio.h>
#include <string.h>
#include "core/hex_utils.h"

int hex_char(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

int hex_to_bytes(const char* hex, unsigned char* out, size_t out_len)
{
    if (!hex || !out)
        return 0;
    if (strlen(hex) < out_len * 2)
        return 0;

    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_char(hex[i * 2]);
        int lo = hex_char(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

void bytes_to_hex(const unsigned char* bytes, size_t len, char* out)
{
    for (size_t i = 0; i < len; i++)
        snprintf(out + i * 2, 3, "%02x", bytes[i]);
}
