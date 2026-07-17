#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "core/format.h"
#include "storage/object_serialization.h"

char* read_string_field(FILE* f, size_t len)
{
    if (len == 0)
        return NULL;

    char* buf = malloc(len + 1);
    if (!buf)
        return NULL;

    if (fread(buf, 1, len, f) != len) {
        free(buf);
        return NULL;
    }

    buf[len] = '\0';
    return buf;
}

int try_read_header(FILE* f, uint8_t expected_type, uint8_t* out_version)
{
    X2sFileHeader hdr;
    long              start = ftell(f);

    if (fread(&hdr, sizeof(hdr), 1, f) != 1) {
        clearerr(f);
        fseek(f, start, SEEK_SET);
        return 0;
    }

    if (hdr.magic[0] == X2S_MAGIC_0 && hdr.magic[1] == X2S_MAGIC_1 &&
        hdr.file_type == expected_type) {
        if (hdr.version > X2S_FORMAT_VERSION_1) {
            return -1;
        }
        *out_version = hdr.version;
        return 1;
    }

    fseek(f, start, SEEK_SET);
    return 0;
}

int try_write_header(FILE* f, uint8_t file_type)
{
    return write_header(f, file_type, X2S_FORMAT_VERSION_1);
}
