#ifndef FORMAT_H
#define FORMAT_H

#include <stdint.h>
#include <stdio.h>

#define X2S_MAGIC_0         0x58
#define X2S_MAGIC_1         0x32

#define X2S_FILE_TYPE_METADATA  0x01
#define X2S_FILE_TYPE_INDEX     0x02
#define X2S_FILE_TYPE_USERS     0x03

#define X2S_FORMAT_VERSION_1   1

typedef struct {
    uint8_t magic[2];
    uint8_t file_type;
    uint8_t version;
} x2s_file_header_t;

static inline int write_header(FILE *f, uint8_t file_type, uint8_t version) {
    x2s_file_header_t hdr = {{X2S_MAGIC_0, X2S_MAGIC_1}, file_type, version};
    return fwrite(&hdr, sizeof(hdr), 1, f) == 1;
}

static inline int read_header(FILE *f, x2s_file_header_t *out) {
    return fread(out, sizeof(*out), 1, f) == 1;
}

static inline int header_matches(const x2s_file_header_t *hdr, uint8_t expected_type) {
    return hdr->magic[0] == X2S_MAGIC_0 &&
           hdr->magic[1] == X2S_MAGIC_1 &&
           hdr->file_type == expected_type;
}

int try_read_header(FILE *f, uint8_t expected_type, uint8_t *out_version);
int try_write_header(FILE *f, uint8_t file_type);

#endif
