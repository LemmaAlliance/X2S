#ifndef OBJECT_SERIALIZATION_H
#define OBJECT_SERIALIZATION_H

#include <stdio.h>
#include <stdint.h>

char *read_string_field(FILE *f, size_t len);
int try_read_header(FILE *f, uint8_t expected_type, uint8_t *out_version);
int try_write_header(FILE *f, uint8_t file_type);

#endif
