#ifndef FORMAT_V2_H
#define FORMAT_V2_H

#include <stdio.h>
#include <stdint.h>
#include "core/object_types.h"
#include "core/format_registry.h"

int read_metadata_v2(FILE* f, Object* out);
int write_metadata_v2(FILE* f, Object* obj);

int read_index_v2(FILE* f, size_t* capacity, size_t* count, unsigned char** ids);
int write_index_v2(FILE* f, size_t capacity, size_t count, unsigned char* ids);

int read_users_v2(FILE* f, UserStore* store);
int write_users_v2(FILE* f, UserStore* store);

int read_data_hash_v2(FILE* f, unsigned char hash[32]);

#endif
