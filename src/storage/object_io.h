#ifndef OBJECT_IO_H
#define OBJECT_IO_H

#include <stdio.h>
#include "core/object_types.h"

void free_metadata(Metadata *metadata);
void id_to_hex(const unsigned char id[32], char out[65]);
void object_path(ObjectStore *store, const unsigned char id[32],
                 char *out, size_t out_len);
int write_object_file(ObjectStore *store, Object *obj);
int read_object_file(ObjectStore *store, const unsigned char id[32], Object *out);
void delete_metadata_file(ObjectStore *store, const unsigned char id[32]);
void delete_data_blob_file(ObjectStore *store, const unsigned char data_hash[32]);
int count_data_blob_references(ObjectStore *store,
    const unsigned char target_data_hash[32], const unsigned char current_meta_id[32]);

#endif
