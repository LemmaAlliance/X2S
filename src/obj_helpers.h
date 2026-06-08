#ifndef OBJ_HELPERS_H
#define OBJ_HELPERS_H

#include <stdio.h>
#include "obj_structs.h"

int has_permission(Object *obj, unsigned char user_id[16], uint32_t perm);
void free_metadata(Metadata *metadata);
int compute_object_id(User *user, Object *obj, unsigned char out[32]);
size_t hash_id(const unsigned char id[32]);
size_t index_for(ObjectStore *store, const unsigned char id[32]);
int check_object_permission(ObjectStore *store, const unsigned char id[32],
    unsigned char user_id[16], uint32_t perm);
int load_index(ObjectStore *store);
void id_to_hex(const unsigned char id[32], char out[65]);
void object_path(ObjectStore *store, const unsigned char id[32],
    char *out, size_t out_len);
int count_data_blob_references(ObjectStore *store, 
    const unsigned char target_data_hash[32], const unsigned char current_meta_id[32]);
int compute_data_hash(const void *data, size_t size, unsigned char out[32]);
int write_object_file(ObjectStore *store, Object *obj);
char *read_string_field(FILE *f, size_t len);
int read_object_file(ObjectStore *store, const unsigned char id[32], Object *out);
void delete_metadata_file(ObjectStore *store, const unsigned char id[32]);
void delete_data_blob_file(ObjectStore *store, const unsigned char data_hash[32]);

#endif