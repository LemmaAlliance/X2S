#ifndef OBJ_OPERATIONS_H
#define OBJ_OPERATIONS_H

#include <stdlib.h>
#include "obj_structs.h"

ObjectStore *create_store(size_t initial_capacity, const char *path);
void free_store(ObjectStore *store);
void free_metadata(Metadata *metadata);
int put_object(ObjectStore *store, User *user, Object *obj);
Object *get_object(ObjectStore *store, User *user, const unsigned char id[32]);
int remove_object(ObjectStore *store, User *user, const unsigned char id[32]);
int check_object_permission(ObjectStore *store, const unsigned char id[32],
                            unsigned char user_id[16], uint32_t perm);
int share_object(ObjectStore *store, User *requester, const unsigned char id[32], 
                 unsigned char target_user_id[16], uint32_t permissions);
int list_user_objects(ObjectStore *store, User *user, 
                      const char *filter_category, const char *filter_filename,
                      const char *filter_extension,
                      Object ***out_objects, size_t *out_count);

#endif