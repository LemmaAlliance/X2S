#ifndef OBJECT_REPOSITORY_H
#define OBJECT_REPOSITORY_H

/*
 * Core CRUD operations for the object store.
 *
 * Manages object creation (with deduplication), retrieval, deletion,
 * permission-based sharing, and filtered listing. Maintains an in-memory
 * hash index backed by an on-disk index file for fast lookups.
 */

#include <stdlib.h>
#include "core/object_types.h"

ObjectStore* create_store(size_t initial_capacity, const char* path);
void         free_store(ObjectStore* store);
int          put_object(ObjectStore* store, User* user, Object* obj);
Object*      get_object(ObjectStore* store, User* user, const unsigned char id[32]);
int          remove_object(ObjectStore* store, User* user, const unsigned char id[32]);
int          check_object_permission(ObjectStore* store, const unsigned char id[32],
                                     unsigned char user_id[16], uint32_t perm);
int          share_object(ObjectStore* store, User* requester, const unsigned char id[32],
                          unsigned char target_user_id[16], uint32_t permissions);
int          list_user_objects(ObjectStore* store, User* user, const char* filter_category,
                               const char* filter_filename, const char* filter_extension,
                               const char* filter_metadata_key, const char* filter_metadata_value,
                               Object*** out_objects, size_t* out_count);
int          load_index(ObjectStore* store);

#endif
