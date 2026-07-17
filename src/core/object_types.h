#ifndef OBJECT_TYPES_H
#define OBJECT_TYPES_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#define PERM_READ 1
#define PERM_WRITE 2
#define PERM_DELETE 4

typedef struct
{
    char          username[64];
    unsigned char user_id[16];
} User;

typedef struct
{
    unsigned char user_id[16];
    uint32_t      permissions;
} ACLEntry;

typedef struct
{
    ACLEntry* entries;
    size_t    count;
} ACL;

typedef struct
{
    char*  category;
    char*  extension;
    char*  filename;
    char** metadata_keys;
    char** metadata_values;
    size_t metadata_count;
} Metadata;

typedef struct
{
    unsigned char  id[32];
    size_t         size;
    Metadata*      metadata;
    unsigned char* data;
    ACL*           acl;
    unsigned char  owner[16];
    unsigned char  data_hash[32];
} Object;

typedef struct ObjectNode
{
    Object*            obj;
    struct ObjectNode* next;
} ObjectNode;

typedef struct
{
    ObjectNode** buckets;
    size_t       capacity;
    size_t       count;
    char         store_path[4096];
} ObjectStore;

#endif
