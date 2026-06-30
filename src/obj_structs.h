#ifndef OBJ_STRUCTS_H
#define OBJ_STRUCTS_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#define PERM_READ  1
#define PERM_WRITE 2
#define PERM_DELETE 4

typedef struct {
    char username[64];
    unsigned char user_id[16];
} User;

typedef struct {
    unsigned char user_id[16];
    uint32_t permissions;
} ACLEntry;

typedef struct {
    ACLEntry *entries;
    size_t count;
} ACL;

typedef struct {
    char *category;
    char *extension;
    char *filename;
} Metadata;

typedef struct {
    unsigned char id[32]; // SHA-256
    size_t size; // byte length of data
    Metadata *metadata; // populated on get_object, NULL otherwise
    FILE *data; // populated on get_object, NULL otherwise
    ACL *acl;
    unsigned char owner[16];
} Object;

/* Linked list node for hash buckets */
typedef struct ObjectNode {
    Object *obj;
    struct ObjectNode *next;
} ObjectNode;

typedef struct {
    ObjectNode **buckets;
    size_t capacity;
    size_t count;
    char store_path[4096]; // directory where object files are written (PATH_MAX)
} ObjectStore;

#endif