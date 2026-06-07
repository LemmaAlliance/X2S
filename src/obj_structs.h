#ifndef OBJ_STRUCTS_H
#define OBJ_STRUCTS_H

#include <stdlib.h>

typedef struct {
    char *category;
    char *extension;
    char *filename;
} Metadata;

typedef struct {
    unsigned char id[32]; // SHA-256
    size_t size; // byte length of data
    Metadata *metadata; // populated on get_object, NULL otherwise
    void *data; // populated on get_object, NULL otherwise
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