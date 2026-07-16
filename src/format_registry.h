#ifndef FORMAT_REGISTRY_H
#define FORMAT_REGISTRY_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "obj_structs.h"
#include "auth.h"

typedef struct {
    uint8_t version;
    const char *name;

    int  (*read_metadata)(FILE *f, Object *out);
    int  (*write_metadata)(FILE *f, Object *obj);

    int  (*read_index)(FILE *f, size_t *capacity, size_t *count, unsigned char **ids);
    int  (*write_index)(FILE *f, size_t capacity, size_t count, unsigned char *ids);

    int  (*read_users)(FILE *f, UserStore *store);
    int  (*write_users)(FILE *f, UserStore *store);
} FormatVtable;

extern const FormatVtable format_registry[];
extern const size_t       format_registry_count;

const FormatVtable *lookup_format(uint8_t version);
const FormatVtable *latest_format(void);

#endif
