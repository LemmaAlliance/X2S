#ifndef OBJECT_INDEX_H
#define OBJECT_INDEX_H

#include <stdlib.h>
#include "core/object_types.h"

size_t hash_id(const unsigned char id[32]);
size_t index_for(ObjectStore* store, const unsigned char id[32]);

#endif
