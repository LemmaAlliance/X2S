#include "core/object_types.h"
#include "storage/object_index.h"

size_t hash_id(const unsigned char id[32])
{
    size_t h = 1469598103934665603ULL;

    for (int i = 0; i < 32; i++) {
        h ^= id[i];
        h *= 1099511628211ULL;
    }

    return h;
}

size_t index_for(ObjectStore* store, const unsigned char id[32])
{
    return hash_id(id) % store->capacity;
}
