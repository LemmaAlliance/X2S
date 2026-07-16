#ifndef OBJECT_CRYPTO_H
#define OBJECT_CRYPTO_H

#include <stddef.h>
#include "core/object_types.h"

int compute_object_id(User *user, Object *obj, unsigned char out[32]);
int compute_data_hash(const unsigned char *data, size_t size, unsigned char out[32]);

#endif
