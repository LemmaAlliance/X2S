#ifndef OBJECT_CRYPTO_H
#define OBJECT_CRYPTO_H

#include <stdio.h>
#include "core/object_types.h"

int compute_object_id(User *user, Object *obj, unsigned char out[32]);
int compute_data_hash(FILE *file, unsigned char out[32]);

#endif
