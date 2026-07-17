#ifndef OBJECT_CRYPTO_H
#define OBJECT_CRYPTO_H

/*
 * Cryptographic hashing for object identity and data deduplication.
 *
 * compute_object_id produces a SHA-256 hash of (user_id || data || metadata)
 * to uniquely identify stored objects. compute_data_hash produces a SHA-256
 * hash of raw data for deduplication across objects.
 */

#include <stddef.h>
#include "core/object_types.h"

int compute_object_id(User* user, Object* obj, unsigned char out[32]);
int compute_data_hash(const unsigned char* data, size_t size, unsigned char out[32]);

#endif
