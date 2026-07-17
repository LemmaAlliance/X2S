#ifndef OBJECT_PERMISSIONS_H
#define OBJECT_PERMISSIONS_H

#include <stdint.h>
#include "core/object_types.h"

int has_permission(Object* obj, unsigned char user_id[16], uint32_t perm);

#endif
