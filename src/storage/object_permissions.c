#include <string.h>
#include "core/object_types.h"
#include "storage/object_permissions.h"

int has_permission(Object* obj, unsigned char user_id[16], uint32_t perm)
{
    if (!obj->acl)
        return 0;

    for (size_t i = 0; i < obj->acl->count; i++) {
        ACLEntry* e = &obj->acl->entries[i];
        if (memcmp(e->user_id, user_id, 16) == 0) {
            return (e->permissions & perm) != 0;
        }
    }

    return 0;
}
