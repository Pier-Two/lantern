#ifndef LANTERN_SUPPORT_SECURE_MEM_H
#define LANTERN_SUPPORT_SECURE_MEM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void lantern_secure_zero(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* LANTERN_SUPPORT_SECURE_MEM_H */
