#ifndef LANTERN_SUPPORT_SECURE_MEM_H
#define LANTERN_SUPPORT_SECURE_MEM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Overwrite a writable memory range with zero bytes.
 *
 * The implementation uses volatile stores that the compiler must preserve.
 * After a successful call, all `len` bytes are zero. A `NULL` pointer or zero
 * length has no effect. The caller retains ownership of the memory. Concurrent
 * calls must use nonoverlapping ranges or external synchronization.
 *
 * @param[in,out] ptr Start of a writable `len`-byte range. This value can be
 * `NULL`.
 * @param[in] len Number of bytes to overwrite.
 */
void lantern_secure_zero(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* LANTERN_SUPPORT_SECURE_MEM_H */
