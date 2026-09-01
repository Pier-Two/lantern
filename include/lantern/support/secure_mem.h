#ifndef LANTERN_SUPPORT_SECURE_MEM_H
#define LANTERN_SUPPORT_SECURE_MEM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * Clear a writable memory range with non-optimizable stores.
     *
     * This function is thread-safe for separate memory ranges.
     *
     * @param ptr Writable memory, or NULL when len is zero.
     * @param len Number of bytes to clear.
     */
    void lantern_secure_zero(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* LANTERN_SUPPORT_SECURE_MEM_H */
