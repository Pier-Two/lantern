#include "lantern/support/secure_mem.h"

#include <stdint.h>

void lantern_secure_zero(void *ptr, size_t len)
{
    if (!ptr || len == 0)
    {
        return;
    }

    /* Volatile stores keep the compiler from removing the secret clear. */
    volatile uint8_t *bytes = ptr;
    while (len > 0)
    {
        *bytes = 0;
        ++bytes;
        --len;
    }
}
