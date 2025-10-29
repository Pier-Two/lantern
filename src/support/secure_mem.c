#include "lantern/support/secure_mem.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(__STDC_LIB_EXT1__)
#define HAVE_MEMSET_S 1
#endif

#if defined(_MSC_VER)
#include <windows.h>
#endif

void lantern_secure_zero(void *ptr, size_t len) {
    if (!ptr || len == 0) {
        return;
    }

#if defined(HAVE_MEMSET_S)
    memset_s(ptr, len, 0, len);
    return;
#elif defined(_WIN32)
    SecureZeroMemory(ptr, len);
    return;
#elif defined(__GNUC__) || defined(__clang__)
    __builtin_memset(ptr, 0, len);
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
    return;
#else
    volatile uint8_t *volatile bytes = (volatile uint8_t *volatile)ptr;
    for (size_t i = 0; i < len; ++i) {
        bytes[i] = 0;
    }
#endif
}
