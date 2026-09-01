#ifndef LANTERN_SUPPORT_STRINGS_H
#define LANTERN_SUPPORT_STRINGS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @file
     * String conversion and copy helpers.
     *
     * Functions are thread-safe when callers do not share writable buffers.
     */

    /** Return an owned duplicate, or NULL for invalid input or allocation
     * failure. */
    char *lantern_string_duplicate(const char *source);

    /** Return an owned duplicate of length bytes, or NULL on failure. */
    char *lantern_string_duplicate_len(const char *source, size_t length);

    /** Copy src with termination and return its full length. */
    size_t lantern_string_copy(char *dst, size_t dst_len, const char *src);

    /** Trim value in place and return its first non-whitespace byte. */
    char *lantern_trim_whitespace(char *value);

    /** Decode exactly out_len bytes and return zero on success. */
    int lantern_hex_decode(const char *hex, uint8_t *out, size_t out_len);

    /** Encode len bytes and return zero on success. */
    int lantern_bytes_to_hex(const uint8_t *bytes, size_t len, char *out,
                             size_t out_len, bool include_prefix);

#ifdef __cplusplus
}
#endif

#endif /* LANTERN_SUPPORT_STRINGS_H */
