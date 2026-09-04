#ifndef LANTERN_SUPPORT_HEX_H
#define LANTERN_SUPPORT_HEX_H

/**
 * @file
 * Convert between caller-owned byte buffers and hexadecimal text.
 *
 * Decoding accepts surrounding whitespace and an optional `0x` prefix, and it
 * validates the complete input before changing the output buffer. Encoding
 * produces lowercase text with an optional prefix. Both operations report
 * invalid arguments and unsafe sizes through `lantern_hex_result`.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/** Distinguishes successful conversion from invalid input and unsafe sizes. */
enum lantern_hex_result
{
    LANTERN_HEX_OK = 0,
    LANTERN_HEX_ERR_INVALID = -1,
    LANTERN_HEX_ERR_RANGE = -2,
};

/**
 * Decode hexadecimal text into an exact number of bytes.
 *
 * The input can have surrounding whitespace and an optional `0x` prefix.
 * Each byte requires exactly two hexadecimal characters after these are
 * removed. The function leaves `out` unchanged after every failure. The
 * caller retains ownership of both buffers. The buffers must not overlap.
 * Concurrent calls must use separate output buffers.
 *
 * @param[in] hex Null-terminated text to decode. Must not be `NULL`.
 * @param[out] out Buffer for exactly `out_len` decoded bytes. Must not be
 * `NULL`.
 * @param[in] out_len Required decoded size in bytes. Must be greater than
 * zero.
 * @return `LANTERN_HEX_OK` after writing exactly `out_len` bytes.
 * @return `LANTERN_HEX_ERR_INVALID` when a pointer is `NULL`, `out_len` is
 * zero, the text length is incorrect, or the text contains a non-hexadecimal
 * character.
 * @return `LANTERN_HEX_ERR_RANGE` when doubling `out_len` would overflow
 * `size_t`.
 */
enum lantern_hex_result lantern_hex_decode(const char *hex, uint8_t *out,
                                           size_t out_len);

/**
 * Encode bytes as lowercase hexadecimal text.
 *
 * The function adds a `0x` prefix when `include_prefix` is true. A successful
 * result always includes a null terminator. Each failure empties `out` when
 * `out` is not `NULL` and `out_len` is greater than zero. The caller retains
 * ownership of both buffers. The buffers must not overlap. Concurrent calls
 * must use separate output buffers.
 *
 * @param[in] bytes Buffer containing `len` bytes. Must not be `NULL`, including
 * when `len` is zero.
 * @param[in] len Number of bytes to encode.
 * @param[out] out Buffer that receives the encoded null-terminated text. Must
 * not be `NULL`.
 * @param[in] out_len Output capacity in bytes, including the null terminator.
 * @param[in] include_prefix Selects whether the output starts with `0x`.
 * @return `LANTERN_HEX_OK` after writing the complete encoded string.
 * @return `LANTERN_HEX_ERR_INVALID` when `bytes` or `out` is `NULL`.
 * @return `LANTERN_HEX_ERR_RANGE` when the required size would overflow
 * `size_t` or exceeds `out_len`.
 */
enum lantern_hex_result lantern_hex_encode(const uint8_t *bytes, size_t len,
                                           char *out, size_t out_len,
                                           bool include_prefix);

#ifdef __cplusplus
}
#endif

#endif /* LANTERN_SUPPORT_HEX_H */
