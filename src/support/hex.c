#include "lantern/support/hex.h"

#include <ctype.h>
#include <stdint.h>
#include <string.h>

static enum lantern_hex_result hex_value(char value, uint8_t *out_value)
{
    if (!out_value)
    {
        return LANTERN_HEX_ERR_INVALID;
    }
    if (value >= '0' && value <= '9')
    {
        *out_value = (uint8_t)(value - '0');
        return LANTERN_HEX_OK;
    }
    if (value >= 'a' && value <= 'f')
    {
        *out_value = (uint8_t)(value - 'a' + 10);
        return LANTERN_HEX_OK;
    }
    if (value >= 'A' && value <= 'F')
    {
        *out_value = (uint8_t)(value - 'A' + 10);
        return LANTERN_HEX_OK;
    }

    return LANTERN_HEX_ERR_INVALID;
}

enum lantern_hex_result lantern_hex_decode(const char *hex, uint8_t *out,
                                           size_t out_len)
{
    if (!hex || !out || out_len == 0)
    {
        return LANTERN_HEX_ERR_INVALID;
    }
    if (out_len > SIZE_MAX / 2u)
    {
        return LANTERN_HEX_ERR_RANGE;
    }

    while (*hex && isspace((unsigned char)*hex))
    {
        ++hex;
    }
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
    {
        hex += 2;
    }

    size_t hex_len = strlen(hex);
    while (hex_len > 0 && isspace((unsigned char)hex[hex_len - 1u]))
    {
        --hex_len;
    }

    if (hex_len != out_len * 2u)
    {
        return LANTERN_HEX_ERR_INVALID;
    }

    /* Validate all input before writing to preserve the failure contract. */
    for (size_t i = 0; i < hex_len; ++i)
    {
        uint8_t value;
        if (hex_value(hex[i], &value) != LANTERN_HEX_OK)
        {
            return LANTERN_HEX_ERR_INVALID;
        }
    }

    /* Complete validation guarantees that both conversions succeed. */
    for (size_t i = 0; i < out_len; ++i)
    {
        uint8_t hi;
        uint8_t lo;
        (void)hex_value(hex[i * 2u], &hi);
        (void)hex_value(hex[i * 2u + 1u], &lo);
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    return LANTERN_HEX_OK;
}

enum lantern_hex_result lantern_hex_encode(const uint8_t *bytes, size_t len,
                                             char *out, size_t out_len,
                                             bool include_prefix)
{
    static const char hex_digits[] = "0123456789abcdef";

    if (!bytes || !out)
    {
        if (out && out_len > 0)
        {
            out[0] = '\0';
        }
        return LANTERN_HEX_ERR_INVALID;
    }

    size_t extra = include_prefix ? 3u : 1u;
    if (len > (SIZE_MAX - extra) / 2u)
    {
        if (out_len > 0)
        {
            out[0] = '\0';
        }
        return LANTERN_HEX_ERR_RANGE;
    }

    size_t required = (len * 2u) + extra;
    if (out_len < required)
    {
        if (out_len > 0)
        {
            out[0] = '\0';
        }
        return LANTERN_HEX_ERR_RANGE;
    }

    size_t offset = 0;
    if (include_prefix)
    {
        out[offset++] = '0';
        out[offset++] = 'x';
    }

    for (size_t i = 0; i < len; ++i)
    {
        uint8_t byte = bytes[i];
        out[offset++] = hex_digits[(byte >> 4) & 0x0f];
        out[offset++] = hex_digits[byte & 0x0f];
    }

    out[offset] = '\0';
    return LANTERN_HEX_OK;
}
