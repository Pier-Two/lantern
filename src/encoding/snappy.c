#include "lantern/encoding/snappy.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "snappy.h"

enum {
    LANTERN_SNAPPY_CHUNK_COMPRESSED = 0x00,
    LANTERN_SNAPPY_CHUNK_UNCOMPRESSED = 0x01,
    LANTERN_SNAPPY_CHUNK_PADDING_START = 0x02,
    LANTERN_SNAPPY_CHUNK_PADDING_END = 0x7f,
    LANTERN_SNAPPY_CHUNK_RESERVED_START = 0x80,
    LANTERN_SNAPPY_CHUNK_RESERVED_END = 0xfe,
    LANTERN_SNAPPY_CHUNK_STREAM_IDENTIFIER = 0xff,
};

enum {
    LANTERN_SNAPPY_STREAM_IDENTIFIER_LEN = 6,
    LANTERN_SNAPPY_STREAM_HEADER_BYTES = 4 + LANTERN_SNAPPY_STREAM_IDENTIFIER_LEN,
    LANTERN_SNAPPY_CHUNK_HEADER_BYTES = 4,
    LANTERN_SNAPPY_CHUNK_CRC_BYTES = 4,
};

static uint32_t lantern_snappy_read_le24(const uint8_t *data) {
    return (uint32_t)data[0]
        | ((uint32_t)data[1] << 8u)
        | ((uint32_t)data[2] << 16u);
}

static int lantern_snappy_framed_uncompressed_length(
    const uint8_t *input,
    size_t input_len,
    size_t *result);

static int lantern_snappy_decompress_framed(
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t output_len,
    size_t *written);


static uint32_t lantern_snappy_crc32c(const uint8_t *data, size_t len);
static uint32_t lantern_snappy_mask_crc32c(uint32_t crc);
static void lantern_snappy_write_chunk_header(
    uint8_t chunk_type,
    uint32_t chunk_len,
    uint8_t header[4]);

int lantern_snappy_max_compressed_size(size_t input_len, size_t *max_size) {
    if (!max_size) {
        return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
    }
    size_t raw_max = snappy_max_compressed_length(input_len);
    size_t overhead = LANTERN_SNAPPY_STREAM_HEADER_BYTES
        + LANTERN_SNAPPY_CHUNK_HEADER_BYTES
        + LANTERN_SNAPPY_CHUNK_CRC_BYTES;
    if (SIZE_MAX - raw_max < overhead) {
        return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
    }
    *max_size = raw_max + overhead;
    return LANTERN_SNAPPY_OK;
}

int lantern_snappy_compress(
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t output_len,
    size_t *written) {
    if (!input || !output || !written) {
        return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
    }

    size_t raw_max = snappy_max_compressed_length(input_len);
    size_t overhead = LANTERN_SNAPPY_STREAM_HEADER_BYTES
        + LANTERN_SNAPPY_CHUNK_HEADER_BYTES
        + LANTERN_SNAPPY_CHUNK_CRC_BYTES;
    if (SIZE_MAX - raw_max < overhead) {
        return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
    }
    size_t required = raw_max + overhead;
    if (output_len < required) {
        *written = required;
        return LANTERN_SNAPPY_ERROR_BUFFER_TOO_SMALL;
    }

    uint8_t *compressed = (uint8_t *)malloc(raw_max);
    if (!compressed) {
        return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
    }

    struct snappy_env env;
    if (snappy_init_env(&env) != 0) {
        free(compressed);
        return LANTERN_SNAPPY_ERROR_UNSUPPORTED;
    }

    size_t compressed_len = 0;
    int rc = snappy_compress(&env,
                             (const char *)input,
                             input_len,
                             (char *)compressed,
                             &compressed_len);
    snappy_free_env(&env);
    if (rc != 0) {
        free(compressed);
        return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
    }

    size_t pos = 0;
    uint8_t header[4];
    lantern_snappy_write_chunk_header(
        LANTERN_SNAPPY_CHUNK_STREAM_IDENTIFIER,
        LANTERN_SNAPPY_STREAM_IDENTIFIER_LEN,
        header);
    memcpy(output + pos, header, sizeof(header));
    pos += sizeof(header);
    memcpy(output + pos, "sNaPpY", LANTERN_SNAPPY_STREAM_IDENTIFIER_LEN);
    pos += LANTERN_SNAPPY_STREAM_IDENTIFIER_LEN;

    uint32_t chunk_len = (uint32_t)(compressed_len + LANTERN_SNAPPY_CHUNK_CRC_BYTES);
    if (chunk_len > 0x00ffffffu) {
        free(compressed);
        return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
    }
    lantern_snappy_write_chunk_header(LANTERN_SNAPPY_CHUNK_COMPRESSED, chunk_len, header);
    memcpy(output + pos, header, sizeof(header));
    pos += sizeof(header);

    uint32_t crc = lantern_snappy_crc32c(input, input_len);
    uint32_t masked_crc = lantern_snappy_mask_crc32c(crc);
    output[pos + 0] = (uint8_t)(masked_crc & 0xffu);
    output[pos + 1] = (uint8_t)((masked_crc >> 8u) & 0xffu);
    output[pos + 2] = (uint8_t)((masked_crc >> 16u) & 0xffu);
    output[pos + 3] = (uint8_t)((masked_crc >> 24u) & 0xffu);
    pos += LANTERN_SNAPPY_CHUNK_CRC_BYTES;

    memcpy(output + pos, compressed, compressed_len);
    pos += compressed_len;

    free(compressed);
    *written = pos;
    return LANTERN_SNAPPY_OK;
}

int lantern_snappy_uncompressed_length(
    const uint8_t *input,
    size_t input_len,
    size_t *result) {
    if (!input || !result) {
        return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
    }

    size_t framed_length = 0;
    if (lantern_snappy_framed_uncompressed_length(input, input_len, &framed_length) == LANTERN_SNAPPY_OK) {
        *result = framed_length;
        return LANTERN_SNAPPY_OK;
    }

    size_t raw_length = 0;
    if (snappy_uncompressed_length((const char *)input, input_len, &raw_length)) {
        *result = raw_length;
        return LANTERN_SNAPPY_OK;
    }

    return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
}

int lantern_snappy_decompress(
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t output_len,
    size_t *written) {
    if (!input || !output || !written) {
        return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
    }

    size_t expected = 0;
    if (lantern_snappy_framed_uncompressed_length(input, input_len, &expected) == LANTERN_SNAPPY_OK) {
        if (output_len < expected) {
            *written = expected;
            return LANTERN_SNAPPY_ERROR_BUFFER_TOO_SMALL;
        }
        return lantern_snappy_decompress_framed(input, input_len, output, output_len, written);
    }

    if (!snappy_uncompressed_length((const char *)input, input_len, &expected)) {
        return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
    }
    if (output_len < expected) {
        *written = expected;
        return LANTERN_SNAPPY_ERROR_BUFFER_TOO_SMALL;
    }
    int rc = snappy_uncompress((const char *)input, input_len, (char *)output);
    if (rc != 0) {
        return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
    }
    *written = expected;
    return LANTERN_SNAPPY_OK;
}

static int lantern_snappy_framed_uncompressed_length(
    const uint8_t *input,
    size_t input_len,
    size_t *result) {
    size_t pos = 0;
    size_t total = 0;

    while (pos + 4 <= input_len) {
        uint8_t chunk_type = input[pos];
        uint32_t chunk_len = lantern_snappy_read_le24(&input[pos + 1]);
        pos += 4;
        if (chunk_len > input_len - pos) {
            return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
        }
        const uint8_t *chunk = &input[pos];
        pos += chunk_len;

        if (chunk_type == LANTERN_SNAPPY_CHUNK_STREAM_IDENTIFIER) {
            if (chunk_len != 6 || memcmp(chunk, "sNaPpY", 6) != 0) {
                return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
            }
            continue;
        }

        if (chunk_type == LANTERN_SNAPPY_CHUNK_COMPRESSED || chunk_type == LANTERN_SNAPPY_CHUNK_UNCOMPRESSED) {
            if (chunk_len < 4) {
                return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
            }
            size_t payload_len = chunk_len - 4;
            const uint8_t *payload = chunk + 4;
            if (chunk_type == LANTERN_SNAPPY_CHUNK_COMPRESSED) {
                size_t chunk_expected = 0;
                if (!snappy_uncompressed_length((const char *)payload, payload_len, &chunk_expected)) {
                    return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
                }
                if (SIZE_MAX - total < chunk_expected) {
                    return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
                }
                total += chunk_expected;
            } else {
                if (SIZE_MAX - total < payload_len) {
                    return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
                }
                total += payload_len;
            }
            continue;
        }

        if (chunk_type >= LANTERN_SNAPPY_CHUNK_PADDING_START && chunk_type <= LANTERN_SNAPPY_CHUNK_PADDING_END) {
            continue;
        }

        return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
    }

    if (pos != input_len) {
        return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
    }

    if (result) {
        *result = total;
    }
    return LANTERN_SNAPPY_OK;
}

static int lantern_snappy_decompress_framed(
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t output_len,
    size_t *written) {
    size_t pos = 0;
    size_t produced = 0;

    while (pos + 4 <= input_len) {
        uint8_t chunk_type = input[pos];
        uint32_t chunk_len = lantern_snappy_read_le24(&input[pos + 1]);
        pos += 4;
        if (chunk_len > input_len - pos) {
            return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
        }
        const uint8_t *chunk = &input[pos];
        pos += chunk_len;

        if (chunk_type == LANTERN_SNAPPY_CHUNK_STREAM_IDENTIFIER) {
            if (chunk_len != 6 || memcmp(chunk, "sNaPpY", 6) != 0) {
                return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
            }
            continue;
        }

        if (chunk_type == LANTERN_SNAPPY_CHUNK_COMPRESSED || chunk_type == LANTERN_SNAPPY_CHUNK_UNCOMPRESSED) {
            if (chunk_len < 4) {
                return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
            }
            const uint8_t *payload = chunk + 4;
            size_t payload_len = chunk_len - 4;

            if (chunk_type == LANTERN_SNAPPY_CHUNK_COMPRESSED) {
                size_t chunk_expected = 0;
                if (!snappy_uncompressed_length((const char *)payload, payload_len, &chunk_expected)) {
                    return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
                }
                if (produced > output_len || chunk_expected > output_len - produced) {
                    *written = produced + chunk_expected;
                    return LANTERN_SNAPPY_ERROR_BUFFER_TOO_SMALL;
                }
                if (snappy_uncompress((const char *)payload, payload_len, (char *)output + produced) != 0) {
                    return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
                }
                produced += chunk_expected;
            } else {
                if (produced > output_len || payload_len > output_len - produced) {
                    *written = produced + payload_len;
                    return LANTERN_SNAPPY_ERROR_BUFFER_TOO_SMALL;
                }
                memcpy(output + produced, payload, payload_len);
                produced += payload_len;
            }
            continue;
        }

        if (chunk_type >= LANTERN_SNAPPY_CHUNK_PADDING_START && chunk_type <= LANTERN_SNAPPY_CHUNK_PADDING_END) {
            continue;
        }

        return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
    }

    if (pos != input_len) {
        return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
    }

    *written = produced;
    return LANTERN_SNAPPY_OK;
}

static uint32_t lantern_snappy_crc32c(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; ++bit) {
            uint32_t mask = (uint32_t)-(int32_t)(crc & 1u);
            crc = (crc >> 1) ^ (0x82F63B78u & mask);
        }
    }
    return ~crc;
}

static uint32_t lantern_snappy_mask_crc32c(uint32_t crc) {
    return ((crc >> 15) | (crc << 17)) + 0xA282EAD8u;
}

static void lantern_snappy_write_chunk_header(
    uint8_t chunk_type,
    uint32_t chunk_len,
    uint8_t header[4]) {
    header[0] = chunk_type;
    header[1] = (uint8_t)(chunk_len & 0xffu);
    header[2] = (uint8_t)((chunk_len >> 8u) & 0xffu);
    header[3] = (uint8_t)((chunk_len >> 16u) & 0xffu);
}
