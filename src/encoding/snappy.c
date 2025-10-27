#include "lantern/encoding/snappy.h"

#include <stddef.h>
#include <stdint.h>

#include "snappy.h"

int lantern_snappy_max_compressed_size(size_t input_len, size_t *max_size) {
    if (!max_size) {
        return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
    }
    *max_size = snappy_max_compressed_length(input_len);
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

    size_t required = snappy_max_compressed_length(input_len);
    if (output_len < required) {
        *written = required;
        return LANTERN_SNAPPY_ERROR_BUFFER_TOO_SMALL;
    }

    struct snappy_env env;
    if (snappy_init_env(&env) != 0) {
        return LANTERN_SNAPPY_ERROR_UNSUPPORTED;
    }

    size_t compressed_len = 0;
    int rc = snappy_compress(&env,
                             (const char *)input,
                             input_len,
                             (char *)output,
                             &compressed_len);
    snappy_free_env(&env);
    if (rc != 0) {
        return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
    }

    *written = compressed_len;
    return LANTERN_SNAPPY_OK;
}

int lantern_snappy_uncompressed_length(
    const uint8_t *input,
    size_t input_len,
    size_t *result) {
    if (!input || !result) {
        return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
    }
    if (!snappy_uncompressed_length((const char *)input, input_len, result)) {
        return LANTERN_SNAPPY_ERROR_INVALID_INPUT;
    }
    return LANTERN_SNAPPY_OK;
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
