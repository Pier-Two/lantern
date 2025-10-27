#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lantern/encoding/snappy.h"

#define CHECK(cond)                                                                 \
    do {                                                                            \
        if (!(cond)) {                                                              \
            fprintf(stderr, "check failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
            abort();                                                                \
        }                                                                           \
    } while (0)

static void check_zero(int rc, const char *context) {
    if (rc != LANTERN_SNAPPY_OK) {
        fprintf(stderr, "%s failed (rc=%d)\n", context, rc);
        abort();
    }
}

static void fill_pattern(uint8_t *dst, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; ++i) {
        dst[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static void roundtrip_case(size_t len, uint8_t seed) {
    size_t input_size = len > 0 ? len : 1;
    uint8_t *input = malloc(input_size);
    CHECK(input != NULL);
    if (len > 0) {
        fill_pattern(input, len, seed);
    }

    size_t max_compressed = 0;
    CHECK(lantern_snappy_max_compressed_size(len, &max_compressed) == LANTERN_SNAPPY_OK);
    uint8_t *compressed = malloc(max_compressed);
    CHECK(compressed != NULL);

    size_t written = 0;
    check_zero(lantern_snappy_compress(input, len, compressed, max_compressed, &written), "roundtrip compress");

    size_t output_size = len > 0 ? len : 1;
    uint8_t *output = malloc(output_size);
    CHECK(output != NULL);
    size_t out_written = len;
    check_zero(lantern_snappy_decompress(compressed, written, output, output_size, &out_written), "roundtrip decompress");
    CHECK(out_written == len);
    if (len > 0) {
        CHECK(memcmp(input, output, len) == 0);
    }

    free(input);
    free(compressed);
    free(output);
}

static void test_roundtrip_patterns(void) {
    size_t sizes[] = {0, 1, 8, 60, 61, 200, 4096, 65535};
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
        roundtrip_case(sizes[i], (uint8_t)i * 13u);
    }
}

static void test_buffer_too_small(void) {
    uint8_t input[128];
    fill_pattern(input, sizeof(input), 0x42);

    uint8_t compressed[256];
    size_t written = 0;
    check_zero(lantern_snappy_compress(input, sizeof(input), compressed, sizeof(compressed), &written), "compress buffer test");

    uint8_t output[10];
    size_t out_written = sizeof(output);
    int rc = lantern_snappy_decompress(compressed, written, output, sizeof(output), &out_written);
    CHECK(rc == LANTERN_SNAPPY_ERROR_BUFFER_TOO_SMALL);
    CHECK(out_written == sizeof(input));
}

static void test_invalid_payload(void) {
    uint8_t invalid[] = {0xFF, 0xFF, 0xFF};
    uint8_t out[16];
    size_t written = sizeof(out);
    int rc = lantern_snappy_decompress(invalid, sizeof(invalid), out, sizeof(out), &written);
    CHECK(rc == LANTERN_SNAPPY_ERROR_INVALID_INPUT);
}

int main(void) {
    test_roundtrip_patterns();
    test_buffer_too_small();
    test_invalid_payload();
    puts("lantern_snappy_test OK");
    return 0;
}
