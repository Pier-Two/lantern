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

enum {
    TEST_CHUNK_COMPRESSED = 0x00,
    TEST_CHUNK_UNCOMPRESSED = 0x01,
    TEST_CHUNK_STREAM_IDENTIFIER = 0xff,
};

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

static size_t append_chunk(uint8_t type, const uint8_t *payload, size_t payload_len, uint8_t *dst) {
    dst[0] = type;
    dst[1] = (uint8_t)(payload_len & 0xffu);
    dst[2] = (uint8_t)((payload_len >> 8u) & 0xffu);
    dst[3] = (uint8_t)((payload_len >> 16u) & 0xffu);
    if (payload_len > 0) {
        memcpy(dst + 4, payload, payload_len);
    }
    return 4u + payload_len;
}

static size_t append_stream_identifier(uint8_t *dst) {
    static const uint8_t magic[] = {'s', 'N', 'a', 'P', 'p', 'Y'};
    return append_chunk(TEST_CHUNK_STREAM_IDENTIFIER, magic, sizeof(magic), dst);
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

static void test_framed_uncompressed_chunks(void) {
    uint8_t payload[] = {0x00, 0x11, 0x22, 0x33};
    uint8_t chunk_data[sizeof(payload) + 4u];
    memset(chunk_data, 0, 4u);
    memcpy(chunk_data + 4u, payload, sizeof(payload));

    uint8_t frame[64];
    size_t used = 0;
    used += append_stream_identifier(frame + used);
    used += append_chunk(TEST_CHUNK_UNCOMPRESSED, chunk_data, sizeof(chunk_data), frame + used);

    size_t expected = 0;
    check_zero(lantern_snappy_uncompressed_length(frame, used, &expected), "framed uncompressed length");
    CHECK(expected == sizeof(payload));

    uint8_t output[sizeof(payload)];
    size_t written = sizeof(output);
    check_zero(lantern_snappy_decompress(frame, used, output, sizeof(output), &written), "framed uncompressed decode");
    CHECK(written == sizeof(payload));
    CHECK(memcmp(output, payload, sizeof(payload)) == 0);
}

static void test_framed_compressed_chunks(void) {
    uint8_t source[64];
    fill_pattern(source, sizeof(source), 0x5a);

    size_t max_comp = 0;
    check_zero(lantern_snappy_max_compressed_size(sizeof(source), &max_comp), "framed compressed max");
    uint8_t *compressed = malloc(max_comp);
    CHECK(compressed != NULL);
    size_t compressed_len = 0;
    check_zero(lantern_snappy_compress(source, sizeof(source), compressed, max_comp, &compressed_len), "framed compressed encode");

    size_t chunk_payload_len = 4u + compressed_len;
    uint8_t *chunk_payload = malloc(chunk_payload_len);
    CHECK(chunk_payload != NULL);
    memset(chunk_payload, 0, 4u);
    memcpy(chunk_payload + 4u, compressed, compressed_len);

    uint8_t frame[256];
    size_t used = 0;
    used += append_stream_identifier(frame + used);
    used += append_chunk(TEST_CHUNK_COMPRESSED, chunk_payload, chunk_payload_len, frame + used);

    size_t expected = 0;
    check_zero(lantern_snappy_uncompressed_length(frame, used, &expected), "framed compressed length");
    CHECK(expected == sizeof(source));

    uint8_t decoded[sizeof(source)];
    size_t written = sizeof(decoded);
    check_zero(lantern_snappy_decompress(frame, used, decoded, sizeof(decoded), &written), "framed compressed decode");
    CHECK(written == sizeof(source));
    CHECK(memcmp(decoded, source, sizeof(source)) == 0);

    free(chunk_payload);
    free(compressed);
}

int main(void) {
    test_roundtrip_patterns();
    test_buffer_too_small();
    test_invalid_payload();
    test_framed_uncompressed_chunks();
    test_framed_compressed_chunks();
    puts("lantern_snappy_test OK");
    return 0;
}
