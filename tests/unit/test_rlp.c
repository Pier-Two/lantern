#include "lantern/rlp.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const uint8_t kExampleEnrRlp[] = {
    0xf8, 0x84, 0xb8, 0x40, 0x70, 0x98, 0xad, 0x86, 0x5b, 0x00, 0xa5, 0x82, 0x05, 0x19, 0x40, 0xcb, 0x9c, 0xf3,
    0x68, 0x36, 0x57, 0x24, 0x11, 0xa4, 0x72, 0x78, 0x78, 0x30, 0x77, 0x01, 0x15, 0x99, 0xed, 0x5c, 0xd1, 0x6b,
    0x76, 0xf2, 0x63, 0x5f, 0x4e, 0x23, 0x47, 0x38, 0xf3, 0x08, 0x13, 0xa8, 0x9e, 0xb9, 0x13, 0x7e, 0x3e, 0x3d,
    0xf5, 0x26, 0x6e, 0x3a, 0x1f, 0x11, 0xdf, 0x72, 0xec, 0xf1, 0x14, 0x5c, 0xcb, 0x9c, 0x01, 0x82, 0x69, 0x64,
    0x82, 0x76, 0x34, 0x82, 0x69, 0x70, 0x84, 0x7f, 0x00, 0x00, 0x01, 0x89, 0x73, 0x65, 0x63, 0x70, 0x32, 0x35,
    0x36, 0x6b, 0x31, 0xa1, 0x03, 0xca, 0x63, 0x4c, 0xae, 0x0d, 0x49, 0xac, 0xb4, 0x01, 0xd8, 0xa4, 0xc6, 0xb6,
    0xfe, 0x8c, 0x55, 0xb7, 0x0d, 0x11, 0x5b, 0xf4, 0x00, 0x76, 0x9c, 0xc1, 0x40, 0x0f, 0x32, 0x58, 0xcd, 0x31,
    0x38, 0x83, 0x75, 0x64, 0x70, 0x82, 0x76, 0x5f,
};

static const uint8_t kExampleSignature[64] = {
    0x70, 0x98, 0xad, 0x86, 0x5b, 0x00, 0xa5, 0x82, 0x05, 0x19, 0x40, 0xcb, 0x9c, 0xf3, 0x68, 0x36,
    0x57, 0x24, 0x11, 0xa4, 0x72, 0x78, 0x78, 0x30, 0x77, 0x01, 0x15, 0x99, 0xed, 0x5c, 0xd1, 0x6b,
    0x76, 0xf2, 0x63, 0x5f, 0x4e, 0x23, 0x47, 0x38, 0xf3, 0x08, 0x13, 0xa8, 0x9e, 0xb9, 0x13, 0x7e,
    0x3e, 0x3d, 0xf5, 0x26, 0x6e, 0x3a, 0x1f, 0x11, 0xdf, 0x72, 0xec, 0xf1, 0x14, 0x5c, 0xcb, 0x9c,
};

static const uint8_t kExamplePubkey[33] = {
    0x03, 0xca, 0x63, 0x4c, 0xae, 0x0d, 0x49, 0xac, 0xb4, 0x01, 0xd8, 0xa4, 0xc6, 0xb6, 0xfe, 0x8c, 0x55,
    0xb7, 0x0d, 0x11, 0x5b, 0xf4, 0x00, 0x76, 0x9c, 0xc1, 0x40, 0x0f, 0x32, 0x58, 0xcd, 0x31, 0x38,
};

static void reset_buffers(struct lantern_rlp_buffer *buffers, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        lantern_rlp_buffer_reset(&buffers[i]);
    }
}

static int test_encode_single_byte(void) {
    struct lantern_rlp_buffer buffer = {0};
    uint8_t value = 0x7f;
    if (lantern_rlp_encode_bytes(&buffer, &value, 1) != 0) {
        fprintf(stderr, "encode single byte failed\n");
        return 1;
    }
    if (buffer.length != 1 || buffer.data[0] != 0x7f) {
        fprintf(stderr, "unexpected single byte encoding\n");
        lantern_rlp_buffer_reset(&buffer);
        return 1;
    }
    struct lantern_rlp_view view;
    if (lantern_rlp_decode(buffer.data, buffer.length, &view) != 0) {
        fprintf(stderr, "decode single byte failed\n");
        lantern_rlp_buffer_reset(&buffer);
        return 1;
    }
    int failed = !(view.kind == LANTERN_RLP_KIND_BYTES && view.length == 1 && view.data[0] == 0x7f);
    lantern_rlp_view_reset(&view);
    lantern_rlp_buffer_reset(&buffer);
    if (failed) {
        fprintf(stderr, "decoded single byte mismatch\n");
        return 1;
    }
    return 0;
}

static int test_encode_short_string(void) {
    const uint8_t text[] = {'d', 'o', 'g'};
    struct lantern_rlp_buffer buffer = {0};
    if (lantern_rlp_encode_bytes(&buffer, text, sizeof(text)) != 0) {
        fprintf(stderr, "encode short string failed\n");
        return 1;
    }
    const uint8_t expected[] = {0x83, 'd', 'o', 'g'};
    int failed = !(buffer.length == sizeof(expected) && memcmp(buffer.data, expected, sizeof(expected)) == 0);
    lantern_rlp_buffer_reset(&buffer);
    if (failed) {
        fprintf(stderr, "short string encoding mismatch\n");
        return 1;
    }
    return 0;
}

static int test_encode_list(void) {
    struct lantern_rlp_buffer cat = {0};
    struct lantern_rlp_buffer dog = {0};
    struct lantern_rlp_buffer list = {0};

    if (lantern_rlp_encode_bytes(&cat, (const uint8_t *)"cat", 3) != 0) {
        fprintf(stderr, "encode cat failed\n");
        goto error;
    }
    if (lantern_rlp_encode_bytes(&dog, (const uint8_t *)"dog", 3) != 0) {
        fprintf(stderr, "encode dog failed\n");
        goto error;
    }

    const struct lantern_rlp_buffer items[] = {cat, dog};
    if (lantern_rlp_encode_list(&list, items, 2) != 0) {
        fprintf(stderr, "encode list failed\n");
        goto error;
    }

    const uint8_t expected[] = {0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g'};
    if (list.length != sizeof(expected) || memcmp(list.data, expected, sizeof(expected)) != 0) {
        fprintf(stderr, "list encoding mismatch\n");
        goto error;
    }

    lantern_rlp_buffer_reset(&cat);
    lantern_rlp_buffer_reset(&dog);
    lantern_rlp_buffer_reset(&list);
    return 0;

error:
    lantern_rlp_buffer_reset(&cat);
    lantern_rlp_buffer_reset(&dog);
    lantern_rlp_buffer_reset(&list);
    return 1;
}

static int test_decode_enr_example(void) {
    struct lantern_rlp_view root;
    if (lantern_rlp_decode(kExampleEnrRlp, sizeof(kExampleEnrRlp), &root) != 0) {
        fprintf(stderr, "decode ENR example failed\n");
        return 1;
    }

    int failed = 0;
    if (root.kind != LANTERN_RLP_KIND_LIST || root.item_count != 10) {
        fprintf(stderr, "unexpected ENR root structure\n");
        failed = 1;
        goto cleanup;
    }

    if (root.items[0].kind != LANTERN_RLP_KIND_BYTES || root.items[0].length != 64) {
        fprintf(stderr, "signature length mismatch\n");
        failed = 1;
        goto cleanup;
    }

    uint64_t seq = 0;
    if (lantern_rlp_view_as_uint64(&root.items[1], &seq) != 0 || seq != 1) {
        fprintf(stderr, "sequence mismatch\n");
        failed = 1;
        goto cleanup;
    }

    if (root.items[2].length != 2 || memcmp(root.items[2].data, "id", 2) != 0) {
        fprintf(stderr, "missing id key\n");
        failed = 1;
        goto cleanup;
    }
    if (root.items[3].length != 2 || memcmp(root.items[3].data, "v4", 2) != 0) {
        fprintf(stderr, "missing id value\n");
        failed = 1;
        goto cleanup;
    }
    if (root.items[4].length != 2 || memcmp(root.items[4].data, "ip", 2) != 0) {
        fprintf(stderr, "missing ip key\n");
        failed = 1;
        goto cleanup;
    }
    const uint8_t expected_ip[] = {0x7f, 0x00, 0x00, 0x01};
    if (root.items[5].length != sizeof(expected_ip)
        || memcmp(root.items[5].data, expected_ip, sizeof(expected_ip)) != 0) {
        fprintf(stderr, "ip value mismatch\n");
        failed = 1;
        goto cleanup;
    }
    const char secp_key[] = "secp256k1";
    if (root.items[6].length != (sizeof(secp_key) - 1)
        || memcmp(root.items[6].data, secp_key, sizeof(secp_key) - 1) != 0) {
        fprintf(stderr, "secp key mismatch\n");
        failed = 1;
        goto cleanup;
    }
    if (root.items[7].length != sizeof(kExamplePubkey)
        || memcmp(root.items[7].data, kExamplePubkey, sizeof(kExamplePubkey)) != 0) {
        fprintf(stderr, "pubkey mismatch\n");
        failed = 1;
        goto cleanup;
    }
    if (root.items[8].length != 3 || memcmp(root.items[8].data, "udp", 3) != 0) {
        fprintf(stderr, "udp key mismatch\n");
        failed = 1;
        goto cleanup;
    }
    uint64_t udp_port = 0;
    if (lantern_rlp_view_as_uint64(&root.items[9], &udp_port) != 0 || udp_port != 0x765f) {
        fprintf(stderr, "udp port mismatch\n");
        failed = 1;
        goto cleanup;
    }

cleanup:
    lantern_rlp_view_reset(&root);
    return failed ? 1 : 0;
}

static int test_encode_enr_example(void) {
    struct lantern_rlp_buffer fields[10] = {0};
    struct lantern_rlp_buffer list = {0};
    int rc = 1;

    if (lantern_rlp_encode_bytes(&fields[0], kExampleSignature, sizeof(kExampleSignature)) != 0) {
        fprintf(stderr, "encode signature failed\n");
        goto cleanup;
    }
    if (lantern_rlp_encode_uint64(&fields[1], 1) != 0) {
        fprintf(stderr, "encode sequence failed\n");
        goto cleanup;
    }
    if (lantern_rlp_encode_bytes(&fields[2], (const uint8_t *)"id", 2) != 0) {
        fprintf(stderr, "encode id key failed\n");
        goto cleanup;
    }
    if (lantern_rlp_encode_bytes(&fields[3], (const uint8_t *)"v4", 2) != 0) {
        fprintf(stderr, "encode id value failed\n");
        goto cleanup;
    }
    if (lantern_rlp_encode_bytes(&fields[4], (const uint8_t *)"ip", 2) != 0) {
        fprintf(stderr, "encode ip key failed\n");
        goto cleanup;
    }
    const uint8_t ip_value[] = {0x7f, 0x00, 0x00, 0x01};
    if (lantern_rlp_encode_bytes(&fields[5], ip_value, sizeof(ip_value)) != 0) {
        fprintf(stderr, "encode ip value failed\n");
        goto cleanup;
    }
    if (lantern_rlp_encode_bytes(&fields[6], (const uint8_t *)"secp256k1", 9) != 0) {
        fprintf(stderr, "encode secp key failed\n");
        goto cleanup;
    }
    if (lantern_rlp_encode_bytes(&fields[7], kExamplePubkey, sizeof(kExamplePubkey)) != 0) {
        fprintf(stderr, "encode pubkey failed\n");
        goto cleanup;
    }
    if (lantern_rlp_encode_bytes(&fields[8], (const uint8_t *)"udp", 3) != 0) {
        fprintf(stderr, "encode udp key failed\n");
        goto cleanup;
    }
    if (lantern_rlp_encode_uint64(&fields[9], 0x765f) != 0) {
        fprintf(stderr, "encode udp port failed\n");
        goto cleanup;
    }

    if (lantern_rlp_encode_list(&list, fields, 10) != 0) {
        fprintf(stderr, "encode enr list failed\n");
        goto cleanup;
    }

    if (list.length != sizeof(kExampleEnrRlp)
        || memcmp(list.data, kExampleEnrRlp, sizeof(kExampleEnrRlp)) != 0) {
        fprintf(stderr, "encoded ENR mismatch\n");
        goto cleanup;
    }

    rc = 0;

cleanup:
    reset_buffers(fields, 10);
    lantern_rlp_buffer_reset(&list);
    return rc;
}

int main(void) {
    if (test_encode_single_byte() != 0) {
        return 1;
    }
    if (test_encode_short_string() != 0) {
        return 1;
    }
    if (test_encode_list() != 0) {
        return 1;
    }
    if (test_decode_enr_example() != 0) {
        return 1;
    }
    if (test_encode_enr_example() != 0) {
        return 1;
    }
    return 0;
}
