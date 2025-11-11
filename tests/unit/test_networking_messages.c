#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "lantern/consensus/containers.h"
#include "lantern/consensus/hash.h"
#include "lantern/consensus/signature.h"
#include "lantern/consensus/ssz.h"
#include "lantern/core/client.h"
#include "lantern/networking/gossip.h"
#include "lantern/networking/gossipsub_service.h"
#include "lantern/networking/messages.h"
#include "lantern/networking/gossip_payloads.h"
#include "lantern/encoding/snappy.h"
#include "lantern/support/strings.h"
#include "tests/support/fixture_loader.h"
#include "ssz_constants.h"

#ifndef LANTERN_TEST_FIXTURE_DIR
#error "LANTERN_TEST_FIXTURE_DIR must be defined"
#endif

#define CHECK(cond)                                                                 \
    do {                                                                            \
        if (!(cond)) {                                                              \
            fprintf(stderr, "check failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
            abort();                                                                \
        }                                                                           \
    } while (0)

static void check_zero(int rc, const char *context) {
    if (rc != 0) {
        fprintf(stderr, "%s failed (rc=%d)\n", context, rc);
        abort();
    }
}

static void fill_bytes(uint8_t *dst, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; ++i) {
        dst[i] = (uint8_t)(seed + i);
    }
}

static uint64_t le_bytes_to_u64(const uint8_t *src, size_t len) {
    if (!src) {
        return 0;
    }
    if (len > sizeof(uint64_t)) {
        len = sizeof(uint64_t);
    }
    uint64_t value = 0;
    for (size_t i = 0; i < len; ++i) {
        value |= ((uint64_t)src[i]) << (8u * i);
    }
    return value;
}

static uint32_t rng_state = UINT32_C(0x6ac1e39d);

static uint32_t rng_next(void) {
    uint32_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    rng_state = x;
    return x;
}

static uint64_t rng_next_u64(void) {
    uint64_t hi = (uint64_t)rng_next();
    uint64_t lo = (uint64_t)rng_next();
    return (hi << 32) | lo;
}

static uint64_t rng_uniform(uint64_t max_inclusive) {
    if (max_inclusive == 0) {
        return 0;
    }
    return rng_next_u64() % (max_inclusive + 1);
}

static void rng_fill_bytes(uint8_t *dst, size_t len) {
    if (!dst) {
        return;
    }
    for (size_t i = 0; i < len; ++i) {
        dst[i] = (uint8_t)(rng_next() & 0xFFu);
    }
}

static size_t signed_block_min_capacity_for_test(const LanternSignedBlock *block) {
    if (!block) {
        return 0;
    }
    size_t base = (SSZ_BYTE_SIZE_OF_UINT32 + LANTERN_SIGNATURE_SIZE)
        + (SSZ_BYTE_SIZE_OF_UINT64 * 2u)
        + (LANTERN_ROOT_SIZE * 2u)
        + SSZ_BYTE_SIZE_OF_UINT32
        + SSZ_BYTE_SIZE_OF_UINT32;
    size_t att_bytes = 0;
    if (block->message.body.attestations.length > 0) {
        att_bytes = block->message.body.attestations.length * LANTERN_SIGNED_VOTE_SSZ_SIZE;
    }
    return base + att_bytes;
}

static LanternCheckpoint build_checkpoint(uint8_t seed, uint64_t slot) {
    LanternCheckpoint checkpoint;
    fill_bytes(checkpoint.root.bytes, sizeof(checkpoint.root.bytes), seed);
    checkpoint.slot = slot;
    return checkpoint;
}

static LanternVote build_vote(void) {
    LanternVote vote;
    vote.validator_id = 0;
    vote.slot = 9;
    vote.head = build_checkpoint(0xAB, 10);
    vote.target = build_checkpoint(0xCD, 11);
    vote.source = build_checkpoint(0xEF, 12);
    return vote;
}

static LanternSignedVote build_signed_vote(uint64_t validator_id, uint64_t slot, uint8_t seed) {
    LanternSignedVote signed_vote;
    memset(&signed_vote, 0, sizeof(signed_vote));
    signed_vote.data = build_vote();
    signed_vote.data.validator_id = validator_id;
    signed_vote.data.slot = slot;
    signed_vote.data.head = build_checkpoint(seed, slot);
    signed_vote.data.target = build_checkpoint(seed + 1, slot);
    signed_vote.data.source = build_checkpoint(seed + 2, slot > 0 ? slot - 1 : slot);
    return signed_vote;
}

static void populate_block(LanternSignedBlock *signed_block, uint8_t seed) {
    memset(signed_block, 0, sizeof(*signed_block));
    lantern_block_body_init(&signed_block->message.body);
    signed_block->message.slot = 100 + seed;
    signed_block->message.proposer_index = 3 + seed;
    fill_bytes(signed_block->message.parent_root.bytes, LANTERN_ROOT_SIZE, (uint8_t)(0x10 + seed));
    fill_bytes(signed_block->message.state_root.bytes, LANTERN_ROOT_SIZE, (uint8_t)(0x20 + seed));
    LanternSignedVote vote = build_signed_vote(1 + seed, 50 + seed, (uint8_t)(0x30 + seed));
    check_zero(lantern_attestations_append(&signed_block->message.body.attestations, &vote), "attestation append");
    memset(signed_block->signature.bytes, 0, sizeof(signed_block->signature.bytes));
}

struct block_hook_ctx {
    const LanternSignedBlock *expected;
    const char *expected_topic;
    int called;
};

static int block_publish_hook(
    const char *topic,
    const uint8_t *payload,
    size_t payload_len,
    void *user_data) {
    struct block_hook_ctx *ctx = (struct block_hook_ctx *)user_data;
    CHECK(ctx);
    CHECK(topic);
    CHECK(payload);
    CHECK(payload_len > 0);
    if (ctx->expected_topic) {
        CHECK(strcmp(topic, ctx->expected_topic) == 0);
    }

    LanternSignedBlock decoded;
    memset(&decoded, 0, sizeof(decoded));
    lantern_block_body_init(&decoded.message.body);
    int rc = lantern_gossip_decode_signed_block_snappy(&decoded, payload, payload_len);
    if (rc != 0) {
        lantern_block_body_reset(&decoded.message.body);
        return -1;
    }

    const LanternSignedBlock *expected = ctx->expected;
    CHECK(expected != NULL);
    CHECK(decoded.message.slot == expected->message.slot);
    CHECK(decoded.message.proposer_index == expected->message.proposer_index);
    CHECK(decoded.message.body.attestations.length == expected->message.body.attestations.length);
    CHECK(memcmp(decoded.signature.bytes, expected->signature.bytes, LANTERN_SIGNATURE_SIZE) == 0);
    lantern_block_body_reset(&decoded.message.body);
    ctx->called += 1;
    return 0;
}

enum block_fixture_kind {
    BLOCK_FIXTURE_STATE_TRANSITION,
    BLOCK_FIXTURE_FORK_CHOICE_STEP,
};

struct block_fixture_case {
    const char *fixture;
    enum block_fixture_kind kind;
    size_t index;
};

static int load_signed_block_fixture(const struct block_fixture_case *spec, LanternSignedBlock *out_block) {
    if (!spec || !out_block) {
        return -1;
    }
    char path[PATH_MAX];
    int written = snprintf(path, sizeof(path), "%s/%s", LANTERN_TEST_FIXTURE_DIR, spec->fixture);
    if (written <= 0 || (size_t)written >= sizeof(path)) {
        return -1;
    }

    struct lantern_fixture_document doc;
    memset(&doc, 0, sizeof(doc));

    char *text = NULL;
    if (lantern_fixture_read_text_file(path, &text) != 0) {
        return -1;
    }
    if (lantern_fixture_document_init(&doc, text) != 0) {
        lantern_fixture_document_reset(&doc);
        return -1;
    }

    int status = -1;
    int case_idx = lantern_fixture_object_get_value_at(&doc, 0, 0);
    if (case_idx < 0) {
        goto cleanup;
    }

    int block_idx = -1;
    if (spec->kind == BLOCK_FIXTURE_STATE_TRANSITION) {
        int blocks_idx = lantern_fixture_object_get_field(&doc, case_idx, "blocks");
        if (blocks_idx < 0) {
            goto cleanup;
        }
        block_idx = lantern_fixture_array_get_element(&doc, blocks_idx, (int)spec->index);
    } else if (spec->kind == BLOCK_FIXTURE_FORK_CHOICE_STEP) {
        int steps_idx = lantern_fixture_object_get_field(&doc, case_idx, "steps");
        if (steps_idx < 0) {
            goto cleanup;
        }
        int step_idx = lantern_fixture_array_get_element(&doc, steps_idx, (int)spec->index);
        if (step_idx < 0) {
            goto cleanup;
        }
        block_idx = lantern_fixture_object_get_field(&doc, step_idx, "block");
    }

    if (block_idx < 0) {
        goto cleanup;
    }

    memset(out_block, 0, sizeof(*out_block));
    status = lantern_fixture_parse_signed_block(&doc, block_idx, out_block);

cleanup:
    lantern_fixture_document_reset(&doc);
    return status;
}

static int parse_hex_bytes(const char *hex, uint8_t *out, size_t expected_len) {
    if (!hex || !out) {
        return -1;
    }
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex += 2;
    }
    size_t hex_len = strlen(hex);
    if (hex_len != expected_len * 2u) {
        return -1;
    }
    for (size_t i = 0; i < expected_len; ++i) {
        char buf[3];
        buf[0] = hex[(i * 2u)];
        buf[1] = hex[(i * 2u) + 1u];
        buf[2] = '\0';
        char *end = NULL;
        unsigned long value = strtoul(buf, &end, 16);
        if (!end || *end != '\0') {
            return -1;
        }
        out[i] = (uint8_t)value;
    }
    return 0;
}

static void test_replay_devnet_block_payloads(void) {
    struct block_fixture_case cases[] = {
        {
            .fixture =
                "consensus/consensus/fork_choice/devnet/fc/test_fork_choice_reorgs/test_reorg_on_newly_justified_slot.json",
            .kind = BLOCK_FIXTURE_FORK_CHOICE_STEP,
            .index = 5,
        },
        {
            .fixture =
                "consensus/consensus/state_transition/devnet/state_transition/test_block_processing/test_linear_chain_multiple_blocks.json",
            .kind = BLOCK_FIXTURE_STATE_TRANSITION,
            .index = 1,
        },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        LanternSignedBlock original;
        memset(&original, 0, sizeof(original));
        CHECK(load_signed_block_fixture(&cases[i], &original) == 0);

        LanternRoot original_block_root;
        memset(&original_block_root, 0, sizeof(original_block_root));
        CHECK(lantern_hash_tree_root_block(&original.message, &original_block_root) == 0);

        size_t ssz_capacity = signed_block_min_capacity_for_test(&original);
        CHECK(ssz_capacity > 0);
        uint8_t *ssz_encoded = (uint8_t *)malloc(ssz_capacity);
        CHECK(ssz_encoded != NULL);
        size_t ssz_written = ssz_capacity;
        CHECK(lantern_ssz_encode_signed_block(&original, ssz_encoded, ssz_capacity, &ssz_written) == 0);

        size_t max_compressed = 0;
        CHECK(lantern_snappy_max_compressed_size(ssz_written, &max_compressed) == LANTERN_SNAPPY_OK);
        uint8_t *compressed = (uint8_t *)malloc(max_compressed);
        CHECK(compressed != NULL);
        size_t compressed_len = max_compressed;
        CHECK(lantern_gossip_encode_signed_block_snappy(&original, compressed, max_compressed, &compressed_len) == 0);

        LanternSignedBlock decoded;
        memset(&decoded, 0, sizeof(decoded));
        lantern_block_body_init(&decoded.message.body);
        CHECK(lantern_gossip_decode_signed_block_snappy(&decoded, compressed, compressed_len) == 0);

        CHECK(decoded.message.slot == original.message.slot);
        CHECK(decoded.message.proposer_index == original.message.proposer_index);
        CHECK(memcmp(decoded.message.parent_root.bytes, original.message.parent_root.bytes, LANTERN_ROOT_SIZE) == 0);
        CHECK(memcmp(decoded.message.state_root.bytes, original.message.state_root.bytes, LANTERN_ROOT_SIZE) == 0);

        CHECK(lantern_signature_is_zero(&decoded.signature));
        CHECK(decoded.message.body.attestations.length == original.message.body.attestations.length);
        if (decoded.message.body.attestations.length > 0) {
            CHECK(decoded.message.body.attestations.data != NULL);
            CHECK(original.message.body.attestations.data != NULL);
        }
        for (size_t att_idx = 0; att_idx < decoded.message.body.attestations.length; ++att_idx) {
            const LanternSignedVote *expected_vote = &original.message.body.attestations.data[att_idx];
            const LanternSignedVote *decoded_vote = &decoded.message.body.attestations.data[att_idx];
            CHECK(decoded_vote->data.validator_id == expected_vote->data.validator_id);
            CHECK(decoded_vote->data.slot == expected_vote->data.slot);
            CHECK(decoded_vote->data.head.slot == expected_vote->data.head.slot);
            CHECK(memcmp(decoded_vote->data.head.root.bytes, expected_vote->data.head.root.bytes, LANTERN_ROOT_SIZE) == 0);
            CHECK(decoded_vote->data.target.slot == expected_vote->data.target.slot);
            CHECK(memcmp(decoded_vote->data.target.root.bytes, expected_vote->data.target.root.bytes, LANTERN_ROOT_SIZE) == 0);
            CHECK(decoded_vote->data.source.slot == expected_vote->data.source.slot);
            CHECK(memcmp(decoded_vote->data.source.root.bytes, expected_vote->data.source.root.bytes, LANTERN_ROOT_SIZE) == 0);
            CHECK(lantern_signature_is_zero(&decoded_vote->signature));
        }

        LanternRoot decoded_block_root;
        memset(&decoded_block_root, 0, sizeof(decoded_block_root));
        CHECK(lantern_hash_tree_root_block(&decoded.message, &decoded_block_root) == 0);
        CHECK(memcmp(decoded_block_root.bytes, original_block_root.bytes, LANTERN_ROOT_SIZE) == 0);

        uint8_t *roundtrip = (uint8_t *)malloc(ssz_written);
        CHECK(roundtrip != NULL);
        size_t roundtrip_written = ssz_written;
        CHECK(
            lantern_snappy_decompress(
                compressed,
                compressed_len,
                roundtrip,
                ssz_written,
                &roundtrip_written)
            == LANTERN_SNAPPY_OK);
        CHECK(roundtrip_written == ssz_written);
        CHECK(memcmp(roundtrip, ssz_encoded, ssz_written) == 0);

        free(roundtrip);
        free(compressed);
        free(ssz_encoded);
        lantern_block_body_reset(&decoded.message.body);
        lantern_block_body_reset(&original.message.body);
    }
}

static void test_status_snappy(void) {
    LanternStatusMessage status = {
        .finalized = build_checkpoint(0xAA, 42),
        .head = build_checkpoint(0xBB, 64),
    };

    uint8_t encoded[128];
    size_t written = 0;
    check_zero(lantern_network_status_encode(&status, encoded, sizeof(encoded), &written), "status encode");
    CHECK(written == 2u * LANTERN_CHECKPOINT_SSZ_SIZE);

    LanternStatusMessage decoded = {0};
    check_zero(lantern_network_status_decode(&decoded, encoded, written), "status decode");
    CHECK(memcmp(decoded.finalized.root.bytes, status.finalized.root.bytes, LANTERN_ROOT_SIZE) == 0);
    CHECK(decoded.head.slot == status.head.slot);

    uint8_t compressed[256];
    size_t compressed_len = 0;
    size_t status_raw_len = 0;
    check_zero(
        lantern_network_status_encode_snappy(&status, compressed, sizeof(compressed), &compressed_len, &status_raw_len),
        "status encode snappy");
    CHECK(status_raw_len == 2u * LANTERN_CHECKPOINT_SSZ_SIZE);

    LanternStatusMessage snappy_decoded = {0};
    check_zero(lantern_network_status_decode_snappy(&snappy_decoded, compressed, compressed_len), "status decode snappy");
    CHECK(memcmp(snappy_decoded.head.root.bytes, status.head.root.bytes, LANTERN_ROOT_SIZE) == 0);
    CHECK(snappy_decoded.finalized.slot == status.finalized.slot);
}

static void test_status_decode_truncated_head_slot(void) {
    uint8_t finalized_root[LANTERN_ROOT_SIZE];
    uint8_t head_root[LANTERN_ROOT_SIZE];
    fill_bytes(finalized_root, sizeof(finalized_root), 0x31);
    fill_bytes(head_root, sizeof(head_root), 0x62);

    const uint8_t finalized_slot_bytes[8] = {0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE};
    const uint8_t head_slot_bytes[6] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB};

    uint8_t payload[LANTERN_ROOT_SIZE + sizeof(finalized_slot_bytes) + LANTERN_ROOT_SIZE + sizeof(head_slot_bytes)];
    uint8_t *cursor = payload;
    memcpy(cursor, finalized_root, LANTERN_ROOT_SIZE);
    cursor += LANTERN_ROOT_SIZE;
    memcpy(cursor, finalized_slot_bytes, sizeof(finalized_slot_bytes));
    cursor += sizeof(finalized_slot_bytes);
    memcpy(cursor, head_root, LANTERN_ROOT_SIZE);
    cursor += LANTERN_ROOT_SIZE;
    memcpy(cursor, head_slot_bytes, sizeof(head_slot_bytes));

    LanternStatusMessage decoded = {0};
    CHECK(lantern_network_status_decode(&decoded, payload, sizeof(payload)) == 0);
    CHECK(memcmp(decoded.finalized.root.bytes, finalized_root, LANTERN_ROOT_SIZE) == 0);
    CHECK(decoded.finalized.slot == le_bytes_to_u64(finalized_slot_bytes, sizeof(finalized_slot_bytes)));
    CHECK(memcmp(decoded.head.root.bytes, head_root, LANTERN_ROOT_SIZE) == 0);
    CHECK(decoded.head.slot == le_bytes_to_u64(head_slot_bytes, sizeof(head_slot_bytes)));
}

static void test_status_decode_single_truncated_checkpoint(void) {
    uint8_t head_root[LANTERN_ROOT_SIZE];
    fill_bytes(head_root, sizeof(head_root), 0x5A);

    const uint8_t slot_bytes[10] = {0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x10, 0x12, 0x14};
    uint8_t payload[LANTERN_ROOT_SIZE + sizeof(slot_bytes)];
    memcpy(payload, head_root, LANTERN_ROOT_SIZE);
    memcpy(payload + LANTERN_ROOT_SIZE, slot_bytes, sizeof(slot_bytes));

    LanternStatusMessage decoded = {0};
    CHECK(lantern_network_status_decode(&decoded, payload, sizeof(payload)) == 0);
    CHECK(memcmp(decoded.head.root.bytes, head_root, LANTERN_ROOT_SIZE) == 0);
    CHECK(decoded.finalized.slot == decoded.head.slot);
    CHECK(decoded.head.slot == le_bytes_to_u64(slot_bytes, sizeof(slot_bytes)));
}

static void test_blocks_by_root_request(void) {
    LanternBlocksByRootRequest req;
    lantern_blocks_by_root_request_init(&req);
    check_zero(lantern_root_list_resize(&req.roots, 2), "request roots resize");
    fill_bytes(req.roots.items[0].bytes, LANTERN_ROOT_SIZE, 0x11);
    fill_bytes(req.roots.items[1].bytes, LANTERN_ROOT_SIZE, 0x22);

    uint8_t encoded[128];
    size_t written = 0;
    check_zero(lantern_network_blocks_by_root_request_encode(&req, encoded, sizeof(encoded), &written), "request encode");
    size_t expected_written = sizeof(uint32_t) + (req.roots.length * LANTERN_ROOT_SIZE);
    CHECK(written == expected_written);

    LanternBlocksByRootRequest decoded;
    lantern_blocks_by_root_request_init(&decoded);
    check_zero(lantern_network_blocks_by_root_request_decode(&decoded, encoded, written), "request decode");
    CHECK(decoded.roots.length == req.roots.length);
    CHECK(memcmp(decoded.roots.items[1].bytes, req.roots.items[1].bytes, LANTERN_ROOT_SIZE) == 0);

    uint8_t compressed[256];
    size_t compressed_len = 0;
    size_t request_raw_len = 0;
    check_zero(
        lantern_network_blocks_by_root_request_encode_snappy(
            &req,
            compressed,
            sizeof(compressed),
            &compressed_len,
            &request_raw_len),
        "request encode snappy");
    CHECK(request_raw_len == expected_written);

    LanternBlocksByRootRequest snappy_decoded;
    lantern_blocks_by_root_request_init(&snappy_decoded);
    check_zero(lantern_network_blocks_by_root_request_decode_snappy(&snappy_decoded, compressed, compressed_len), "request decode snappy");
    CHECK(snappy_decoded.roots.length == req.roots.length);
    CHECK(memcmp(snappy_decoded.roots.items[0].bytes, req.roots.items[0].bytes, LANTERN_ROOT_SIZE) == 0);

    lantern_blocks_by_root_request_reset(&req);
    lantern_blocks_by_root_request_reset(&decoded);
    lantern_blocks_by_root_request_reset(&snappy_decoded);
}

static void test_blocks_by_root_response(void) {
    LanternBlocksByRootResponse resp;
    lantern_blocks_by_root_response_init(&resp);
    check_zero(lantern_blocks_by_root_response_resize(&resp, 2), "response resize");
    populate_block(&resp.blocks[0], 1);
    populate_block(&resp.blocks[1], 2);

    size_t encoded_capacity = 1u << 20;
    uint8_t *encoded = (uint8_t *)malloc(encoded_capacity);
    CHECK(encoded != NULL);
    for (size_t i = 0; i < resp.length; ++i) {
        size_t tmp_written = 0;
        CHECK(lantern_ssz_encode_signed_block(&resp.blocks[i], encoded, encoded_capacity, &tmp_written) == 0);
        CHECK(tmp_written > 0);
    }
    size_t written = 0;
    check_zero(
        lantern_network_blocks_by_root_response_encode(&resp, encoded, encoded_capacity, &written),
        "response encode");
    CHECK(written > sizeof(uint32_t));
    uint32_t container_offset = (uint32_t)encoded[0]
        | ((uint32_t)encoded[1] << 8)
        | ((uint32_t)encoded[2] << 16)
        | ((uint32_t)encoded[3] << 24);
    CHECK(container_offset == sizeof(uint32_t));
    uint32_t first_offset = (uint32_t)encoded[4]
        | ((uint32_t)encoded[5] << 8)
        | ((uint32_t)encoded[6] << 16)
        | ((uint32_t)encoded[7] << 24);
    CHECK(first_offset == resp.length * sizeof(uint32_t));
    if (resp.length > 1) {
        uint32_t second_offset = (uint32_t)encoded[8]
            | ((uint32_t)encoded[9] << 8)
            | ((uint32_t)encoded[10] << 16)
            | ((uint32_t)encoded[11] << 24);
        CHECK(second_offset > first_offset);
    }

    LanternBlocksByRootResponse decoded;
    lantern_blocks_by_root_response_init(&decoded);
    check_zero(lantern_network_blocks_by_root_response_decode(&decoded, encoded, written), "response decode");
    CHECK(decoded.length == resp.length);
    CHECK(memcmp(decoded.blocks[1].signature.bytes,
                 resp.blocks[1].signature.bytes,
                 LANTERN_SIGNATURE_SIZE)
          == 0);

    size_t max_compressed = 0;
    CHECK(lantern_snappy_max_compressed_size(written, &max_compressed) == LANTERN_SNAPPY_OK);
    uint8_t *compressed = (uint8_t *)malloc(max_compressed);
    CHECK(compressed != NULL);
    size_t compressed_len = 0;
    size_t response_raw_len = 0;
    check_zero(
        lantern_network_blocks_by_root_response_encode_snappy(
            &resp,
            compressed,
            max_compressed,
            &compressed_len,
            &response_raw_len),
        "response encode snappy");
    CHECK(response_raw_len == written);

    LanternBlocksByRootResponse snappy_decoded;
    lantern_blocks_by_root_response_init(&snappy_decoded);
    check_zero(lantern_network_blocks_by_root_response_decode_snappy(&snappy_decoded, compressed, compressed_len), "response decode snappy");
    CHECK(snappy_decoded.length == resp.length);
    CHECK(snappy_decoded.blocks[0].message.slot == resp.blocks[0].message.slot);

    lantern_blocks_by_root_response_reset(&resp);
    lantern_blocks_by_root_response_reset(&decoded);
    lantern_blocks_by_root_response_reset(&snappy_decoded);
    free(encoded);
    free(compressed);
}

static void test_gossip_helpers(void) {
    char topic[128];
    check_zero(lantern_gossip_topic_format(LANTERN_GOSSIP_TOPIC_BLOCK, "devnet", topic, sizeof(topic)), "topic format");
    CHECK(strcmp(topic, "/leanconsensus/devnet/block/ssz_snappy") == 0);

    uint8_t payload[64];
    fill_bytes(payload, sizeof(payload), 0x5A);
    size_t max_compressed = 0;
    CHECK(lantern_snappy_max_compressed_size(sizeof(payload), &max_compressed) == LANTERN_SNAPPY_OK);
    uint8_t *compressed = malloc(max_compressed);
    CHECK(compressed);
    size_t compressed_len = 0;
    CHECK(lantern_snappy_compress(payload, sizeof(payload), compressed, max_compressed, &compressed_len) == LANTERN_SNAPPY_OK);

    LanternGossipMessageId valid_id;
    uint8_t scratch[sizeof(payload)];
    size_t required = 0;
    check_zero(lantern_gossip_compute_message_id(&valid_id,
                                                 (const uint8_t *)topic,
                                                 strlen(topic),
                                                 compressed,
                                                 compressed_len,
                                                 scratch,
                                                 sizeof(scratch),
                                                 &required),
               "message id valid");
    CHECK(required == 0);

    LanternGossipMessageId invalid_id;
    required = 0;
    check_zero(lantern_gossip_compute_message_id(&invalid_id,
                                                 (const uint8_t *)topic,
                                                 strlen(topic),
                                                 compressed,
                                                 compressed_len,
                                                 scratch,
                                                 8,
                                                 &required),
               "message id insufficient scratch");
    CHECK(required == sizeof(payload));
    CHECK(memcmp(valid_id.bytes, invalid_id.bytes, LANTERN_GOSSIP_MESSAGE_ID_SIZE) != 0);

    LanternGossipMessageId raw_id;
    const uint8_t raw_payload[] = {0x01, 0x02, 0x03};
    check_zero(lantern_gossip_compute_message_id(&raw_id,
                                                 (const uint8_t *)topic,
                                                 strlen(topic),
                                                 raw_payload,
                                                 sizeof(raw_payload),
                                                 NULL,
                                                 0,
                                                 &required),
               "message id raw payload");
    CHECK(required == 0);

    free(compressed);
}

static void test_gossip_signed_vote_payload(void) {
    LanternSignedVote vote = build_signed_vote(3, 12, 0x44);

    uint8_t raw_buf[8192];
    size_t raw_written = 0;
    CHECK(lantern_ssz_encode_signed_vote(&vote, raw_buf, sizeof(raw_buf), &raw_written) == 0);

    size_t max_compressed = 0;
    CHECK(lantern_snappy_max_compressed_size(raw_written, &max_compressed) == LANTERN_SNAPPY_OK);
    uint8_t *compressed = malloc(max_compressed);
    CHECK(compressed);

    size_t compressed_len = 0;
    check_zero(
        lantern_gossip_encode_signed_vote_snappy(&vote, compressed, max_compressed, &compressed_len),
        "encode signed vote gossip");
    CHECK(compressed_len > 0);

    LanternSignedVote decoded = {0};
    check_zero(
        lantern_gossip_decode_signed_vote_snappy(&decoded, compressed, compressed_len),
        "decode signed vote gossip");
    CHECK(decoded.data.validator_id == vote.data.validator_id);
    CHECK(decoded.data.target.slot == vote.data.target.slot);

    uint8_t invalid_payload[] = {0x01, 0x02, 0x03};
    CHECK(lantern_gossip_decode_signed_vote_snappy(&decoded, invalid_payload, sizeof(invalid_payload)) != 0);

    free(compressed);
}

static void test_gossip_signed_block_payload(void) {
    LanternSignedBlock block;
    memset(&block, 0, sizeof(block));
    lantern_block_body_init(&block.message.body);
    populate_block(&block, 5);

   size_t raw_upper = signed_block_min_capacity_for_test(&block);
   size_t max_compressed = 0;
    CHECK(lantern_snappy_max_compressed_size(raw_upper, &max_compressed) == LANTERN_SNAPPY_OK);
    uint8_t *compressed = malloc(max_compressed);
    CHECK(compressed);

    size_t compressed_len = 0;
    check_zero(
        lantern_gossip_encode_signed_block_snappy(&block, compressed, max_compressed, &compressed_len),
        "encode signed block gossip");
    CHECK(compressed_len > 0);

    LanternSignedBlock decoded;
    memset(&decoded, 0, sizeof(decoded));
    lantern_block_body_init(&decoded.message.body);
    check_zero(
        lantern_gossip_decode_signed_block_snappy(&decoded, compressed, compressed_len),
        "decode signed block gossip");
    CHECK(decoded.message.slot == block.message.slot);
    CHECK(decoded.message.body.attestations.length == block.message.body.attestations.length);

    uint8_t invalid_payload[] = {0xFF};
    CHECK(lantern_gossip_decode_signed_block_snappy(&decoded, invalid_payload, sizeof(invalid_payload)) != 0);

    lantern_block_body_reset(&decoded.message.body);
    lantern_block_body_reset(&block.message.body);
    free(compressed);
}

static void test_gossip_block_snappy_roundtrip_random(void) {
    const size_t iterations = 64;
    for (size_t i = 0; i < iterations; ++i) {
        LanternSignedBlock original;
        memset(&original, 0, sizeof(original));
        lantern_block_body_init(&original.message.body);
        original.message.slot = 1 + rng_uniform(2047);
        original.message.proposer_index = rng_uniform(63);
        rng_fill_bytes(original.message.parent_root.bytes, LANTERN_ROOT_SIZE);
        rng_fill_bytes(original.message.state_root.bytes, LANTERN_ROOT_SIZE);
        memset(original.signature.bytes, 0, sizeof(original.signature.bytes));

        size_t att_count = rng_uniform(4);
        for (size_t j = 0; j < att_count; ++j) {
            LanternSignedVote vote;
            memset(&vote, 0, sizeof(vote));
            vote.data.validator_id = rng_uniform(255);
            vote.data.slot = rng_uniform(original.message.slot);
            vote.data.source.slot = vote.data.slot > 0 ? rng_uniform(vote.data.slot) : 0;
            if (vote.data.source.slot > vote.data.slot) {
                vote.data.source.slot = vote.data.slot;
            }
            vote.data.target.slot = vote.data.slot;
            vote.data.head.slot = vote.data.slot;
            rng_fill_bytes(vote.data.head.root.bytes, LANTERN_ROOT_SIZE);
            rng_fill_bytes(vote.data.target.root.bytes, LANTERN_ROOT_SIZE);
            rng_fill_bytes(vote.data.source.root.bytes, LANTERN_ROOT_SIZE);
            memset(vote.signature.bytes, 0, sizeof(vote.signature.bytes));
            CHECK(lantern_attestations_append(&original.message.body.attestations, &vote) == 0);
        }

        size_t raw_estimate = signed_block_min_capacity_for_test(&original);
        CHECK(raw_estimate > 0);
        size_t max_compressed = 0;
        CHECK(lantern_snappy_max_compressed_size(raw_estimate, &max_compressed) == LANTERN_SNAPPY_OK);
        uint8_t *compressed = malloc(max_compressed);
        CHECK(compressed != NULL);

        size_t written = 0;
        check_zero(
            lantern_gossip_encode_signed_block_snappy(&original, compressed, max_compressed, &written),
            "random block encode");
        CHECK(written > 0);

        LanternSignedBlock decoded;
        memset(&decoded, 0, sizeof(decoded));
        lantern_block_body_init(&decoded.message.body);
        check_zero(
            lantern_gossip_decode_signed_block_snappy(&decoded, compressed, written),
            "random block decode");

        CHECK(decoded.message.slot == original.message.slot);
        CHECK(decoded.message.proposer_index == original.message.proposer_index);
        CHECK(memcmp(decoded.message.parent_root.bytes, original.message.parent_root.bytes, LANTERN_ROOT_SIZE) == 0);
        CHECK(memcmp(decoded.message.state_root.bytes, original.message.state_root.bytes, LANTERN_ROOT_SIZE) == 0);
        CHECK(decoded.message.body.attestations.length == original.message.body.attestations.length);
        for (size_t j = 0; j < decoded.message.body.attestations.length; ++j) {
            const LanternSignedVote *expected = &original.message.body.attestations.data[j];
            const LanternSignedVote *actual = &decoded.message.body.attestations.data[j];
            CHECK(actual->data.validator_id == expected->data.validator_id);
            CHECK(actual->data.slot == expected->data.slot);
            CHECK(actual->data.head.slot == expected->data.head.slot);
            CHECK(actual->data.target.slot == expected->data.target.slot);
            CHECK(actual->data.source.slot == expected->data.source.slot);
            CHECK(memcmp(actual->data.head.root.bytes, expected->data.head.root.bytes, LANTERN_ROOT_SIZE) == 0);
            CHECK(memcmp(actual->data.target.root.bytes, expected->data.target.root.bytes, LANTERN_ROOT_SIZE) == 0);
            CHECK(memcmp(actual->data.source.root.bytes, expected->data.source.root.bytes, LANTERN_ROOT_SIZE) == 0);
        }
        CHECK(memcmp(decoded.signature.bytes, original.signature.bytes, LANTERN_SIGNATURE_SIZE) == 0);

        free(compressed);
        lantern_block_body_reset(&original.message.body);
        lantern_block_body_reset(&decoded.message.body);
    }
}

static void test_gossipsub_service_loopback(void) {
    struct lantern_gossipsub_service service;
    lantern_gossipsub_service_init(&service);
    snprintf(service.block_topic, sizeof(service.block_topic), "/leanconsensus/devnet0/block/ssz_snappy");
    lantern_gossipsub_service_set_loopback_only(&service, 1);

    LanternSignedBlock block;
    memset(&block, 0, sizeof(block));
    lantern_block_body_init(&block.message.body);
    populate_block(&block, 9);

    struct block_hook_ctx ctx = {
        .expected = &block,
        .expected_topic = service.block_topic,
        .called = 0,
    };
    lantern_gossipsub_service_set_publish_hook(&service, block_publish_hook, &ctx);

    CHECK(lantern_gossipsub_service_publish_block(&service, &block) == 0);
    CHECK(ctx.called == 1);

    lantern_block_body_reset(&block.message.body);
    lantern_gossipsub_service_reset(&service);
}

static void test_client_publish_block_loopback(void) {
    struct lantern_client client;
    memset(&client, 0, sizeof(client));
    lantern_gossipsub_service_init(&client.gossip);
    snprintf(client.gossip.block_topic, sizeof(client.gossip.block_topic), "/leanconsensus/devnet/block/ssz_snappy");
    lantern_gossipsub_service_set_loopback_only(&client.gossip, 1);

    LanternSignedBlock block;
    memset(&block, 0, sizeof(block));
    lantern_block_body_init(&block.message.body);
    populate_block(&block, 4);

    struct block_hook_ctx ctx = {
        .expected = &block,
        .expected_topic = client.gossip.block_topic,
        .called = 0,
    };
    lantern_gossipsub_service_set_publish_hook(&client.gossip, block_publish_hook, &ctx);

    client.gossip_running = true;
    client.node_id = "loopback";

    CHECK(lantern_client_publish_block(&client, &block) == 0);
    CHECK(ctx.called == 1);

    lantern_block_body_reset(&block.message.body);
    lantern_gossipsub_service_reset(&client.gossip);
}

int main(void) {
    test_status_snappy();
    test_status_decode_truncated_head_slot();
    test_status_decode_single_truncated_checkpoint();
    test_blocks_by_root_request();
    test_blocks_by_root_response();
    test_gossip_signed_vote_payload();
    test_gossip_signed_block_payload();
    test_gossip_block_snappy_roundtrip_random();
    test_replay_devnet_block_payloads();
    test_gossipsub_service_loopback();
    test_client_publish_block_loopback();
    test_gossip_helpers();
    puts("lantern_networking_messages_test OK");
    return 0;
}
