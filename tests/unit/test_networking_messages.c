#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    vote.validator_id = 7;
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
    signed_vote.data.target = build_checkpoint(seed + 1, slot + 1);
    signed_vote.data.source = build_checkpoint(seed + 2, slot > 0 ? slot - 1 : slot);
    return signed_vote;
}

static void populate_block(LanternSignedBlock *signed_block, uint8_t seed) {
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

static int load_fixture_file(const char *relative, uint8_t **out_buf, size_t *out_len) {
    if (!relative || !out_buf || !out_len) {
        return -1;
    }
    char path[512];
    int written = snprintf(path, sizeof(path), "%s/%s", LANTERN_TEST_FIXTURE_DIR, relative);
    if (written <= 0 || (size_t)written >= sizeof(path)) {
        return -1;
    }
    FILE *file = fopen(path, "rb");
    if (!file) {
        perror("fopen");
        return -1;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return -1;
    }
    long size = ftell(file);
    if (size < 0) {
        fclose(file);
        return -1;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return -1;
    }
    uint8_t *buffer = (uint8_t *)malloc((size_t)size);
    if (!buffer) {
        fclose(file);
        return -1;
    }
    size_t read_len = fread(buffer, 1u, (size_t)size, file);
    fclose(file);
    if (read_len != (size_t)size) {
        free(buffer);
        return -1;
    }
    *out_buf = buffer;
    *out_len = read_len;
    return 0;
}

static void test_replay_devnet_block_payloads(void) {
    struct devnet_block_case {
        const char *fixture;
        uint64_t expected_slot;
        uint64_t expected_proposer;
        const char *expected_parent_root;
        const char *expected_state_root;
        const char *expected_block_root;
        size_t expected_attestations;
        uint64_t first_vote_slot;
        uint64_t first_vote_head_slot;
    } cases[] = {
        {
            .fixture = "devnet0/block_slot6.ssz_snappy",
            .expected_slot = 6,
            .expected_proposer = 0,
            .expected_parent_root = "0xb4e0f2473e0819b1dbdec17adc011c61ebec46121f8c2642dabc43745df2f1a6",
            .expected_state_root = "0x9d3ba02c972d48b943861189154fef8378426b40052a0c9a9a7e707900c6cb89",
            .expected_block_root = "0x51b0d0b0737bdd173b4c5ba46493b0c04a732eaaef38d27512dac7124e6e2ff7",
            .expected_attestations = 2,
            .first_vote_slot = 5,
            .first_vote_head_slot = 1,
        },
        {
            .fixture = "devnet0/block_slot7.ssz_snappy",
            .expected_slot = 7,
            .expected_proposer = 1,
            .expected_parent_root = "0xaff22c5edbda1ace79d20617204a02261de3dc1b97277d79992eba175f334f92",
            .expected_state_root = "0x32aa99576ae2294491d86eeca8310f94eee6d28f8cb3d8fc9ecc086a8ea49b2e",
            .expected_block_root = "0x2a7c152001a6b8712d66850d20e11faee62fcc373d51a8e305d0a3cd9ea22c05",
            .expected_attestations = 2,
            .first_vote_slot = 6,
            .first_vote_head_slot = 6,
        },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint8_t *compressed = NULL;
        size_t compressed_len = 0;
        CHECK(load_fixture_file(cases[i].fixture, &compressed, &compressed_len) == 0);
        CHECK(compressed_len > 0);

        size_t raw_len = 0;
        CHECK(lantern_snappy_uncompressed_length(compressed, compressed_len, &raw_len) == LANTERN_SNAPPY_OK);
        CHECK(raw_len > 0);

        LanternSignedBlock decoded;
        memset(&decoded, 0, sizeof(decoded));
        lantern_block_body_init(&decoded.message.body);
        CHECK(lantern_gossip_decode_signed_block_snappy(&decoded, compressed, compressed_len) == 0);

        uint8_t expected_parent[LANTERN_ROOT_SIZE];
        uint8_t expected_state[LANTERN_ROOT_SIZE];
        uint8_t expected_block[LANTERN_ROOT_SIZE];
        CHECK(parse_hex_bytes(cases[i].expected_parent_root, expected_parent, sizeof(expected_parent)) == 0);
        CHECK(parse_hex_bytes(cases[i].expected_state_root, expected_state, sizeof(expected_state)) == 0);
        CHECK(parse_hex_bytes(cases[i].expected_block_root, expected_block, sizeof(expected_block)) == 0);

        CHECK(decoded.message.slot == cases[i].expected_slot);
        CHECK(decoded.message.proposer_index == cases[i].expected_proposer);
        CHECK(memcmp(decoded.message.parent_root.bytes, expected_parent, LANTERN_ROOT_SIZE) == 0);
        CHECK(memcmp(decoded.message.state_root.bytes, expected_state, LANTERN_ROOT_SIZE) == 0);
        CHECK(lantern_signature_is_zero(&decoded.signature));
        CHECK(decoded.message.body.attestations.length == cases[i].expected_attestations);

        if (decoded.message.body.attestations.length > 0 && decoded.message.body.attestations.data) {
            const LanternSignedVote *vote = &decoded.message.body.attestations.data[0];
            CHECK(vote->data.slot == cases[i].first_vote_slot);
            CHECK(vote->data.head.slot == cases[i].first_vote_head_slot);
            static const uint8_t zero_sig[LANTERN_SIGNATURE_SIZE] = {0};
            CHECK(memcmp(vote->signature.bytes, zero_sig, LANTERN_SIGNATURE_SIZE) == 0);
        }
        for (size_t att_idx = 0; att_idx < decoded.message.body.attestations.length; ++att_idx) {
            CHECK(lantern_signature_is_zero(&decoded.message.body.attestations.data[att_idx].signature));
        }

        LanternRoot computed_root;
        memset(&computed_root, 0, sizeof(computed_root));
        CHECK(lantern_hash_tree_root_block(&decoded.message, &computed_root) == 0);
        CHECK(memcmp(computed_root.bytes, expected_block, LANTERN_ROOT_SIZE) == 0);

        uint8_t *raw_fixture = (uint8_t *)malloc(raw_len);
        CHECK(raw_fixture != NULL);
        size_t raw_fixture_written = raw_len;
        CHECK(lantern_snappy_decompress(compressed, compressed_len, raw_fixture, raw_len, &raw_fixture_written) == LANTERN_SNAPPY_OK);

        uint8_t raw_encoded[512];
        size_t raw_encoded_written = sizeof(raw_encoded);
        CHECK(lantern_ssz_encode_signed_block(&decoded, raw_encoded, sizeof(raw_encoded), &raw_encoded_written) == 0);
        CHECK(raw_encoded_written == raw_fixture_written);
        CHECK(memcmp(raw_encoded, raw_fixture, raw_fixture_written) == 0);

        size_t max_compressed = 0;
        CHECK(lantern_snappy_max_compressed_size(raw_encoded_written, &max_compressed) == LANTERN_SNAPPY_OK);
        uint8_t *recompressed = (uint8_t *)malloc(max_compressed);
        CHECK(recompressed != NULL);
        size_t recompressed_len = max_compressed;
        CHECK(lantern_gossip_encode_signed_block_snappy(&decoded, recompressed, max_compressed, &recompressed_len) == 0);

        size_t recon_len = 0;
        CHECK(lantern_snappy_uncompressed_length(recompressed, recompressed_len, &recon_len) == LANTERN_SNAPPY_OK);
        CHECK(recon_len == raw_encoded_written);
        uint8_t *recon_raw = (uint8_t *)malloc(recon_len);
        CHECK(recon_raw != NULL);
        size_t recon_written = recon_len;
        CHECK(lantern_snappy_decompress(recompressed, recompressed_len, recon_raw, recon_len, &recon_written) == LANTERN_SNAPPY_OK);
        CHECK(recon_written == raw_encoded_written);
        CHECK(memcmp(recon_raw, raw_encoded, raw_encoded_written) == 0);

        lantern_block_body_reset(&decoded.message.body);
        free(recon_raw);
        free(recompressed);
        free(raw_fixture);
        free(compressed);
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
    check_zero(lantern_network_status_encode_snappy(&status, compressed, sizeof(compressed), &compressed_len), "status encode snappy");

    LanternStatusMessage snappy_decoded = {0};
    check_zero(lantern_network_status_decode_snappy(&snappy_decoded, compressed, compressed_len), "status decode snappy");
    CHECK(memcmp(snappy_decoded.head.root.bytes, status.head.root.bytes, LANTERN_ROOT_SIZE) == 0);
    CHECK(snappy_decoded.finalized.slot == status.finalized.slot);
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
    check_zero(lantern_network_blocks_by_root_request_encode_snappy(&req, compressed, sizeof(compressed), &compressed_len), "request encode snappy");

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

    uint8_t encoded[8192];
    size_t written = 0;
    check_zero(lantern_network_blocks_by_root_response_encode(&resp, encoded, sizeof(encoded), &written), "response encode");
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

    uint8_t compressed[16384];
    size_t compressed_len = 0;
    check_zero(lantern_network_blocks_by_root_response_encode_snappy(&resp, compressed, sizeof(compressed), &compressed_len), "response encode snappy");

    LanternBlocksByRootResponse snappy_decoded;
    lantern_blocks_by_root_response_init(&snappy_decoded);
    check_zero(lantern_network_blocks_by_root_response_decode_snappy(&snappy_decoded, compressed, compressed_len), "response decode snappy");
    CHECK(snappy_decoded.length == resp.length);
    CHECK(snappy_decoded.blocks[0].message.slot == resp.blocks[0].message.slot);

    lantern_blocks_by_root_response_reset(&resp);
    lantern_blocks_by_root_response_reset(&decoded);
    lantern_blocks_by_root_response_reset(&snappy_decoded);
}

static void test_gossip_helpers(void) {
    char topic[128];
    check_zero(lantern_gossip_topic_format(LANTERN_GOSSIP_TOPIC_BLOCK, "devnet0", topic, sizeof(topic)), "topic format");
    CHECK(strcmp(topic, "/leanconsensus/devnet0/block/ssz_snappy") == 0);

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

    size_t max_compressed = 0;
    CHECK(lantern_snappy_max_compressed_size(LANTERN_SIGNED_VOTE_SSZ_SIZE, &max_compressed) == LANTERN_SNAPPY_OK);
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
            uint64_t target_floor = vote.data.slot > vote.data.source.slot ? vote.data.slot : vote.data.source.slot;
            vote.data.target.slot = target_floor + rng_uniform(3);
            vote.data.head.slot = vote.data.target.slot + rng_uniform(2);
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
    snprintf(client.gossip.block_topic, sizeof(client.gossip.block_topic), "/leanconsensus/devnet0/block/ssz_snappy");
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
