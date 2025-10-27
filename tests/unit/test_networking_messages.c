#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lantern/consensus/containers.h"
#include "lantern/consensus/ssz.h"
#include "lantern/networking/gossip.h"
#include "lantern/networking/messages.h"
#include "lantern/encoding/snappy.h"

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

int main(void) {
    test_status_snappy();
    test_blocks_by_root_request();
    test_blocks_by_root_response();
    test_gossip_helpers();
    puts("lantern_networking_messages_test OK");
    return 0;
}
