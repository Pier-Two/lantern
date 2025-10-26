#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "lantern/consensus/containers.h"
#include "lantern/consensus/ssz.h"

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

static void test_checkpoint_roundtrip(void) {
    LanternCheckpoint input = build_checkpoint(0x11, 42);
    uint8_t buffer[LANTERN_CHECKPOINT_SSZ_SIZE];
    size_t written = 0;
    assert(lantern_ssz_encode_checkpoint(&input, buffer, sizeof(buffer), &written) == 0);
    assert(written == sizeof(buffer));

    LanternCheckpoint decoded;
    memset(&decoded, 0, sizeof(decoded));
    assert(lantern_ssz_decode_checkpoint(&decoded, buffer, sizeof(buffer)) == 0);
    assert(decoded.slot == input.slot);
    assert(memcmp(decoded.root.bytes, input.root.bytes, LANTERN_ROOT_SIZE) == 0);
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

static LanternSignedVote build_signed_vote(uint64_t validator_id, uint64_t slot, uint8_t sig_seed) {
    LanternSignedVote signed_vote;
    signed_vote.data = build_vote();
    signed_vote.data.validator_id = validator_id;
    signed_vote.data.slot = slot;
    signed_vote.data.head = build_checkpoint(sig_seed, slot);
    signed_vote.data.target = build_checkpoint(sig_seed + 1, slot + 1);
    signed_vote.data.source = build_checkpoint(sig_seed + 2, slot > 0 ? slot - 1 : slot);
    fill_bytes(signed_vote.signature.bytes, sizeof(signed_vote.signature.bytes), sig_seed);
    return signed_vote;
}

static void test_vote_roundtrip(void) {
    LanternVote input = build_vote();
    uint8_t buffer[LANTERN_VOTE_SSZ_SIZE];
    size_t written = 0;
    assert(lantern_ssz_encode_vote(&input, buffer, sizeof(buffer), &written) == 0);
    assert(written == sizeof(buffer));

    LanternVote decoded;
    memset(&decoded, 0, sizeof(decoded));
    assert(lantern_ssz_decode_vote(&decoded, buffer, sizeof(buffer)) == 0);
    assert(decoded.validator_id == input.validator_id);
    assert(decoded.slot == input.slot);
    assert(memcmp(decoded.head.root.bytes, input.head.root.bytes, LANTERN_ROOT_SIZE) == 0);
    assert(memcmp(decoded.target.root.bytes, input.target.root.bytes, LANTERN_ROOT_SIZE) == 0);
    assert(memcmp(decoded.source.root.bytes, input.source.root.bytes, LANTERN_ROOT_SIZE) == 0);
}

static void test_signed_vote_roundtrip(void) {
    LanternSignedVote signed_vote;
    signed_vote.data = build_vote();
    fill_bytes(signed_vote.signature.bytes, sizeof(signed_vote.signature.bytes), 0x44);

    uint8_t buffer[LANTERN_SIGNED_VOTE_SSZ_SIZE];
    size_t written = 0;
    assert(lantern_ssz_encode_signed_vote(&signed_vote, buffer, sizeof(buffer), &written) == 0);
    assert(written == sizeof(buffer));

    LanternSignedVote decoded;
    memset(&decoded, 0, sizeof(decoded));
    assert(lantern_ssz_decode_signed_vote(&decoded, buffer, sizeof(buffer)) == 0);
    assert(decoded.data.validator_id == signed_vote.data.validator_id);
    assert(decoded.data.slot == signed_vote.data.slot);
    assert(memcmp(decoded.signature.bytes, signed_vote.signature.bytes, LANTERN_SIGNATURE_SIZE) == 0);
}

static void test_block_header_roundtrip(void) {
    LanternBlockHeader header;
    header.slot = 64;
    header.proposer_index = 5;
    fill_bytes(header.parent_root.bytes, sizeof(header.parent_root.bytes), 0x10);
    fill_bytes(header.state_root.bytes, sizeof(header.state_root.bytes), 0x20);
    fill_bytes(header.body_root.bytes, sizeof(header.body_root.bytes), 0x30);

    uint8_t buffer[LANTERN_BLOCK_HEADER_SSZ_SIZE];
    size_t written = 0;
    assert(lantern_ssz_encode_block_header(&header, buffer, sizeof(buffer), &written) == 0);
    assert(written == sizeof(buffer));

    LanternBlockHeader decoded;
    memset(&decoded, 0, sizeof(decoded));
    assert(lantern_ssz_decode_block_header(&decoded, buffer, sizeof(buffer)) == 0);
    assert(decoded.slot == header.slot);
    assert(decoded.proposer_index == header.proposer_index);
    assert(memcmp(decoded.parent_root.bytes, header.parent_root.bytes, LANTERN_ROOT_SIZE) == 0);
    assert(memcmp(decoded.state_root.bytes, header.state_root.bytes, LANTERN_ROOT_SIZE) == 0);
    assert(memcmp(decoded.body_root.bytes, header.body_root.bytes, LANTERN_ROOT_SIZE) == 0);
}

static void test_block_body_roundtrip(void) {
    LanternBlockBody body;
    lantern_block_body_init(&body);

    LanternSignedVote vote_a = build_signed_vote(1, 5, 0x50);
    LanternSignedVote vote_b = build_signed_vote(2, 6, 0x60);
    assert(lantern_attestations_append(&body.attestations, &vote_a) == 0);
    assert(lantern_attestations_append(&body.attestations, &vote_b) == 0);

    uint8_t buffer[1024];
    size_t written = 0;
    assert(lantern_ssz_encode_block_body(&body, buffer, sizeof(buffer), &written) == 0);

    LanternBlockBody decoded;
    lantern_block_body_init(&decoded);
    assert(lantern_ssz_decode_block_body(&decoded, buffer, written) == 0);
    assert(decoded.attestations.length == body.attestations.length);

    for (size_t i = 0; i < body.attestations.length; ++i) {
        assert(decoded.attestations.data[i].data.validator_id == body.attestations.data[i].data.validator_id);
        assert(memcmp(decoded.attestations.data[i].signature.bytes,
                      body.attestations.data[i].signature.bytes,
                      LANTERN_SIGNATURE_SIZE)
               == 0);
    }

    lantern_block_body_reset(&body);
    lantern_block_body_reset(&decoded);
}

static void populate_block(LanternBlock *block) {
    memset(block, 0, sizeof(*block));
    block->slot = 88;
    block->proposer_index = 12;
    fill_bytes(block->parent_root.bytes, sizeof(block->parent_root.bytes), 0xAA);
    fill_bytes(block->state_root.bytes, sizeof(block->state_root.bytes), 0xBB);
    lantern_block_body_init(&block->body);

    LanternSignedVote vote_a = build_signed_vote(11, 15, 0x70);
    LanternSignedVote vote_b = build_signed_vote(22, 16, 0x80);
    assert(lantern_attestations_append(&block->body.attestations, &vote_a) == 0);
    assert(lantern_attestations_append(&block->body.attestations, &vote_b) == 0);
}

static void reset_block(LanternBlock *block) {
    lantern_block_body_reset(&block->body);
}

static void test_block_roundtrip(void) {
    LanternBlock block;
    populate_block(&block);

    uint8_t buffer[4096];
    size_t written = 0;
    assert(lantern_ssz_encode_block(&block, buffer, sizeof(buffer), &written) == 0);

    LanternBlock decoded;
    memset(&decoded, 0, sizeof(decoded));
    lantern_block_body_init(&decoded.body);
    assert(lantern_ssz_decode_block(&decoded, buffer, written) == 0);

    assert(decoded.slot == block.slot);
    assert(decoded.proposer_index == block.proposer_index);
    assert(memcmp(decoded.parent_root.bytes, block.parent_root.bytes, LANTERN_ROOT_SIZE) == 0);
    assert(memcmp(decoded.state_root.bytes, block.state_root.bytes, LANTERN_ROOT_SIZE) == 0);
    assert(decoded.body.attestations.length == block.body.attestations.length);

    for (size_t i = 0; i < block.body.attestations.length; ++i) {
        assert(memcmp(decoded.body.attestations.data[i].signature.bytes,
                      block.body.attestations.data[i].signature.bytes,
                      LANTERN_SIGNATURE_SIZE)
               == 0);
    }

    reset_block(&block);
    reset_block(&decoded);
}

static void test_signed_block_roundtrip(void) {
    LanternSignedBlock signed_block;
    memset(&signed_block, 0, sizeof(signed_block));
    populate_block(&signed_block.message);
    fill_bytes(signed_block.signature.bytes, sizeof(signed_block.signature.bytes), 0x90);

    uint8_t buffer[4096];
    size_t written = 0;
    assert(lantern_ssz_encode_signed_block(&signed_block, buffer, sizeof(buffer), &written) == 0);

    LanternSignedBlock decoded;
    memset(&decoded, 0, sizeof(decoded));
    lantern_block_body_init(&decoded.message.body);
    assert(lantern_ssz_decode_signed_block(&decoded, buffer, written) == 0);

    assert(decoded.message.slot == signed_block.message.slot);
    assert(memcmp(decoded.signature.bytes, signed_block.signature.bytes, LANTERN_SIGNATURE_SIZE) == 0);
    assert(decoded.message.body.attestations.length == signed_block.message.body.attestations.length);

    reset_block(&signed_block.message);
    reset_block(&decoded.message);
}

int main(void) {
    test_checkpoint_roundtrip();
    test_vote_roundtrip();
    test_signed_vote_roundtrip();
    test_block_header_roundtrip();
    test_block_body_roundtrip();
    test_block_roundtrip();
    test_signed_block_roundtrip();
    puts("lantern_ssz_test OK");
    return 0;
}
