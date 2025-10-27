#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "lantern/consensus/duties.h"
#include "lantern/consensus/hash.h"
#include "lantern/consensus/state.h"

static void expect_zero(int rc, const char *label) {
    if (rc != 0) {
        fprintf(stderr, "%s failed (rc=%d)\n", label, rc);
        exit(EXIT_FAILURE);
    }
}

static void expect_nonzero_root(const LanternRoot *root, const char *label) {
    bool all_zero = true;
    for (size_t i = 0; i < LANTERN_ROOT_SIZE; ++i) {
        if (root->bytes[i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) {
        fprintf(stderr, "%s still zero\n", label);
        exit(EXIT_FAILURE);
    }
}

static void fill_root(LanternRoot *root, uint8_t value) {
    if (!root) {
        return;
    }
    memset(root->bytes, value, LANTERN_ROOT_SIZE);
}

static int test_genesis_state(void) {
    LanternState state;
    lantern_state_init(&state);
    expect_zero(lantern_state_generate_genesis(&state, 1234, 8), "generate genesis");

    assert(state.config.genesis_time == 1234);
    assert(state.config.num_validators == 8);
    assert(state.slot == 0);

    LanternBlockBody empty_body;
    lantern_block_body_init(&empty_body);
    LanternRoot expected_body_root;
    expect_zero(lantern_hash_tree_root_block_body(&empty_body, &expected_body_root), "hash empty body");
    lantern_block_body_reset(&empty_body);
    assert(memcmp(state.latest_block_header.body_root.bytes, expected_body_root.bytes, LANTERN_ROOT_SIZE) == 0);
    for (size_t i = 0; i < LANTERN_ROOT_SIZE; ++i) {
        assert(state.latest_block_header.state_root.bytes[i] == 0);
    }

    lantern_state_reset(&state);
    return 0;
}

static int test_process_slots_sets_state_root(void) {
    LanternState state;
    lantern_state_init(&state);
    expect_zero(lantern_state_generate_genesis(&state, 50, 4), "generate genesis");

    LanternRoot pre_root;
    expect_zero(lantern_hash_tree_root_state(&state, &pre_root), "hash state pre-slot");

    expect_zero(lantern_state_process_slots(&state, 1), "process slot 1");
    assert(state.slot == 1);
    assert(memcmp(state.latest_block_header.state_root.bytes, pre_root.bytes, LANTERN_ROOT_SIZE) == 0);

    lantern_state_reset(&state);
    return 0;
}

static int test_state_transition_applies_block(void) {
    const uint64_t genesis_time = 500;
    const uint64_t validator_count = 8;

    LanternState state;
    lantern_state_init(&state);
    expect_zero(lantern_state_generate_genesis(&state, genesis_time, validator_count), "generate genesis state");

    LanternState expected;
    lantern_state_init(&expected);
    expect_zero(lantern_state_generate_genesis(&expected, genesis_time, validator_count), "generate expected state");

    LanternBlock block;
    memset(&block, 0, sizeof(block));
    block.slot = 1;
    expect_zero(lantern_proposer_for_slot(block.slot, validator_count, &block.proposer_index), "compute proposer");
    lantern_block_body_init(&block.body);

    expect_zero(lantern_state_process_slots(&expected, block.slot), "expected process slots");
    LanternRoot parent_root;
    expect_zero(lantern_hash_tree_root_block_header(&expected.latest_block_header, &parent_root), "hash parent header");
    block.parent_root = parent_root;
    expect_zero(lantern_state_process_block(&expected, &block), "expected process block");
    LanternRoot expected_state_root;
    expect_zero(lantern_hash_tree_root_state(&expected, &expected_state_root), "hash expected state");
    block.state_root = expected_state_root;

    LanternSignedBlock signed_block;
    memset(&signed_block, 0, sizeof(signed_block));
    signed_block.message = block;

    expect_zero(lantern_state_transition(&state, &signed_block), "state transition");
    LanternRoot post_root;
    expect_zero(lantern_hash_tree_root_state(&state, &post_root), "hash post state");
    assert(memcmp(post_root.bytes, expected_state_root.bytes, LANTERN_ROOT_SIZE) == 0);
    assert(state.slot == expected.slot);
    assert(state.historical_block_hashes.length == expected.historical_block_hashes.length);

    lantern_block_body_reset(&block.body);
    lantern_state_reset(&state);
    lantern_state_reset(&expected);
    return 0;
}

static void build_vote(
    LanternSignedVote *out,
    uint64_t validator_id,
    uint64_t slot,
    const LanternCheckpoint *source,
    const LanternCheckpoint *target_template,
    uint8_t head_marker) {
    memset(out, 0, sizeof(*out));
    out->data.validator_id = validator_id;
    out->data.slot = slot;
    out->data.source = *source;
    out->data.target = *target_template;
    out->data.head = out->data.target;
    if (head_marker != 0) {
        fill_root(&out->data.head.root, head_marker);
    }
}

static int test_attestations_require_quorum(void) {
    LanternState state;
    lantern_state_init(&state);
    expect_zero(lantern_state_generate_genesis(&state, 500, 4), "genesis for quorum test");

    LanternAttestations attestations;
    lantern_attestations_init(&attestations);

    LanternCheckpoint target_checkpoint = state.latest_justified;
    target_checkpoint.slot = 1;
    fill_root(&target_checkpoint.root, 0xAB);

    expect_zero(lantern_attestations_resize(&attestations, 2), "resize partial quorum");
    build_vote(&attestations.data[0], 0, 1, &state.latest_justified, &target_checkpoint, 0);
    build_vote(&attestations.data[1], 1, 1, &state.latest_justified, &target_checkpoint, 0);

    expect_zero(lantern_state_process_attestations(&state, &attestations), "process below quorum");
    assert(state.latest_justified.slot == 0);
    assert(state.latest_finalized.slot == 0);

    expect_zero(lantern_attestations_resize(&attestations, 1), "resize for quorum vote");
    build_vote(&attestations.data[0], 2, 1, &state.latest_justified, &target_checkpoint, 0);

    expect_zero(lantern_state_process_attestations(&state, &attestations), "process reaching quorum");
    assert(state.latest_justified.slot == 1);
    assert(state.latest_finalized.slot == 0);

    lantern_attestations_reset(&attestations);
    lantern_state_reset(&state);
    return 0;
}

static int test_attestations_reject_double_vote(void) {
    LanternState state;
    lantern_state_init(&state);
    expect_zero(lantern_state_generate_genesis(&state, 700, 3), "genesis for double vote test");

    LanternAttestations attestations;
    lantern_attestations_init(&attestations);
    expect_zero(lantern_attestations_resize(&attestations, 2), "double vote resize");

    LanternCheckpoint target_checkpoint = state.latest_justified;
    target_checkpoint.slot = 1;
    fill_root(&target_checkpoint.root, 0xCD);

    build_vote(&attestations.data[0], 0, 1, &state.latest_justified, &target_checkpoint, 0x11);
    build_vote(&attestations.data[1], 0, 1, &state.latest_justified, &target_checkpoint, 0x22);

    if (lantern_state_process_attestations(&state, &attestations) == 0) {
        fprintf(stderr, "Expected double vote rejection\n");
        lantern_attestations_reset(&attestations);
        lantern_state_reset(&state);
        return 1;
    }

    lantern_attestations_reset(&attestations);
    lantern_state_reset(&state);
    return 0;
}

int main(void) {
    if (test_genesis_state() != 0) {
        return 1;
    }
    if (test_process_slots_sets_state_root() != 0) {
        return 1;
    }
    if (test_state_transition_applies_block() != 0) {
        return 1;
    }
    if (test_attestations_require_quorum() != 0) {
        return 1;
    }
    if (test_attestations_reject_double_vote() != 0) {
        return 1;
    }
    puts("lantern_state_test OK");
    return 0;
}
