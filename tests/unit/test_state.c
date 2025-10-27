#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    puts("lantern_state_test OK");
    return 0;
}
