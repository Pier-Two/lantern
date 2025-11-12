#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "lantern/consensus/duties.h"
#include "lantern/consensus/hash.h"
#include "lantern/consensus/fork_choice.h"
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

static void fill_signature(LanternSignature *signature, uint8_t value) {
    if (!signature) {
        return;
    }
    memset(signature->bytes, value, LANTERN_SIGNATURE_SIZE);
}

static bool checkpoints_equal(const LanternCheckpoint *a, const LanternCheckpoint *b) {
    if (!a || !b) {
        return false;
    }
    if (a->slot != b->slot) {
        return false;
    }
    return memcmp(a->root.bytes, b->root.bytes, LANTERN_ROOT_SIZE) == 0;
}

static void setup_state_and_fork_choice(
    LanternState *state,
    LanternForkChoice *fork_choice,
    uint64_t genesis_time,
    uint64_t validator_count,
    LanternRoot *out_anchor_root) {
    lantern_state_init(state);
    expect_zero(lantern_state_generate_genesis(state, genesis_time, validator_count), "generate genesis for setup");

    lantern_fork_choice_init(fork_choice);
    expect_zero(lantern_fork_choice_configure(fork_choice, &state->config), "configure fork choice for setup");

    LanternRoot state_root;
    expect_zero(lantern_hash_tree_root_state(state, &state_root), "hash state for anchor setup");
    state->latest_block_header.state_root = state_root;
    LanternRoot header_root;
    expect_zero(
        lantern_hash_tree_root_block_header(&state->latest_block_header, &header_root),
        "hash header for anchor setup");
    state->latest_justified.root = header_root;
    state->latest_finalized.root = header_root;

    LanternBlock anchor;
    memset(&anchor, 0, sizeof(anchor));
    anchor.slot = state->latest_block_header.slot;
    anchor.proposer_index = state->latest_block_header.proposer_index;
    anchor.parent_root = state->latest_block_header.parent_root;
    anchor.state_root = state_root;
    lantern_block_body_init(&anchor.body);

    expect_zero(lantern_hash_tree_root_block(&anchor, out_anchor_root), "hash anchor block");

    expect_zero(
        lantern_fork_choice_set_anchor(
            fork_choice,
            &anchor,
            &state->latest_justified,
            &state->latest_finalized,
            out_anchor_root),
        "set fork choice anchor");

    lantern_state_attach_fork_choice(state, fork_choice);
    lantern_block_body_reset(&anchor.body);
}

static void make_block(
    const LanternState *state,
    uint64_t slot,
    const LanternRoot *parent_root,
    LanternBlock *out_block,
    LanternRoot *out_root) {
    memset(out_block, 0, sizeof(*out_block));
    out_block->slot = slot;
    expect_zero(
        lantern_proposer_for_slot(slot, state->config.num_validators, &out_block->proposer_index),
        "compute proposer for block");
    out_block->parent_root = *parent_root;
    memset(out_block->state_root.bytes, 0, sizeof(out_block->state_root.bytes));
    lantern_block_body_init(&out_block->body);
    expect_zero(lantern_hash_tree_root_block(out_block, out_root), "hash block");
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
    expect_zero(lantern_state_process_block(&expected, &block, NULL), "expected process block");
    LanternRoot expected_state_root;
    expect_zero(lantern_hash_tree_root_state(&expected, &expected_state_root), "hash expected state");
    block.state_root = expected_state_root;

    LanternSignedBlock signed_block;
    memset(&signed_block, 0, sizeof(signed_block));
    signed_block.message.block = block;

    expect_zero(lantern_state_transition(&state, &signed_block), "state transition");
    LanternRoot post_root;
    expect_zero(lantern_hash_tree_root_state(&state, &post_root), "hash post state");
    assert(memcmp(post_root.bytes, expected_state_root.bytes, LANTERN_ROOT_SIZE) == 0);
    assert(memcmp(state.latest_block_header.state_root.bytes, expected_state_root.bytes, LANTERN_ROOT_SIZE) == 0);
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
    uint8_t sig_marker = head_marker ? head_marker : (uint8_t)(validator_id + slot);
    fill_signature(&out->signature, sig_marker);
}

static const LanternSignedVote *find_vote_by_validator(
    const LanternAttestations *attestations,
    uint64_t validator_id) {
    if (!attestations) {
        return NULL;
    }
    for (size_t i = 0; i < attestations->length; ++i) {
        if (attestations->data[i].data.validator_id == validator_id) {
            return &attestations->data[i];
        }
    }
    return NULL;
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

static int test_collect_attestations_for_block(void) {
    LanternState state;
    lantern_state_init(&state);
    expect_zero(lantern_state_generate_genesis(&state, 900, 4), "genesis for collection test");

    LanternAttestations input;
    lantern_attestations_init(&input);
    expect_zero(lantern_attestations_resize(&input, 3), "resize attestation input");

    LanternCheckpoint justified = state.latest_justified;
    LanternCheckpoint target = justified;
    target.slot = justified.slot + 1;
    fill_root(&target.root, 0x90);

    build_vote(&input.data[0], 0, target.slot, &justified, &target, 0x01);
    build_vote(&input.data[1], 1, target.slot, &justified, &target, 0x02);

    LanternCheckpoint other_source = justified;
    other_source.slot = justified.slot + 2;
    fill_root(&other_source.root, 0xA0);
    LanternCheckpoint other_target = other_source;
    other_target.slot = other_source.slot + 1;
    fill_root(&other_target.root, 0xB0);
    build_vote(&input.data[2], 2, other_target.slot, &other_source, &other_target, 0x03);

    expect_zero(lantern_state_process_attestations(&state, &input), "process mixed attestations");

    LanternAttestations collected;
    lantern_attestations_init(&collected);
    expect_zero(lantern_state_collect_attestations_for_block(&state, &collected), "collect attestations");

    if (collected.length != 2) {
        fprintf(stderr, "Expected two votes collected, got %zu\n", collected.length);
        lantern_attestations_reset(&collected);
        lantern_attestations_reset(&input);
        lantern_state_reset(&state);
        return 1;
    }

    bool seen_validator[2] = {false, false};
    for (size_t i = 0; i < collected.length; ++i) {
        const LanternSignedVote *vote = &collected.data[i];
        const LanternSignedVote *original = find_vote_by_validator(&input, vote->data.validator_id);
        if (!original
            || memcmp(vote->signature.bytes, original->signature.bytes, LANTERN_SIGNATURE_SIZE) != 0) {
            fprintf(stderr, "Collected vote %zu signature mismatch\n", i);
            lantern_attestations_reset(&collected);
            lantern_attestations_reset(&input);
            lantern_state_reset(&state);
            return 1;
        }
        if (!checkpoints_equal(&vote->data.source, &state.latest_justified)) {
            fprintf(stderr, "Collected vote %zu has mismatched source checkpoint\n", i);
            lantern_attestations_reset(&collected);
            lantern_attestations_reset(&input);
            lantern_state_reset(&state);
            return 1;
        }
        if (vote->data.validator_id == 0) {
            seen_validator[0] = true;
        } else if (vote->data.validator_id == 1) {
            seen_validator[1] = true;
        } else {
            fprintf(stderr, "Unexpected validator id %" PRIu64 " in collected vote\n", vote->data.validator_id);
            lantern_attestations_reset(&collected);
            lantern_attestations_reset(&input);
            lantern_state_reset(&state);
            return 1;
        }
    }

    if (!seen_validator[0] || !seen_validator[1]) {
        fprintf(stderr, "Missing expected validators in collected votes\n");
        lantern_attestations_reset(&collected);
        lantern_attestations_reset(&input);
        lantern_state_reset(&state);
        return 1;
    }

    lantern_attestations_reset(&collected);
    lantern_attestations_reset(&input);
    lantern_state_reset(&state);
    return 0;
}

static int test_select_block_parent_uses_fork_choice(void) {
    LanternState state;
    lantern_state_init(&state);
    expect_zero(lantern_state_generate_genesis(&state, 1200, 4), "genesis for parent selection");

    LanternForkChoice fork_choice;
    lantern_fork_choice_init(&fork_choice);
    expect_zero(lantern_fork_choice_configure(&fork_choice, &state.config), "configure fork choice");

    LanternBlock genesis_block;
    memset(&genesis_block, 0, sizeof(genesis_block));
    genesis_block.slot = 0;
    genesis_block.proposer_index = 0;
    lantern_block_body_init(&genesis_block.body);
    genesis_block.parent_root = state.latest_block_header.parent_root;
    genesis_block.state_root = state.latest_block_header.state_root;

    LanternRoot genesis_root;
    expect_zero(lantern_hash_tree_root_block(&genesis_block, &genesis_root), "genesis block root");
    LanternCheckpoint genesis_cp = {.root = genesis_root, .slot = genesis_block.slot};
    expect_zero(
        lantern_fork_choice_set_anchor(&fork_choice, &genesis_block, &genesis_cp, &genesis_cp, &genesis_root),
        "set anchor");

    lantern_state_attach_fork_choice(&state, &fork_choice);

    LanternRoot parent_root;
    expect_zero(lantern_state_select_block_parent(&state, &parent_root), "select parent at genesis");
    assert(memcmp(parent_root.bytes, genesis_root.bytes, LANTERN_ROOT_SIZE) == 0);

    LanternBlock block_one;
    memset(&block_one, 0, sizeof(block_one));
    block_one.slot = 1;
    expect_zero(
        lantern_proposer_for_slot(block_one.slot, state.config.num_validators, &block_one.proposer_index),
        "proposer slot1");
    lantern_block_body_init(&block_one.body);
    block_one.parent_root = genesis_root;

    LanternRoot body_root_one;
    expect_zero(lantern_hash_tree_root_block_body(&block_one.body, &body_root_one), "block one body root");
    state.slot = block_one.slot;
    state.latest_block_header.slot = block_one.slot;
    state.latest_block_header.proposer_index = block_one.proposer_index;
    state.latest_block_header.parent_root = block_one.parent_root;
    state.latest_block_header.body_root = body_root_one;
    memset(state.latest_block_header.state_root.bytes, 0, LANTERN_ROOT_SIZE);
    LanternRoot block_one_root;
    expect_zero(lantern_hash_tree_root_block(&block_one, &block_one_root), "block one root");
    expect_zero(
        lantern_fork_choice_add_block(
            &fork_choice,
            &block_one,
            NULL,
            &state.latest_justified,
            &state.latest_finalized,
            &block_one_root),
        "add block one to fork choice");

    expect_zero(lantern_state_select_block_parent(&state, &parent_root), "select parent after block one");
    assert(memcmp(parent_root.bytes, block_one_root.bytes, LANTERN_ROOT_SIZE) == 0);

    LanternBlock block_two;
    memset(&block_two, 0, sizeof(block_two));
    block_two.slot = 2;
    expect_zero(
        lantern_proposer_for_slot(block_two.slot, state.config.num_validators, &block_two.proposer_index),
        "proposer slot2");
    block_two.parent_root = block_one_root;
    lantern_block_body_init(&block_two.body);
    memset(block_two.state_root.bytes, 0x7Au, sizeof(block_two.state_root.bytes));
    LanternRoot block_two_root;
    expect_zero(lantern_hash_tree_root_block(&block_two, &block_two_root), "block two root");
    expect_zero(
        lantern_fork_choice_add_block(&fork_choice, &block_two, NULL, NULL, NULL, &block_two_root),
        "add block two");

    if (lantern_state_select_block_parent(&state, &parent_root) == 0) {
        fprintf(stderr, "Expected parent mismatch detection to fail\n");
        lantern_block_body_reset(&block_two.body);
        lantern_block_body_reset(&block_one.body);
        lantern_block_body_reset(&genesis_block.body);
        lantern_state_reset(&state);
        lantern_fork_choice_reset(&fork_choice);
        return 1;
    }

    lantern_block_body_reset(&block_two.body);
    lantern_block_body_reset(&block_one.body);
    lantern_block_body_reset(&genesis_block.body);
    lantern_state_reset(&state);
    lantern_fork_choice_reset(&fork_choice);
    return 0;
}

static int test_compute_vote_checkpoints_basic(void) {
    LanternState state;
    LanternForkChoice fork_choice;
    LanternRoot genesis_root;
    setup_state_and_fork_choice(&state, &fork_choice, 1500, 4, &genesis_root);

    LanternBlock block1;
    LanternRoot block1_root;
    make_block(&state, 1, &genesis_root, &block1, &block1_root);
    expect_zero(
        lantern_fork_choice_add_block(&fork_choice, &block1, NULL, NULL, NULL, &block1_root),
        "add block1");
    fork_choice.head = block1_root;
    fork_choice.has_head = true;
    fork_choice.safe_target = block1_root;
    fork_choice.has_safe_target = true;

    LanternCheckpoint head;
    LanternCheckpoint target;
    LanternCheckpoint source;
    int rc = lantern_state_compute_vote_checkpoints(&state, &head, &target, &source);
    if (rc != 0) {
        fprintf(stderr, "compute vote checkpoints basic failed (rc=%d)\n", rc);
        lantern_block_body_reset(&block1.body);
        lantern_state_reset(&state);
        lantern_fork_choice_reset(&fork_choice);
        return 1;
    }
    if (head.slot != block1.slot || memcmp(head.root.bytes, block1_root.bytes, LANTERN_ROOT_SIZE) != 0) {
        fprintf(stderr, "unexpected head checkpoint in basic test\n");
        lantern_block_body_reset(&block1.body);
        lantern_state_reset(&state);
        lantern_fork_choice_reset(&fork_choice);
        return 1;
    }
    if (!checkpoints_equal(&target, &head)) {
        fprintf(stderr, "target mismatch in basic checkpoint computation\n");
        lantern_block_body_reset(&block1.body);
        lantern_state_reset(&state);
        lantern_fork_choice_reset(&fork_choice);
        return 1;
    }
    if (!checkpoints_equal(&source, &state.latest_justified)) {
        fprintf(stderr, "source checkpoint mismatch in basic test\n");
        lantern_block_body_reset(&block1.body);
        lantern_state_reset(&state);
        lantern_fork_choice_reset(&fork_choice);
        return 1;
    }

    lantern_block_body_reset(&block1.body);
    lantern_state_reset(&state);
    lantern_fork_choice_reset(&fork_choice);
    return 0;
}

static int test_compute_vote_checkpoints_respects_safe_target(void) {
    LanternState state;
    LanternForkChoice fork_choice;
    LanternRoot genesis_root;
    setup_state_and_fork_choice(&state, &fork_choice, 1600, 6, &genesis_root);

    LanternBlock block1;
    LanternRoot block1_root;
    make_block(&state, 1, &genesis_root, &block1, &block1_root);
    expect_zero(
        lantern_fork_choice_add_block(&fork_choice, &block1, NULL, NULL, NULL, &block1_root),
        "add block1 safe target test");

    LanternBlock block2;
    LanternRoot block2_root;
    make_block(&state, 2, &block1_root, &block2, &block2_root);
    expect_zero(
        lantern_fork_choice_add_block(&fork_choice, &block2, NULL, NULL, NULL, &block2_root),
        "add block2 safe target test");

    fork_choice.head = block2_root;
    fork_choice.has_head = true;
    fork_choice.safe_target = block1_root;
    fork_choice.has_safe_target = true;

    state.latest_finalized.slot = 0;
    state.latest_finalized.root = genesis_root;
    state.latest_justified = state.latest_finalized;

    LanternCheckpoint head;
    LanternCheckpoint target;
    LanternCheckpoint source;
    int rc = lantern_state_compute_vote_checkpoints(&state, &head, &target, &source);
    if (rc != 0) {
        fprintf(stderr, "compute vote checkpoints safe target failed (rc=%d)\n", rc);
        lantern_block_body_reset(&block2.body);
        lantern_block_body_reset(&block1.body);
        lantern_state_reset(&state);
        lantern_fork_choice_reset(&fork_choice);
        return 1;
    }
    if (head.slot != block2.slot || memcmp(head.root.bytes, block2_root.bytes, LANTERN_ROOT_SIZE) != 0) {
        fprintf(stderr, "unexpected head checkpoint in safe target test\n");
        lantern_block_body_reset(&block2.body);
        lantern_block_body_reset(&block1.body);
        lantern_state_reset(&state);
        lantern_fork_choice_reset(&fork_choice);
        return 1;
    }
    if (target.slot != block1.slot || memcmp(target.root.bytes, block1_root.bytes, LANTERN_ROOT_SIZE) != 0) {
        fprintf(stderr, "target checkpoint not aligned with safe target\n");
        lantern_block_body_reset(&block2.body);
        lantern_block_body_reset(&block1.body);
        lantern_state_reset(&state);
        lantern_fork_choice_reset(&fork_choice);
        return 1;
    }
    if (!checkpoints_equal(&source, &state.latest_justified)) {
        fprintf(stderr, "source checkpoint mismatch in safe target test\n");
        lantern_block_body_reset(&block2.body);
        lantern_block_body_reset(&block1.body);
        lantern_state_reset(&state);
        lantern_fork_choice_reset(&fork_choice);
        return 1;
    }

    lantern_block_body_reset(&block2.body);
    lantern_block_body_reset(&block1.body);
    lantern_state_reset(&state);
    lantern_fork_choice_reset(&fork_choice);
    return 0;
}

static int test_compute_vote_checkpoints_justifiable(void) {
    LanternState state;
    LanternForkChoice fork_choice;
    LanternRoot genesis_root;
    setup_state_and_fork_choice(&state, &fork_choice, 1700, 8, &genesis_root);

    LanternRoot parent_root = genesis_root;
    LanternRoot block_roots[8];
    block_roots[0] = genesis_root;
    for (uint64_t slot = 1; slot <= 7; ++slot) {
        LanternBlock block;
        LanternRoot block_root;
        make_block(&state, slot, &parent_root, &block, &block_root);
        expect_zero(
            lantern_fork_choice_add_block(&fork_choice, &block, NULL, NULL, NULL, &block_root),
            "add block for justifiable test");
        block_roots[slot] = block_root;
        parent_root = block_root;
        lantern_block_body_reset(&block.body);
    }

    fork_choice.head = block_roots[7];
    fork_choice.has_head = true;
    fork_choice.safe_target = block_roots[7];
    fork_choice.has_safe_target = true;

    state.latest_finalized.slot = 0;
    state.latest_finalized.root = genesis_root;
    state.latest_justified = state.latest_finalized;

    LanternCheckpoint head;
    LanternCheckpoint target;
    LanternCheckpoint source;
    int rc = lantern_state_compute_vote_checkpoints(&state, &head, &target, &source);
    if (rc != 0) {
        fprintf(stderr, "compute vote checkpoints justifiable failed (rc=%d)\n", rc);
        lantern_state_reset(&state);
        lantern_fork_choice_reset(&fork_choice);
        return 1;
    }
    if (head.slot != 7 || memcmp(head.root.bytes, block_roots[7].bytes, LANTERN_ROOT_SIZE) != 0) {
        fprintf(stderr, "unexpected head checkpoint in justifiable test\n");
        lantern_state_reset(&state);
        lantern_fork_choice_reset(&fork_choice);
        return 1;
    }
    if (target.slot != 6 || memcmp(target.root.bytes, block_roots[6].bytes, LANTERN_ROOT_SIZE) != 0) {
        fprintf(stderr, "target checkpoint not adjusted for justifiability\n");
        lantern_state_reset(&state);
        lantern_fork_choice_reset(&fork_choice);
        return 1;
    }
    if (!checkpoints_equal(&source, &state.latest_justified)) {
        fprintf(stderr, "source checkpoint mismatch in justifiable test\n");
        lantern_state_reset(&state);
        lantern_fork_choice_reset(&fork_choice);
        return 1;
    }

    lantern_state_reset(&state);
    lantern_fork_choice_reset(&fork_choice);
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
    if (test_collect_attestations_for_block() != 0) {
        return 1;
    }
    if (test_select_block_parent_uses_fork_choice() != 0) {
        return 1;
    }
    if (test_compute_vote_checkpoints_basic() != 0) {
        return 1;
    }
    if (test_compute_vote_checkpoints_respects_safe_target() != 0) {
        return 1;
    }
    if (test_compute_vote_checkpoints_justifiable() != 0) {
        return 1;
    }
    puts("lantern_state_test OK");
    return 0;
}
