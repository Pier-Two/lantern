#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "lantern/consensus/fork_choice.h"
#include "lantern/consensus/hash.h"
#include "lantern/consensus/state.h"

static void zero_root(LanternRoot *root) {
    if (!root) {
        return;
    }
    memset(root->bytes, 0, sizeof(root->bytes));
}

static void fill_root(LanternRoot *root, uint8_t value) {
    if (!root) {
        return;
    }
    memset(root->bytes, value, sizeof(root->bytes));
}

static bool roots_equal(const LanternRoot *a, const LanternRoot *b) {
    if (!a || !b) {
        return false;
    }
    return memcmp(a->bytes, b->bytes, sizeof(a->bytes)) == 0;
}

static void init_block(
    LanternBlock *block,
    uint64_t slot,
    uint64_t proposer_index,
    const LanternRoot *parent_root,
    uint8_t state_marker) {
    memset(block, 0, sizeof(*block));
    block->slot = slot;
    block->proposer_index = proposer_index;
    if (parent_root) {
        block->parent_root = *parent_root;
    } else {
        zero_root(&block->parent_root);
    }
    fill_root(&block->state_root, state_marker);
    lantern_block_body_init(&block->body);
}

static void reset_block(LanternBlock *block) {
    if (!block) {
        return;
    }
    lantern_block_body_reset(&block->body);
}

static LanternCheckpoint make_checkpoint(const LanternRoot *root, uint64_t slot) {
    LanternCheckpoint cp;
    cp.root = *root;
    cp.slot = slot;
    return cp;
}

static LanternSignedVote make_vote(
    uint64_t validator_id,
    const LanternCheckpoint *source,
    const LanternCheckpoint *target) {
    LanternSignedVote vote;
    memset(&vote, 0, sizeof(vote));
    vote.data.validator_id = validator_id;
    vote.data.slot = target ? target->slot : 0;
    if (source) {
        vote.data.source = *source;
    } else {
        zero_root(&vote.data.source.root);
        vote.data.source.slot = 0;
    }
    if (target) {
        vote.data.target = *target;
        vote.data.head = *target;
    } else {
        zero_root(&vote.data.target.root);
        vote.data.target.slot = 0;
        zero_root(&vote.data.head.root);
        vote.data.head.slot = 0;
    }
    return vote;
}

static int test_fork_choice_vote_flow(void) {
    LanternForkChoice store;
    lantern_fork_choice_init(&store);

    LanternConfig config = {.num_validators = 4, .genesis_time = 1};
    assert(lantern_fork_choice_configure(&store, &config) == 0);

    LanternBlock genesis;
    init_block(&genesis, 0, 0, NULL, 0x10);
    LanternRoot genesis_root;
    assert(lantern_hash_tree_root_block(&genesis, &genesis_root) == 0);
    LanternCheckpoint genesis_cp = make_checkpoint(&genesis_root, genesis.slot);
    assert(lantern_fork_choice_set_anchor(&store, &genesis, &genesis_cp, &genesis_cp, &genesis_root) == 0);

    LanternRoot head;
    assert(lantern_fork_choice_current_head(&store, &head) == 0);
    assert(roots_equal(&head, &genesis_root));

    LanternBlock block_one;
    init_block(&block_one, 1, 0, &genesis_root, 0x21);
    LanternRoot block_one_root;
    assert(lantern_hash_tree_root_block(&block_one, &block_one_root) == 0);
    assert(
        lantern_fork_choice_add_block(
            &store,
            &block_one,
            NULL,
            NULL,
            NULL,
            &block_one_root)
        == 0);

    LanternBlock block_two;
    init_block(&block_two, 2, 1, &block_one_root, 0x32);
    LanternRoot block_two_root;
    assert(lantern_hash_tree_root_block(&block_two, &block_two_root) == 0);
    assert(
        lantern_fork_choice_add_block(
            &store,
            &block_two,
            NULL,
            NULL,
            NULL,
            &block_two_root)
        == 0);

    LanternCheckpoint block_one_cp = make_checkpoint(&block_one_root, block_one.slot);
    LanternSignedVote vote0 = make_vote(0, &genesis_cp, &block_one_cp);

    assert(lantern_fork_choice_add_vote(&store, &vote0, false) == 0);

    LanternSignedVote vote1 = make_vote(1, &genesis_cp, &block_one_cp);
    assert(lantern_fork_choice_add_vote(&store, &vote1, false) == 0);

    assert(lantern_fork_choice_accept_new_votes(&store) == 0);
    assert(lantern_fork_choice_current_head(&store, &head) == 0);
    assert(roots_equal(&head, &block_one_root));

    const LanternRoot *safe_initial = lantern_fork_choice_safe_target(&store);
    assert(safe_initial != NULL);

    LanternCheckpoint block_two_cp = make_checkpoint(&block_two_root, block_two.slot);
    LanternSignedVote vote2 = make_vote(0, &genesis_cp, &block_two_cp);
    LanternSignedVote vote3 = make_vote(1, &genesis_cp, &block_two_cp);
    LanternSignedVote vote4 = make_vote(2, &genesis_cp, &block_two_cp);

    assert(lantern_fork_choice_add_vote(&store, &vote2, false) == 0);
    assert(lantern_fork_choice_add_vote(&store, &vote3, false) == 0);

    assert(lantern_fork_choice_update_safe_target(&store) == 0);
    const LanternRoot *safe_after_two = lantern_fork_choice_safe_target(&store);
    assert(safe_after_two != NULL);
    assert(roots_equal(safe_initial, safe_after_two));

    assert(lantern_fork_choice_add_vote(&store, &vote4, false) == 0);
    assert(lantern_fork_choice_update_safe_target(&store) == 0);
    const LanternRoot *safe_after_three = lantern_fork_choice_safe_target(&store);
    assert(safe_after_three != NULL);
    assert(roots_equal(safe_after_three, &block_two_root));

    assert(lantern_fork_choice_accept_new_votes(&store) == 0);
    assert(lantern_fork_choice_current_head(&store, &head) == 0);
    assert(roots_equal(&head, &block_two_root));

    lantern_fork_choice_reset(&store);
    reset_block(&block_two);
    reset_block(&block_one);
    reset_block(&genesis);
    return 0;
}

static int test_fork_choice_checkpoint_progression(void) {
    LanternForkChoice store;
    lantern_fork_choice_init(&store);

    LanternConfig config = {.num_validators = 4, .genesis_time = 1};
    assert(lantern_fork_choice_configure(&store, &config) == 0);

    LanternBlock genesis;
    init_block(&genesis, 0, 0, NULL, 0x10);
    LanternRoot genesis_root;
    assert(lantern_hash_tree_root_block(&genesis, &genesis_root) == 0);
    LanternCheckpoint genesis_cp = make_checkpoint(&genesis_root, genesis.slot);
    assert(lantern_fork_choice_set_anchor(&store, &genesis, &genesis_cp, &genesis_cp, &genesis_root) == 0);

    const LanternCheckpoint *initial_justified = lantern_fork_choice_latest_justified(&store);
    const LanternCheckpoint *initial_finalized = lantern_fork_choice_latest_finalized(&store);
    assert(initial_justified && roots_equal(&initial_justified->root, &genesis_root));
    assert(initial_finalized && roots_equal(&initial_finalized->root, &genesis_root));

    LanternBlock block_one;
    init_block(&block_one, 1, 0, &genesis_root, 0x21);
    LanternRoot block_one_root;
    assert(lantern_hash_tree_root_block(&block_one, &block_one_root) == 0);
    LanternCheckpoint block_one_cp = make_checkpoint(&block_one_root, block_one.slot);
    assert(
        lantern_fork_choice_add_block(
            &store,
            &block_one,
            NULL,
            NULL,
            NULL,
            &block_one_root)
        == 0);

    assert(lantern_fork_choice_update_checkpoints(&store, &block_one_cp, NULL) == 0);
    const LanternCheckpoint *latest_justified = lantern_fork_choice_latest_justified(&store);
    assert(latest_justified);
    assert(latest_justified->slot == block_one.slot);
    assert(roots_equal(&latest_justified->root, &block_one_root));

    const LanternCheckpoint *latest_finalized = lantern_fork_choice_latest_finalized(&store);
    assert(latest_finalized);
    assert(latest_finalized->slot == genesis.slot);
    assert(roots_equal(&latest_finalized->root, &genesis_root));

    /* Regressing to older checkpoints must not overwrite progress */
    assert(lantern_fork_choice_update_checkpoints(&store, &genesis_cp, &genesis_cp) == 0);
    latest_justified = lantern_fork_choice_latest_justified(&store);
    assert(latest_justified->slot == block_one.slot);
    assert(roots_equal(&latest_justified->root, &block_one_root));

    assert(lantern_fork_choice_update_checkpoints(&store, &block_one_cp, &block_one_cp) == 0);
    latest_finalized = lantern_fork_choice_latest_finalized(&store);
    assert(latest_finalized);
    assert(latest_finalized->slot == block_one.slot);
    assert(roots_equal(&latest_finalized->root, &block_one_root));

    LanternRoot head;
    assert(lantern_fork_choice_recompute_head(&store) == 0);
    assert(lantern_fork_choice_current_head(&store, &head) == 0);
    assert(roots_equal(&head, &block_one_root));

    lantern_fork_choice_reset(&store);
    reset_block(&block_one);
    reset_block(&genesis);
    return 0;
}

static int test_fork_choice_advance_time_schedules_votes(void) {
    LanternForkChoice store;
    lantern_fork_choice_init(&store);

    LanternConfig config = {.num_validators = 4, .genesis_time = 1};
    assert(lantern_fork_choice_configure(&store, &config) == 0);

    LanternBlock genesis;
    init_block(&genesis, 0, 0, NULL, 0x01);
    LanternRoot genesis_root;
    assert(lantern_hash_tree_root_block(&genesis, &genesis_root) == 0);
    LanternCheckpoint genesis_cp = make_checkpoint(&genesis_root, genesis.slot);
    assert(lantern_fork_choice_set_anchor(&store, &genesis, &genesis_cp, &genesis_cp, &genesis_root) == 0);

    LanternBlock block_voted;
    init_block(&block_voted, 1, 0, &genesis_root, 0x11);
    LanternRoot block_voted_root;
    assert(lantern_hash_tree_root_block(&block_voted, &block_voted_root) == 0);
    LanternCheckpoint block_voted_cp = make_checkpoint(&block_voted_root, block_voted.slot);
    assert(
        lantern_fork_choice_add_block(
            &store,
            &block_voted,
            NULL,
            NULL,
            NULL,
            &block_voted_root)
        == 0);

    LanternBlock block_competing;
    init_block(&block_competing, 2, 1, &genesis_root, 0x22);
    LanternRoot block_competing_root;
    assert(lantern_hash_tree_root_block(&block_competing, &block_competing_root) == 0);
    assert(
        lantern_fork_choice_add_block(
            &store,
            &block_competing,
            NULL,
            NULL,
            NULL,
            &block_competing_root)
        == 0);

    LanternRoot head;
    assert(lantern_fork_choice_current_head(&store, &head) == 0);
    assert(roots_equal(&head, &block_competing_root));

    LanternSignedVote vote0 = make_vote(0, &genesis_cp, &block_voted_cp);
    LanternSignedVote vote1 = make_vote(1, &genesis_cp, &block_voted_cp);
    LanternSignedVote vote2 = make_vote(2, &genesis_cp, &block_voted_cp);
    assert(lantern_fork_choice_add_vote(&store, &vote0, false) == 0);
    assert(lantern_fork_choice_add_vote(&store, &vote1, false) == 0);
    assert(lantern_fork_choice_add_vote(&store, &vote2, false) == 0);

    const LanternRoot *safe_initial = lantern_fork_choice_safe_target(&store);
    assert(safe_initial && roots_equal(safe_initial, &genesis_root));

    uint64_t genesis_time = config.genesis_time;
    assert(lantern_fork_choice_advance_time(&store, genesis_time + 2, false) == 0);
    const LanternRoot *safe_after = lantern_fork_choice_safe_target(&store);
    assert(safe_after && roots_equal(safe_after, &block_voted_root));

    assert(lantern_fork_choice_current_head(&store, &head) == 0);
    assert(roots_equal(&head, &block_competing_root));

    assert(lantern_fork_choice_advance_time(&store, genesis_time + 3, false) == 0);
    assert(lantern_fork_choice_current_head(&store, &head) == 0);
    assert(roots_equal(&head, &block_voted_root));

    const LanternRoot *safe_final = lantern_fork_choice_safe_target(&store);
    assert(safe_final && roots_equal(safe_final, &block_voted_root));

    lantern_fork_choice_reset(&store);
    reset_block(&block_competing);
    reset_block(&block_voted);
    reset_block(&genesis);
    return 0;
}

int main(void) {
    if (test_fork_choice_vote_flow() != 0) {
        return 1;
    }
    if (test_fork_choice_checkpoint_progression() != 0) {
        return 1;
    }
    if (test_fork_choice_advance_time_schedules_votes() != 0) {
        return 1;
    }
    return 0;
}
