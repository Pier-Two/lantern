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
    assert(lantern_fork_choice_add_block(
               &store,
               &block_one,
               NULL,
               NULL,
               &block_one_root)
        == 0);

    LanternBlock block_two;
    init_block(&block_two, 2, 1, &block_one_root, 0x32);
    LanternRoot block_two_root;
    assert(lantern_hash_tree_root_block(&block_two, &block_two_root) == 0);
    assert(lantern_fork_choice_add_block(
               &store,
               &block_two,
               NULL,
               NULL,
               &block_two_root)
        == 0);

    LanternCheckpoint block_one_cp = make_checkpoint(&block_one_root, block_one.slot);
    LanternSignedVote vote0;
    memset(&vote0, 0, sizeof(vote0));
    vote0.data.validator_id = 0;
    vote0.data.slot = block_one.slot;
    vote0.data.source = genesis_cp;
    vote0.data.target = block_one_cp;
    vote0.data.head = block_one_cp;

    assert(lantern_fork_choice_add_vote(&store, &vote0, false) == 0);

    LanternSignedVote vote1 = vote0;
    vote1.data.validator_id = 1;
    assert(lantern_fork_choice_add_vote(&store, &vote1, false) == 0);

    assert(lantern_fork_choice_accept_new_votes(&store) == 0);
    assert(lantern_fork_choice_current_head(&store, &head) == 0);
    assert(roots_equal(&head, &block_one_root));

    const LanternRoot *safe_initial = lantern_fork_choice_safe_target(&store);
    assert(safe_initial != NULL);

    LanternCheckpoint block_two_cp = make_checkpoint(&block_two_root, block_two.slot);
    LanternSignedVote vote2;
    memset(&vote2, 0, sizeof(vote2));
    vote2.data.validator_id = 0;
    vote2.data.slot = block_two.slot;
    vote2.data.source = genesis_cp;
    vote2.data.target = block_two_cp;
    vote2.data.head = block_two_cp;

    LanternSignedVote vote3 = vote2;
    vote3.data.validator_id = 1;

    LanternSignedVote vote4 = vote2;
    vote4.data.validator_id = 2;

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

int main(void) {
    if (test_fork_choice_vote_flow() != 0) {
        return 1;
    }
    return 0;
}
