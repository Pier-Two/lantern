#ifndef LANTERN_CONSENSUS_STATE_H
#define LANTERN_CONSENSUS_STATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "lantern/consensus/containers.h"

struct lantern_vote_record;
struct lantern_checkpoint_tally;
struct lantern_fork_choice;

struct lantern_root_list {
    LanternRoot *items;
    size_t length;
    size_t capacity;
};

struct lantern_bitlist {
    uint8_t *bytes;
    size_t bit_length;
    size_t capacity;
};

typedef struct {
    LanternConfig config;
    uint64_t slot;
    LanternBlockHeader latest_block_header;
    LanternCheckpoint latest_justified;
    LanternCheckpoint latest_finalized;
    struct lantern_root_list historical_block_hashes;
    struct lantern_bitlist justified_slots;
    LanternRoot validators_root;
    struct lantern_root_list justification_roots;
    struct lantern_bitlist justification_validators;
    struct lantern_vote_record *validator_votes;
    size_t validator_votes_len;
    struct lantern_checkpoint_tally *justification_tallies;
    size_t justification_tally_len;
    size_t justification_tally_capacity;
    struct lantern_fork_choice *fork_choice;
} LanternState;

void lantern_root_list_init(struct lantern_root_list *list);
void lantern_root_list_reset(struct lantern_root_list *list);
int lantern_root_list_resize(struct lantern_root_list *list, size_t new_length);

void lantern_bitlist_init(struct lantern_bitlist *list);
void lantern_bitlist_reset(struct lantern_bitlist *list);
int lantern_bitlist_resize(struct lantern_bitlist *list, size_t new_bit_length);

void lantern_state_init(LanternState *state);
void lantern_state_reset(LanternState *state);
void lantern_state_attach_fork_choice(LanternState *state, struct lantern_fork_choice *fork_choice);
int lantern_state_generate_genesis(LanternState *state, uint64_t genesis_time, uint64_t num_validators);
int lantern_state_process_slot(LanternState *state);
int lantern_state_process_slots(LanternState *state, uint64_t target_slot);
int lantern_state_process_block_header(LanternState *state, const LanternBlock *block);
int lantern_state_process_attestations(LanternState *state, const LanternAttestations *attestations);
int lantern_state_process_block(LanternState *state, const LanternBlock *block);
int lantern_state_transition(LanternState *state, const LanternSignedBlock *signed_block);
int lantern_state_prepare_validator_votes(LanternState *state, uint64_t validator_count);
size_t lantern_state_validator_capacity(const LanternState *state);
bool lantern_state_validator_has_vote(const LanternState *state, size_t index);
int lantern_state_get_validator_vote(const LanternState *state, size_t index, LanternVote *out_vote);
int lantern_state_set_validator_vote(LanternState *state, size_t index, const LanternVote *vote);
void lantern_state_clear_validator_vote(LanternState *state, size_t index);
int lantern_state_select_block_parent(const LanternState *state, LanternRoot *out_parent_root);
int lantern_state_collect_attestations_for_block(
    const LanternState *state,
    LanternAttestations *out_attestations);
int lantern_state_compute_vote_checkpoints(
    const LanternState *state,
    LanternCheckpoint *out_head,
    LanternCheckpoint *out_target,
    LanternCheckpoint *out_source);

#endif /* LANTERN_CONSENSUS_STATE_H */
