#ifndef LANTERN_CONSENSUS_STATE_H
#define LANTERN_CONSENSUS_STATE_H

#include <stddef.h>
#include <stdint.h>

#include "lantern/consensus/containers.h"

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
    struct lantern_root_list justification_roots;
    struct lantern_bitlist justification_validators;
} LanternState;

void lantern_root_list_init(struct lantern_root_list *list);
void lantern_root_list_reset(struct lantern_root_list *list);
int lantern_root_list_resize(struct lantern_root_list *list, size_t new_length);

void lantern_bitlist_init(struct lantern_bitlist *list);
void lantern_bitlist_reset(struct lantern_bitlist *list);
int lantern_bitlist_resize(struct lantern_bitlist *list, size_t new_bit_length);

void lantern_state_init(LanternState *state);
void lantern_state_reset(LanternState *state);
int lantern_state_generate_genesis(LanternState *state, uint64_t genesis_time, uint64_t num_validators);
int lantern_state_process_slot(LanternState *state);
int lantern_state_process_slots(LanternState *state, uint64_t target_slot);
int lantern_state_process_block_header(LanternState *state, const LanternBlock *block);
int lantern_state_process_attestations(LanternState *state, const LanternAttestations *attestations);
int lantern_state_process_block(LanternState *state, const LanternBlock *block);
int lantern_state_transition(LanternState *state, const LanternSignedBlock *signed_block);

#endif /* LANTERN_CONSENSUS_STATE_H */
