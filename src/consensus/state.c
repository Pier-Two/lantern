#include "lantern/consensus/state.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "lantern/consensus/duties.h"
#include "lantern/consensus/hash.h"
#include "lantern/consensus/signature.h"

struct lantern_vote_record {
    LanternVote vote;
    bool has_vote;
};

struct lantern_checkpoint_tally {
    LanternCheckpoint checkpoint;
    struct lantern_bitlist voters;
    uint32_t count;
};

static size_t bitlist_required_bytes(size_t bit_length) {
    if (bit_length == 0) {
        return 0;
    }
    return (bit_length + 7) / 8;
}

static int ensure_root_capacity(struct lantern_root_list *list, size_t required) {
    if (!list) {
        return -1;
    }
    if (list->capacity >= required) {
        return 0;
    }
    size_t new_capacity = list->capacity == 0 ? 4 : list->capacity;
    while (new_capacity < required) {
        if (new_capacity > (SIZE_MAX / 2)) {
            return -1;
        }
        new_capacity *= 2;
    }
    LanternRoot *items = realloc(list->items, new_capacity * sizeof(*items));
    if (!items) {
        return -1;
    }
    list->items = items;
    list->capacity = new_capacity;
    return 0;
}

static int ensure_bit_capacity(struct lantern_bitlist *list, size_t required_bytes) {
    if (!list) {
        return -1;
    }
    if (list->capacity >= required_bytes) {
        return 0;
    }
    size_t new_capacity = list->capacity == 0 ? 4 : list->capacity;
    while (new_capacity < required_bytes) {
        if (new_capacity > (SIZE_MAX / 2)) {
            return -1;
        }
        new_capacity *= 2;
    }
    uint8_t *bytes = realloc(list->bytes, new_capacity * sizeof(*bytes));
    if (!bytes) {
        return -1;
    }
    list->bytes = bytes;
    list->capacity = new_capacity;
    return 0;
}

void lantern_root_list_init(struct lantern_root_list *list) {
    if (!list) {
        return;
    }
    list->items = NULL;
    list->length = 0;
    list->capacity = 0;
}

void lantern_root_list_reset(struct lantern_root_list *list) {
    if (!list) {
        return;
    }
    free(list->items);
    list->items = NULL;
    list->length = 0;
    list->capacity = 0;
}

int lantern_root_list_resize(struct lantern_root_list *list, size_t new_length) {
    if (!list) {
        return -1;
    }
    if (new_length == 0) {
        if (list->items && list->length > 0) {
            memset(list->items, 0, list->length * sizeof(*list->items));
        }
        list->length = 0;
        return 0;
    }
    if (ensure_root_capacity(list, new_length) != 0) {
        return -1;
    }
    size_t old_length = list->length;
    if (new_length > old_length) {
        size_t added = new_length - old_length;
        memset(&list->items[old_length], 0, added * sizeof(*list->items));
    } else if (new_length < old_length) {
        size_t removed = old_length - new_length;
        memset(&list->items[new_length], 0, removed * sizeof(*list->items));
    }
    list->length = new_length;
    return 0;
}

void lantern_bitlist_init(struct lantern_bitlist *list) {
    if (!list) {
        return;
    }
    list->bytes = NULL;
    list->bit_length = 0;
    list->capacity = 0;
}

void lantern_bitlist_reset(struct lantern_bitlist *list) {
    if (!list) {
        return;
    }
    free(list->bytes);
    list->bytes = NULL;
    list->bit_length = 0;
    list->capacity = 0;
}

int lantern_bitlist_resize(struct lantern_bitlist *list, size_t new_bit_length) {
    if (!list) {
        return -1;
    }
    if (new_bit_length == 0) {
        if (list->bytes && list->bit_length > 0) {
            size_t old_bytes = bitlist_required_bytes(list->bit_length);
            memset(list->bytes, 0, old_bytes);
        }
        list->bit_length = 0;
        return 0;
    }

    size_t required_bytes = bitlist_required_bytes(new_bit_length);
    if (ensure_bit_capacity(list, required_bytes) != 0) {
        return -1;
    }
    size_t old_bytes = bitlist_required_bytes(list->bit_length);
    if (required_bytes > old_bytes) {
        memset(list->bytes + old_bytes, 0, required_bytes - old_bytes);
    }

    if (new_bit_length < list->bit_length && required_bytes > 0) {
        size_t new_bytes = required_bytes;
        size_t start_bit = new_bit_length;
        size_t start_byte = start_bit / 8;
        size_t start_bit_offset = start_bit % 8;
        if (start_byte < new_bytes) {
            if (start_bit_offset > 0) {
                uint8_t mask = (uint8_t)((1u << start_bit_offset) - 1u);
                list->bytes[start_byte] &= mask;
                ++start_byte;
            }
            if (start_byte < new_bytes) {
                memset(list->bytes + start_byte, 0, new_bytes - start_byte);
            }
        }
    }

    list->bit_length = new_bit_length;
    return 0;
}

static bool lantern_root_is_zero(const LanternRoot *root) {
    if (!root) {
        return false;
    }
    for (size_t i = 0; i < LANTERN_ROOT_SIZE; ++i) {
        if (root->bytes[i] != 0) {
            return false;
        }
    }
    return true;
}

static int lantern_root_list_append(struct lantern_root_list *list, const LanternRoot *root) {
    if (!list || !root) {
        return -1;
    }
    if (lantern_root_list_resize(list, list->length + 1) != 0) {
        return -1;
    }
    list->items[list->length - 1] = *root;
    return 0;
}

static int lantern_bitlist_set_bit(struct lantern_bitlist *list, size_t index, bool value) {
    if (!list) {
        return -1;
    }
    size_t required_bytes = bitlist_required_bytes(index + 1);
    if (ensure_bit_capacity(list, required_bytes) != 0) {
        return -1;
    }
    if (!list->bytes) {
        return -1;
    }
    size_t byte_index = index / 8u;
    if (byte_index >= list->capacity) {
        return -1;
    }
    size_t bit_index = index % 8u;
    uint8_t mask = (uint8_t)(1u << bit_index);
    if (value) {
        list->bytes[byte_index] |= mask;
    } else {
        list->bytes[byte_index] &= (uint8_t)~mask;
    }
    if (index + 1 > list->bit_length) {
        list->bit_length = index + 1;
    }
    return 0;
}

static int lantern_bitlist_get_bit(const struct lantern_bitlist *list, size_t index, bool *out_value) {
    if (!list || !out_value) {
        return -1;
    }
    if (index >= list->bit_length) {
        return -1;
    }
    if (!list->bytes) {
        return -1;
    }
    size_t byte_index = index / 8u;
    size_t bit_index = index % 8u;
    uint8_t mask = (uint8_t)(1u << bit_index);
    *out_value = (list->bytes[byte_index] & mask) != 0;
    return 0;
}

static int lantern_bitlist_append(struct lantern_bitlist *list, bool value) {
    if (!list) {
        return -1;
    }
    size_t new_length = list->bit_length + 1;
    if (lantern_bitlist_resize(list, new_length) != 0) {
        return -1;
    }
    return lantern_bitlist_set_bit(list, new_length - 1, value);
}

static int lantern_bitlist_ensure_length(struct lantern_bitlist *list, size_t bit_length) {
    if (!list) {
        return -1;
    }
    if (bit_length <= list->bit_length) {
        return 0;
    }
    size_t original = list->bit_length;
    if (lantern_bitlist_resize(list, bit_length) != 0) {
        return -1;
    }
    for (size_t i = original; i < bit_length; ++i) {
        if (lantern_bitlist_set_bit(list, i, false) != 0) {
            return -1;
        }
    }
    return 0;
}

static void lantern_vote_record_reset(struct lantern_vote_record *record) {
    if (!record) {
        return;
    }
    memset(record, 0, sizeof(*record));
}

static bool lantern_checkpoint_equal(const LanternCheckpoint *a, const LanternCheckpoint *b) {
    if (!a || !b) {
        return false;
    }
    if (a->slot != b->slot) {
        return false;
    }
    return memcmp(a->root.bytes, b->root.bytes, LANTERN_ROOT_SIZE) == 0;
}

static bool lantern_votes_equal(const LanternVote *a, const LanternVote *b) {
    if (!a || !b) {
        return false;
    }
    if (a->validator_id != b->validator_id || a->slot != b->slot) {
        return false;
    }
    if (!lantern_checkpoint_equal(&a->head, &b->head)) {
        return false;
    }
    if (!lantern_checkpoint_equal(&a->target, &b->target)) {
        return false;
    }
    if (!lantern_checkpoint_equal(&a->source, &b->source)) {
        return false;
    }
    return true;
}

static size_t lantern_quorum_threshold(uint64_t validator_count) {
    if (validator_count == 0) {
        return 0;
    }
    uint64_t numerator = validator_count * 2u;
    uint64_t threshold = (numerator + 2u) / 3u;
    if (threshold > SIZE_MAX) {
        return SIZE_MAX;
    }
    return (size_t)threshold;
}

static void lantern_checkpoint_tally_init(struct lantern_checkpoint_tally *tally) {
    if (!tally) {
        return;
    }
    memset(&tally->checkpoint, 0, sizeof(tally->checkpoint));
    lantern_bitlist_init(&tally->voters);
    tally->count = 0;
}

static void lantern_checkpoint_tally_reset(struct lantern_checkpoint_tally *tally) {
    if (!tally) {
        return;
    }
    lantern_bitlist_reset(&tally->voters);
    memset(&tally->checkpoint, 0, sizeof(tally->checkpoint));
    tally->count = 0;
}

static int lantern_checkpoint_tally_prepare(struct lantern_checkpoint_tally *tally, uint64_t validator_count) {
    if (!tally) {
        return -1;
    }
    if (validator_count > SIZE_MAX) {
        return -1;
    }
    size_t required = (size_t)validator_count;
    if (lantern_bitlist_resize(&tally->voters, required) != 0) {
        return -1;
    }
    return 0;
}

static int lantern_state_allocate_validator_votes(LanternState *state, uint64_t validator_count) {
    if (!state || validator_count == 0) {
        return -1;
    }
    if (validator_count > SIZE_MAX) {
        return -1;
    }
    size_t count = (size_t)validator_count;
    struct lantern_vote_record *records = calloc(count, sizeof(*records));
    if (!records) {
        return -1;
    }
    state->validator_votes = records;
    state->validator_votes_len = count;
    return 0;
}

static void lantern_root_zero(LanternRoot *root) {
    if (root) {
        memset(root->bytes, 0, LANTERN_ROOT_SIZE);
    }
}

void lantern_state_init(LanternState *state) {
    if (!state) {
        return;
    }
    memset(state, 0, sizeof(*state));
    lantern_root_list_init(&state->historical_block_hashes);
    lantern_bitlist_init(&state->justified_slots);
    lantern_root_list_init(&state->justification_roots);
    lantern_bitlist_init(&state->justification_validators);
}

void lantern_state_reset(LanternState *state) {
    if (!state) {
        return;
    }
    lantern_root_list_reset(&state->historical_block_hashes);
    lantern_bitlist_reset(&state->justified_slots);
    lantern_root_list_reset(&state->justification_roots);
    lantern_bitlist_reset(&state->justification_validators);
    if (state->validator_votes) {
        free(state->validator_votes);
        state->validator_votes = NULL;
        state->validator_votes_len = 0;
    }
    if (state->justification_tallies) {
        for (size_t i = 0; i < state->justification_tally_len; ++i) {
            lantern_checkpoint_tally_reset(&state->justification_tallies[i]);
        }
        free(state->justification_tallies);
        state->justification_tallies = NULL;
        state->justification_tally_len = 0;
        state->justification_tally_capacity = 0;
    }
    memset(state, 0, sizeof(*state));
    lantern_root_list_init(&state->historical_block_hashes);
    lantern_bitlist_init(&state->justified_slots);
    lantern_root_list_init(&state->justification_roots);
    lantern_bitlist_init(&state->justification_validators);
}

int lantern_state_generate_genesis(LanternState *state, uint64_t genesis_time, uint64_t num_validators) {
    if (!state || num_validators == 0) {
        return -1;
    }
    lantern_state_reset(state);
    if (lantern_state_allocate_validator_votes(state, num_validators) != 0) {
        lantern_state_reset(state);
        return -1;
    }
    state->config.num_validators = num_validators;
    state->config.genesis_time = genesis_time;
    state->slot = 0;

    lantern_root_zero(&state->latest_block_header.parent_root);
    lantern_root_zero(&state->latest_block_header.state_root);
    state->latest_block_header.slot = 0;
    state->latest_block_header.proposer_index = 0;

    LanternBlockBody empty_body;
    lantern_block_body_init(&empty_body);
    LanternRoot body_root;
    if (lantern_hash_tree_root_block_body(&empty_body, &body_root) != 0) {
        lantern_block_body_reset(&empty_body);
        lantern_state_reset(state);
        return -1;
    }
    state->latest_block_header.body_root = body_root;
    lantern_block_body_reset(&empty_body);

    LanternRoot genesis_header_root;
    if (lantern_hash_tree_root_block_header(&state->latest_block_header, &genesis_header_root) != 0) {
        lantern_state_reset(state);
        return -1;
    }
    state->latest_justified.root = genesis_header_root;
    state->latest_justified.slot = 0;
    state->latest_finalized.root = genesis_header_root;
    state->latest_finalized.slot = 0;

    if (lantern_bitlist_resize(&state->justified_slots, 1) != 0) {
        lantern_state_reset(state);
        return -1;
    }
    if (lantern_bitlist_set_bit(&state->justified_slots, 0, true) != 0) {
        lantern_state_reset(state);
        return -1;
    }

    return 0;
}

int lantern_state_process_slot(LanternState *state) {
    if (!state) {
        return -1;
    }
    if (lantern_root_is_zero(&state->latest_block_header.state_root)) {
        LanternRoot computed;
        if (lantern_hash_tree_root_state(state, &computed) != 0) {
            return -1;
        }
        state->latest_block_header.state_root = computed;
    }
    return 0;
}

int lantern_state_process_slots(LanternState *state, uint64_t target_slot) {
    if (!state) {
        return -1;
    }
    if (target_slot <= state->slot) {
        return -1;
    }
    while (state->slot < target_slot) {
        if (lantern_state_process_slot(state) != 0) {
            return -1;
        }
        if (state->slot == UINT64_MAX) {
            return -1;
        }
        state->slot += 1;
    }
    return 0;
}

static struct lantern_checkpoint_tally *lantern_state_find_or_create_tally(
    LanternState *state,
    const LanternCheckpoint *checkpoint) {
    if (!state || !checkpoint) {
        return NULL;
    }
    for (size_t i = 0; i < state->justification_tally_len; ++i) {
        struct lantern_checkpoint_tally *candidate = &state->justification_tallies[i];
        if (lantern_checkpoint_equal(&candidate->checkpoint, checkpoint)) {
            return candidate;
        }
    }
    if (state->justification_tally_len == state->justification_tally_capacity) {
        size_t new_capacity = state->justification_tally_capacity == 0 ? 4u : state->justification_tally_capacity * 2u;
        size_t element_size = sizeof(struct lantern_checkpoint_tally);
        if (new_capacity == 0 || new_capacity > SIZE_MAX / element_size) {
            return NULL;
        }
        struct lantern_checkpoint_tally *expanded = realloc(
            state->justification_tallies,
            new_capacity * element_size);
        if (!expanded) {
            return NULL;
        }
        state->justification_tallies = expanded;
        state->justification_tally_capacity = new_capacity;
    }
    struct lantern_checkpoint_tally *tally = &state->justification_tallies[state->justification_tally_len++];
    lantern_checkpoint_tally_init(tally);
    if (lantern_checkpoint_tally_prepare(tally, state->config.num_validators) != 0) {
        lantern_checkpoint_tally_reset(tally);
        state->justification_tally_len -= 1;
        return NULL;
    }
    tally->checkpoint = *checkpoint;
    return tally;
}

static void lantern_state_prune_tallies(LanternState *state, uint64_t finalized_slot) {
    if (!state || !state->justification_tallies) {
        return;
    }
    size_t write = 0;
    size_t original_len = state->justification_tally_len;
    for (size_t i = 0; i < original_len; ++i) {
        struct lantern_checkpoint_tally *current = &state->justification_tallies[i];
        if (current->checkpoint.slot <= finalized_slot) {
            lantern_checkpoint_tally_reset(current);
            continue;
        }
        if (write != i) {
            state->justification_tallies[write] = *current;
            memset(current, 0, sizeof(*current));
        }
        ++write;
    }
    if (write < original_len) {
        for (size_t j = write; j < original_len; ++j) {
            lantern_checkpoint_tally_reset(&state->justification_tallies[j]);
        }
    }
    state->justification_tally_len = write;
}

static int lantern_state_mark_justified_slot(LanternState *state, uint64_t slot) {
    if (!state) {
        return -1;
    }
    if (slot > SIZE_MAX) {
        return -1;
    }
    size_t index = (size_t)slot;
    if (lantern_bitlist_ensure_length(&state->justified_slots, index + 1) != 0) {
        return -1;
    }
    return lantern_bitlist_set_bit(&state->justified_slots, index, true);
}

static bool lantern_signature_is_zeroed(const LanternSignature *signature) {
    if (!signature) {
        return false;
    }
    return lantern_signature_is_zero(signature);
}

int lantern_state_process_block_header(LanternState *state, const LanternBlock *block) {
    if (!state || !block) {
        return -1;
    }
    if (block->slot != state->slot) {
        return -1;
    }
    if (block->slot <= state->latest_block_header.slot) {
        return -1;
    }
    uint64_t expected_proposer = 0;
    if (lantern_proposer_for_slot(block->slot, state->config.num_validators, &expected_proposer) != 0) {
        return -1;
    }
    if (block->proposer_index != expected_proposer) {
        return -1;
    }

    LanternRoot latest_header_root;
    if (lantern_hash_tree_root_block_header(&state->latest_block_header, &latest_header_root) != 0) {
        return -1;
    }
    if (memcmp(block->parent_root.bytes, latest_header_root.bytes, LANTERN_ROOT_SIZE) != 0) {
        return -1;
    }

    if (state->latest_block_header.slot == 0) {
        state->latest_justified.root = latest_header_root;
        state->latest_finalized.root = latest_header_root;
    }

    if (lantern_root_list_append(&state->historical_block_hashes, &latest_header_root) != 0) {
        return -1;
    }
    if (lantern_bitlist_append(&state->justified_slots, state->latest_block_header.slot == 0) != 0) {
        return -1;
    }

    uint64_t parent_slot = state->latest_block_header.slot;
    uint64_t delta = block->slot - parent_slot;
    if (delta > 1) {
        LanternRoot zero_root;
        lantern_root_zero(&zero_root);
        for (uint64_t i = 0; i < delta - 1; ++i) {
            if (lantern_root_list_append(&state->historical_block_hashes, &zero_root) != 0) {
                return -1;
            }
            if (lantern_bitlist_append(&state->justified_slots, false) != 0) {
                return -1;
            }
        }
    }

    LanternRoot body_root;
    if (lantern_hash_tree_root_block_body(&block->body, &body_root) != 0) {
        return -1;
    }
    state->latest_block_header.slot = block->slot;
    state->latest_block_header.proposer_index = block->proposer_index;
    state->latest_block_header.parent_root = block->parent_root;
    state->latest_block_header.body_root = body_root;
    lantern_root_zero(&state->latest_block_header.state_root);

    return 0;
}

int lantern_state_process_attestations(LanternState *state, const LanternAttestations *attestations) {
    if (!state || !attestations) {
        return -1;
    }
    uint64_t validator_count = state->config.num_validators;
    if (validator_count == 0 || validator_count > SIZE_MAX) {
        return -1;
    }
    if (!state->validator_votes || state->validator_votes_len != (size_t)validator_count) {
        return -1;
    }

    LanternCheckpoint latest_justified = state->latest_justified;
    LanternCheckpoint latest_finalized = state->latest_finalized;
    size_t quorum = lantern_quorum_threshold(validator_count);

    for (size_t i = 0; i < attestations->length; ++i) {
        const LanternSignedVote *signed_vote = &attestations->data[i];
        if (!lantern_signature_is_zeroed(&signed_vote->signature)) {
            continue;
        }
        const LanternVote *vote = &signed_vote->data;
        if (vote->validator_id >= validator_count) {
            return -1;
        }
        if (vote->target.slot <= vote->source.slot) {
            continue;
        }
        if (!lantern_checkpoint_equal(&vote->source, &latest_justified)) {
            continue;
        }

        struct lantern_vote_record *record = &state->validator_votes[vote->validator_id];
        if (record->has_vote) {
            if (vote->slot < record->vote.slot) {
                continue;
            }
            if (vote->slot == record->vote.slot) {
                if (lantern_votes_equal(&record->vote, vote)) {
                    continue;
                }
                return -1;
            }
        }

        bool target_is_justified = false;
        if (vote->target.slot < state->justified_slots.bit_length) {
            if (lantern_bitlist_get_bit(&state->justified_slots, (size_t)vote->target.slot, &target_is_justified) != 0) {
                return -1;
            }
        }
        if (target_is_justified) {
            record->vote = *vote;
            record->has_vote = true;
            continue;
        }

        struct lantern_checkpoint_tally *tally = lantern_state_find_or_create_tally(state, &vote->target);
        if (!tally) {
            return -1;
        }
        size_t validator_index = (size_t)vote->validator_id;
        bool already_voted = false;
        if (lantern_bitlist_get_bit(&tally->voters, validator_index, &already_voted) != 0) {
            return -1;
        }
        if (already_voted) {
            record->vote = *vote;
            record->has_vote = true;
            continue;
        }
        if (lantern_bitlist_set_bit(&tally->voters, validator_index, true) != 0) {
            return -1;
        }
        if (tally->count < UINT32_MAX) {
            tally->count += 1;
        }
        record->vote = *vote;
        record->has_vote = true;

        if (tally->count >= quorum) {
            bool is_new = !lantern_checkpoint_equal(&latest_justified, &vote->target);
            if (is_new || vote->target.slot > latest_justified.slot) {
                latest_justified = vote->target;
                if (vote->target.slot == vote->source.slot + 1 && vote->source.slot >= latest_finalized.slot) {
                    latest_finalized = vote->source;
                }
            }
        }
    }

    if (lantern_state_mark_justified_slot(state, latest_justified.slot) != 0) {
        return -1;
    }
    if (lantern_state_mark_justified_slot(state, latest_finalized.slot) != 0) {
        return -1;
    }

    state->latest_justified = latest_justified;
    state->latest_finalized = latest_finalized;
    lantern_state_prune_tallies(state, latest_finalized.slot);
    return 0;
}

int lantern_state_process_block(LanternState *state, const LanternBlock *block) {
    if (!state || !block) {
        return -1;
    }
    if (lantern_state_process_block_header(state, block) != 0) {
        return -1;
    }
    if (lantern_state_process_attestations(state, &block->body.attestations) != 0) {
        return -1;
    }
    return 0;
}

int lantern_state_transition(LanternState *state, const LanternSignedBlock *signed_block) {
    if (!state || !signed_block) {
        return -1;
    }
    if (!lantern_signature_is_zeroed(&signed_block->signature)) {
        return -1;
    }
    const LanternBlock *block = &signed_block->message;
    if (block->slot <= state->slot) {
        return -1;
    }
    if (lantern_state_process_slots(state, block->slot) != 0) {
        return -1;
    }
    if (lantern_state_process_block(state, block) != 0) {
        return -1;
    }
    LanternRoot computed_state_root;
    if (lantern_hash_tree_root_state(state, &computed_state_root) != 0) {
        return -1;
    }
    if (memcmp(block->state_root.bytes, computed_state_root.bytes, LANTERN_ROOT_SIZE) != 0) {
        return -1;
    }
    return 0;
}
