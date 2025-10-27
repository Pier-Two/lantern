#include "lantern/consensus/state.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "lantern/consensus/duties.h"
#include "lantern/consensus/hash.h"
#include "lantern/consensus/signature.h"

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

    lantern_root_zero(&state->latest_justified.root);
    state->latest_justified.slot = 0;
    lantern_root_zero(&state->latest_finalized.root);
    state->latest_finalized.slot = 0;

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

    LanternCheckpoint latest_justified = state->latest_justified;
    LanternCheckpoint latest_finalized = state->latest_finalized;

    for (size_t i = 0; i < attestations->length; ++i) {
        const LanternSignedVote *signed_vote = &attestations->data[i];
        if (!lantern_signature_is_zeroed(&signed_vote->signature)) {
            continue;
        }
        const LanternVote *vote = &signed_vote->data;
        if (vote->target.slot <= vote->source.slot) {
            continue;
        }
        if (vote->source.slot > SIZE_MAX || vote->target.slot > SIZE_MAX) {
            continue;
        }
        size_t source_index = (size_t)vote->source.slot;
        size_t target_index = (size_t)vote->target.slot;
        bool source_is_justified = false;
        if (lantern_bitlist_get_bit(&state->justified_slots, source_index, &source_is_justified) != 0 || !source_is_justified) {
            continue;
        }

        bool target_already_justified = false;
        if (target_index < state->justified_slots.bit_length) {
            if (lantern_bitlist_get_bit(&state->justified_slots, target_index, &target_already_justified) != 0) {
                target_already_justified = false;
            }
        }

        if (target_already_justified) {
            if (vote->target.slot == vote->source.slot + 1 && latest_justified.slot < vote->target.slot) {
                latest_finalized = vote->source;
                latest_justified = vote->target;
            }
            continue;
        }

        if (lantern_bitlist_ensure_length(&state->justified_slots, target_index + 1) != 0) {
            return -1;
        }
        if (lantern_bitlist_set_bit(&state->justified_slots, target_index, true) != 0) {
            return -1;
        }
        if (vote->target.slot > latest_justified.slot) {
            latest_justified = vote->target;
        }
    }

    state->latest_justified = latest_justified;
    state->latest_finalized = latest_finalized;
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
