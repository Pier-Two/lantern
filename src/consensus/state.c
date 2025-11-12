#include "lantern/consensus/state.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "lantern/support/log.h"
#include "lantern/support/strings.h"
#include "lantern/support/time.h"
#include "lantern/metrics/lean_metrics.h"

#include "lantern/consensus/duties.h"
#include "lantern/consensus/fork_choice.h"
#include "lantern/consensus/hash.h"
#include "lantern/consensus/signature.h"

struct lantern_vote_record {
    LanternVote vote;
    bool has_vote;
};

struct state_profile_metric {
    double seconds;
    size_t calls;
};

static bool state_profile_enabled(void) {
    static bool initialized = false;
    static bool enabled = false;
    if (!initialized) {
        const char *env = getenv("LANTERN_PROFILE_CONSENSUS_VECTORS");
        enabled = env && env[0] != '\0' && env[0] != '0';
        initialized = true;
    }
    return enabled;
}

static double state_profile_now(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}

static void state_profile_record(struct state_profile_metric *metric, double delta) {
    if (!metric) {
        return;
    }
    metric->seconds += delta;
    metric->calls += 1;
}

static void record_attestation_validation_metric(double start_seconds, bool valid) {
    lean_metrics_record_attestation_validation(lantern_time_now_seconds() - start_seconds, valid);
}

static struct state_profile_metric g_profile_process_slots;
static struct state_profile_metric g_profile_process_block;
static struct state_profile_metric g_profile_state_root;
static size_t g_profile_max_justification_bits = 0;

static int lantern_state_mark_justified_slot(LanternState *state, uint64_t slot);

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

static uint64_t lantern_u64_isqrt(uint64_t value) {
    uint64_t result = 0;
    uint64_t bit = 1ull << 62;
    while (bit > value) {
        bit >>= 2;
    }
    while (bit != 0) {
        if (value >= result + bit) {
            value -= result + bit;
            result = (result >> 1) + bit;
        } else {
            result >>= 1;
        }
        bit >>= 2;
    }
    return result;
}

static bool lantern_is_pronic(uint64_t delta) {
    if (delta == 0) {
        return true;
    }
    uint64_t root = lantern_u64_isqrt(delta);
    uint64_t candidates[3];
    size_t count = 0;
    if (root > 0) {
        candidates[count++] = root - 1;
    }
    candidates[count++] = root;
    if (root < UINT64_MAX) {
        candidates[count++] = root + 1;
    }
    for (size_t i = 0; i < count; ++i) {
        uint64_t a = candidates[i];
        if (a == UINT64_MAX) {
            continue;
        }
        uint64_t b = a + 1;
        if (b == 0) {
            continue;
        }
        if (a > UINT64_MAX / b) {
            continue;
        }
        if (a * b == delta) {
            return true;
        }
    }
    return false;
}

static bool lantern_slot_is_justifiable(uint64_t candidate_slot, uint64_t finalized_slot) {
    if (candidate_slot < finalized_slot) {
        return false;
    }
    uint64_t delta = candidate_slot - finalized_slot;
    if (delta <= 5) {
        return true;
    }
    uint64_t root = lantern_u64_isqrt(delta);
    if (root * root == delta) {
        return true;
    }
    return lantern_is_pronic(delta);
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
    if (a->slot != b->slot) {
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
    uint64_t threshold = numerator / 3u;
    if (threshold == 0) {
        threshold = 1;
    }
    if (threshold > SIZE_MAX) {
        return SIZE_MAX;
    }
    return (size_t)threshold;
}

int lantern_state_prepare_validator_votes(LanternState *state, uint64_t validator_count) {
    if (!state || validator_count == 0) {
        return -1;
    }
    if (validator_count > SIZE_MAX) {
        return -1;
    }
    size_t count = (size_t)validator_count;
    if (state->validator_votes && state->validator_votes_len != count) {
        free(state->validator_votes);
        state->validator_votes = NULL;
        state->validator_votes_len = 0;
    }
    if (!state->validator_votes) {
        struct lantern_vote_record *records = calloc(count, sizeof(*records));
        if (!records) {
            return -1;
        }
        state->validator_votes = records;
        state->validator_votes_len = count;
    } else {
        for (size_t i = 0; i < count; ++i) {
            lantern_vote_record_reset(&state->validator_votes[i]);
        }
    }
    return 0;
}

size_t lantern_state_validator_capacity(const LanternState *state) {
    if (!state || !state->validator_votes) {
        return 0;
    }
    return state->validator_votes_len;
}

bool lantern_state_validator_has_vote(const LanternState *state, size_t index) {
    if (!state || !state->validator_votes || index >= state->validator_votes_len) {
        return false;
    }
    return state->validator_votes[index].has_vote;
}

int lantern_state_get_validator_vote(const LanternState *state, size_t index, LanternVote *out_vote) {
    if (!state || !state->validator_votes || index >= state->validator_votes_len || !out_vote) {
        return -1;
    }
    if (!state->validator_votes[index].has_vote) {
        return -1;
    }
    *out_vote = state->validator_votes[index].vote;
    out_vote->validator_id = (uint64_t)index;
    return 0;
}

int lantern_state_set_validator_vote(LanternState *state, size_t index, const LanternVote *vote) {
    if (!state || !state->validator_votes || index >= state->validator_votes_len || !vote) {
        return -1;
    }
    state->validator_votes[index].vote = *vote;
    state->validator_votes[index].vote.validator_id = (uint64_t)index;
    state->validator_votes[index].has_vote = true;
    return 0;
}

void lantern_state_clear_validator_vote(LanternState *state, size_t index) {
    if (!state || !state->validator_votes || index >= state->validator_votes_len) {
        return;
    }
    lantern_vote_record_reset(&state->validator_votes[index]);
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
    struct lantern_fork_choice *attached = state->fork_choice;
    lantern_root_list_reset(&state->historical_block_hashes);
    lantern_bitlist_reset(&state->justified_slots);
    lantern_root_list_reset(&state->justification_roots);
    lantern_bitlist_reset(&state->justification_validators);
    if (state->validator_votes) {
        free(state->validator_votes);
        state->validator_votes = NULL;
        state->validator_votes_len = 0;
    }
    memset(state, 0, sizeof(*state));
    lantern_root_list_init(&state->historical_block_hashes);
    lantern_bitlist_init(&state->justified_slots);
    lantern_root_list_init(&state->justification_roots);
    lantern_bitlist_init(&state->justification_validators);
    state->fork_choice = attached;
}

void lantern_state_attach_fork_choice(LanternState *state, struct lantern_fork_choice *fork_choice) {
    if (!state) {
        return;
    }
    state->fork_choice = fork_choice;
}

int lantern_state_generate_genesis(LanternState *state, uint64_t genesis_time, uint64_t num_validators) {
    if (!state || num_validators == 0) {
        return -1;
    }
    lantern_state_reset(state);
    if (lantern_state_prepare_validator_votes(state, num_validators) != 0) {
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

    lantern_root_zero(&state->latest_justified.root);
    state->latest_justified.slot = 0;
    lantern_root_zero(&state->latest_finalized.root);
    state->latest_finalized.slot = 0;

    if (lantern_state_mark_justified_slot(state, state->latest_justified.slot) != 0) {
        lantern_state_reset(state);
        return -1;
    }
    if (lantern_state_mark_justified_slot(state, state->latest_finalized.slot) != 0) {
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
        const char *debug_hash = getenv("LANTERN_DEBUG_STATE_HASH");
        if (debug_hash && debug_hash[0] != '\0') {
            char computed_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
            if (lantern_bytes_to_hex(computed.bytes, LANTERN_ROOT_SIZE, computed_hex, sizeof(computed_hex), 1) == 0) {
                lantern_log_debug(
                    "state",
                    &(const struct lantern_log_metadata){.has_slot = true, .slot = state->slot},
                    "cached header state root=%s",
                    computed_hex);
            }
        }
        state->latest_block_header.state_root = computed;
    }
    return 0;
}

int lantern_state_process_slots(LanternState *state, uint64_t target_slot) {
    if (!state) {
        return -1;
    }
    if (target_slot < state->slot) {
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
        lantern_log_debug(
            "state",
            &(const struct lantern_log_metadata){
                .has_slot = true,
                .slot = state->slot},
            "slot advanced");
    }
    return 0;
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
    const char *debug_hash = getenv("LANTERN_DEBUG_STATE_HASH");
    if (debug_hash && debug_hash[0] != '\0') {
        fprintf(stderr, "mark justified slot %" PRIu64 "\n", slot);
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
    const struct lantern_log_metadata meta = {
        .has_slot = true,
        .slot = block->slot,
    };
    if (block->slot != state->slot) {
        lantern_log_warn(
            "state",
            &meta,
            "header rejected: block slot %" PRIu64 " expected state slot %" PRIu64,
            block->slot,
            state->slot);
        return -1;
    }
    if (block->slot < state->latest_block_header.slot) {
        lantern_log_warn(
            "state",
            &meta,
            "header rejected: stale slot %" PRIu64 " latest %" PRIu64,
            block->slot,
            state->latest_block_header.slot);
        return -1;
    }
    uint64_t expected_proposer = 0;
    if (lantern_proposer_for_slot(block->slot, state->config.num_validators, &expected_proposer) != 0) {
        return -1;
    }
    if (block->proposer_index != expected_proposer) {
        lantern_log_warn(
            "state",
            &meta,
            "header rejected: proposer %" PRIu64 " expected %" PRIu64,
            block->proposer_index,
            expected_proposer);
        return -1;
    }

    LanternRoot latest_header_root;
    if (lantern_hash_tree_root_block_header(&state->latest_block_header, &latest_header_root) != 0) {
        return -1;
    }
    bool skip_parent_check = state->latest_block_header.slot == 0 && lantern_root_is_zero(&block->parent_root);
    if (!skip_parent_check && memcmp(block->parent_root.bytes, latest_header_root.bytes, LANTERN_ROOT_SIZE) != 0) {
        char expected_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
        char received_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
        if (lantern_bytes_to_hex(
                latest_header_root.bytes,
                LANTERN_ROOT_SIZE,
                expected_hex,
                sizeof(expected_hex),
                1)
            != 0) {
            expected_hex[0] = '\0';
        }
        if (lantern_bytes_to_hex(
                block->parent_root.bytes,
                LANTERN_ROOT_SIZE,
                received_hex,
                sizeof(received_hex),
                1)
            != 0) {
            received_hex[0] = '\0';
        }
        lantern_log_warn(
            "state",
            &meta,
            "header rejected: parent mismatch expected=%s received=%s",
            expected_hex[0] ? expected_hex : "0x0",
            received_hex[0] ? received_hex : "0x0");
        return -1;
    }

    if (state->latest_block_header.slot == 0) {
        state->latest_justified.root = block->parent_root;
        state->latest_finalized.root = block->parent_root;
    }

    if (lantern_root_list_append(&state->historical_block_hashes, &block->parent_root) != 0) {
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
    const char *debug_hash = getenv("LANTERN_DEBUG_STATE_HASH");
    const struct lantern_log_metadata meta = {
        .has_slot = true,
        .slot = state->slot,
    };
    double att_batch_start = lantern_time_now_seconds();
    size_t att_attempted = 0;

    for (size_t i = 0; i < attestations->length; ++i) {
        const LanternSignedVote *signed_vote = &attestations->data[i];
        const LanternVote *vote = &signed_vote->data;
        att_attempted += 1;
        double att_validation_start = lantern_time_now_seconds();
        if (vote->validator_id >= validator_count) {
            lantern_log_warn(
                "state",
                &meta,
                "attestation rejected: validator %" PRIu64 " out of range (validators=%" PRIu64 ")",
                vote->validator_id,
                validator_count);
            record_attestation_validation_metric(att_validation_start, false);
            return -1;
        }
        if (vote->target.slot <= vote->source.slot) {
            record_attestation_validation_metric(att_validation_start, false);
            continue;
        }
        if (vote->source.slot > SIZE_MAX || vote->target.slot > SIZE_MAX) {
            record_attestation_validation_metric(att_validation_start, false);
            return -1;
        }

        bool source_is_justified = false;
        if (vote->source.slot >= state->justified_slots.bit_length) {
            record_attestation_validation_metric(att_validation_start, false);
            continue;
        }
        if (lantern_bitlist_get_bit(&state->justified_slots, (size_t)vote->source.slot, &source_is_justified) != 0) {
            lantern_log_warn(
                "state",
                &meta,
                "attestation rejected: unable to read justified bit for slot %" PRIu64,
                vote->source.slot);
            record_attestation_validation_metric(att_validation_start, false);
            return -1;
        }
        if (!source_is_justified) {
            record_attestation_validation_metric(att_validation_start, false);
            continue;
        }
        if (debug_hash && debug_hash[0] != '\0') {
            fprintf(
                stderr,
                "process attestation validator=%" PRIu64 " source=%" PRIu64 " target=%" PRIu64 "\n",
                vote->validator_id,
                vote->source.slot,
                vote->target.slot);
        }

        struct lantern_vote_record *record = &state->validator_votes[vote->validator_id];
        if (record->has_vote) {
            if (vote->slot < record->vote.slot) {
                record_attestation_validation_metric(att_validation_start, false);
                continue;
            }
            if (vote->slot == record->vote.slot) {
                if (lantern_votes_equal(&record->vote, vote)) {
                    record_attestation_validation_metric(att_validation_start, false);
                    continue;
                }
                lantern_log_warn(
                    "state",
                    &meta,
                    "attestation rejected: validator %" PRIu64 " produced conflicting vote at slot %" PRIu64,
                    vote->validator_id,
                    vote->slot);
                record_attestation_validation_metric(att_validation_start, false);
                return -1;
            }
        }

        bool target_is_justified = false;
        if (vote->target.slot < state->justified_slots.bit_length) {
            if (lantern_bitlist_get_bit(&state->justified_slots, (size_t)vote->target.slot, &target_is_justified) != 0) {
                lantern_log_warn(
                    "state",
                    &meta,
                    "attestation rejected: unable to read justified bit for slot %" PRIu64,
                    vote->target.slot);
                record_attestation_validation_metric(att_validation_start, false);
                return -1;
            }
        }
        record->vote = *vote;
        record->has_vote = true;
        if (target_is_justified) {
            if ((vote->source.slot + 1 == vote->target.slot) && latest_justified.slot < vote->target.slot) {
                latest_finalized = vote->source;
                latest_justified = vote->target;
                if (debug_hash && debug_hash[0] != '\0') {
                    char target_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
                    if (lantern_bytes_to_hex(
                            vote->target.root.bytes,
                            LANTERN_ROOT_SIZE,
                            target_hex,
                            sizeof(target_hex),
                            1)
                        == 0) {
                        lantern_log_debug(
                            "state",
                            &meta,
                            "finalized slot=%" PRIu64 " root=%s",
                            vote->source.slot,
                            target_hex);
                    }
                }
            }
            record_attestation_validation_metric(att_validation_start, true);
            continue;
        }

        if (lantern_state_mark_justified_slot(state, vote->target.slot) != 0) {
            record_attestation_validation_metric(att_validation_start, false);
            return -1;
        }
        if (debug_hash && debug_hash[0] != '\0') {
            fprintf(stderr, "marked slot %" PRIu64 " justified\n", vote->target.slot);
        }
        if (vote->target.slot > latest_justified.slot) {
            latest_justified = vote->target;
        }
        if (debug_hash && debug_hash[0] != '\0') {
            char target_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
            if (lantern_bytes_to_hex(
                    vote->target.root.bytes,
                    LANTERN_ROOT_SIZE,
                    target_hex,
                    sizeof(target_hex),
                    1)
                == 0) {
                lantern_log_debug(
                    "state",
                    &meta,
                    "justified slot=%" PRIu64 " root=%s",
                    vote->target.slot,
                    target_hex);
            }
        }
        record_attestation_validation_metric(att_validation_start, true);
    }

    if (lantern_state_mark_justified_slot(state, latest_justified.slot) != 0) {
        return -1;
    }
    if (lantern_state_mark_justified_slot(state, latest_finalized.slot) != 0) {
        return -1;
    }

    state->latest_justified = latest_justified;
    state->latest_finalized = latest_finalized;
    if (state->validator_votes && state->validator_votes_len > 0) {
        for (size_t i = 0; i < state->validator_votes_len; ++i) {
            struct lantern_vote_record *record = &state->validator_votes[i];
            if (!record->has_vote) {
                continue;
            }
            if (lantern_checkpoint_equal(&record->vote.target, &state->latest_justified)) {
                record->vote.source = state->latest_justified;
            }
        }
    }
    if (state->fork_choice) {
        if (lantern_fork_choice_update_checkpoints(
                state->fork_choice,
                &state->latest_justified,
                &state->latest_finalized)
            != 0) {
            return -1;
        }
    }
    lean_metrics_record_state_transition_attestations(att_attempted, lantern_time_now_seconds() - att_batch_start);
    return 0;
}

int lantern_state_process_block(LanternState *state, const LanternBlock *block) {
    if (!state || !block) {
        return -1;
    }
    double block_metrics_start = lantern_time_now_seconds();
    if (lantern_state_process_block_header(state, block) != 0) {
        return -1;
    }
    if (lantern_state_process_attestations(state, &block->body.attestations) != 0) {
        return -1;
    }
    if (state->fork_choice) {
        if (lantern_fork_choice_add_block(
                state->fork_choice,
                block,
                &state->latest_justified,
                &state->latest_finalized,
                NULL)
            != 0) {
            return -1;
        }
    }
    lean_metrics_record_state_transition_block(lantern_time_now_seconds() - block_metrics_start);
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
    bool profiling = state_profile_enabled();
    double transition_metrics_start = lantern_time_now_seconds();
#define STATE_FAIL(fmt, ...)                                                                 \
    do {                                                                                     \
        lantern_log_warn(                                                                    \
            "state",                                                                         \
            &(const struct lantern_log_metadata){.has_slot = true, .slot = block->slot},     \
            fmt,                                                                             \
            ##__VA_ARGS__);                                                                  \
        return -1;                                                                           \
    } while (0)

    if (block->slot < state->slot) {
        STATE_FAIL("block slot %" PRIu64 " not ahead of state %" PRIu64, block->slot, state->slot);
    }
    uint64_t slot_before = state->slot;
    double slots_start = profiling ? state_profile_now() : 0.0;
    double slots_metrics_start = lantern_time_now_seconds();
    if (lantern_state_process_slots(state, block->slot) != 0) {
        STATE_FAIL("process slots failed current=%" PRIu64, state->slot);
    }
    if (profiling) {
        state_profile_record(&g_profile_process_slots, state_profile_now() - slots_start);
    }
    double slots_duration = lantern_time_now_seconds() - slots_metrics_start;
    uint64_t slots_processed = block->slot >= slot_before ? (block->slot - slot_before) : 0;
    lean_metrics_record_state_transition_slots(slots_processed, slots_duration);
    double block_start = profiling ? state_profile_now() : 0.0;
    if (lantern_state_process_block(state, block) != 0) {
        STATE_FAIL("process block failed");
    }
    if (profiling) {
        state_profile_record(&g_profile_process_block, state_profile_now() - block_start);
    }
    LanternRoot computed_state_root;
    double hash_start = profiling ? state_profile_now() : 0.0;
    bool hashed_state = lantern_hash_tree_root_state(state, &computed_state_root) == 0;
    if (profiling && state->justification_validators.bit_length > g_profile_max_justification_bits) {
        g_profile_max_justification_bits = state->justification_validators.bit_length;
    }
    if (profiling) {
        state_profile_record(&g_profile_state_root, state_profile_now() - hash_start);
    }
    const char *debug_hash = getenv("LANTERN_DEBUG_STATE_HASH");
    if (hashed_state && debug_hash && debug_hash[0] != '\0') {
        char expected_hex_dbg[(LANTERN_ROOT_SIZE * 2u) + 3u];
        char computed_hex_dbg[(LANTERN_ROOT_SIZE * 2u) + 3u];
        if (lantern_bytes_to_hex(
                block->state_root.bytes,
                LANTERN_ROOT_SIZE,
                expected_hex_dbg,
                sizeof(expected_hex_dbg),
                1)
            != 0) {
            expected_hex_dbg[0] = '\0';
        }
        if (lantern_bytes_to_hex(
                computed_state_root.bytes,
                LANTERN_ROOT_SIZE,
                computed_hex_dbg,
                sizeof(computed_hex_dbg),
                1)
            != 0) {
            computed_hex_dbg[0] = '\0';
        }
        fprintf(
            stderr,
            "state slot %" PRIu64 " expected=%s computed=%s\n",
            block->slot,
            expected_hex_dbg[0] ? expected_hex_dbg : "0x0",
            computed_hex_dbg[0] ? computed_hex_dbg : "0x0");
    }

    bool allow_genesis_mismatch = (state->slot == 0 && block->slot == 0);
        if (hashed_state) {
            if (memcmp(block->state_root.bytes, computed_state_root.bytes, LANTERN_ROOT_SIZE) != 0) {
                char expected_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
                char computed_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
                if (lantern_bytes_to_hex(
                    block->state_root.bytes,
                    LANTERN_ROOT_SIZE,
                    expected_hex,
                    sizeof(expected_hex),
                    1)
                != 0) {
                expected_hex[0] = '\0';
            }
            if (lantern_bytes_to_hex(
                    computed_state_root.bytes,
                    LANTERN_ROOT_SIZE,
                    computed_hex,
                    sizeof(computed_hex),
                    1)
                != 0) {
                computed_hex[0] = '\0';
            }
            if (allow_genesis_mismatch) {
                lantern_log_warn(
                    "state",
                    &(const struct lantern_log_metadata){.has_slot = true, .slot = block->slot},
                    "genesis block state root mismatch: expected=%s computed=%s (accepting)",
                    expected_hex[0] ? expected_hex : "0x0",
                    computed_hex[0] ? computed_hex : "0x0");
            } else {
                lantern_log_warn(
                    "state",
                    &(const struct lantern_log_metadata){.has_slot = true, .slot = block->slot},
                    "state root mismatch: expected=%s computed=%s",
                    expected_hex[0] ? expected_hex : "0x0",
                    computed_hex[0] ? computed_hex : "0x0");
                STATE_FAIL("state root mismatch for slot %" PRIu64, block->slot);
            }
        }
    } else if (!allow_genesis_mismatch) {
        STATE_FAIL("failed to hash state for slot %" PRIu64, block->slot);
    }

    state->slot = block->slot;
    lean_metrics_record_state_transition(lantern_time_now_seconds() - transition_metrics_start);
#undef STATE_FAIL
    return 0;
}

int lantern_state_select_block_parent(const LanternState *state, LanternRoot *out_parent_root) {
    if (!state || !out_parent_root) {
        return -1;
    }
    if (state->config.num_validators == 0) {
        return -1;
    }

    LanternRoot header_root;
    if (lantern_hash_tree_root_block_header(&state->latest_block_header, &header_root) != 0) {
        return -1;
    }

    if (state->fork_choice) {
        LanternRoot head_root;
        if (lantern_fork_choice_current_head(state->fork_choice, &head_root) != 0) {
            return -1;
        }
        if (memcmp(head_root.bytes, header_root.bytes, LANTERN_ROOT_SIZE) != 0) {
            return -1;
        }
        *out_parent_root = head_root;
    } else {
        *out_parent_root = header_root;
    }
    return 0;
}

int lantern_state_collect_attestations_for_block(
    const LanternState *state,
    LanternAttestations *out_attestations) {
    if (!state || !out_attestations) {
        return -1;
    }
    if (!state->validator_votes || state->validator_votes_len == 0) {
        return -1;
    }
    if (lantern_attestations_resize(out_attestations, 0) != 0) {
        return -1;
    }

    for (size_t i = 0; i < state->validator_votes_len; ++i) {
        const struct lantern_vote_record *record = &state->validator_votes[i];
        if (!record->has_vote) {
            continue;
        }
        if (!lantern_checkpoint_equal(&record->vote.source, &state->latest_justified)) {
            continue;
        }
        if (out_attestations->length >= LANTERN_MAX_ATTESTATIONS) {
            (void)lantern_attestations_resize(out_attestations, 0);
            return -1;
        }
        LanternSignedVote signed_vote;
        memset(&signed_vote, 0, sizeof(signed_vote));
        signed_vote.data = record->vote;
        if (lantern_attestations_append(out_attestations, &signed_vote) != 0) {
            (void)lantern_attestations_resize(out_attestations, 0);
            return -1;
        }
    }
    return 0;
}

void lantern_state_profile_dump(void) {
    if (!state_profile_enabled()) {
        return;
    }
    fprintf(stderr, "[lantern_profile] state internals:\n");
    const struct {
        const char *label;
        const struct state_profile_metric *metric;
    } rows[] = {
        {"process_slots", &g_profile_process_slots},
        {"process_block", &g_profile_process_block},
        {"hash_state_root", &g_profile_state_root},
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); ++i) {
        const struct state_profile_metric *metric = rows[i].metric;
        double avg_ms = metric->calls ? (metric->seconds / (double)metric->calls) * 1000.0 : 0.0;
        fprintf(
            stderr,
            "    %-15s %8zu calls  %10.3f s total  %8.3f ms avg\n",
            rows[i].label,
            metric->calls,
            metric->seconds,
            avg_ms);
    }
    if (g_profile_max_justification_bits > 0) {
        fprintf(
            stderr,
            "    justification bits max: %zu (limit %" PRIu64 ")\n",
            g_profile_max_justification_bits,
            (uint64_t)LANTERN_JUSTIFICATION_VALIDATORS_LIMIT);
    }
}

int lantern_state_compute_vote_checkpoints(
    const LanternState *state,
    LanternCheckpoint *out_head,
    LanternCheckpoint *out_target,
    LanternCheckpoint *out_source) {
    if (!state || !out_head || !out_target || !out_source) {
        return -1;
    }
    if (!state->fork_choice) {
        return -1;
    }

    const LanternForkChoice *store = state->fork_choice;
    LanternRoot head_root;
    if (lantern_fork_choice_current_head(store, &head_root) != 0) {
        return -1;
    }
    uint64_t head_slot = 0;
    if (lantern_fork_choice_block_info(store, &head_root, &head_slot, NULL, NULL) != 0) {
        return -1;
    }

    LanternRoot target_root = head_root;
    uint64_t target_slot = head_slot;

    uint64_t safe_slot = head_slot;
    bool has_safe = false;
    const LanternRoot *safe_ptr = lantern_fork_choice_safe_target(store);
    if (safe_ptr) {
        if (lantern_fork_choice_block_info(store, safe_ptr, &safe_slot, NULL, NULL) != 0) {
            return -1;
        }
        has_safe = true;
    }

    if (has_safe) {
        for (size_t i = 0; i < 3 && target_slot > safe_slot; ++i) {
            LanternRoot parent_root;
            bool has_parent = false;
            if (lantern_fork_choice_block_info(store, &target_root, &target_slot, &parent_root, &has_parent) != 0) {
                return -1;
            }
            if (!has_parent) {
                break;
            }
            uint64_t parent_slot = 0;
            if (lantern_fork_choice_block_info(store, &parent_root, &parent_slot, NULL, NULL) != 0) {
                return -1;
            }
            target_root = parent_root;
            target_slot = parent_slot;
        }
    }

    while (!lantern_slot_is_justifiable(target_slot, state->latest_finalized.slot)) {
        LanternRoot parent_root;
        bool has_parent = false;
        if (lantern_fork_choice_block_info(store, &target_root, &target_slot, &parent_root, &has_parent) != 0) {
            return -1;
        }
        if (!has_parent) {
            break;
        }
        uint64_t parent_slot = 0;
        if (lantern_fork_choice_block_info(store, &parent_root, &parent_slot, NULL, NULL) != 0) {
            return -1;
        }
        target_root = parent_root;
        target_slot = parent_slot;
    }

    out_head->root = head_root;
    out_head->slot = head_slot;
    out_target->root = target_root;
    out_target->slot = target_slot;
    *out_source = state->latest_justified;
    return 0;
}
