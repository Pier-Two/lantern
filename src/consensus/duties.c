#include "lantern/consensus/duties.h"

#include <stddef.h>
#include <stdint.h>

static int add_u64(uint64_t a, uint64_t b, uint64_t *out) {
    if (!out) {
        return -1;
    }
    if (a > UINT64_MAX - b) {
        return -1;
    }
    *out = a + b;
    return 0;
}

void lantern_validator_assignment_init(struct lantern_validator_assignment *assignment) {
    if (!assignment) {
        return;
    }
    assignment->start_index = 0;
    assignment->count = 0;
}

bool lantern_validator_assignment_is_valid(const struct lantern_validator_assignment *assignment) {
    return assignment && assignment->count > 0;
}

int lantern_validator_assignment_from_config(
    const struct lantern_validator_config *config,
    const struct lantern_validator_config_entry *entry,
    struct lantern_validator_assignment *assignment) {
    if (!assignment) {
        return -1;
    }
    lantern_validator_assignment_init(assignment);
    if (!config || !entry || !config->entries || config->count == 0) {
        return -1;
    }
    uint64_t offset = 0;
    bool found = false;
    for (size_t i = 0; i < config->count; ++i) {
        const struct lantern_validator_config_entry *current = &config->entries[i];
        if (current == entry) {
            found = true;
            break;
        }
        if (add_u64(offset, current->count, &offset) != 0) {
            return -1;
        }
    }
    if (!found) {
        return -1;
    }
    assignment->start_index = offset;
    assignment->count = entry->count;
    return 0;
}

int lantern_proposer_for_slot(uint64_t slot, uint64_t validator_count, uint64_t *out_proposer_index) {
    if (!out_proposer_index || validator_count == 0) {
        return -1;
    }
    *out_proposer_index = slot % validator_count;
    return 0;
}

bool lantern_validator_assignment_contains(
    const struct lantern_validator_assignment *assignment,
    uint64_t global_validator_index,
    uint64_t *out_local_index) {
    if (!assignment || assignment->count == 0) {
        return false;
    }
    uint64_t start = assignment->start_index;
    uint64_t end = start + assignment->count;
    if (global_validator_index < start || global_validator_index >= end) {
        return false;
    }
    if (out_local_index) {
        *out_local_index = global_validator_index - start;
    }
    return true;
}
