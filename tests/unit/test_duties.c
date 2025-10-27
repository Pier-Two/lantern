#include "lantern/consensus/duties.h"

#include <stdio.h>
#include <string.h>

static int test_assignment_offsets(void) {
    struct lantern_validator_config_entry entries[3];
    memset(entries, 0, sizeof(entries));
    entries[0].count = 2;
    entries[1].count = 1;
    entries[2].count = 3;

    struct lantern_validator_config config = {
        .entries = entries,
        .count = 3,
    };

    struct lantern_validator_assignment assignment;
    if (lantern_validator_assignment_from_config(&config, &entries[1], &assignment) != 0) {
        fprintf(stderr, "assignment from config failed\n");
        return 1;
    }
    if (assignment.start_index != 2 || assignment.count != 1) {
        fprintf(stderr, "assignment offset mismatch (start=%llu count=%llu)\n",
            (unsigned long long)assignment.start_index,
            (unsigned long long)assignment.count);
        return 1;
    }

    uint64_t local_index = 0;
    if (!lantern_validator_assignment_contains(&assignment, 2, &local_index)) {
        fprintf(stderr, "expected local validator to contain index 2\n");
        return 1;
    }
    if (local_index != 0) {
        fprintf(stderr, "local index mismatch (%llu)\n", (unsigned long long)local_index);
        return 1;
    }
    if (lantern_validator_assignment_contains(&assignment, 3, &local_index)) {
        fprintf(stderr, "unexpected validator inclusion\n");
        return 1;
    }

    return 0;
}

static int test_proposer_selection(void) {
    uint64_t proposer = 0;
    if (lantern_proposer_for_slot(5, 4, &proposer) != 0) {
        fprintf(stderr, "proposer selection failed\n");
        return 1;
    }
    if (proposer != 1) {
        fprintf(stderr, "unexpected proposer index %llu\n", (unsigned long long)proposer);
        return 1;
    }
    if (lantern_proposer_for_slot(3, 0, &proposer) == 0) {
        fprintf(stderr, "expected proposer selection failure with zero validators\n");
        return 1;
    }
    return 0;
}

int main(void) {
    if (test_assignment_offsets() != 0) {
        return 1;
    }
    if (test_proposer_selection() != 0) {
        return 1;
    }
    puts("lantern_duties_test OK");
    return 0;
}
