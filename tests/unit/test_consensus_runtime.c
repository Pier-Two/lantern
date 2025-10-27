#include "lantern/consensus/runtime.h"

#include <stdio.h>
#include <string.h>

static int test_runtime_time_update(void) {
    struct lantern_validator_assignment assignment = {
        .start_index = 2,
        .count = 1,
    };

    struct lantern_consensus_runtime_config config;
    lantern_consensus_runtime_config_init(&config);
    config.genesis_time = 1000;
    config.validator_count = 4;

    struct lantern_consensus_runtime runtime;
    if (lantern_consensus_runtime_init(&runtime, &config, &assignment) != 0) {
        fprintf(stderr, "runtime init failed\n");
        return 1;
    }

    if (lantern_consensus_runtime_update_time(&runtime, 1004) != 0) {
        fprintf(stderr, "runtime update time failed\n");
        return 1;
    }
    const struct lantern_slot_timepoint *tp = lantern_consensus_runtime_current_timepoint(&runtime);
    if (!tp) {
        fprintf(stderr, "missing timepoint\n");
        return 1;
    }
    if (tp->slot != 1 || tp->interval_index != 0) {
        fprintf(stderr, "unexpected timepoint slot=%llu interval=%u\n",
            (unsigned long long)tp->slot,
            tp->interval_index);
        return 1;
    }
    if (tp->phase != LANTERN_DUTY_PHASE_PROPOSAL) {
        fprintf(stderr, "unexpected phase %u\n", tp->phase);
        return 1;
    }

    struct lantern_duty_schedule schedule;
    if (lantern_consensus_runtime_schedule_slot(&runtime, 2, &schedule) != 0) {
        fprintf(stderr, "schedule slot failed\n");
        return 1;
    }
    if (schedule.phase_start_times[0] != 1008) {
        fprintf(stderr, "unexpected proposal start time %llu\n",
            (unsigned long long)schedule.phase_start_times[0]);
        return 1;
    }

    return 0;
}

static int test_local_proposer_detection(void) {
    struct lantern_validator_assignment assignment = {
        .start_index = 2,
        .count = 1,
    };

    struct lantern_consensus_runtime_config config;
    lantern_consensus_runtime_config_init(&config);
    config.genesis_time = 0;
    config.validator_count = 4;

    struct lantern_consensus_runtime runtime;
    if (lantern_consensus_runtime_init(&runtime, &config, &assignment) != 0) {
        fprintf(stderr, "runtime init failed\n");
        return 1;
    }

    bool is_local = false;
    uint64_t local_index = 0;
    if (lantern_consensus_runtime_local_proposer(&runtime, 5, &is_local, &local_index) != 0) {
        fprintf(stderr, "local proposer query failed\n");
        return 1;
    }
    if (is_local) {
        fprintf(stderr, "slot 5 should not be local proposer\n");
        return 1;
    }

    if (lantern_consensus_runtime_local_proposer(&runtime, 6, &is_local, &local_index) != 0) {
        fprintf(stderr, "local proposer query failed\n");
        return 1;
    }
    if (!is_local || local_index != 0) {
        fprintf(stderr, "slot 6 should map to local validator index 0\n");
        return 1;
    }

    if (lantern_consensus_runtime_validator_count(&runtime) != 4) {
        fprintf(stderr, "validator count mismatch\n");
        return 1;
    }
    return 0;
}

int main(void) {
    if (test_runtime_time_update() != 0) {
        return 1;
    }
    if (test_local_proposer_detection() != 0) {
        return 1;
    }
    puts("lantern_consensus_runtime_test OK");
    return 0;
}
