#include <assert.h>
#include <string.h>

#include "lantern/metrics/lean_metrics.h"

static int test_attestation_validation_metrics(void) {
    lean_metrics_reset();
    lean_metrics_record_attestation_validation(0.01, true);
    lean_metrics_record_attestation_validation(0.02, false);

    struct lean_metrics_snapshot snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    lean_metrics_snapshot(&snapshot);

    assert(snapshot.attestations_valid_total == 1);
    assert(snapshot.attestations_invalid_total == 1);
    assert(snapshot.attestation_validation_time.total == 2);
    assert(snapshot.attestation_validation_time.sum > 0.0);
    return 0;
}

static int test_state_transition_counters(void) {
    lean_metrics_reset();
    lean_metrics_record_state_transition_slots(5, 0.05);
    lean_metrics_record_state_transition_slots(0, 0.01);
    lean_metrics_record_state_transition_attestations(3, 0.02);
    lean_metrics_record_state_transition(0.5);

    struct lean_metrics_snapshot snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    lean_metrics_snapshot(&snapshot);

    assert(snapshot.state_transition_slots_processed_total == 5);
    assert(snapshot.state_transition_attestations_processed_total == 3);
    assert(snapshot.state_transition_time.total == 1);
    assert(snapshot.state_transition_time.sum > 0.0);
    return 0;
}

static int test_fork_choice_histogram(void) {
    lean_metrics_reset();
    lean_metrics_record_fork_choice_block_time(0.001);
    lean_metrics_record_fork_choice_block_time(0.5);
    lean_metrics_record_fork_choice_block_time(2.0);

    struct lean_metrics_snapshot snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    lean_metrics_snapshot(&snapshot);

    assert(snapshot.fork_choice_block_time.total == 3);
    assert(snapshot.fork_choice_block_time.counts[0] == 1);
    assert(snapshot.fork_choice_block_time.counts[2] >= 1);
    return 0;
}

int main(void) {
    if (test_attestation_validation_metrics() != 0) {
        return 1;
    }
    if (test_state_transition_counters() != 0) {
        return 1;
    }
    if (test_fork_choice_histogram() != 0) {
        return 1;
    }
    return 0;
}
