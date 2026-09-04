/**
 * @file fork_choice.c
 * @brief Fork-choice interval advancement and aggregated-payload pools
 *
 * @see internal.h for shared internal declarations
 */

#include "internal.h"

#include "lantern/consensus/fork_choice.h"
#include "lantern/consensus/slot_clock.h"
#include "lantern/metrics/lean_metrics.h"
#include "lantern/support/time.h"

#include <inttypes.h>

static void log_aggregated_payload_interval_transition(
    const struct lantern_client *client,
    const char *context,
    uint64_t interval,
    uint64_t phase,
    size_t new_before,
    size_t known_before,
    size_t promoted) {
    if (!client || !context) {
        return;
    }
    struct lantern_log_metadata meta = {.validator = client->node_id};
    lantern_log(LANTERN_LOG_LEVEL_INFO,
        "forkchoice",
        &meta,
        "aggregated payload transition context=%s interval=%" PRIu64 " phase=%" PRIu64
        " new_before=%zu known_before=%zu promoted=%zu new_after=%zu known_after=%zu",
        context,
        interval,
        phase,
        new_before,
        known_before,
        promoted,
        client->store.new_aggregated_payloads.length,
        client->store.known_aggregated_payloads.length);
}

static bool interval_range_first_with_phase(
    uint64_t start,
    uint64_t end,
    uint64_t phase,
    uint64_t *out_interval) {
    if (phase >= LANTERN_INTERVALS_PER_SLOT || start > end) {
        return false;
    }
    uint64_t distance = end - start;
    uint64_t remainder = start % LANTERN_INTERVALS_PER_SLOT;
    uint64_t offset =
        (phase + LANTERN_INTERVALS_PER_SLOT - remainder) % LANTERN_INTERVALS_PER_SLOT;
    if (offset > distance) {
        return false;
    }
    if (out_interval) {
        *out_interval = start + offset;
    }
    return true;
}

static bool interval_range_last_with_phase(
    uint64_t start,
    uint64_t end,
    uint64_t phase,
    uint64_t *out_interval) {
    if (phase >= LANTERN_INTERVALS_PER_SLOT || start > end) {
        return false;
    }
    uint64_t distance = end - start;
    uint64_t remainder = end % LANTERN_INTERVALS_PER_SLOT;
    uint64_t offset =
        (remainder + LANTERN_INTERVALS_PER_SLOT - phase) % LANTERN_INTERVALS_PER_SLOT;
    if (offset > distance) {
        return false;
    }
    if (out_interval) {
        *out_interval = end - offset;
    }
    return true;
}

int lantern_client_tick_fork_choice_interval_locked(
    struct lantern_client *client,
    bool has_proposal) {
    if (!client || client->store.block_len == 0u) {
        return -1;
    }

    uint64_t previous_intervals = client->store.time_intervals;
    uint64_t next_interval = previous_intervals + 1u;
    if (next_interval < previous_intervals) {
        return -1;
    }
    size_t new_before = client->store.new_aggregated_payloads.length;
    size_t known_before = client->store.known_aggregated_payloads.length;

    double tick_start_seconds;
    enum lantern_time_result tick_time_result =
        lantern_time_now_seconds(&tick_start_seconds);
    int rc = lantern_fork_choice_advance_to(&client->store, next_interval, has_proposal);
    if (rc != 0) {
        return rc;
    }
    if (client->store.time_intervals != next_interval) {
        return -1;
    }

    if (tick_time_result == LANTERN_TIME_OK && tick_start_seconds > 0.0) {
        if (client->last_tick_interval_started_seconds > 0.0
            && tick_start_seconds >= client->last_tick_interval_started_seconds) {
            lean_metrics_record_tick_interval_duration(
                tick_start_seconds - client->last_tick_interval_started_seconds);
        }
        client->last_tick_interval_started_seconds = tick_start_seconds;
    }

    uint64_t phase = next_interval % LANTERN_INTERVALS_PER_SLOT;
    if (phase == LANTERN_DUTY_PHASE_SAFE_TARGET) {
        log_aggregated_payload_interval_transition(
            client,
            "safe_target",
            next_interval,
            phase,
            new_before,
            known_before,
            0u);
    } else if (phase == LANTERN_DUTY_PHASE_VOTE_ACCEPT
        || (phase == LANTERN_DUTY_PHASE_PROPOSAL && has_proposal)) {
        size_t new_after = client->store.new_aggregated_payloads.length;
        size_t promoted = new_before >= new_after ? new_before - new_after : 0u;
        log_aggregated_payload_interval_transition(
            client,
            phase == LANTERN_DUTY_PHASE_VOTE_ACCEPT
                ? "accept_new"
                : "proposal_accept_new",
            next_interval,
            phase,
            new_before,
            known_before,
            promoted);
    }

    return 0;
}

int lantern_client_skip_fork_choice_intervals_locked(
    struct lantern_client *client,
    uint64_t target_interval) {
    if (!client || client->store.block_len == 0u) {
        return -1;
    }
    if (target_interval < client->store.time_intervals) {
        return -1;
    }
    uint64_t previous_intervals = client->store.time_intervals;
    client->store.time_intervals = target_interval;
    if (target_interval == previous_intervals) {
        return 0;
    }

    uint64_t start_interval = previous_intervals + 1u;
    uint64_t first_accept_interval = 0u;
    uint64_t last_safe_interval = 0u;
    bool has_accept = interval_range_first_with_phase(
        start_interval,
        target_interval,
        LANTERN_DUTY_PHASE_VOTE_ACCEPT,
        &first_accept_interval);
    bool has_safe = interval_range_last_with_phase(
        start_interval,
        target_interval,
        LANTERN_DUTY_PHASE_SAFE_TARGET,
        &last_safe_interval);

    if (has_safe && (!has_accept || last_safe_interval < first_accept_interval)) {
        size_t new_before = client->store.new_aggregated_payloads.length;
        size_t known_before = client->store.known_aggregated_payloads.length;
        if (lantern_fork_choice_update_safe_target(&client->store) != 0) {
            return -1;
        }
        log_aggregated_payload_interval_transition(
            client,
            "skip_safe_target",
            last_safe_interval,
            last_safe_interval % LANTERN_INTERVALS_PER_SLOT,
            new_before,
            known_before,
            0u);
    }

    if (has_accept) {
        size_t new_before = client->store.new_aggregated_payloads.length;
        size_t known_before = client->store.known_aggregated_payloads.length;
        size_t promoted = lantern_store_promote_new_aggregated_payloads(&client->store);
        if (lantern_fork_choice_accept_new_aggregated_payloads(&client->store) != 0) {
            return -1;
        }
        log_aggregated_payload_interval_transition(
            client,
            "skip_accept_new",
            first_accept_interval,
            first_accept_interval % LANTERN_INTERVALS_PER_SLOT,
            new_before,
            known_before,
            promoted);
    }

    if (has_safe && has_accept && last_safe_interval > first_accept_interval) {
        size_t new_before = client->store.new_aggregated_payloads.length;
        size_t known_before = client->store.known_aggregated_payloads.length;
        if (lantern_fork_choice_update_safe_target(&client->store) != 0) {
            return -1;
        }
        log_aggregated_payload_interval_transition(
            client,
            "skip_safe_target",
            last_safe_interval,
            last_safe_interval % LANTERN_INTERVALS_PER_SLOT,
            new_before,
            known_before,
            0u);
    }
    return 0;
}

int lantern_client_advance_fork_choice_time_locked(
    struct lantern_client *client,
    uint64_t now_milliseconds,
    bool has_proposal) {
    if (!client || client->store.block_len == 0u) {
        return -1;
    }

    uint64_t previous_intervals = client->store.time_intervals;
    uint64_t target_interval = 0u;
    int target_rc = lantern_slot_clock_total_interval(
        client->state.config.genesis_time,
        now_milliseconds,
        &target_interval);
    if (target_rc < 0) {
        return -1;
    }
    if (target_rc == 0
        && target_interval > previous_intervals
        && (target_interval - previous_intervals) > LANTERN_INTERVALS_PER_SLOT)
    {
        uint64_t skip_to_interval =
            target_interval - LANTERN_INTERVALS_PER_SLOT;
        if (lantern_client_skip_fork_choice_intervals_locked(client, skip_to_interval) != 0) {
            return -1;
        }
    }

    if (target_rc > 0) {
        return 0;
    }
    return lantern_fork_choice_advance_to(
        &client->store,
        target_interval,
        has_proposal);
}
