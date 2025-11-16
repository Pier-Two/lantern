#include "core/client/validator_service.h"

#include <inttypes.h>
#include <string.h>
#include <time.h>

#include "core/client/common.h"
#include "lantern/consensus/hash.h"
#include "lantern/consensus/signature.h"
#include "lantern/storage/storage.h"
#include "lantern/support/log.h"
#include "lantern/support/secure_mem.h"

static void validator_duty_state_reset(struct lantern_validator_duty_state *state) {
    if (!state) {
        return;
    }
    memset(state, 0, sizeof(*state));
}

static void validator_sleep_ms(uint32_t ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000u;
    ts.tv_nsec = (long)(ms % 1000u) * 1000000L;
    nanosleep(&ts, NULL);
}

static bool validator_service_should_run(const struct lantern_client *client) {
    if (!client) {
        return false;
    }
    if (!client->has_state || !client->has_runtime || !client->has_fork_choice) {
        return false;
    }
    if (!client->gossip_running || client->local_validator_count == 0) {
        return false;
    }
    return true;
}

static bool validator_is_enabled(const struct lantern_client *client, size_t local_index) {
    if (!client || local_index >= client->local_validator_count) {
        return false;
    }
    if (!client->validator_enabled) {
        return true;
    }
    if (!client->validator_lock_initialized) {
        return client->validator_enabled[local_index];
    }
    if (pthread_mutex_lock((pthread_mutex_t *)&client->validator_lock) != 0) {
        return client->validator_enabled[local_index];
    }
    bool enabled = client->validator_enabled[local_index];
    pthread_mutex_unlock((pthread_mutex_t *)&client->validator_lock);
    return enabled;
}

static uint64_t validator_global_index(const struct lantern_client *client, size_t local_index) {
    if (!client || !client->local_validators || local_index >= client->local_validator_count) {
        return UINT64_MAX;
    }
    return client->local_validators[local_index].global_index;
}

static int validator_sign_vote(struct lantern_local_validator *validator, uint64_t slot, LanternSignedVote *vote) {
    if (!validator || !vote || !validator->secret_key) {
        return -1;
    }
    LanternRoot vote_root;
    if (lantern_hash_tree_root_vote(&vote->data, &vote_root) != 0) {
        return -1;
    }
    if (!lantern_signature_sign(
            validator->secret_key,
            slot,
            vote_root.bytes,
            sizeof(vote_root.bytes),
            &vote->signature)) {
        return -1;
    }
    return 0;
}

static int validator_store_vote(struct lantern_client *client, const LanternSignedVote *vote) {
    if (!client || !vote) {
        return -1;
    }
    if (!client->has_state) {
        return -1;
    }
    bool state_locked = lantern_client_lock_state(client);
    if (!state_locked) {
        return -1;
    }
    int rc = lantern_state_set_signed_validator_vote(
        &client->state,
        (size_t)vote->data.validator_id,
        vote);
    lantern_client_unlock_state(client, state_locked);
    if (rc != 0) {
        lantern_log_warn(
            "state",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to cache validator vote validator=%" PRIu64 " slot=%" PRIu64,
            vote->data.validator_id,
            vote->data.slot);
        return -1;
    }
    if (client->data_dir) {
        if (lantern_storage_save_votes(client->data_dir, &client->state) != 0) {
            lantern_log_warn(
                "storage",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to persist local votes");
        }
    }
    return 0;
}

static int validator_publish_vote(struct lantern_client *client, const LanternSignedVote *vote) {
    if (!client || !vote) {
        return -1;
    }
    if (!client->gossip_running) {
        return -1;
    }
    if (lantern_gossipsub_service_publish_vote(&client->gossip, vote) != 0) {
        lantern_log_warn(
            "validator",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to broadcast vote validator=%" PRIu64 " slot=%" PRIu64,
            vote->data.validator_id,
            vote->data.slot);
        return -1;
    }
    return 0;
}

static int validator_build_block(
    struct lantern_client *client,
    uint64_t slot,
    struct lantern_local_validator *validator,
    LanternSignedBlock *out_block) {
    if (!client || !client->has_state || !client->has_runtime || !validator || !out_block) {
        return -1;
    }
    if (!client->has_fork_choice) {
        return -1;
    }
    LanternRoot parent_root;
    if (lantern_fork_choice_current_head(&client->fork_choice, &parent_root) != 0) {
        return -1;
    }
    LanternRoot parent_state_root;
    if (lantern_fork_choice_state_root(&client->fork_choice, &parent_root, &parent_state_root) != 0) {
        return -1;
    }
    LanternRoot parent_body_root;
    if (lantern_fork_choice_body_root(&client->fork_choice, &parent_root, &parent_body_root) != 0) {
        return -1;
    }
    LanternSignedBlock block;
    memset(&block, 0, sizeof(block));
    block.message.block.slot = slot;
    block.message.block.parent_root = parent_root;
    block.message.block.state_root = parent_state_root;
    block.message.block.body_root = parent_body_root;
    block.message.block.proposer_index = validator->global_index;
    lantern_block_body_init(&block.message.block.body);

    bool state_locked = lantern_client_lock_state(client);
    if (!state_locked) {
        lantern_block_body_reset(&block.message.block.body);
        return -1;
    }
    int rc = lantern_consensus_runtime_build_block(
        &client->runtime,
        &client->state,
        slot,
        validator->global_index,
        &block);
    lantern_client_unlock_state(client, state_locked);
    if (rc != 0) {
        lantern_block_body_reset(&block.message.block.body);
        return -1;
    }
    *out_block = block;
    return 0;
}

static int validator_propose_block(struct lantern_client *client, uint64_t slot, size_t local_index) {
    if (!client || local_index >= client->local_validator_count) {
        return -1;
    }
    struct lantern_local_validator *local = &client->local_validators[local_index];
    if (!validator_is_enabled(client, local_index)) {
        return 0;
    }
    if (local->last_proposed_slot == slot) {
        return 0;
    }

    LanternSignedBlock block;
    memset(&block, 0, sizeof(block));
    if (validator_build_block(client, slot, local, &block) != 0) {
        return -1;
    }
    local->last_proposed_slot = slot;
    int rc = lantern_client_publish_block(client, &block);
    lantern_signed_block_with_attestation_reset(&block);
    return rc;
}

static int validator_publish_attestations(struct lantern_client *client, uint64_t slot) {
    if (!client) {
        return -1;
    }
    if (!client->has_state || !client->has_runtime) {
        return -1;
    }

    LanternCheckpoint head_cp;
    LanternCheckpoint target_cp;
    LanternCheckpoint source_cp;
    memset(&head_cp, 0, sizeof(head_cp));
    memset(&target_cp, 0, sizeof(target_cp));
    memset(&source_cp, 0, sizeof(source_cp));

    bool state_locked = lantern_client_lock_state(client);
    if (!state_locked) {
        return -1;
    }
    if (lantern_state_current_checkpoints(&client->state, &head_cp, &target_cp, &source_cp) != 0) {
        lantern_client_unlock_state(client, state_locked);
        return -1;
    }
    if (lantern_state_compute_vote_checkpoints(&client->state, &head_cp, &target_cp, &source_cp) != 0) {
        lantern_client_unlock_state(client, state_locked);
        return -1;
    }
    lantern_client_unlock_state(client, state_locked);

    bool have_lock = false;
    if (client->validator_lock_initialized) {
        if (pthread_mutex_lock(&client->validator_lock) != 0) {
            return -1;
        }
        have_lock = true;
    }

    for (size_t i = 0; i < client->local_validator_count; ++i) {
        bool enabled = client->validator_enabled ? client->validator_enabled[i] : true;
        if (!enabled) {
            continue;
        }
        struct lantern_local_validator *validator = &client->local_validators[i];
        if (validator->last_attested_slot == slot) {
            continue;
        }
        LanternSignedVote vote;
        if (validator->has_pending_attestation && validator->pending_attestation_slot == slot) {
            vote = validator->pending_attestation;
        } else {
            memset(&vote, 0, sizeof(vote));
            vote.data.validator_id = validator->global_index;
            vote.data.slot = slot;
            vote.data.head = head_cp;
            vote.data.target = target_cp;
            vote.data.source = source_cp;
            if (validator_sign_vote(validator, slot, &vote) != 0) {
                continue;
            }
        }
        validator->last_attested_slot = slot;
        validator->has_pending_attestation = false;

        (void)validator_store_vote(client, &vote);
        (void)validator_publish_vote(client, &vote);
    }

    if (have_lock) {
        pthread_mutex_unlock(&client->validator_lock);
    }
    return 0;
}

static void *validator_thread(void *arg) {
    struct lantern_client *client = arg;
    if (!client) {
        return NULL;
    }

    while (__atomic_load_n(&client->validator_stop_flag, __ATOMIC_RELAXED) == 0) {
        if (!validator_service_should_run(client)) {
            validator_sleep_ms(200);
            continue;
        }

        uint64_t now = lantern_client_wall_time_seconds();
        if (client->has_runtime) {
            if (lantern_consensus_runtime_update_time(&client->runtime, now) != 0) {
                validator_sleep_ms(50);
                continue;
            }
        }

        const struct lantern_slot_timepoint *tp = lantern_consensus_runtime_current_timepoint(&client->runtime);
        if (!tp) {
            validator_sleep_ms(50);
            continue;
        }

        struct lantern_validator_duty_state *duty = &client->validator_duty;
        if (!duty->have_timepoint || duty->last_slot != tp->slot) {
            duty->have_timepoint = true;
            duty->last_slot = tp->slot;
            duty->slot_proposed = false;
            duty->slot_attested = false;
            duty->pending_local_proposal = false;
            duty->pending_local_index = 0;

            bool is_local = false;
            uint64_t local_index = 0;
            if (lantern_consensus_runtime_local_proposer(&client->runtime, tp->slot, &is_local, &local_index) == 0
                && is_local
                && local_index < client->local_validator_count) {
                duty->pending_local_proposal = true;
                duty->pending_local_index = local_index;
            }
        }
        duty->last_interval = tp->interval_index;

        if (client->has_fork_choice) {
            bool has_proposal = duty->slot_proposed;
            (void)lantern_fork_choice_advance_time(&client->fork_choice, now, has_proposal);
        }

        switch (tp->phase) {
        case LANTERN_DUTY_PHASE_PROPOSAL:
            if (duty->pending_local_proposal && !duty->slot_proposed) {
                if (validator_propose_block(client, tp->slot, (size_t)duty->pending_local_index) == 0) {
                    duty->slot_proposed = true;
                }
            }
            break;
        case LANTERN_DUTY_PHASE_VOTE:
            if (!duty->slot_attested) {
                if (validator_publish_attestations(client, tp->slot) == 0) {
                    duty->slot_attested = true;
                }
            }
            break;
        default:
            break;
        }

        validator_sleep_ms(50);
    }
    return NULL;
}

int lantern_client_start_validator_service(struct lantern_client *client) {
    if (!client) {
        return -1;
    }
    if (client->validator_thread_started) {
        return 0;
    }
    if (client->local_validator_count == 0 || !client->has_runtime) {
        return 0;
    }
    validator_duty_state_reset(&client->validator_duty);
    __atomic_store_n(&client->validator_stop_flag, 0, __ATOMIC_RELAXED);
    if (pthread_create(&client->validator_thread, NULL, validator_thread, client) != 0) {
        lantern_log_warn(
            "validator",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to start validator service thread");
        return -1;
    }
    client->validator_thread_started = true;
    lantern_log_info(
        "validator",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "validator service started");
    return 0;
}

void lantern_client_stop_validator_service(struct lantern_client *client) {
    if (!client || !client->validator_thread_started) {
        return;
    }
    __atomic_store_n(&client->validator_stop_flag, 1, __ATOMIC_RELAXED);
    (void)pthread_join(client->validator_thread, NULL);
    client->validator_thread_started = false;
    lantern_log_info(
        "validator",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "validator service stopped");
}

size_t lantern_client_local_validator_count(const struct lantern_client *client) {
    if (!client) {
        return 0;
    }
    return client->local_validator_count;
}

const struct lantern_local_validator *lantern_client_local_validator(
    const struct lantern_client *client,
    size_t index) {
    if (!client || index >= client->local_validator_count) {
        return NULL;
    }
    return &client->local_validators[index];
}

int lantern_client_publish_block(struct lantern_client *client, const LanternSignedBlock *block) {
    if (!client || !block) {
        return -1;
    }
    if (!client->gossip_running) {
        lantern_log_error(
            "gossip",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "cannot publish block at slot %" PRIu64 ": gossip service inactive",
            block->message.block.slot);
        return -1;
    }
    if (lantern_gossipsub_service_publish_block(&client->gossip, block) != 0) {
        lantern_log_error(
            "gossip",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to publish block at slot %" PRIu64,
            block->message.block.slot);
        return -1;
    }

    LanternRoot block_root;
    char root_hex[2 * LANTERN_ROOT_SIZE + 3];
    if (lantern_hash_tree_root_signed_block(block, &block_root) == 0) {
        lantern_client_format_root_hex(&block_root, root_hex, sizeof(root_hex));
    } else {
        root_hex[0] = '\0';
    }

    lantern_log_info(
        "gossip",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "published block slot=%" PRIu64 " root=%s attestations=%zu",
        block->message.block.slot,
        root_hex[0] ? root_hex : "0x0",
        block->message.block.body.attestations.length);
    return 0;
}
