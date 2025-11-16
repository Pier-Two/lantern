#include "core/client/http_handlers.h"

#include <inttypes.h>
#include <string.h>

#include "core/client/common.h"
#include "lantern/metrics/lean_metrics.h"
#include "lantern/support/log.h"

static int find_local_validator_index(const struct lantern_client *client, uint64_t global_index, size_t *out_index) {
    if (!client || !client->local_validators || client->local_validator_count == 0 || !out_index) {
        return -1;
    }
    for (size_t i = 0; i < client->local_validator_count; ++i) {
        const struct lantern_local_validator *validator = &client->local_validators[i];
        if (validator->global_index == global_index) {
            *out_index = i;
            return 0;
        }
    }
    return -1;
}

int lantern_client_http_snapshot_head(void *context, struct lantern_http_head_snapshot *out_snapshot) {
    if (!context || !out_snapshot) {
        return -1;
    }
    struct lantern_client *client = context;
    if (!client->has_state) {
        return -1;
    }
    memset(out_snapshot, 0, sizeof(*out_snapshot));
    out_snapshot->slot = client->state.slot;
    if (lantern_hash_tree_root_block_header(&client->state.latest_block_header, &out_snapshot->head_root) != 0) {
        return -1;
    }
    out_snapshot->justified = client->state.latest_justified;
    out_snapshot->finalized = client->state.latest_finalized;
    return 0;
}

size_t lantern_client_http_validator_count_cb(void *context) {
    const struct lantern_client *client = context;
    if (!client) {
        return 0;
    }
    return client->local_validator_count;
}

int lantern_client_http_validator_info_cb(void *context, size_t index, struct lantern_http_validator_info *out_info) {
    if (!context || !out_info) {
        return -1;
    }
    struct lantern_client *client = context;
    if (index >= client->local_validator_count || !client->local_validators) {
        return -1;
    }
    memset(out_info, 0, sizeof(*out_info));
    out_info->global_index = client->local_validators[index].global_index;

    bool enabled = true;
    if (client->validator_lock_initialized) {
        if (pthread_mutex_lock(&client->validator_lock) != 0) {
            return -1;
        }
        if (client->validator_enabled && index < client->local_validator_count) {
            enabled = client->validator_enabled[index];
        }
        pthread_mutex_unlock(&client->validator_lock);
    } else if (client->validator_enabled && index < client->local_validator_count) {
        enabled = client->validator_enabled[index];
    }
    out_info->enabled = enabled;

    const char *base = client->node_id ? client->node_id : "validator";
    int written = snprintf(out_info->label, sizeof(out_info->label), "%s#%" PRIu64, base, out_info->global_index);
    if (written < 0 || (size_t)written >= sizeof(out_info->label)) {
        strncpy(out_info->label, base, sizeof(out_info->label));
        out_info->label[sizeof(out_info->label) - 1] = '\0';
    }
    return 0;
}

int lantern_client_http_set_validator_status_cb(void *context, uint64_t global_index, bool enabled) {
    if (!context) {
        return -1;
    }
    struct lantern_client *client = context;
    if (!client->validator_lock_initialized || !client->validator_enabled) {
        return -1;
    }
    if (pthread_mutex_lock(&client->validator_lock) != 0) {
        return -1;
    }
    size_t local_index = 0;
    if (find_local_validator_index(client, global_index, &local_index) != 0
        || local_index >= client->local_validator_count) {
        pthread_mutex_unlock(&client->validator_lock);
        return -1;
    }
    client->validator_enabled[local_index] = enabled;
    pthread_mutex_unlock(&client->validator_lock);

    lantern_log_info(
        "validator",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "validator %" PRIu64 " %s",
        global_index,
        enabled ? "enabled" : "disabled");
    return 0;
}

int lantern_client_metrics_snapshot_cb(void *context, struct lantern_metrics_snapshot *out_snapshot) {
    if (!context || !out_snapshot) {
        return -1;
    }
    struct lantern_client *client = context;
    if (!client->has_state) {
        return -1;
    }
    bool state_locked = lantern_client_lock_state(client);
    if (!state_locked) {
        return -1;
    }
    out_snapshot->state = client->state;
    lantern_client_unlock_state(client, state_locked);
    lean_metrics_snapshot(&out_snapshot->lean_metrics);
    return 0;
}
