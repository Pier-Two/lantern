#include "core/client/common.h"

#include <time.h>

#include "lantern/support/log.h"
#include "lantern/support/strings.h"

void lantern_client_format_root_hex(const LanternRoot *root, char *out, size_t out_len) {
    if (!out || out_len == 0) {
        return;
    }
    if (!root) {
        out[0] = '\0';
        return;
    }
    if (lantern_bytes_to_hex(root->bytes, LANTERN_ROOT_SIZE, out, out_len, 1) != 0) {
        out[0] = '\0';
    }
}

bool lantern_client_lock_state(struct lantern_client *client) {
    if (!client || !client->state_lock_initialized) {
        return false;
    }
    if (pthread_mutex_lock(&client->state_lock) != 0) {
        lantern_log_warn(
            "state",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to lock state mutex");
        return false;
    }
    return true;
}

void lantern_client_unlock_state(struct lantern_client *client, bool locked) {
    if (!client || !locked || !client->state_lock_initialized) {
        return;
    }
    pthread_mutex_unlock(&client->state_lock);
}

bool lantern_client_lock_pending(struct lantern_client *client) {
    if (!client || !client->pending_lock_initialized) {
        return false;
    }
    if (pthread_mutex_lock(&client->pending_lock) != 0) {
        lantern_log_warn(
            "state",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to lock pending block mutex");
        return false;
    }
    return true;
}

void lantern_client_unlock_pending(struct lantern_client *client, bool locked) {
    if (!client || !locked || !client->pending_lock_initialized) {
        return;
    }
    pthread_mutex_unlock(&client->pending_lock);
}

uint64_t lantern_client_wall_time_seconds(void) {
#if defined(CLOCK_REALTIME)
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        return (uint64_t)ts.tv_sec;
    }
#endif
    time_t now = time(NULL);
    return now > 0 ? (uint64_t)now : 0;
}
