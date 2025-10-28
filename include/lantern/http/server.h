#ifndef LANTERN_HTTP_SERVER_H
#define LANTERN_HTTP_SERVER_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "lantern/consensus/containers.h"

#ifdef __cplusplus
extern "C" {
#endif

struct lantern_http_head_snapshot {
    uint64_t slot;
    LanternRoot head_root;
    LanternCheckpoint justified;
    LanternCheckpoint finalized;
};

struct lantern_http_validator_info {
    uint64_t global_index;
    bool enabled;
    char label[64];
};

struct lantern_http_server_callbacks {
    void *context;
    int (*snapshot_head)(void *context, struct lantern_http_head_snapshot *out_snapshot);
    size_t (*validator_count)(void *context);
    int (*validator_info)(void *context, size_t index, struct lantern_http_validator_info *out_info);
    int (*set_validator_status)(void *context, uint64_t global_index, bool enabled);
};

struct lantern_http_server_config {
    uint16_t port;
    struct lantern_http_server_callbacks callbacks;
};

struct lantern_http_server {
    int listen_fd;
    pthread_t thread;
    int running;
    int thread_started;
    uint16_t port;
    struct lantern_http_server_callbacks callbacks;
};

void lantern_http_server_init(struct lantern_http_server *server);
void lantern_http_server_reset(struct lantern_http_server *server);
int lantern_http_server_start(struct lantern_http_server *server, const struct lantern_http_server_config *config);
void lantern_http_server_stop(struct lantern_http_server *server);

#ifdef __cplusplus
}
#endif

#endif /* LANTERN_HTTP_SERVER_H */
