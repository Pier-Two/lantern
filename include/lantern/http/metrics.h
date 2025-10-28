#ifndef LANTERN_HTTP_METRICS_H
#define LANTERN_HTTP_METRICS_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "lantern/consensus/containers.h"

#ifdef __cplusplus
extern "C" {
#endif

struct lantern_metrics_snapshot {
    char node_id[64];
    uint64_t head_slot;
    LanternRoot head_root;
    LanternCheckpoint justified;
    LanternCheckpoint finalized;
    size_t known_peers;
    size_t connected_peers;
    size_t gossip_topics;
    size_t gossip_validation_failures;
    size_t validators_total;
    size_t validators_active;
};

struct lantern_metrics_callbacks {
    void *context;
    int (*snapshot)(void *context, struct lantern_metrics_snapshot *out_snapshot);
};

struct lantern_metrics_server {
    int listen_fd;
    pthread_t thread;
    int running;
    int thread_started;
    uint16_t port;
    struct lantern_metrics_callbacks callbacks;
};

void lantern_metrics_server_init(struct lantern_metrics_server *server);
void lantern_metrics_server_reset(struct lantern_metrics_server *server);
int lantern_metrics_server_start(
    struct lantern_metrics_server *server,
    uint16_t port,
    const struct lantern_metrics_callbacks *callbacks);
void lantern_metrics_server_stop(struct lantern_metrics_server *server);

#ifdef __cplusplus
}
#endif

#endif /* LANTERN_HTTP_METRICS_H */
