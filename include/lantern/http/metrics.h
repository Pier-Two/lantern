#ifndef LANTERN_HTTP_METRICS_H
#define LANTERN_HTTP_METRICS_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "lantern/metrics/lean_metrics.h"

#ifdef __cplusplus
extern "C" {
#endif

struct lantern_metrics_snapshot {
    uint64_t lean_head_slot;
    uint64_t lean_latest_justified_slot;
    uint64_t lean_latest_finalized_slot;
    size_t lean_validators_count;
    struct lean_metrics_snapshot lean_metrics;
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
