#ifndef LANTERN_NETWORKING_REQRESP_SERVICE_H
#define LANTERN_NETWORKING_REQRESP_SERVICE_H

#include <pthread.h>
#include <stddef.h>

#include "lantern/networking/messages.h"

struct libp2p_host;
struct libp2p_protocol_server;
struct libp2p_subscription;

struct lantern_reqresp_service_callbacks {
    void *context;
    int (*build_status)(void *context, LanternStatusMessage *out_status);
    int (*handle_status)(
        void *context,
        const LanternStatusMessage *peer_status,
        const char *peer_id);
    int (*collect_blocks)(
        void *context,
        const LanternRoot *roots,
        size_t root_count,
        LanternBlocksByRootResponse *out_blocks);
};

struct lantern_reqresp_service_config {
    struct libp2p_host *host;
    const struct lantern_reqresp_service_callbacks *callbacks;
};

struct lantern_reqresp_service {
    struct libp2p_host *host;
    struct lantern_reqresp_service_callbacks callbacks;
    struct libp2p_protocol_server *status_server;
    struct libp2p_protocol_server *blocks_server;
    struct libp2p_subscription *event_subscription;
    int lock_initialized;
    pthread_mutex_t lock;
};

#ifdef __cplusplus
extern "C" {
#endif

void lantern_reqresp_service_init(struct lantern_reqresp_service *service);
void lantern_reqresp_service_reset(struct lantern_reqresp_service *service);
int lantern_reqresp_service_start(
    struct lantern_reqresp_service *service,
    const struct lantern_reqresp_service_config *config);

#ifdef __cplusplus
}
#endif

#endif /* LANTERN_NETWORKING_REQRESP_SERVICE_H */
