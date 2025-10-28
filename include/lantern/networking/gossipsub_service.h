#ifndef LANTERN_NETWORKING_GOSSIPSUB_SERVICE_H
#define LANTERN_NETWORKING_GOSSIPSUB_SERVICE_H

#include <stddef.h>
#include <stdint.h>

#include "lantern/consensus/containers.h"

struct libp2p_host;
typedef struct libp2p_gossipsub libp2p_gossipsub_t;

#ifdef __cplusplus
extern "C" {
#endif

struct lantern_gossipsub_config {
    struct libp2p_host *host;
    const char *devnet;
};

struct lantern_gossipsub_service {
    libp2p_gossipsub_t *gossipsub;
    char block_topic[128];
    char vote_topic[128];
    uint8_t *scratch;
    size_t scratch_capacity;
};

void lantern_gossipsub_service_init(struct lantern_gossipsub_service *service);
void lantern_gossipsub_service_reset(struct lantern_gossipsub_service *service);
int lantern_gossipsub_service_start(
    struct lantern_gossipsub_service *service,
    const struct lantern_gossipsub_config *config);
int lantern_gossipsub_service_publish_block(
    struct lantern_gossipsub_service *service,
    const LanternSignedBlock *block);
int lantern_gossipsub_service_publish_vote(
    struct lantern_gossipsub_service *service,
    const LanternSignedVote *vote);

#ifdef __cplusplus
}
#endif

#endif /* LANTERN_NETWORKING_GOSSIPSUB_SERVICE_H */
