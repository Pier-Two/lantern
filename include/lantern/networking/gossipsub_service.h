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
    int (*publish_hook)(const char *topic, const uint8_t *payload, size_t payload_len, void *user_data);
    void *publish_hook_user_data;
    int loopback_only;
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
void lantern_gossipsub_service_set_publish_hook(
    struct lantern_gossipsub_service *service,
    int (*hook)(const char *topic, const uint8_t *payload, size_t payload_len, void *user_data),
    void *user_data);
void lantern_gossipsub_service_set_loopback_only(
    struct lantern_gossipsub_service *service,
    int loopback_only);

#ifdef __cplusplus
}
#endif

#endif /* LANTERN_NETWORKING_GOSSIPSUB_SERVICE_H */
