#include "lantern/networking/gossipsub_service.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "lantern/consensus/ssz.h"
#include "lantern/encoding/snappy.h"
#include "lantern/networking/gossip.h"
#include "lantern/networking/gossip_payloads.h"
#include "lantern/support/log.h"
#include "ssz_constants.h"

#include "libp2p/errors.h"
#include "libp2p/host.h"
#include "protocol/gossipsub/gossipsub.h"

#define LANTERN_GOSSIPSUB_TOPIC_CAP 128u

static int ensure_scratch_capacity(struct lantern_gossipsub_service *service, size_t required) {
    if (!service) {
        return -1;
    }
    if (required == 0) {
        return 0;
    }
    if (service->scratch_capacity >= required) {
        return 0;
    }
    uint8_t *resized = (uint8_t *)realloc(service->scratch, required);
    if (!resized) {
        return -1;
    }
    service->scratch = resized;
    service->scratch_capacity = required;
    return 0;
}

static size_t signed_block_min_capacity(const LanternSignedBlock *block) {
    if (!block) {
        return 0;
    }
    size_t base = (SSZ_BYTE_SIZE_OF_UINT32 + LANTERN_SIGNATURE_SIZE)
        + (SSZ_BYTE_SIZE_OF_UINT64 * 2u)
        + (LANTERN_ROOT_SIZE * 2u)
        + SSZ_BYTE_SIZE_OF_UINT32
        + SSZ_BYTE_SIZE_OF_UINT32;
    size_t att_count = block->message.body.attestations.length;
    if (att_count > LANTERN_MAX_ATTESTATIONS) {
        return 0;
    }
    size_t att_bytes = att_count * LANTERN_SIGNED_VOTE_SSZ_SIZE;
    if (att_bytes > SIZE_MAX - base) {
        return 0;
    }
    return base + att_bytes;
}

static libp2p_err_t lantern_gossipsub_message_id_cb(
    const libp2p_gossipsub_message_t *msg,
    uint8_t **out_id,
    size_t *out_len,
    void *user_data) {
    if (!msg || !out_id || !out_len) {
        return LIBP2P_ERR_NULL_PTR;
    }
    struct lantern_gossipsub_service *service = (struct lantern_gossipsub_service *)user_data;
    if (!service) {
        return LIBP2P_ERR_NULL_PTR;
    }
    const char *topic = msg->topic.topic;
    if (!topic) {
        return LIBP2P_ERR_INTERNAL;
    }

    uint8_t *scratch = NULL;
    size_t scratch_len = 0;
    if (msg->data && msg->data_len > 0) {
        size_t expected = 0;
        if (lantern_snappy_uncompressed_length(msg->data, msg->data_len, &expected) == LANTERN_SNAPPY_OK && expected > 0) {
            if (ensure_scratch_capacity(service, expected) != 0) {
                return LIBP2P_ERR_INTERNAL;
            }
            scratch = service->scratch;
            scratch_len = service->scratch_capacity;
        }
    }

    LanternGossipMessageId id;
    if (lantern_gossip_compute_message_id(
            &id,
            (const uint8_t *)topic,
            strlen(topic),
            msg->data,
            msg->data_len,
            scratch,
            scratch_len,
            NULL)
        != 0) {
        return LIBP2P_ERR_INTERNAL;
    }

    uint8_t *buffer = (uint8_t *)malloc(LANTERN_GOSSIP_MESSAGE_ID_SIZE);
    if (!buffer) {
        return LIBP2P_ERR_INTERNAL;
    }
    memcpy(buffer, id.bytes, LANTERN_GOSSIP_MESSAGE_ID_SIZE);
    *out_id = buffer;
    *out_len = LANTERN_GOSSIP_MESSAGE_ID_SIZE;
    return LIBP2P_ERR_OK;
}

static int subscribe_topic(
    struct lantern_gossipsub_service *service,
    const char *topic) {
    if (!service || !service->gossipsub || !topic) {
        return -1;
    }
    libp2p_gossipsub_topic_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.struct_size = sizeof(cfg);
    cfg.descriptor.struct_size = sizeof(cfg.descriptor);
    cfg.descriptor.topic = topic;
    cfg.message_id_fn = lantern_gossipsub_message_id_cb;
    cfg.message_id_user_data = service;
    libp2p_err_t err = libp2p_gossipsub_subscribe(service->gossipsub, &cfg);
    return err == LIBP2P_ERR_OK ? 0 : -1;
}

void lantern_gossipsub_service_init(struct lantern_gossipsub_service *service) {
    if (!service) {
        return;
    }
    memset(service, 0, sizeof(*service));
}

void lantern_gossipsub_service_reset(struct lantern_gossipsub_service *service) {
    if (!service) {
        return;
    }
    if (service->gossipsub) {
        libp2p_gossipsub_stop(service->gossipsub);
        libp2p_gossipsub_free(service->gossipsub);
        service->gossipsub = NULL;
    }
    free(service->scratch);
    service->scratch = NULL;
    service->scratch_capacity = 0;
    memset(service->block_topic, 0, sizeof(service->block_topic));
    memset(service->vote_topic, 0, sizeof(service->vote_topic));
}

int lantern_gossipsub_service_start(
    struct lantern_gossipsub_service *service,
    const struct lantern_gossipsub_config *config) {
    if (!service || !config || !config->host || !config->devnet) {
        return -1;
    }
    lantern_gossipsub_service_reset(service);

    if (lantern_gossip_topic_format(
            LANTERN_GOSSIP_TOPIC_BLOCK,
            config->devnet,
            service->block_topic,
            sizeof(service->block_topic))
        != 0) {
        return -1;
    }
    if (lantern_gossip_topic_format(
            LANTERN_GOSSIP_TOPIC_VOTE,
            config->devnet,
            service->vote_topic,
            sizeof(service->vote_topic))
        != 0) {
        return -1;
    }

    libp2p_gossipsub_config_t cfg;
    if (libp2p_gossipsub_config_default(&cfg) != LIBP2P_ERR_OK) {
        return -1;
    }

    libp2p_gossipsub_t *gs = NULL;
    if (libp2p_gossipsub_new(config->host, &cfg, &gs) != LIBP2P_ERR_OK || !gs) {
        return -1;
    }
    if (libp2p_gossipsub_start(gs) != LIBP2P_ERR_OK) {
        libp2p_gossipsub_free(gs);
        return -1;
    }
    service->gossipsub = gs;
    if (subscribe_topic(service, service->block_topic) != 0) {
        lantern_gossipsub_service_reset(service);
        return -1;
    }
    if (subscribe_topic(service, service->vote_topic) != 0) {
        lantern_gossipsub_service_reset(service);
        return -1;
    }
    lantern_log_info(
        "network",
        &(const struct lantern_log_metadata){.peer = config->devnet},
        "gossipsub topics ready");
    return 0;
}

static int publish_payload(
    struct lantern_gossipsub_service *service,
    const char *topic,
    const uint8_t *payload,
    size_t payload_len) {
    if (!service || !service->gossipsub || !topic || !payload || payload_len == 0) {
        return -1;
    }
    libp2p_gossipsub_message_t message;
    memset(&message, 0, sizeof(message));
    message.topic.struct_size = sizeof(message.topic);
    message.topic.topic = topic;
    message.data = payload;
    message.data_len = payload_len;
    libp2p_err_t err = libp2p_gossipsub_publish(service->gossipsub, &message);
    return err == LIBP2P_ERR_OK ? 0 : -1;
}

int lantern_gossipsub_service_publish_block(
    struct lantern_gossipsub_service *service,
    const LanternSignedBlock *block) {
    if (!service || !block) {
        return -1;
    }
    size_t raw_capacity = signed_block_min_capacity(block);
    if (raw_capacity == 0) {
        return -1;
    }
    size_t max_compressed = 0;
    if (lantern_snappy_max_compressed_size(raw_capacity, &max_compressed) != LANTERN_SNAPPY_OK) {
        return -1;
    }
    uint8_t *compressed = (uint8_t *)malloc(max_compressed);
    if (!compressed) {
        return -1;
    }
    size_t written = 0;
    int encode_rc = lantern_gossip_encode_signed_block_snappy(block, compressed, max_compressed, &written);
    if (encode_rc != 0 || written == 0) {
        free(compressed);
        return -1;
    }
    int publish_rc = publish_payload(service, service->block_topic, compressed, written);
    free(compressed);
    return publish_rc;
}

int lantern_gossipsub_service_publish_vote(
    struct lantern_gossipsub_service *service,
    const LanternSignedVote *vote) {
    if (!service || !vote) {
        return -1;
    }
    size_t max_compressed = 0;
    if (lantern_snappy_max_compressed_size(LANTERN_SIGNED_VOTE_SSZ_SIZE, &max_compressed) != LANTERN_SNAPPY_OK) {
        return -1;
    }
    uint8_t *compressed = (uint8_t *)malloc(max_compressed);
    if (!compressed) {
        return -1;
    }
    size_t written = 0;
    int encode_rc = lantern_gossip_encode_signed_vote_snappy(vote, compressed, max_compressed, &written);
    if (encode_rc != 0 || written == 0) {
        free(compressed);
        return -1;
    }
    int publish_rc = publish_payload(service, service->vote_topic, compressed, written);
    free(compressed);
    return publish_rc;
}
