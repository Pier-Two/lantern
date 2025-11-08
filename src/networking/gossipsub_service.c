#include "lantern/networking/gossipsub_service.h"

#include <limits.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "lantern/consensus/ssz.h"
#include "lantern/encoding/snappy.h"
#include "lantern/networking/gossip.h"
#include "lantern/networking/gossip_payloads.h"
#include "lantern/support/log.h"
#include "lantern/support/strings.h"
#include "ssz_constants.h"

#include "libp2p/errors.h"
#include "libp2p/host.h"
#include "protocol/gossipsub/gossipsub.h"

#define LANTERN_GOSSIPSUB_TOPIC_CAP 128u

static void describe_peer_id(const peer_id_t *peer, char *buffer, size_t length) {
    if (!buffer || length == 0) {
        return;
    }
    if (!peer) {
        buffer[0] = '\0';
        return;
    }
    int written = peer_id_to_string(peer, PEER_ID_FMT_BASE58_LEGACY, buffer, length);
    if (written < 0) {
        buffer[0] = '\0';
    }
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
            scratch = (uint8_t *)malloc(expected);
            if (!scratch) {
                return LIBP2P_ERR_INTERNAL;
            }
            scratch_len = expected;
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
        free(scratch);
        return LIBP2P_ERR_INTERNAL;
    }

    free(scratch);
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

static libp2p_gossipsub_validation_result_t gossipsub_block_validator(
    const libp2p_gossipsub_message_t *msg,
    void *user_data) {
    struct lantern_gossipsub_service *service = (struct lantern_gossipsub_service *)user_data;
    if (!service || !msg) {
        return LIBP2P_GOSSIPSUB_VALIDATION_REJECT;
    }
    if (!service->block_handler || !msg->data || msg->data_len == 0) {
        return LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT;
    }

    LanternSignedBlock block;
    memset(&block, 0, sizeof(block));
    lantern_block_body_init(&block.message.body);

    libp2p_gossipsub_validation_result_t result = LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT;
    char peer_text[128];
    describe_peer_id(msg->from, peer_text, sizeof(peer_text));
    const struct lantern_log_metadata meta = {.peer = peer_text[0] ? peer_text : NULL};

    lantern_log_debug(
        "gossip",
        &meta,
        "block gossip message received bytes=%zu",
        msg->data_len);
    if (lantern_gossip_decode_signed_block_snappy(&block, msg->data, msg->data_len) != 0) {
        lantern_log_warn(
            "gossip",
            &meta,
            "failed to decode gossip block payload bytes=%zu",
            msg->data_len);
        result = LIBP2P_GOSSIPSUB_VALIDATION_REJECT;
        goto cleanup;
    }

    if (service->block_handler(&block, msg->from, service->block_handler_user_data) != 0) {
        result = LIBP2P_GOSSIPSUB_VALIDATION_IGNORE;
    }
    char block_root_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
    if (lantern_bytes_to_hex(
            block.message.parent_root.bytes,
            LANTERN_ROOT_SIZE,
            block_root_hex,
            sizeof(block_root_hex),
            1)
        != 0) {
        block_root_hex[0] = '\0';
    }
    lantern_log_debug(
        "gossip",
        &meta,
        "accepted block gossip slot=%" PRIu64 " proposer=%" PRIu64 " parent=%s",
        block.message.slot,
        block.message.proposer_index,
        block_root_hex[0] ? block_root_hex : "0x0");

cleanup:
    lantern_block_body_reset(&block.message.body);
    return result;
}

static libp2p_gossipsub_validation_result_t gossipsub_vote_validator(
    const libp2p_gossipsub_message_t *msg,
    void *user_data) {
    struct lantern_gossipsub_service *service = (struct lantern_gossipsub_service *)user_data;
    if (!service || !msg) {
        return LIBP2P_GOSSIPSUB_VALIDATION_REJECT;
    }
    if (!service->vote_handler || !msg->data || msg->data_len == 0) {
        return LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT;
    }

    LanternSignedVote vote;
    memset(&vote, 0, sizeof(vote));

    libp2p_gossipsub_validation_result_t result = LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT;
    char peer_text[128];
    describe_peer_id(msg->from, peer_text, sizeof(peer_text));
    const struct lantern_log_metadata meta = {.peer = peer_text[0] ? peer_text : NULL};

    lantern_log_debug(
        "gossip",
        &meta,
        "vote gossip message received bytes=%zu",
        msg->data_len);
    if (lantern_gossip_decode_signed_vote_snappy(&vote, msg->data, msg->data_len) != 0) {
        lantern_log_warn(
            "gossip",
            &meta,
            "failed to decode gossip vote payload bytes=%zu",
            msg->data_len);
        result = LIBP2P_GOSSIPSUB_VALIDATION_REJECT;
        goto cleanup;
    }

    if (service->vote_handler(&vote, msg->from, service->vote_handler_user_data) != 0) {
        result = LIBP2P_GOSSIPSUB_VALIDATION_IGNORE;
    }
    char head_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
    if (lantern_bytes_to_hex(
            vote.data.head.root.bytes,
            LANTERN_ROOT_SIZE,
            head_hex,
            sizeof(head_hex),
            1)
        != 0) {
        head_hex[0] = '\0';
    }
    lantern_log_debug(
        "gossip",
        &meta,
        "accepted vote gossip validator=%" PRIu64 " slot=%" PRIu64 " head=%s",
        vote.validator_id,
        vote.data.slot,
        head_hex[0] ? head_hex : "0x0");

cleanup:
    return result;
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
        if (service->block_validator_handle) {
            (void)libp2p_gossipsub_remove_validator(service->gossipsub, service->block_validator_handle);
        }
        if (service->vote_validator_handle) {
            (void)libp2p_gossipsub_remove_validator(service->gossipsub, service->vote_validator_handle);
        }
        if (service->vote_legacy_validator_handle) {
            (void)libp2p_gossipsub_remove_validator(service->gossipsub, service->vote_legacy_validator_handle);
        }
    }
    service->block_validator_handle = NULL;
    service->vote_validator_handle = NULL;
    service->vote_legacy_validator_handle = NULL;
    if (service->gossipsub) {
        libp2p_gossipsub_stop(service->gossipsub);
        libp2p_gossipsub_free(service->gossipsub);
        service->gossipsub = NULL;
    }
    memset(service->block_topic, 0, sizeof(service->block_topic));
    memset(service->vote_topic, 0, sizeof(service->vote_topic));
    memset(service->legacy_vote_topic, 0, sizeof(service->legacy_vote_topic));
    service->publish_hook = NULL;
    service->publish_hook_user_data = NULL;
    service->loopback_only = 0;
}

int lantern_gossipsub_service_start(
    struct lantern_gossipsub_service *service,
    const struct lantern_gossipsub_config *config) {
    if (!service || !config || !config->host || !config->devnet) {
        return -1;
    }
    int previous_loopback = service->loopback_only;
    int (*previous_publish_hook)(const char *, const uint8_t *, size_t, void *) = service->publish_hook;
    void *previous_publish_user_data = service->publish_hook_user_data;
    lantern_gossipsub_block_handler previous_block_handler = service->block_handler;
    void *previous_block_user_data = service->block_handler_user_data;
    lantern_gossipsub_vote_handler previous_vote_handler = service->vote_handler;
    void *previous_vote_user_data = service->vote_handler_user_data;

    lantern_gossipsub_service_reset(service);
    service->loopback_only = previous_loopback;
    service->publish_hook = previous_publish_hook;
    service->publish_hook_user_data = previous_publish_user_data;
    service->block_handler = previous_block_handler;
    service->block_handler_user_data = previous_block_user_data;
    service->vote_handler = previous_vote_handler;
    service->vote_handler_user_data = previous_vote_user_data;

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
    if (snprintf(
            service->legacy_vote_topic,
            sizeof(service->legacy_vote_topic),
            "/leanconsensus/%s/vote/ssz_snappy",
            config->devnet)
        < 0) {
        return -1;
    }

    libp2p_gossipsub_config_t cfg;
    if (libp2p_gossipsub_config_default(&cfg) != LIBP2P_ERR_OK) {
        return -1;
    }
    cfg.enable_flood_publish = true;

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
    if (strcmp(service->legacy_vote_topic, service->vote_topic) != 0) {
        if (subscribe_topic(service, service->legacy_vote_topic) != 0) {
            lantern_gossipsub_service_reset(service);
            return -1;
        }
    }

    if (service->block_handler) {
        libp2p_gossipsub_validator_def_t def = {
            .struct_size = sizeof(def),
            .type = LIBP2P_GOSSIPSUB_VALIDATOR_SYNC,
            .sync_fn = gossipsub_block_validator,
            .async_fn = NULL,
            .user_data = service
        };
        if (libp2p_gossipsub_add_validator(service->gossipsub, service->block_topic, &def, &service->block_validator_handle)
            != LIBP2P_ERR_OK) {
            lantern_log_error(
                "gossip",
                NULL,
                "failed to register block gossip validator");
            lantern_gossipsub_service_reset(service);
            return -1;
        }
    }

    if (service->vote_handler) {
        libp2p_gossipsub_validator_def_t def = {
            .struct_size = sizeof(def),
            .type = LIBP2P_GOSSIPSUB_VALIDATOR_SYNC,
            .sync_fn = gossipsub_vote_validator,
            .async_fn = NULL,
            .user_data = service
        };
        if (libp2p_gossipsub_add_validator(service->gossipsub, service->vote_topic, &def, &service->vote_validator_handle)
            != LIBP2P_ERR_OK) {
            lantern_log_error(
                "gossip",
                NULL,
                "failed to register vote gossip validator");
            lantern_gossipsub_service_reset(service);
            return -1;
        }
    }
    if (service->vote_handler && strcmp(service->legacy_vote_topic, service->vote_topic) != 0) {
        libp2p_gossipsub_validator_def_t def = {
            .struct_size = sizeof(def),
            .type = LIBP2P_GOSSIPSUB_VALIDATOR_SYNC,
            .sync_fn = gossipsub_vote_validator,
            .async_fn = NULL,
            .user_data = service
        };
        if (libp2p_gossipsub_add_validator(service->gossipsub, service->legacy_vote_topic, &def, &service->vote_legacy_validator_handle)
            != LIBP2P_ERR_OK) {
            lantern_log_error(
                "gossip",
                NULL,
                "failed to register legacy vote gossip validator");
            lantern_gossipsub_service_reset(service);
            return -1;
        }
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
    if (!service || !topic || !payload || payload_len == 0) {
        return -1;
    }
    if (service->publish_hook) {
        if (service->publish_hook(topic, payload, payload_len, service->publish_hook_user_data) != 0) {
            return -1;
        }
    }
    if (service->loopback_only) {
        return 0;
    }
    if (!service->gossipsub) {
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
    if (publish_rc == 0 && strcmp(service->legacy_vote_topic, service->vote_topic) != 0) {
        int legacy_rc = publish_payload(service, service->legacy_vote_topic, compressed, written);
        if (legacy_rc != 0) {
            /* propagate error but keep primary success */
            publish_rc = legacy_rc;
        }
    }
    free(compressed);
    return publish_rc;
}

void lantern_gossipsub_service_set_publish_hook(
    struct lantern_gossipsub_service *service,
    int (*hook)(const char *topic, const uint8_t *payload, size_t payload_len, void *user_data),
    void *user_data) {
    if (!service) {
        return;
    }
    service->publish_hook = hook;
    service->publish_hook_user_data = user_data;
}

void lantern_gossipsub_service_set_loopback_only(
    struct lantern_gossipsub_service *service,
    int loopback_only) {
    if (!service) {
        return;
    }
    service->loopback_only = loopback_only ? 1 : 0;
}

void lantern_gossipsub_service_set_block_handler(
    struct lantern_gossipsub_service *service,
    lantern_gossipsub_block_handler handler,
    void *user_data) {
    if (!service) {
        return;
    }
    service->block_handler = handler;
    service->block_handler_user_data = user_data;
}

void lantern_gossipsub_service_set_vote_handler(
    struct lantern_gossipsub_service *service,
    lantern_gossipsub_vote_handler handler,
    void *user_data) {
    if (!service) {
        return;
    }
    service->vote_handler = handler;
    service->vote_handler_user_data = user_data;
}
