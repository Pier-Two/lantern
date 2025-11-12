#ifndef LANTERN_NETWORKING_REQRESP_SERVICE_H
#define LANTERN_NETWORKING_REQRESP_SERVICE_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "lantern/networking/messages.h"
#include "libp2p/stream.h"
#include "peer_id/peer_id.h"

#define LANTERN_REQRESP_STATUS_PROTOCOL "/leanconsensus/req/status/1/"
#define LANTERN_REQRESP_STATUS_PROTOCOL_LEGACY "/leanconsensus/req/status/1/ssz_snappy"
#define LANTERN_REQRESP_BLOCKS_BY_ROOT_PROTOCOL "/leanconsensus/req/blocks_by_root/1/"
#define LANTERN_REQRESP_BLOCKS_BY_ROOT_PROTOCOL_LEGACY "/leanconsensus/req/lean_blocks_by_root/1/ssz_snappy"
#define LANTERN_REQRESP_STATUS_PREVIEW_BYTES 64u
#define LANTERN_REQRESP_MAX_CHUNK_BYTES (1u << 22)
#define LANTERN_REQRESP_MAX_CONTEXT_BYTES (1u << 20)
#define LANTERN_REQRESP_HEADER_MAX_BYTES 10u
#define LANTERN_REQRESP_STALL_TIMEOUT_MS 2000u
#define LANTERN_REQRESP_RESPONSE_SUCCESS 0u
#define LANTERN_REQRESP_RESPONSE_RESOURCE_UNAVAILABLE 1u
#define LANTERN_REQRESP_RESPONSE_INVALID_REQUEST 2u
#define LANTERN_REQRESP_RESPONSE_SERVER_ERROR 3u
#define LANTERN_REQRESP_MAX_PEER_PREFS 64u
#define LANTERN_REQRESP_PREF_FLAG_LEGACY_NO_CODE 0x01u

#define LANTERN_STATUS_PROTOCOL_ID LANTERN_REQRESP_STATUS_PROTOCOL
#define LANTERN_STATUS_PROTOCOL_ID_LEGACY LANTERN_REQRESP_STATUS_PROTOCOL_LEGACY
#define LANTERN_BLOCKS_BY_ROOT_PROTOCOL_ID LANTERN_REQRESP_BLOCKS_BY_ROOT_PROTOCOL
#define LANTERN_BLOCKS_BY_ROOT_PROTOCOL_ID_LEGACY LANTERN_REQRESP_BLOCKS_BY_ROOT_PROTOCOL_LEGACY
#define LANTERN_STATUS_PREVIEW_BYTES LANTERN_REQRESP_STATUS_PREVIEW_BYTES

struct lantern_reqresp_peer_pref {
    char peer_id[128];
    uint8_t flags;
};

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
    void (*status_failure)(
        void *context,
        const char *peer_id,
        int error);
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
    struct libp2p_protocol_server *status_legacy_server;
    struct libp2p_protocol_server *blocks_server;
    struct libp2p_protocol_server *blocks_legacy_server;
    struct libp2p_subscription *event_subscription;
    struct lantern_reqresp_peer_pref peer_prefs[LANTERN_REQRESP_MAX_PEER_PREFS];
    size_t peer_pref_count;
    size_t peer_pref_cursor;
    int lock_initialized;
    pthread_mutex_t lock;
};

#ifdef __cplusplus
extern "C" {
#endif

void lantern_reqresp_service_init(struct lantern_reqresp_service *service);
void lantern_reqresp_service_reset(struct lantern_reqresp_service *service);
int lantern_reqresp_service_request_status(
    struct lantern_reqresp_service *service,
    const peer_id_t *peer_id,
    const char *peer_id_text);
int lantern_reqresp_service_start(
    struct lantern_reqresp_service *service,
    const struct lantern_reqresp_service_config *config);

int lantern_reqresp_read_response_chunk(
    struct lantern_reqresp_service *service,
    libp2p_stream_t *stream,
    int expect_response_code,
    uint8_t **out_data,
    size_t *out_len,
    ssize_t *out_err,
    uint8_t *out_response_code);
void lantern_reqresp_service_hint_peer_legacy(
    struct lantern_reqresp_service *service,
    const char *peer_id_text,
    int legacy_no_code);
int lantern_reqresp_service_peer_prefers_legacy(
    const struct lantern_reqresp_service *service,
    const char *peer_id_text);

#ifdef __cplusplus
}
#endif

#endif /* LANTERN_NETWORKING_REQRESP_SERVICE_H */
