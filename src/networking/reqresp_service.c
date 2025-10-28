#include "lantern/networking/reqresp_service.h"

#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "lantern/encoding/snappy.h"
#include "lantern/consensus/ssz.h"
#include "lantern/support/log.h"

#include "libp2p/events.h"
#include "libp2p/host.h"
#include "libp2p/protocol.h"
#include "libp2p/protocol_listen.h"
#include "libp2p/stream.h"

#include "peer_id/peer_id.h"

#include "ssz_constants.h"

#define LANTERN_STATUS_PROTOCOL_ID "/leanconsensus/req/status/1/ssz_snappy"
#define LANTERN_BLOCKS_BY_ROOT_PROTOCOL_ID "/leanconsensus/req/blocks_by_root/1/ssz_snappy"

struct status_stream_ctx {
    struct lantern_reqresp_service *service;
    libp2p_stream_t *stream;
};

struct blocks_stream_ctx {
    struct lantern_reqresp_service *service;
    libp2p_stream_t *stream;
};

static void lantern_reqresp_service_clear(struct lantern_reqresp_service *service) {
    if (!service) {
        return;
    }
    service->host = NULL;
    service->callbacks.context = NULL;
    service->callbacks.build_status = NULL;
    service->callbacks.handle_status = NULL;
    service->callbacks.collect_blocks = NULL;
    service->status_server = NULL;
    service->blocks_server = NULL;
    service->event_subscription = NULL;
}

void lantern_reqresp_service_init(struct lantern_reqresp_service *service) {
    if (!service) {
        return;
    }
    memset(service, 0, sizeof(*service));
    service->lock_initialized = 0;
}

static void destroy_lock(struct lantern_reqresp_service *service) {
    if (!service || !service->lock_initialized) {
        return;
    }
    pthread_mutex_destroy(&service->lock);
    service->lock_initialized = 0;
}

void lantern_reqresp_service_reset(struct lantern_reqresp_service *service) {
    if (!service) {
        return;
    }

    struct libp2p_host *host = service->host;
    if (service->event_subscription && host) {
        libp2p_event_unsubscribe(host, service->event_subscription);
    }

    if (service->status_server && host) {
        (void)libp2p_host_unlisten(host, service->status_server);
    }

    if (service->blocks_server && host) {
        (void)libp2p_host_unlisten(host, service->blocks_server);
    }

    destroy_lock(service);
    lantern_reqresp_service_clear(service);
}

static void ensure_lock(struct lantern_reqresp_service *service) {
    if (!service) {
        return;
    }
    if (!service->lock_initialized) {
        if (pthread_mutex_init(&service->lock, NULL) == 0) {
            service->lock_initialized = 1;
        }
    }
}

static void describe_peer(const peer_id_t *peer, char *buffer, size_t length) {
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

static int read_stream_fully(libp2p_stream_t *stream, uint8_t **out_data, size_t *out_len) {
    if (!stream || !out_data || !out_len) {
        return -1;
    }
    size_t capacity = 1024;
    size_t length = 0;
    uint8_t *buffer = (uint8_t *)malloc(capacity);
    if (!buffer) {
        return -1;
    }
    while (true) {
        uint8_t chunk[1024];
        ssize_t read_len = libp2p_stream_read(stream, chunk, sizeof(chunk));
        if (read_len > 0) {
            if (length + (size_t)read_len > capacity) {
                size_t next_capacity = capacity * 2u;
                while (next_capacity < length + (size_t)read_len) {
                    if (next_capacity > SIZE_MAX / 2u) {
                        free(buffer);
                        return -1;
                    }
                    next_capacity *= 2u;
                }
                uint8_t *resized = (uint8_t *)realloc(buffer, next_capacity);
                if (!resized) {
                    free(buffer);
                    return -1;
                }
                buffer = resized;
                capacity = next_capacity;
            }
            memcpy(buffer + length, chunk, (size_t)read_len);
            length += (size_t)read_len;
            continue;
        }
        if (read_len == 0) {
            break;
        }
        free(buffer);
        return -1;
    }
    *out_data = buffer;
    *out_len = length;
    return 0;
}

static int write_stream_all(libp2p_stream_t *stream, const uint8_t *data, size_t length) {
    if (!stream || (!data && length > 0)) {
        return -1;
    }
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = libp2p_stream_write(stream, data + offset, length - offset);
        if (written <= 0) {
            return -1;
        }
        offset += (size_t)written;
    }
    return 0;
}

static void close_stream(libp2p_stream_t *stream) {
    if (!stream) {
        return;
    }
    libp2p_stream_close(stream);
    libp2p_stream_free(stream);
}

static void log_stream_error(const char *phase, const char *protocol_id, const char *peer_id) {
    lantern_log_error(
        "network",
        &(const struct lantern_log_metadata){.peer = peer_id},
        "%s %s request failed",
        protocol_id ? protocol_id : "unknown",
        phase ? phase : "processing");
}

static void handle_remote_status(
    struct lantern_reqresp_service *service,
    const LanternStatusMessage *status,
    const char *peer_text) {
    if (!service || !status) {
        return;
    }
    if (service->callbacks.handle_status) {
        service->callbacks.handle_status(service->callbacks.context, status, peer_text);
    }
}

static void *status_worker(void *arg) {
    struct status_stream_ctx *ctx = (struct status_stream_ctx *)arg;
    if (!ctx) {
        return NULL;
    }
    struct lantern_reqresp_service *service = ctx->service;
    libp2p_stream_t *stream = ctx->stream;
    free(ctx);

    if (!service || !stream) {
        close_stream(stream);
        return NULL;
    }

    libp2p_stream_set_read_interest(stream, true);

    uint8_t *request = NULL;
    size_t request_len = 0;
    if (read_stream_fully(stream, &request, &request_len) != 0) {
        log_stream_error("read", LANTERN_STATUS_PROTOCOL_ID, NULL);
        close_stream(stream);
        return NULL;
    }

    LanternStatusMessage remote_status;
    memset(&remote_status, 0, sizeof(remote_status));
    if (lantern_network_status_decode_snappy(&remote_status, request, request_len) != 0) {
        free(request);
        log_stream_error("decode", LANTERN_STATUS_PROTOCOL_ID, NULL);
        close_stream(stream);
        return NULL;
    }
    free(request);

    char peer_text[128];
    describe_peer(libp2p_stream_remote_peer(stream), peer_text, sizeof(peer_text));
    handle_remote_status(service, &remote_status, peer_text);

    LanternStatusMessage response;
    memset(&response, 0, sizeof(response));
    if (!service->callbacks.build_status
        || service->callbacks.build_status(service->callbacks.context, &response) != 0) {
        log_stream_error("status", LANTERN_STATUS_PROTOCOL_ID, peer_text);
        close_stream(stream);
        return NULL;
    }

    size_t max_payload = 0;
    if (lantern_snappy_max_compressed_size(2u * LANTERN_CHECKPOINT_SSZ_SIZE, &max_payload) != LANTERN_SNAPPY_OK) {
        log_stream_error("encode", LANTERN_STATUS_PROTOCOL_ID, peer_text);
        close_stream(stream);
        return NULL;
    }

    uint8_t *buffer = (uint8_t *)malloc(max_payload);
    if (!buffer) {
        log_stream_error("encode", LANTERN_STATUS_PROTOCOL_ID, peer_text);
        close_stream(stream);
        return NULL;
    }

    size_t written = 0;
    if (lantern_network_status_encode_snappy(&response, buffer, max_payload, &written) != 0) {
        free(buffer);
        log_stream_error("encode", LANTERN_STATUS_PROTOCOL_ID, peer_text);
        close_stream(stream);
        return NULL;
    }

    if (write_stream_all(stream, buffer, written) != 0) {
        free(buffer);
        log_stream_error("write", LANTERN_STATUS_PROTOCOL_ID, peer_text);
        close_stream(stream);
        return NULL;
    }
    free(buffer);
    close_stream(stream);

    lantern_log_info(
        "network",
        &(const struct lantern_log_metadata){.peer = peer_text},
        "served status request");
    return NULL;
}

static void *blocks_worker(void *arg) {
    struct blocks_stream_ctx *ctx = (struct blocks_stream_ctx *)arg;
    if (!ctx) {
        return NULL;
    }
    struct lantern_reqresp_service *service = ctx->service;
    libp2p_stream_t *stream = ctx->stream;
    free(ctx);

    if (!service || !stream) {
        close_stream(stream);
        return NULL;
    }

    libp2p_stream_set_read_interest(stream, true);

    uint8_t *request = NULL;
    size_t request_len = 0;
    if (read_stream_fully(stream, &request, &request_len) != 0) {
        log_stream_error("read", LANTERN_BLOCKS_BY_ROOT_PROTOCOL_ID, NULL);
        close_stream(stream);
        return NULL;
    }

    LanternBlocksByRootRequest decoded_request;
    lantern_blocks_by_root_request_init(&decoded_request);
    int decode_rc = lantern_network_blocks_by_root_request_decode_snappy(
        &decoded_request,
        request,
        request_len);
    free(request);
    if (decode_rc != 0) {
        lantern_blocks_by_root_request_reset(&decoded_request);
        log_stream_error("decode", LANTERN_BLOCKS_BY_ROOT_PROTOCOL_ID, NULL);
        close_stream(stream);
        return NULL;
    }

    LanternBlocksByRootResponse response;
    lantern_blocks_by_root_response_init(&response);

    int collect_rc = 0;
    if (service->callbacks.collect_blocks) {
        collect_rc = service->callbacks.collect_blocks(
            service->callbacks.context,
            decoded_request.roots.items,
            decoded_request.roots.length,
            &response);
    }
    lantern_blocks_by_root_request_reset(&decoded_request);

    if (collect_rc != 0) {
        lantern_blocks_by_root_response_reset(&response);
        log_stream_error("collect", LANTERN_BLOCKS_BY_ROOT_PROTOCOL_ID, NULL);
        close_stream(stream);
        return NULL;
    }

    size_t block_count = response.length;
    size_t buffer_capacity = 4096;
    uint8_t *buffer = NULL;
    size_t written = 0;
    int encode_rc = -1;

    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        uint8_t *resized = (uint8_t *)realloc(buffer, buffer_capacity);
        if (!resized) {
            free(buffer);
            lantern_blocks_by_root_response_reset(&response);
            log_stream_error("encode", LANTERN_BLOCKS_BY_ROOT_PROTOCOL_ID, NULL);
            close_stream(stream);
            return NULL;
        }
        buffer = resized;

        written = 0;
        encode_rc = lantern_network_blocks_by_root_response_encode_snappy(&response, buffer, buffer_capacity, &written);
        if (encode_rc == 0) {
            break;
        }
        buffer_capacity *= 2u;
    }

    lantern_blocks_by_root_response_reset(&response);

    if (encode_rc != 0) {
        free(buffer);
        log_stream_error("encode", LANTERN_BLOCKS_BY_ROOT_PROTOCOL_ID, NULL);
        close_stream(stream);
        return NULL;
    }

    if (write_stream_all(stream, buffer, written) != 0) {
        free(buffer);
        log_stream_error("write", LANTERN_BLOCKS_BY_ROOT_PROTOCOL_ID, NULL);
        close_stream(stream);
        return NULL;
    }
    free(buffer);
    close_stream(stream);

    char peer_text[128];
    describe_peer(libp2p_stream_remote_peer(stream), peer_text, sizeof(peer_text));
    lantern_log_info(
        "network",
        &(const struct lantern_log_metadata){.peer = peer_text},
        "served blocks-by-root request (%zu roots)",
        block_count);
    return NULL;
}

static void status_on_open(libp2p_stream_t *stream, void *user_data) {
    struct lantern_reqresp_service *service = (struct lantern_reqresp_service *)user_data;
    struct status_stream_ctx *ctx = (struct status_stream_ctx *)malloc(sizeof(*ctx));
    if (!ctx) {
        close_stream(stream);
        return;
    }
    ctx->service = service;
    ctx->stream = stream;
    pthread_t thread;
    if (pthread_create(&thread, NULL, status_worker, ctx) != 0) {
        free(ctx);
        close_stream(stream);
        return;
    }
    pthread_detach(thread);
}

static void blocks_on_open(libp2p_stream_t *stream, void *user_data) {
    struct lantern_reqresp_service *service = (struct lantern_reqresp_service *)user_data;
    struct blocks_stream_ctx *ctx = (struct blocks_stream_ctx *)malloc(sizeof(*ctx));
    if (!ctx) {
        close_stream(stream);
        return;
    }
    ctx->service = service;
    ctx->stream = stream;
    pthread_t thread;
    if (pthread_create(&thread, NULL, blocks_worker, ctx) != 0) {
        free(ctx);
        close_stream(stream);
        return;
    }
    pthread_detach(thread);
}

int lantern_reqresp_service_start(
    struct lantern_reqresp_service *service,
    const struct lantern_reqresp_service_config *config) {
    if (!service || !config || !config->host) {
        return -1;
    }

    lantern_reqresp_service_reset(service);

    ensure_lock(service);
    service->host = config->host;
    if (config->callbacks) {
        service->callbacks = *config->callbacks;
    } else {
        memset(&service->callbacks, 0, sizeof(service->callbacks));
    }

    libp2p_protocol_def_t status_def;
    memset(&status_def, 0, sizeof(status_def));
    status_def.protocol_id = LANTERN_STATUS_PROTOCOL_ID;
    status_def.read_mode = LIBP2P_READ_PULL;
    status_def.on_open = status_on_open;
    status_def.user_data = service;

    libp2p_protocol_def_t blocks_def;
    memset(&blocks_def, 0, sizeof(blocks_def));
    blocks_def.protocol_id = LANTERN_BLOCKS_BY_ROOT_PROTOCOL_ID;
    blocks_def.read_mode = LIBP2P_READ_PULL;
    blocks_def.on_open = blocks_on_open;
    blocks_def.user_data = service;

    if (libp2p_host_listen_protocol(service->host, &status_def, &service->status_server) != 0) {
        lantern_reqresp_service_reset(service);
        return -1;
    }
    if (libp2p_host_listen_protocol(service->host, &blocks_def, &service->blocks_server) != 0) {
        lantern_reqresp_service_reset(service);
        return -1;
    }

    lantern_log_info(
        "network",
        &(const struct lantern_log_metadata){0},
        "request/response protocols registered");

    return 0;
}
