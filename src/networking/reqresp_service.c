#include "lantern/networking/reqresp_service.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "lantern/encoding/snappy.h"
#include "lantern/consensus/ssz.h"
#include "lantern/support/log.h"
#include "lantern/support/strings.h"

#include "libp2p/events.h"
#include "libp2p/host.h"
#include "libp2p/protocol.h"
#include "libp2p/protocol_listen.h"
#include "libp2p/stream.h"
#include "libp2p/errors.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"

#include "peer_id/peer_id.h"

#include "ssz_constants.h"

struct status_stream_ctx {
    struct lantern_reqresp_service *service;
    libp2p_stream_t *stream;
};

struct blocks_stream_ctx {
    struct lantern_reqresp_service *service;
    libp2p_stream_t *stream;
    const char *protocol_id;
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
    service->blocks_legacy_server = NULL;
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
    if (service->blocks_legacy_server && host) {
        (void)libp2p_host_unlisten(host, service->blocks_legacy_server);
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

static const char *stream_error_name(ssize_t code) {
    switch (code) {
    case LIBP2P_ERR_AGAIN:
        return "again";
    case LIBP2P_ERR_TIMEOUT:
        return "timeout";
    case LIBP2P_ERR_EOF:
        return "eof";
    case LIBP2P_ERR_CLOSED:
        return "closed";
    case LIBP2P_ERR_RESET:
        return "reset";
    case LIBP2P_ERR_MSG_TOO_LARGE:
        return "too_large";
    default:
        return NULL;
    }
}

static void log_payload_preview(
    const char *stage,
    const char *peer_text,
    const uint8_t *data,
    size_t length) {
    if (!data) {
        return;
    }
    size_t preview_len = length < LANTERN_STATUS_PREVIEW_BYTES ? length : LANTERN_STATUS_PREVIEW_BYTES;
    char hex[(LANTERN_STATUS_PREVIEW_BYTES * 2u) + 1u];
    if (preview_len > 0) {
        if (lantern_bytes_to_hex(data, preview_len, hex, sizeof(hex), 0) != 0) {
            hex[0] = '\0';
        }
    } else {
        hex[0] = '\0';
    }
    const char *ellipsis = length > preview_len ? "..." : "";
    const struct lantern_log_metadata meta = {.peer = peer_text};
    lantern_log_trace(
        "reqresp",
        &meta,
        "%s bytes=%zu preview=%s%s",
        stage ? stage : "payload",
        length,
        hex[0] ? hex : "-",
        ellipsis);
}

static int read_length_prefixed_stream(
    libp2p_stream_t *stream,
    const char *label,
    const char *peer_text,
    uint8_t **out_data,
    size_t *out_len,
    ssize_t *out_err) {
    if (!stream || !out_data || !out_len) {
        if (out_err) {
            *out_err = LIBP2P_ERR_NULL_PTR;
        }
        return -1;
    }

    struct lantern_log_metadata meta = {.peer = peer_text};
    uint8_t header[LANTERN_REQRESP_HEADER_MAX_BYTES];
    size_t header_used = 0;
    size_t consumed = 0;
    uint64_t payload_len = 0;
    ssize_t last_err = 0;

    if (out_err) {
        *out_err = 0;
    }

    while (header_used < sizeof(header)) {
        (void)libp2p_stream_set_deadline(stream, LANTERN_REQRESP_STALL_TIMEOUT_MS);
        ssize_t n = libp2p_stream_read(stream, &header[header_used], 1);
        if (n == 1) {
            header_used += 1;
            lantern_log_trace(
                "reqresp",
                &meta,
                "%s header byte[%zu]=0x%02x",
                label ? label : "stream",
                header_used - 1,
                (unsigned)header[header_used - 1]);
            if (unsigned_varint_decode(header, header_used, &payload_len, &consumed) == UNSIGNED_VARINT_OK) {
                lantern_log_trace(
                    "reqresp",
                    &meta,
                    "%s header decoded length=%" PRIu64,
                    label ? label : "stream",
                    payload_len);
                break;
            }
            continue;
        }
        if (n == (ssize_t)LIBP2P_ERR_AGAIN) {
            continue;
        }
        if (n == 0 || n == (ssize_t)LIBP2P_ERR_EOF || n == (ssize_t)LIBP2P_ERR_CLOSED || n == (ssize_t)LIBP2P_ERR_RESET) {
            last_err = n == 0 ? (ssize_t)LIBP2P_ERR_EOF : n;
            break;
        }
        last_err = n;
        break;
    }
    (void)libp2p_stream_set_deadline(stream, 0);

    if (header_used == sizeof(header)
        && unsigned_varint_decode(header, header_used, &payload_len, &consumed) != UNSIGNED_VARINT_OK) {
        last_err = LIBP2P_ERR_INTERNAL;
    }

    if (payload_len == 0 || payload_len > LANTERN_REQRESP_MAX_CHUNK_BYTES || payload_len > SIZE_MAX) {
        if (last_err == 0) {
            last_err = LIBP2P_ERR_MSG_TOO_LARGE;
        }
        lantern_log_trace(
            "reqresp",
            &meta,
            "%s header invalid length=%" PRIu64,
            label ? label : "stream",
            payload_len);
    }

    if (last_err != 0) {
        if (out_err) {
            *out_err = last_err;
        }
        const char *err_name = stream_error_name(last_err);
        lantern_log_trace(
            "reqresp",
            &meta,
            "%s header read failed err=%s(%zd) bytes=%zu",
            label ? label : "stream",
            err_name ? err_name : "unknown",
            last_err,
            header_used);
        return -1;
    }

    size_t payload_size = (size_t)payload_len;
    uint8_t *buffer = (uint8_t *)malloc(payload_size);
    if (!buffer) {
        if (out_err) {
            *out_err = -ENOMEM;
        }
        lantern_log_trace(
            "reqresp",
            &meta,
            "%s payload allocation failed bytes=%zu",
            label ? label : "stream",
            payload_size);
        return -1;
    }

    lantern_log_trace(
        "reqresp",
        &meta,
        "%s chunk length=%zu",
        label ? label : "stream",
        payload_size);

    size_t collected = 0;
    while (collected < payload_size) {
        (void)libp2p_stream_set_deadline(stream, LANTERN_REQRESP_STALL_TIMEOUT_MS);
        ssize_t n = libp2p_stream_read(stream, buffer + collected, payload_size - collected);
        if (n > 0) {
            collected += (size_t)n;
            continue;
        }
        if (n == (ssize_t)LIBP2P_ERR_AGAIN) {
            continue;
        }
        (void)libp2p_stream_set_deadline(stream, 0);
        free(buffer);
        last_err = n == 0 ? (ssize_t)LIBP2P_ERR_EOF : n;
        if (out_err) {
            *out_err = last_err;
        }
        const char *err_name = stream_error_name(last_err);
        lantern_log_trace(
            "reqresp",
            &meta,
            "%s payload read failed err=%s(%zd) collected=%zu/%zu",
            label ? label : "stream",
            err_name ? err_name : "unknown",
            last_err,
            collected,
            payload_size);
        return -1;
    }
    (void)libp2p_stream_set_deadline(stream, 0);

    *out_data = buffer;
    *out_len = payload_size;
    if (out_err) {
        *out_err = 0;
    }
    lantern_log_trace(
        "reqresp",
        &meta,
        "%s payload read complete bytes=%zu",
        label ? label : "stream",
        payload_size);
    return 0;
}

static int write_stream_all(libp2p_stream_t *stream, const uint8_t *data, size_t length) {
    if (!stream || (!data && length > 0)) {
        return -1;
    }
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = libp2p_stream_write(stream, data + offset, length - offset);
        if (written > 0) {
            offset += (size_t)written;
            continue;
        }
        if (written == (ssize_t)LIBP2P_ERR_AGAIN || written == (ssize_t)LIBP2P_ERR_TIMEOUT) {
            continue;
        }
        if (written == 0 || written == (ssize_t)LIBP2P_ERR_EOF || written == (ssize_t)LIBP2P_ERR_CLOSED) {
            return -1;
        }
        if (written == (ssize_t)LIBP2P_ERR_RESET) {
            return -1;
        }
        return -1;
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

    char peer_text[128];
    describe_peer(libp2p_stream_remote_peer(stream), peer_text, sizeof(peer_text));

    lantern_log_trace(
        "reqresp",
        &(const struct lantern_log_metadata){.peer = peer_text},
        "status stream opened");

    libp2p_stream_set_read_interest(stream, true);

    uint8_t *request = NULL;
    size_t request_len = 0;
    ssize_t read_err = 0;
    if (read_length_prefixed_stream(stream, "status", peer_text, &request, &request_len, &read_err) != 0) {
        const char *err_name = read_err == 0 ? "empty" : stream_error_name(read_err);
        lantern_log_trace(
            "reqresp",
            &(const struct lantern_log_metadata){.peer = peer_text},
            "status read failed err=%s(%zd)",
            err_name ? err_name : "unknown",
            read_err);
        log_stream_error("read", LANTERN_STATUS_PROTOCOL_ID, peer_text[0] ? peer_text : NULL);
        close_stream(stream);
        return NULL;
    }

    log_payload_preview("status request raw", peer_text, request, request_len);

    LanternStatusMessage remote_status;
    memset(&remote_status, 0, sizeof(remote_status));
    if (lantern_network_status_decode_snappy(&remote_status, request, request_len) != 0) {
        log_payload_preview("status request decode_failed", peer_text, request, request_len);
        free(request);
        log_stream_error("decode", LANTERN_STATUS_PROTOCOL_ID, peer_text[0] ? peer_text : NULL);
        close_stream(stream);
        return NULL;
    }
    free(request);

    char head_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
    if (lantern_bytes_to_hex(remote_status.head.root.bytes, LANTERN_ROOT_SIZE, head_hex, sizeof(head_hex), 1) != 0) {
        head_hex[0] = '\0';
    }
    char finalized_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
    if (lantern_bytes_to_hex(
            remote_status.finalized.root.bytes,
            LANTERN_ROOT_SIZE,
            finalized_hex,
            sizeof(finalized_hex),
            1)
        != 0) {
        finalized_hex[0] = '\0';
    }
    lantern_log_trace(
        "reqresp",
        &(const struct lantern_log_metadata){.peer = peer_text},
        "decoded status head_slot=%" PRIu64 " head_root=%s finalized_slot=%" PRIu64 " finalized_root=%s",
        remote_status.head.slot,
        head_hex[0] ? head_hex : "0x0",
        remote_status.finalized.slot,
        finalized_hex[0] ? finalized_hex : "0x0");

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

    log_payload_preview("status response raw", peer_text, buffer, written);

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
    const char *protocol_id = ctx->protocol_id ? ctx->protocol_id : LANTERN_BLOCKS_BY_ROOT_PROTOCOL_ID;
    free(ctx);

    if (!service || !stream) {
        close_stream(stream);
        return NULL;
    }

    char peer_text[128];
    describe_peer(libp2p_stream_remote_peer(stream), peer_text, sizeof(peer_text));

    libp2p_stream_set_read_interest(stream, true);

    uint8_t *request = NULL;
    size_t request_len = 0;
    ssize_t request_err = 0;
    if (read_length_prefixed_stream(stream, "blocks_by_root", peer_text, &request, &request_len, &request_err) != 0) {
        const char *err_name = request_err == 0 ? "empty" : stream_error_name(request_err);
        lantern_log_trace(
            "reqresp",
            &(const struct lantern_log_metadata){.peer = peer_text},
            "blocks_by_root read failed err=%s(%zd)",
            err_name ? err_name : "unknown",
            request_err);
        log_stream_error("read", protocol_id, peer_text[0] ? peer_text : NULL);
        close_stream(stream);
        return NULL;
    }

    log_payload_preview("blocks_by_root request raw", peer_text, request, request_len);

    LanternBlocksByRootRequest decoded_request;
    lantern_blocks_by_root_request_init(&decoded_request);
    int decode_rc = lantern_network_blocks_by_root_request_decode_snappy(
        &decoded_request,
        request,
        request_len);
    free(request);
    if (decode_rc != 0) {
        lantern_blocks_by_root_request_reset(&decoded_request);
        log_stream_error("decode", protocol_id, peer_text[0] ? peer_text : NULL);
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
        log_stream_error("collect", protocol_id, peer_text[0] ? peer_text : NULL);
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
            log_stream_error("encode", protocol_id, NULL);
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
        log_stream_error("encode", protocol_id, peer_text[0] ? peer_text : NULL);
        close_stream(stream);
        return NULL;
    }

    log_payload_preview("blocks_by_root response raw", peer_text, buffer, written);

    if (write_stream_all(stream, buffer, written) != 0) {
        free(buffer);
        log_stream_error("write", protocol_id, peer_text[0] ? peer_text : NULL);
        close_stream(stream);
        return NULL;
    }
    free(buffer);
    close_stream(stream);

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

static void blocks_on_open_impl(libp2p_stream_t *stream, void *user_data, const char *protocol_id) {
    struct lantern_reqresp_service *service = (struct lantern_reqresp_service *)user_data;
    if (!service) {
        close_stream(stream);
        return;
    }
    struct blocks_stream_ctx *ctx = (struct blocks_stream_ctx *)malloc(sizeof(*ctx));
    if (!ctx) {
        close_stream(stream);
        return;
    }
    ctx->service = service;
    ctx->stream = stream;
    ctx->protocol_id = protocol_id;
    pthread_t thread;
    if (pthread_create(&thread, NULL, blocks_worker, ctx) != 0) {
        free(ctx);
        close_stream(stream);
        return;
    }
    pthread_detach(thread);
}

static void blocks_on_open_primary(libp2p_stream_t *stream, void *user_data) {
    blocks_on_open_impl(stream, user_data, LANTERN_BLOCKS_BY_ROOT_PROTOCOL_ID);
}

static void blocks_on_open_legacy(libp2p_stream_t *stream, void *user_data) {
    blocks_on_open_impl(stream, user_data, LANTERN_BLOCKS_BY_ROOT_PROTOCOL_ID_LEGACY);
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
    blocks_def.on_open = blocks_on_open_primary;
    blocks_def.user_data = service;

    libp2p_protocol_def_t blocks_legacy_def;
    memset(&blocks_legacy_def, 0, sizeof(blocks_legacy_def));
    blocks_legacy_def.protocol_id = LANTERN_BLOCKS_BY_ROOT_PROTOCOL_ID_LEGACY;
    blocks_legacy_def.read_mode = LIBP2P_READ_PULL;
    blocks_legacy_def.on_open = blocks_on_open_legacy;
    blocks_legacy_def.user_data = service;

    if (libp2p_host_listen_protocol(service->host, &status_def, &service->status_server) != 0) {
        lantern_reqresp_service_reset(service);
        return -1;
    }
    if (libp2p_host_listen_protocol(service->host, &blocks_def, &service->blocks_server) != 0) {
        lantern_reqresp_service_reset(service);
        return -1;
    }
    int legacy_rc = libp2p_host_listen_protocol(
        service->host,
        &blocks_legacy_def,
        &service->blocks_legacy_server);
    if (legacy_rc != 0) {
        service->blocks_legacy_server = NULL;
        lantern_log_warn(
            "network",
            &(const struct lantern_log_metadata){0},
            "legacy request/response protocol registration failed (%d) id=%s",
            legacy_rc,
            LANTERN_BLOCKS_BY_ROOT_PROTOCOL_ID_LEGACY);
    }

    lantern_log_info(
        "network",
        &(const struct lantern_log_metadata){0},
        "request/response protocols registered");

    return 0;
}
