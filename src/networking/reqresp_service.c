#include "lantern/networking/reqresp_service.h"

#include <errno.h>
#include <stdbool.h>
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
    const char *protocol_id;
};

struct blocks_stream_ctx {
    struct lantern_reqresp_service *service;
    libp2p_stream_t *stream;
    const char *protocol_id;
};

struct status_request_ctx {
    struct lantern_reqresp_service *service;
    peer_id_t peer_id;
    char peer_text[128];
    int legacy_no_code;
};

struct status_request_worker_args {
    struct status_request_ctx *ctx;
    libp2p_stream_t *stream;
};

static void log_stream_error(const char *phase, const char *protocol_id, const char *peer_id);
static void status_request_notify_failure(
    struct lantern_reqresp_service *service,
    const char *peer_text,
    int error);
static void reqresp_peer_prefs_reset(struct lantern_reqresp_service *service);
static ssize_t reqresp_peer_pref_index_locked(
    const struct lantern_reqresp_service *service,
    const char *peer_text);
static void reqresp_peer_pref_set(
    struct lantern_reqresp_service *service,
    const char *peer_text,
    bool legacy);
static bool reqresp_peer_pref_is_legacy(
    struct lantern_reqresp_service *service,
    const char *peer_text);
static void lantern_reqresp_service_clear(struct lantern_reqresp_service *service) {
    if (!service) {
        return;
    }
    service->host = NULL;
    service->callbacks.context = NULL;
    service->callbacks.build_status = NULL;
    service->callbacks.handle_status = NULL;
    service->callbacks.status_failure = NULL;
    service->callbacks.collect_blocks = NULL;
    service->status_server = NULL;
    service->status_legacy_server = NULL;
    service->blocks_server = NULL;
    service->blocks_legacy_server = NULL;
    service->event_subscription = NULL;
    reqresp_peer_prefs_reset(service);
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
    if (service->status_legacy_server && host) {
        (void)libp2p_host_unlisten(host, service->status_legacy_server);
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

static void status_request_ctx_free(struct status_request_ctx *ctx) {
    if (!ctx) {
        return;
    }
    peer_id_destroy(&ctx->peer_id);
    free(ctx);
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

static int read_snappy_payload_bytes(
    libp2p_stream_t *stream,
    const char *label,
    const struct lantern_log_metadata *meta,
    uint64_t declared_len,
    uint8_t **out_data,
    size_t *out_len,
    ssize_t *out_err) {
    if (!stream || !out_data || !out_len) {
        if (out_err) {
            *out_err = LIBP2P_ERR_NULL_PTR;
        }
        return -1;
    }

    size_t raw_capacity = declared_len > 0 ? (size_t)declared_len : 1u;
    if (raw_capacity > LANTERN_REQRESP_MAX_CHUNK_BYTES) {
        if (out_err) {
            *out_err = LIBP2P_ERR_MSG_TOO_LARGE;
        }
        lantern_log_trace(
            "reqresp",
            meta,
            "%s declared length too large=%zu",
            label ? label : "stream",
            raw_capacity);
        return -1;
    }

    uint8_t *raw = (uint8_t *)malloc(raw_capacity);
    if (!raw) {
        if (out_err) {
            *out_err = -ENOMEM;
        }
        lantern_log_trace(
            "reqresp",
            meta,
            "%s raw allocation failed bytes=%zu",
            label ? label : "stream",
            raw_capacity);
        return -1;
    }

    size_t comp_cap = raw_capacity + 256u;
    if (comp_cap < raw_capacity) {
        comp_cap = raw_capacity;
    }
    if (comp_cap > (size_t)LANTERN_REQRESP_MAX_CHUNK_BYTES * 2u) {
        comp_cap = (size_t)LANTERN_REQRESP_MAX_CHUNK_BYTES * 2u;
    }
    uint8_t *comp = (uint8_t *)malloc(comp_cap);
    if (!comp) {
        free(raw);
        if (out_err) {
            *out_err = -ENOMEM;
        }
        lantern_log_trace(
            "reqresp",
            meta,
            "%s compressed allocation failed bytes=%zu",
            label ? label : "stream",
            comp_cap);
        return -1;
    }

    size_t comp_len = 0;
    ssize_t last_err = 0;
    bool logged_legacy = false;

    while (true) {
        if (comp_len == comp_cap) {
            if (comp_cap >= (size_t)LANTERN_REQRESP_MAX_CHUNK_BYTES * 2u) {
                last_err = LIBP2P_ERR_MSG_TOO_LARGE;
                break;
            }
            size_t new_cap = comp_cap * 2u;
            if (new_cap > (size_t)LANTERN_REQRESP_MAX_CHUNK_BYTES * 2u) {
                new_cap = (size_t)LANTERN_REQRESP_MAX_CHUNK_BYTES * 2u;
            }
            uint8_t *new_buf = (uint8_t *)realloc(comp, new_cap);
            if (!new_buf) {
                last_err = -ENOMEM;
                break;
            }
            comp = new_buf;
            comp_cap = new_cap;
        }

        (void)libp2p_stream_set_deadline(stream, LANTERN_REQRESP_STALL_TIMEOUT_MS);
        ssize_t n = libp2p_stream_read(stream, comp + comp_len, comp_cap - comp_len);
        if (n > 0) {
            comp_len += (size_t)n;
        } else if (n == (ssize_t)LIBP2P_ERR_AGAIN) {
            continue;
        } else {
            last_err = n == 0 ? (ssize_t)LIBP2P_ERR_EOF : n;
            break;
        }
        (void)libp2p_stream_set_deadline(stream, 0);

        while (true) {
            size_t raw_written = raw_capacity;
            int rc = lantern_snappy_decompress(comp, comp_len, raw, raw_capacity, &raw_written);
            if (rc == LANTERN_SNAPPY_OK) {
                if (raw_written != raw_capacity) {
                    uint8_t *shrunk = (uint8_t *)realloc(raw, raw_written ? raw_written : 1u);
                    if (shrunk) {
                        raw = shrunk;
                    }
                    raw_capacity = raw_written;
                }
                if (declared_len > 0 && raw_capacity != declared_len && !logged_legacy) {
                    lantern_log_info(
                        "reqresp",
                        meta,
                        "%s payload length mismatch declared=%" PRIu64 " actual=%zu (peer may be legacy)",
                        label ? label : "stream",
                        declared_len,
                        raw_capacity);
                    logged_legacy = true;
                }
                free(comp);
                *out_data = raw;
                *out_len = raw_capacity;
                if (out_err) {
                    *out_err = 0;
                }
                lantern_log_trace(
                    "reqresp",
                    meta,
                    "%s payload decoded bytes=%zu",
                    label ? label : "stream",
                    raw_capacity);
                return 0;
            }
            if (rc == LANTERN_SNAPPY_ERROR_BUFFER_TOO_SMALL) {
                uint8_t *resized = (uint8_t *)realloc(raw, raw_written ? raw_written : 1u);
                if (!resized) {
                    last_err = -ENOMEM;
                    goto snappy_error;
                }
                raw = resized;
                raw_capacity = raw_written;
                continue;
            }
            if (rc == LANTERN_SNAPPY_ERROR_INVALID_INPUT) {
                break;
            }
            last_err = LIBP2P_ERR_INTERNAL;
            goto snappy_error;
        }
    }

snappy_error:
    free(comp);
    free(raw);
    if (out_err) {
        *out_err = last_err != 0 ? last_err : LIBP2P_ERR_INTERNAL;
    }
    const char *err_name = stream_error_name(last_err);
    lantern_log_trace(
        "reqresp",
        meta,
        "%s snappy read failed err=%s(%zd) bytes=%zu",
        label ? label : "stream",
        err_name ? err_name : "unknown",
        last_err,
        comp_len);
    return -1;
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
                char header_hex[(LANTERN_REQRESP_HEADER_MAX_BYTES * 2u) + 1u];
                header_hex[0] = '\0';
                if (lantern_bytes_to_hex(header, consumed, header_hex, sizeof(header_hex), 0) != 0) {
                    header_hex[0] = '\0';
                }
                lantern_log_info(
                    "reqresp",
                    &meta,
                    "%s header decoded length=%" PRIu64 " header_len=%zu header_hex=%s",
                    label ? label : "stream",
                    payload_len,
                    consumed,
                    header_hex[0] ? header_hex : "-");
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

    uint8_t *raw = NULL;
    size_t raw_len = 0;
    if (read_snappy_payload_bytes(stream, label, &meta, payload_len, &raw, &raw_len, out_err) != 0) {
        return -1;
    }
    *out_data = raw;
    *out_len = raw_len;
    lantern_log_info(
        "reqresp",
        &meta,
        "%s payload read complete bytes=%zu",
        label ? label : "stream",
        raw_len);
    return 0;
}

static int write_stream_all(
    libp2p_stream_t *stream,
    const uint8_t *data,
    size_t length,
    const char *protocol_id,
    const char *phase,
    const char *peer_hint) {
    if (!stream || (!data && length > 0)) {
        return LIBP2P_ERR_NULL_PTR;
    }

    char peer_text[128];
    peer_text[0] = '\0';
    if (!peer_hint || peer_hint[0] == '\0') {
        const peer_id_t *peer = libp2p_stream_remote_peer(stream);
        if (peer && peer_id_to_string(peer, PEER_ID_FMT_BASE58_LEGACY, peer_text, sizeof(peer_text)) < 0) {
            peer_text[0] = '\0';
        }
    }
    const char *peer_label = (peer_hint && peer_hint[0]) ? peer_hint : (peer_text[0] ? peer_text : NULL);

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

        ssize_t err = written;
        if (written == 0) {
            err = LIBP2P_ERR_EOF;
        }

        const char *err_name = stream_error_name(err);
        struct lantern_log_metadata meta = {
            .peer = peer_label,
        };
        lantern_log_trace(
            "reqresp",
            &meta,
            "%s write failed protocol=%s err=%s(%zd) remaining=%zu",
            phase ? phase : "stream",
            protocol_id ? protocol_id : "-",
            err_name ? err_name : "unknown",
            err,
            length - offset);
        if (protocol_id) {
            log_stream_error("write", protocol_id, peer_label);
        }
        return (int)err;
    }
    return 0;
}

static int send_response_chunk(
    libp2p_stream_t *stream,
    const struct lantern_log_metadata *meta,
    const char *protocol_id,
    const char *phase,
    const char *peer_text,
    bool include_response_code,
    uint8_t response_code,
    const uint8_t *payload,
    size_t payload_len) {
    if (!stream) {
        return -1;
    }

    if (include_response_code) {
        if (write_stream_all(
                stream,
                &response_code,
                1,
                protocol_id,
                phase ? phase : "response code",
                peer_text)
            != 0) {
            lantern_log_error(
                "reqresp",
                meta,
                "%s code write failed code=%u",
                phase ? phase : "response",
                (unsigned)response_code);
            return -1;
        }
    }

    uint8_t header[LANTERN_REQRESP_HEADER_MAX_BYTES];
    size_t header_len = 0;
    if (unsigned_varint_encode(payload_len, header, sizeof(header), &header_len) != UNSIGNED_VARINT_OK) {
        lantern_log_error(
            "reqresp",
            meta,
            "%s payload header encode failed bytes=%zu",
            phase ? phase : "response",
            payload_len);
        return -1;
    }

    if (write_stream_all(
            stream,
            header,
            header_len,
            protocol_id,
            phase ? phase : "response header",
            peer_text)
        != 0) {
        lantern_log_error(
            "reqresp",
            meta,
            "%s header write failed bytes=%zu",
            phase ? phase : "response",
            header_len);
        return -1;
    }

    if (payload_len > 0
        && write_stream_all(
               stream,
               payload,
               payload_len,
               protocol_id,
               phase ? phase : "response payload",
               peer_text)
            != 0) {
        lantern_log_error(
            "reqresp",
            meta,
            "%s payload write failed bytes=%zu",
            phase ? phase : "response",
            payload_len);
        return -1;
    }

    lantern_log_trace(
        "reqresp",
        meta,
        "%s response sent bytes=%zu",
        phase ? phase : "response",
        payload_len);

    return 0;
}

static void status_request_notify_failure(
    struct lantern_reqresp_service *service,
    const char *peer_text,
    int error) {
    if (!service || !service->callbacks.status_failure) {
        return;
    }
    service->callbacks.status_failure(
        service->callbacks.context,
        peer_text,
        error);
}

static void reqresp_peer_prefs_reset(struct lantern_reqresp_service *service) {
    if (!service) {
        return;
    }
    memset(service->peer_prefs, 0, sizeof(service->peer_prefs));
    service->peer_pref_count = 0;
    service->peer_pref_cursor = 0;
}

static ssize_t reqresp_peer_pref_index_locked(
    const struct lantern_reqresp_service *service,
    const char *peer_text) {
    if (!service || !peer_text || !peer_text[0]) {
        return -1;
    }
    for (size_t i = 0; i < service->peer_pref_count; ++i) {
        if (service->peer_prefs[i].peer_id[0]
            && strcmp(service->peer_prefs[i].peer_id, peer_text) == 0) {
            return (ssize_t)i;
        }
    }
    return -1;
}

static void reqresp_peer_pref_set(
    struct lantern_reqresp_service *service,
    const char *peer_text,
    bool legacy) {
    if (!service || !peer_text || !peer_text[0]) {
        return;
    }
    ensure_lock(service);
    if (!service->lock_initialized) {
        return;
    }
    pthread_mutex_lock(&service->lock);
    ssize_t existing = reqresp_peer_pref_index_locked(service, peer_text);
    size_t target = 0;
    if (existing >= 0) {
        target = (size_t)existing;
    } else {
        if (service->peer_pref_count < LANTERN_REQRESP_MAX_PEER_PREFS) {
            target = service->peer_pref_count++;
        } else {
            target = service->peer_pref_cursor;
            service->peer_pref_cursor =
                (service->peer_pref_cursor + 1) % LANTERN_REQRESP_MAX_PEER_PREFS;
        }
        strncpy(
            service->peer_prefs[target].peer_id,
            peer_text,
            sizeof(service->peer_prefs[target].peer_id) - 1u);
        service->peer_prefs[target].peer_id[sizeof(service->peer_prefs[target].peer_id) - 1u] = '\0';
    }
    if (legacy) {
        service->peer_prefs[target].flags |= LANTERN_REQRESP_PREF_FLAG_LEGACY_NO_CODE;
    } else {
        service->peer_prefs[target].flags &= (uint8_t)(~LANTERN_REQRESP_PREF_FLAG_LEGACY_NO_CODE);
    }
    pthread_mutex_unlock(&service->lock);
}

static bool reqresp_peer_pref_is_legacy(
    struct lantern_reqresp_service *service,
    const char *peer_text) {
    if (!service || !peer_text || !peer_text[0] || !service->lock_initialized) {
        return false;
    }
    pthread_mutex_lock(&service->lock);
    bool legacy = false;
    ssize_t index = reqresp_peer_pref_index_locked(service, peer_text);
    if (index >= 0) {
        legacy = (service->peer_prefs[index].flags & LANTERN_REQRESP_PREF_FLAG_LEGACY_NO_CODE) != 0;
    }
    pthread_mutex_unlock(&service->lock);
    return legacy;
}

static void close_stream(libp2p_stream_t *stream) {
    if (!stream) {
        return;
    }
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
    const char *protocol_id =
        ctx->protocol_id ? ctx->protocol_id : LANTERN_STATUS_PROTOCOL_ID;
    free(ctx);

    if (!service || !stream) {
        close_stream(stream);
        return NULL;
    }

    char peer_text[128];
    describe_peer(libp2p_stream_remote_peer(stream), peer_text, sizeof(peer_text));

    bool include_response_code = true;
    if (protocol_id && strcmp(protocol_id, LANTERN_STATUS_PROTOCOL_ID_LEGACY) == 0) {
        include_response_code = false;
    } else if (peer_text[0]) {
        include_response_code =
            !lantern_reqresp_service_peer_prefers_legacy(service, peer_text);
    }
    if (peer_text[0]) {
        lantern_reqresp_service_hint_peer_legacy(
            service,
            peer_text,
            include_response_code ? 0 : 1);
    }

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
        log_stream_error("read", protocol_id, peer_text[0] ? peer_text : NULL);
        close_stream(stream);
        return NULL;
    }

    log_payload_preview("status request raw", peer_text, request, request_len);

    LanternStatusMessage remote_status;
    memset(&remote_status, 0, sizeof(remote_status));
    if (lantern_network_status_decode(&remote_status, request, request_len) != 0) {
        log_payload_preview("status request decode_failed", peer_text, request, request_len);
        free(request);
        log_stream_error("decode", protocol_id, peer_text[0] ? peer_text : NULL);
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
        log_stream_error("status", protocol_id, peer_text);
        close_stream(stream);
        return NULL;
    }

    size_t max_payload = 0;
    if (lantern_snappy_max_compressed_size(2u * LANTERN_CHECKPOINT_SSZ_SIZE, &max_payload) != LANTERN_SNAPPY_OK) {
        log_stream_error("encode", protocol_id, peer_text);
        close_stream(stream);
        return NULL;
    }

    uint8_t *buffer = (uint8_t *)malloc(max_payload);
    if (!buffer) {
        log_stream_error("encode", protocol_id, peer_text);
        close_stream(stream);
        return NULL;
    }

    size_t response_raw_len = 0;
    size_t written = 0;
    if (lantern_network_status_encode_snappy(&response, buffer, max_payload, &written, &response_raw_len) != 0) {
        free(buffer);
        log_stream_error("encode", protocol_id, peer_text);
        close_stream(stream);
        return NULL;
    }

    log_payload_preview("status response raw", peer_text, buffer, written);

    const struct lantern_log_metadata meta = {.peer = peer_text};
    lantern_log_info(
        "reqresp",
        &meta,
        "status response lengths raw=%zu compressed=%zu",
        response_raw_len,
        written);

    if (send_response_chunk(
            stream,
            &meta,
            protocol_id,
            "status response",
            peer_text[0] ? peer_text : NULL,
            include_response_code,
            LANTERN_REQRESP_RESPONSE_SUCCESS,
            buffer,
            written)
        != 0) {
        free(buffer);
        log_stream_error("write", protocol_id, peer_text);
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

static void *status_request_worker(void *arg) {
    struct status_request_worker_args *worker = (struct status_request_worker_args *)arg;
    if (!worker) {
        return NULL;
    }
    struct status_request_ctx *ctx = worker->ctx;
    libp2p_stream_t *stream = worker->stream;
    free(worker);
    if (!ctx || !stream) {
        if (stream) {
            libp2p_stream_free(stream);
        }
        status_request_ctx_free(ctx);
        return NULL;
    }

    struct lantern_reqresp_service *service = ctx->service;
    char peer_text[sizeof(ctx->peer_text)];
    memcpy(peer_text, ctx->peer_text, sizeof(peer_text));
    if (peer_text[sizeof(peer_text) - 1] != '\0') {
        peer_text[sizeof(peer_text) - 1] = '\0';
    }
    struct lantern_log_metadata meta = {
        .peer = peer_text[0] ? peer_text : NULL,
    };
    int failure_code = LIBP2P_ERR_INTERNAL;
    int rc = 0;

    LanternStatusMessage local_status;
    memset(&local_status, 0, sizeof(local_status));
    if (!service->callbacks.build_status
        || service->callbacks.build_status(service->callbacks.context, &local_status) != 0) {
        lantern_log_warn(
            "reqresp",
            &meta,
            "failed to build local status for request");
        goto finish;
    }

    size_t max_payload = 0;
    if (lantern_snappy_max_compressed_size(2u * LANTERN_CHECKPOINT_SSZ_SIZE, &max_payload) != LANTERN_SNAPPY_OK) {
        lantern_log_error(
            "reqresp",
            &meta,
            "failed to compute snappy size for status request");
        goto finish;
    }

    uint8_t *payload = (uint8_t *)malloc(max_payload);
    if (!payload) {
        lantern_log_error(
            "reqresp",
            &meta,
            "out of memory building status request");
        goto finish;
    }

    size_t payload_len = 0;
    size_t payload_raw_len = 0;
    if (lantern_network_status_encode_snappy(&local_status, payload, max_payload, &payload_len, &payload_raw_len) != 0) {
        lantern_log_error(
            "reqresp",
            &meta,
            "failed to encode status request");
        free(payload);
        goto finish;
    }

    log_payload_preview("status request snappy", ctx->peer_text, payload, payload_len);

    uint8_t header[LANTERN_REQRESP_HEADER_MAX_BYTES];
    size_t header_len = 0;
    if (unsigned_varint_encode(payload_len, header, sizeof(header), &header_len) != UNSIGNED_VARINT_OK) {
        lantern_log_error(
            "reqresp",
            &meta,
            "failed to encode status request header bytes=%zu",
            payload_len);
        free(payload);
        goto finish;
    }

    char header_hex[(LANTERN_REQRESP_HEADER_MAX_BYTES * 2u) + 1u];
    header_hex[0] = '\0';
    if (lantern_bytes_to_hex(header, header_len, header_hex, sizeof(header_hex), 0) != 0) {
        header_hex[0] = '\0';
    }
    const char *protocol_id = LANTERN_STATUS_PROTOCOL_ID;
    lantern_log_info(
        "reqresp",
        &meta,
        "status request header_len=%zu declared_len=%zu raw_len=%zu header_hex=%s",
        header_len,
        payload_len,
        payload_raw_len,
        header_hex[0] ? header_hex : "-");

    lantern_log_info(
        "reqresp",
        &meta,
        "sending %s request declared_bytes=%zu raw_bytes=%zu",
        protocol_id,
        payload_len,
        payload_raw_len);

    const char *peer_label = ctx->peer_text[0] ? ctx->peer_text : NULL;
    rc = write_stream_all(
        stream,
        header,
        header_len,
        protocol_id,
        "status request header",
        peer_label);
    if (rc == 0 && payload_len > 0) {
        rc = write_stream_all(
            stream,
            payload,
            payload_len,
            protocol_id,
            "status request payload",
            peer_label);
    }
    if (rc != 0) {
        lantern_log_error(
            "reqresp",
            &meta,
            "failed to write status request");
        free(payload);
        failure_code = rc;
        goto finish;
    }
    free(payload);

    uint8_t *response = NULL;
    size_t response_len = 0;
    ssize_t read_err = 0;
    uint8_t response_code = LANTERN_REQRESP_RESPONSE_SUCCESS;
    bool expect_response_code = ctx->legacy_no_code ? false : true;
    rc = lantern_reqresp_read_response_chunk(
        service,
        stream,
        expect_response_code,
        &response,
        &response_len,
        &read_err,
        &response_code);
    if (rc != 0) {
        lantern_log_error(
            "reqresp",
            &meta,
            "failed to read status response err=%zd",
            read_err);
        failure_code = (read_err != 0) ? (int)read_err : LIBP2P_ERR_INTERNAL;
        goto finish;
    }

    lantern_log_info(
        "reqresp",
        &meta,
        "status response received code=%u raw_len=%zu",
        (unsigned)response_code,
        response_len);

    log_payload_preview("status response raw", ctx->peer_text, response, response_len);

    if (response_code != LANTERN_REQRESP_RESPONSE_SUCCESS) {
        lantern_log_error(
            "reqresp",
            &meta,
            "status response returned code=%u payload_len=%zu",
            (unsigned)response_code,
            response_len);
        free(response);
        failure_code = LIBP2P_ERR_INTERNAL;
        goto finish;
    }

    LanternStatusMessage remote_status;
    memset(&remote_status, 0, sizeof(remote_status));
    if (response_len == 0
        || lantern_network_status_decode(&remote_status, response, response_len) != 0) {
        lantern_log_error(
            "reqresp",
            &meta,
            "failed to decode status response bytes=%zu",
            response_len);
        free(response);
        failure_code = LIBP2P_ERR_INTERNAL;
        goto finish;
    }
    free(response);

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
        &meta,
        "received status head_slot=%" PRIu64 " head_root=%s finalized_slot=%" PRIu64 " finalized_root=%s",
        remote_status.head.slot,
        head_hex[0] ? head_hex : "0x0",
        remote_status.finalized.slot,
        finalized_hex[0] ? finalized_hex : "0x0");

    lantern_log_info(
        "reqresp",
        &meta,
        "status decoded head_slot=%" PRIu64 " finalized_slot=%" PRIu64,
        remote_status.head.slot,
        remote_status.finalized.slot);

    handle_remote_status(service, &remote_status, ctx->peer_text);
    failure_code = LIBP2P_ERR_OK;

finish:
    libp2p_stream_free(stream);
    status_request_ctx_free(ctx);
    if (failure_code != LIBP2P_ERR_OK) {
        status_request_notify_failure(service, peer_text[0] ? peer_text : NULL, failure_code);
    }
    return NULL;
}

static void status_request_on_open(libp2p_stream_t *stream, void *user_data, int err) {
    struct status_request_ctx *ctx = (struct status_request_ctx *)user_data;
    struct lantern_log_metadata meta = {
        .peer = (ctx && ctx->peer_text[0]) ? ctx->peer_text : NULL,
    };
    const char *protocol_id = LANTERN_STATUS_PROTOCOL_ID;
    lantern_log_info(
        "reqresp",
        &meta,
        "status request stream opened protocol=%s err=%d",
        protocol_id,
        err);
    if (!ctx) {
        if (stream) {
            libp2p_stream_free(stream);
        }
        return;
    }

    if (err != 0 || !stream) {
        lantern_log_warn(
            "reqresp",
            &meta,
            "failed to open %s stream err=%d",
            protocol_id,
            err);
        status_request_notify_failure(ctx->service, meta.peer, err != 0 ? err : LIBP2P_ERR_INTERNAL);
        if (stream) {
            libp2p_stream_free(stream);
        }
        status_request_ctx_free(ctx);
        return;
    }

    struct status_request_worker_args *worker = (struct status_request_worker_args *)malloc(sizeof(*worker));
    if (!worker) {
        lantern_log_error(
            "reqresp",
            &meta,
            "failed to allocate worker for %s stream",
            protocol_id);
        status_request_notify_failure(ctx->service, meta.peer, LIBP2P_ERR_INTERNAL);
        libp2p_stream_free(stream);
        status_request_ctx_free(ctx);
        return;
    }
    worker->ctx = ctx;
    worker->stream = stream;

    pthread_t thread;
    if (pthread_create(&thread, NULL, status_request_worker, worker) != 0) {
        lantern_log_error(
            "reqresp",
            &meta,
            "failed to spawn status request worker");
        free(worker);
        status_request_notify_failure(ctx->service, meta.peer, LIBP2P_ERR_INTERNAL);
        libp2p_stream_free(stream);
        status_request_ctx_free(ctx);
        return;
    }
    lantern_log_info(
        "reqresp",
        &meta,
        "spawned status request worker");
    pthread_detach(thread);
}

static int clone_peer_id(peer_id_t *dest, const peer_id_t *src) {
    if (!dest || !src || !src->bytes || src->size == 0) {
        return -1;
    }
    dest->bytes = (uint8_t *)malloc(src->size);
    if (!dest->bytes) {
        dest->size = 0;
        return -1;
    }
    memcpy(dest->bytes, src->bytes, src->size);
    dest->size = src->size;
    return 0;
}

int lantern_reqresp_service_request_status(
    struct lantern_reqresp_service *service,
    const peer_id_t *peer_id,
    const char *peer_id_text) {
    if (!service || !service->host || !peer_id || !peer_id->bytes || peer_id->size == 0) {
        return -1;
    }

    struct status_request_ctx *ctx = (struct status_request_ctx *)calloc(1, sizeof(*ctx));
    if (!ctx) {
        return -1;
    }
    ctx->service = service;

    struct lantern_log_metadata meta = {
        .peer = NULL,
    };

    if (peer_id_text && peer_id_text[0] != '\0') {
        strncpy(ctx->peer_text, peer_id_text, sizeof(ctx->peer_text) - 1);
        ctx->peer_text[sizeof(ctx->peer_text) - 1] = '\0';
    } else {
        if (peer_id_to_string(peer_id, PEER_ID_FMT_BASE58_LEGACY, ctx->peer_text, sizeof(ctx->peer_text)) < 0) {
            ctx->peer_text[0] = '\0';
        }
    }
    if (ctx->peer_text[0] != '\0') {
        meta.peer = ctx->peer_text;
    }

    if (clone_peer_id(&ctx->peer_id, peer_id) != 0) {
        lantern_log_warn(
            "reqresp",
            &meta,
            "failed to clone peer id for status request");
        status_request_notify_failure(service, meta.peer, LIBP2P_ERR_INTERNAL);
        status_request_ctx_free(ctx);
        return -1;
    }

    ctx->legacy_no_code = lantern_reqresp_service_peer_prefers_legacy(service, ctx->peer_text) ? 1 : 0;
    const char *protocol_id = LANTERN_STATUS_PROTOCOL_ID;

    int rc = libp2p_host_open_stream_async(
        service->host,
        &ctx->peer_id,
        protocol_id,
        status_request_on_open,
        ctx);
    if (rc != 0) {
        lantern_log_warn(
            "reqresp",
            &meta,
            "libp2p open stream failed rc=%d",
            rc);
        status_request_notify_failure(service, meta.peer, rc);
        status_request_ctx_free(ctx);
        return -1;
    }
    return 0;
}

static void *blocks_worker(void *arg) {
    struct blocks_stream_ctx *ctx = (struct blocks_stream_ctx *)arg;
    if (!ctx) {
        return NULL;
    }
    struct lantern_reqresp_service *service = ctx->service;
    libp2p_stream_t *stream = ctx->stream;
    const char *protocol_id =
        ctx->protocol_id ? ctx->protocol_id : LANTERN_BLOCKS_BY_ROOT_PROTOCOL_ID;
    free(ctx);

    if (!service || !stream) {
        close_stream(stream);
        return NULL;
    }

    char peer_text[128];
    describe_peer(libp2p_stream_remote_peer(stream), peer_text, sizeof(peer_text));
    bool include_response_code = true;
    if (protocol_id && strcmp(protocol_id, LANTERN_BLOCKS_BY_ROOT_PROTOCOL_ID_LEGACY) == 0) {
        include_response_code = false;
    } else if (peer_text[0]) {
        include_response_code =
            !lantern_reqresp_service_peer_prefers_legacy(service, peer_text);
    }
    if (peer_text[0]) {
        lantern_reqresp_service_hint_peer_legacy(
            service,
            peer_text,
            include_response_code ? 0 : 1);
    }

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
    int decode_rc = lantern_network_blocks_by_root_request_decode(
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
    size_t response_raw_len = 0;
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
        response_raw_len = 0;
        encode_rc = lantern_network_blocks_by_root_response_encode_snappy(
            &response,
            buffer,
            buffer_capacity,
            &written,
            &response_raw_len);
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

    const struct lantern_log_metadata meta = {.peer = peer_text};
    lantern_log_info(
        "reqresp",
        &meta,
        "blocks_by_root response lengths raw=%zu compressed=%zu",
        response_raw_len,
        written);

    if (send_response_chunk(
            stream,
            &meta,
            protocol_id,
            "blocks_by_root response",
            peer_text[0] ? peer_text : NULL,
            include_response_code,
            LANTERN_REQRESP_RESPONSE_SUCCESS,
            buffer,
            written)
        != 0) {
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

static void status_on_open_impl(
    libp2p_stream_t *stream,
    void *user_data,
    const char *protocol_id) {
    struct lantern_reqresp_service *service = (struct lantern_reqresp_service *)user_data;
    struct status_stream_ctx *ctx = (struct status_stream_ctx *)malloc(sizeof(*ctx));
    if (!ctx) {
        close_stream(stream);
        return;
    }
    ctx->service = service;
    ctx->stream = stream;
    ctx->protocol_id = protocol_id;
    pthread_t thread;
    if (pthread_create(&thread, NULL, status_worker, ctx) != 0) {
        free(ctx);
        close_stream(stream);
        return;
    }
    pthread_detach(thread);
}

static void status_on_open_primary(libp2p_stream_t *stream, void *user_data) {
    status_on_open_impl(stream, user_data, LANTERN_STATUS_PROTOCOL_ID);
}

static void status_on_open_legacy(libp2p_stream_t *stream, void *user_data) {
    status_on_open_impl(stream, user_data, LANTERN_STATUS_PROTOCOL_ID_LEGACY);
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
    status_def.on_open = status_on_open_primary;
    status_def.user_data = service;

    libp2p_protocol_def_t status_legacy_def;
    memset(&status_legacy_def, 0, sizeof(status_legacy_def));
    status_legacy_def.protocol_id = LANTERN_STATUS_PROTOCOL_ID_LEGACY;
    status_legacy_def.read_mode = LIBP2P_READ_PULL;
    status_legacy_def.on_open = status_on_open_legacy;
    status_legacy_def.user_data = service;

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
    int status_legacy_rc =
        libp2p_host_listen_protocol(service->host, &status_legacy_def, &service->status_legacy_server);
    if (status_legacy_rc != 0) {
        service->status_legacy_server = NULL;
        lantern_log_warn(
            "network",
            &(const struct lantern_log_metadata){0},
            "legacy request/response protocol registration failed (%d) id=%s",
            status_legacy_rc,
            LANTERN_STATUS_PROTOCOL_ID_LEGACY);
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

void lantern_reqresp_service_hint_peer_legacy(
    struct lantern_reqresp_service *service,
    const char *peer_id_text,
    int legacy_no_code) {
    if (!service || !peer_id_text || !peer_id_text[0]) {
        return;
    }
    reqresp_peer_pref_set(service, peer_id_text, legacy_no_code != 0);
}

int lantern_reqresp_service_peer_prefers_legacy(
    const struct lantern_reqresp_service *service,
    const char *peer_id_text) {
    if (!service || !peer_id_text || !peer_id_text[0]) {
        return 0;
    }
    return reqresp_peer_pref_is_legacy((struct lantern_reqresp_service *)service, peer_id_text) ? 1 : 0;
}
