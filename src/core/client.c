#include "lantern/core/client.h"

#include "lantern/consensus/hash.h"
#include "lantern/consensus/containers.h"
#include "lantern/consensus/duties.h"
#include "lantern/consensus/runtime.h"
#include "lantern/consensus/state.h"
#include "lantern/consensus/ssz.h"
#include "lantern/consensus/fork_choice.h"
#include "lantern/storage/storage.h"
#include "lantern/http/server.h"
#include "lantern/support/strings.h"
#include "lantern/support/log.h"
#include "lantern/support/secure_mem.h"
#include "lantern/networking/messages.h"
#include "lantern/encoding/snappy.h"
#include "libp2p/events.h"
#include "libp2p/errors.h"
#include "libp2p/protocol_dial.h"
#include "libp2p/stream.h"
#include "libp2p/host.h"
#include "protocol/gossipsub/gossipsub.h"
#include "protocol/ping/protocol_ping.h"
#include "peer_id/peer_id.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/time.h>
#endif

#define LANTERN_PEER_DIAL_INTERVAL_SECONDS 5u
#define LANTERN_BLOCKS_REQUEST_BACKOFF_BASE_MS 5000u
#define LANTERN_BLOCKS_REQUEST_BACKOFF_MAX_MS 300000u
#define LANTERN_BLOCKS_REQUEST_BACKOFF_MAX_FAILURES 8u

enum lantern_blocks_request_outcome {
    LANTERN_BLOCKS_REQUEST_SUCCESS = 0,
    LANTERN_BLOCKS_REQUEST_FAILED,
    LANTERN_BLOCKS_REQUEST_ABORTED
};

static uint64_t monotonic_millis(void);
static uint64_t blocks_request_backoff_ms(uint32_t failures);
static int set_owned_string(char **dest, const char *value);
static int copy_genesis_paths(struct lantern_genesis_paths *paths, const struct lantern_client_options *options);
static void reset_genesis_paths(struct lantern_genesis_paths *paths);
static int read_trimmed_file(const char *path, char **out_text);
static int load_node_key_bytes(const struct lantern_client_options *options, uint8_t out_key[32]);
static bool string_list_contains(const struct lantern_string_list *list, const char *value);
static int append_unique_bootnode(struct lantern_string_list *list, const char *value);
static int append_genesis_bootnodes(struct lantern_client *client);
static int compute_local_validator_assignment(struct lantern_client *client);
static int populate_local_validators(struct lantern_client *client);
static int init_consensus_runtime(struct lantern_client *client);
static int find_local_validator_index(const struct lantern_client *client, uint64_t global_index, size_t *out_index);
static void reset_local_validators(struct lantern_client *client);
static void local_validator_cleanup(struct lantern_local_validator *validator);
static int decode_validator_secret(const char *hex, uint8_t **out_key, size_t *out_len);
static int http_snapshot_head(void *context, struct lantern_http_head_snapshot *out_snapshot);
static size_t http_validator_count_cb(void *context);
static int http_validator_info_cb(void *context, size_t index, struct lantern_http_validator_info *out_info);
static int http_set_validator_status_cb(void *context, uint64_t global_index, bool enabled);
static int metrics_snapshot_cb(void *context, struct lantern_metrics_snapshot *out_snapshot);
static void format_root_hex(const LanternRoot *root, char *out, size_t out_len);
static int reqresp_build_status(void *context, LanternStatusMessage *out_status);
static int reqresp_handle_status(void *context, const LanternStatusMessage *peer_status, const char *peer_id);
static void lantern_client_on_peer_status(
    struct lantern_client *client,
    const LanternStatusMessage *peer_status,
    const char *peer_id);
static void lantern_client_on_blocks_request_complete(
    struct lantern_client *client,
    const char *peer_id,
    enum lantern_blocks_request_outcome outcome);
static int reqresp_collect_blocks(
    void *context,
    const LanternRoot *roots,
    size_t root_count,
    LanternBlocksByRootResponse *out_blocks);
static bool listen_address_is_unspecified(const char *addr);
static void adopt_validator_listen_address(struct lantern_client *client);
static int initialize_fork_choice(struct lantern_client *client);
static int restore_persisted_blocks(struct lantern_client *client);
static void connection_events_cb(const libp2p_event_t *evt, void *user_data);
static const char *connection_reason_text(int reason);
static void connection_counter_update(
    struct lantern_client *client,
    int delta,
    const peer_id_t *peer,
    bool inbound,
    int reason);
static void connection_counter_reset(struct lantern_client *client);
static int start_peer_dialer(struct lantern_client *client);
static void stop_peer_dialer(struct lantern_client *client);
static void *peer_dialer_thread(void *arg);
static void peer_dialer_attempt(struct lantern_client *client);
static void peer_dialer_sleep(struct lantern_client *client, unsigned seconds);
static bool lantern_root_is_zero(const LanternRoot *root);
static int lantern_client_schedule_blocks_request(
    struct lantern_client *client,
    const char *peer_id_text,
    const LanternRoot *root,
    bool use_legacy);
static void block_request_on_open(libp2p_stream_t *stream, void *user_data, int err);
static void *block_request_worker(void *arg);
static int stream_write_all(libp2p_stream_t *stream, const uint8_t *data, size_t length);
static int read_length_prefixed_chunk(libp2p_stream_t *stream, uint8_t **out_data, size_t *out_len, ssize_t *out_err);

struct lantern_peer_status_entry {
    char peer_id[128];
    LanternStatusMessage status;
    bool has_status;
    bool requested_head;
    uint64_t last_blocks_request_ms;
    uint32_t consecutive_blocks_failures;
};

struct block_request_ctx {
    struct lantern_client *client;
    peer_id_t peer_id;
    char peer_text[128];
    LanternRoot root;
    const char *protocol_id;
    bool using_legacy;
};

struct block_request_worker_args {
    struct block_request_ctx *ctx;
    libp2p_stream_t *stream;
};

struct lantern_persisted_block {
    LanternSignedBlock block;
    LanternRoot root;
};

struct lantern_persisted_block_list {
    struct lantern_persisted_block *items;
    size_t length;
    size_t capacity;
};

static uint64_t monotonic_millis(void) {
#if defined(_WIN32)
    LARGE_INTEGER freq = {0};
    LARGE_INTEGER counter = {0};
    if (!QueryPerformanceFrequency(&freq) || !QueryPerformanceCounter(&counter) || freq.QuadPart == 0) {
        return 0;
    }
    return (uint64_t)((counter.QuadPart * 1000ULL) / (uint64_t)freq.QuadPart);
#elif defined(CLOCK_MONOTONIC)
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
#else
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0) {
        return 0;
    }
    return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000ULL);
#endif
}

static uint64_t blocks_request_backoff_ms(uint32_t failures) {
    if (failures == 0) {
        return 0;
    }
    if (failures > LANTERN_BLOCKS_REQUEST_BACKOFF_MAX_FAILURES) {
        failures = LANTERN_BLOCKS_REQUEST_BACKOFF_MAX_FAILURES;
    }
    uint64_t backoff = (uint64_t)LANTERN_BLOCKS_REQUEST_BACKOFF_BASE_MS << (failures - 1u);
    if (backoff > LANTERN_BLOCKS_REQUEST_BACKOFF_MAX_MS) {
        return LANTERN_BLOCKS_REQUEST_BACKOFF_MAX_MS;
    }
    return backoff;
}

static void connection_counter_reset(struct lantern_client *client) {
    if (!client) {
        return;
    }
    if (!client->connection_lock_initialized) {
        client->connected_peers = 0;
        return;
    }
    if (pthread_mutex_lock(&client->connection_lock) == 0) {
        client->connected_peers = 0;
        pthread_mutex_unlock(&client->connection_lock);
    } else {
        client->connected_peers = 0;
    }
}

static void connection_counter_update(
    struct lantern_client *client,
    int delta,
    const peer_id_t *peer,
    bool inbound,
    int reason) {
    if (!client || !client->connection_lock_initialized) {
        return;
    }

    char peer_text[128];
    peer_text[0] = '\0';
    if (peer) {
        if (peer_id_to_string(peer, PEER_ID_FMT_BASE58_LEGACY, peer_text, sizeof(peer_text)) < 0) {
            peer_text[0] = '\0';
        }
    }

    size_t total = 0;
    if (pthread_mutex_lock(&client->connection_lock) == 0) {
        if (delta > 0) {
            client->connected_peers += (size_t)delta;
        } else if (delta < 0) {
            size_t decrease = (size_t)(-delta);
            if (client->connected_peers > decrease) {
                client->connected_peers -= decrease;
            } else {
                client->connected_peers = 0;
            }
        }
        total = client->connected_peers;
        pthread_mutex_unlock(&client->connection_lock);
    } else {
        return;
    }

    lantern_log_trace(
        "network",
        &(const struct lantern_log_metadata){
            .validator = client->node_id,
            .peer = peer_text[0] ? peer_text : NULL,
        },
        "connection %s inbound=%s total=%zu reason=%d (%s)",
        delta > 0 ? "opened" : "closed",
        inbound ? "true" : "false",
        total,
        reason,
        connection_reason_text(reason));
}

static void peer_dialer_sleep(struct lantern_client *client, unsigned seconds) {
    if (!client || seconds == 0u) {
        return;
    }
    struct timespec req = {.tv_sec = 1, .tv_nsec = 0};
    for (unsigned i = 0; i < seconds; ++i) {
        if (__atomic_load_n(&client->dialer_stop_flag, __ATOMIC_RELAXED) != 0) {
            break;
        }
        (void)nanosleep(&req, NULL);
    }
}

static bool listen_address_is_unspecified(const char *addr) {
    if (!addr) {
        return false;
    }
    if (strncmp(addr, "/ip4/0.0.0.0/", strlen("/ip4/0.0.0.0/")) == 0) {
        return true;
    }
    if (strncmp(addr, "/ip6/::/", strlen("/ip6/::/")) == 0) {
        return true;
    }
    return false;
}

static void adopt_validator_listen_address(struct lantern_client *client) {
    if (!client || !client->assigned_validators) {
        return;
    }
    const char *current = client->listen_address;
    if (!listen_address_is_unspecified(current)) {
        return;
    }
    const struct lantern_validator_config_enr *enr = &client->assigned_validators->enr;
    if (!enr->ip || *enr->ip == '\0' || enr->quic_port == 0) {
        return;
    }
    const char *fmt = strchr(enr->ip, ':') ? "/ip6/%s/udp/%u/quic_v1" : "/ip4/%s/udp/%u/quic_v1";
    char derived[128];
    int written = snprintf(derived, sizeof(derived), fmt, enr->ip, (unsigned)enr->quic_port);
    if (written <= 0 || (size_t)written >= sizeof(derived)) {
        lantern_log_warn(
            "network",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to derive listen address from ENR ip=%s port=%u",
            enr->ip,
            (unsigned)enr->quic_port);
        return;
    }
    if (set_owned_string(&client->listen_address, derived) != 0) {
        lantern_log_warn(
            "network",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to apply derived listen address %s",
            derived);
        return;
    }
    lantern_log_info(
        "network",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "using validator ENR listen multiaddr %s",
        client->listen_address);
}

static void peer_dialer_attempt(struct lantern_client *client) {
    if (!client || !client->network.host) {
        return;
    }

    size_t connected = client->connected_peers;
    if (client->connection_lock_initialized) {
        if (pthread_mutex_lock(&client->connection_lock) == 0) {
            connected = client->connected_peers;
            pthread_mutex_unlock(&client->connection_lock);
        }
    }

    if (connected > 0) {
        return;
    }

    const struct lantern_enr_record_list *enrs = &client->genesis.enrs;
    if (!enrs || enrs->count == 0) {
        return;
    }

    peer_id_t *local_peer = NULL;
    if (libp2p_host_get_peer_id(client->network.host, &local_peer) != 0) {
        local_peer = NULL;
    }

    for (size_t idx = 0; idx < enrs->count; ++idx) {
        if (__atomic_load_n(&client->dialer_stop_flag, __ATOMIC_RELAXED) != 0) {
            break;
        }

        const struct lantern_enr_record *record = &enrs->records[idx];
        if (!record || !record->encoded) {
            continue;
        }

        char multiaddr[256];
        peer_id_t peer_id = {0};
        if (lantern_libp2p_enr_to_multiaddr(record, multiaddr, sizeof(multiaddr), &peer_id) != 0) {
            continue;
        }

        bool is_self = false;
        if (local_peer) {
            int eq = peer_id_equals(local_peer, &peer_id);
            if (eq == 1) {
                is_self = true;
            }
        }

        if (!is_self) {
            (void)lantern_libp2p_host_add_enr_peer(&client->network, record, LANTERN_LIBP2P_DEFAULT_PEER_TTL_MS);

            char peer_text[128];
            if (peer_id_to_string(&peer_id, PEER_ID_FMT_BASE58_LEGACY, peer_text, sizeof(peer_text)) < 0) {
                peer_text[0] = '\0';
            }

            bool already_added = false;
            if (peer_text[0]) {
                already_added = string_list_contains(&client->dialer_peers, peer_text);
            }

            if (client->gossip_running && client->gossip.gossipsub) {
                if (!already_added) {
                    libp2p_err_t perr = libp2p_gossipsub_peering_add(client->gossip.gossipsub, &peer_id);
                    if (perr == LIBP2P_ERR_OK) {
                        if (peer_text[0]) {
                            (void)lantern_string_list_append(&client->dialer_peers, peer_text);
                        }
                        lantern_log_trace(
                            "network",
                            &(const struct lantern_log_metadata){
                                .validator = client->node_id,
                                .peer = peer_text[0] ? peer_text : record->encoded},
                            "dialer added peer to gossipsub peering");
                    }
                }
            }
        }

        peer_id_destroy(&peer_id);
    }

    if (local_peer) {
        peer_id_destroy(local_peer);
        free(local_peer);
    }
}

static void *peer_dialer_thread(void *arg) {
    struct lantern_client *client = (struct lantern_client *)arg;
    if (!client) {
        return NULL;
    }

    while (__atomic_load_n(&client->dialer_stop_flag, __ATOMIC_RELAXED) == 0) {
        peer_dialer_attempt(client);
        peer_dialer_sleep(client, LANTERN_PEER_DIAL_INTERVAL_SECONDS);
    }
    return NULL;
}

static int start_peer_dialer(struct lantern_client *client) {
    if (!client) {
        return -1;
    }
    if (client->dialer_thread_started) {
        return 0;
    }
    __atomic_store_n(&client->dialer_stop_flag, 0, __ATOMIC_RELAXED);
    int rc = pthread_create(&client->dialer_thread, NULL, peer_dialer_thread, client);
    if (rc != 0) {
        __atomic_store_n(&client->dialer_stop_flag, 1, __ATOMIC_RELAXED);
        return -1;
    }
    client->dialer_thread_started = true;
    return 0;
}

static void stop_peer_dialer(struct lantern_client *client) {
    if (!client) {
        return;
    }
    if (!client->dialer_thread_started) {
        __atomic_store_n(&client->dialer_stop_flag, 1, __ATOMIC_RELAXED);
        return;
    }
    __atomic_store_n(&client->dialer_stop_flag, 1, __ATOMIC_RELAXED);
    (void)pthread_join(client->dialer_thread, NULL);
    client->dialer_thread_started = false;
}

static void connection_events_cb(const libp2p_event_t *evt, void *user_data) {
    if (!evt || !user_data) {
        return;
    }
    struct lantern_client *client = (struct lantern_client *)user_data;
    switch (evt->kind) {
    case LIBP2P_EVT_CONN_OPENED:
        connection_counter_update(client, 1, evt->u.conn_opened.peer, evt->u.conn_opened.inbound, 0);
        break;
    case LIBP2P_EVT_CONN_CLOSED:
        connection_counter_update(client, -1, evt->u.conn_closed.peer, false, evt->u.conn_closed.reason);
        break;
    case LIBP2P_EVT_DIALING: {
        char peer_text[128];
        peer_text[0] = '\0';
        if (evt->u.dialing.peer) {
            if (peer_id_to_string(evt->u.dialing.peer, PEER_ID_FMT_BASE58_LEGACY, peer_text, sizeof(peer_text)) < 0) {
                peer_text[0] = '\0';
            }
        }
        lantern_log_debug(
            "network",
            &(const struct lantern_log_metadata){
                .validator = client->node_id,
                .peer = peer_text[0] ? peer_text : NULL,
            },
            "dialing peer addr=%s",
            evt->u.dialing.addr ? evt->u.dialing.addr : "-");
        break;
    }
    case LIBP2P_EVT_OUTGOING_CONNECTION_ERROR: {
        char peer_text[128];
        peer_text[0] = '\0';
        if (evt->u.outgoing_conn_error.peer) {
            if (peer_id_to_string(evt->u.outgoing_conn_error.peer, PEER_ID_FMT_BASE58_LEGACY, peer_text, sizeof(peer_text)) < 0) {
                peer_text[0] = '\0';
            }
        }
        lantern_log_warn(
            "network",
            &(const struct lantern_log_metadata){
                .validator = client->node_id,
                .peer = peer_text[0] ? peer_text : NULL,
            },
            "outgoing connection error code=%d (%s) msg=%s",
            evt->u.outgoing_conn_error.code,
            connection_reason_text(evt->u.outgoing_conn_error.code),
            evt->u.outgoing_conn_error.msg ? evt->u.outgoing_conn_error.msg : "-");
        break;
    }
    case LIBP2P_EVT_INCOMING_CONNECTION_ERROR: {
        char peer_text[128];
        peer_text[0] = '\0';
        if (evt->u.incoming_conn_error.peer) {
            if (peer_id_to_string(evt->u.incoming_conn_error.peer, PEER_ID_FMT_BASE58_LEGACY, peer_text, sizeof(peer_text)) < 0) {
                peer_text[0] = '\0';
            }
        }
        lantern_log_warn(
            "network",
            &(const struct lantern_log_metadata){
                .validator = client->node_id,
                .peer = peer_text[0] ? peer_text : NULL,
            },
            "incoming connection error code=%d (%s) msg=%s",
            evt->u.incoming_conn_error.code,
            connection_reason_text(evt->u.incoming_conn_error.code),
            evt->u.incoming_conn_error.msg ? evt->u.incoming_conn_error.msg : "-");
        break;
    }
    default:
        break;
    }
}

static const char *connection_reason_text(int reason) {
    switch (reason) {
    case 0:
        return "ok";
    case LIBP2P_ERR_NULL_PTR:
        return "null_ptr";
    case LIBP2P_ERR_AGAIN:
        return "again";
    case LIBP2P_ERR_EOF:
        return "eof";
    case LIBP2P_ERR_TIMEOUT:
        return "timeout";
    case LIBP2P_ERR_CLOSED:
        return "closed";
    case LIBP2P_ERR_RESET:
        return "reset";
    case LIBP2P_ERR_INTERNAL:
        return "internal";
    case LIBP2P_ERR_PROTO_NEGOTIATION_FAILED:
        return "protocol_negotiation_failed";
    case LIBP2P_ERR_MSG_TOO_LARGE:
        return "msg_too_large";
    case LIBP2P_ERR_UNSUPPORTED:
        return "unsupported";
    case LIBP2P_ERR_CANCELED:
        return "canceled";
    default:
        return "unknown";
    }
}

static void persisted_block_list_init(struct lantern_persisted_block_list *list) {
    if (!list) {
        return;
    }
    list->items = NULL;
    list->length = 0;
    list->capacity = 0;
}

static void persisted_block_list_reset(struct lantern_persisted_block_list *list) {
    if (!list) {
        return;
    }
    if (list->items) {
        for (size_t i = 0; i < list->length; ++i) {
            lantern_block_body_reset(&list->items[i].block.message.body);
        }
        free(list->items);
    }
    list->items = NULL;
    list->length = 0;
    list->capacity = 0;
}

static int clone_signed_block(const LanternSignedBlock *source, LanternSignedBlock *dest) {
    if (!source || !dest) {
        return -1;
    }
    memset(dest, 0, sizeof(*dest));
    dest->signature = source->signature;
    dest->message.slot = source->message.slot;
    dest->message.proposer_index = source->message.proposer_index;
    dest->message.parent_root = source->message.parent_root;
    dest->message.state_root = source->message.state_root;
    lantern_block_body_init(&dest->message.body);
    if (lantern_attestations_copy(&dest->message.body.attestations, &source->message.body.attestations) != 0) {
        lantern_block_body_reset(&dest->message.body);
        return -1;
    }
    return 0;
}

static int persisted_block_list_append(
    struct lantern_persisted_block_list *list,
    const LanternSignedBlock *block,
    const LanternRoot *root) {
    if (!list || !block || !root) {
        return -1;
    }
    if (list->length == list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 4u : list->capacity * 2u;
        struct lantern_persisted_block *expanded = realloc(
            list->items,
            new_capacity * sizeof(*expanded));
        if (!expanded) {
            return -1;
        }
        list->items = expanded;
        list->capacity = new_capacity;
    }
    struct lantern_persisted_block *entry = &list->items[list->length];
    if (clone_signed_block(block, &entry->block) != 0) {
        return -1;
    }
    entry->root = *root;
    list->length += 1;
    return 0;
}

static int collect_block_visitor(
    const LanternSignedBlock *block,
    const LanternRoot *root,
    void *context) {
    if (!context) {
        return -1;
    }
    struct lantern_persisted_block_list *list = context;
    return persisted_block_list_append(list, block, root);
}

static int compare_blocks_by_slot(const void *lhs_ptr, const void *rhs_ptr) {
    const struct lantern_persisted_block *lhs = lhs_ptr;
    const struct lantern_persisted_block *rhs = rhs_ptr;
    if (lhs->block.message.slot < rhs->block.message.slot) {
        return -1;
    }
    if (lhs->block.message.slot > rhs->block.message.slot) {
        return 1;
    }
    return memcmp(lhs->root.bytes, rhs->root.bytes, LANTERN_ROOT_SIZE);
}

static void local_validator_cleanup(struct lantern_local_validator *validator) {
    if (!validator) {
        return;
    }
    if (validator->secret && validator->secret_len > 0) {
        lantern_secure_zero(validator->secret, validator->secret_len);
        free(validator->secret);
    }
    validator->secret = NULL;
    validator->secret_len = 0;
    validator->has_secret = false;
}

static void reset_local_validators(struct lantern_client *client) {
    if (!client) {
        return;
    }
    if (client->local_validators) {
        for (size_t i = 0; i < client->local_validator_count; ++i) {
            local_validator_cleanup(&client->local_validators[i]);
        }
        free(client->local_validators);
        client->local_validators = NULL;
    }
    client->local_validator_count = 0;
}

static int decode_validator_secret(const char *hex, uint8_t **out_key, size_t *out_len) {
    if (!hex || !out_key || !out_len) {
        return -1;
    }

    char *dup = lantern_string_duplicate(hex);
    if (!dup) {
        return -1;
    }
    char *trimmed = lantern_trim_whitespace(dup);
    if (!trimmed || *trimmed == '\0') {
        lantern_secure_zero(dup, strlen(dup));
        free(dup);
        return -1;
    }

    const char *hex_start = trimmed;
    if (hex_start[0] == '0' && (hex_start[1] == 'x' || hex_start[1] == 'X')) {
        hex_start += 2;
    }
    size_t hex_len = strlen(hex_start);
    if (hex_len == 0 || (hex_len % 2) != 0) {
        lantern_secure_zero(dup, strlen(dup));
        free(dup);
        return -1;
    }

    size_t secret_len = hex_len / 2;
    uint8_t *secret = malloc(secret_len);
    if (!secret) {
        lantern_secure_zero(dup, strlen(dup));
        free(dup);
        return -1;
    }

    if (lantern_hex_decode(trimmed, secret, secret_len) != 0) {
        lantern_secure_zero(secret, secret_len);
        free(secret);
        lantern_secure_zero(dup, strlen(dup));
        free(dup);
        return -1;
    }

    lantern_secure_zero(dup, strlen(dup));
    free(dup);

    *out_key = secret;
    *out_len = secret_len;
    return 0;
}

void lantern_client_options_init(struct lantern_client_options *options) {
    if (!options) {
        return;
    }

    options->data_dir = LANTERN_DEFAULT_DATA_DIR;
    options->genesis_config_path = LANTERN_DEFAULT_GENESIS_CONFIG;
    options->validator_registry_path = LANTERN_DEFAULT_VALIDATOR_REGISTRY;
    options->nodes_path = LANTERN_DEFAULT_NODES_FILE;
    options->genesis_state_path = LANTERN_DEFAULT_GENESIS_STATE;
    options->validator_config_path = LANTERN_DEFAULT_VALIDATOR_CONFIG;
    options->node_id = LANTERN_DEFAULT_NODE_ID;
    options->node_key_hex = NULL;
    options->node_key_path = NULL;
    options->listen_address = LANTERN_DEFAULT_LISTEN_ADDR;
    options->http_port = LANTERN_DEFAULT_HTTP_PORT;
    options->metrics_port = LANTERN_DEFAULT_METRICS_PORT;
    options->devnet = LANTERN_DEFAULT_DEVNET;
    lantern_string_list_init(&options->bootnodes);
}

void lantern_client_options_free(struct lantern_client_options *options) {
    if (!options) {
        return;
    }
    lantern_string_list_reset(&options->bootnodes);
}

int lantern_client_options_add_bootnode(struct lantern_client_options *options, const char *bootnode) {
    if (!options || !bootnode) {
        return -1;
    }
    return lantern_string_list_append(&options->bootnodes, bootnode);
}

int lantern_init(struct lantern_client *client, const struct lantern_client_options *options) {
    if (!client || !options) {
        return -1;
    }

    memset(client, 0, sizeof(*client));
    lantern_string_list_init(&client->bootnodes);
    lantern_string_list_init(&client->dialer_peers);
    lantern_genesis_artifacts_init(&client->genesis);
    lantern_enr_record_init(&client->local_enr);
    lantern_libp2p_host_init(&client->network);
    client->ping_server = NULL;
    client->ping_running = false;
    lantern_gossipsub_service_init(&client->gossip);
    lantern_reqresp_service_init(&client->reqresp);
    client->reqresp_running = false;
    lantern_validator_assignment_init(&client->validator_assignment);
    client->has_validator_assignment = false;
    lantern_consensus_runtime_reset(&client->runtime);
    client->has_runtime = false;
    lantern_metrics_server_init(&client->metrics_server);
    client->metrics_running = false;
    lantern_http_server_init(&client->http_server);
   client->http_running = false;
   lantern_state_init(&client->state);
   lantern_fork_choice_init(&client->fork_choice);
   client->has_fork_choice = false;
    client->dialer_thread_started = false;
    client->dialer_stop_flag = 1;

    if (set_owned_string(&client->data_dir, options->data_dir) != 0) {
        goto error;
    }
    if (set_owned_string(&client->node_id, options->node_id) != 0) {
        goto error;
    }
    lantern_log_set_node_id(client->node_id);
    if (set_owned_string(&client->listen_address, options->listen_address) != 0) {
        goto error;
    }
    if (set_owned_string(&client->devnet, options->devnet) != 0) {
        goto error;
    }
    if (!client->status_lock_initialized) {
        if (pthread_mutex_init(&client->status_lock, NULL) != 0) {
            lantern_log_error(
                "client",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to initialize peer status lock");
            goto error;
        }
        client->status_lock_initialized = true;
    }
    client->http_port = options->http_port;
    client->metrics_port = options->metrics_port;
    if (lantern_storage_prepare(client->data_dir) != 0) {
        lantern_log_error(
            "storage",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to prepare data directory '%s'",
            client->data_dir);
        goto error;
    }

    if (lantern_string_list_copy(&client->bootnodes, &options->bootnodes) != 0) {
        goto error;
    }

    if (copy_genesis_paths(&client->genesis_paths, options) != 0) {
        goto error;
    }

    if (lantern_genesis_load(&client->genesis, &client->genesis_paths) != 0) {
        goto error;
    }

    bool loaded_from_storage = false;
    int storage_state_rc = lantern_storage_load_state(client->data_dir, &client->state);
    if (storage_state_rc == 0) {
        client->has_state = true;
        loaded_from_storage = true;
    } else if (storage_state_rc < 0) {
        lantern_log_error(
            "storage",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to load persisted state");
        goto error;
    } else {
        if (!client->genesis.state_bytes || client->genesis.state_size == 0) {
            lantern_log_warn(
                "client",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "genesis state bytes missing; head snapshot disabled");
        } else if (lantern_ssz_decode_state(&client->state, client->genesis.state_bytes, client->genesis.state_size) != 0) {
            lantern_log_warn(
                "client",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to decode genesis state; head snapshot disabled");
        } else if (lantern_state_prepare_validator_votes(&client->state, client->state.config.num_validators) != 0) {
            lantern_log_error(
                "client",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to prepare validator vote records");
            goto error;
        } else {
            client->has_state = true;
        }
    }
    if (client->has_state) {
        int votes_rc = lantern_storage_load_votes(client->data_dir, &client->state);
        if (votes_rc < 0) {
            lantern_log_error(
                "storage",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to load persisted votes");
            goto error;
        }
        if (initialize_fork_choice(client) != 0) {
            goto error;
        }
        if (restore_persisted_blocks(client) != 0) {
            goto error;
        }
    }
    if (client->has_state && !loaded_from_storage) {
        if (lantern_storage_save_state(client->data_dir, &client->state) != 0) {
            lantern_log_warn(
                "storage",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to persist initial state snapshot");
        }
        if (lantern_storage_save_votes(client->data_dir, &client->state) != 0) {
            lantern_log_warn(
                "storage",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to persist initial votes snapshot");
        }
    }

    client->assigned_validators = lantern_validator_config_find(
        &client->genesis.validator_config,
        client->node_id);

    if (!client->assigned_validators) {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "node-id '%s' not found in validator-config",
            client->node_id);
        goto error;
    }
    if (!client->assigned_validators->enr.ip || client->assigned_validators->enr.quic_port == 0) {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "validator '%s' missing ENR fields",
            client->node_id);
        goto error;
    }
    adopt_validator_listen_address(client);
    if (compute_local_validator_assignment(client) != 0) {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to compute validator assignment for '%s'",
            client->node_id);
        goto error;
    }
    if (populate_local_validators(client) != 0) {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to enumerate local validators for '%s'",
            client->node_id);
        goto error;
    }
    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "validator slice start=%" PRIu64 " count=%" PRIu64,
        client->validator_assignment.start_index,
        client->validator_assignment.count);
    if (init_consensus_runtime(client) != 0) {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to initialize consensus runtime");
        goto error;
    }
    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "consensus runtime ready genesis_time=%" PRIu64 " validators=%" PRIu64,
        client->genesis.chain_config.genesis_time,
        client->genesis.chain_config.validator_count);

    uint8_t node_key[32];
    if (load_node_key_bytes(options, node_key) != 0) {
        goto error;
    }
    memcpy(client->node_private_key, node_key, sizeof(node_key));
    client->has_node_private_key = true;

    struct lantern_libp2p_config net_cfg = {
        .listen_multiaddr = client->listen_address,
        .secp256k1_secret = node_key,
        .secret_len = sizeof(node_key),
    };
    if (lantern_libp2p_host_start(&client->network, &net_cfg) != 0) {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to initialize libp2p host");
        memset(node_key, 0, sizeof(node_key));
        goto error;
    }

    if (!client->connection_lock_initialized) {
        if (pthread_mutex_init(&client->connection_lock, NULL) != 0) {
            lantern_log_error(
                "network",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to initialize connection lock");
            memset(node_key, 0, sizeof(node_key));
            goto error;
        }
        client->connection_lock_initialized = true;
    }
    connection_counter_reset(client);

    if (libp2p_event_subscribe(client->network.host, connection_events_cb, client, &client->connection_subscription) != 0) {
        lantern_log_error(
            "network",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to subscribe to libp2p connection events");
        memset(node_key, 0, sizeof(node_key));
        goto error;
    }

    {
        libp2p_protocol_server_t *ping_server = NULL;
        if (libp2p_ping_service_start(client->network.host, &ping_server) != 0) {
            lantern_log_error(
                "network",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to start libp2p ping service");
            memset(node_key, 0, sizeof(node_key));
            goto error;
        }
        client->ping_server = ping_server;
        client->ping_running = true;
        lantern_log_info(
            "network",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "libp2p ping service started");
    }

    struct lantern_gossipsub_config gossip_cfg = {
        .host = client->network.host,
        .devnet = client->devnet,
    };
    if (lantern_gossipsub_service_start(&client->gossip, &gossip_cfg) != 0) {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to start gossipsub service");
        memset(node_key, 0, sizeof(node_key));
        goto error;
    }
    client->gossip_running = true;

    struct lantern_reqresp_service_callbacks req_callbacks;
    memset(&req_callbacks, 0, sizeof(req_callbacks));
    req_callbacks.context = client;
    req_callbacks.build_status = reqresp_build_status;
    req_callbacks.handle_status = reqresp_handle_status;
    req_callbacks.collect_blocks = reqresp_collect_blocks;

    struct lantern_reqresp_service_config req_config;
    memset(&req_config, 0, sizeof(req_config));
    req_config.host = client->network.host;
    req_config.callbacks = &req_callbacks;
    if (lantern_reqresp_service_start(&client->reqresp, &req_config) != 0) {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to start request/response service");
        memset(node_key, 0, sizeof(node_key));
        goto error;
    }
    client->reqresp_running = true;

    if (append_genesis_bootnodes(client) != 0) {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to append bootnodes from genesis");
        memset(node_key, 0, sizeof(node_key));
        goto error;
    }

    if (lantern_enr_record_build_v4(
            &client->local_enr,
            node_key,
            client->assigned_validators->enr.ip,
            client->assigned_validators->enr.quic_port,
            client->assigned_validators->enr.sequence)
        != 0) {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to build local ENR");
        memset(node_key, 0, sizeof(node_key));
        goto error;
    }
    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "local ENR prepared sequence=%" PRIu64,
        client->assigned_validators->enr.sequence);
    memset(node_key, 0, sizeof(node_key));

    if (start_peer_dialer(client) != 0) {
        lantern_log_warn(
            "network",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to start peer dialer thread");
    }

    struct lantern_http_server_config http_config;
    memset(&http_config, 0, sizeof(http_config));
    http_config.port = client->http_port;
    http_config.callbacks.context = client;
    http_config.callbacks.snapshot_head = http_snapshot_head;
    http_config.callbacks.validator_count = http_validator_count_cb;
    http_config.callbacks.validator_info = http_validator_info_cb;
    http_config.callbacks.set_validator_status = http_set_validator_status_cb;
    if (lantern_http_server_start(&client->http_server, &http_config) != 0) {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to start HTTP server on port %" PRIu16,
            client->http_port);
        goto error;
    }
    client->http_running = true;

    struct lantern_metrics_callbacks metrics_callbacks;
    memset(&metrics_callbacks, 0, sizeof(metrics_callbacks));
    metrics_callbacks.context = client;
    metrics_callbacks.snapshot = metrics_snapshot_cb;
    if (client->metrics_port != 0) {
        if (lantern_metrics_server_start(&client->metrics_server, client->metrics_port, &metrics_callbacks) != 0) {
            lantern_log_error(
                "client",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to start metrics server on port %" PRIu16,
                client->metrics_port);
            goto error;
        }
        client->metrics_running = true;
    }

    return 0;

error:
    lantern_shutdown(client);
    return -1;
}

void lantern_shutdown(struct lantern_client *client) {
    if (!client) {
        return;
    }

    stop_peer_dialer(client);

    lantern_metrics_server_stop(&client->metrics_server);
    lantern_metrics_server_init(&client->metrics_server);
    client->metrics_running = false;

    lantern_http_server_stop(&client->http_server);
    lantern_http_server_init(&client->http_server);
    client->http_running = false;

    if (client->network.host && client->connection_subscription) {
        libp2p_event_unsubscribe(client->network.host, client->connection_subscription);
    }
    client->connection_subscription = NULL;

    if (client->network.host && client->ping_running && client->ping_server) {
        if (libp2p_ping_service_stop(client->network.host, client->ping_server) != 0) {
            lantern_log_warn(
                "network",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to stop libp2p ping service cleanly");
        } else {
            lantern_log_info(
                "network",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "shutdown: libp2p ping service stopped");
        }
    }
    client->ping_server = NULL;
    client->ping_running = false;

    if (client->connection_lock_initialized) {
        connection_counter_reset(client);
        pthread_mutex_destroy(&client->connection_lock);
        client->connection_lock_initialized = false;
    } else {
        client->connected_peers = 0;
    }

    if (client->status_lock_initialized) {
        if (pthread_mutex_lock(&client->status_lock) == 0) {
            free(client->peer_status_entries);
            client->peer_status_entries = NULL;
            client->peer_status_count = 0;
            client->peer_status_capacity = 0;
            pthread_mutex_unlock(&client->status_lock);
        } else {
            free(client->peer_status_entries);
            client->peer_status_entries = NULL;
            client->peer_status_count = 0;
            client->peer_status_capacity = 0;
        }
        pthread_mutex_destroy(&client->status_lock);
        client->status_lock_initialized = false;
    } else {
        free(client->peer_status_entries);
        client->peer_status_entries = NULL;
        client->peer_status_count = 0;
        client->peer_status_capacity = 0;
    }

    if (client->validator_lock_initialized) {
        if (pthread_mutex_lock(&client->validator_lock) == 0) {
            free(client->validator_enabled);
            client->validator_enabled = NULL;
            pthread_mutex_unlock(&client->validator_lock);
        } else {
            free(client->validator_enabled);
            client->validator_enabled = NULL;
        }
        pthread_mutex_destroy(&client->validator_lock);
        client->validator_lock_initialized = false;
    } else {
        free(client->validator_enabled);
        client->validator_enabled = NULL;
    }

    lantern_string_list_reset(&client->dialer_peers);
    lantern_string_list_reset(&client->bootnodes);
    free(client->data_dir);
    client->data_dir = NULL;
    free(client->node_id);
    client->node_id = NULL;
    free(client->listen_address);
    client->listen_address = NULL;
    free(client->devnet);
    client->devnet = NULL;

    reset_genesis_paths(&client->genesis_paths);
    lantern_genesis_artifacts_reset(&client->genesis);
    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "shutdown: stopping request/response service");
    lantern_reqresp_service_reset(&client->reqresp);
    lantern_reqresp_service_init(&client->reqresp);
    client->reqresp_running = false;
    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "shutdown: request/response service stopped");
    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "shutdown: stopping gossipsub");
    lantern_gossipsub_service_reset(&client->gossip);
    client->gossip_running = false;
    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "shutdown: gossipsub stopped");
    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "shutdown: resetting libp2p host");
    lantern_libp2p_host_reset(&client->network);
    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "shutdown: libp2p host reset");
    lantern_enr_record_reset(&client->local_enr);
    memset(client->node_private_key, 0, sizeof(client->node_private_key));
    client->has_node_private_key = false;
    if (client->has_state) {
        lantern_state_reset(&client->state);
        client->has_state = false;
    } else {
        lantern_state_reset(&client->state);
    }
    lantern_fork_choice_reset(&client->fork_choice);
    client->has_fork_choice = false;
    reset_local_validators(client);
    lantern_validator_assignment_init(&client->validator_assignment);
    client->has_validator_assignment = false;
    lantern_consensus_runtime_reset(&client->runtime);
    client->has_runtime = false;

    client->http_port = 0;
    client->metrics_port = 0;
    client->assigned_validators = NULL;
    lantern_log_reset_node_id();
}

static bool string_list_contains(const struct lantern_string_list *list, const char *value) {
    if (!list || !value) {
        return false;
    }
    for (size_t i = 0; i < list->len; ++i) {
        if (list->items && list->items[i] && strcmp(list->items[i], value) == 0) {
            return true;
        }
    }
    return false;
}

static int append_unique_bootnode(struct lantern_string_list *list, const char *value) {
    if (!list || !value) {
        return -1;
    }
    if (*value == '\0') {
        return 0;
    }
    if (string_list_contains(list, value)) {
        return 0;
    }
    return lantern_string_list_append(list, value);
}

static int append_genesis_bootnodes(struct lantern_client *client) {
    if (!client) {
        return -1;
    }
    const struct lantern_enr_record_list *enrs = &client->genesis.enrs;
    for (size_t i = 0; i < enrs->count; ++i) {
        const struct lantern_enr_record *record = &enrs->records[i];
        if (!record->encoded) {
            continue;
        }
        if (append_unique_bootnode(&client->bootnodes, record->encoded) != 0) {
            return -1;
        }
        if (client->network.host) {
            if (lantern_libp2p_host_add_enr_peer(&client->network, record, LANTERN_LIBP2P_DEFAULT_PEER_TTL_MS) != 0) {
                lantern_log_warn(
                    "network",
                    &(const struct lantern_log_metadata){
                        .validator = client->node_id,
                        .peer = record->encoded},
                    "failed to add ENR peer from genesis");
                continue;
            }
            lantern_log_info(
                "network",
                &(const struct lantern_log_metadata){
                    .validator = client->node_id,
                    .peer = record->encoded},
                "bootnode registered sequence=%" PRIu64,
                record->sequence);
        }
    }
    return 0;
}

static int compute_local_validator_assignment(struct lantern_client *client) {
    if (!client || !client->assigned_validators) {
        return -1;
    }
    lantern_validator_assignment_init(&client->validator_assignment);
    client->has_validator_assignment = false;
    if (lantern_validator_assignment_from_config(
            &client->genesis.validator_config,
            client->assigned_validators,
            &client->validator_assignment)
        != 0) {
        return -1;
    }
    if (!lantern_validator_assignment_is_valid(&client->validator_assignment)) {
        return -1;
    }
    client->has_validator_assignment = true;
    return 0;
}

static int populate_local_validators(struct lantern_client *client) {
    if (!client || !client->has_validator_assignment || !client->assigned_validators) {
        return -1;
    }

    uint64_t local_count = client->validator_assignment.count;
    uint64_t start_index = client->validator_assignment.start_index;
    if (local_count == 0) {
        return -1;
    }
    if (local_count > SIZE_MAX) {
        return -1;
    }
    if (local_count > UINT64_MAX - start_index) {
        return -1;
    }

    uint64_t end_index = start_index + local_count;
    uint64_t total_validators = client->genesis.chain_config.validator_count;
    if (end_index > total_validators) {
        return -1;
    }
    if (!client->genesis.validator_registry.records
        || client->genesis.validator_registry.count < end_index) {
        return -1;
    }

    const char *priv_hex = client->assigned_validators->privkey_hex;
    if (!priv_hex || *priv_hex == '\0') {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "validator '%s' missing privkey in validator-config",
            client->node_id);
        return -1;
    }

    uint8_t *decoded_secret = NULL;
    size_t decoded_len = 0;
    if (decode_validator_secret(priv_hex, &decoded_secret, &decoded_len) != 0 || decoded_len == 0) {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "validator '%s' privkey is invalid",
            client->node_id);
        if (decoded_secret) {
            lantern_secure_zero(decoded_secret, decoded_len);
            free(decoded_secret);
        }
        return -1;
    }

    size_t stored_len = strlen(client->assigned_validators->privkey_hex);
    if (stored_len > 0) {
        lantern_secure_zero(client->assigned_validators->privkey_hex, stored_len);
        client->assigned_validators->privkey_hex[0] = '\0';
    }

    size_t count = (size_t)local_count;
    struct lantern_local_validator *validators = calloc(count, sizeof(*validators));
    if (!validators) {
        lantern_secure_zero(decoded_secret, decoded_len);
        free(decoded_secret);
        return -1;
    }

    for (size_t i = 0; i < count; ++i) {
        uint64_t global_index = start_index + (uint64_t)i;
        validators[i].global_index = global_index;
        validators[i].registry = &client->genesis.validator_registry.records[global_index];
        validators[i].secret_len = decoded_len;
        if (decoded_len > 0) {
            validators[i].secret = malloc(decoded_len);
            if (!validators[i].secret) {
                for (size_t j = 0; j <= i; ++j) {
                    local_validator_cleanup(&validators[j]);
                }
                free(validators);
                lantern_secure_zero(decoded_secret, decoded_len);
                free(decoded_secret);
                return -1;
            }
            memcpy(validators[i].secret, decoded_secret, decoded_len);
            validators[i].has_secret = true;
        }
    }

    bool *enabled = calloc(count, sizeof(*enabled));
    if (!enabled) {
        for (size_t i = 0; i < count; ++i) {
            local_validator_cleanup(&validators[i]);
        }
        free(validators);
        lantern_secure_zero(decoded_secret, decoded_len);
        free(decoded_secret);
        return -1;
    }
    for (size_t i = 0; i < count; ++i) {
        enabled[i] = true;
    }

    if (!client->validator_lock_initialized) {
        if (pthread_mutex_init(&client->validator_lock, NULL) != 0) {
            free(enabled);
            for (size_t i = 0; i < count; ++i) {
                local_validator_cleanup(&validators[i]);
            }
            free(validators);
            lantern_secure_zero(decoded_secret, decoded_len);
            free(decoded_secret);
            return -1;
        }
        client->validator_lock_initialized = true;
    }

    if (pthread_mutex_lock(&client->validator_lock) != 0) {
        free(enabled);
        for (size_t i = 0; i < count; ++i) {
            local_validator_cleanup(&validators[i]);
        }
        free(validators);
        lantern_secure_zero(decoded_secret, decoded_len);
        free(decoded_secret);
        return -1;
    }

    free(client->validator_enabled);
    client->validator_enabled = enabled;
    enabled = NULL;

    reset_local_validators(client);
    client->local_validators = validators;
    client->local_validator_count = count;
    validators = NULL;

    pthread_mutex_unlock(&client->validator_lock);

    lantern_secure_zero(decoded_secret, decoded_len);
    free(decoded_secret);
    return 0;
}

static int find_local_validator_index(const struct lantern_client *client, uint64_t global_index, size_t *out_index) {
    if (!client) {
        return -1;
    }
    for (size_t i = 0; i < client->local_validator_count; ++i) {
        if (client->local_validators && client->local_validators[i].global_index == global_index) {
            if (out_index) {
                *out_index = i;
            }
            return 0;
        }
    }
    return -1;
}

static int http_snapshot_head(void *context, struct lantern_http_head_snapshot *out_snapshot) {
    if (!context || !out_snapshot) {
        return -1;
    }
    struct lantern_client *client = context;
    if (!client->has_state) {
        return -1;
    }
    memset(out_snapshot, 0, sizeof(*out_snapshot));
    out_snapshot->slot = client->state.slot;
    if (lantern_hash_tree_root_block_header(&client->state.latest_block_header, &out_snapshot->head_root) != 0) {
        return -1;
    }
    out_snapshot->justified = client->state.latest_justified;
    out_snapshot->finalized = client->state.latest_finalized;
    return 0;
}

static size_t http_validator_count_cb(void *context) {
    const struct lantern_client *client = context;
    if (!client) {
        return 0;
    }
    return client->local_validator_count;
}

static int http_validator_info_cb(void *context, size_t index, struct lantern_http_validator_info *out_info) {
    if (!context || !out_info) {
        return -1;
    }
    struct lantern_client *client = context;
    if (index >= client->local_validator_count || !client->local_validators) {
        return -1;
    }
    memset(out_info, 0, sizeof(*out_info));
    out_info->global_index = client->local_validators[index].global_index;

    bool enabled = true;
    if (client->validator_lock_initialized) {
        if (pthread_mutex_lock(&client->validator_lock) != 0) {
            return -1;
        }
        if (client->validator_enabled && index < client->local_validator_count) {
            enabled = client->validator_enabled[index];
        }
        pthread_mutex_unlock(&client->validator_lock);
    } else if (client->validator_enabled && index < client->local_validator_count) {
        enabled = client->validator_enabled[index];
    }
    out_info->enabled = enabled;

    const char *base = client->node_id ? client->node_id : "validator";
    int written = snprintf(out_info->label, sizeof(out_info->label), "%s#%" PRIu64, base, out_info->global_index);
    if (written < 0 || (size_t)written >= sizeof(out_info->label)) {
        strncpy(out_info->label, base, sizeof(out_info->label));
        out_info->label[sizeof(out_info->label) - 1] = '\0';
    }
    return 0;
}

static int http_set_validator_status_cb(void *context, uint64_t global_index, bool enabled) {
    if (!context) {
        return -1;
    }
    struct lantern_client *client = context;
    if (!client->validator_lock_initialized || !client->validator_enabled) {
        return -1;
    }
    if (pthread_mutex_lock(&client->validator_lock) != 0) {
        return -1;
    }
    size_t local_index = 0;
    if (find_local_validator_index(client, global_index, &local_index) != 0
        || local_index >= client->local_validator_count) {
        pthread_mutex_unlock(&client->validator_lock);
        return -1;
    }
    client->validator_enabled[local_index] = enabled;
    pthread_mutex_unlock(&client->validator_lock);

    lantern_log_info(
        "validator",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "validator %" PRIu64 " %s",
        global_index,
        enabled ? "activated" : "deactivated");
    return 0;
}

static int metrics_snapshot_cb(void *context, struct lantern_metrics_snapshot *out_snapshot) {
    if (!context || !out_snapshot) {
        return -1;
    }
    struct lantern_client *client = context;
    memset(out_snapshot, 0, sizeof(*out_snapshot));

    if (client->node_id) {
        snprintf(out_snapshot->node_id, sizeof(out_snapshot->node_id), "%s", client->node_id);
    }

    size_t connected = 0;
    if (client->connection_lock_initialized) {
        if (pthread_mutex_lock(&client->connection_lock) == 0) {
            connected = client->connected_peers;
            pthread_mutex_unlock(&client->connection_lock);
        }
    }

    if (client->has_state) {
        out_snapshot->head_slot = client->state.slot;
        if (lantern_hash_tree_root_block_header(&client->state.latest_block_header, &out_snapshot->head_root) != 0) {
            memset(&out_snapshot->head_root, 0, sizeof(out_snapshot->head_root));
        }
        out_snapshot->justified = client->state.latest_justified;
        out_snapshot->finalized = client->state.latest_finalized;
    } else {
        memset(&out_snapshot->head_root, 0, sizeof(out_snapshot->head_root));
        memset(&out_snapshot->justified, 0, sizeof(out_snapshot->justified));
        memset(&out_snapshot->finalized, 0, sizeof(out_snapshot->finalized));
        out_snapshot->head_slot = 0;
    }

    out_snapshot->known_peers = client->bootnodes.len;
    out_snapshot->connected_peers = connected;
    out_snapshot->gossip_topics = 2;
    out_snapshot->gossip_validation_failures = 0;
    out_snapshot->validators_total = client->local_validator_count;

    size_t active = 0;
    if (client->validator_enabled && client->local_validator_count > 0) {
        bool counted = false;
        if (client->validator_lock_initialized) {
            if (pthread_mutex_lock(&client->validator_lock) == 0) {
                for (size_t i = 0; i < client->local_validator_count; ++i) {
                    if (client->validator_enabled[i]) {
                        active++;
                    }
                }
                pthread_mutex_unlock(&client->validator_lock);
                counted = true;
            }
        }
        if (!counted) {
            for (size_t i = 0; i < client->local_validator_count; ++i) {
                if (client->validator_enabled[i]) {
                    active++;
                }
            }
        }
    } else {
        active = client->local_validator_count;
    }
    out_snapshot->validators_active = active;
    return 0;
}

static void format_root_hex(const LanternRoot *root, char *out, size_t out_len) {
    if (!out || out_len == 0) {
        return;
    }
    if (!root) {
        out[0] = '\0';
        return;
    }
    if (lantern_bytes_to_hex(root->bytes, LANTERN_ROOT_SIZE, out, out_len, 1) != 0) {
        out[0] = '\0';
    }
}

static bool lantern_root_is_zero(const LanternRoot *root) {
    if (!root) {
        return true;
    }
    for (size_t i = 0; i < LANTERN_ROOT_SIZE; ++i) {
        if (root->bytes[i] != 0) {
            return false;
        }
    }
    return true;
}

static int reqresp_build_status(void *context, LanternStatusMessage *out_status) {
    if (!context || !out_status) {
        return -1;
    }
    struct lantern_client *client = context;
    memset(out_status, 0, sizeof(*out_status));
    if (!client->has_state) {
        return 0;
    }

    out_status->finalized = client->state.latest_finalized;
    out_status->head.slot = client->state.latest_block_header.slot;
    if (lantern_hash_tree_root_block_header(&client->state.latest_block_header, &out_status->head.root) != 0) {
        memset(&out_status->head.root, 0, sizeof(out_status->head.root));
    }
    return 0;
}

static int reqresp_handle_status(void *context, const LanternStatusMessage *peer_status, const char *peer_id) {
    if (!context || !peer_status) {
        return -1;
    }
    struct lantern_client *client = context;
    char head_hex[2 * LANTERN_ROOT_SIZE + 3];
    char finalized_hex[2 * LANTERN_ROOT_SIZE + 3];
    format_root_hex(&peer_status->head.root, head_hex, sizeof(head_hex));
    format_root_hex(&peer_status->finalized.root, finalized_hex, sizeof(finalized_hex));

    lantern_log_info(
        "network",
        &(const struct lantern_log_metadata){
            .validator = client->node_id,
            .peer = peer_id},
        "peer status head_slot=%" PRIu64 " head_root=%s finalized_slot=%" PRIu64 " finalized_root=%s",
        peer_status->head.slot,
        head_hex[0] ? head_hex : "0x0",
        peer_status->finalized.slot,
        finalized_hex[0] ? finalized_hex : "0x0");
    lantern_client_on_peer_status(client, peer_status, peer_id);
    return 0;
}

static void lantern_client_on_peer_status(
    struct lantern_client *client,
    const LanternStatusMessage *peer_status,
    const char *peer_id) {
    if (!client || !peer_status || !client->status_lock_initialized) {
        return;
    }
    if (!peer_id || *peer_id == '\0') {
        return;
    }
    if (lantern_root_is_zero(&peer_status->head.root)) {
        return;
    }

    char head_hex[2 * LANTERN_ROOT_SIZE + 3];
    format_root_hex(&peer_status->head.root, head_hex, sizeof(head_hex));

    const size_t peer_cap = sizeof(((struct lantern_peer_status_entry *)0)->peer_id);
    char peer_copy[sizeof(((struct lantern_peer_status_entry *)0)->peer_id)];
    memset(peer_copy, 0, sizeof(peer_copy));
    strncpy(peer_copy, peer_id, peer_cap - 1);

    LanternRoot request_root = peer_status->head.root;
    bool should_request = false;

    if (pthread_mutex_lock(&client->status_lock) != 0) {
        return;
    }

    struct lantern_peer_status_entry *entry = NULL;
    for (size_t i = 0; i < client->peer_status_count; ++i) {
        if (strncmp(client->peer_status_entries[i].peer_id, peer_copy, peer_cap) == 0) {
            entry = &client->peer_status_entries[i];
            break;
        }
    }

    if (!entry) {
        if (client->peer_status_count == client->peer_status_capacity) {
            size_t new_capacity = client->peer_status_capacity == 0 ? 4 : client->peer_status_capacity * 2;
            if (new_capacity > (SIZE_MAX / sizeof(*client->peer_status_entries))) {
                pthread_mutex_unlock(&client->status_lock);
                return;
            }
            struct lantern_peer_status_entry *grown = realloc(
                client->peer_status_entries,
                new_capacity * sizeof(*client->peer_status_entries));
            if (!grown) {
                pthread_mutex_unlock(&client->status_lock);
                return;
            }
            memset(
                grown + client->peer_status_capacity,
                0,
                (new_capacity - client->peer_status_capacity) * sizeof(*grown));
            client->peer_status_entries = grown;
            client->peer_status_capacity = new_capacity;
        }
        entry = &client->peer_status_entries[client->peer_status_count++];
        memset(entry, 0, sizeof(*entry));
        memcpy(entry->peer_id, peer_copy, peer_cap);
    }

    entry->status = *peer_status;
    entry->has_status = true;
    if (!entry->requested_head) {
        uint64_t now_ms = monotonic_millis();
        uint64_t backoff_ms = blocks_request_backoff_ms(entry->consecutive_blocks_failures);
        bool within_backoff = entry->last_blocks_request_ms != 0
            && now_ms < entry->last_blocks_request_ms + backoff_ms;
        if (!within_backoff) {
            entry->requested_head = true;
            entry->last_blocks_request_ms = now_ms;
            should_request = true;
        } else {
            uint64_t resume_ms = entry->last_blocks_request_ms + backoff_ms;
            uint64_t remaining_ms = resume_ms > now_ms ? (resume_ms - now_ms) : 0;
            lantern_log_debug(
                "reqresp",
                &(const struct lantern_log_metadata){
                    .validator = client->node_id,
                    .peer = peer_copy},
                "backing off blocks_by_root head=%s failures=%u remaining_ms=%" PRIu64,
                head_hex[0] ? head_hex : "0x0",
                entry->consecutive_blocks_failures,
                remaining_ms);
        }
    }

    pthread_mutex_unlock(&client->status_lock);

    if (should_request) {
        if (lantern_client_schedule_blocks_request(client, peer_copy, &request_root, false) != 0) {
            lantern_client_on_blocks_request_complete(
                client,
                peer_copy,
                LANTERN_BLOCKS_REQUEST_ABORTED);
        }
    }
}

static void lantern_client_on_blocks_request_complete(
    struct lantern_client *client,
    const char *peer_id,
    enum lantern_blocks_request_outcome outcome) {
    if (!client || !peer_id || !client->status_lock_initialized) {
        return;
    }
    const size_t peer_cap = sizeof(((struct lantern_peer_status_entry *)0)->peer_id);
    if (pthread_mutex_lock(&client->status_lock) != 0) {
        return;
    }
    for (size_t i = 0; i < client->peer_status_count; ++i) {
        struct lantern_peer_status_entry *entry = &client->peer_status_entries[i];
        if (strncmp(entry->peer_id, peer_id, peer_cap) == 0) {
            entry->requested_head = false;
            switch (outcome) {
            case LANTERN_BLOCKS_REQUEST_SUCCESS:
                entry->consecutive_blocks_failures = 0;
                break;
            case LANTERN_BLOCKS_REQUEST_FAILED:
                if (entry->consecutive_blocks_failures < UINT32_MAX) {
                    entry->consecutive_blocks_failures += 1;
                }
                break;
            case LANTERN_BLOCKS_REQUEST_ABORTED:
                entry->last_blocks_request_ms = 0;
                break;
            default:
                break;
            }
            if (outcome != LANTERN_BLOCKS_REQUEST_ABORTED && entry->last_blocks_request_ms == 0) {
                entry->last_blocks_request_ms = monotonic_millis();
            }
            break;
        }
    }
    pthread_mutex_unlock(&client->status_lock);
}

static int stream_write_all(libp2p_stream_t *stream, const uint8_t *data, size_t length) {
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
        return -1;
    }
    return 0;
}

static int read_length_prefixed_chunk(libp2p_stream_t *stream, uint8_t **out_data, size_t *out_len, ssize_t *out_err) {
    if (!stream || !out_data || !out_len) {
        if (out_err) {
            *out_err = LIBP2P_ERR_NULL_PTR;
        }
        return -1;
    }
    uint8_t header[LANTERN_REQRESP_HEADER_MAX_BYTES];
    size_t header_used = 0;
    uint64_t payload_len = 0;
    ssize_t last_err = 0;

    while (header_used < sizeof(header)) {
        (void)libp2p_stream_set_deadline(stream, LANTERN_REQRESP_STALL_TIMEOUT_MS);
        ssize_t n = libp2p_stream_read(stream, &header[header_used], 1);
        if (n == 1) {
            header_used += 1;
            size_t consumed = 0;
            if (unsigned_varint_decode(header, header_used, &payload_len, &consumed) == UNSIGNED_VARINT_OK) {
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

    if (payload_len == 0 || payload_len > LANTERN_REQRESP_MAX_CHUNK_BYTES || payload_len > SIZE_MAX) {
        last_err = LIBP2P_ERR_MSG_TOO_LARGE;
    }

    if (last_err != 0) {
        if (out_err) {
            *out_err = last_err;
        }
        return -1;
    }

    size_t payload_size = (size_t)payload_len;
    uint8_t *buffer = (uint8_t *)malloc(payload_size);
    if (!buffer) {
        if (out_err) {
            *out_err = -ENOMEM;
        }
        return -1;
    }

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
        return -1;
    }
    (void)libp2p_stream_set_deadline(stream, 0);

    *out_data = buffer;
    *out_len = payload_size;
    if (out_err) {
        *out_err = 0;
    }
    return 0;
}

static void block_request_ctx_free(struct block_request_ctx *ctx) {
    if (!ctx) {
        return;
    }
    peer_id_destroy(&ctx->peer_id);
    free(ctx);
}

static void *block_request_worker(void *arg) {
    struct block_request_worker_args *worker = (struct block_request_worker_args *)arg;
    if (!worker) {
        return NULL;
    }
    struct block_request_ctx *ctx = worker->ctx;
    libp2p_stream_t *stream = worker->stream;
    free(worker);
    if (!ctx || !stream) {
        if (stream) {
            libp2p_stream_close(stream);
            libp2p_stream_free(stream);
        }
        block_request_ctx_free(ctx);
        return NULL;
    }

    struct lantern_log_metadata meta = {
        .validator = ctx->client ? ctx->client->node_id : NULL,
        .peer = ctx->peer_text[0] ? ctx->peer_text : NULL,
    };

    char root_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
    format_root_hex(&ctx->root, root_hex, sizeof(root_hex));

    LanternBlocksByRootRequest request;
    lantern_blocks_by_root_request_init(&request);

    LanternBlocksByRootResponse response_msg;
    lantern_blocks_by_root_response_init(&response_msg);

    uint8_t *payload = NULL;
    uint8_t *response = NULL;
    bool request_success = false;
    bool schedule_legacy = false;

    if (lantern_root_list_resize(&request.roots, 1) != 0) {
        lantern_log_error(
            "reqresp",
            &meta,
            "failed to size blocks_by_root request");
        schedule_legacy = !ctx->using_legacy;
        goto cleanup;
    }
    request.roots.items[0] = ctx->root;

    size_t raw_size = sizeof(uint32_t) + LANTERN_ROOT_SIZE;
    size_t max_payload = 0;
    if (lantern_snappy_max_compressed_size(raw_size, &max_payload) != LANTERN_SNAPPY_OK) {
        lantern_log_error(
            "reqresp",
            &meta,
            "failed to compute snappy size for blocks_by_root request");
        schedule_legacy = !ctx->using_legacy;
        goto cleanup;
    }

    payload = (uint8_t *)malloc(max_payload);
    if (!payload) {
        lantern_log_error(
            "reqresp",
            &meta,
            "out of memory building blocks_by_root request");
        schedule_legacy = !ctx->using_legacy;
        goto cleanup;
    }

    size_t payload_len = 0;
    if (lantern_network_blocks_by_root_request_encode_snappy(&request, payload, max_payload, &payload_len) != 0
        || payload_len == 0) {
        lantern_log_error(
            "reqresp",
            &meta,
            "failed to encode blocks_by_root request");
        schedule_legacy = !ctx->using_legacy;
        goto cleanup;
    }

    uint8_t header[LANTERN_REQRESP_HEADER_MAX_BYTES];
    size_t header_len = 0;
    if (unsigned_varint_encode(payload_len, header, sizeof(header), &header_len) != UNSIGNED_VARINT_OK) {
        lantern_log_error(
            "reqresp",
            &meta,
            "failed to encode blocks_by_root header length=%zu",
            payload_len);
        schedule_legacy = !ctx->using_legacy;
        goto cleanup;
    }

    lantern_log_info(
        "reqresp",
        &meta,
        "sending %s request root=%s bytes=%zu",
        ctx->protocol_id,
        root_hex[0] ? root_hex : "0x0",
        payload_len);

    if (stream_write_all(stream, header, header_len) != 0 || stream_write_all(stream, payload, payload_len) != 0) {
        lantern_log_error(
            "reqresp",
            &meta,
            "failed to write blocks_by_root request");
        schedule_legacy = !ctx->using_legacy;
        goto cleanup;
    }

    size_t response_len = 0;
    ssize_t read_err = 0;
    if (read_length_prefixed_chunk(stream, &response, &response_len, &read_err) != 0) {
        lantern_log_error(
            "reqresp",
            &meta,
            "failed to read blocks_by_root response err=%zd",
            read_err);
        schedule_legacy = !ctx->using_legacy;
        goto cleanup;
    }

    if (lantern_network_blocks_by_root_response_decode_snappy(&response_msg, response, response_len) != 0) {
        lantern_log_error(
            "reqresp",
            &meta,
            "failed to decode blocks_by_root response bytes=%zu",
            response_len);
        schedule_legacy = !ctx->using_legacy;
        goto cleanup;
    }

    lantern_log_info(
        "reqresp",
        &meta,
        "received %zu block(s) via %s",
        response_msg.length,
        ctx->protocol_id);

    request_success = true;

    for (size_t i = 0; i < response_msg.length; ++i) {
        LanternRoot computed = {{0}};
        if (lantern_hash_tree_root_block(&response_msg.blocks[i].message, &computed) != 0) {
            lantern_log_warn(
                "reqresp",
                &meta,
                "failed to hash block index=%zu slot=%" PRIu64,
                i,
                response_msg.blocks[i].message.slot);
            continue;
        }
        char computed_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
        format_root_hex(&computed, computed_hex, sizeof(computed_hex));
        bool matches = memcmp(computed.bytes, ctx->root.bytes, LANTERN_ROOT_SIZE) == 0;
        lantern_log_info(
            "reqresp",
            &meta,
            "block index=%zu slot=%" PRIu64 " proposer=%" PRIu64 " root=%s match=%s attestations=%zu",
            i,
            response_msg.blocks[i].message.slot,
            response_msg.blocks[i].message.proposer_index,
            computed_hex[0] ? computed_hex : "0x0",
            matches ? "true" : "false",
            response_msg.blocks[i].message.body.attestations.length);
    }

cleanup:
    lantern_blocks_by_root_response_reset(&response_msg);
    free(response);
    free(payload);
    lantern_blocks_by_root_request_reset(&request);
    libp2p_stream_close(stream);
    libp2p_stream_free(stream);

    if (!request_success) {
        if (schedule_legacy && ctx->client) {
            if (lantern_client_schedule_blocks_request(ctx->client, ctx->peer_text, &ctx->root, true) != 0) {
                lantern_client_on_blocks_request_complete(
                    ctx->client,
                    ctx->peer_text,
                    LANTERN_BLOCKS_REQUEST_FAILED);
            }
        } else if (ctx->client && ctx->using_legacy) {
            lantern_client_on_blocks_request_complete(
                ctx->client,
                ctx->peer_text,
                LANTERN_BLOCKS_REQUEST_FAILED);
        }
    } else if (ctx->client) {
        lantern_client_on_blocks_request_complete(
            ctx->client,
            ctx->peer_text,
            LANTERN_BLOCKS_REQUEST_SUCCESS);
    }

    block_request_ctx_free(ctx);
    return NULL;
}

static void block_request_on_open(libp2p_stream_t *stream, void *user_data, int err) {
    struct block_request_ctx *ctx = (struct block_request_ctx *)user_data;
    if (!ctx) {
        if (stream) {
            libp2p_stream_close(stream);
            libp2p_stream_free(stream);
        }
        return;
    }
    struct lantern_log_metadata meta = {
        .validator = ctx->client ? ctx->client->node_id : NULL,
        .peer = ctx->peer_text[0] ? ctx->peer_text : NULL,
    };
    if (err != 0 || !stream) {
        lantern_log_warn(
            "reqresp",
            &meta,
            "failed to open %s stream err=%d",
            ctx->protocol_id,
            err);
        bool attempted_fallback = false;
        if (!ctx->using_legacy && ctx->client) {
            attempted_fallback = (lantern_client_schedule_blocks_request(
                                      ctx->client,
                                      ctx->peer_text,
                                      &ctx->root,
                                      true)
                                  == 0);
            if (!attempted_fallback) {
                lantern_client_on_blocks_request_complete(
                    ctx->client,
                    ctx->peer_text,
                    LANTERN_BLOCKS_REQUEST_FAILED);
            }
        } else if (ctx->client) {
            lantern_client_on_blocks_request_complete(
                ctx->client,
                ctx->peer_text,
                LANTERN_BLOCKS_REQUEST_FAILED);
        }
        if (stream) {
            libp2p_stream_close(stream);
            libp2p_stream_free(stream);
        }
        block_request_ctx_free(ctx);
        return;
    }

    struct block_request_worker_args *worker = (struct block_request_worker_args *)malloc(sizeof(*worker));
    if (!worker) {
        lantern_log_error(
            "reqresp",
            &meta,
            "failed to allocate worker for %s stream",
            ctx->protocol_id);
        libp2p_stream_close(stream);
        libp2p_stream_free(stream);
        if (ctx->client) {
            lantern_client_on_blocks_request_complete(
                ctx->client,
                ctx->peer_text,
                LANTERN_BLOCKS_REQUEST_FAILED);
        }
        block_request_ctx_free(ctx);
        return;
    }
    worker->ctx = ctx;
    worker->stream = stream;

    pthread_t thread;
    if (pthread_create(&thread, NULL, block_request_worker, worker) != 0) {
        lantern_log_error(
            "reqresp",
            &meta,
            "failed to spawn blocks_by_root worker");
        free(worker);
        libp2p_stream_close(stream);
        libp2p_stream_free(stream);
        if (ctx->client) {
            lantern_client_on_blocks_request_complete(
                ctx->client,
                ctx->peer_text,
                LANTERN_BLOCKS_REQUEST_FAILED);
        }
        block_request_ctx_free(ctx);
        return;
    }
    pthread_detach(thread);
}

static int lantern_client_schedule_blocks_request(
    struct lantern_client *client,
    const char *peer_id_text,
    const LanternRoot *root,
    bool use_legacy) {
    if (!client || !peer_id_text || !root || !client->network.host) {
        return -1;
    }
    if (lantern_root_is_zero(root)) {
        return -1;
    }

    struct block_request_ctx *ctx = (struct block_request_ctx *)calloc(1, sizeof(*ctx));
    if (!ctx) {
        return -1;
    }
    ctx->client = client;
    ctx->root = *root;
    ctx->protocol_id = use_legacy ? LANTERN_BLOCKS_BY_ROOT_PROTOCOL_ID_LEGACY : LANTERN_BLOCKS_BY_ROOT_PROTOCOL_ID;
    ctx->using_legacy = use_legacy;
    strncpy(ctx->peer_text, peer_id_text, sizeof(ctx->peer_text) - 1);
    ctx->peer_text[sizeof(ctx->peer_text) - 1] = '\0';

    if (peer_id_create_from_string(peer_id_text, &ctx->peer_id) != PEER_ID_SUCCESS) {
        lantern_log_warn(
            "reqresp",
            &(const struct lantern_log_metadata){
                .validator = client->node_id,
                .peer = peer_id_text},
            "failed to parse peer id for blocks_by_root request");
        block_request_ctx_free(ctx);
        return -1;
    }

    char root_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
    format_root_hex(root, root_hex, sizeof(root_hex));
    lantern_log_info(
        "reqresp",
        &(const struct lantern_log_metadata){
            .validator = client->node_id,
            .peer = ctx->peer_text[0] ? ctx->peer_text : NULL},
        "dialing peer for %s root=%s",
        ctx->protocol_id,
        root_hex[0] ? root_hex : "0x0");

    int rc = libp2p_host_open_stream_async(
        client->network.host,
        &ctx->peer_id,
        ctx->protocol_id,
        block_request_on_open,
        ctx);
    if (rc != 0) {
        lantern_log_warn(
            "reqresp",
            &(const struct lantern_log_metadata){
                .validator = client->node_id,
                .peer = ctx->peer_text[0] ? ctx->peer_text : NULL},
            "libp2p open stream failed rc=%d",
            rc);
        block_request_ctx_free(ctx);
        return -1;
    }
    return 0;
}

static int reqresp_collect_blocks(
    void *context,
    const LanternRoot *roots,
    size_t root_count,
    LanternBlocksByRootResponse *out_blocks) {
    if (!context || !out_blocks) {
        return -1;
    }
    struct lantern_client *client = context;
    if (!client->data_dir) {
        return lantern_blocks_by_root_response_resize(out_blocks, 0);
    }
    int rc = lantern_storage_collect_blocks(client->data_dir, roots, root_count, out_blocks);
    if (rc != 0) {
        lantern_log_error(
            "reqresp",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to collect blocks from storage");
        return -1;
    }
    return 0;
}

static int initialize_fork_choice(struct lantern_client *client) {
    if (!client || !client->has_state) {
        return -1;
    }
    lantern_fork_choice_reset(&client->fork_choice);
    if (lantern_fork_choice_configure(&client->fork_choice, &client->state.config) != 0) {
        lantern_log_error(
            "forkchoice",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to configure fork choice");
        return -1;
    }

    LanternBlock anchor;
    memset(&anchor, 0, sizeof(anchor));
    anchor.slot = client->state.latest_block_header.slot;
    anchor.proposer_index = client->state.latest_block_header.proposer_index;
    anchor.parent_root = client->state.latest_block_header.parent_root;
    anchor.state_root = client->state.latest_block_header.state_root;
    lantern_block_body_init(&anchor.body);

    LanternRoot anchor_root;
    if (lantern_hash_tree_root_block(&anchor, &anchor_root) != 0) {
        lantern_block_body_reset(&anchor.body);
        lantern_log_error(
            "forkchoice",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to hash anchor block");
        return -1;
    }

    if (lantern_fork_choice_set_anchor(
            &client->fork_choice,
            &anchor,
            &client->state.latest_justified,
            &client->state.latest_finalized,
            &anchor_root)
        != 0) {
        lantern_block_body_reset(&anchor.body);
        lantern_log_error(
            "forkchoice",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to set fork choice anchor");
        return -1;
    }
    lantern_block_body_reset(&anchor.body);
    lantern_state_attach_fork_choice(&client->state, &client->fork_choice);
    client->has_fork_choice = true;
    return 0;
}

static int restore_persisted_blocks(struct lantern_client *client) {
    if (!client || !client->has_state || !client->data_dir || !client->has_fork_choice) {
        return 0;
    }
    struct lantern_persisted_block_list list;
    persisted_block_list_init(&list);
    int iterate_rc = lantern_storage_iterate_blocks(client->data_dir, collect_block_visitor, &list);
    if (iterate_rc < 0) {
        lantern_log_error(
            "storage",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to enumerate persisted blocks");
        persisted_block_list_reset(&list);
        return -1;
    }
    if (list.length == 0) {
        persisted_block_list_reset(&list);
        return 0;
    }
    qsort(list.items, list.length, sizeof(list.items[0]), compare_blocks_by_slot);

    for (size_t i = 0; i < list.length; ++i) {
        const struct lantern_persisted_block *entry = &list.items[i];
        if (lantern_fork_choice_add_block(
                &client->fork_choice,
                &entry->block.message,
                &client->state.latest_justified,
                &client->state.latest_finalized,
                &entry->root)
            != 0) {
            lantern_log_warn(
                "forkchoice",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to restore block at slot %" PRIu64,
                entry->block.message.slot);
        }
    }

    if (lantern_fork_choice_accept_new_votes(&client->fork_choice) != 0) {
        lantern_log_warn(
            "forkchoice",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "accepting new votes from storage failed");
    }
    if (lantern_fork_choice_update_safe_target(&client->fork_choice) != 0) {
        lantern_log_warn(
            "forkchoice",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "updating safe target after restore failed");
    }
    if (lantern_fork_choice_recompute_head(&client->fork_choice) != 0) {
        lantern_log_warn(
            "forkchoice",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "recomputing head after restore failed");
    }

    persisted_block_list_reset(&list);
    return 0;
}

static int init_consensus_runtime(struct lantern_client *client) {
    if (!client || !client->has_validator_assignment) {
        return -1;
    }
    struct lantern_consensus_runtime_config runtime_config;
    lantern_consensus_runtime_config_init(&runtime_config);
    runtime_config.genesis_time = client->genesis.chain_config.genesis_time;
    runtime_config.validator_count = client->genesis.chain_config.validator_count;
    if (runtime_config.validator_count == 0) {
        return -1;
    }
    if (lantern_consensus_runtime_init(
            &client->runtime,
            &runtime_config,
            &client->validator_assignment)
        != 0) {
        return -1;
    }
    client->has_runtime = true;
    return 0;
}

static int set_owned_string(char **dest, const char *value) {
    if (!dest || !value) {
        return -1;
    }
    char *copy = lantern_string_duplicate(value);
    if (!copy) {
        return -1;
    }
    free(*dest);
    *dest = copy;
    return 0;
}

static int copy_genesis_paths(struct lantern_genesis_paths *paths, const struct lantern_client_options *options) {
    if (!paths || !options) {
        return -1;
    }

    reset_genesis_paths(paths);

    if (set_owned_string(&paths->config_path, options->genesis_config_path) != 0) {
        return -1;
    }
    if (set_owned_string(&paths->validator_registry_path, options->validator_registry_path) != 0) {
        return -1;
    }
    if (set_owned_string(&paths->nodes_path, options->nodes_path) != 0) {
        return -1;
    }
    if (set_owned_string(&paths->state_path, options->genesis_state_path) != 0) {
        return -1;
    }
    if (set_owned_string(&paths->validator_config_path, options->validator_config_path) != 0) {
        return -1;
    }

    return 0;
}

static void reset_genesis_paths(struct lantern_genesis_paths *paths) {
    if (!paths) {
        return;
    }
    free(paths->config_path);
    free(paths->validator_registry_path);
    free(paths->nodes_path);
    free(paths->state_path);
    free(paths->validator_config_path);
    memset(paths, 0, sizeof(*paths));
}

static int read_trimmed_file(const char *path, char **out_text) {
    if (!path || !out_text) {
        return -1;
    }

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){0},
            "unable to open %s for reading",
            path);
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    long file_size = ftell(fp);
    if (file_size < 0) {
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    char *buffer = malloc((size_t)file_size + 1);
    if (!buffer) {
        fclose(fp);
        return -1;
    }

    size_t read_len = fread(buffer, 1, (size_t)file_size, fp);
    fclose(fp);
    buffer[read_len] = '\0';

    char *trimmed = lantern_trim_whitespace(buffer);
    size_t trimmed_len = strlen(trimmed);
    memmove(buffer, trimmed, trimmed_len + 1);
    *out_text = buffer;
    return 0;
}

size_t lantern_client_local_validator_count(const struct lantern_client *client) {
    if (!client) {
        return 0;
    }
    return client->local_validator_count;
}

const struct lantern_local_validator *lantern_client_local_validator(
    const struct lantern_client *client,
    size_t index) {
    if (!client || index >= client->local_validator_count) {
        return NULL;
    }
    return &client->local_validators[index];
}

int lantern_client_publish_block(struct lantern_client *client, const LanternSignedBlock *block) {
    if (!client || !block) {
        return -1;
    }
    if (!client->gossip_running) {
        lantern_log_error(
            "gossip",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "cannot publish block at slot %" PRIu64 ": gossip service inactive",
            block->message.slot);
        return -1;
    }
    if (lantern_gossipsub_service_publish_block(&client->gossip, block) != 0) {
        lantern_log_error(
            "gossip",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to publish block at slot %" PRIu64,
            block->message.slot);
        return -1;
    }

    LanternRoot block_root;
    char root_hex[2 * LANTERN_ROOT_SIZE + 3];
    if (lantern_hash_tree_root_signed_block(block, &block_root) == 0) {
        format_root_hex(&block_root, root_hex, sizeof(root_hex));
    } else {
        root_hex[0] = '\0';
    }

    lantern_log_info(
        "gossip",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "published block slot=%" PRIu64 " root=%s attestations=%zu",
        block->message.slot,
        root_hex[0] ? root_hex : "0x0",
        block->message.body.attestations.length);
    return 0;
}

static int load_node_key_bytes(const struct lantern_client_options *options, uint8_t out_key[32]) {
    if (!options || !out_key) {
        return -1;
    }

    char *owned = NULL;
    int rc = -1;

    if (options->node_key_hex) {
        owned = lantern_string_duplicate(options->node_key_hex);
        if (!owned) {
            return -1;
        }
    } else if (options->node_key_path) {
        if (read_trimmed_file(options->node_key_path, &owned) != 0) {
            return -1;
        }
    } else {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = options->node_id},
            "--node-key or --node-key-path is required");
        return -1;
    }

    char *trimmed = lantern_trim_whitespace(owned);
    if (!trimmed) {
        free(owned);
        return -1;
    }

    rc = lantern_hex_decode(trimmed, out_key, 32);
    if (rc != 0) {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = options->node_id},
            "invalid node key (expected 32-byte hex string)");
    }

    if (owned) {
        memset(owned, 0, strlen(owned));
        free(owned);
    }

    return rc;
}
