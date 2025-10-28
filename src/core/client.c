#include "lantern/core/client.h"

#include "lantern/consensus/hash.h"
#include "lantern/consensus/duties.h"
#include "lantern/consensus/runtime.h"
#include "lantern/consensus/state.h"
#include "lantern/consensus/ssz.h"
#include "lantern/http/server.h"
#include "lantern/support/strings.h"
#include "lantern/support/log.h"

#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
static int http_snapshot_head(void *context, struct lantern_http_head_snapshot *out_snapshot);
static size_t http_validator_count_cb(void *context);
static int http_validator_info_cb(void *context, size_t index, struct lantern_http_validator_info *out_info);
static int http_set_validator_status_cb(void *context, uint64_t global_index, bool enabled);
static int metrics_snapshot_cb(void *context, struct lantern_metrics_snapshot *out_snapshot);

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
    lantern_genesis_artifacts_init(&client->genesis);
    lantern_enr_record_init(&client->local_enr);
    lantern_libp2p_host_init(&client->network);
    lantern_gossipsub_service_init(&client->gossip);
    lantern_validator_assignment_init(&client->validator_assignment);
    client->has_validator_assignment = false;
    lantern_consensus_runtime_reset(&client->runtime);
    client->has_runtime = false;
    lantern_metrics_server_init(&client->metrics_server);
    client->metrics_running = false;
    lantern_http_server_init(&client->http_server);
    client->http_running = false;
    lantern_state_init(&client->state);

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
    client->http_port = options->http_port;
    client->metrics_port = options->metrics_port;

    if (lantern_string_list_copy(&client->bootnodes, &options->bootnodes) != 0) {
        goto error;
    }

    if (copy_genesis_paths(&client->genesis_paths, options) != 0) {
        goto error;
    }

    if (lantern_genesis_load(&client->genesis, &client->genesis_paths) != 0) {
        goto error;
    }

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
    } else {
        client->has_state = true;
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

    lantern_metrics_server_stop(&client->metrics_server);
    lantern_metrics_server_init(&client->metrics_server);
    client->metrics_running = false;

    lantern_http_server_stop(&client->http_server);
    lantern_http_server_init(&client->http_server);
    client->http_running = false;

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
    free(client->local_validators);
    client->local_validators = NULL;
    client->local_validator_count = 0;
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
                lantern_log_error(
                    "network",
                    &(const struct lantern_log_metadata){
                        .validator = client->node_id,
                        .peer = record->encoded},
                    "failed to add ENR peer from genesis");
                return -1;
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
    if (!client || !client->has_validator_assignment) {
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

    size_t count = (size_t)local_count;
    struct lantern_local_validator *validators = calloc(count, sizeof(*validators));
    if (!validators) {
        return -1;
    }

    for (size_t i = 0; i < count; ++i) {
        uint64_t global_index = start_index + (uint64_t)i;
        validators[i].global_index = global_index;
        validators[i].registry = &client->genesis.validator_registry.records[global_index];
    }

    bool *enabled = calloc(count, sizeof(*enabled));
    if (!enabled) {
        free(validators);
        return -1;
    }
    for (size_t i = 0; i < count; ++i) {
        enabled[i] = true;
    }

    if (!client->validator_lock_initialized) {
        if (pthread_mutex_init(&client->validator_lock, NULL) != 0) {
            free(validators);
            free(enabled);
            return -1;
        }
        client->validator_lock_initialized = true;
    }

    if (pthread_mutex_lock(&client->validator_lock) != 0) {
        free(validators);
        free(enabled);
        return -1;
    }

    free(client->validator_enabled);
    client->validator_enabled = enabled;

    free(client->local_validators);
    client->local_validators = validators;
    client->local_validator_count = count;

    pthread_mutex_unlock(&client->validator_lock);
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
    out_snapshot->connected_peers = 0;
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
