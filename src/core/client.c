#include "lantern/core/client.h"

#include "lantern/support/strings.h"

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

    if (set_owned_string(&client->data_dir, options->data_dir) != 0) {
        goto error;
    }
    if (set_owned_string(&client->node_id, options->node_id) != 0) {
        goto error;
    }
    if (set_owned_string(&client->listen_address, options->listen_address) != 0) {
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

    client->assigned_validators = lantern_validator_config_find(
        &client->genesis.validator_config,
        client->node_id);

    if (!client->assigned_validators) {
        fprintf(stderr, "lantern: node-id '%s' not found in validator-config\n", client->node_id);
        goto error;
    }
    if (!client->assigned_validators->enr.ip || client->assigned_validators->enr.quic_port == 0) {
        fprintf(stderr, "lantern: validator '%s' missing ENR fields\n", client->node_id);
        goto error;
    }

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
        fprintf(stderr, "lantern: failed to initialize libp2p host\n");
        memset(node_key, 0, sizeof(node_key));
        goto error;
    }

    if (append_genesis_bootnodes(client) != 0) {
        fprintf(stderr, "lantern: failed to append bootnodes from genesis\n");
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
        fprintf(stderr, "lantern: failed to build local ENR\n");
        memset(node_key, 0, sizeof(node_key));
        goto error;
    }
    memset(node_key, 0, sizeof(node_key));

    return 0;

error:
    lantern_shutdown(client);
    return -1;
}

void lantern_shutdown(struct lantern_client *client) {
    if (!client) {
        return;
    }

    lantern_string_list_reset(&client->bootnodes);
    free(client->data_dir);
    client->data_dir = NULL;
    free(client->node_id);
    client->node_id = NULL;
    free(client->listen_address);
    client->listen_address = NULL;

    reset_genesis_paths(&client->genesis_paths);
    lantern_genesis_artifacts_reset(&client->genesis);
    lantern_enr_record_reset(&client->local_enr);
    lantern_libp2p_host_reset(&client->network);
    memset(client->node_private_key, 0, sizeof(client->node_private_key));
    client->has_node_private_key = false;

    client->http_port = 0;
    client->metrics_port = 0;
    client->assigned_validators = NULL;
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
                fprintf(stderr, "lantern: failed to add ENR peer from genesis\n");
                return -1;
            }
        }
    }
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
        fprintf(stderr, "lantern: unable to open %s for reading\n", path);
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
        fprintf(stderr, "lantern: --node-key or --node-key-path is required\n");
        return -1;
    }

    char *trimmed = lantern_trim_whitespace(owned);
    if (!trimmed) {
        free(owned);
        return -1;
    }

    rc = lantern_hex_decode(trimmed, out_key, 32);
    if (rc != 0) {
        fprintf(stderr, "lantern: invalid node key (expected 32-byte hex string)\n");
    }

    if (owned) {
        memset(owned, 0, strlen(owned));
        free(owned);
    }

    return rc;
}
