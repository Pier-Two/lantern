#include "lantern/client.h"

#include "internal/strings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int set_owned_string(char **dest, const char *value);
static int copy_genesis_paths(struct lantern_genesis_paths *paths, const struct lantern_client_options *options);
static void reset_genesis_paths(struct lantern_genesis_paths *paths);

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

    lantern_string_list_reset(&client->bootnodes);
    free(client->data_dir);
    client->data_dir = NULL;
    free(client->node_id);
    client->node_id = NULL;
    free(client->listen_address);
    client->listen_address = NULL;

    reset_genesis_paths(&client->genesis_paths);
    lantern_genesis_artifacts_reset(&client->genesis);

    client->http_port = 0;
    client->metrics_port = 0;
    client->assigned_validators = NULL;
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
