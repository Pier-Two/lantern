#include "lantern/client.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#ifndef LANTERN_TEST_FIXTURE_DIR
#error "LANTERN_TEST_FIXTURE_DIR must be defined"
#endif

static void build_fixture_path(char *buffer, size_t length, const char *relative) {
    int written = snprintf(buffer, length, "%s/%s", LANTERN_TEST_FIXTURE_DIR, relative);
    if (written <= 0 || (size_t)written >= length) {
        fprintf(stderr, "Failed to compose fixture path for %s\n", relative);
    }
}

static int verify_client_state(const struct lantern_client *client, const struct lantern_client_options *options) {
    if (client->genesis.chain_config.genesis_time != 1700000000ULL) {
        fprintf(stderr, "Unexpected genesis_time: %llu\n",
            (unsigned long long)client->genesis.chain_config.genesis_time);
        return 1;
    }
    if (client->genesis.chain_config.validator_count != 4) {
        fprintf(stderr, "Unexpected validator_count: %llu\n",
            (unsigned long long)client->genesis.chain_config.validator_count);
        return 1;
    }
    if (client->genesis.enrs.count != 2) {
        fprintf(stderr, "Unexpected ENR count: %zu\n", client->genesis.enrs.count);
        return 1;
    }
    if (client->genesis.enrs.count > 0) {
        const struct lantern_enr_record *first = &client->genesis.enrs.records[0];
        const struct lantern_enr_key_value *id = lantern_enr_record_find(first, "id");
        if (!id || id->value_len != 2 || memcmp(id->value, "v4", 2) != 0) {
            fprintf(stderr, "ENR id mismatch\n");
            return 1;
        }
        const struct lantern_enr_key_value *ip = lantern_enr_record_find(first, "ip");
        if (!ip || ip->value_len != 4) {
            fprintf(stderr, "ENR ip missing\n");
            return 1;
        }
    }
    if (client->genesis.validator_registry.count != 2) {
        fprintf(stderr, "Unexpected validator registry count: %zu\n", client->genesis.validator_registry.count);
        return 1;
    }
    if (client->genesis.validator_config.count != 2) {
        fprintf(stderr, "Unexpected validator config count: %zu\n", client->genesis.validator_config.count);
        return 1;
    }
    if (!client->assigned_validators || client->assigned_validators->count != 1) {
        fprintf(stderr, "Validator assignment missing or incorrect\n");
        return 1;
    }
    if (client->bootnodes.len != options->bootnodes.len) {
        fprintf(
            stderr,
            "Bootnode count mismatch: expected %zu got %zu\n",
            options->bootnodes.len,
            client->bootnodes.len);
        return 1;
    }
    return 0;
}

int main(void) {
    struct lantern_client_options options;
    lantern_client_options_init(&options);

    char config_path[512];
    char registry_path[512];
    char nodes_path[512];
    char state_path[512];
    char validator_config_path[512];

    build_fixture_path(config_path, sizeof(config_path), "genesis/config.yaml");
    build_fixture_path(registry_path, sizeof(registry_path), "genesis/validators.yaml");
    build_fixture_path(nodes_path, sizeof(nodes_path), "genesis/nodes.yaml");
    build_fixture_path(state_path, sizeof(state_path), "genesis/genesis.ssz");
    build_fixture_path(validator_config_path, sizeof(validator_config_path), "genesis/validator-config.yaml");

    options.data_dir = LANTERN_TEST_FIXTURE_DIR;
    options.genesis_config_path = config_path;
    options.validator_registry_path = registry_path;
    options.nodes_path = nodes_path;
    options.genesis_state_path = state_path;
    options.validator_config_path = validator_config_path;
    options.node_id = "lantern_0";
    options.listen_address = "/ip4/127.0.0.1/udp/9100/quic-v1";

    if (lantern_client_options_add_bootnode(&options, "enr:-ManualEnr") != 0) {
        fprintf(stderr, "Failed to add bootnode\n");
        lantern_client_options_free(&options);
        return 1;
    }

    struct lantern_client client;
    bool client_ready = false;
    int exit_code = 1;

    if (lantern_init(&client, &options) != 0) {
        fprintf(stderr, "lantern_init failed\n");
        goto cleanup;
    }
    client_ready = true;

    if (verify_client_state(&client, &options) != 0) {
        goto cleanup;
    }

    exit_code = 0;

cleanup:
    if (client_ready) {
        lantern_shutdown(&client);
    }
    lantern_client_options_free(&options);
    return exit_code;
}
