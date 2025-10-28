#include "lantern/core/client.h"

#include <stdbool.h>
#include <stdint.h>
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

static int verify_client_state(
    const struct lantern_client *client,
    const struct lantern_client_options *options,
    const uint64_t *expected_indices,
    size_t expected_count,
    uint16_t expected_udp_port) {
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
    if (client->genesis.validator_registry.count != 4) {
        fprintf(stderr, "Unexpected validator registry count: %zu\n", client->genesis.validator_registry.count);
        return 1;
    }
    if (client->genesis.validator_config.count != 3) {
        fprintf(stderr, "Unexpected validator config count: %zu\n", client->genesis.validator_config.count);
        return 1;
    }
    if (!client->assigned_validators || client->assigned_validators->count != expected_count) {
        fprintf(stderr, "Validator assignment missing or incorrect\n");
        return 1;
    }
    if (client->validator_assignment.count != expected_count) {
        fprintf(stderr, "Validator assignment count mismatch\n");
        return 1;
    }
    if (!expected_indices || expected_count == 0) {
        fprintf(stderr, "Expected indices missing\n");
        return 1;
    }
    if (client->validator_assignment.start_index != expected_indices[0]) {
        fprintf(stderr, "Validator assignment start index mismatch\n");
        return 1;
    }
    if (!client->local_enr.encoded) {
        fprintf(stderr, "Local ENR missing\n");
        return 1;
    }
    if (client->local_enr.sequence != client->assigned_validators->enr.sequence) {
        fprintf(stderr, "Local ENR sequence mismatch\n");
        return 1;
    }
    const struct lantern_enr_key_value *udp = lantern_enr_record_find(&client->local_enr, "udp");
    if (!udp || udp->value_len != 2) {
        fprintf(stderr, "Local ENR UDP missing\n");
        return 1;
    }
    uint16_t udp_port = (uint16_t)(((uint16_t)udp->value[0] << 8) | (uint16_t)udp->value[1]);
    if (udp_port != expected_udp_port) {
        fprintf(stderr, "Local ENR UDP mismatch\n");
        return 1;
    }
    if (!client->network.host || !client->network.started) {
        fprintf(stderr, "libp2p host missing or not started\n");
        return 1;
    }
    if (!client->gossip_running || !client->gossip.gossipsub) {
        fprintf(stderr, "gossipsub service not running\n");
        return 1;
    }

    if (lantern_client_local_validator_count(client) != expected_count) {
        fprintf(stderr, "Local validator count mismatch\n");
        return 1;
    }
    for (size_t i = 0; i < expected_count; ++i) {
        const struct lantern_local_validator *validator = lantern_client_local_validator(client, i);
        if (!validator) {
            fprintf(stderr, "Missing local validator %zu\n", i);
            return 1;
        }
        if (validator->global_index != expected_indices[i]) {
            fprintf(stderr, "Unexpected global index at %zu: expected %llu got %llu\n",
                i,
                (unsigned long long)expected_indices[i],
                (unsigned long long)validator->global_index);
            return 1;
        }
        if (!validator->registry || validator->registry->index != expected_indices[i]) {
            fprintf(stderr, "Validator registry pointer mismatch at %zu\n", i);
            return 1;
        }
    }

    size_t expected_bootnodes = options->bootnodes.len;
    for (size_t i = 0; i < options->bootnodes.len; ++i) {
        if (!string_list_contains(&client->bootnodes, options->bootnodes.items[i])) {
            fprintf(stderr, "Missing manual bootnode: %s\n", options->bootnodes.items[i]);
            return 1;
        }
    }
    for (size_t i = 0; i < client->genesis.enrs.count; ++i) {
        const struct lantern_enr_record *record = &client->genesis.enrs.records[i];
        if (!record->encoded) {
            continue;
        }
        if (!string_list_contains(&client->bootnodes, record->encoded)) {
            fprintf(stderr, "Missing genesis bootnode: %s\n", record->encoded);
            return 1;
        }
        if (!string_list_contains(&options->bootnodes, record->encoded)) {
            ++expected_bootnodes;
        }
    }
    if (client->bootnodes.len != expected_bootnodes) {
        fprintf(
            stderr,
            "Bootnode count mismatch: expected %zu got %zu\n",
            expected_bootnodes,
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
    options.listen_address = "/ip4/127.0.0.1/udp/9100/quic_v1";
    options.node_key_hex = "0xb71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291";
    options.metrics_port = 0;

    if (lantern_client_options_add_bootnode(&options, "enr:-ManualEnr") != 0) {
        fprintf(stderr, "Failed to add bootnode\n");
        lantern_client_options_free(&options);
        return 1;
    }

    const uint64_t node0_indices[] = {0};
    const uint64_t node1_indices[] = {1, 2};

    struct lantern_client client;
    bool client_ready = false;
    int exit_code = 1;

    if (lantern_init(&client, &options) != 0) {
        fprintf(stderr, "lantern_init failed for lantern_0\n");
        goto cleanup;
    }
    client_ready = true;

    if (verify_client_state(&client, &options, node0_indices, 1, 9100) != 0) {
        goto cleanup;
    }

    lantern_shutdown(&client);
    client_ready = false;
    memset(&client, 0, sizeof(client));

    options.node_id = "lantern_1";
    options.listen_address = "/ip4/127.0.0.1/udp/9200/quic_v1";

    if (lantern_init(&client, &options) != 0) {
        fprintf(stderr, "lantern_init failed for lantern_1\n");
        goto cleanup;
    }
    client_ready = true;

    if (verify_client_state(&client, &options, node1_indices, 2, 9101) != 0) {
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
