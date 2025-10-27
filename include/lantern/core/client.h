#ifndef LANTERN_CLIENT_H
#define LANTERN_CLIENT_H

#include <stdbool.h>
#include <stdint.h>

#include "lantern/genesis/genesis.h"
#include "lantern/networking/libp2p.h"
#include "lantern/support/string_list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LANTERN_DEFAULT_DATA_DIR "./data"
#define LANTERN_DEFAULT_GENESIS_CONFIG "./genesis/config.yaml"
#define LANTERN_DEFAULT_VALIDATOR_REGISTRY "./genesis/validators.yaml"
#define LANTERN_DEFAULT_NODES_FILE "./genesis/nodes.yaml"
#define LANTERN_DEFAULT_GENESIS_STATE "./genesis/genesis.ssz"
#define LANTERN_DEFAULT_VALIDATOR_CONFIG "./genesis/validator-config.yaml"
#define LANTERN_DEFAULT_NODE_ID "lantern_0"
#define LANTERN_DEFAULT_LISTEN_ADDR "/ip4/0.0.0.0/udp/9000/quic_v1"
#define LANTERN_DEFAULT_HTTP_PORT 5052
#define LANTERN_DEFAULT_METRICS_PORT 8080

struct lantern_client_options {
    const char *data_dir;
    const char *genesis_config_path;
    const char *validator_registry_path;
    const char *nodes_path;
    const char *genesis_state_path;
    const char *validator_config_path;
    const char *node_id;
    const char *node_key_hex;
    const char *node_key_path;
    const char *listen_address;
    uint16_t http_port;
    uint16_t metrics_port;
    struct lantern_string_list bootnodes;
};

struct lantern_client {
    char *data_dir;
    char *node_id;
    char *listen_address;
    uint16_t http_port;
    uint16_t metrics_port;
    struct lantern_string_list bootnodes;
    struct lantern_genesis_paths genesis_paths;
    struct lantern_genesis_artifacts genesis;
    struct lantern_enr_record local_enr;
    struct lantern_libp2p_host network;
    uint8_t node_private_key[32];
    bool has_node_private_key;
    const struct lantern_validator_config_entry *assigned_validators;
};

void lantern_client_options_init(struct lantern_client_options *options);
void lantern_client_options_free(struct lantern_client_options *options);
int lantern_client_options_add_bootnode(struct lantern_client_options *options, const char *bootnode);

int lantern_init(struct lantern_client *client, const struct lantern_client_options *options);
void lantern_shutdown(struct lantern_client *client);

#ifdef __cplusplus
}
#endif

#endif /* LANTERN_CLIENT_H */
