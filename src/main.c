#include "lantern/client.h"

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    OPT_GENESIS_CONFIG = 1000,
    OPT_VALIDATOR_REGISTRY,
    OPT_NODES_PATH,
    OPT_GENESIS_STATE,
    OPT_VALIDATOR_CONFIG,
    OPT_NODE_ID,
    OPT_LISTEN_ADDRESS,
    OPT_HTTP_PORT,
    OPT_METRICS_PORT,
    OPT_BOOTNODE,
    OPT_BOOTNODE_FILE,
};

static void print_usage(const char *prog);
static int parse_u16(const char *text, uint16_t *out_value);
static int add_bootnodes_from_file(struct lantern_client_options *options, const char *path);
static char *trim_line(char *line);

int main(int argc, char **argv) {
    struct lantern_client_options options;
    lantern_client_options_init(&options);

    struct lantern_client client;
    memset(&client, 0, sizeof(client));

    bool show_version = false;
    bool show_help = false;

    static struct option long_options[] = {
        {"data-dir", required_argument, NULL, 'd'},
        {"genesis-config", required_argument, NULL, OPT_GENESIS_CONFIG},
        {"validator-registry-path", required_argument, NULL, OPT_VALIDATOR_REGISTRY},
        {"nodes-path", required_argument, NULL, OPT_NODES_PATH},
        {"genesis-state", required_argument, NULL, OPT_GENESIS_STATE},
        {"validator-config", required_argument, NULL, OPT_VALIDATOR_CONFIG},
        {"node-id", required_argument, NULL, OPT_NODE_ID},
        {"listen-address", required_argument, NULL, OPT_LISTEN_ADDRESS},
        {"http-port", required_argument, NULL, OPT_HTTP_PORT},
        {"metrics-port", required_argument, NULL, OPT_METRICS_PORT},
        {"bootnode", required_argument, NULL, OPT_BOOTNODE},
        {"bootnodes-file", required_argument, NULL, OPT_BOOTNODE_FILE},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'v'},
        {0, 0, 0, 0},
    };

    int opt = 0;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "d:hv", long_options, &option_index)) != -1) {
        switch (opt) {
        case 'd':
            options.data_dir = optarg;
            break;
        case 'h':
            show_help = true;
            break;
        case 'v':
            show_version = true;
            break;
        case OPT_GENESIS_CONFIG:
            options.genesis_config_path = optarg;
            break;
        case OPT_VALIDATOR_REGISTRY:
            options.validator_registry_path = optarg;
            break;
        case OPT_NODES_PATH:
            options.nodes_path = optarg;
            break;
        case OPT_GENESIS_STATE:
            options.genesis_state_path = optarg;
            break;
        case OPT_VALIDATOR_CONFIG:
            options.validator_config_path = optarg;
            break;
        case OPT_NODE_ID:
            options.node_id = optarg;
            break;
        case OPT_LISTEN_ADDRESS:
            options.listen_address = optarg;
            break;
        case OPT_HTTP_PORT:
            if (parse_u16(optarg, &options.http_port) != 0) {
                fprintf(stderr, "lantern: invalid http-port '%s'\n", optarg);
                goto error;
            }
            break;
        case OPT_METRICS_PORT:
            if (parse_u16(optarg, &options.metrics_port) != 0) {
                fprintf(stderr, "lantern: invalid metrics-port '%s'\n", optarg);
                goto error;
            }
            break;
        case OPT_BOOTNODE:
            if (lantern_client_options_add_bootnode(&options, optarg) != 0) {
                fprintf(stderr, "lantern: failed to add bootnode\n");
                goto error;
            }
            break;
        case OPT_BOOTNODE_FILE:
            if (add_bootnodes_from_file(&options, optarg) != 0) {
                fprintf(stderr, "lantern: failed to read bootnodes file %s\n", optarg);
                goto error;
            }
            break;
        default:
            goto error;
        }
    }

    if (show_version) {
        printf("lantern devnet0 preview\n");
        goto cleanup;
    }

    if (show_help) {
        print_usage(argv[0]);
        goto cleanup;
    }

    if (!options.node_id) {
        fprintf(stderr, "lantern: --node-id is required\n");
        goto error;
    }

    if (lantern_init(&client, &options) != 0) {
        fprintf(stderr, "lantern: initialization failed\n");
        goto error;
    }

    printf(
        "lantern ready | genesis_time=%" PRIu64 " validators=%" PRIu64 " enr=%zu manual_bootnodes=%zu\n",
        client.genesis.chain_config.genesis_time,
        client.genesis.chain_config.validator_count,
        client.genesis.enrs.count,
        client.bootnodes.len);

cleanup:
    lantern_shutdown(&client);
    lantern_client_options_free(&options);
    return 0;

error:
    print_usage(argv[0]);
    lantern_shutdown(&client);
    lantern_client_options_free(&options);
    return 1;
}

static void print_usage(const char *prog) {
    fprintf(
        stderr,
        "Usage: %s [options]\n"
        "  --data-dir PATH              Data directory (default %s)\n"
        "  --genesis-config PATH        Path to genesis config YAML\n"
        "  --validator-registry-path PATH  Path to validators.yaml\n"
        "  --nodes-path PATH            Path to nodes.yaml\n"
        "  --genesis-state PATH         Path to genesis.ssz\n"
        "  --validator-config PATH      Path to validator-config.yaml\n"
        "  --node-id NAME               Node identifier (e.g., ream_0)\n"
        "  --listen-address ADDR        QUIC listen multiaddr\n"
        "  --http-port PORT             HTTP API port\n"
        "  --metrics-port PORT          Metrics port\n"
        "  --bootnode ENR               Add a bootnode enr\n"
        "  --bootnodes-file PATH        File with newline-delimited ENRs\n"
        "  --help                       Show this message\n"
        "  --version                    Print version information\n",
        prog,
        LANTERN_DEFAULT_DATA_DIR);
}

static int parse_u16(const char *text, uint16_t *out_value) {
    if (!text || !out_value) {
        return -1;
    }
    errno = 0;
    char *end = NULL;
    long parsed = strtol(text, &end, 10);
    if (errno != 0 || end == text || parsed < 0 || parsed > UINT16_MAX) {
        return -1;
    }
    *out_value = (uint16_t)parsed;
    return 0;
}

static int add_bootnodes_from_file(struct lantern_client_options *options, const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror("lantern: fopen bootnodes");
        return -1;
    }

    char line[2048];
    while (fgets(line, sizeof(line), fp)) {
        char *trimmed = trim_line(line);
        if (*trimmed == '\0' || *trimmed == '#') {
            continue;
        }
        if (lantern_client_options_add_bootnode(options, trimmed) != 0) {
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return 0;
}

static char *trim_line(char *line) {
    if (!line) {
        return NULL;
    }
    while (*line && isspace((unsigned char)*line)) {
        ++line;
    }
    char *end = line + strlen(line);
    while (end > line && isspace((unsigned char)*(end - 1))) {
        --end;
    }
    *end = '\0';
    return line;
}
