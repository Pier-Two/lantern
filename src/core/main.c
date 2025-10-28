#include "lantern/core/client.h"
#include "lantern/support/log.h"

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum {
    OPT_GENESIS_CONFIG = 1000,
    OPT_VALIDATOR_REGISTRY,
    OPT_NODES_PATH,
    OPT_GENESIS_STATE,
    OPT_VALIDATOR_CONFIG,
    OPT_NODE_ID,
    OPT_NODE_KEY,
    OPT_NODE_KEY_PATH,
    OPT_LISTEN_ADDRESS,
    OPT_HTTP_PORT,
    OPT_METRICS_PORT,
    OPT_BOOTNODE,
    OPT_BOOTNODES,
    OPT_BOOTNODE_FILE,
};

static void print_usage(const char *prog);
static int parse_u16(const char *text, uint16_t *out_value);
static int add_bootnodes_from_file(struct lantern_client_options *options, const char *path);
static int add_bootnodes_argument(struct lantern_client_options *options, const char *value);
static char *trim_line(char *line);

static volatile sig_atomic_t g_keep_running = 1;

static void lantern_handle_signal(int signo) {
    (void)signo;
    g_keep_running = 0;
}

int main(int argc, char **argv) {
    struct lantern_client_options options;
    lantern_client_options_init(&options);

    struct lantern_client client;
    memset(&client, 0, sizeof(client));

    signal(SIGINT, lantern_handle_signal);
    signal(SIGTERM, lantern_handle_signal);

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
        {"node-key", required_argument, NULL, OPT_NODE_KEY},
        {"node-key-path", required_argument, NULL, OPT_NODE_KEY_PATH},
        {"listen-address", required_argument, NULL, OPT_LISTEN_ADDRESS},
        {"http-port", required_argument, NULL, OPT_HTTP_PORT},
        {"metrics-port", required_argument, NULL, OPT_METRICS_PORT},
        {"bootnode", required_argument, NULL, OPT_BOOTNODE},
        {"bootnodes", required_argument, NULL, OPT_BOOTNODES},
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
        case OPT_NODE_KEY:
            options.node_key_hex = optarg;
            break;
        case OPT_NODE_KEY_PATH:
            options.node_key_path = optarg;
            break;
        case OPT_LISTEN_ADDRESS:
            options.listen_address = optarg;
            break;
        case OPT_HTTP_PORT:
            if (parse_u16(optarg, &options.http_port) != 0) {
                lantern_log_error(
                    "cli",
                    &(const struct lantern_log_metadata){.validator = options.node_id},
                    "invalid http-port '%s'",
                    optarg);
                goto error;
            }
            break;
        case OPT_METRICS_PORT:
            if (parse_u16(optarg, &options.metrics_port) != 0) {
                lantern_log_error(
                    "cli",
                    &(const struct lantern_log_metadata){.validator = options.node_id},
                    "invalid metrics-port '%s'",
                    optarg);
                goto error;
            }
            break;
        case OPT_BOOTNODE:
            if (lantern_client_options_add_bootnode(&options, optarg) != 0) {
                lantern_log_error(
                    "cli",
                    &(const struct lantern_log_metadata){.validator = options.node_id},
                    "failed to add bootnode '%s'",
                    optarg);
                goto error;
            }
            break;
        case OPT_BOOTNODES:
            if (add_bootnodes_argument(&options, optarg) != 0) {
                lantern_log_error(
                    "cli",
                    &(const struct lantern_log_metadata){.validator = options.node_id},
                    "failed to consume bootnodes from %s",
                    optarg);
                goto error;
            }
            break;
        case OPT_BOOTNODE_FILE:
            if (add_bootnodes_from_file(&options, optarg) != 0) {
                lantern_log_error(
                    "cli",
                    &(const struct lantern_log_metadata){.validator = options.node_id},
                    "failed to read bootnodes file %s",
                    optarg);
                goto error;
            }
            break;
        default:
            goto error;
        }
    }

    if (options.node_key_hex && options.node_key_path) {
        lantern_log_error(
            "cli",
            &(const struct lantern_log_metadata){.validator = options.node_id},
            "specify only one of --node-key or --node-key-path");
        goto error;
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
        lantern_log_error(
            "cli",
            &(const struct lantern_log_metadata){0},
            "--node-id is required");
        goto error;
    }

    if (lantern_init(&client, &options) != 0) {
        lantern_log_error(
            "cli",
            &(const struct lantern_log_metadata){.validator = options.node_id},
            "initialization failed");
        goto error;
    }

    lantern_log_info(
        "cli",
        &(const struct lantern_log_metadata){.validator = client.node_id},
        "lantern ready genesis_time=%" PRIu64 " validators=%" PRIu64 " enr=%zu manual_bootnodes=%zu local_enr=%s",
        client.genesis.chain_config.genesis_time,
        client.genesis.chain_config.validator_count,
        client.genesis.enrs.count,
        client.bootnodes.len,
        client.local_enr.encoded ? client.local_enr.encoded : "-");

    struct timespec sleep_duration;
    sleep_duration.tv_sec = 1;
    sleep_duration.tv_nsec = 0;
    while (g_keep_running) {
        nanosleep(&sleep_duration, NULL);
    }

    lantern_log_info(
        "cli",
        &(const struct lantern_log_metadata){.validator = client.node_id},
        "shutdown requested");

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
        "  --node-key HEX               Local node private key (32-byte hex)\n"
        "  --node-key-path PATH         Path to file containing node private key hex\n"
        "  --listen-address ADDR        QUIC listen multiaddr\n"
        "  --http-port PORT             HTTP API port\n"
        "  --metrics-port PORT          Metrics port\n"
        "  --bootnode ENR               Add a bootnode enr\n"
        "  --bootnodes VALUE            ENR or path to YAML/List file of ENRs\n"
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
    if (!options || !path) {
        return -1;
    }

    FILE *fp = fopen(path, "r");
    if (!fp) {
        lantern_log_error(
            "cli",
            &(const struct lantern_log_metadata){.validator = options->node_id},
            "unable to open bootnodes file %s",
            path);
        return -1;
    }

    char line[2048];
    size_t added = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *trimmed = trim_line(line);
        if (!trimmed || *trimmed == '\0' || *trimmed == '#') {
            continue;
        }

        char *hash = strchr(trimmed, '#');
        if (hash) {
            *hash = '\0';
            trimmed = trim_line(trimmed);
            if (!trimmed || *trimmed == '\0') {
                continue;
            }
        }

        if (*trimmed == '-') {
            ++trimmed;
            while (*trimmed && isspace((unsigned char)*trimmed)) {
                ++trimmed;
            }
        }

        char *value_start = strstr(trimmed, "enr:");
        if (!value_start) {
            if (strncmp(trimmed, "enr:", 4) != 0) {
                continue;
            }
            value_start = trimmed;
        }

        char *end = value_start + strlen(value_start);
        while (end > value_start && isspace((unsigned char)*(end - 1))) {
            --end;
        }
        *end = '\0';

        if (*value_start == '"' || *value_start == '\'') {
            ++value_start;
            size_t len = strlen(value_start);
            if (len > 0 && (value_start[len - 1] == '"' || value_start[len - 1] == '\'')) {
                value_start[len - 1] = '\0';
            }
        }

        if (strncmp(value_start, "enr:", 4) != 0) {
            continue;
        }

        if (lantern_client_options_add_bootnode(options, value_start) != 0) {
            fclose(fp);
            return -1;
        }
        added++;
        lantern_log_info(
            "cli",
            &(const struct lantern_log_metadata){
                .validator = options->node_id,
                .peer = value_start},
            "bootnode registered from %s",
            path);
    }

    fclose(fp);

    if (added == 0) {
        lantern_log_warn(
            "cli",
            &(const struct lantern_log_metadata){.validator = options->node_id},
            "no ENRs found in %s",
            path);
        return -1;
    }

    return 0;
}

static int add_bootnodes_argument(struct lantern_client_options *options, const char *value) {
    if (!options || !value) {
        return -1;
    }
    if (strncmp(value, "enr:", 4) == 0) {
        return lantern_client_options_add_bootnode(options, value);
    }
    return add_bootnodes_from_file(options, value);
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
