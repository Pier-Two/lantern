/**
 * @file client_options.c
 * @brief Configuration parsing for the Lantern client options struct
 *
 * @see client_internal.h for shared internal declarations
 */

#include "client_internal.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const size_t BOOTNODE_LINE_MAX_LEN = 2048u;

/**
 * @brief Initialize client options with default values.
 *
 * Sets all fields to their default values, including paths to configuration
 * files, network settings, and an empty bootnode list.
 *
 * @param options  Client options struct to initialize
 *
 * @note Thread safety: None required - operates on caller-provided struct.
 */
void lantern_client_options_init(struct lantern_client_options *options)
{
    if (!options)
    {
        return;
    }

    memset(options, 0, sizeof(*options));
    options->data_dir = LANTERN_DEFAULT_DATA_DIR;
    options->genesis_config_path = LANTERN_DEFAULT_GENESIS_CONFIG;
    options->validator_config_dir = LANTERN_DEFAULT_VALIDATOR_CONFIG_DIR;
    options->nodes_path = LANTERN_DEFAULT_NODES_FILE;
    options->node_id = LANTERN_DEFAULT_NODE_ID;
    options->listen_address = LANTERN_DEFAULT_LISTEN_ADDR;
    options->http_port = LANTERN_DEFAULT_HTTP_PORT;
    options->metrics_port = LANTERN_DEFAULT_METRICS_PORT;
    options->devnet = LANTERN_DEFAULT_DEVNET;
}

/**
 * @brief Free resources allocated within client options.
 *
 * Releases the bootnode list and any other dynamically allocated resources.
 * The options struct itself is not freed (caller-owned).
 *
 * @param options  Client options struct to free (may be NULL)
 *
 * @note Thread safety: None required - operates on caller-provided struct.
 */
void lantern_client_options_free(struct lantern_client_options *options)
{
    if (!options)
    {
        return;
    }
    lantern_string_list_reset(&options->bootnodes);
    free(options->aggregate_subnet_ids);
    options->aggregate_subnet_ids = NULL;
    options->aggregate_subnet_id_count = 0;
    options->aggregate_subnet_id_capacity = 0;
}

/**
 * @brief Add a bootnode address to client options.
 *
 * Appends an ENR string to the list of bootnodes that will be used
 * during client initialization to discover peers.
 *
 * @param options   Client options struct to modify
 * @param bootnode  ENR string (e.g., "enr:-...")
 *
 * @return LANTERN_CLIENT_OK on success
 * @return LANTERN_CLIENT_ERR_INVALID_PARAM if options or bootnode is NULL
 * @return LANTERN_CLIENT_ERR_ALLOC on allocation failure
 *
 * @note Thread safety: None required - operates on caller-provided struct.
 */
lantern_client_error lantern_client_options_add_bootnode(
    struct lantern_client_options *options,
    const char *bootnode)
{
    if (!options || !bootnode)
    {
        return LANTERN_CLIENT_ERR_INVALID_PARAM;
    }
    return lantern_string_list_append(&options->bootnodes, bootnode) == 0
               ? LANTERN_CLIENT_OK
               : LANTERN_CLIENT_ERR_ALLOC;
}

lantern_client_error lantern_client_options_add_aggregate_subnet_id(
    struct lantern_client_options *options,
    size_t subnet_id)
{
    if (!options)
    {
        return LANTERN_CLIENT_ERR_INVALID_PARAM;
    }
    if (options->aggregate_subnet_id_count == options->aggregate_subnet_id_capacity)
    {
        if (options->aggregate_subnet_id_capacity > SIZE_MAX / 2u)
        {
            return LANTERN_CLIENT_ERR_ALLOC;
        }
        size_t next_capacity =
            options->aggregate_subnet_id_capacity == 0
                ? 4u
                : options->aggregate_subnet_id_capacity * 2u;
        if (next_capacity < options->aggregate_subnet_id_count
            || next_capacity > SIZE_MAX / sizeof(*options->aggregate_subnet_ids))
        {
            return LANTERN_CLIENT_ERR_ALLOC;
        }
        size_t *next = realloc(
            options->aggregate_subnet_ids,
            next_capacity * sizeof(*next));
        if (!next)
        {
            return LANTERN_CLIENT_ERR_ALLOC;
        }
        options->aggregate_subnet_ids = next;
        options->aggregate_subnet_id_capacity = next_capacity;
    }
    options->aggregate_subnet_ids[options->aggregate_subnet_id_count++] = subnet_id;
    return LANTERN_CLIENT_OK;
}

/**
 * @brief Trim leading and trailing whitespace from a string in place.
 *
 * Advances the pointer past leading whitespace and overwrites trailing
 * whitespace with a null terminator.
 *
 * @param line  String to trim (modified in place)
 *
 * @return Pointer to the trimmed string, or NULL if input is NULL
 *
 * @note Thread safety: Caller must ensure exclusive access to the buffer.
 */
static char *trim_line(char *line)
{
    if (!line)
    {
        return NULL;
    }
    while (*line && isspace((unsigned char)*line))
    {
        ++line;
    }
    char *end = line + strlen(line);
    while (end > line && isspace((unsigned char)*(end - 1)))
    {
        --end;
    }
    *end = '\0';
    return line;
}

/**
 * @brief Add bootnodes from a newline-delimited or YAML-style file.
 *
 * Supports YAML list entries (leading '-') and ignores comments beginning
 * with '#'. Each parsed ENR is appended to the options bootnode list.
 *
 * @param options  Client options to mutate
 * @param path     Path to bootnodes file
 *
 * @return LANTERN_CLIENT_OK on success (at least one ENR added)
 * @return LANTERN_CLIENT_ERR_INVALID_PARAM on bad inputs or parse failure
 * @return LANTERN_CLIENT_ERR_ALLOC on allocation failure
 *
 * @note Thread safety: Not thread-safe; mutates caller-owned options and uses
 *       shared logging. Call during single-threaded startup only.
 */
lantern_client_error lantern_client_options_add_bootnodes_from_file(
    struct lantern_client_options *options,
    const char *path)
{
    if (!options || !path)
    {
        return LANTERN_CLIENT_ERR_INVALID_PARAM;
    }

    FILE *fp = fopen(path, "r");
    if (!fp)
    {
        lantern_log_error(
            "cli",
            &(const struct lantern_log_metadata){.validator = options->node_id},
            "unable to open bootnodes file %s",
            path);
        return LANTERN_CLIENT_ERR_INVALID_PARAM;
    }

    char line[BOOTNODE_LINE_MAX_LEN];
    size_t added = 0;
    lantern_client_error result = LANTERN_CLIENT_OK;

    while (fgets(line, sizeof(line), fp))
    {
        char *trimmed = trim_line(line);
        if (!trimmed || *trimmed == '\0' || *trimmed == '#')
        {
            continue;
        }

        char *hash = strchr(trimmed, '#');
        if (hash)
        {
            *hash = '\0';
            trimmed = trim_line(trimmed);
            if (!trimmed || *trimmed == '\0')
            {
                continue;
            }
        }

        if (*trimmed == '-')
        {
            ++trimmed;
            while (*trimmed && isspace((unsigned char)*trimmed))
            {
                ++trimmed;
            }
        }

        char *value_start = strstr(trimmed, "enr:");
        if (!value_start)
        {
            if (strncmp(trimmed, "enr:", 4) != 0)
            {
                continue;
            }
            value_start = trimmed;
        }

        char *end = value_start + strlen(value_start);
        while (end > value_start && isspace((unsigned char)*(end - 1)))
        {
            --end;
        }
        *end = '\0';

        if (*value_start == '"' || *value_start == '\'')
        {
            ++value_start;
            size_t len = strlen(value_start);
            if (len > 0 && (value_start[len - 1] == '"' || value_start[len - 1] == '\''))
            {
                value_start[len - 1] = '\0';
            }
        }

        if (strncmp(value_start, "enr:", 4) != 0)
        {
            continue;
        }

        result = lantern_client_options_add_bootnode(options, value_start);
        if (result != LANTERN_CLIENT_OK)
        {
            break;
        }
        ++added;
        lantern_log_info(
            "cli",
            &(const struct lantern_log_metadata){
                .validator = options->node_id,
                .peer = value_start},
            "bootnode registered from %s",
            path);
    }

    if (fclose(fp) != 0)
    {
        lantern_log_warn(
            "cli",
            &(const struct lantern_log_metadata){.validator = options->node_id},
            "failed to close bootnodes file %s: %s",
            path,
            strerror(errno));
        if (result == LANTERN_CLIENT_OK)
        {
            result = LANTERN_CLIENT_ERR_INVALID_PARAM;
        }
    }

    if (result != LANTERN_CLIENT_OK)
    {
        return result;
    }

    if (added == 0)
    {
        lantern_log_warn(
            "cli",
            &(const struct lantern_log_metadata){.validator = options->node_id},
            "no ENRs found in %s",
            path);
        return LANTERN_CLIENT_ERR_INVALID_PARAM;
    }

    return LANTERN_CLIENT_OK;
}

/**
 * @brief Add bootnodes from a command-line style argument.
 *
 * If the value begins with "enr:" it is treated as an ENR; otherwise it is
 * treated as a file path of ENRs.
 *
 * @param options  Client options to mutate
 * @param value    ENR string or path
 *
 * @return LANTERN_CLIENT_OK on success
 * @return LANTERN_CLIENT_ERR_INVALID_PARAM on invalid input/parse error
 * @return LANTERN_CLIENT_ERR_ALLOC on allocation failure
 *
 * @note Thread safety: Not thread-safe; mutates caller-owned options.
 */
lantern_client_error lantern_client_options_add_bootnodes_argument(
    struct lantern_client_options *options,
    const char *value)
{
    if (!options || !value)
    {
        return LANTERN_CLIENT_ERR_INVALID_PARAM;
    }

    if (strncmp(value, "enr:", 4) == 0)
    {
        return lantern_client_options_add_bootnode(options, value);
    }

    return lantern_client_options_add_bootnodes_from_file(options, value);
}

