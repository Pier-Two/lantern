/**
 * @file lifecycle.c
 * @brief Lantern client core initialization and lifecycle management
 *
 * Implements the main client structure initialization, startup sequence,
 * and graceful shutdown. This is the central coordinator that brings together:
 * - Genesis configuration loading
 * - Consensus state management
 * - Networking (libp2p, gossipsub, request/response)
 * - Validator services
 * - HTTP and metrics servers
 *
 * @see internal.h for shared internal declarations
 */

#include "lantern/core/client.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "internal/yaml_parser.h"
#include "internal.h"
#include "lantern/consensus/containers.h"
#include "lantern/consensus/fork_choice.h"
#include "lantern/consensus/hash.h"
#include "lantern/consensus/signature.h"
#include "lantern/consensus/slot_clock.h"
#include "lantern/consensus/ssz.h"
#include "lantern/consensus/state.h"
#include "lantern/crypto/xmss.h"
#include "lantern/encoding/snappy.h"
#include "lantern/http/client.h"
#include "lantern/http/server.h"
#include "lantern/metrics/lean_metrics.h"
#include "lantern/networking/gossip.h"
#include "lantern/networking/messages.h"
#include "lantern/networking/reqresp_service.h"
#include "lantern/storage/storage.h"
#include "lantern/support/log.h"
#include "lantern/support/secure_mem.h"
#include "lantern/support/strings.h"
#include "lantern/support/time.h"

_Static_assert(
    sizeof(LanternValidator)
        == (2u * LANTERN_VALIDATOR_PUBKEY_SIZE) + sizeof(LanternValidatorIndex),
    "LanternValidator registry entries must not contain padding");

/**
 * @brief Reset the client struct to baseline defaults.
 *
 * Zeroes all fields, establishes server descriptor sentinels and Store atomics,
 * and leaves background services stopped. This prepares the struct for
 * subsequent initialization steps.
 *
 * @param client  Client instance to reset (must not be NULL)
 *
 * @note Thread safety: Caller must ensure exclusive access; intended for
 *       single-threaded initialization only.
 */
static void client_reset_base(struct lantern_client *client)
{
    memset(client, 0, sizeof(*client));
    time_t now_seconds = time(NULL);
    client->start_time_seconds = now_seconds > 0 ? (uint64_t)now_seconds : 0u;
    lantern_metrics_server_init(&client->metrics_server);
    lantern_http_server_init(&client->http_server);
    lantern_store_init(&client->store);
    lean_metrics_reset();
    client->block_proposal_stop = true;
    client->timing_stop_flag = 1;
    client->dialer_stop_flag = 1;
    client->block_import_stop = true;
}

/**
 * @brief Apply user-provided options to the client instance.
 *
 * Copies configurable strings and ports into the client.
 *
 * @param client   Client being configured
 * @param options  Source options (must not be NULL)
 *
 * @return LANTERN_CLIENT_OK on success
 * @return LANTERN_CLIENT_ERR_ALLOC if allocation fails
 *
 * @note Thread safety: Must be called before concurrent access to the client.
 */
static lantern_client_error client_apply_options(
    struct lantern_client *client,
    const struct lantern_client_options *options)
{
    if (set_owned_string(&client->data_dir, options->data_dir) != 0)
    {
        return LANTERN_CLIENT_ERR_ALLOC;
    }
    if (set_owned_string(&client->node_id, options->node_id) != 0)
    {
        return LANTERN_CLIENT_ERR_ALLOC;
    }
    if (set_owned_string(&client->listen_address, options->listen_address) != 0)
    {
        return LANTERN_CLIENT_ERR_ALLOC;
    }
    if (set_owned_string(&client->devnet, options->devnet) != 0)
    {
        return LANTERN_CLIENT_ERR_ALLOC;
    }

    client->http_port = options->http_port;
    client->metrics_port = options->metrics_port;
    if (options->attestation_committee_count_override > 0u)
    {
        client->debug_attestation_committee_count =
            (size_t)options->attestation_committee_count_override;
    }
    if (options->aggregate_subnet_id_count > 0)
    {
        size_t bytes =
            options->aggregate_subnet_id_count * sizeof(*client->aggregate_subnet_ids);
        if (bytes / sizeof(*client->aggregate_subnet_ids) != options->aggregate_subnet_id_count)
        {
            return LANTERN_CLIENT_ERR_ALLOC;
        }
        client->aggregate_subnet_ids = malloc(bytes);
        if (!client->aggregate_subnet_ids)
        {
            return LANTERN_CLIENT_ERR_ALLOC;
        }
        memcpy(
            client->aggregate_subnet_ids,
            options->aggregate_subnet_ids,
            bytes);
        client->aggregate_subnet_id_count = options->aggregate_subnet_id_count;
    }
    return LANTERN_CLIENT_OK;
}

/**
 * @brief Initialize mutexes used by the client.
 *
 * Creates pending, status, state, and peer vote locks if they have not already
 * been initialized.
 *
 * @param client  Client owning the locks
 *
 * @return LANTERN_CLIENT_OK on success
 * @return LANTERN_CLIENT_ERR_RUNTIME if any mutex initialization fails
 *
 * @note Thread safety: Must be invoked before any multi-threaded use.
 */
static lantern_client_error client_init_locks(struct lantern_client *client)
{
    if (pthread_mutex_init(&client->pending_lock, NULL) != 0)
    {
        lantern_log_error(
            "client",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to initialize pending block lock");
        return LANTERN_CLIENT_ERR_RUNTIME;
    }
    client->pending_lock_initialized = true;

    if (!client->status_lock_initialized)
    {
        if (pthread_mutex_init(&client->status_lock, NULL) != 0)
        {
            lantern_log_error(
                "client",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to initialize peer status lock");
            return LANTERN_CLIENT_ERR_RUNTIME;
        }
        client->status_lock_initialized = true;
    }

    if (!client->state_lock_initialized)
    {
        if (pthread_mutex_init(&client->state_lock, NULL) != 0)
        {
            lantern_log_error(
                "client",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to initialize state lock");
            return LANTERN_CLIENT_ERR_RUNTIME;
        }
        client->state_lock_initialized = true;
    }

    return LANTERN_CLIENT_OK;
}

/**
 * @brief Launch background services for peer maintenance and validator duties.
 *
 * Starts auxiliary threads; failures are logged as warnings but do not abort
 * client startup.
 *
 * @param client  Client for which background services are started
 *
 * @note Thread safety: Caller must ensure services are started once during init.
 */
static void client_start_background_services(struct lantern_client *client)
{
    if (start_peer_dialer(client) != 0)
    {
        lantern_log_warn(
            "network",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "failed to enable peer maintenance");
    }

    if (start_block_proposal_worker(client) != 0)
    {
        lantern_log_warn(
            "validator",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "block proposal worker inactive");
    }

    if (start_timing_service(client) != 0)
    {
        lantern_log_warn(
            "forkchoice",
            &(const struct lantern_log_metadata){.validator = client->node_id},
            "chain scheduler inactive");
    }
}

/**
 * @brief Initialize and start the Lantern client.
 *
 * Sets up all subsystems including networking, gossip, request/response,
 * validator services, and HTTP/metrics servers. This is the main entry
 * point for starting a Lantern node.
 *
 * Initialization order:
 * 1. Genesis and state loading
 * 2. Validator configuration
 * 3. Networking (libp2p host, gossipsub, request/response)
 * 4. Services (HTTP, metrics, validator duties)
 *
 * @param client   Client struct to initialize (must be zeroed or freshly allocated)
 * @param options  Configuration options (not modified, can be freed after call)
 *
 * @return LANTERN_CLIENT_OK on success
 * @return negative lantern_client_error on failure (client is cleaned up via lantern_shutdown)
 *
 * @note Thread safety: Must be called from a single thread before any
 *       concurrent access to the client. Initializes all internal locks.
 */
lantern_client_error lantern_init(
    struct lantern_client *client,
    const struct lantern_client_options *options)
{
    if (!client || !options)
    {
        return LANTERN_CLIENT_ERR_INVALID_PARAM;
    }

    uint8_t node_key[NODE_PRIVATE_KEY_SIZE];
    lantern_client_error err = LANTERN_CLIENT_OK;

    lantern_signature_configure_shadow_costs(
        options->shadow_xmss_rates,
        options->shadow_xmss_rates_set);
    lantern_signature_configure_prover(options->prover_arena);

    client_reset_base(client);

    err = client_apply_options(client, options);
    if (err != LANTERN_CLIENT_OK)
    {
        goto error;
    }

    err = client_init_locks(client);
    if (err != LANTERN_CLIENT_OK)
    {
        goto error;
    }

    err = lantern_client_block_importer_start(client);
    if (err != LANTERN_CLIENT_OK)
    {
        goto error;
    }

    err = client_prepare_storage_and_genesis(client, options);
    if (err != LANTERN_CLIENT_OK)
    {
        goto error;
    }

    err = client_load_or_build_state(client, options, NULL);
    if (err != LANTERN_CLIENT_OK)
    {
        goto error;
    }

    err = client_setup_validators(client, options);
    if (err != LANTERN_CLIENT_OK)
    {
        goto error;
    }

    err = client_start_network(client, options, node_key);
    if (err != LANTERN_CLIENT_OK)
    {
        memset(node_key, 0, sizeof(node_key));
        goto error;
    }

    err = client_start_protocols(client, node_key);
    if (err != LANTERN_CLIENT_OK)
    {
        memset(node_key, 0, sizeof(node_key));
        goto error;
    }

    client_start_background_services(client);

    err = client_start_apis(client);
    if (err != LANTERN_CLIENT_OK)
    {
        goto error;
    }

    return LANTERN_CLIENT_OK;

error:
    memset(node_key, 0, sizeof(node_key));
    lantern_shutdown(client);
    return (err == LANTERN_CLIENT_OK) ? LANTERN_CLIENT_ERR_RUNTIME : err;
}

/**
 * @brief Shutdown and clean up the Lantern client.
 *
 * Stops all services, releases all resources, and restores the same empty
 * baseline used at initialization.
 *
 * Shutdown order (reverse of initialization):
 * 1. Validator and ping services
 * 2. HTTP and metrics servers
 * 3. Networking (gossipsub, request/response, libp2p)
 * 4. Genesis artifacts and configuration
 * 5. State and fork choice
 *
 * @param client  Client to shutdown (may be NULL, which is a no-op)
 *
 * @note Thread safety: Must be called from a single thread after all other
 *       threads have stopped using the client. Destroys all internal locks.
 */
void lantern_shutdown(struct lantern_client *client)
{
    if (!client)
    {
        return;
    }

    stop_timing_service(client);
    stop_block_proposal_worker(client);
    stop_peer_dialer(client);
    lantern_libp2p_host_stop(&client->network);
    free(client->xmss_key_dir);
    free(client->xmss_secret_template);
    free(client->xmss_secret_path);

    lantern_metrics_server_stop(&client->metrics_server);
    lantern_http_server_stop(&client->http_server);
    lantern_client_block_importer_stop(client);

    connection_counter_reset(client);
    if (client->connection_lock_initialized)
    {
        pthread_mutex_destroy(&client->connection_lock);
    }

    bool status_locked = client->status_lock_initialized
        && pthread_mutex_lock(&client->status_lock) == 0;
    free(client->peer_status_entries);
    for (size_t i = 0; i < client->active_blocks_request_count; ++i)
    {
        free(client->active_blocks_requests[i].roots);
    }
    free(client->active_blocks_requests);
    free(client->block_fetches);
    lantern_string_list_reset(&client->range_sync.failed_peers);
    if (status_locked)
    {
        pthread_mutex_unlock(&client->status_lock);
    }
    if (client->status_lock_initialized)
    {
        pthread_mutex_destroy(&client->status_lock);
    }
    if (client->validator_lock_initialized)
    {
        pthread_mutex_destroy(&client->validator_lock);
    }

    bool pending_locked = client->pending_lock_initialized
        && pthread_mutex_lock(&client->pending_lock) == 0;
    pending_block_list_reset(&client->pending_blocks);
    if (pending_locked)
    {
        pthread_mutex_unlock(&client->pending_lock);
    }
    if (client->pending_lock_initialized)
    {
        pthread_mutex_destroy(&client->pending_lock);
    }

    reset_genesis_paths(&client->genesis_paths);
    lantern_genesis_artifacts_reset(&client->genesis);
    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "shutdown: stopping request/response service");
    lantern_reqresp_service_reset(&client->reqresp);
    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "shutdown: request/response service stopped");
    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "shutdown: stopping gossipsub");
    lantern_gossipsub_service_stop(&client->gossip);
    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "shutdown: gossipsub stopped");
    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "shutdown: resetting libp2p host");
    lantern_libp2p_host_reset(&client->network);
    lantern_gossipsub_service_reset(&client->gossip);
    lantern_log_info(
        "client",
        &(const struct lantern_log_metadata){.validator = client->node_id},
        "shutdown: libp2p host reset");
    lantern_enr_record_reset(&client->local_enr);

    pending_vote_list_reset(&client->pending_gossip_votes);
    lantern_state_reset(&client->state);
    lantern_store_reset(&client->store);
    if (client->state_lock_initialized)
    {
        pthread_mutex_destroy(&client->state_lock);
    }
    lantern_client_reset_local_validators(client);
    lantern_string_list_reset(&client->bootnodes);
    lantern_storage_close(&client->storage);
    free(client->data_dir);
    free(client->node_id);
    free(client->listen_address);
    free(client->devnet);
    free(client->aggregate_subnet_ids);
    client_reset_base(client);
}
