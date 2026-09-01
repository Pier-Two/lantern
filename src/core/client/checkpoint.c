/**
 * @file checkpoint.c
 * @brief State loading and checkpoint sync handling
 *
 * @see internal.h for shared internal declarations
 */

#include "internal.h"

#include "lantern/consensus/containers.h"
#include "lantern/consensus/hash.h"
#include "lantern/consensus/ssz.h"
#include "lantern/consensus/state.h"
#include "lantern/http/client.h"
#include "lantern/storage/storage.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const size_t CHECKPOINT_SYNC_MAX_RESPONSE_BYTES =
    512u
    + (LANTERN_HISTORICAL_ROOTS_LIMIT * 32u)
    + (LANTERN_HISTORICAL_ROOTS_LIMIT / 8u)
    + (LANTERN_VALIDATOR_REGISTRY_LIMIT * 52u)
    + (LANTERN_HISTORICAL_ROOTS_LIMIT * 32u)
    + (LANTERN_JUSTIFICATION_VALIDATORS_LIMIT / 8u);
static const size_t CHECKPOINT_SYNC_MAX_BLOCK_RESPONSE_BYTES = 64u * 1024u * 1024u;
static const uint64_t LANTERN_CHECKPOINT_SYNC_STALE_PERSISTED_STATE_SLOT_THRESHOLD = 2u * 32u;
static const char CHECKPOINT_SYNC_FINALIZED_STATE_PATH[] = "/lean/v0/states/finalized";
static const char CHECKPOINT_SYNC_FINALIZED_BLOCK_PATH[] = "/lean/v0/blocks/finalized";

bool lantern_client_persisted_state_is_stale_for_checkpoint_sync(
    const LanternState *persisted_state,
    uint64_t genesis_time,
    uint64_t now_seconds,
    uint64_t *out_expected_current_slot,
    uint64_t *out_gap) {
    uint64_t expected_current_slot = 0u;
    uint64_t gap = 0u;

    if (out_expected_current_slot) {
        *out_expected_current_slot = 0u;
    }
    if (out_gap) {
        *out_gap = 0u;
    }
    if (!persisted_state) {
        return false;
    }

    if (now_seconds > genesis_time) {
        expected_current_slot = (now_seconds - genesis_time) / LANTERN_SECONDS_PER_SLOT;
    }
    if (expected_current_slot > persisted_state->slot) {
        gap = expected_current_slot - persisted_state->slot;
    }

    if (out_expected_current_slot) {
        *out_expected_current_slot = expected_current_slot;
    }
    if (out_gap) {
        *out_gap = gap;
    }

    return gap > LANTERN_CHECKPOINT_SYNC_STALE_PERSISTED_STATE_SLOT_THRESHOLD;
}

/**
 * @brief Attempt genesis creation using the embedded validator registry.
 *
 * Builds the initial state from validators included in the chain configuration.
 *
 * @param client  Client with loaded chain configuration
 *
 * @return true on success, false if pubkeys are missing or initialization fails
 *
 * @note Thread safety: Must run before concurrent access to the state.
 */
static bool client_try_genesis_from_pubkeys(struct lantern_client *client)
{
    if (!client->genesis.chain_config.validators
        || client->genesis.chain_config.validator_count == 0
        || client->genesis.chain_config.validator_count > SIZE_MAX)
    {
        return false;
    }

    size_t vcount = (size_t)client->genesis.chain_config.validator_count;
    if (lantern_state_generate_genesis(
            &client->state, client->genesis.chain_config.genesis_time, vcount)
        != 0)
    {
        return false;
    }

    memcpy(
        client->state.validators,
        client->genesis.chain_config.validators,
        vcount * sizeof(*client->state.validators));
    return true;
}

/* ============================================================================
 * Checkpoint Sync Helpers
 * ============================================================================ */
static char *checkpoint_sync_endpoint_url(const char *checkpoint_sync_url, const char *endpoint_path)
{
    if (!checkpoint_sync_url || checkpoint_sync_url[0] == '\0'
        || !endpoint_path || endpoint_path[0] != '/')
    {
        return NULL;
    }

    size_t url_len = strlen(checkpoint_sync_url);
    size_t endpoint_len = strlen(endpoint_path);
    while (url_len > 0u && checkpoint_sync_url[url_len - 1u] == '/')
    {
        --url_len;
    }

    const char *known_endpoints[] = {
        CHECKPOINT_SYNC_FINALIZED_STATE_PATH,
        CHECKPOINT_SYNC_FINALIZED_BLOCK_PATH,
    };

    for (size_t i = 0; i < sizeof(known_endpoints) / sizeof(known_endpoints[0]); ++i)
    {
        size_t known_len = strlen(known_endpoints[i]);
        if (url_len < known_len
            || strncmp(
                   checkpoint_sync_url + url_len - known_len,
                   known_endpoints[i],
                   known_len)
                   != 0)
        {
            continue;
        }
        url_len -= known_len;
        break;
    }

    size_t out_len = url_len + endpoint_len;
    char *out = malloc(out_len + 1u);
    if (!out)
    {
        return NULL;
    }
    memcpy(out, checkpoint_sync_url, url_len);
    memcpy(out + url_len, endpoint_path, endpoint_len);
    out[out_len] = '\0';
    return out;
}

static lantern_client_error client_fetch_checkpoint_bytes(
    struct lantern_client *client,
    const char *checkpoint_sync_url,
    const char *endpoint_path,
    size_t max_response_bytes,
    const char *label,
    struct lantern_http_fetch_result *out_result)
{
    if (!client || !checkpoint_sync_url || !endpoint_path || !label || !out_result)
    {
        return LANTERN_CLIENT_ERR_INVALID_PARAM;
    }
    memset(out_result, 0, sizeof(*out_result));
    char *url = checkpoint_sync_endpoint_url(checkpoint_sync_url, endpoint_path);
    if (!url)
    {
        return LANTERN_CLIENT_ERR_NETWORK;
    }

    struct lantern_log_metadata meta = {.validator = client->node_id};
    lantern_log_info("checkpoint_sync", &meta, "fetching finalized checkpoint %s from %s", label, url);
    int fetch_rc = lantern_http_get_bytes(
        url,
        "application/octet-stream",
        max_response_bytes,
        out_result);
    if (fetch_rc != 0)
    {
        if (fetch_rc == LANTERN_HTTP_CLIENT_STATUS_ERROR)
        {
            lantern_log_error(
                "checkpoint_sync",
                &meta,
                "checkpoint %s endpoint returned HTTP %d",
                label,
                out_result->status_code);
        }
        else
        {
            lantern_log_error("checkpoint_sync", &meta, "failed to fetch checkpoint %s", label);
        }
        lantern_http_fetch_result_reset(out_result);
        free(url);
        return LANTERN_CLIENT_ERR_NETWORK;
    }
    free(url);

    if (!out_result->body || out_result->body_len == 0)
    {
        lantern_http_fetch_result_reset(out_result);
        lantern_log_error("checkpoint_sync", &meta, "checkpoint %s endpoint returned no data", label);
        return LANTERN_CLIENT_ERR_NETWORK;
    }
    return LANTERN_CLIENT_OK;
}

static lantern_client_error client_fetch_checkpoint_anchor_block(
    struct lantern_client *client,
    const char *checkpoint_sync_url,
    LanternSignedBlock *out_block,
    LanternRoot *out_root)
{
    if (!client || !checkpoint_sync_url || !out_block || !out_root)
    {
        return LANTERN_CLIENT_ERR_INVALID_PARAM;
    }

    struct lantern_http_fetch_result fetch_result;
    lantern_client_error fetch_rc = client_fetch_checkpoint_bytes(
        client,
        checkpoint_sync_url,
        CHECKPOINT_SYNC_FINALIZED_BLOCK_PATH,
        CHECKPOINT_SYNC_MAX_BLOCK_RESPONSE_BYTES,
        "block",
        &fetch_result);
    if (fetch_rc != LANTERN_CLIENT_OK)
    {
        return fetch_rc;
    }

    struct lantern_log_metadata meta = {.validator = client->node_id};
    if (lantern_ssz_decode_signed_block(out_block, fetch_result.body, fetch_result.body_len)
        != SSZ_SUCCESS)
    {
        lantern_http_fetch_result_reset(&fetch_result);
        lantern_log_error(
            "checkpoint_sync",
            &meta,
            "failed to decode checkpoint block SSZ (bytes=%zu)",
            fetch_result.body_len);
        return LANTERN_CLIENT_ERR_GENESIS;
    }
    lantern_http_fetch_result_reset(&fetch_result);

    if (lantern_hash_tree_root_block(&out_block->block, out_root) != SSZ_SUCCESS)
    {
        lantern_log_error(
            "checkpoint_sync",
            &meta,
            "failed to compute checkpoint block root");
        return LANTERN_CLIENT_ERR_GENESIS;
    }

    return LANTERN_CLIENT_OK;
}

static bool checkpoint_anchor_block_matches_state_header(
    const LanternSignedBlock *anchor_block,
    const LanternState *state,
    const LanternRoot *state_root)
{
    if (!anchor_block || !state || !state_root)
    {
        return false;
    }

    const LanternBlockHeader *header = &state->latest_block_header;
    if (anchor_block->block.slot != header->slot
        || anchor_block->block.proposer_index != header->proposer_index
        || memcmp(
               anchor_block->block.parent_root.bytes,
               header->parent_root.bytes,
               LANTERN_ROOT_SIZE)
            != 0)
    {
        return false;
    }

    if (!lantern_root_is_zero(&header->state_root)
        && memcmp(header->state_root.bytes, state_root->bytes, LANTERN_ROOT_SIZE) != 0)
    {
        return false;
    }

    LanternRoot body_root;
    if (lantern_hash_tree_root_block_body(&anchor_block->block.body, &body_root) != SSZ_SUCCESS)
    {
        return false;
    }
    return memcmp(body_root.bytes, header->body_root.bytes, LANTERN_ROOT_SIZE) == 0;
}

int lantern_client_validate_state_validator_pubkeys(
    const struct lantern_client *client,
    const LanternState *state,
    const char *log_component)
{
    if (!client || !state)
    {
        return LANTERN_CLIENT_ERR_INVALID_PARAM;
    }

    const char *component =
        (log_component && log_component[0] != '\0') ? log_component : "client";
    const struct lantern_log_metadata meta = {.validator = client->node_id};
    const struct lantern_chain_config *config = &client->genesis.chain_config;
    if (!config->validators
        || config->validator_count == 0
        || config->validator_count > SIZE_MAX)
    {
        lantern_log_error(
            component,
            &meta,
            "local genesis validator pubkeys unavailable for state validation");
        return LANTERN_CLIENT_ERR_GENESIS;
    }

    size_t expected_count = (size_t)config->validator_count;
    if (!state->validators
        || state->validator_count != expected_count)
    {
        lantern_log_error(
            component,
            &meta,
            "state validator count mismatch state=%zu local=%zu",
            state->validator_count,
            expected_count);
        return LANTERN_CLIENT_ERR_GENESIS;
    }

    if (memcmp(
            state->validators,
            config->validators,
            expected_count * sizeof(*state->validators))
        != 0)
    {
        lantern_log_error(component, &meta, "state validator registry mismatch");
        return LANTERN_CLIENT_ERR_GENESIS;
    }

    return LANTERN_CLIENT_OK;
}

static lantern_client_error client_load_state_from_checkpoint(
    struct lantern_client *client,
    const char *checkpoint_sync_url)
{
    if (!client || !checkpoint_sync_url || checkpoint_sync_url[0] == '\0')
    {
        return LANTERN_CLIENT_ERR_INVALID_PARAM;
    }

    struct lantern_log_metadata meta = {.validator = client->node_id};
    LanternSignedBlock anchor_signed_block;
    lantern_signed_block_init(&anchor_signed_block);
    LanternRoot anchor_root = {0};
    lantern_client_error block_rc = client_fetch_checkpoint_anchor_block(
        client,
        checkpoint_sync_url,
        &anchor_signed_block,
        &anchor_root);
    if (block_rc != LANTERN_CLIENT_OK)
    {
        lantern_signed_block_reset(&anchor_signed_block);
        return block_rc;
    }

    struct lantern_http_fetch_result fetch_result;
    lantern_client_error fetch_rc = client_fetch_checkpoint_bytes(
        client,
        checkpoint_sync_url,
        CHECKPOINT_SYNC_FINALIZED_STATE_PATH,
        CHECKPOINT_SYNC_MAX_RESPONSE_BYTES,
        "state",
        &fetch_result);
    if (fetch_rc != LANTERN_CLIENT_OK)
    {
        lantern_signed_block_reset(&anchor_signed_block);
        return fetch_rc;
    }

    LanternState decoded;
    lantern_state_init(&decoded);
    lantern_client_error result = LANTERN_CLIENT_OK;

    if (lantern_ssz_decode_state(&decoded, fetch_result.body, fetch_result.body_len) != SSZ_SUCCESS)
    {
        lantern_log_error(
            "checkpoint_sync",
            &meta,
            "failed to decode checkpoint state SSZ (bytes=%zu)",
            fetch_result.body_len);
        result = LANTERN_CLIENT_ERR_GENESIS;
        goto cleanup;
    }

    if (decoded.validator_count == 0)
    {
        lantern_log_error(
            "checkpoint_sync",
            &meta,
            "checkpoint state validator metadata invalid decoded=%zu",
            decoded.validator_count);
        result = LANTERN_CLIENT_ERR_GENESIS;
        goto cleanup;
    }

    if (decoded.config.genesis_time != client->genesis.chain_config.genesis_time)
    {
        lantern_log_error(
            "checkpoint_sync",
            &meta,
            "checkpoint genesis time mismatch checkpoint=%" PRIu64 " local=%" PRIu64,
            decoded.config.genesis_time,
            client->genesis.chain_config.genesis_time);
        result = LANTERN_CLIENT_ERR_GENESIS;
        goto cleanup;
    }

    if (decoded.latest_block_header.slot > decoded.slot
        || decoded.latest_justified.slot > decoded.slot
        || decoded.latest_finalized.slot > decoded.slot
        || decoded.latest_finalized.slot > decoded.latest_justified.slot)
    {
        lantern_log_error(
            "checkpoint_sync",
            &meta,
            "checkpoint state has inconsistent slot metadata state=%" PRIu64
            " head=%" PRIu64 " justified=%" PRIu64 " finalized=%" PRIu64,
            decoded.slot,
            decoded.latest_block_header.slot,
            decoded.latest_justified.slot,
            decoded.latest_finalized.slot);
        result = LANTERN_CLIENT_ERR_GENESIS;
        goto cleanup;
    }

    int pubkey_rc = lantern_client_validate_state_validator_pubkeys(
        client,
        &decoded,
        "checkpoint_sync");
    if (pubkey_rc != LANTERN_CLIENT_OK)
    {
        result = pubkey_rc;
        goto cleanup;
    }

    LanternRoot state_root;
    if (lantern_hash_tree_root_state(&decoded, &state_root) != SSZ_SUCCESS)
    {
        lantern_log_error(
            "checkpoint_sync",
            &meta,
            "failed to compute checkpoint state root");
        result = LANTERN_CLIENT_ERR_GENESIS;
        goto cleanup;
    }

    if (memcmp(anchor_signed_block.block.state_root.bytes, state_root.bytes, LANTERN_ROOT_SIZE) != 0)
    {
        char block_state_root_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
        char state_root_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
        format_root_hex(
            &anchor_signed_block.block.state_root,
            block_state_root_hex,
            sizeof(block_state_root_hex));
        format_root_hex(&state_root, state_root_hex, sizeof(state_root_hex));
        lantern_log_error(
            "checkpoint_sync",
            &meta,
            "checkpoint anchor block/state mismatch block_state_root=%s state_root=%s",
            block_state_root_hex[0] ? block_state_root_hex : "0x0",
            state_root_hex[0] ? state_root_hex : "0x0");
        result = LANTERN_CLIENT_ERR_GENESIS;
        goto cleanup;
    }

    if (!checkpoint_anchor_block_matches_state_header(&anchor_signed_block, &decoded, &state_root))
    {
        lantern_log_error(
            "checkpoint_sync",
            &meta,
            "checkpoint anchor block/header mismatch");
        result = LANTERN_CLIENT_ERR_GENESIS;
        goto cleanup;
    }

    char state_root_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
    char anchor_root_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
    format_root_hex(&state_root, state_root_hex, sizeof(state_root_hex));
    format_root_hex(&anchor_root, anchor_root_hex, sizeof(anchor_root_hex));

    if (!client->data_dir)
    {
        lantern_log_error(
            "storage",
            &meta,
            "checkpoint sync requires a data directory for the anchor block");
        result = LANTERN_CLIENT_ERR_STORAGE;
        goto cleanup;
    }
    if (lantern_storage_store_block_for_root(
            &client->storage,
            &anchor_root,
            &anchor_signed_block)
        != 0)
    {
        lantern_log_error(
            "storage",
            &meta,
            "failed to persist checkpoint anchor block");
        result = LANTERN_CLIENT_ERR_STORAGE;
        goto cleanup;
    }
    if (lantern_storage_store_state_for_root(
            &client->storage,
            &anchor_root,
            &decoded)
        != 0)
    {
        lantern_log_error(
            "storage",
            &meta,
            "failed to persist checkpoint anchor state alias");
        result = LANTERN_CLIENT_ERR_STORAGE;
        goto cleanup;
    }

    lantern_state_reset(&client->state);
    client->state = decoded;
    decoded = (LanternState){0};
    lantern_log_info(
        "checkpoint_sync",
        &meta,
        "initialized from checkpoint state slot=%" PRIu64
        " validators=%" PRIu64 " finalized_slot=%" PRIu64 " state_root=%s"
        " anchor_root=%s",
        client->state.slot,
        (uint64_t)client->state.validator_count,
        client->state.latest_finalized.slot,
        state_root_hex[0] ? state_root_hex : "0x0",
        anchor_root_hex[0] ? anchor_root_hex : "0x0");

cleanup:
    lantern_http_fetch_result_reset(&fetch_result);
    lantern_signed_block_reset(&anchor_signed_block);
    lantern_state_reset(&decoded);
    return result;
}

/**
 * @brief Build genesis state using the available artifact priority order.
 *
 * Builds the state from the canonical validator keypairs in the chain config.
 *
 * @param client  Client being initialized
 *
 * @return LANTERN_CLIENT_OK on success
 * @return LANTERN_CLIENT_ERR_GENESIS when all strategies fail
 *
 * @note Thread safety: Single-threaded initialization only.
 */
static lantern_client_error client_generate_state_from_genesis(struct lantern_client *client)
{
    if (!client_try_genesis_from_pubkeys(client))
    {
        return LANTERN_CLIENT_ERR_GENESIS;
    }
    return LANTERN_CLIENT_OK;
}

/**
 * @brief Load persisted state, checkpoint state, or construct a genesis state.
 *
 * Reuses fresh persisted state when available. If checkpoint sync is configured
 * and no reusable state exists, checkpoint sync must succeed; genesis bootstrap
 * is only used when checkpoint sync is not configured.
 *
 * @param client               Client whose state is being initialized
 * @param options              Client options (checkpoint sync URL, etc.)
 * @param loaded_from_storage  Optional output flag indicating storage load
 *
 * @return LANTERN_CLIENT_OK on success
 * @return LANTERN_CLIENT_ERR_STORAGE on storage I/O failure
 * @return LANTERN_CLIENT_ERR_GENESIS on genesis construction failure
 * @return negative lantern_client_error when checkpoint sync fails
 *
 * @note Thread safety: Must be called before any concurrent access.
 */
lantern_client_error client_load_or_build_state(
    struct lantern_client *client,
    const struct lantern_client_options *options,
    bool *loaded_from_storage)
{
    const bool checkpoint_sync_configured =
        options
        && options->checkpoint_sync_url
        && options->checkpoint_sync_url[0] != '\0';
    const struct lantern_log_metadata meta = {.validator = client ? client->node_id : NULL};
    bool from_storage = false;
    bool should_attempt_checkpoint_sync = false;
    int storage_state_rc = lantern_storage_load_state(&client->storage, &client->state);
    if (storage_state_rc == 0)
    {
        from_storage = true;
        if (checkpoint_sync_configured)
        {
            uint64_t expected_current_slot = 0u;
            uint64_t gap = 0u;
            time_t now_time = time(NULL);
            if (now_time != (time_t)-1
                && lantern_client_persisted_state_is_stale_for_checkpoint_sync(
                    &client->state,
                    client->genesis.chain_config.genesis_time,
                    (uint64_t)now_time,
                    &expected_current_slot,
                    &gap))
            {
                lantern_log_info(
                    "checkpoint_sync",
                    &meta,
                    "persisted state stale slot=%" PRIu64
                    " expected_current_slot=%" PRIu64
                    " gap=%" PRIu64
                    " threshold=%" PRIu64
                    "; discarding state and using checkpoint sync",
                    client->state.slot,
                    expected_current_slot,
                    gap,
                    LANTERN_CHECKPOINT_SYNC_STALE_PERSISTED_STATE_SLOT_THRESHOLD);
                lantern_state_reset(&client->state);
                from_storage = false;
                should_attempt_checkpoint_sync = true;
            }
            else
            {
                lantern_log_info(
                    "checkpoint_sync",
                    &meta,
                    "using persisted state; skipping checkpoint fetch");
            }
        }
    }
    else if (storage_state_rc < 0)
    {
        lantern_log_error(
            "storage",
            &meta,
            "failed to load persisted state");
        return LANTERN_CLIENT_ERR_STORAGE;
    }
    else
    {
        should_attempt_checkpoint_sync = checkpoint_sync_configured;
    }

    if (client->state.validator_count == 0u)
    {
        if (should_attempt_checkpoint_sync)
        {
            lantern_client_error checkpoint_rc = client_load_state_from_checkpoint(
                client,
                options->checkpoint_sync_url);
            if (checkpoint_rc != LANTERN_CLIENT_OK)
            {
                lantern_log_error(
                    "checkpoint_sync",
                    &meta,
                    "checkpoint sync failed; aborting startup");
                return checkpoint_rc;
            }
        }
        else if (client_generate_state_from_genesis(client) != LANTERN_CLIENT_OK)
        {
            return LANTERN_CLIENT_ERR_GENESIS;
        }
    }

    if (client->state.validator_count > 0u)
    {
        if (initialize_fork_choice(client) != 0)
        {
            return LANTERN_CLIENT_ERR_GENESIS;
        }
        if (restore_persisted_blocks(client) != 0)
        {
            return LANTERN_CLIENT_ERR_STORAGE;
        }
    }

    if (client->state.validator_count > 0u && !from_storage)
    {
        if (lantern_storage_save_state(&client->storage, &client->state) != 0)
        {
            lantern_log_warn(
                "storage",
                &(const struct lantern_log_metadata){.validator = client->node_id},
                "failed to persist initial state snapshot");
        }
    }

    if (loaded_from_storage)
    {
        *loaded_from_storage = from_storage;
    }
    return client->state.validator_count > 0u ? LANTERN_CLIENT_OK : LANTERN_CLIENT_ERR_GENESIS;
}

