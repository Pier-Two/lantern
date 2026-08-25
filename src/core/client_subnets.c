/**
 * @file client_subnets.c
 * @brief Attestation-subnet accessors and startup subnet collection
 *
 * @see client_internal.h for shared internal declarations
 */

#include "client_internal.h"

#include "lantern/consensus/containers.h"

#include <inttypes.h>
#include <stdint.h>

static const size_t LANTERN_DEFAULT_ATTESTATION_COMMITTEE_COUNT = 1u;

size_t lantern_client_attestation_committee_count(const struct lantern_client *client)
{
    if (!client)
    {
        return LANTERN_DEFAULT_ATTESTATION_COMMITTEE_COUNT;
    }
    if (client->debug_attestation_committee_count > 0)
    {
        return client->debug_attestation_committee_count;
    }
    if (client->genesis.chain_config.attestation_committee_count > 0)
    {
        return (size_t)client->genesis.chain_config.attestation_committee_count;
    }
    return LANTERN_DEFAULT_ATTESTATION_COMMITTEE_COUNT;
}

int lantern_client_aggregation_subnet_id(
    const struct lantern_client *client,
    size_t *out_subnet_id)
{
    if (!client || !out_subnet_id)
    {
        return -1;
    }

    const struct lantern_validator_config_entry *entry = client->assigned_validators;
    if (entry && entry->enr.is_aggregator && entry->has_subnet)
    {
        if (entry->subnet > (uint64_t)SIZE_MAX)
        {
            return -1;
        }
        *out_subnet_id = (size_t)entry->subnet;
        return 0;
    }

    if (client->local_validators && client->local_validator_count > 0)
    {
        return lantern_validator_index_compute_subnet_id(
            client->local_validators[0].global_index,
            lantern_client_attestation_committee_count(client),
            out_subnet_id);
    }
    if (entry && entry->indices_len > 0)
    {
        return lantern_validator_index_compute_subnet_id(
            entry->indices[0],
            lantern_client_attestation_committee_count(client),
            out_subnet_id);
    }
    *out_subnet_id = client->gossip.attestation_subnet_id;
    return 0;
}

static bool subnet_id_list_contains(
    const size_t *subnet_ids,
    size_t count,
    size_t subnet_id)
{
    for (size_t i = 0; i < count; ++i)
    {
        if (subnet_ids[i] == subnet_id)
        {
            return true;
        }
    }
    return false;
}

static int subnet_id_list_append_unique(
    size_t **subnet_ids,
    size_t *count,
    size_t subnet_id)
{
    if (!subnet_ids || !count)
    {
        return -1;
    }
    if (subnet_id_list_contains(*subnet_ids, *count, subnet_id))
    {
        return 0;
    }
    if (*count == SIZE_MAX || (*count + 1u) > SIZE_MAX / sizeof(**subnet_ids))
    {
        return -1;
    }
    size_t new_count = *count + 1u;
    size_t *next = realloc(*subnet_ids, new_count * sizeof(*next));
    if (!next)
    {
        return -1;
    }
    next[*count] = subnet_id;
    *subnet_ids = next;
    *count = new_count;
    return 0;
}

int collect_startup_attestation_subnets(
    const struct lantern_client *client,
    size_t attestation_committee_count,
    size_t primary_subnet_id,
    size_t **out_subnet_ids,
    size_t *out_count)
{
    if (!client || !out_subnet_ids || !out_count)
    {
        return -1;
    }
    *out_subnet_ids = NULL;
    *out_count = 0;

    if (subnet_id_list_append_unique(out_subnet_ids, out_count, primary_subnet_id) != 0)
    {
        return -1;
    }

    bool is_aggregator =
        client->assigned_validators && client->assigned_validators->enr.is_aggregator;
    if (is_aggregator)
    {
        for (size_t i = 0; i < client->aggregate_subnet_id_count; ++i)
        {
            if (subnet_id_list_append_unique(
                    out_subnet_ids,
                    out_count,
                    client->aggregate_subnet_ids[i])
                != 0)
            {
                return -1;
            }
        }
    }

    if (client->local_validators && client->local_validator_count > 0)
    {
        for (size_t i = 0; i < client->local_validator_count; ++i)
        {
            size_t validator_subnet_id = 0;
            if (lantern_validator_index_compute_subnet_id(
                    client->local_validators[i].global_index,
                    attestation_committee_count,
                    &validator_subnet_id)
                != 0)
            {
                return -1;
            }
            if (subnet_id_list_append_unique(out_subnet_ids, out_count, validator_subnet_id) != 0)
            {
                return -1;
            }
        }
    }

    return 0;
}

