#include "lantern/consensus/hash.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ssz_constants.h"
#include "ssz_merkle.h"
#include "ssz_utils.h"
#include "mincrypt/sha256.h"
#include "lantern/support/strings.h"

static void chunk_from_uint64(uint64_t value, uint8_t out[SSZ_BYTES_PER_CHUNK]) {
    memset(out, 0, SSZ_BYTES_PER_CHUNK);
    out[0] = (uint8_t)(value & 0xFFu);
    out[1] = (uint8_t)((value >> 8) & 0xFFu);
    out[2] = (uint8_t)((value >> 16) & 0xFFu);
    out[3] = (uint8_t)((value >> 24) & 0xFFu);
    out[4] = (uint8_t)((value >> 32) & 0xFFu);
    out[5] = (uint8_t)((value >> 40) & 0xFFu);
    out[6] = (uint8_t)((value >> 48) & 0xFFu);
    out[7] = (uint8_t)((value >> 56) & 0xFFu);
}

static int merkleize_chunks(
    const uint8_t *chunks,
    size_t chunk_count,
    size_t limit,
    LanternRoot *out_root) {
    if (!out_root) {
        return -1;
    }
    uint8_t temp_root[SSZ_BYTES_PER_CHUNK];
    ssz_error_t err = ssz_merkleize(chunks, chunk_count, limit, temp_root);
    if (err != SSZ_SUCCESS) {
        return -1;
    }
    memcpy(out_root->bytes, temp_root, SSZ_BYTES_PER_CHUNK);
    return 0;
}

static int hash_byte_vector(const uint8_t *bytes, size_t length, LanternRoot *out_root) {
    if (!out_root) {
        return -1;
    }
    size_t chunk_count = (length + SSZ_BYTES_PER_CHUNK - 1u) / SSZ_BYTES_PER_CHUNK;
    if (chunk_count == 0) {
        chunk_count = 1;
    }
    size_t total_bytes = chunk_count * SSZ_BYTES_PER_CHUNK;
    uint8_t *chunks = calloc(chunk_count, SSZ_BYTES_PER_CHUNK);
    if (!chunks) {
        return -1;
    }
    if (bytes && length > 0) {
        memcpy(chunks, bytes, length);
    }
    int result = merkleize_chunks(chunks, chunk_count, 0, out_root);
    free(chunks);
    return result;
}

static int hash_validator(const uint8_t *pubkey, LanternRoot *out_root) {
    if (!out_root) {
        return -1;
    }
    LanternRoot pubkey_root;
    if (hash_byte_vector(pubkey, LANTERN_VALIDATOR_PUBKEY_SIZE, &pubkey_root) != 0) {
        return -1;
    }
    uint8_t chunk[SSZ_BYTES_PER_CHUNK];
    memcpy(chunk, pubkey_root.bytes, SSZ_BYTES_PER_CHUNK);
    return merkleize_chunks(chunk, 1, 0, out_root);
}

static const uint8_t HISTORICAL_ROOTS_EMPTY[LANTERN_ROOT_SIZE] = {
    0xe7, 0x99, 0x0d, 0x74, 0xa7, 0xbd, 0x8d, 0x59,
    0xa8, 0x03, 0x6f, 0xbd, 0xde, 0x31, 0x96, 0xe3,
    0x21, 0x8f, 0xdd, 0x34, 0x7d, 0x52, 0x01, 0x44,
    0xa9, 0x7a, 0x9a, 0x26, 0x82, 0x02, 0xec, 0x4b};

static const uint8_t JUSTIFIED_SLOTS_EMPTY[LANTERN_ROOT_SIZE] = {
    0xce, 0xb3, 0x26, 0x6b, 0xf0, 0x93, 0x8b, 0xc7,
    0x2f, 0x82, 0x56, 0x35, 0x6d, 0xdc, 0x13, 0xbc,
    0xcc, 0x20, 0xdd, 0x76, 0x7f, 0x25, 0x44, 0x8b,
    0x26, 0x58, 0x13, 0x57, 0x80, 0xb7, 0xda, 0x51};

static const uint8_t JUSTIFICATION_VALIDATORS_EMPTY[LANTERN_ROOT_SIZE] = {
    0xbd, 0xf2, 0xa1, 0xa5, 0xe9, 0x51, 0x13, 0x6f,
    0x58, 0x43, 0xed, 0xa2, 0x47, 0xb5, 0x7d, 0xae,
    0x78, 0xc2, 0x11, 0x39, 0x9c, 0xff, 0xf5, 0xf1,
    0xaa, 0x2d, 0x52, 0x56, 0x1d, 0x46, 0x9c, 0x68};

static int zero_merkle_root(size_t chunk_limit, LanternRoot *out_root) {
    if (!out_root) {
        return -1;
    }
    uint64_t effective = chunk_limit;
    if (effective == 0) {
        memset(out_root->bytes, 0, LANTERN_ROOT_SIZE);
        return 0;
    }
    uint64_t padded = next_pow_of_two(effective);
    if (padded == 0) {
        return -1;
    }
    LanternRoot current;
    memset(current.bytes, 0, LANTERN_ROOT_SIZE);
    uint8_t buffer[SSZ_BYTES_PER_CHUNK * 2u];
    uint64_t depth = 0;
    while (((uint64_t)1 << depth) < padded) {
        memcpy(buffer, current.bytes, SSZ_BYTES_PER_CHUNK);
        memcpy(buffer + SSZ_BYTES_PER_CHUNK, current.bytes, SSZ_BYTES_PER_CHUNK);
        SHA256_hash(buffer, sizeof(buffer), current.bytes);
        ++depth;
    }
    *out_root = current;
    return 0;
}

static int hash_empty_list_root(size_t element_limit, LanternRoot *out_root) {
    if (!out_root) {
        return -1;
    }
    if (element_limit == LANTERN_HISTORICAL_ROOTS_LIMIT) {
        memcpy(out_root->bytes, HISTORICAL_ROOTS_EMPTY, LANTERN_ROOT_SIZE);
        return 0;
    }
    LanternRoot zero_root;
    size_t limit = element_limit ? element_limit : 1u;
    if (zero_merkle_root(limit, &zero_root) != 0) {
        return -1;
    }
    return ssz_mix_in_length(zero_root.bytes, 0, out_root->bytes) == SSZ_SUCCESS ? 0 : -1;
}

static int hash_empty_bitlist_root(size_t bit_limit, LanternRoot *out_root) {
    if (!out_root) {
        return -1;
    }
    size_t bits_per_chunk = SSZ_BYTES_PER_CHUNK * 8u;
    size_t chunk_limit = bit_limit ? ((bit_limit + bits_per_chunk - 1u) / bits_per_chunk) : 1u;
    if (bit_limit == LANTERN_HISTORICAL_ROOTS_LIMIT) {
        memcpy(out_root->bytes, JUSTIFIED_SLOTS_EMPTY, LANTERN_ROOT_SIZE);
        return 0;
    }
    if (bit_limit == LANTERN_JUSTIFICATION_VALIDATORS_LIMIT) {
        memcpy(out_root->bytes, JUSTIFICATION_VALIDATORS_EMPTY, LANTERN_ROOT_SIZE);
        return 0;
    }
    LanternRoot zero_root;
    if (zero_merkle_root(chunk_limit, &zero_root) != 0) {
        return -1;
    }
    return ssz_mix_in_length(zero_root.bytes, 0, out_root->bytes) == SSZ_SUCCESS ? 0 : -1;
}

int lantern_hash_tree_root_config(const LanternConfig *config, LanternRoot *out_root) {
    if (!config || !out_root) {
        return -1;
    }
    uint8_t chunks[1][SSZ_BYTES_PER_CHUNK];
    chunk_from_uint64(config->genesis_time, chunks[0]);
    return merkleize_chunks(&chunks[0][0], 1, 0, out_root);
}

int lantern_hash_tree_root_checkpoint(const LanternCheckpoint *checkpoint, LanternRoot *out_root) {
    if (!checkpoint || !out_root) {
        return -1;
    }
    uint8_t chunks[2][SSZ_BYTES_PER_CHUNK];
    memcpy(chunks[0], checkpoint->root.bytes, SSZ_BYTES_PER_CHUNK);
    chunk_from_uint64(checkpoint->slot, chunks[1]);
    return merkleize_chunks(&chunks[0][0], 2, 0, out_root);
}

int lantern_hash_tree_root_vote(const LanternVote *vote, LanternRoot *out_root) {
    if (!vote || !out_root) {
        return -1;
    }
    LanternRoot head_root;
    LanternRoot target_root;
    LanternRoot source_root;
    if (lantern_hash_tree_root_checkpoint(&vote->head, &head_root) != 0) {
        return -1;
    }
    if (lantern_hash_tree_root_checkpoint(&vote->target, &target_root) != 0) {
        return -1;
    }
    if (lantern_hash_tree_root_checkpoint(&vote->source, &source_root) != 0) {
        return -1;
    }
    uint8_t data_chunks[4][SSZ_BYTES_PER_CHUNK];
    chunk_from_uint64(vote->slot, data_chunks[0]);
    memcpy(data_chunks[1], head_root.bytes, SSZ_BYTES_PER_CHUNK);
    memcpy(data_chunks[2], target_root.bytes, SSZ_BYTES_PER_CHUNK);
    memcpy(data_chunks[3], source_root.bytes, SSZ_BYTES_PER_CHUNK);
    LanternRoot data_root;
    if (merkleize_chunks(&data_chunks[0][0], 4, 0, &data_root) != 0) {
        return -1;
    }
    uint8_t chunks[2][SSZ_BYTES_PER_CHUNK];
    chunk_from_uint64(vote->validator_id, chunks[0]);
    memcpy(chunks[1], data_root.bytes, SSZ_BYTES_PER_CHUNK);
    return merkleize_chunks(&chunks[0][0], 2, 0, out_root);
}

int lantern_hash_tree_root_signed_vote(const LanternSignedVote *vote, LanternRoot *out_root) {
    if (!vote || !out_root) {
        return -1;
    }
    LanternRoot vote_root;
    if (lantern_hash_tree_root_vote(&vote->data, &vote_root) != 0) {
        return -1;
    }
    uint8_t chunks[2][SSZ_BYTES_PER_CHUNK];
    memcpy(chunks[0], vote_root.bytes, SSZ_BYTES_PER_CHUNK);
    memcpy(chunks[1], vote->signature.bytes, SSZ_BYTES_PER_CHUNK);
    return merkleize_chunks(&chunks[0][0], 2, 0, out_root);
}

int lantern_merkleize_root_list(
    const struct lantern_root_list *list,
    size_t limit,
    LanternRoot *out_root) {
    if (!list || !out_root) {
        return -1;
    }
    size_t count = list->length;
    uint8_t temp_root[SSZ_BYTES_PER_CHUNK];
    uint8_t *chunk_bytes = NULL;
    if (count > 0) {
        if (!list->items) {
            return -1;
        }
        if (count > SIZE_MAX / SSZ_BYTES_PER_CHUNK) {
            return -1;
        }
        size_t total_bytes = count * SSZ_BYTES_PER_CHUNK;
        chunk_bytes = malloc(total_bytes);
        if (!chunk_bytes) {
            return -1;
        }
        for (size_t i = 0; i < count; ++i) {
            memcpy(chunk_bytes + (i * SSZ_BYTES_PER_CHUNK), list->items[i].bytes, SSZ_BYTES_PER_CHUNK);
        }
    }
    ssz_error_t err = ssz_merkleize(chunk_bytes, count, limit, temp_root);
    if (chunk_bytes) {
        free(chunk_bytes);
    }
    if (err != SSZ_SUCCESS) {
        return -1;
    }
    err = ssz_mix_in_length(temp_root, (uint64_t)count, out_root->bytes);
    return err == SSZ_SUCCESS ? 0 : -1;
}

int lantern_merkleize_bitlist(
    const struct lantern_bitlist *bitlist,
    size_t limit,
    LanternRoot *out_root) {
    if (!bitlist || !out_root) {
        return -1;
    }
    size_t bit_count = bitlist->bit_length;
    bool *bits = NULL;
    if (bit_count > 0) {
        if (!bitlist->bytes) {
            return -1;
        }
        bits = calloc(bit_count, sizeof(*bits));
        if (!bits) {
            return -1;
        }
        for (size_t i = 0; i < bit_count; ++i) {
            size_t byte_index = i / 8u;
            size_t bit_index = i % 8u;
            if (byte_index < bitlist->capacity) {
                bits[i] = (bitlist->bytes[byte_index] >> bit_index) & 1u;
            }
        }
    }

    size_t bitfield_len = bit_count ? ((bit_count + 7u) / 8u) : 1u;
    size_t max_chunks = (bitfield_len + SSZ_BYTES_PER_CHUNK - 1u) / SSZ_BYTES_PER_CHUNK;
    if (max_chunks == 0) {
        max_chunks = 1;
    }
    uint8_t *packed = calloc(max_chunks, SSZ_BYTES_PER_CHUNK);
    if (!packed) {
        free(bits);
        return -1;
    }
    size_t chunk_count = 0;
    ssz_error_t err = ssz_pack_bits(bits, bit_count, packed, &chunk_count);
    free(bits);
    if (err != SSZ_SUCCESS) {
        free(packed);
        return -1;
    }
    uint8_t temp_root[SSZ_BYTES_PER_CHUNK];
    err = ssz_merkleize(packed, chunk_count, limit, temp_root);
    free(packed);
    if (err != SSZ_SUCCESS) {
        return -1;
    }
    err = ssz_mix_in_length(temp_root, (uint64_t)bit_count, out_root->bytes);
    return err == SSZ_SUCCESS ? 0 : -1;
}

static int hash_attestations(const LanternAttestations *attestations, LanternRoot *out_root) {
    if (!attestations || !out_root) {
        return -1;
    }
    size_t count = attestations->length;
    uint8_t *chunks = NULL;
    if (count > 0) {
        if (!attestations->data) {
            return -1;
        }
        if (count > LANTERN_MAX_ATTESTATIONS) {
            return -1;
        }
        if (count > SIZE_MAX / SSZ_BYTES_PER_CHUNK) {
            return -1;
        }
        size_t total_bytes = count * SSZ_BYTES_PER_CHUNK;
        chunks = malloc(total_bytes);
        if (!chunks) {
            return -1;
        }
        for (size_t i = 0; i < count; ++i) {
            LanternRoot vote_root;
            if (lantern_hash_tree_root_vote(&attestations->data[i].data, &vote_root) != 0) {
                free(chunks);
                return -1;
            }
            memcpy(chunks + (i * SSZ_BYTES_PER_CHUNK), vote_root.bytes, SSZ_BYTES_PER_CHUNK);
        }
    }
    uint8_t temp_root[SSZ_BYTES_PER_CHUNK];
    memset(temp_root, 0, sizeof(temp_root));
    ssz_error_t err = ssz_merkleize(chunks, attestations->length, LANTERN_MAX_ATTESTATIONS, temp_root);
    if (chunks) {
        free(chunks);
    }
    if (err != SSZ_SUCCESS) {
        return -1;
    }
    err = ssz_mix_in_length(temp_root, (uint64_t)attestations->length, out_root->bytes);
    return err == SSZ_SUCCESS ? 0 : -1;
}

int lantern_hash_tree_root_block_body(const LanternBlockBody *body, LanternRoot *out_root) {
    if (!body || !out_root) {
        return -1;
    }
    LanternRoot att_root;
    if (hash_attestations(&body->attestations, &att_root) != 0) {
        return -1;
    }
    uint8_t chunks[1][SSZ_BYTES_PER_CHUNK];
    memcpy(chunks[0], att_root.bytes, SSZ_BYTES_PER_CHUNK);
    return merkleize_chunks(&chunks[0][0], 1, 0, out_root);
}

int lantern_hash_tree_root_block_header(const LanternBlockHeader *header, LanternRoot *out_root) {
    if (!header || !out_root) {
        return -1;
    }
    uint8_t chunks[5][SSZ_BYTES_PER_CHUNK];
    chunk_from_uint64(header->slot, chunks[0]);
    chunk_from_uint64(header->proposer_index, chunks[1]);
    memcpy(chunks[2], header->parent_root.bytes, SSZ_BYTES_PER_CHUNK);
    memcpy(chunks[3], header->state_root.bytes, SSZ_BYTES_PER_CHUNK);
    memcpy(chunks[4], header->body_root.bytes, SSZ_BYTES_PER_CHUNK);
    return merkleize_chunks(&chunks[0][0], 5, 0, out_root);
}

int lantern_hash_tree_root_block(const LanternBlock *block, LanternRoot *out_root) {
    if (!block || !out_root) {
        return -1;
    }
    LanternRoot body_root;
    if (lantern_hash_tree_root_block_body(&block->body, &body_root) != 0) {
        return -1;
    }
    uint8_t chunks[5][SSZ_BYTES_PER_CHUNK];
    chunk_from_uint64(block->slot, chunks[0]);
    chunk_from_uint64(block->proposer_index, chunks[1]);
    memcpy(chunks[2], block->parent_root.bytes, SSZ_BYTES_PER_CHUNK);
    memcpy(chunks[3], block->state_root.bytes, SSZ_BYTES_PER_CHUNK);
    memcpy(chunks[4], body_root.bytes, SSZ_BYTES_PER_CHUNK);
    return merkleize_chunks(&chunks[0][0], 5, 0, out_root);
}

int lantern_hash_tree_root_signed_block(const LanternSignedBlock *block, LanternRoot *out_root) {
    if (!block || !out_root) {
        return -1;
    }
    LanternRoot block_root;
    if (lantern_hash_tree_root_block(&block->message, &block_root) != 0) {
        return -1;
    }
    uint8_t chunks[2][SSZ_BYTES_PER_CHUNK];
    memcpy(chunks[0], block_root.bytes, SSZ_BYTES_PER_CHUNK);
    memcpy(chunks[1], block->signature.bytes, SSZ_BYTES_PER_CHUNK);
    return merkleize_chunks(&chunks[0][0], 2, 0, out_root);
}

int lantern_hash_tree_root_state(const LanternState *state, LanternRoot *out_root) {
    if (!state || !out_root) {
        return -1;
    }

    LanternRoot config_root;
    LanternRoot header_root;
    LanternRoot justified_root;
    LanternRoot finalized_root;
    LanternRoot historical_root;
    LanternRoot justified_slots_root;
    LanternRoot justification_roots_root;
    LanternRoot justification_validators_root;

    if (lantern_hash_tree_root_config(&state->config, &config_root) != 0) {
        return -1;
    }
    LanternBlockHeader header_copy = state->latest_block_header;
    memset(header_copy.state_root.bytes, 0, sizeof(header_copy.state_root.bytes));
    if (lantern_hash_tree_root_block_header(&header_copy, &header_root) != 0) {
        return -1;
    }
    if (lantern_hash_tree_root_checkpoint(&state->latest_justified, &justified_root) != 0) {
        return -1;
    }
    if (lantern_hash_tree_root_checkpoint(&state->latest_finalized, &finalized_root) != 0) {
        return -1;
    }
    if (state->historical_block_hashes.length == 0) {
        if (hash_empty_list_root(LANTERN_HISTORICAL_ROOTS_LIMIT, &historical_root) != 0) {
            return -1;
        }
    } else if (lantern_merkleize_root_list(&state->historical_block_hashes, LANTERN_HISTORICAL_ROOTS_LIMIT, &historical_root) != 0) {
        return -1;
    }
    size_t bits_per_chunk = SSZ_BYTES_PER_CHUNK * 8u;
    size_t justified_chunk_limit = (LANTERN_HISTORICAL_ROOTS_LIMIT + bits_per_chunk - 1u) / bits_per_chunk;
    if (state->justified_slots.bit_length == 0) {
        if (hash_empty_bitlist_root(LANTERN_HISTORICAL_ROOTS_LIMIT, &justified_slots_root) != 0) {
            return -1;
        }
    } else if (lantern_merkleize_bitlist(&state->justified_slots, justified_chunk_limit, &justified_slots_root) != 0) {
        return -1;
    }
    if (state->justification_roots.length == 0) {
        if (hash_empty_list_root(LANTERN_HISTORICAL_ROOTS_LIMIT, &justification_roots_root) != 0) {
            return -1;
        }
    } else if (lantern_merkleize_root_list(&state->justification_roots, LANTERN_HISTORICAL_ROOTS_LIMIT, &justification_roots_root) != 0) {
        return -1;
    }
    size_t justification_validators_chunk_limit =
        (LANTERN_JUSTIFICATION_VALIDATORS_LIMIT + bits_per_chunk - 1u) / bits_per_chunk;
    if (state->justification_validators.bit_length == 0) {
        if (hash_empty_bitlist_root(LANTERN_JUSTIFICATION_VALIDATORS_LIMIT, &justification_validators_root) != 0) {
            return -1;
        }
    } else if (
        lantern_merkleize_bitlist(&state->justification_validators, justification_validators_chunk_limit, &justification_validators_root)
        != 0) {
        return -1;
    }

    const char *debug_hash = getenv("LANTERN_DEBUG_STATE_HASH");
    if (debug_hash && debug_hash[0] != '\0') {
        char debug_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
        if (lantern_bytes_to_hex(config_root.bytes, LANTERN_ROOT_SIZE, debug_hex, sizeof(debug_hex), 1) == 0) {
            fprintf(stderr, "hash state slot %llu config root: %s\n", (unsigned long long)state->slot, debug_hex);
        }
        if (lantern_bytes_to_hex(header_root.bytes, LANTERN_ROOT_SIZE, debug_hex, sizeof(debug_hex), 1) == 0) {
            fprintf(stderr, "hash state slot %llu header root: %s\n", (unsigned long long)state->slot, debug_hex);
            char header_parent_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
            char header_state_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
            char header_body_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
            if (lantern_bytes_to_hex(
                    state->latest_block_header.parent_root.bytes,
                    LANTERN_ROOT_SIZE,
                    header_parent_hex,
                    sizeof(header_parent_hex),
                    1)
                == 0
                && lantern_bytes_to_hex(
                       state->latest_block_header.state_root.bytes,
                       LANTERN_ROOT_SIZE,
                       header_state_hex,
                       sizeof(header_state_hex),
                       1)
                    == 0
                && lantern_bytes_to_hex(
                       state->latest_block_header.body_root.bytes,
                       LANTERN_ROOT_SIZE,
                       header_body_hex,
                       sizeof(header_body_hex),
                       1)
                    == 0) {
                fprintf(
                    stderr,
                    "header fields parent=%s state=%s body=%s\n",
                    header_parent_hex,
                    header_state_hex,
                    header_body_hex);
            }
        }
        if (lantern_bytes_to_hex(justified_root.bytes, LANTERN_ROOT_SIZE, debug_hex, sizeof(debug_hex), 1) == 0) {
            fprintf(stderr, "hash state slot %llu justified root: %s\n", (unsigned long long)state->slot, debug_hex);
        }
        if (lantern_bytes_to_hex(finalized_root.bytes, LANTERN_ROOT_SIZE, debug_hex, sizeof(debug_hex), 1) == 0) {
            fprintf(stderr, "hash state slot %llu finalized root: %s\n", (unsigned long long)state->slot, debug_hex);
        }
        if (lantern_bytes_to_hex(historical_root.bytes, LANTERN_ROOT_SIZE, debug_hex, sizeof(debug_hex), 1) == 0) {
            fprintf(stderr, "hash state slot %llu historical root: %s\n", (unsigned long long)state->slot, debug_hex);
        }
        if (lantern_bytes_to_hex(justified_slots_root.bytes, LANTERN_ROOT_SIZE, debug_hex, sizeof(debug_hex), 1) == 0) {
            fprintf(stderr, "hash state slot %llu justified slots root: %s\n", (unsigned long long)state->slot, debug_hex);
        }
        if (lantern_bytes_to_hex(state->validators_root.bytes, LANTERN_ROOT_SIZE, debug_hex, sizeof(debug_hex), 1) == 0) {
            fprintf(stderr, "hash state slot %llu validators root: %s\n", (unsigned long long)state->slot, debug_hex);
        }
        if (lantern_bytes_to_hex(justification_roots_root.bytes, LANTERN_ROOT_SIZE, debug_hex, sizeof(debug_hex), 1) == 0) {
            fprintf(stderr, "hash state slot %llu justification roots root: %s\n", (unsigned long long)state->slot, debug_hex);
        }
        if (lantern_bytes_to_hex(justification_validators_root.bytes, LANTERN_ROOT_SIZE, debug_hex, sizeof(debug_hex), 1) == 0) {
            fprintf(
                stderr,
                "hash state slot %llu justification validators root: %s\n",
                (unsigned long long)state->slot,
                debug_hex);
        }
    }

    uint8_t chunks[10][SSZ_BYTES_PER_CHUNK];
    memcpy(chunks[0], config_root.bytes, SSZ_BYTES_PER_CHUNK);
    chunk_from_uint64(state->slot, chunks[1]);
    memcpy(chunks[2], header_root.bytes, SSZ_BYTES_PER_CHUNK);
    memcpy(chunks[3], justified_root.bytes, SSZ_BYTES_PER_CHUNK);
    memcpy(chunks[4], finalized_root.bytes, SSZ_BYTES_PER_CHUNK);
    memcpy(chunks[5], historical_root.bytes, SSZ_BYTES_PER_CHUNK);
    memcpy(chunks[6], justified_slots_root.bytes, SSZ_BYTES_PER_CHUNK);
    memcpy(chunks[7], state->validators_root.bytes, SSZ_BYTES_PER_CHUNK);
    memcpy(chunks[8], justification_roots_root.bytes, SSZ_BYTES_PER_CHUNK);
    memcpy(chunks[9], justification_validators_root.bytes, SSZ_BYTES_PER_CHUNK);
    return merkleize_chunks(&chunks[0][0], 10, 0, out_root);
}

int lantern_hash_tree_root_validators(const uint8_t *pubkeys, size_t count, LanternRoot *out_root) {
    if (!out_root) {
        return -1;
    }
    uint8_t *chunks = NULL;
    if (count > 0) {
        if (!pubkeys) {
            return -1;
        }
        if (count > SIZE_MAX / SSZ_BYTES_PER_CHUNK) {
            return -1;
        }
        chunks = malloc(count * SSZ_BYTES_PER_CHUNK);
        if (!chunks) {
            return -1;
        }
        for (size_t i = 0; i < count; ++i) {
            LanternRoot validator_root;
            if (hash_validator(pubkeys + (i * LANTERN_VALIDATOR_PUBKEY_SIZE), &validator_root) != 0) {
                free(chunks);
                return -1;
            }
            if (i == 0) {
                char validator_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
                if (lantern_bytes_to_hex(
                        validator_root.bytes,
                        LANTERN_ROOT_SIZE,
                        validator_hex,
                        sizeof(validator_hex),
                        1)
                    == 0) {
                    fprintf(stderr, "validator[0] root: %s\n", validator_hex);
                }
            }
    memcpy(chunks + (i * SSZ_BYTES_PER_CHUNK), validator_root.bytes, SSZ_BYTES_PER_CHUNK);
        }
    }
    uint8_t temp_root[SSZ_BYTES_PER_CHUNK];
    ssz_error_t err = ssz_merkleize(chunks, count, LANTERN_VALIDATOR_REGISTRY_LIMIT, temp_root);
    free(chunks);
    if (err != SSZ_SUCCESS) {
        return -1;
    }
    err = ssz_mix_in_length(temp_root, (uint64_t)count, out_root->bytes);
    return err == SSZ_SUCCESS ? 0 : -1;
}
