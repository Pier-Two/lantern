#include "lantern/consensus/hash.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ssz_constants.h"
#include "ssz_merkle.h"

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

int lantern_hash_tree_root_config(const LanternConfig *config, LanternRoot *out_root) {
    if (!config || !out_root) {
        return -1;
    }
    uint8_t chunks[2][SSZ_BYTES_PER_CHUNK];
    chunk_from_uint64(config->num_validators, chunks[0]);
    chunk_from_uint64(config->genesis_time, chunks[1]);
    return merkleize_chunks(&chunks[0][0], 2, 0, out_root);
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
    uint8_t chunks[5][SSZ_BYTES_PER_CHUNK];
    chunk_from_uint64(vote->validator_id, chunks[0]);
    chunk_from_uint64(vote->slot, chunks[1]);
    memcpy(chunks[2], head_root.bytes, SSZ_BYTES_PER_CHUNK);
    memcpy(chunks[3], target_root.bytes, SSZ_BYTES_PER_CHUNK);
    memcpy(chunks[4], source_root.bytes, SSZ_BYTES_PER_CHUNK);
    return merkleize_chunks(&chunks[0][0], 5, 0, out_root);
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
            if (lantern_hash_tree_root_signed_vote(&attestations->data[i], &vote_root) != 0) {
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
    if (lantern_hash_tree_root_block_header(&state->latest_block_header, &header_root) != 0) {
        return -1;
    }
    if (lantern_hash_tree_root_checkpoint(&state->latest_justified, &justified_root) != 0) {
        return -1;
    }
    if (lantern_hash_tree_root_checkpoint(&state->latest_finalized, &finalized_root) != 0) {
        return -1;
    }
    if (lantern_merkleize_root_list(&state->historical_block_hashes, 0, &historical_root) != 0) {
        return -1;
    }
    if (lantern_merkleize_bitlist(&state->justified_slots, 0, &justified_slots_root) != 0) {
        return -1;
    }
    if (lantern_merkleize_root_list(&state->justification_roots, 0, &justification_roots_root) != 0) {
        return -1;
    }
    if (lantern_merkleize_bitlist(&state->justification_validators, 0, &justification_validators_root) != 0) {
        return -1;
    }

    uint8_t chunks[9][SSZ_BYTES_PER_CHUNK];
    memcpy(chunks[0], config_root.bytes, SSZ_BYTES_PER_CHUNK);
    chunk_from_uint64(state->slot, chunks[1]);
    memcpy(chunks[2], header_root.bytes, SSZ_BYTES_PER_CHUNK);
    memcpy(chunks[3], justified_root.bytes, SSZ_BYTES_PER_CHUNK);
    memcpy(chunks[4], finalized_root.bytes, SSZ_BYTES_PER_CHUNK);
    memcpy(chunks[5], historical_root.bytes, SSZ_BYTES_PER_CHUNK);
    memcpy(chunks[6], justified_slots_root.bytes, SSZ_BYTES_PER_CHUNK);
    memcpy(chunks[7], justification_roots_root.bytes, SSZ_BYTES_PER_CHUNK);
    memcpy(chunks[8], justification_validators_root.bytes, SSZ_BYTES_PER_CHUNK);
    return merkleize_chunks(&chunks[0][0], 9, 0, out_root);
}
