#include "lantern/networking/gossip_payloads.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "lantern/consensus/containers.h"
#include "lantern/consensus/ssz.h"
#include "lantern/encoding/snappy.h"
#include "ssz_constants.h"

static uint8_t *alloc_buffer(size_t size) {
    if (size == 0) {
        return NULL;
    }
    return (uint8_t *)malloc(size);
}

static size_t signed_block_base_ssz_size(void) {
    return (SSZ_BYTE_SIZE_OF_UINT32 + LANTERN_SIGNATURE_SIZE)
        + (SSZ_BYTE_SIZE_OF_UINT64 * 2u)
        + (LANTERN_ROOT_SIZE * 2u)
        + SSZ_BYTE_SIZE_OF_UINT32 /* block body offset */
        + SSZ_BYTE_SIZE_OF_UINT32; /* attestations offset */
}

static size_t signed_block_max_ssz_size(void) {
    size_t base = signed_block_base_ssz_size();
    size_t attestations_max = (size_t)LANTERN_MAX_ATTESTATIONS * LANTERN_SIGNED_VOTE_SSZ_SIZE;
    if (attestations_max > SIZE_MAX - base) {
        return SIZE_MAX;
    }
    return base + attestations_max;
}

static size_t signed_block_min_capacity(const LanternSignedBlock *block) {
    size_t base = signed_block_base_ssz_size();
    size_t att_count = block->message.body.attestations.length;
    if (att_count > LANTERN_MAX_ATTESTATIONS) {
        return 0;
    }
    size_t att_bytes = att_count * LANTERN_SIGNED_VOTE_SSZ_SIZE;
    if (att_bytes > SIZE_MAX - base) {
        return 0;
    }
    return base + att_bytes;
}

static int basic_vote_sanity(const LanternSignedVote *vote) {
    if (!vote) {
        return -1;
    }
    const LanternVote *data = &vote->data;
    if (data->target.slot < data->source.slot) {
        return -1;
    }
    if (data->slot < data->target.slot) {
        return -1;
    }
    return 0;
}

static int basic_block_sanity(const LanternSignedBlock *block) {
    if (!block) {
        return -1;
    }
    const LanternBlock *message = &block->message;
    for (size_t i = 0; i < message->body.attestations.length; ++i) {
        const LanternSignedVote *att = &message->body.attestations.data[i];
        if (att->data.slot > message->slot) {
            return -1;
        }
        if (basic_vote_sanity(att) != 0) {
            return -1;
        }
    }
    return 0;
}

int lantern_gossip_encode_signed_block_snappy(
    const LanternSignedBlock *block,
    uint8_t *out,
    size_t out_len,
    size_t *written) {
    if (!block || !out || !written) {
        return -1;
    }
    size_t raw_capacity = signed_block_min_capacity(block);
    if (raw_capacity == 0) {
        return -1;
    }
    uint8_t *raw = alloc_buffer(raw_capacity);
    if (!raw) {
        return -1;
    }
    size_t raw_written = raw_capacity;
    if (lantern_ssz_encode_signed_block(block, raw, raw_capacity, &raw_written) != 0) {
        free(raw);
        return -1;
    }
    int snappy_rc = lantern_snappy_compress(raw, raw_written, out, out_len, written);
    free(raw);
    return snappy_rc == LANTERN_SNAPPY_OK ? 0 : -1;
}

int lantern_gossip_decode_signed_block_snappy(
    LanternSignedBlock *block,
    const uint8_t *data,
    size_t data_len) {
    if (!block || !data) {
        return -1;
    }
    size_t raw_len = 0;
    if (lantern_snappy_uncompressed_length(data, data_len, &raw_len) != LANTERN_SNAPPY_OK) {
        return -1;
    }
    if (raw_len == 0 || raw_len > signed_block_max_ssz_size()) {
        return -1;
    }
    uint8_t *raw = alloc_buffer(raw_len);
    if (!raw) {
        return -1;
    }
    size_t written = raw_len;
    int snappy_rc = lantern_snappy_decompress(data, data_len, raw, raw_len, &written);
    if (snappy_rc != LANTERN_SNAPPY_OK) {
        free(raw);
        return -1;
    }
    int decode_rc = lantern_ssz_decode_signed_block(block, raw, written);
    free(raw);
    if (decode_rc != 0) {
        return -1;
    }
    if (basic_block_sanity(block) != 0) {
        return -1;
    }
    return 0;
}

int lantern_gossip_encode_signed_vote_snappy(
    const LanternSignedVote *vote,
    uint8_t *out,
    size_t out_len,
    size_t *written) {
    if (!vote || !out || !written) {
        return -1;
    }
    if (basic_vote_sanity(vote) != 0) {
        return -1;
    }
    uint8_t raw[LANTERN_SIGNED_VOTE_SSZ_SIZE];
    size_t raw_written = sizeof(raw);
    if (lantern_ssz_encode_signed_vote(vote, raw, sizeof(raw), &raw_written) != 0) {
        return -1;
    }
    int snappy_rc = lantern_snappy_compress(raw, raw_written, out, out_len, written);
    return snappy_rc == LANTERN_SNAPPY_OK ? 0 : -1;
}

int lantern_gossip_decode_signed_vote_snappy(
    LanternSignedVote *vote,
    const uint8_t *data,
    size_t data_len) {
    if (!vote || !data) {
        return -1;
    }
    size_t raw_len = 0;
    if (lantern_snappy_uncompressed_length(data, data_len, &raw_len) != LANTERN_SNAPPY_OK) {
        return -1;
    }
    if (raw_len != LANTERN_SIGNED_VOTE_SSZ_SIZE) {
        return -1;
    }
    uint8_t raw[LANTERN_SIGNED_VOTE_SSZ_SIZE];
    size_t written = sizeof(raw);
    int snappy_rc = lantern_snappy_decompress(data, data_len, raw, sizeof(raw), &written);
    if (snappy_rc != LANTERN_SNAPPY_OK) {
        return -1;
    }
    if (written != sizeof(raw)) {
        return -1;
    }
    if (lantern_ssz_decode_signed_vote(vote, raw, sizeof(raw)) != 0) {
        return -1;
    }
    if (basic_vote_sanity(vote) != 0) {
        return -1;
    }
    return 0;
}
