#include "lantern/consensus/ssz.h"

#include <limits.h>
#include <string.h>

#include "ssz_constants.h"
#include "ssz_deserialize.h"
#include "ssz_serialize.h"

static int write_u32(uint8_t *out, size_t remaining, uint32_t value) {
    if (!out || remaining < SSZ_BYTE_SIZE_OF_UINT32) {
        return -1;
    }
    size_t written = SSZ_BYTE_SIZE_OF_UINT32;
    ssz_error_t err = ssz_serialize_uint32(&value, out, &written);
    if (err != SSZ_SUCCESS || written != SSZ_BYTE_SIZE_OF_UINT32) {
        return -1;
    }
    return 0;
}

static int read_u32(const uint8_t *data, size_t remaining, uint32_t *value) {
    if (!data || !value || remaining < SSZ_BYTE_SIZE_OF_UINT32) {
        return -1;
    }
    ssz_error_t err = ssz_deserialize_uint32(data, SSZ_BYTE_SIZE_OF_UINT32, value);
    return err == SSZ_SUCCESS ? 0 : -1;
}

static int write_u64(uint8_t *out, size_t remaining, uint64_t value) {
    if (!out || remaining < SSZ_BYTE_SIZE_OF_UINT64) {
        return -1;
    }
    size_t written = SSZ_BYTE_SIZE_OF_UINT64;
    ssz_error_t err = ssz_serialize_uint64(&value, out, &written);
    if (err != SSZ_SUCCESS || written != SSZ_BYTE_SIZE_OF_UINT64) {
        return -1;
    }
    return 0;
}

static int read_u64(const uint8_t *data, size_t remaining, uint64_t *value) {
    if (!data || !value || remaining < SSZ_BYTE_SIZE_OF_UINT64) {
        return -1;
    }
    ssz_error_t err = ssz_deserialize_uint64(data, SSZ_BYTE_SIZE_OF_UINT64, value);
    return err == SSZ_SUCCESS ? 0 : -1;
}

static int write_root(uint8_t *out, size_t remaining, const LanternRoot *root) {
    if (!out || !root || remaining < LANTERN_ROOT_SIZE) {
        return -1;
    }
    memcpy(out, root->bytes, LANTERN_ROOT_SIZE);
    return 0;
}

static int read_root(const uint8_t *data, size_t remaining, LanternRoot *root) {
    if (!data || !root || remaining < LANTERN_ROOT_SIZE) {
        return -1;
    }
    memcpy(root->bytes, data, LANTERN_ROOT_SIZE);
    return 0;
}

static void set_written(size_t *written, size_t value) {
    if (written) {
        *written = value;
    }
}

static int encode_attestations(const LanternAttestations *attestations, uint8_t *out, size_t remaining, size_t *written) {
    if (!attestations) {
        return -1;
    }
    if (attestations->length > LANTERN_MAX_ATTESTATIONS) {
        return -1;
    }
    if (attestations->length > 0 && !attestations->data) {
        return -1;
    }

    size_t required = attestations->length * LANTERN_SIGNED_VOTE_SSZ_SIZE;
    if (remaining < required) {
        return -1;
    }

    size_t offset = 0;
    for (size_t i = 0; i < attestations->length; ++i) {
        size_t vote_written = 0;
        if (lantern_ssz_encode_signed_vote(&attestations->data[i], out + offset, remaining - offset, &vote_written) != 0) {
            return -1;
        }
        offset += vote_written;
    }
    set_written(written, offset);
    return 0;
}

static int decode_attestations(LanternAttestations *attestations, const uint8_t *data, size_t data_len) {
    if (!attestations) {
        return -1;
    }
    if (data_len == 0) {
        return lantern_attestations_resize(attestations, 0);
    }
    if (data_len % LANTERN_SIGNED_VOTE_SSZ_SIZE != 0) {
        return -1;
    }
    size_t count = data_len / LANTERN_SIGNED_VOTE_SSZ_SIZE;
    if (count > LANTERN_MAX_ATTESTATIONS) {
        return -1;
    }
    if (lantern_attestations_resize(attestations, count) != 0) {
        return -1;
    }
    for (size_t i = 0; i < count; ++i) {
        if (lantern_ssz_decode_signed_vote(&attestations->data[i], data + (i * LANTERN_SIGNED_VOTE_SSZ_SIZE), LANTERN_SIGNED_VOTE_SSZ_SIZE) != 0) {
            return -1;
        }
    }
    return 0;
}

int lantern_ssz_encode_config(const LanternConfig *config, uint8_t *out, size_t out_len, size_t *written) {
    if (!config || !out || out_len < LANTERN_CONFIG_SSZ_SIZE) {
        return -1;
    }
    size_t offset = 0;
    if (write_u64(out + offset, out_len - offset, config->num_validators) != 0) {
        return -1;
    }
    offset += SSZ_BYTE_SIZE_OF_UINT64;
    if (write_u64(out + offset, out_len - offset, config->genesis_time) != 0) {
        return -1;
    }
    offset += SSZ_BYTE_SIZE_OF_UINT64;
    set_written(written, offset);
    return 0;
}

int lantern_ssz_decode_config(LanternConfig *config, const uint8_t *data, size_t data_len) {
    if (!config || !data || data_len != LANTERN_CONFIG_SSZ_SIZE) {
        return -1;
    }
    size_t offset = 0;
    if (read_u64(data + offset, data_len - offset, &config->num_validators) != 0) {
        return -1;
    }
    offset += SSZ_BYTE_SIZE_OF_UINT64;
    if (read_u64(data + offset, data_len - offset, &config->genesis_time) != 0) {
        return -1;
    }
    return 0;
}

int lantern_ssz_encode_checkpoint(const LanternCheckpoint *checkpoint, uint8_t *out, size_t out_len, size_t *written) {
    if (!checkpoint || !out || out_len < LANTERN_CHECKPOINT_SSZ_SIZE) {
        return -1;
    }
    size_t offset = 0;
    if (write_root(out + offset, out_len - offset, &checkpoint->root) != 0) {
        return -1;
    }
    offset += LANTERN_ROOT_SIZE;
    if (write_u64(out + offset, out_len - offset, checkpoint->slot) != 0) {
        return -1;
    }
    offset += SSZ_BYTE_SIZE_OF_UINT64;
    set_written(written, offset);
    return 0;
}

int lantern_ssz_decode_checkpoint(LanternCheckpoint *checkpoint, const uint8_t *data, size_t data_len) {
    if (!checkpoint || !data || data_len != LANTERN_CHECKPOINT_SSZ_SIZE) {
        return -1;
    }
    size_t offset = 0;
    if (read_root(data + offset, data_len - offset, &checkpoint->root) != 0) {
        return -1;
    }
    offset += LANTERN_ROOT_SIZE;
    if (read_u64(data + offset, data_len - offset, &checkpoint->slot) != 0) {
        return -1;
    }
    return 0;
}

static int encode_vote_internal(const LanternVote *vote, uint8_t *out, size_t out_len, size_t *written) {
    if (!vote || !out || out_len < LANTERN_VOTE_SSZ_SIZE) {
        return -1;
    }
    size_t offset = 0;
    if (write_u64(out + offset, out_len - offset, vote->validator_id) != 0) {
        return -1;
    }
    offset += SSZ_BYTE_SIZE_OF_UINT64;
    if (write_u64(out + offset, out_len - offset, vote->slot) != 0) {
        return -1;
    }
    offset += SSZ_BYTE_SIZE_OF_UINT64;

    size_t tmp_written = 0;
    if (lantern_ssz_encode_checkpoint(&vote->head, out + offset, out_len - offset, &tmp_written) != 0) {
        return -1;
    }
    offset += tmp_written;
    if (lantern_ssz_encode_checkpoint(&vote->target, out + offset, out_len - offset, &tmp_written) != 0) {
        return -1;
    }
    offset += tmp_written;
    if (lantern_ssz_encode_checkpoint(&vote->source, out + offset, out_len - offset, &tmp_written) != 0) {
        return -1;
    }
    offset += tmp_written;

    set_written(written, offset);
    return 0;
}

static int decode_vote_internal(LanternVote *vote, const uint8_t *data, size_t data_len) {
    if (!vote || !data || data_len != LANTERN_VOTE_SSZ_SIZE) {
        return -1;
    }
    size_t offset = 0;
    if (read_u64(data + offset, data_len - offset, &vote->validator_id) != 0) {
        return -1;
    }
    offset += SSZ_BYTE_SIZE_OF_UINT64;
    if (read_u64(data + offset, data_len - offset, &vote->slot) != 0) {
        return -1;
    }
    offset += SSZ_BYTE_SIZE_OF_UINT64;

    if (lantern_ssz_decode_checkpoint(&vote->head, data + offset, LANTERN_CHECKPOINT_SSZ_SIZE) != 0) {
        return -1;
    }
    offset += LANTERN_CHECKPOINT_SSZ_SIZE;
    if (lantern_ssz_decode_checkpoint(&vote->target, data + offset, LANTERN_CHECKPOINT_SSZ_SIZE) != 0) {
        return -1;
    }
    offset += LANTERN_CHECKPOINT_SSZ_SIZE;
    if (lantern_ssz_decode_checkpoint(&vote->source, data + offset, LANTERN_CHECKPOINT_SSZ_SIZE) != 0) {
        return -1;
    }
    return 0;
}

int lantern_ssz_encode_vote(const LanternVote *vote, uint8_t *out, size_t out_len, size_t *written) {
    return encode_vote_internal(vote, out, out_len, written);
}

int lantern_ssz_decode_vote(LanternVote *vote, const uint8_t *data, size_t data_len) {
    return decode_vote_internal(vote, data, data_len);
}

int lantern_ssz_encode_signed_vote(const LanternSignedVote *vote, uint8_t *out, size_t out_len, size_t *written) {
    if (!vote || !out || out_len < LANTERN_SIGNED_VOTE_SSZ_SIZE) {
        return -1;
    }
    size_t offset = 0;
    if (encode_vote_internal(&vote->data, out + offset, out_len - offset, NULL) != 0) {
        return -1;
    }
    offset += LANTERN_VOTE_SSZ_SIZE;
    memcpy(out + offset, vote->signature.bytes, LANTERN_SIGNATURE_SIZE);
    offset += LANTERN_SIGNATURE_SIZE;
    set_written(written, offset);
    return 0;
}

int lantern_ssz_decode_signed_vote(LanternSignedVote *vote, const uint8_t *data, size_t data_len) {
    if (!vote || !data || data_len != LANTERN_SIGNED_VOTE_SSZ_SIZE) {
        return -1;
    }
    if (decode_vote_internal(&vote->data, data, LANTERN_VOTE_SSZ_SIZE) != 0) {
        return -1;
    }
    memcpy(vote->signature.bytes, data + LANTERN_VOTE_SSZ_SIZE, LANTERN_SIGNATURE_SIZE);
    return 0;
}

int lantern_ssz_encode_block_header(const LanternBlockHeader *header, uint8_t *out, size_t out_len, size_t *written) {
    if (!header || !out || out_len < LANTERN_BLOCK_HEADER_SSZ_SIZE) {
        return -1;
    }
    size_t offset = 0;
    if (write_u64(out + offset, out_len - offset, header->slot) != 0) {
        return -1;
    }
    offset += SSZ_BYTE_SIZE_OF_UINT64;
    if (write_u64(out + offset, out_len - offset, header->proposer_index) != 0) {
        return -1;
    }
    offset += SSZ_BYTE_SIZE_OF_UINT64;
    if (write_root(out + offset, out_len - offset, &header->parent_root) != 0) {
        return -1;
    }
    offset += LANTERN_ROOT_SIZE;
    if (write_root(out + offset, out_len - offset, &header->state_root) != 0) {
        return -1;
    }
    offset += LANTERN_ROOT_SIZE;
    if (write_root(out + offset, out_len - offset, &header->body_root) != 0) {
        return -1;
    }
    offset += LANTERN_ROOT_SIZE;
    set_written(written, offset);
    return 0;
}

int lantern_ssz_decode_block_header(LanternBlockHeader *header, const uint8_t *data, size_t data_len) {
    if (!header || !data || data_len != LANTERN_BLOCK_HEADER_SSZ_SIZE) {
        return -1;
    }
    size_t offset = 0;
    if (read_u64(data + offset, data_len - offset, &header->slot) != 0) {
        return -1;
    }
    offset += SSZ_BYTE_SIZE_OF_UINT64;
    if (read_u64(data + offset, data_len - offset, &header->proposer_index) != 0) {
        return -1;
    }
    offset += SSZ_BYTE_SIZE_OF_UINT64;
    if (read_root(data + offset, data_len - offset, &header->parent_root) != 0) {
        return -1;
    }
    offset += LANTERN_ROOT_SIZE;
    if (read_root(data + offset, data_len - offset, &header->state_root) != 0) {
        return -1;
    }
    offset += LANTERN_ROOT_SIZE;
    if (read_root(data + offset, data_len - offset, &header->body_root) != 0) {
        return -1;
    }
    return 0;
}

int lantern_ssz_encode_block_body(const LanternBlockBody *body, uint8_t *out, size_t out_len, size_t *written) {
    if (!body || !out) {
        return -1;
    }

    uint32_t att_offset = SSZ_BYTE_SIZE_OF_UINT32;
    size_t att_bytes = body->attestations.length * LANTERN_SIGNED_VOTE_SSZ_SIZE;
    if (att_bytes > UINT32_MAX) {
        return -1;
    }
    if ((size_t)att_offset > SIZE_MAX - att_bytes) {
        return -1;
    }
    size_t total = att_offset + att_bytes;
    if (out_len < total) {
        return -1;
    }

    if (write_u32(out, out_len, att_offset) != 0) {
        return -1;
    }

    if (encode_attestations(&body->attestations, out + att_offset, out_len - att_offset, NULL) != 0) {
        return -1;
    }

    set_written(written, total);
    return 0;
}

int lantern_ssz_decode_block_body(LanternBlockBody *body, const uint8_t *data, size_t data_len) {
    if (!body || !data || data_len < SSZ_BYTE_SIZE_OF_UINT32) {
        return -1;
    }

    uint32_t att_offset = 0;
    if (read_u32(data, data_len, &att_offset) != 0) {
        return -1;
    }
    if (att_offset > data_len || att_offset < SSZ_BYTE_SIZE_OF_UINT32) {
        return -1;
    }

    size_t att_size = data_len - att_offset;
    if (decode_attestations(&body->attestations, data + att_offset, att_size) != 0) {
        return -1;
    }
    return 0;
}

int lantern_ssz_encode_block(const LanternBlock *block, uint8_t *out, size_t out_len, size_t *written) {
    if (!block || !out) {
        return -1;
    }

    const size_t fixed_fields = (SSZ_BYTE_SIZE_OF_UINT64 * 2) + (LANTERN_ROOT_SIZE * 2);
    const size_t fixed_section = fixed_fields + SSZ_BYTE_SIZE_OF_UINT32; /* single variable field offset */
    if (fixed_section > UINT32_MAX) {
        return -1;
    }
    if (out_len < fixed_section) {
        return -1;
    }

    size_t offset = 0;
    if (write_u64(out + offset, out_len - offset, block->slot) != 0) {
        return -1;
    }
    offset += SSZ_BYTE_SIZE_OF_UINT64;
    if (write_u64(out + offset, out_len - offset, block->proposer_index) != 0) {
        return -1;
    }
    offset += SSZ_BYTE_SIZE_OF_UINT64;
    if (write_root(out + offset, out_len - offset, &block->parent_root) != 0) {
        return -1;
    }
    offset += LANTERN_ROOT_SIZE;
    if (write_root(out + offset, out_len - offset, &block->state_root) != 0) {
        return -1;
    }
    offset += LANTERN_ROOT_SIZE;

    uint32_t body_offset = (uint32_t)fixed_section;
    if (write_u32(out + offset, out_len - offset, body_offset) != 0) {
        return -1;
    }
    offset += SSZ_BYTE_SIZE_OF_UINT32;

    size_t body_written = 0;
    if (lantern_ssz_encode_block_body(&block->body, out + body_offset, out_len - body_offset, &body_written) != 0) {
        return -1;
    }

    size_t total = body_offset + body_written;
    if (total > UINT32_MAX) {
        return -1;
    }
    set_written(written, total);
    return 0;
}

int lantern_ssz_decode_block(LanternBlock *block, const uint8_t *data, size_t data_len) {
    if (!block || !data) {
        return -1;
    }

    const size_t fixed_fields = (SSZ_BYTE_SIZE_OF_UINT64 * 2) + (LANTERN_ROOT_SIZE * 2);
    const size_t min_size = fixed_fields + SSZ_BYTE_SIZE_OF_UINT32;
    if (data_len < min_size) {
        return -1;
    }

    size_t offset = 0;
    if (read_u64(data + offset, data_len - offset, &block->slot) != 0) {
        return -1;
    }
    offset += SSZ_BYTE_SIZE_OF_UINT64;
    if (read_u64(data + offset, data_len - offset, &block->proposer_index) != 0) {
        return -1;
    }
    offset += SSZ_BYTE_SIZE_OF_UINT64;
    if (read_root(data + offset, data_len - offset, &block->parent_root) != 0) {
        return -1;
    }
    offset += LANTERN_ROOT_SIZE;
    if (read_root(data + offset, data_len - offset, &block->state_root) != 0) {
        return -1;
    }
    offset += LANTERN_ROOT_SIZE;

    uint32_t body_offset = 0;
    if (read_u32(data + offset, data_len - offset, &body_offset) != 0) {
        return -1;
    }
    offset += SSZ_BYTE_SIZE_OF_UINT32;

    if (body_offset > data_len || body_offset < min_size) {
        return -1;
    }

    if (lantern_ssz_decode_block_body(&block->body, data + body_offset, data_len - body_offset) != 0) {
        return -1;
    }
    return 0;
}

int lantern_ssz_encode_signed_block(const LanternSignedBlock *block, uint8_t *out, size_t out_len, size_t *written) {
    if (!block || !out) {
        return -1;
    }

    const size_t header_size = SSZ_BYTE_SIZE_OF_UINT32 + LANTERN_SIGNATURE_SIZE;
    if (header_size > UINT32_MAX) {
        return -1;
    }
    if (out_len < header_size) {
        return -1;
    }

    uint32_t message_offset = (uint32_t)header_size;
    if (write_u32(out, out_len, message_offset) != 0) {
        return -1;
    }

    memcpy(out + SSZ_BYTE_SIZE_OF_UINT32, block->signature.bytes, LANTERN_SIGNATURE_SIZE);

    size_t message_written = 0;
    if (lantern_ssz_encode_block(&block->message, out + message_offset, out_len - message_offset, &message_written) != 0) {
        return -1;
    }

    size_t total = message_offset + message_written;
    if (total > UINT32_MAX) {
        return -1;
    }
    set_written(written, total);
    return 0;
}

int lantern_ssz_decode_signed_block(LanternSignedBlock *block, const uint8_t *data, size_t data_len) {
    if (!block || !data || data_len < SSZ_BYTE_SIZE_OF_UINT32 + LANTERN_SIGNATURE_SIZE) {
        return -1;
    }

    uint32_t message_offset = 0;
    if (read_u32(data, data_len, &message_offset) != 0) {
        return -1;
    }
    if (message_offset > data_len || message_offset < SSZ_BYTE_SIZE_OF_UINT32 + LANTERN_SIGNATURE_SIZE) {
        return -1;
    }

    memcpy(block->signature.bytes, data + SSZ_BYTE_SIZE_OF_UINT32, LANTERN_SIGNATURE_SIZE);

    if (lantern_ssz_decode_block(&block->message, data + message_offset, data_len - message_offset) != 0) {
        return -1;
    }
    return 0;
}
