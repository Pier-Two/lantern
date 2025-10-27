#include "lantern/networking/messages.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "lantern/consensus/ssz.h"
#include "ssz_constants.h"
#include "lantern/encoding/snappy.h"

static int write_u32_le(uint32_t value, uint8_t *out, size_t out_len) {
    if (!out || out_len < sizeof(uint32_t)) {
        return -1;
    }
    out[0] = (uint8_t)(value & 0xFFu);
    out[1] = (uint8_t)((value >> 8) & 0xFFu);
    out[2] = (uint8_t)((value >> 16) & 0xFFu);
    out[3] = (uint8_t)((value >> 24) & 0xFFu);
    return 0;
}

static int read_u32_le(const uint8_t *data, size_t data_len, uint32_t *value) {
    if (!data || data_len < sizeof(uint32_t) || !value) {
        return -1;
    }
    *value = (uint32_t)data[0]
        | ((uint32_t)data[1] << 8)
        | ((uint32_t)data[2] << 16)
        | ((uint32_t)data[3] << 24);
    return 0;
}

static int ensure_block_capacity(LanternBlocksByRootResponse *resp, size_t required) {
    if (!resp) {
        return -1;
    }
    if (resp->capacity >= required) {
        return 0;
    }
    size_t new_capacity = resp->capacity == 0 ? 4u : resp->capacity;
    while (new_capacity < required) {
        if (new_capacity > SIZE_MAX / 2u) {
            return -1;
        }
        new_capacity *= 2u;
    }
    LanternSignedBlock *blocks = realloc(resp->blocks, new_capacity * sizeof(*blocks));
    if (!blocks) {
        return -1;
    }
    resp->blocks = blocks;
    resp->capacity = new_capacity;
    return 0;
}

void lantern_blocks_by_root_request_init(LanternBlocksByRootRequest *req) {
    if (!req) {
        return;
    }
    lantern_root_list_init(&req->roots);
}

void lantern_blocks_by_root_request_reset(LanternBlocksByRootRequest *req) {
    if (!req) {
        return;
    }
    lantern_root_list_reset(&req->roots);
}

void lantern_blocks_by_root_response_init(LanternBlocksByRootResponse *resp) {
    if (!resp) {
        return;
    }
    resp->blocks = NULL;
    resp->length = 0;
    resp->capacity = 0;
}

void lantern_blocks_by_root_response_reset(LanternBlocksByRootResponse *resp) {
    if (!resp) {
        return;
    }
    if (resp->blocks) {
        for (size_t i = 0; i < resp->length; ++i) {
            lantern_block_body_reset(&resp->blocks[i].message.body);
        }
    }
    free(resp->blocks);
    resp->blocks = NULL;
    resp->length = 0;
    resp->capacity = 0;
}

int lantern_blocks_by_root_response_resize(LanternBlocksByRootResponse *resp, size_t new_length) {
    if (!resp) {
        return -1;
    }
    if (new_length == 0) {
        if (resp->blocks) {
            for (size_t i = 0; i < resp->length; ++i) {
                lantern_block_body_reset(&resp->blocks[i].message.body);
            }
        }
        resp->length = 0;
        return 0;
    }
    if (ensure_block_capacity(resp, new_length) != 0) {
        return -1;
    }
    if (!resp->blocks) {
        return -1;
    }
    size_t old_length = resp->length;
    if (new_length > old_length) {
        for (size_t i = old_length; i < new_length; ++i) {
            memset(&resp->blocks[i], 0, sizeof(resp->blocks[i]));
            lantern_block_body_init(&resp->blocks[i].message.body);
        }
    } else if (new_length < old_length) {
        for (size_t i = new_length; i < old_length; ++i) {
            lantern_block_body_reset(&resp->blocks[i].message.body);
        }
    }
    resp->length = new_length;
    return 0;
}

static int encode_status_raw(
    const LanternStatusMessage *status,
    uint8_t *out,
    size_t out_len,
    size_t *written) {
    if (!status || !out || !written) {
        return -1;
    }
    size_t offset = 0;
    size_t checkpoint_written = 0;
    if (lantern_ssz_encode_checkpoint(&status->finalized, out + offset, out_len - offset, &checkpoint_written) != 0) {
        return -1;
    }
    offset += checkpoint_written;
    if (lantern_ssz_encode_checkpoint(&status->head, out + offset, out_len - offset, &checkpoint_written) != 0) {
        return -1;
    }
    offset += checkpoint_written;
    *written = offset;
    return 0;
}

int lantern_network_status_encode(
    const LanternStatusMessage *status,
    uint8_t *out,
    size_t out_len,
    size_t *written) {
    return encode_status_raw(status, out, out_len, written);
}

int lantern_network_status_decode(
    LanternStatusMessage *status,
    const uint8_t *data,
    size_t data_len) {
    if (!status || !data) {
        return -1;
    }
    if (data_len != 2u * LANTERN_CHECKPOINT_SSZ_SIZE) {
        return -1;
    }
    if (lantern_ssz_decode_checkpoint(&status->finalized, data, LANTERN_CHECKPOINT_SSZ_SIZE) != 0) {
        return -1;
    }
    if (lantern_ssz_decode_checkpoint(&status->head, data + LANTERN_CHECKPOINT_SSZ_SIZE, LANTERN_CHECKPOINT_SSZ_SIZE) != 0) {
        return -1;
    }
    return 0;
}

int lantern_network_status_encode_snappy(
    const LanternStatusMessage *status,
    uint8_t *out,
    size_t out_len,
    size_t *written) {
    if (!status || !out || !written) {
        return -1;
    }
    uint8_t raw[2u * LANTERN_CHECKPOINT_SSZ_SIZE];
    size_t raw_written = sizeof(raw);
    if (encode_status_raw(status, raw, sizeof(raw), &raw_written) != 0) {
        return -1;
    }
    int rc = lantern_snappy_compress(raw, raw_written, out, out_len, written);
    return rc == LANTERN_SNAPPY_OK ? 0 : -1;
}

int lantern_network_status_decode_snappy(
    LanternStatusMessage *status,
    const uint8_t *data,
    size_t data_len) {
    if (!status || !data) {
        return -1;
    }
    uint8_t raw[2u * LANTERN_CHECKPOINT_SSZ_SIZE];
    size_t raw_written = sizeof(raw);
    int rc = lantern_snappy_decompress(data, data_len, raw, sizeof(raw), &raw_written);
    if (rc != LANTERN_SNAPPY_OK) {
        return -1;
    }
    return lantern_network_status_decode(status, raw, raw_written);
}

int lantern_network_blocks_by_root_request_encode(
    const LanternBlocksByRootRequest *req,
    uint8_t *out,
    size_t out_len,
    size_t *written) {
    if (!req || !out || !written) {
        return -1;
    }
    if (req->roots.length > LANTERN_MAX_REQUEST_BLOCKS) {
        return -1;
    }
    size_t required = sizeof(uint32_t) + req->roots.length * LANTERN_ROOT_SIZE;
    if (out_len < required) {
        return -1;
    }
    if (write_u32_le((uint32_t)req->roots.length, out, out_len) != 0) {
        return -1;
    }
    if (req->roots.length > 0 && req->roots.items) {
        memcpy(out + sizeof(uint32_t), req->roots.items, req->roots.length * LANTERN_ROOT_SIZE);
    }
    *written = required;
    return 0;
}

int lantern_network_blocks_by_root_request_decode(
    LanternBlocksByRootRequest *req,
    const uint8_t *data,
    size_t data_len) {
    if (!req || !data) {
        return -1;
    }
    if (data_len < sizeof(uint32_t)) {
        return -1;
    }
    uint32_t count = 0;
    if (read_u32_le(data, data_len, &count) != 0) {
        return -1;
    }
    if (count > LANTERN_MAX_REQUEST_BLOCKS) {
        return -1;
    }
    size_t expected = sizeof(uint32_t) + ((size_t)count * LANTERN_ROOT_SIZE);
    if (data_len != expected) {
        return -1;
    }
    if (lantern_root_list_resize(&req->roots, count) != 0) {
        return -1;
    }
    if (count > 0 && req->roots.items) {
        memcpy(req->roots.items, data + sizeof(uint32_t), count * LANTERN_ROOT_SIZE);
    }
    return 0;
}

static uint8_t *alloc_scratch(size_t size) {
    if (size == 0) {
        return NULL;
    }
    return malloc(size);
}

int lantern_network_blocks_by_root_request_encode_snappy(
    const LanternBlocksByRootRequest *req,
    uint8_t *out,
    size_t out_len,
    size_t *written) {
    if (!req || !out || !written) {
        return -1;
    }
    size_t raw_size = sizeof(uint32_t) + req->roots.length * LANTERN_ROOT_SIZE;
    uint8_t *raw = alloc_scratch(raw_size);
    if (!raw) {
        return -1;
    }
    size_t raw_written = raw_size;
    int result = -1;
    if (lantern_network_blocks_by_root_request_encode(req, raw, raw_size, &raw_written) == 0) {
        int rc = lantern_snappy_compress(raw, raw_written, out, out_len, written);
        result = (rc == LANTERN_SNAPPY_OK) ? 0 : -1;
    }
    free(raw);
    return result;
}

int lantern_network_blocks_by_root_request_decode_snappy(
    LanternBlocksByRootRequest *req,
    const uint8_t *data,
    size_t data_len) {
    if (!req || !data) {
        return -1;
    }
    size_t raw_len = 0;
    if (lantern_snappy_uncompressed_length(data, data_len, &raw_len) != LANTERN_SNAPPY_OK) {
        return -1;
    }
    uint8_t *raw = alloc_scratch(raw_len);
    if (!raw) {
        return -1;
    }
    size_t written = raw_len;
    int rc = lantern_snappy_decompress(data, data_len, raw, raw_len, &written);
    if (rc != LANTERN_SNAPPY_OK) {
        free(raw);
        return -1;
    }
    int decode_rc = lantern_network_blocks_by_root_request_decode(req, raw, written);
    free(raw);
    return decode_rc;
}

int lantern_network_blocks_by_root_response_encode(
    const LanternBlocksByRootResponse *resp,
    uint8_t *out,
    size_t out_len,
    size_t *written) {
    if (!resp || !out || !written) {
        return -1;
    }
    if (resp->length > LANTERN_MAX_REQUEST_BLOCKS) {
        return -1;
    }
    if (out_len < sizeof(uint32_t)) {
        return -1;
    }
    if (write_u32_le((uint32_t)resp->length, out, out_len) != 0) {
        return -1;
    }
    size_t offset = sizeof(uint32_t);
    for (size_t i = 0; i < resp->length; ++i) {
        if (out_len - offset < sizeof(uint32_t)) {
            return -1;
        }
        uint8_t *len_ptr = out + offset;
        offset += sizeof(uint32_t);
        size_t block_written = 0;
        if (lantern_ssz_encode_signed_block(&resp->blocks[i], out + offset, out_len - offset, &block_written) != 0) {
            return -1;
        }
        if (block_written > UINT32_MAX) {
            return -1;
        }
        if (write_u32_le((uint32_t)block_written, len_ptr, sizeof(uint32_t)) != 0) {
            return -1;
        }
        offset += block_written;
    }
    *written = offset;
    return 0;
}

int lantern_network_blocks_by_root_response_decode(
    LanternBlocksByRootResponse *resp,
    const uint8_t *data,
    size_t data_len) {
    if (!resp || !data) {
        return -1;
    }
    if (data_len < sizeof(uint32_t)) {
        return -1;
    }
    uint32_t count = 0;
    if (read_u32_le(data, data_len, &count) != 0) {
        return -1;
    }
    if (count > LANTERN_MAX_REQUEST_BLOCKS) {
        return -1;
    }
    size_t offset = sizeof(uint32_t);
    if (lantern_blocks_by_root_response_resize(resp, count) != 0) {
        return -1;
    }
    for (size_t i = 0; i < count; ++i) {
        if (offset + sizeof(uint32_t) > data_len) {
            lantern_blocks_by_root_response_reset(resp);
            return -1;
        }
        uint32_t block_len = 0;
        if (read_u32_le(data + offset, data_len - offset, &block_len) != 0) {
            lantern_blocks_by_root_response_reset(resp);
            return -1;
        }
        offset += sizeof(uint32_t);
        if (offset + block_len > data_len) {
            lantern_blocks_by_root_response_reset(resp);
            return -1;
        }
        if (lantern_ssz_decode_signed_block(&resp->blocks[i], data + offset, block_len) != 0) {
            lantern_blocks_by_root_response_reset(resp);
            return -1;
        }
        offset += block_len;
    }
    if (offset != data_len) {
        lantern_blocks_by_root_response_reset(resp);
        return -1;
    }
    return 0;
}

int lantern_network_blocks_by_root_response_encode_snappy(
    const LanternBlocksByRootResponse *resp,
    uint8_t *out,
    size_t out_len,
    size_t *written) {
    if (!resp || !out || !written) {
        return -1;
    }
    const size_t base_per_block = sizeof(uint32_t) + LANTERN_SIGNATURE_SIZE + (SSZ_BYTE_SIZE_OF_UINT64 * 2)
        + (LANTERN_ROOT_SIZE * 2) + SSZ_BYTE_SIZE_OF_UINT32
        + (LANTERN_MAX_ATTESTATIONS * LANTERN_SIGNED_VOTE_SSZ_SIZE);
    size_t max_capacity = sizeof(uint32_t);
    if (resp->length > 0) {
        size_t per_block = sizeof(uint32_t) + base_per_block;
        if (per_block > SIZE_MAX / resp->length) {
            return -1;
        }
        max_capacity += resp->length * per_block;
    }
    size_t capacity = sizeof(uint32_t);
    if (resp->length > 0) {
        size_t per_block_initial = sizeof(uint32_t) + LANTERN_SIGNATURE_SIZE + 256;
        if (per_block_initial > SIZE_MAX / resp->length) {
            capacity = max_capacity;
        } else {
            size_t tentative = capacity + resp->length * per_block_initial;
            capacity = tentative > max_capacity ? max_capacity : tentative;
        }
    }

    while (true) {
        uint8_t *raw = alloc_scratch(capacity);
        if (!raw) {
            return -1;
        }
        size_t raw_written = capacity;
        int rc = lantern_network_blocks_by_root_response_encode(resp, raw, capacity, &raw_written);
        if (rc == 0) {
            int snappy_rc = lantern_snappy_compress(raw, raw_written, out, out_len, written);
            free(raw);
            return snappy_rc == LANTERN_SNAPPY_OK ? 0 : -1;
        }
        free(raw);
        if (capacity == max_capacity) {
            return -1;
        }
        size_t next = capacity * 2u;
        capacity = next > max_capacity ? max_capacity : next;
    }
}

int lantern_network_blocks_by_root_response_decode_snappy(
    LanternBlocksByRootResponse *resp,
    const uint8_t *data,
    size_t data_len) {
    if (!resp || !data) {
        return -1;
    }
    size_t raw_len = 0;
    if (lantern_snappy_uncompressed_length(data, data_len, &raw_len) != LANTERN_SNAPPY_OK) {
        return -1;
    }
    uint8_t *raw = alloc_scratch(raw_len);
    if (!raw) {
        return -1;
    }
    size_t written = raw_len;
    int rc = lantern_snappy_decompress(data, data_len, raw, raw_len, &written);
    if (rc != LANTERN_SNAPPY_OK) {
        free(raw);
        return -1;
    }
    int decode_rc = lantern_network_blocks_by_root_response_decode(resp, raw, written);
    free(raw);
    return decode_rc;
}
