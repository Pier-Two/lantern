#ifndef LANTERN_RLP_H
#define LANTERN_RLP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum lantern_rlp_kind {
    LANTERN_RLP_KIND_BYTES = 1,
    LANTERN_RLP_KIND_LIST = 2,
};

struct lantern_rlp_view {
    enum lantern_rlp_kind kind;
    const uint8_t *data;
    size_t length;
    struct lantern_rlp_view *items;
    size_t item_count;
};

struct lantern_rlp_buffer {
    uint8_t *data;
    size_t length;
};

void lantern_rlp_view_reset(struct lantern_rlp_view *view);
int lantern_rlp_decode(const uint8_t *encoded, size_t encoded_length, struct lantern_rlp_view *out_view);
int lantern_rlp_view_as_uint64(const struct lantern_rlp_view *view, uint64_t *out_value);

void lantern_rlp_buffer_reset(struct lantern_rlp_buffer *buffer);
int lantern_rlp_encode_bytes(struct lantern_rlp_buffer *buffer, const uint8_t *data, size_t length);
int lantern_rlp_encode_uint64(struct lantern_rlp_buffer *buffer, uint64_t value);
int lantern_rlp_encode_list(
    struct lantern_rlp_buffer *buffer,
    const struct lantern_rlp_buffer *items,
    size_t item_count);

#ifdef __cplusplus
}
#endif

#endif /* LANTERN_RLP_H */
