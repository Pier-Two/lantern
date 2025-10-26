#include "lantern/rlp.h"

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

struct lantern_rlp_cursor {
    const uint8_t *data;
    size_t length;
    size_t offset;
};

static void lantern_rlp_view_zero(struct lantern_rlp_view *view) {
    if (view) {
        view->kind = 0;
        view->data = NULL;
        view->length = 0;
        view->items = NULL;
        view->item_count = 0;
    }
}

void lantern_rlp_view_reset(struct lantern_rlp_view *view) {
    if (!view) {
        return;
    }
    if (view->kind == LANTERN_RLP_KIND_LIST && view->items) {
        for (size_t i = 0; i < view->item_count; ++i) {
            lantern_rlp_view_reset(&view->items[i]);
        }
        free(view->items);
    }
    lantern_rlp_view_zero(view);
}

void lantern_rlp_buffer_reset(struct lantern_rlp_buffer *buffer) {
    if (!buffer) {
        return;
    }
    free(buffer->data);
    buffer->data = NULL;
    buffer->length = 0;
}

static size_t bytes_required(size_t value) {
    size_t count = 0;
    do {
        ++count;
        value >>= 8;
    } while (value != 0);
    return count;
}

static size_t rlp_string_encoded_length(const uint8_t *data, size_t length) {
    if (length == 1 && data && data[0] < 0x80) {
        return 1;
    }
    if (length < 56) {
        return 1 + length;
    }
    return 1 + bytes_required(length) + length;
}

static size_t rlp_list_header_length(size_t payload_length) {
    if (payload_length < 56) {
        return 1;
    }
    return 1 + bytes_required(payload_length);
}

static bool size_add_overflow(size_t a, size_t b, size_t *out) {
    if (SIZE_MAX - a < b) {
        return true;
    }
    *out = a + b;
    return false;
}

static int write_length(uint8_t *dest, size_t length, uint8_t short_base, uint8_t long_base) {
    if (length < 56) {
        dest[0] = (uint8_t)(short_base + length);
        return 1;
    }

    size_t len_of_len = bytes_required(length);
    dest[0] = (uint8_t)(long_base + len_of_len);
    for (size_t i = 0; i < len_of_len; ++i) {
        size_t shift = (len_of_len - i - 1) * 8;
        dest[1 + i] = (uint8_t)((length >> shift) & 0xFF);
    }
    return (int)(1 + len_of_len);
}

int lantern_rlp_encode_bytes(struct lantern_rlp_buffer *buffer, const uint8_t *data, size_t length) {
    if (!buffer || (length > 0 && !data)) {
        return -1;
    }

    lantern_rlp_buffer_reset(buffer);

    size_t total = rlp_string_encoded_length(data, length);
    uint8_t *encoded = malloc(total);
    if (!encoded) {
        return -1;
    }

    size_t offset = 0;
    if (length == 1 && data[0] < 0x80) {
        encoded[offset++] = data[0];
    } else if (length < 56) {
        encoded[offset++] = (uint8_t)(0x80 + length);
        if (length > 0) {
            memcpy(encoded + offset, data, length);
        }
        offset += length;
    } else {
        int header = write_length(encoded + offset, length, 0x80, 0xB7);
        if (header <= 0) {
            free(encoded);
            return -1;
        }
        offset += (size_t)header;
        memcpy(encoded + offset, data, length);
        offset += length;
    }

    buffer->data = encoded;
    buffer->length = offset;
    return 0;
}

int lantern_rlp_encode_uint64(struct lantern_rlp_buffer *buffer, uint64_t value) {
    uint8_t bytes[8];
    size_t length = 0;
    if (value == 0) {
        return lantern_rlp_encode_bytes(buffer, NULL, 0);
    }

    for (size_t i = 0; i < sizeof(bytes); ++i) {
        bytes[sizeof(bytes) - 1 - i] = (uint8_t)(value & 0xFF);
        value >>= 8;
    }

    while (length < sizeof(bytes) && bytes[length] == 0) {
        ++length;
    }

    const uint8_t *start = bytes + length;
    size_t remaining = sizeof(bytes) - length;
    return lantern_rlp_encode_bytes(buffer, start, remaining);
}

int lantern_rlp_encode_list(
    struct lantern_rlp_buffer *buffer,
    const struct lantern_rlp_buffer *items,
    size_t item_count) {
    if (!buffer || (!items && item_count > 0)) {
        return -1;
    }

    lantern_rlp_buffer_reset(buffer);

    size_t payload_length = 0;
    for (size_t i = 0; i < item_count; ++i) {
        if (items[i].length == 0 || !items[i].data) {
            return -1;
        }
        if (size_add_overflow(payload_length, items[i].length, &payload_length)) {
            return -1;
        }
    }

    size_t header_length = rlp_list_header_length(payload_length);
    size_t total = 0;
    if (size_add_overflow(header_length, payload_length, &total)) {
        return -1;
    }

    uint8_t *encoded = malloc(total);
    if (!encoded) {
        return -1;
    }

    size_t offset = 0;
    int header_written = write_length(encoded, payload_length, 0xC0, 0xF7);
    if (header_written <= 0) {
        free(encoded);
        return -1;
    }
    offset += (size_t)header_written;

    for (size_t i = 0; i < item_count; ++i) {
        memcpy(encoded + offset, items[i].data, items[i].length);
        offset += items[i].length;
    }

    buffer->data = encoded;
    buffer->length = offset;
    return 0;
}

static bool cursor_read(const struct lantern_rlp_cursor *cursor, size_t offset, size_t size) {
    return offset <= cursor->length && size <= cursor->length - offset;
}

static int read_long_length(struct lantern_rlp_cursor *cursor, size_t len_of_len, size_t *out_length) {
    if (len_of_len == 0 || len_of_len > sizeof(size_t)) {
        return -1;
    }
    if (!cursor_read(cursor, cursor->offset, len_of_len)) {
        return -1;
    }

    size_t value = 0;
    for (size_t i = 0; i < len_of_len; ++i) {
        uint8_t byte = cursor->data[cursor->offset + i];
        if (value > (SIZE_MAX >> 8)) {
            return -1;
        }
        value = (value << 8) | byte;
    }

    cursor->offset += len_of_len;
    *out_length = value;
    return 0;
}

static int decode_list_payload(
    struct lantern_rlp_cursor *cursor,
    size_t payload_length,
    struct lantern_rlp_view *view);

static int decode_item(struct lantern_rlp_cursor *cursor, struct lantern_rlp_view *view) {
    if (!cursor || !view) {
        return -1;
    }
    lantern_rlp_view_zero(view);

    if (cursor->offset >= cursor->length) {
        return -1;
    }

    uint8_t prefix = cursor->data[cursor->offset++];
    if (prefix <= 0x7F) {
        view->kind = LANTERN_RLP_KIND_BYTES;
        view->data = &cursor->data[cursor->offset - 1];
        view->length = 1;
        return 0;
    }

    if (prefix <= 0xB7) {
        size_t str_len = (size_t)(prefix - 0x80);
        if (!cursor_read(cursor, cursor->offset, str_len)) {
            return -1;
        }
        view->kind = LANTERN_RLP_KIND_BYTES;
        view->data = cursor->data + cursor->offset;
        view->length = str_len;
        cursor->offset += str_len;
        return 0;
    }

    if (prefix <= 0xBF) {
        size_t len_of_len = (size_t)(prefix - 0xB7);
        size_t str_len = 0;
        if (read_long_length(cursor, len_of_len, &str_len) != 0) {
            return -1;
        }
        if (!cursor_read(cursor, cursor->offset, str_len)) {
            return -1;
        }
        view->kind = LANTERN_RLP_KIND_BYTES;
        view->data = cursor->data + cursor->offset;
        view->length = str_len;
        cursor->offset += str_len;
        return 0;
    }

    if (prefix <= 0xF7) {
        size_t payload_length = (size_t)(prefix - 0xC0);
        const uint8_t *payload_start = cursor->data + cursor->offset;
        if (!cursor_read(cursor, cursor->offset, payload_length)) {
            return -1;
        }
        if (decode_list_payload(cursor, payload_length, view) != 0) {
            return -1;
        }
        view->data = payload_start;
        view->length = payload_length;
        return 0;
    }

    size_t len_of_len = (size_t)(prefix - 0xF7);
    size_t payload_length = 0;
    if (read_long_length(cursor, len_of_len, &payload_length) != 0) {
        return -1;
    }
    const uint8_t *payload_start = cursor->data + cursor->offset;
    if (!cursor_read(cursor, cursor->offset, payload_length)) {
        return -1;
    }
    if (decode_list_payload(cursor, payload_length, view) != 0) {
        return -1;
    }
    view->data = payload_start;
    view->length = payload_length;
    return 0;
}

static int decode_list_payload(
    struct lantern_rlp_cursor *cursor,
    size_t payload_length,
    struct lantern_rlp_view *view) {
    struct lantern_rlp_cursor nested = {
        .data = cursor->data + cursor->offset,
        .length = payload_length,
        .offset = 0,
    };

    size_t capacity = 0;
    struct lantern_rlp_view *items = NULL;
    size_t count = 0;

    while (nested.offset < nested.length) {
        if (count == capacity) {
            size_t new_capacity = capacity == 0 ? 4 : capacity * 2;
            struct lantern_rlp_view *resized = realloc(items, new_capacity * sizeof(*resized));
            if (!resized) {
                goto error;
            }
            for (size_t i = capacity; i < new_capacity; ++i) {
                lantern_rlp_view_zero(&resized[i]);
            }
            items = resized;
            capacity = new_capacity;
        }
        if (decode_item(&nested, &items[count]) != 0) {
            goto error;
        }
        count++;
    }

    if (nested.offset != nested.length) {
        goto error;
    }

    cursor->offset += payload_length;
    view->kind = LANTERN_RLP_KIND_LIST;
    view->items = items;
    view->item_count = count;
    return 0;

error:
    if (items) {
        for (size_t i = 0; i < count; ++i) {
            lantern_rlp_view_reset(&items[i]);
        }
    }
    free(items);
    return -1;
}

int lantern_rlp_decode(const uint8_t *encoded, size_t encoded_length, struct lantern_rlp_view *out_view) {
    if (!encoded || encoded_length == 0 || !out_view) {
        return -1;
    }

    lantern_rlp_view_zero(out_view);

    struct lantern_rlp_cursor cursor = {
        .data = encoded,
        .length = encoded_length,
        .offset = 0,
    };

    if (decode_item(&cursor, out_view) != 0) {
        lantern_rlp_view_reset(out_view);
        return -1;
    }

    if (cursor.offset != cursor.length) {
        lantern_rlp_view_reset(out_view);
        return -1;
    }
    return 0;
}

int lantern_rlp_view_as_uint64(const struct lantern_rlp_view *view, uint64_t *out_value) {
    if (!view || !out_value || view->kind != LANTERN_RLP_KIND_BYTES || view->length > sizeof(uint64_t)
        || (view->length > 0 && !view->data)) {
        return -1;
    }

    uint64_t value = 0;
    for (size_t i = 0; i < view->length; ++i) {
        value = (value << 8) | view->data[i];
    }
    *out_value = value;
    return 0;
}
