#include "lantern/enr.h"

#include "internal/strings.h"
#include "lantern/rlp.h"
#include "multiformats/multibase/encoding/base64_url.h"

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void lantern_enr_key_value_reset(struct lantern_enr_key_value *pair) {
    if (!pair) {
        return;
    }
    free(pair->key);
    pair->key = NULL;
    free(pair->value);
    pair->value = NULL;
    pair->value_len = 0;
}

void lantern_enr_record_init(struct lantern_enr_record *record) {
    if (!record) {
        return;
    }
    record->encoded = NULL;
    record->signature = NULL;
    record->signature_len = 0;
    record->sequence = 0;
    record->pairs = NULL;
    record->pair_count = 0;
}

void lantern_enr_record_reset(struct lantern_enr_record *record) {
    if (!record) {
        return;
    }
    free(record->encoded);
    record->encoded = NULL;
    free(record->signature);
    record->signature = NULL;
    record->signature_len = 0;
    record->sequence = 0;
    if (record->pairs) {
        for (size_t i = 0; i < record->pair_count; ++i) {
            lantern_enr_key_value_reset(&record->pairs[i]);
        }
        free(record->pairs);
    }
    record->pairs = NULL;
    record->pair_count = 0;
}

void lantern_enr_record_list_init(struct lantern_enr_record_list *list) {
    if (!list) {
        return;
    }
    list->records = NULL;
    list->count = 0;
    list->capacity = 0;
}

void lantern_enr_record_list_reset(struct lantern_enr_record_list *list) {
    if (!list) {
        return;
    }
    if (list->records) {
        for (size_t i = 0; i < list->count; ++i) {
            lantern_enr_record_reset(&list->records[i]);
        }
        free(list->records);
    }
    list->records = NULL;
    list->count = 0;
    list->capacity = 0;
}

static int lantern_enr_record_list_reserve(struct lantern_enr_record_list *list, size_t new_capacity) {
    if (!list) {
        return -1;
    }
    if (new_capacity <= list->capacity) {
        return 0;
    }
    size_t adjusted = list->capacity == 0 ? 4 : list->capacity;
    while (adjusted < new_capacity) {
        adjusted *= 2;
    }

    struct lantern_enr_record *records = realloc(list->records, adjusted * sizeof(*records));
    if (!records) {
        return -1;
    }
    for (size_t i = list->capacity; i < adjusted; ++i) {
        lantern_enr_record_init(&records[i]);
    }
    list->records = records;
    list->capacity = adjusted;
    return 0;
}

static int base64url_decode(const char *input, uint8_t **out_bytes, size_t *out_len) {
    if (!input || !out_bytes || !out_len) {
        return -1;
    }
    size_t input_len = strlen(input);
    if (input_len == 0) {
        return -1;
    }

    uint8_t *decoded = malloc(input_len);
    if (!decoded) {
        return -1;
    }

    int written = multibase_base64_url_decode(input, input_len, decoded, input_len);
    if (written < 0) {
        free(decoded);
        return -1;
    }

    *out_bytes = decoded;
    *out_len = (size_t)written;
    return 0;
}

static int copy_signature(struct lantern_enr_record *record, const struct lantern_rlp_view *signature) {
    if (!record || !signature || signature->kind != LANTERN_RLP_KIND_BYTES || signature->length == 0) {
        return -1;
    }
    uint8_t *copy = malloc(signature->length);
    if (!copy) {
        return -1;
    }
    memcpy(copy, signature->data, signature->length);
    record->signature = copy;
    record->signature_len = signature->length;
    return 0;
}

static int copy_pairs(struct lantern_enr_record *record, const struct lantern_rlp_view *items, size_t item_count) {
    if (!record || !items || item_count < 2 || ((item_count - 2) % 2) != 0) {
        return -1;
    }

    size_t pair_count = (item_count - 2) / 2;
    if (pair_count == 0) {
        record->pairs = NULL;
        record->pair_count = 0;
        return 0;
    }

    struct lantern_enr_key_value *pairs = calloc(pair_count, sizeof(*pairs));
    if (!pairs) {
        return -1;
    }

    size_t pair_index = 0;
    for (size_t i = 2; i < item_count; i += 2) {
        const struct lantern_rlp_view *key_view = &items[i];
        const struct lantern_rlp_view *value_view = &items[i + 1];
        if (key_view->kind != LANTERN_RLP_KIND_BYTES || key_view->length == 0) {
            goto error;
        }
        char *key = lantern_string_duplicate_len((const char *)key_view->data, key_view->length);
        if (!key) {
            goto error;
        }
        uint8_t *value = NULL;
        if (value_view->length > 0) {
            value = malloc(value_view->length);
            if (!value) {
                free(key);
                goto error;
            }
            memcpy(value, value_view->data, value_view->length);
        }

        pairs[pair_index].key = key;
        pairs[pair_index].value = value;
        pairs[pair_index].value_len = value_view->length;
        pair_index++;
    }

    record->pairs = pairs;
    record->pair_count = pair_count;
    return 0;

error:
    for (size_t j = 0; j < pair_count; ++j) {
        lantern_enr_key_value_reset(&pairs[j]);
    }
    free(pairs);
    return -1;
}

int lantern_enr_record_decode(const char *enr_text, struct lantern_enr_record *record) {
    if (!enr_text || !record) {
        return -1;
    }

    struct lantern_enr_record temp;
    lantern_enr_record_init(&temp);

    while (isspace((unsigned char)*enr_text)) {
        ++enr_text;
    }

    if (strncmp(enr_text, "enr:", 4) != 0) {
        return -1;
    }
    const char *payload = enr_text + 4;
    if (*payload == '\0') {
        return -1;
    }

    temp.encoded = lantern_string_duplicate(enr_text);
    if (!temp.encoded) {
        return -1;
    }

    uint8_t *encoded_bytes = NULL;
    size_t encoded_len = 0;
    if (base64url_decode(payload, &encoded_bytes, &encoded_len) != 0) {
        goto error;
    }

    struct lantern_rlp_view root;
    memset(&root, 0, sizeof(root));
    int root_ready = 0;
    if (lantern_rlp_decode(encoded_bytes, encoded_len, &root) != 0) {
        goto error;
    }
    root_ready = 1;

    if (root.kind != LANTERN_RLP_KIND_LIST || root.item_count < 2 || ((root.item_count - 2) % 2) != 0) {
        goto error;
    }

    if (copy_signature(&temp, &root.items[0]) != 0) {
        goto error;
    }

    if (lantern_rlp_view_as_uint64(&root.items[1], &temp.sequence) != 0) {
        goto error;
    }

    if (copy_pairs(&temp, root.items, root.item_count) != 0) {
        goto error;
    }

    lantern_rlp_view_reset(&root);
    root_ready = 0;
    free(encoded_bytes);
    encoded_bytes = NULL;
    lantern_enr_record_reset(record);
    *record = temp;
    return 0;

error:
    if (root_ready) {
        lantern_rlp_view_reset(&root);
    }
    free(encoded_bytes);
    lantern_enr_record_reset(&temp);
    return -1;
}

const struct lantern_enr_key_value *lantern_enr_record_find(const struct lantern_enr_record *record, const char *key) {
    if (!record || !key) {
        return NULL;
    }
    for (size_t i = 0; i < record->pair_count; ++i) {
        if (record->pairs[i].key && strcmp(record->pairs[i].key, key) == 0) {
            return &record->pairs[i];
        }
    }
    return NULL;
}

int lantern_enr_record_list_append(struct lantern_enr_record_list *list, const char *enr_text) {
    if (!list || !enr_text) {
        return -1;
    }
    if (lantern_enr_record_list_reserve(list, list->count + 1) != 0) {
        return -1;
    }

    struct lantern_enr_record *record = &list->records[list->count];
    if (lantern_enr_record_decode(enr_text, record) != 0) {
        lantern_enr_record_reset(record);
        return -1;
    }
    list->count++;
    return 0;
}
