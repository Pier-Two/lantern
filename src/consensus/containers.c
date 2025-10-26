#include "lantern/consensus/containers.h"

#include <stdlib.h>
#include <string.h>

static int ensure_capacity(LanternAttestations *list, size_t required) {
    if (!list) {
        return -1;
    }
    if (list->capacity >= required) {
        return 0;
    }

    size_t new_capacity = list->capacity == 0 ? 4 : list->capacity;
    while (new_capacity < required) {
        if (new_capacity > (SIZE_MAX / 2)) {
            return -1;
        }
        new_capacity *= 2;
    }

    LanternSignedVote *items = realloc(list->data, new_capacity * sizeof(*items));
    if (!items) {
        return -1;
    }

    list->data = items;
    list->capacity = new_capacity;
    return 0;
}

void lantern_attestations_init(LanternAttestations *list) {
    if (!list) {
        return;
    }
    list->data = NULL;
    list->length = 0;
    list->capacity = 0;
}

void lantern_attestations_reset(LanternAttestations *list) {
    if (!list) {
        return;
    }
    free(list->data);
    list->data = NULL;
    list->length = 0;
    list->capacity = 0;
}

int lantern_attestations_append(LanternAttestations *list, const LanternSignedVote *vote) {
    if (!list || !vote) {
        return -1;
    }
    if (ensure_capacity(list, list->length + 1) != 0) {
        return -1;
    }
    list->data[list->length++] = *vote;
    return 0;
}

int lantern_attestations_copy(LanternAttestations *dst, const LanternAttestations *src) {
    if (!dst || !src) {
        return -1;
    }
    if (src->length == 0) {
        lantern_attestations_reset(dst);
        lantern_attestations_init(dst);
        return 0;
    }
    if (ensure_capacity(dst, src->length) != 0) {
        return -1;
    }
    memcpy(dst->data, src->data, src->length * sizeof(*src->data));
    dst->length = src->length;
    return 0;
}

int lantern_attestations_resize(LanternAttestations *list, size_t new_length) {
    if (!list) {
        return -1;
    }
    if (new_length == 0) {
        if (list->data && list->length > 0) {
            memset(list->data, 0, list->length * sizeof(*list->data));
        }
        list->length = 0;
        return 0;
    }
    if (ensure_capacity(list, new_length) != 0) {
        return -1;
    }
    if (!list->data) {
        return -1;
    }
    size_t old_length = list->length;
    if (new_length > old_length) {
        size_t start = old_length;
        size_t added = new_length - old_length;
        memset(&list->data[start], 0, added * sizeof(*list->data));
    } else if (new_length < old_length) {
        size_t removed = old_length - new_length;
        memset(&list->data[new_length], 0, removed * sizeof(*list->data));
    }
    list->length = new_length;
    return 0;
}

void lantern_block_body_init(LanternBlockBody *body) {
    if (!body) {
        return;
    }
    lantern_attestations_init(&body->attestations);
}

void lantern_block_body_reset(LanternBlockBody *body) {
    if (!body) {
        return;
    }
    lantern_attestations_reset(&body->attestations);
}
