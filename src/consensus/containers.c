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

    LanternVote *items = realloc(list->data, new_capacity * sizeof(*items));
    if (!items) {
        return -1;
    }

    list->data = items;
    list->capacity = new_capacity;
    return 0;
}

static int ensure_signature_capacity(LanternBlockSignatures *list, size_t required) {
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

    LanternSignature *items = realloc(list->data, new_capacity * sizeof(*items));
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

int lantern_attestations_append(LanternAttestations *list, const LanternVote *vote) {
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

void lantern_block_signatures_init(LanternBlockSignatures *list) {
    if (!list) {
        return;
    }
    list->data = NULL;
    list->length = 0;
    list->capacity = 0;
}

void lantern_block_signatures_reset(LanternBlockSignatures *list) {
    if (!list) {
        return;
    }
    free(list->data);
    list->data = NULL;
    list->length = 0;
    list->capacity = 0;
}

int lantern_block_signatures_append(LanternBlockSignatures *list, const LanternSignature *signature) {
    if (!list || !signature) {
        return -1;
    }
    if (ensure_signature_capacity(list, list->length + 1) != 0) {
        return -1;
    }
    list->data[list->length++] = *signature;
    return 0;
}

int lantern_block_signatures_copy(LanternBlockSignatures *dst, const LanternBlockSignatures *src) {
    if (!dst || !src) {
        return -1;
    }
    if (src->length == 0) {
        lantern_block_signatures_reset(dst);
        lantern_block_signatures_init(dst);
        return 0;
    }
    if (ensure_signature_capacity(dst, src->length) != 0) {
        return -1;
    }
    memcpy(dst->data, src->data, src->length * sizeof(*src->data));
    dst->length = src->length;
    return 0;
}

int lantern_block_signatures_resize(LanternBlockSignatures *list, size_t new_length) {
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
    if (ensure_signature_capacity(list, new_length) != 0) {
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

void lantern_block_with_attestation_init(LanternBlockWithAttestation *block) {
    if (!block) {
        return;
    }
    memset(block, 0, sizeof(*block));
    lantern_block_body_init(&block->block.body);
}

void lantern_block_with_attestation_reset(LanternBlockWithAttestation *block) {
    if (!block) {
        return;
    }
    lantern_block_body_reset(&block->block.body);
    memset(block, 0, sizeof(*block));
}

void lantern_signed_block_with_attestation_init(LanternSignedBlockWithAttestation *block) {
    if (!block) {
        return;
    }
    lantern_block_with_attestation_init(&block->message);
    lantern_block_signatures_init(&block->signatures);
}

void lantern_signed_block_with_attestation_reset(LanternSignedBlockWithAttestation *block) {
    if (!block) {
        return;
    }
    lantern_block_with_attestation_reset(&block->message);
    lantern_block_signatures_reset(&block->signatures);
}
