#include "lantern/consensus/signature.h"

#include <string.h>

static bool bytes_are_zero(const uint8_t *bytes, size_t length) {
    if (!bytes && length > 0) {
        return false;
    }
    for (size_t i = 0; i < length; ++i) {
        if (bytes[i] != 0u) {
            return false;
        }
    }
    return true;
}

bool lantern_signature_is_zero(const LanternSignature *signature) {
    if (!signature) {
        return false;
    }
    return bytes_are_zero(signature->bytes, LANTERN_SIGNATURE_SIZE);
}

void lantern_signature_zero(LanternSignature *signature) {
    if (!signature) {
        return;
    }
    memset(signature->bytes, 0, sizeof(signature->bytes));
}
