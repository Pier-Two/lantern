#include "lantern/consensus/signature.h"

#include <string.h>

#include "pq-bindings-c-rust.h"

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

bool lantern_signature_verify(
    const uint8_t *pubkey_bytes,
    size_t pubkey_len,
    uint32_t epoch,
    const LanternSignature *signature,
    const uint8_t *message,
    size_t message_len) {
    if (!pubkey_bytes || pubkey_len == 0 || !signature || !message) {
        return false;
    }
    if (message_len != LANTERN_ROOT_SIZE) {
        return false;
    }

    struct PQSignatureSchemePublicKey *pq_pubkey = NULL;
    struct PQSignature *pq_signature = NULL;
    enum PQSigningError pk_err = pq_public_key_deserialize(pubkey_bytes, pubkey_len, &pq_pubkey);
    if (pk_err != Success || !pq_pubkey) {
        return false;
    }
    enum PQSigningError sig_err =
        pq_signature_deserialize(signature->bytes, sizeof(signature->bytes), &pq_signature);
    if (sig_err != Success || !pq_signature) {
        pq_public_key_free(pq_pubkey);
        return false;
    }
    int verify_rc = pq_verify(pq_pubkey, epoch, message, message_len, pq_signature);
    pq_signature_free(pq_signature);
    pq_public_key_free(pq_pubkey);
    return verify_rc == 1;
}
