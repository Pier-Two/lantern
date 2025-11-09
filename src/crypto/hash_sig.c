#include "lantern/crypto/hash_sig.h"

#include "pq-bindings-c-rust.h"

bool lantern_hash_sig_is_available(void) {
    /*
     * pq_get_lifetime() is part of the public c-hash-sig API.  A non-zero
     * lifetime means the Rust bindings initialised correctly and returned the
     * scheme configuration constants.
     */
    return pq_get_lifetime() > 0u;
}
