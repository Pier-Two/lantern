#ifndef LANTERN_CRYPTO_HASH_SIG_H
#define LANTERN_CRYPTO_HASH_SIG_H

#include <stdbool.h>

/**
 * Return true when the post-quantum hash signature library is linked in and responsive.
 */
bool lantern_hash_sig_is_available(void);

#endif /* LANTERN_CRYPTO_HASH_SIG_H */
