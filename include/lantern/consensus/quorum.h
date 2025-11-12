#ifndef LANTERN_CONSENSUS_QUORUM_H
#define LANTERN_CONSENSUS_QUORUM_H

#include <stdint.h>

static inline uint64_t lantern_consensus_quorum_threshold(uint64_t validator_count) {
    if (validator_count == 0) {
        return 0;
    }

#if defined(__SIZEOF_INT128__)
    __uint128_t numerator = (__uint128_t)validator_count * 2u;
    uint64_t threshold = (uint64_t)((numerator + 2u) / 3u);
#else
    uint64_t numerator;
    if (validator_count > ((UINT64_MAX - 2u) / 2u)) {
        numerator = UINT64_MAX - 2u;
    } else {
        numerator = validator_count * 2u;
    }
    uint64_t threshold = (numerator + 2u) / 3u;
#endif

    if (threshold == 0) {
        threshold = 1;
    }
    return threshold;
}

#endif /* LANTERN_CONSENSUS_QUORUM_H */
