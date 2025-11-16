#ifndef LANTERN_CORE_CLIENT_TYPES_H
#define LANTERN_CORE_CLIENT_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "lantern/consensus/containers.h"
#include "lantern/consensus/state.h"
#include "pq-bindings-c-rust.h"

#ifdef __cplusplus
extern "C" {
#endif

struct lantern_validator_record;

struct lantern_pending_block {
    LanternSignedBlock block;
    LanternRoot root;
    LanternRoot parent_root;
    char peer_text[128];
    bool parent_requested;
};

struct lantern_pending_block_list {
    struct lantern_pending_block *items;
    size_t length;
    size_t capacity;
};

struct lantern_validator_duty_state {
    uint64_t last_slot;
    uint32_t last_interval;
    bool have_timepoint;
    bool slot_proposed;
    bool slot_attested;
    bool pending_local_proposal;
    uint64_t pending_local_index;
    bool proposal_signal_pending;
};

struct lantern_local_validator {
    uint64_t global_index;
    const struct lantern_validator_record *registry;
    uint8_t *secret;
    size_t secret_len;
    bool has_secret;
    struct PQSignatureSchemeSecretKey *secret_key;
    bool has_secret_handle;
    uint64_t last_proposed_slot;
    uint64_t last_attested_slot;
    LanternSignedVote pending_attestation;
    uint64_t pending_attestation_slot;
    bool has_pending_attestation;
};

#ifdef __cplusplus
}
#endif

#endif /* LANTERN_CORE_CLIENT_TYPES_H */
