#ifndef LANTERN_CONSENSUS_CONTAINERS_H
#define LANTERN_CONSENSUS_CONTAINERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LANTERN_ROOT_SIZE 32
#define LANTERN_SIGNATURE_SIZE 32
#define LANTERN_MAX_ATTESTATIONS 4096

typedef struct {
    uint8_t bytes[LANTERN_ROOT_SIZE];
} LanternRoot;

typedef struct {
    uint8_t bytes[LANTERN_SIGNATURE_SIZE];
} LanternSignature;

typedef struct {
    uint64_t num_validators;
    uint64_t genesis_time;
} LanternConfig;

typedef struct {
    LanternRoot root;
    uint64_t slot;
} LanternCheckpoint;

typedef struct {
    uint64_t validator_id;
    uint64_t slot;
    LanternCheckpoint head;
    LanternCheckpoint target;
    LanternCheckpoint source;
} LanternVote;

typedef struct {
    LanternVote data;
    LanternSignature signature;
} LanternSignedVote;

typedef struct {
    LanternSignedVote *data;
    size_t length;
    size_t capacity;
} LanternAttestations;

typedef struct {
    LanternAttestations attestations;
} LanternBlockBody;

typedef struct {
    uint64_t slot;
    uint64_t proposer_index;
    LanternRoot parent_root;
    LanternRoot state_root;
    LanternRoot body_root;
} LanternBlockHeader;

typedef struct {
    uint64_t slot;
    uint64_t proposer_index;
    LanternRoot parent_root;
    LanternRoot state_root;
    LanternBlockBody body;
} LanternBlock;

typedef struct {
    LanternBlock message;
    LanternSignature signature;
} LanternSignedBlock;

void lantern_attestations_init(LanternAttestations *list);
void lantern_attestations_reset(LanternAttestations *list);
int lantern_attestations_append(LanternAttestations *list, const LanternSignedVote *vote);
int lantern_attestations_copy(LanternAttestations *dst, const LanternAttestations *src);
int lantern_attestations_resize(LanternAttestations *list, size_t new_length);

void lantern_block_body_init(LanternBlockBody *body);
void lantern_block_body_reset(LanternBlockBody *body);

#endif /* LANTERN_CONSENSUS_CONTAINERS_H */
