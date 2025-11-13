#include "lantern/consensus/containers.h"
#include "lantern/consensus/hash.h"
#include "lantern/consensus/signature.h"

#include "pq-bindings-c-rust.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void fill_root(LanternRoot *root, uint8_t seed) {
    assert(root);
    for (size_t i = 0; i < sizeof(root->bytes); ++i) {
        root->bytes[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static void init_checkpoint(LanternCheckpoint *cp, uint64_t slot, uint8_t seed) {
    assert(cp);
    cp->slot = slot;
    fill_root(&cp->root, seed);
}

static void build_proposer_vote(LanternVote *vote, uint64_t validator_id, uint64_t slot) {
    assert(vote);
    memset(vote, 0, sizeof(*vote));
    vote->validator_id = validator_id;
    vote->slot = slot;
    init_checkpoint(&vote->head, slot, 0x11);
    init_checkpoint(&vote->target, slot, 0x33);
    init_checkpoint(&vote->source, slot > 0 ? slot - 1 : 0, 0x55);
}

static int generate_test_keypair(
    struct PQSignatureSchemePublicKey **out_pub,
    struct PQSignatureSchemeSecretKey **out_secret) {
    if (!out_pub || !out_secret) {
        return -1;
    }
    *out_pub = NULL;
    *out_secret = NULL;
    enum PQSigningError err = pq_key_gen(0, 1024, out_pub, out_secret);
    if (err != Success || !*out_pub || !*out_secret) {
        if (*out_pub) {
            pq_public_key_free(*out_pub);
            *out_pub = NULL;
        }
        if (*out_secret) {
            pq_secret_key_free(*out_secret);
            *out_secret = NULL;
        }
        fprintf(stderr, "pq_key_gen failed (%d)\n", (int)err);
        return -1;
    }
    return 0;
}

static bool sign_proposer_vote(
    struct PQSignatureSchemeSecretKey *secret,
    LanternSignedVote *signed_vote,
    LanternRoot *out_vote_root) {
    if (!secret || !signed_vote || !out_vote_root) {
        return false;
    }
    if (lantern_hash_tree_root_vote(&signed_vote->data, out_vote_root) != 0) {
        fprintf(stderr, "hash_tree_root_vote failed\n");
        return false;
    }
    if (!lantern_signature_sign(
            secret,
            signed_vote->data.slot,
            out_vote_root->bytes,
            sizeof(out_vote_root->bytes),
            &signed_vote->signature)) {
        fprintf(stderr, "lantern_signature_sign failed\n");
        return false;
    }
    return true;
}

static int test_proposer_vote_signature_roundtrip(void) {
    struct PQSignatureSchemePublicKey *pubkey = NULL;
    struct PQSignatureSchemeSecretKey *secret = NULL;
    if (generate_test_keypair(&pubkey, &secret) != 0) {
        return 1;
    }

    LanternSignedVote signed_vote;
    memset(&signed_vote, 0, sizeof(signed_vote));
    build_proposer_vote(&signed_vote.data, 5, 12);

    LanternRoot vote_root;
    if (!sign_proposer_vote(secret, &signed_vote, &vote_root)) {
        pq_secret_key_free(secret);
        pq_public_key_free(pubkey);
        return 1;
    }

    if (!lantern_signature_verify_pk(
            pubkey,
            signed_vote.data.slot,
            &signed_vote.signature,
            vote_root.bytes,
            sizeof(vote_root.bytes))) {
        fprintf(stderr, "verify_pk rejected valid proposer vote\n");
        pq_secret_key_free(secret);
        pq_public_key_free(pubkey);
        return 1;
    }

    uint8_t serialized_pubkey[LANTERN_VALIDATOR_PUBKEY_SIZE];
    uintptr_t written = 0;
    enum PQSigningError serr = pq_public_key_serialize(
        pubkey,
        serialized_pubkey,
        sizeof(serialized_pubkey),
        &written);
    if (serr != Success || written == 0 || written > sizeof(serialized_pubkey)) {
        fprintf(stderr, "failed to serialize public key (%d)\n", (int)serr);
        pq_secret_key_free(secret);
        pq_public_key_free(pubkey);
        return 1;
    }

    if (!lantern_signature_verify(
            serialized_pubkey,
            (size_t)written,
            signed_vote.data.slot,
            &signed_vote.signature,
            vote_root.bytes,
            sizeof(vote_root.bytes))) {
        fprintf(stderr, "verify(bytes) rejected valid proposer vote\n");
        pq_secret_key_free(secret);
        pq_public_key_free(pubkey);
        return 1;
    }

    pq_secret_key_free(secret);
    pq_public_key_free(pubkey);
    return 0;
}

static int test_proposer_vote_signature_rejects_tampering(void) {
    struct PQSignatureSchemePublicKey *pubkey = NULL;
    struct PQSignatureSchemeSecretKey *secret = NULL;
    if (generate_test_keypair(&pubkey, &secret) != 0) {
        return 1;
    }

    LanternSignedVote signed_vote;
    memset(&signed_vote, 0, sizeof(signed_vote));
    build_proposer_vote(&signed_vote.data, 9, 3);

    LanternRoot vote_root;
    if (!sign_proposer_vote(secret, &signed_vote, &vote_root)) {
        pq_secret_key_free(secret);
        pq_public_key_free(pubkey);
        return 1;
    }

    LanternVote tampered_vote = signed_vote.data;
    tampered_vote.head.root.bytes[0] ^= 0xFF;
    LanternRoot tampered_root;
    if (lantern_hash_tree_root_vote(&tampered_vote, &tampered_root) != 0) {
        fprintf(stderr, "tampered root calculation failed\n");
        pq_secret_key_free(secret);
        pq_public_key_free(pubkey);
        return 1;
    }

    if (lantern_signature_verify_pk(
            pubkey,
            signed_vote.data.slot,
            &signed_vote.signature,
            tampered_root.bytes,
            sizeof(tampered_root.bytes))) {
        fprintf(stderr, "verify_pk accepted tampered proposer vote\n");
        pq_secret_key_free(secret);
        pq_public_key_free(pubkey);
        return 1;
    }

    pq_secret_key_free(secret);
    pq_public_key_free(pubkey);
    return 0;
}

int main(void) {
    if (test_proposer_vote_signature_roundtrip() != 0) {
        return 1;
    }
    if (test_proposer_vote_signature_rejects_tampering() != 0) {
        return 1;
    }
    puts("lantern_signature_test OK");
    return 0;
}
