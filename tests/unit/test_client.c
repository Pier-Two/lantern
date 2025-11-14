#include "lantern/core/client.h"
#include "lantern/consensus/hash.h"
#include "lantern/consensus/signature.h"
#include "lantern/networking/enr.h"
#include "lantern/networking/libp2p.h"
#include "lantern/networking/reqresp_service.h"
#include "lantern/support/strings.h"
#include "lantern/support/time.h"
#include "protocol/identify/protocol_identify.h"
#include "protocol/ping/protocol_ping.h"

#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#ifndef LANTERN_TEST_FIXTURE_DIR
#error "LANTERN_TEST_FIXTURE_DIR must be defined"
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static void fill_root_with_index(LanternRoot *root, uint32_t index);

static void build_fixture_path(char *buffer, size_t length, const char *relative) {
    int written = snprintf(buffer, length, "%s/%s", LANTERN_TEST_FIXTURE_DIR, relative);
    if (written <= 0 || (size_t)written >= length) {
        fprintf(stderr, "Failed to compose fixture path for %s\n", relative);
    }
}

#define LOOPBACK_STUB_BASE_PORT 12000

struct stub_peer_config {
    const char *name;
    const char *privkey_hex;
};

static const struct stub_peer_config kStubPeerConfigs[] = {
    {"ream_0", "1111111111111111111111111111111111111111111111111111111111111111"},
    {"ream_1", "2222222222222222222222222222222222222222222222222222222222222222"},
    {"zeam_2", "3333333333333333333333333333333333333333333333333333333333333333"},
    {"zeam_3", "4444444444444444444444444444444444444444444444444444444444444444"},
    {"qlean_4", "5555555555555555555555555555555555555555555555555555555555555555"},
    {"qlean_5", "6666666666666666666666666666666666666666666666666666666666666666"},
    {"lantern_6", "7777777777777777777777777777777777777777777777777777777777777777"},
};

#define STUB_PEER_COUNT (sizeof(kStubPeerConfigs) / sizeof(kStubPeerConfigs[0]))

struct stub_peer_runtime {
    struct lantern_libp2p_host host;
    struct lantern_enr_record enr;
    uint16_t port;
    libp2p_protocol_server_t *identify_server;
    libp2p_protocol_server_t *ping_server;
    bool ping_running;
    struct lantern_reqresp_service reqresp;
    bool reqresp_running;
};

struct stub_network_context {
    struct stub_peer_runtime peers[STUB_PEER_COUNT];
    size_t count;
    char nodes_path[PATH_MAX];
};

static int stub_build_status(void *context, LanternStatusMessage *out_status) {
    if (!context || !out_status) {
        return -1;
    }
    struct stub_peer_runtime *peer = (struct stub_peer_runtime *)context;
    memset(out_status, 0, sizeof(*out_status));
    fill_root_with_index(&out_status->finalized.root, peer->port);
    out_status->finalized.slot = peer->port;
    out_status->head = out_status->finalized;
    return 0;
}

static int stub_handle_status(void *context, const LanternStatusMessage *peer_status, const char *peer_id) {
    (void)context;
    (void)peer_status;
    (void)peer_id;
    return 0;
}

static void stub_status_failure(void *context, const char *peer_id, int error) {
    (void)context;
    (void)peer_id;
    (void)error;
}

static int stub_collect_blocks(
    void *context,
    const LanternRoot *roots,
    size_t root_count,
    LanternBlocksByRootResponse *out_blocks) {
    (void)context;
    (void)roots;
    (void)root_count;
    if (!out_blocks) {
        return -1;
    }
    return lantern_blocks_by_root_response_resize(out_blocks, 0);
}

static int stub_build_status(void *context, LanternStatusMessage *out_status);
static int stub_handle_status(void *context, const LanternStatusMessage *peer_status, const char *peer_id);
static void stub_status_failure(void *context, const char *peer_id, int error);
static int stub_collect_blocks(
    void *context,
    const LanternRoot *roots,
    size_t root_count,
    LanternBlocksByRootResponse *out_blocks);

static void stub_network_teardown(struct stub_network_context *ctx) {
    if (!ctx) {
        return;
    }
    for (size_t i = 0; i < ctx->count; ++i) {
        if (ctx->peers[i].reqresp_running) {
            lantern_reqresp_service_reset(&ctx->peers[i].reqresp);
            ctx->peers[i].reqresp_running = false;
        }
        if (ctx->peers[i].ping_running && ctx->peers[i].host.host && ctx->peers[i].ping_server) {
            libp2p_ping_service_stop(ctx->peers[i].host.host, ctx->peers[i].ping_server);
        }
        ctx->peers[i].ping_server = NULL;
        ctx->peers[i].ping_running = false;
        if (ctx->peers[i].identify_server && ctx->peers[i].host.host) {
            libp2p_identify_service_stop(ctx->peers[i].host.host, ctx->peers[i].identify_server);
        }
        ctx->peers[i].identify_server = NULL;
        lantern_libp2p_host_reset(&ctx->peers[i].host);
        lantern_enr_record_reset(&ctx->peers[i].enr);
    }
    ctx->count = 0;
    if (ctx->nodes_path[0] != '\0') {
        (void)remove(ctx->nodes_path);
        ctx->nodes_path[0] = '\0';
    }
}

static int stub_network_initialize(struct stub_network_context *ctx) {
    if (!ctx) {
        return -1;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->count = STUB_PEER_COUNT;
    for (size_t i = 0; i < STUB_PEER_COUNT; ++i) {
        struct stub_peer_runtime *peer = &ctx->peers[i];
        lantern_libp2p_host_init(&peer->host);
        lantern_enr_record_init(&peer->enr);
        peer->port = (uint16_t)(LOOPBACK_STUB_BASE_PORT + (uint16_t)i);
        peer->identify_server = NULL;
        peer->ping_server = NULL;
        peer->ping_running = false;
        lantern_reqresp_service_init(&peer->reqresp);
        peer->reqresp_running = false;

        uint8_t secret[32];
        if (lantern_hex_decode(kStubPeerConfigs[i].privkey_hex, secret, sizeof(secret)) != 0) {
            fprintf(stderr, "Failed to decode stub peer privkey for %s\n", kStubPeerConfigs[i].name);
            memset(secret, 0, sizeof(secret));
            stub_network_teardown(ctx);
            return -1;
        }

        char listen_multiaddr[128];
        int written = snprintf(
            listen_multiaddr, sizeof(listen_multiaddr), "/ip4/127.0.0.1/udp/%u/quic-v1", (unsigned)peer->port);
        if (written <= 0 || (size_t)written >= sizeof(listen_multiaddr)) {
            fprintf(stderr, "Failed to compose stub listen address\n");
            memset(secret, 0, sizeof(secret));
            stub_network_teardown(ctx);
            return -1;
        }

        struct lantern_libp2p_config cfg = {
            .listen_multiaddr = listen_multiaddr,
            .secp256k1_secret = secret,
            .secret_len = sizeof(secret),
            .allow_outbound_identify = 1,
        };
        if (lantern_libp2p_host_start(&peer->host, &cfg) != 0) {
            fprintf(stderr, "Failed to start stub peer host for %s\n", kStubPeerConfigs[i].name);
            memset(secret, 0, sizeof(secret));
            stub_network_teardown(ctx);
            return -1;
        }

        if (libp2p_identify_service_start(peer->host.host, &peer->identify_server) != 0) {
            fprintf(stderr, "Failed to start identify service for stub peer %s\n", kStubPeerConfigs[i].name);
            memset(secret, 0, sizeof(secret));
            stub_network_teardown(ctx);
            return -1;
        }

        if (libp2p_ping_service_start(peer->host.host, &peer->ping_server) != 0) {
            fprintf(stderr, "Failed to start ping service for stub peer %s\n", kStubPeerConfigs[i].name);
            memset(secret, 0, sizeof(secret));
            stub_network_teardown(ctx);
            return -1;
        }
        peer->ping_running = true;

        struct lantern_reqresp_service_callbacks reqresp_callbacks = {
            .context = peer,
            .build_status = stub_build_status,
            .handle_status = stub_handle_status,
            .status_failure = stub_status_failure,
            .collect_blocks = stub_collect_blocks,
        };
        struct lantern_reqresp_service_config reqresp_cfg = {
            .host = peer->host.host,
            .callbacks = &reqresp_callbacks,
        };
        if (lantern_reqresp_service_start(&peer->reqresp, &reqresp_cfg) != 0) {
            fprintf(stderr, "Failed to start req/resp service for stub peer %s\n", kStubPeerConfigs[i].name);
            memset(secret, 0, sizeof(secret));
            stub_network_teardown(ctx);
            return -1;
        }
        peer->reqresp_running = true;

        if (lantern_enr_record_build_v4(&peer->enr, secret, "127.0.0.1", peer->port, 1) != 0) {
            fprintf(stderr, "Failed to build ENR for stub peer %s\n", kStubPeerConfigs[i].name);
            memset(secret, 0, sizeof(secret));
            stub_network_teardown(ctx);
            return -1;
        }

        memset(secret, 0, sizeof(secret));
    }

    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir || tmpdir[0] == '\0') {
        tmpdir = "/tmp";
    }
    int path_written = snprintf(
        ctx->nodes_path, sizeof(ctx->nodes_path), "%s/lantern_client_stub_nodes_%ld.yaml", tmpdir, (long)getpid());
    if (path_written <= 0 || (size_t)path_written >= sizeof(ctx->nodes_path)) {
        fprintf(stderr, "Failed to compose stub nodes path\n");
        stub_network_teardown(ctx);
        return -1;
    }

    FILE *fp = fopen(ctx->nodes_path, "w");
    if (!fp) {
        perror("lantern_client_stub_nodes fopen");
        stub_network_teardown(ctx);
        return -1;
    }
    for (size_t i = 0; i < ctx->count; ++i) {
        if (!ctx->peers[i].enr.encoded) {
            fclose(fp);
            stub_network_teardown(ctx);
            return -1;
        }
        if (fprintf(fp, "- %s\n", ctx->peers[i].enr.encoded) < 0) {
            fclose(fp);
            stub_network_teardown(ctx);
            return -1;
        }
    }
    fclose(fp);
    return 0;
}

static bool string_list_contains(const struct lantern_string_list *list, const char *value) {
    if (!list || !value) {
        return false;
    }
    for (size_t i = 0; i < list->len; ++i) {
        if (list->items && list->items[i] && strcmp(list->items[i], value) == 0) {
            return true;
        }
    }
    return false;
}

static void fill_root(LanternRoot *root, uint8_t seed) {
    if (!root) {
        return;
    }
    for (size_t i = 0; i < LANTERN_ROOT_SIZE; ++i) {
        root->bytes[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static void fill_root_with_index(LanternRoot *root, uint32_t index) {
    if (!root) {
        return;
    }
    memset(root->bytes, 0, sizeof(root->bytes));
    for (size_t i = 0; i < sizeof(index) && i < LANTERN_ROOT_SIZE; ++i) {
        root->bytes[i] = (uint8_t)((index >> (8u * i)) & 0xFFu);
    }
    for (size_t i = sizeof(index); i < LANTERN_ROOT_SIZE; ++i) {
        root->bytes[i] = (uint8_t)((index + i) & 0xFFu);
    }
}

static int slot_for_root(struct lantern_client *client, const LanternRoot *root, uint64_t *out_slot) {
    if (!client || !root || !out_slot || !client->has_fork_choice) {
        return -1;
    }
    if (lantern_fork_choice_block_info(&client->fork_choice, root, out_slot, NULL, NULL) != 0) {
        return -1;
    }
    return 0;
}

static int advance_fork_choice_intervals(LanternForkChoice *store, size_t count, bool has_proposal) {
    if (!store || store->seconds_per_interval == 0) {
        return -1;
    }
    for (size_t i = 0; i < count; ++i) {
        uint64_t next_interval = store->time_intervals + 1u;
        uint64_t now = store->config.genesis_time + (next_interval * store->seconds_per_interval);
        if (now < store->config.genesis_time) {
            return -1;
        }
        if (lantern_fork_choice_advance_time(store, now, has_proposal) != 0) {
            return -1;
        }
    }
    return 0;
}

static bool pending_contains_root(const struct lantern_client *client, const LanternRoot *root) {
    if (!client || !root) {
        return false;
    }
    size_t count = lantern_client_pending_block_count(client);
    for (size_t i = 0; i < count; ++i) {
        LanternRoot candidate;
        if (lantern_client_debug_pending_entry(client, i, &candidate, NULL, NULL, NULL, 0) != 0) {
            continue;
        }
        if (memcmp(candidate.bytes, root->bytes, LANTERN_ROOT_SIZE) == 0) {
            return true;
        }
    }
    return false;
}

static int setup_vote_validation_client(
    struct lantern_client *client,
    const char *node_id,
    struct PQSignatureSchemePublicKey **out_pub,
    struct PQSignatureSchemeSecretKey **out_secret,
    LanternRoot *anchor_root,
    LanternRoot *child_root) {
    if (!client || !out_pub || !out_secret) {
        return -1;
    }
    int rc = -1;
    struct PQSignatureSchemePublicKey *pub = NULL;
    struct PQSignatureSchemeSecretKey *secret = NULL;
    LanternBlock anchor;
    LanternBlock child;
    bool anchor_body_init = false;
    bool child_body_init = false;
    LanternRoot anchor_root_local;
    LanternRoot child_root_local;
    memset(&anchor_root_local, 0, sizeof(anchor_root_local));
    memset(&child_root_local, 0, sizeof(child_root_local));

    memset(client, 0, sizeof(*client));
    client->node_id = (char *)node_id;
    lantern_state_init(&client->state);
    lantern_fork_choice_init(&client->fork_choice);

    if (pthread_mutex_init(&client->state_lock, NULL) != 0) {
        fprintf(stderr, "failed to initialize state mutex for vote test\n");
        return -1;
    }
    client->state_lock_initialized = true;

    double now_seconds = lantern_time_now_seconds();
    if (now_seconds < 0.0) {
        now_seconds = 0.0;
    }
    uint64_t genesis_time = (uint64_t)now_seconds;

    if (lantern_state_generate_genesis(&client->state, genesis_time, 1) != 0) {
        fprintf(stderr, "failed to generate genesis for vote test\n");
        goto finish;
    }
    client->has_state = true;

    if (lantern_fork_choice_configure(&client->fork_choice, &client->state.config) != 0) {
        fprintf(stderr, "failed to configure fork choice for vote test\n");
        goto finish;
    }

    LanternRoot anchor_state_root;
    if (lantern_hash_tree_root_state(&client->state, &anchor_state_root) != 0) {
        fprintf(stderr, "failed to hash anchor state for vote test\n");
        goto finish;
    }
    client->state.latest_block_header.state_root = anchor_state_root;

    memset(&anchor, 0, sizeof(anchor));
    lantern_block_body_init(&anchor.body);
    anchor_body_init = true;
    anchor.slot = 0;
    anchor.proposer_index = 0;
    anchor.parent_root = client->state.latest_block_header.parent_root;
    anchor.state_root = anchor_state_root;

    if (lantern_hash_tree_root_block(&anchor, &anchor_root_local) != 0) {
        fprintf(stderr, "failed to hash anchor block for vote test\n");
        goto finish;
    }
    client->state.latest_justified.root = anchor_root_local;
    client->state.latest_justified.slot = anchor.slot;
    client->state.latest_finalized = client->state.latest_justified;
    if (lantern_state_mark_justified_slot(&client->state, anchor.slot) != 0) {
        fprintf(stderr, "failed to seed justified slot window for vote test\n");
        goto finish;
    }

    if (lantern_fork_choice_set_anchor(
            &client->fork_choice,
            &anchor,
            &client->state.latest_justified,
            &client->state.latest_finalized,
            &anchor_root_local)
        != 0) {
        fprintf(stderr, "failed to set anchor for vote test\n");
        goto finish;
    }

    memset(&child, 0, sizeof(child));
    lantern_block_body_init(&child.body);
    child_body_init = true;
    child.slot = anchor.slot + 1u;
    child.proposer_index = 0;
    child.parent_root = anchor_root_local;
    fill_root(&child.state_root, 0xA1);

    if (lantern_hash_tree_root_block(&child, &child_root_local) != 0) {
        fprintf(stderr, "failed to hash child block for vote test\n");
        goto finish;
    }

    if (lantern_fork_choice_add_block(
            &client->fork_choice,
            &child,
            NULL,
            &client->state.latest_justified,
            &client->state.latest_finalized,
            &child_root_local)
        != 0) {
        fprintf(stderr, "failed to add child block for vote test\n");
        goto finish;
    }

    lantern_state_attach_fork_choice(&client->state, &client->fork_choice);
    client->has_fork_choice = true;

    enum PQSigningError key_err = pq_key_gen(0, 1024, &pub, &secret);
    if (key_err != Success || !pub || !secret) {
        fprintf(stderr, "pq_key_gen failed for vote test (%d)\n", (int)key_err);
        goto finish;
    }

    uint8_t serialized_pub[LANTERN_VALIDATOR_PUBKEY_SIZE];
    uintptr_t written = 0;
    enum PQSigningError serialize_err = pq_public_key_serialize(pub, serialized_pub, sizeof(serialized_pub), &written);
    if (serialize_err != Success || written == 0 || written > sizeof(serialized_pub)) {
        fprintf(stderr, "failed to serialize pubkey for vote test (%d)\n", (int)serialize_err);
        goto finish;
    }
    if (written < sizeof(serialized_pub)) {
        memset(serialized_pub + written, 0, sizeof(serialized_pub) - written);
    }

    if (lantern_state_set_validator_pubkeys(&client->state, serialized_pub, 1) != 0) {
        fprintf(stderr, "failed to set validator pubkeys for vote test\n");
        goto finish;
    }

    if (anchor_root) {
        *anchor_root = anchor_root_local;
    }
    if (child_root) {
        *child_root = child_root_local;
    }
    *out_pub = pub;
    *out_secret = secret;
    rc = 0;

finish:
    if (anchor_body_init) {
        lantern_block_body_reset(&anchor.body);
    }
    if (child_body_init) {
        lantern_block_body_reset(&child.body);
    }
    if (rc != 0) {
        if (secret) {
            pq_secret_key_free(secret);
            secret = NULL;
        }
        if (pub) {
            pq_public_key_free(pub);
            pub = NULL;
        }
        if (client->has_fork_choice) {
            lantern_fork_choice_reset(&client->fork_choice);
            client->has_fork_choice = false;
        }
        if (client->has_state) {
            lantern_state_reset(&client->state);
            client->has_state = false;
        }
        if (client->state_lock_initialized) {
            pthread_mutex_destroy(&client->state_lock);
            client->state_lock_initialized = false;
        }
    }
    return rc;
}

static void teardown_vote_validation_client(
    struct lantern_client *client,
    struct PQSignatureSchemePublicKey *pub,
    struct PQSignatureSchemeSecretKey *secret) {
    if (secret) {
        pq_secret_key_free(secret);
    }
    if (pub) {
        pq_public_key_free(pub);
    }
    if (client->has_fork_choice) {
        lantern_fork_choice_reset(&client->fork_choice);
        client->has_fork_choice = false;
    }
    if (client->has_state) {
        lantern_state_reset(&client->state);
        client->has_state = false;
    }
    if (client->state_lock_initialized) {
        pthread_mutex_destroy(&client->state_lock);
        client->state_lock_initialized = false;
    }
}

static int sign_vote_with_secret(LanternSignedVote *vote, struct PQSignatureSchemeSecretKey *secret) {
    if (!vote || !secret) {
        return -1;
    }
    LanternRoot vote_root;
    if (lantern_hash_tree_root_vote(&vote->data, &vote_root) != 0) {
        return -1;
    }
    if (!lantern_signature_sign(secret, vote->data.slot, vote_root.bytes, sizeof(vote_root.bytes), &vote->signature)) {
        return -1;
    }
    return 0;
}

static int test_record_vote_accepts_known_roots(void) {
    struct lantern_client client;
    struct PQSignatureSchemePublicKey *pub = NULL;
    struct PQSignatureSchemeSecretKey *secret = NULL;
    LanternRoot anchor_root;
    LanternRoot child_root;
    int rc = 1;

    if (setup_vote_validation_client(&client, "vote_known", &pub, &secret, &anchor_root, &child_root) != 0) {
        return 1;
    }

    LanternSignedVote vote;
    memset(&vote, 0, sizeof(vote));
    uint64_t child_slot = 0;
    if (slot_for_root(&client, &child_root, &child_slot) != 0) {
        fprintf(stderr, "failed to resolve child slot for known roots test\n");
        goto cleanup;
    }
    vote.data.validator_id = 0;
    vote.data.slot = 2;
    vote.data.head.slot = child_slot;
    vote.data.head.root = child_root;
    vote.data.target.slot = child_slot;
    vote.data.target.root = child_root;
    vote.data.source.slot = 0;
    vote.data.source.root = anchor_root;

    if (sign_vote_with_secret(&vote, secret) != 0) {
        fprintf(stderr, "failed to sign vote with known roots\n");
        goto cleanup;
    }

    if (lantern_client_debug_record_vote(&client, &vote, "vote_known_peer") != 0) {
        fprintf(stderr, "lantern_client_debug_record_vote failed for known roots\n");
        goto cleanup;
    }

    if (!lantern_state_validator_has_vote(&client.state, 0)) {
        fprintf(stderr, "known root vote was not stored\n");
        goto cleanup;
    }

    LanternSignedVote stored;
    memset(&stored, 0, sizeof(stored));
    if (lantern_state_get_signed_validator_vote(&client.state, 0, &stored) != 0) {
        fprintf(stderr, "failed to fetch stored vote\n");
        goto cleanup;
    }
    if (memcmp(&stored.data, &vote.data, sizeof(vote.data)) != 0) {
        fprintf(stderr, "stored vote data mismatch\n");
        goto cleanup;
    }
    if (memcmp(&stored.signature, &vote.signature, sizeof(vote.signature)) != 0) {
        fprintf(stderr, "stored vote signature mismatch\n");
        goto cleanup;
    }

    rc = 0;

cleanup:
    teardown_vote_validation_client(&client, pub, secret);
    return rc;
}

static int test_record_vote_rejects_unknown_head(void) {
    struct lantern_client client;
    struct PQSignatureSchemePublicKey *pub = NULL;
    struct PQSignatureSchemeSecretKey *secret = NULL;
    LanternRoot anchor_root;
    LanternRoot child_root;
    int rc = 1;

    if (setup_vote_validation_client(&client, "vote_unknown", &pub, &secret, &anchor_root, &child_root) != 0) {
        return 1;
    }

    LanternSignedVote vote;
    memset(&vote, 0, sizeof(vote));
    uint64_t child_slot = 0;
    if (slot_for_root(&client, &child_root, &child_slot) != 0) {
        fprintf(stderr, "failed to resolve child slot for unknown head test\n");
        goto cleanup;
    }
    vote.data.validator_id = 0;
    vote.data.slot = 2;
    vote.data.head.slot = child_slot;
    fill_root(&vote.data.head.root, 0xEE);
    vote.data.target.slot = child_slot;
    vote.data.target.root = child_root;
    vote.data.source.slot = 0;
    vote.data.source.root = anchor_root;

    if (sign_vote_with_secret(&vote, secret) != 0) {
        fprintf(stderr, "failed to sign vote with unknown head\n");
        goto cleanup;
    }

    if (lantern_state_validator_has_vote(&client.state, 0)) {
        fprintf(stderr, "validator unexpectedly had a stored vote before test\n");
        goto cleanup;
    }

    if (lantern_client_debug_record_vote(&client, &vote, "vote_unknown_peer") != 0) {
        fprintf(stderr, "lantern_client_debug_record_vote failed for unknown head\n");
        goto cleanup;
    }

    if (lantern_state_validator_has_vote(&client.state, 0)) {
        fprintf(stderr, "unknown head vote should not be stored\n");
        goto cleanup;
    }

    if (client.fork_choice.new_votes && client.fork_choice.validator_count > 0) {
        for (size_t i = 0; i < client.fork_choice.validator_count; ++i) {
            if (client.fork_choice.new_votes[i].has_checkpoint) {
                fprintf(stderr, "unknown head vote updated fork choice new_votes\n");
                goto cleanup;
            }
        }
    }

    rc = 0;

cleanup:
    teardown_vote_validation_client(&client, pub, secret);
    return rc;
}

static int test_record_vote_rejects_slot_mismatch(void) {
    struct lantern_client client;
    struct PQSignatureSchemePublicKey *pub = NULL;
    struct PQSignatureSchemeSecretKey *secret = NULL;
    LanternRoot anchor_root;
    LanternRoot child_root;
    int rc = 1;

    if (setup_vote_validation_client(&client, "vote_slot_mismatch", &pub, &secret, &anchor_root, &child_root) != 0) {
        return 1;
    }

    LanternSignedVote vote;
    memset(&vote, 0, sizeof(vote));
    uint64_t child_slot = 0;
    if (slot_for_root(&client, &child_root, &child_slot) != 0) {
        fprintf(stderr, "failed to resolve child slot for slot mismatch test\n");
        goto cleanup;
    }
    vote.data.validator_id = 0;
    vote.data.slot = 2;
    uint64_t mismatch_slot = child_slot >= UINT64_MAX - 5u ? UINT64_MAX : child_slot + 5u;
    vote.data.head.slot = mismatch_slot;
    vote.data.head.root = child_root;
    vote.data.target.slot = child_slot;
    vote.data.target.root = child_root;
    vote.data.source.slot = 0;
    vote.data.source.root = anchor_root;

    if (sign_vote_with_secret(&vote, secret) != 0) {
        fprintf(stderr, "failed to sign slot mismatch vote\n");
        goto cleanup;
    }

    if (lantern_state_validator_has_vote(&client.state, 0)) {
        fprintf(stderr, "validator unexpectedly had a stored vote before slot mismatch test\n");
        goto cleanup;
    }

    lantern_client_debug_record_vote(&client, &vote, "slot_mismatch_peer");

    if (lantern_state_validator_has_vote(&client.state, 0)) {
        fprintf(stderr, "slot mismatch vote should have been rejected\n");
        goto cleanup;
    }

    if (client.fork_choice.new_votes && client.fork_choice.validator_count > 0) {
        for (size_t i = 0; i < client.fork_choice.validator_count; ++i) {
            if (client.fork_choice.new_votes[i].has_checkpoint) {
                fprintf(stderr, "slot mismatch vote updated fork choice cache\n");
                goto cleanup;
            }
        }
    }

    rc = 0;

cleanup:
    teardown_vote_validation_client(&client, pub, secret);
    return rc;
}

static int test_record_vote_rejects_future_slot(void) {
    struct lantern_client client;
    struct PQSignatureSchemePublicKey *pub = NULL;
    struct PQSignatureSchemeSecretKey *secret = NULL;
    LanternRoot anchor_root;
    LanternRoot child_root;
    int rc = 1;

    if (setup_vote_validation_client(&client, "vote_future_slot", &pub, &secret, &anchor_root, &child_root) != 0) {
        return 1;
    }

    uint64_t current_slot = 0;
    double now_seconds = lantern_time_now_seconds();
    if (now_seconds < 0.0) {
        now_seconds = 0.0;
    }
    uint32_t seconds_per_slot = client.fork_choice.seconds_per_slot == 0 ? 1u : client.fork_choice.seconds_per_slot;
    uint64_t now = (uint64_t)now_seconds;
    if (now >= client.fork_choice.config.genesis_time) {
        current_slot = (now - client.fork_choice.config.genesis_time) / seconds_per_slot;
    }
    uint64_t allowed_slot = current_slot == UINT64_MAX ? UINT64_MAX : current_slot + 1u;
    uint64_t future_slot = allowed_slot == UINT64_MAX ? UINT64_MAX : allowed_slot + 8u;
    if (future_slot <= allowed_slot) {
        future_slot = allowed_slot + 1u;
    }

    LanternSignedVote vote;
    memset(&vote, 0, sizeof(vote));
    uint64_t child_slot = 0;
    if (slot_for_root(&client, &child_root, &child_slot) != 0) {
        fprintf(stderr, "failed to resolve child slot for future slot test\n");
        goto cleanup;
    }
    vote.data.validator_id = 0;
    vote.data.slot = future_slot;
    vote.data.head.slot = child_slot;
    vote.data.head.root = child_root;
    vote.data.target.slot = child_slot;
    vote.data.target.root = child_root;
    vote.data.source.slot = 0;
    vote.data.source.root = anchor_root;

    lantern_client_debug_record_vote(&client, &vote, "future_slot_peer");

    if (lantern_state_validator_has_vote(&client.state, 0)) {
        fprintf(stderr, "future slot vote should have been dropped\n");
        goto cleanup;
    }

    rc = 0;

cleanup:
    teardown_vote_validation_client(&client, pub, secret);
    return rc;
}

static int test_record_vote_preserves_state_root(void) {
    struct lantern_client client;
    struct PQSignatureSchemePublicKey *pub = NULL;
    struct PQSignatureSchemeSecretKey *secret = NULL;
    LanternRoot anchor_root;
    LanternRoot child_root;
    int rc = 1;

    if (setup_vote_validation_client(&client, "vote_root", &pub, &secret, &anchor_root, &child_root) != 0) {
        return 1;
    }

    LanternCheckpoint pre_justified = client.state.latest_justified;
    LanternCheckpoint pre_finalized = client.state.latest_finalized;
    LanternRoot pre_state_root;
    if (lantern_hash_tree_root_state(&client.state, &pre_state_root) != 0) {
        fprintf(stderr, "failed to hash pre-vote state\n");
        goto cleanup;
    }

    LanternSignedVote vote;
    memset(&vote, 0, sizeof(vote));
    uint64_t child_slot = 0;
    if (slot_for_root(&client, &child_root, &child_slot) != 0) {
        fprintf(stderr, "failed to resolve child slot for root preservation test\n");
        goto cleanup;
    }
    vote.data.validator_id = 0;
    vote.data.slot = 2;
    vote.data.head.slot = child_slot;
    vote.data.head.root = child_root;
    vote.data.target.slot = child_slot;
    vote.data.target.root = child_root;
    vote.data.source.slot = 0;
    vote.data.source.root = anchor_root;

    if (sign_vote_with_secret(&vote, secret) != 0) {
        fprintf(stderr, "failed to sign vote for root preservation test\n");
        goto cleanup;
    }

    if (lantern_client_debug_record_vote(&client, &vote, "vote_root_peer") != 0) {
        fprintf(stderr, "lantern_client_debug_record_vote failed for root preservation test\n");
        goto cleanup;
    }

    LanternRoot post_state_root;
    if (lantern_hash_tree_root_state(&client.state, &post_state_root) != 0) {
        fprintf(stderr, "failed to hash post-vote state\n");
        goto cleanup;
    }

    if (memcmp(pre_state_root.bytes, post_state_root.bytes, LANTERN_ROOT_SIZE) != 0) {
        fprintf(stderr, "state root changed after gossip vote\n");
        goto cleanup;
    }
    if (client.state.latest_justified.slot != pre_justified.slot
        || memcmp(client.state.latest_justified.root.bytes, pre_justified.root.bytes, LANTERN_ROOT_SIZE) != 0) {
        fprintf(stderr, "latest_justified changed after gossip vote\n");
        goto cleanup;
    }
    if (client.state.latest_finalized.slot != pre_finalized.slot
        || memcmp(client.state.latest_finalized.root.bytes, pre_finalized.root.bytes, LANTERN_ROOT_SIZE) != 0) {
        fprintf(stderr, "latest_finalized changed after gossip vote\n");
        goto cleanup;
    }

    rc = 0;

cleanup:
    teardown_vote_validation_client(&client, pub, secret);
    return rc;
}

static int test_record_vote_defers_interval_pipeline(void) {
    struct lantern_client client;
    struct PQSignatureSchemePublicKey *pub = NULL;
    struct PQSignatureSchemeSecretKey *secret = NULL;
    LanternRoot anchor_root;
    LanternRoot child_root;
    int rc = 1;

    if (setup_vote_validation_client(&client, "vote_interval", &pub, &secret, &anchor_root, &child_root) != 0) {
        return 1;
    }

    LanternSignedVote vote;
    memset(&vote, 0, sizeof(vote));
    uint64_t child_slot = 0;
    if (slot_for_root(&client, &child_root, &child_slot) != 0) {
        fprintf(stderr, "failed to resolve child slot for interval pipeline test\n");
        goto cleanup;
    }
    vote.data.validator_id = 0;
    vote.data.slot = child_slot;
    vote.data.head.slot = child_slot;
    vote.data.head.root = child_root;
    vote.data.target.slot = child_slot;
    vote.data.target.root = child_root;
    vote.data.source.slot = 0;
    vote.data.source.root = anchor_root;

    if (sign_vote_with_secret(&vote, secret) != 0) {
        fprintf(stderr, "failed to sign vote for interval pipeline test\n");
        goto cleanup;
    }

    LanternRoot safe_before = client.fork_choice.safe_target;
    bool had_safe_before = client.fork_choice.has_safe_target;

    if (lantern_client_debug_record_vote(&client, &vote, "vote_interval_peer") != 0) {
        fprintf(stderr, "lantern_client_debug_record_vote failed for interval pipeline test\n");
        goto cleanup;
    }

    struct lantern_fork_choice_vote_entry *new_entry = client.fork_choice.new_votes;
    struct lantern_fork_choice_vote_entry *known_entry = client.fork_choice.known_votes;
    if (!new_entry || !known_entry) {
        fprintf(stderr, "fork choice vote tables unavailable for interval pipeline test\n");
        goto cleanup;
    }
    if (!new_entry->has_checkpoint) {
        fprintf(stderr, "gossip vote missing from new_votes immediately after record\n");
        goto cleanup;
    }
    if (known_entry->has_checkpoint) {
        fprintf(stderr, "known_votes updated before interval pipeline advanced\n");
        goto cleanup;
    }
    if (had_safe_before) {
        if (memcmp(client.fork_choice.safe_target.bytes, safe_before.bytes, LANTERN_ROOT_SIZE) != 0) {
            fprintf(stderr, "safe target changed before interval 2\n");
            goto cleanup;
        }
    }

    if (advance_fork_choice_intervals(&client.fork_choice, 1, false) != 0) {
        fprintf(stderr, "failed to advance fork choice to interval 1\n");
        goto cleanup;
    }
    if (!new_entry->has_checkpoint) {
        fprintf(stderr, "new_votes lost checkpoint before interval 2\n");
        goto cleanup;
    }
    if (known_entry->has_checkpoint) {
        fprintf(stderr, "known_votes filled before interval 2\n");
        goto cleanup;
    }
    if (had_safe_before) {
        if (memcmp(client.fork_choice.safe_target.bytes, safe_before.bytes, LANTERN_ROOT_SIZE) != 0) {
            fprintf(stderr, "safe target changed during interval 1\n");
            goto cleanup;
        }
    }

    if (advance_fork_choice_intervals(&client.fork_choice, 1, false) != 0) {
        fprintf(stderr, "failed to advance fork choice to interval 2\n");
        goto cleanup;
    }
    if (!client.fork_choice.has_safe_target) {
        fprintf(stderr, "safe target unavailable after interval 2\n");
        goto cleanup;
    }
    if (memcmp(client.fork_choice.safe_target.bytes, child_root.bytes, LANTERN_ROOT_SIZE) != 0) {
        fprintf(stderr, "safe target did not reflect gossip vote after interval 2\n");
        goto cleanup;
    }
    if (!new_entry->has_checkpoint) {
        fprintf(stderr, "new_votes checkpoint missing after interval 2\n");
        goto cleanup;
    }
    if (known_entry->has_checkpoint) {
        fprintf(stderr, "known_votes filled before interval 3\n");
        goto cleanup;
    }

    if (advance_fork_choice_intervals(&client.fork_choice, 1, false) != 0) {
        fprintf(stderr, "failed to advance fork choice to interval 3\n");
        goto cleanup;
    }
    if (!known_entry->has_checkpoint) {
        fprintf(stderr, "known_votes missing checkpoint after interval 3\n");
        goto cleanup;
    }
    if (known_entry->checkpoint.slot != vote.data.target.slot
        || memcmp(known_entry->checkpoint.root.bytes, child_root.bytes, LANTERN_ROOT_SIZE) != 0) {
        fprintf(stderr, "known_votes checkpoint mismatch after interval 3\n");
        goto cleanup;
    }
    if (new_entry->has_checkpoint) {
        fprintf(stderr, "new_votes retained checkpoint after migration\n");
        goto cleanup;
    }

    rc = 0;

cleanup:
    teardown_vote_validation_client(&client, pub, secret);
    return rc;
}

static int test_pending_block_queue(void) {
    struct lantern_client client;
    memset(&client, 0, sizeof(client));
    client.node_id = "test_pending_queue";

    if (pthread_mutex_init(&client.pending_lock, NULL) != 0) {
        fprintf(stderr, "failed to initialize pending mutex\n");
        return 1;
    }
    client.pending_lock_initialized = true;
    lantern_client_debug_pending_reset(&client);

    if (pthread_mutex_init(&client.status_lock, NULL) != 0) {
        fprintf(stderr, "failed to initialize status mutex\n");
        pthread_mutex_destroy(&client.pending_lock);
        client.pending_lock_initialized = false;
        return 1;
    }
    client.status_lock_initialized = true;

    LanternSignedBlock child;
    memset(&child, 0, sizeof(child));
    lantern_block_body_init(&child.message.body);
    child.message.slot = 10;

    LanternRoot child_root;
    LanternRoot parent_root;
    fill_root(&child_root, 0x10);
    fill_root(&parent_root, 0x20);

    const char *peer_a = "12D3KooWpeerA";
    const char *peer_b = "12D3KooWpeerB";
    LanternRoot fetched_root;
    LanternRoot fetched_parent;
    bool parent_requested = true;
    char peer_text[128];
    LanternRoot last_root;
    fill_root_with_index(&last_root, 0);
    int rc = 0;

    if (lantern_client_debug_enqueue_pending_block(&client, &child, &child_root, &parent_root, peer_a) != 0) {
        fprintf(stderr, "failed to enqueue initial pending block\n");
        rc = 1;
        goto cleanup;
    }

    if (lantern_client_pending_block_count(&client) != 1) {
        fprintf(stderr, "pending queue count mismatch after first enqueue\n");
        rc = 1;
        goto cleanup;
    }

    if (lantern_client_debug_pending_entry(&client, 0, &fetched_root, &fetched_parent, &parent_requested, peer_text, sizeof(peer_text)) != 0) {
        fprintf(stderr, "failed to fetch pending entry\n");
        rc = 1;
        goto cleanup;
    }
    if (memcmp(fetched_root.bytes, child_root.bytes, LANTERN_ROOT_SIZE) != 0) {
        fprintf(stderr, "pending root mismatch after first enqueue\n");
        rc = 1;
        goto cleanup;
    }
    if (memcmp(fetched_parent.bytes, parent_root.bytes, LANTERN_ROOT_SIZE) != 0) {
        fprintf(stderr, "pending parent mismatch after first enqueue\n");
        rc = 1;
        goto cleanup;
    }
    if (strcmp(peer_text, peer_a) != 0) {
        fprintf(stderr, "pending peer mismatch after first enqueue\n");
        rc = 1;
        goto cleanup;
    }
    if (parent_requested) {
        fprintf(stderr, "parent_requested unexpectedly set after schedule failure\n");
        rc = 1;
        goto cleanup;
    }

    if (lantern_client_debug_enqueue_pending_block(&client, &child, &child_root, &parent_root, peer_b) != 0) {
        fprintf(stderr, "failed to enqueue duplicate pending block\n");
        rc = 1;
        goto cleanup;
    }

    if (lantern_client_pending_block_count(&client) != 1) {
        fprintf(stderr, "pending queue count changed after duplicate enqueue\n");
        rc = 1;
        goto cleanup;
    }

    parent_requested = true;
    if (lantern_client_debug_pending_entry(&client, 0, &fetched_root, &fetched_parent, &parent_requested, peer_text, sizeof(peer_text)) != 0) {
        fprintf(stderr, "failed to fetch pending entry after duplicate enqueue\n");
        rc = 1;
        goto cleanup;
    }
    if (strcmp(peer_text, peer_b) != 0) {
        fprintf(stderr, "pending peer did not update after duplicate enqueue\n");
        rc = 1;
        goto cleanup;
    }

    if (lantern_client_debug_set_parent_requested(&client, &child_root, true) != 0) {
        fprintf(stderr, "failed to mark parent_requested for pending block\n");
        rc = 1;
        goto cleanup;
    }

    parent_requested = false;
    if (lantern_client_debug_pending_entry(&client, 0, NULL, NULL, &parent_requested, NULL, 0) != 0 || !parent_requested) {
        fprintf(stderr, "parent_requested flag did not persist after manual set\n");
        rc = 1;
        goto cleanup;
    }

    if (lantern_client_debug_on_blocks_request_complete(
            &client,
            peer_b,
            &parent_root,
            LANTERN_DEBUG_BLOCKS_REQUEST_SUCCESS)
        != 0) {
        fprintf(stderr, "blocks_request_complete debug wrapper failed\n");
        rc = 1;
        goto cleanup;
    }

    parent_requested = true;
    if (lantern_client_debug_pending_entry(&client, 0, NULL, NULL, &parent_requested, NULL, 0) != 0) {
        fprintf(stderr, "failed to inspect parent_requested after completion\n");
        rc = 1;
        goto cleanup;
    }
    if (parent_requested) {
        fprintf(stderr, "parent_requested not cleared after completion\n");
        rc = 1;
        goto cleanup;
    }

    for (size_t i = 0; i < 300; ++i) {
        LanternSignedBlock extra;
        memset(&extra, 0, sizeof(extra));
        lantern_block_body_init(&extra.message.body);
        extra.message.slot = 20 + i;
        LanternRoot extra_root;
        LanternRoot extra_parent;
        fill_root_with_index(&extra_root, 1000u + (uint32_t)i);
        fill_root_with_index(&extra_parent, 2000u + (uint32_t)i);
        if (i == 299) {
            last_root = extra_root;
        }
        if (lantern_client_debug_enqueue_pending_block(&client, &extra, &extra_root, &extra_parent, NULL) != 0) {
            fprintf(stderr, "failed to enqueue additional pending block %zu\n", i);
            lantern_block_body_reset(&extra.message.body);
            rc = 1;
            goto cleanup;
        }
        lantern_block_body_reset(&extra.message.body);
    }

    size_t count = lantern_client_pending_block_count(&client);
    if (count > 256) {
        fprintf(stderr, "pending queue exceeded expected limit: %zu\n", count);
        rc = 1;
        goto cleanup;
    }

    if (pending_contains_root(&client, &child_root)) {
        fprintf(stderr, "oldest pending block was not evicted at capacity\n");
        rc = 1;
        goto cleanup;
    }

    if (!pending_contains_root(&client, &last_root)) {
        fprintf(stderr, "latest pending block missing after enqueues\n");
        rc = 1;
        goto cleanup;
    }

cleanup:
    lantern_client_debug_pending_reset(&client);
    lantern_block_body_reset(&child.message.body);
    if (client.status_lock_initialized) {
        pthread_mutex_destroy(&client.status_lock);
        client.status_lock_initialized = false;
    }
    if (client.pending_lock_initialized) {
        pthread_mutex_destroy(&client.pending_lock);
        client.pending_lock_initialized = false;
    }
    return rc;
}

static int test_import_block_parent_mismatch(void) {
    struct lantern_client client;
    memset(&client, 0, sizeof(client));
    client.node_id = "test_parent_mismatch";

    int rc = 0;
    LanternSignedBlock block;
    LanternRoot block_root;
    LanternRoot parent_root;
    LanternRoot head_root;
    LanternRoot pending_root;
    LanternRoot pending_parent;
    bool parent_requested = true;
    char peer_text[128];

    if (pthread_mutex_init(&client.state_lock, NULL) != 0) {
        fprintf(stderr, "failed to initialize state mutex\n");
        return 1;
    }
    client.state_lock_initialized = true;

    if (pthread_mutex_init(&client.pending_lock, NULL) != 0) {
        fprintf(stderr, "failed to initialize pending mutex\n");
        pthread_mutex_destroy(&client.state_lock);
        client.state_lock_initialized = false;
        return 1;
    }
    client.pending_lock_initialized = true;

    lantern_client_debug_pending_reset(&client);

    lantern_state_init(&client.state);
    client.has_state = true;
    client.state.slot = 0;

    memset(&client.state.latest_block_header, 0, sizeof(client.state.latest_block_header));
    fill_root(&client.state.latest_block_header.state_root, 0x10);
    fill_root(&client.state.latest_block_header.body_root, 0x11);
    fill_root(&client.state.latest_block_header.parent_root, 0x12);
    client.state.latest_block_header.slot = 0;
    client.state.latest_block_header.proposer_index = 0;

    if (lantern_hash_tree_root_block_header(&client.state.latest_block_header, &head_root) != 0) {
        fprintf(stderr, "failed to hash latest block header\n");
        rc = 1;
        goto cleanup;
    }

    lantern_fork_choice_init(&client.fork_choice);
    LanternConfig fork_cfg = {
        .num_validators = 8,
        .genesis_time = 0,
    };
    if (lantern_fork_choice_configure(&client.fork_choice, &fork_cfg) != 0) {
        fprintf(stderr, "failed to configure fork choice\n");
        rc = 1;
        goto cleanup;
    }
    client.has_fork_choice = true;
    lantern_state_attach_fork_choice(&client.state, &client.fork_choice);

    LanternCheckpoint anchor_checkpoint = {
        .root = head_root,
        .slot = 0,
    };
    client.state.latest_justified = anchor_checkpoint;
    client.state.latest_finalized = anchor_checkpoint;

    LanternBlock anchor_block;
    memset(&anchor_block, 0, sizeof(anchor_block));
    lantern_block_body_init(&anchor_block.body);
    anchor_block.slot = 0;
    anchor_block.proposer_index = 0;
    anchor_block.parent_root = client.state.latest_block_header.parent_root;
    anchor_block.state_root = client.state.latest_block_header.state_root;

    if (lantern_fork_choice_set_anchor(
            &client.fork_choice,
            &anchor_block,
            &client.state.latest_justified,
            &client.state.latest_finalized,
            &head_root)
        != 0) {
        fprintf(stderr, "failed to set fork choice anchor\n");
        lantern_block_body_reset(&anchor_block.body);
        rc = 1;
        goto cleanup;
    }

    LanternBlock parent_block;
    memset(&parent_block, 0, sizeof(parent_block));
    lantern_block_body_init(&parent_block.body);
    parent_block.slot = 1;
    parent_block.proposer_index = 0;
    parent_block.parent_root = head_root;
    fill_root(&parent_block.state_root, 0x44);

    if (lantern_fork_choice_add_block(
            &client.fork_choice,
            &parent_block,
            NULL,
            &client.state.latest_justified,
            &client.state.latest_finalized,
            &parent_root)
        != 0) {
        fprintf(stderr, "failed to add parent block to fork choice\n");
        lantern_block_body_reset(&parent_block.body);
        lantern_block_body_reset(&anchor_block.body);
        rc = 1;
        goto cleanup;
    }
    lantern_block_body_reset(&parent_block.body);
    lantern_block_body_reset(&anchor_block.body);

    memset(&block, 0, sizeof(block));
    lantern_block_body_init(&block.message.body);
    block.message.slot = 5;
    block.message.proposer_index = 0;
    fill_root(&block_root, 0x90);
    fill_root(&parent_root, 0x20);
    if (memcmp(parent_root.bytes, head_root.bytes, LANTERN_ROOT_SIZE) == 0) {
        parent_root.bytes[0] ^= 0xFFu;
    }
    block.message.parent_root = parent_root;
    fill_root(&block.message.state_root, 0x30);

    if (lantern_client_pending_block_count(&client) != 0) {
        rc = 1;
        fprintf(stderr, "pending queue not empty at test start\n");
        goto cleanup;
    }

    if (lantern_client_debug_import_block(&client, &block, &block_root, "12D3KooWparent") != 0) {
        fprintf(stderr, "import unexpectedly succeeded for mismatched parent\n");
        rc = 1;
        goto cleanup;
    }

    if (lantern_client_pending_block_count(&client) != 1) {
        fprintf(stderr, "pending queue count mismatch after mismatched parent\n");
        rc = 1;
        goto cleanup;
    }

    memset(peer_text, 0, sizeof(peer_text));
    parent_requested = true;
    if (lantern_client_debug_pending_entry(
            &client,
            0,
            &pending_root,
            &pending_parent,
            &parent_requested,
            peer_text,
            sizeof(peer_text))
        != 0) {
        fprintf(stderr, "failed to inspect pending entry after mismatched parent\n");
        rc = 1;
        goto cleanup;
    }

    if (memcmp(pending_root.bytes, block_root.bytes, LANTERN_ROOT_SIZE) != 0) {
        fprintf(stderr, "pending root mismatch after mismatched parent\n");
        rc = 1;
        goto cleanup;
    }
    if (memcmp(pending_parent.bytes, parent_root.bytes, LANTERN_ROOT_SIZE) != 0) {
        fprintf(stderr, "pending parent root mismatch after mismatched parent\n");
        rc = 1;
        goto cleanup;
    }
    if (parent_requested) {
        fprintf(stderr, "parent_requested flag unexpectedly set after scheduling failure\n");
        rc = 1;
        goto cleanup;
    }

cleanup:
    lantern_client_debug_pending_reset(&client);
    lantern_block_body_reset(&block.message.body);
    if (client.has_fork_choice) {
        lantern_fork_choice_reset(&client.fork_choice);
        client.has_fork_choice = false;
    }
    if (client.pending_lock_initialized) {
        pthread_mutex_destroy(&client.pending_lock);
        client.pending_lock_initialized = false;
    }
    if (client.state_lock_initialized) {
        pthread_mutex_destroy(&client.state_lock);
        client.state_lock_initialized = false;
    }
    if (client.has_state) {
        lantern_state_reset(&client.state);
        client.has_state = false;
    }
    return rc;
}

static const char *placeholder_registry_value = "0x00";

static int verify_client_state(
    const struct lantern_client *client,
    const struct lantern_client_options *options,
    const uint64_t *expected_indices,
    size_t expected_count,
    uint16_t expected_udp_port) {
    if (client->genesis.chain_config.genesis_time != UINT64_C(1761717362)) {
        fprintf(stderr, "Unexpected genesis_time: %llu\n",
            (unsigned long long)client->genesis.chain_config.genesis_time);
        return 1;
    }
    if (client->genesis.chain_config.validator_count != 7) {
        fprintf(stderr, "Unexpected validator_count: %llu\n",
            (unsigned long long)client->genesis.chain_config.validator_count);
        return 1;
    }
    if (client->genesis.enrs.count != 7) {
        fprintf(stderr, "Unexpected ENR count: %zu\n", client->genesis.enrs.count);
        return 1;
    }
    if (client->genesis.enrs.count > 0) {
        const struct lantern_enr_record *first = &client->genesis.enrs.records[0];
        const struct lantern_enr_key_value *id = lantern_enr_record_find(first, "id");
        if (!id || id->value_len != 2 || memcmp(id->value, "v4", 2) != 0) {
            fprintf(stderr, "ENR id mismatch\n");
            return 1;
        }
        const struct lantern_enr_key_value *ip = lantern_enr_record_find(first, "ip");
        if (!ip || ip->value_len != 4) {
            fprintf(stderr, "ENR ip missing\n");
            return 1;
        }
    }
    if (client->genesis.validator_registry.count != 7) {
        fprintf(stderr, "Unexpected validator registry count: %zu\n", client->genesis.validator_registry.count);
        return 1;
    }
    if (client->genesis.validator_config.count != 7) {
        fprintf(stderr, "Unexpected validator config count: %zu\n", client->genesis.validator_config.count);
        return 1;
    }
    if (!client->assigned_validators || client->assigned_validators->count != expected_count) {
        fprintf(stderr, "Validator assignment missing or incorrect\n");
        return 1;
    }
    if (client->validator_assignment.count != expected_count) {
        fprintf(stderr, "Validator assignment count mismatch\n");
        return 1;
    }
    if (!expected_indices || expected_count == 0) {
        fprintf(stderr, "Expected indices missing\n");
        return 1;
    }
    if (client->validator_assignment.start_index != expected_indices[0]) {
        fprintf(stderr, "Validator assignment start index mismatch\n");
        return 1;
    }
    if (!client->local_enr.encoded) {
        fprintf(stderr, "Local ENR missing\n");
        return 1;
    }
    if (client->local_enr.sequence != client->assigned_validators->enr.sequence) {
        fprintf(stderr, "Local ENR sequence mismatch\n");
        return 1;
    }
    const struct lantern_enr_key_value *udp = lantern_enr_record_find(&client->local_enr, "udp");
    if (!udp || udp->value_len != 2) {
        fprintf(stderr, "Local ENR UDP missing\n");
        return 1;
    }
    uint16_t udp_port = (uint16_t)(((uint16_t)udp->value[0] << 8) | (uint16_t)udp->value[1]);
    if (udp_port != expected_udp_port) {
        fprintf(stderr, "Local ENR UDP mismatch\n");
        return 1;
    }
    if (!client->network.host || !client->network.started) {
        fprintf(stderr, "libp2p host missing or not started\n");
        return 1;
    }
    if (!client->gossip_running || !client->gossip.gossipsub) {
        fprintf(stderr, "gossipsub service not running\n");
        return 1;
    }

    if (lantern_client_local_validator_count(client) != expected_count) {
        fprintf(stderr, "Local validator count mismatch\n");
        return 1;
    }
    for (size_t i = 0; i < expected_count; ++i) {
        const struct lantern_local_validator *validator = lantern_client_local_validator(client, i);
        if (!validator) {
            fprintf(stderr, "Missing local validator %zu\n", i);
            return 1;
        }
        if (validator->global_index != expected_indices[i]) {
            fprintf(stderr, "Unexpected global index at %zu: expected %llu got %llu\n",
                i,
                (unsigned long long)expected_indices[i],
                (unsigned long long)validator->global_index);
            return 1;
        }
        if (!validator->registry || validator->registry->index != expected_indices[i]) {
            fprintf(stderr, "Validator registry pointer mismatch at %zu\n", i);
            return 1;
        }
        size_t global_index = (size_t)validator->registry->index;
        (void)global_index;
        if (!validator->registry->pubkey_hex
            || strcmp(validator->registry->pubkey_hex, placeholder_registry_value) != 0) {
            fprintf(stderr, "Validator registry pubkey mismatch at index %" PRIu64 "\n", validator->registry->index);
            return 1;
        }
        const char *actual_withdrawal = validator->registry->withdrawal_credentials_hex;
        if (!actual_withdrawal || strcmp(actual_withdrawal, placeholder_registry_value) != 0) {
            fprintf(stderr, "Validator registry withdrawal mismatch at index %" PRIu64 "\n", validator->registry->index);
            return 1;
        }
        if (!validator->has_secret || !validator->secret || validator->secret_len == 0) {
            fprintf(stderr, "Validator secret missing for index %zu\n", i);
            return 1;
        }
    }

    size_t expected_bootnodes = options->bootnodes.len;
    for (size_t i = 0; i < options->bootnodes.len; ++i) {
        if (!string_list_contains(&client->bootnodes, options->bootnodes.items[i])) {
            fprintf(stderr, "Missing manual bootnode: %s\n", options->bootnodes.items[i]);
            return 1;
        }
    }
    for (size_t i = 0; i < client->genesis.enrs.count; ++i) {
        const struct lantern_enr_record *record = &client->genesis.enrs.records[i];
        if (!record->encoded) {
            continue;
        }
        if (!string_list_contains(&client->bootnodes, record->encoded)) {
            fprintf(stderr, "Missing genesis bootnode: %s\n", record->encoded);
            return 1;
        }
        if (!string_list_contains(&options->bootnodes, record->encoded)) {
            ++expected_bootnodes;
        }
    }
    if (client->bootnodes.len != expected_bootnodes) {
        fprintf(
            stderr,
            "Bootnode count mismatch: expected %zu got %zu\n",
            expected_bootnodes,
            client->bootnodes.len);
        return 1;
    }
    if (!client->has_state) {
        fprintf(stderr, "Client state not initialized\n");
        return 1;
    }
    if (client->state.config.num_validators != client->genesis.chain_config.validator_count) {
        fprintf(stderr, "State validator count mismatch\n");
        return 1;
    }
    if (client->state.config.genesis_time != client->genesis.chain_config.genesis_time) {
        fprintf(stderr, "State genesis time mismatch\n");
        return 1;
    }
    if (client->assigned_validators && client->assigned_validators->privkey_hex
        && client->assigned_validators->privkey_hex[0] != '\0') {
        fprintf(stderr, "Assigned validator privkey was not cleared\n");
        return 1;
    }
    return 0;
}

int main(void) {
    if (test_record_vote_accepts_known_roots() != 0) {
        return 1;
    }
    if (test_record_vote_rejects_unknown_head() != 0) {
        return 1;
    }
    if (test_record_vote_rejects_slot_mismatch() != 0) {
        return 1;
    }
    if (test_record_vote_rejects_future_slot() != 0) {
        return 1;
    }
    if (test_record_vote_preserves_state_root() != 0) {
        return 1;
    }
    if (test_record_vote_defers_interval_pipeline() != 0) {
        return 1;
    }
    if (test_pending_block_queue() != 0) {
        return 1;
    }
    if (test_import_block_parent_mismatch() != 0) {
        return 1;
    }

    struct stub_network_context stub_network;
    bool stub_ready = false;
    if (stub_network_initialize(&stub_network) != 0) {
        fprintf(stderr, "Failed to initialize stub peer network\n");
        return 1;
    }
    stub_ready = true;

    struct lantern_client_options options;
    lantern_client_options_init(&options);

    char config_path[512];
    char registry_path[512];
    char nodes_path[512];
    char state_path[512];
    char validator_config_path[512];

    build_fixture_path(config_path, sizeof(config_path), "genesis/config.yaml");
    build_fixture_path(registry_path, sizeof(registry_path), "genesis/validators.yaml");
    build_fixture_path(nodes_path, sizeof(nodes_path), "genesis/nodes.yaml");
    build_fixture_path(state_path, sizeof(state_path), "genesis/genesis.ssz");
    build_fixture_path(validator_config_path, sizeof(validator_config_path), "genesis/validator-config.yaml");

    options.data_dir = LANTERN_TEST_FIXTURE_DIR;
    options.genesis_config_path = config_path;
    options.validator_registry_path = registry_path;
    if (stub_network.nodes_path[0] != '\0') {
        options.nodes_path = stub_network.nodes_path;
    } else {
        fprintf(stderr, "Stub nodes path missing\n");
        stub_network_teardown(&stub_network);
        lantern_client_options_free(&options);
        return 1;
    }
    options.genesis_state_path = state_path;
    options.validator_config_path = validator_config_path;
    options.node_id = "ream_0";
    options.listen_address = "/ip4/127.0.0.1/udp/9000/quic-v1";
    options.node_key_hex = "0xb71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291";
    options.metrics_port = 0;

    if (lantern_client_options_add_bootnode(&options, "enr:-ManualEnr") != 0) {
        fprintf(stderr, "Failed to add bootnode\n");
        lantern_client_options_free(&options);
        return 1;
    }

    const uint64_t ream_indices[] = {0};
    const uint64_t lantern_indices[] = {6};

    struct lantern_client client;
    bool client_ready = false;
    int exit_code = 1;

    if (lantern_init(&client, &options) != 0) {
        fprintf(stderr, "lantern_init failed for ream_0\n");
        goto cleanup;
    }
    client_ready = true;
    lantern_client_debug_disable_block_requests(&client, true);

    if (verify_client_state(&client, &options, ream_indices, 1, 9000) != 0) {
        goto cleanup;
    }

    usleep(200000);

    lantern_shutdown(&client);
    client_ready = false;
    memset(&client, 0, sizeof(client));

    options.node_id = "lantern_6";
    options.listen_address = "/ip4/127.0.0.1/udp/9100/quic-v1";

    if (lantern_init(&client, &options) != 0) {
        fprintf(stderr, "lantern_init failed for lantern_6\n");
        goto cleanup;
    }
    client_ready = true;
    lantern_client_debug_disable_block_requests(&client, true);

    if (verify_client_state(&client, &options, lantern_indices, 1, 9000) != 0) {
        goto cleanup;
    }

    usleep(200000);

    exit_code = 0;

cleanup:
    if (client_ready) {
        lantern_shutdown(&client);
    }
    lantern_client_options_free(&options);
    if (stub_ready) {
        stub_network_teardown(&stub_network);
    }
    return exit_code;
}
