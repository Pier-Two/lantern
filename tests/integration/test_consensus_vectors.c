#include "lantern/consensus/containers.h"
#include "lantern/consensus/fork_choice.h"
#include "lantern/consensus/hash.h"
#include "lantern/consensus/state.h"
#include "lantern/consensus/ssz.h"
#include "lantern/support/strings.h"

#include "jsmn.h"

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <limits.h>

#ifndef LANTERN_TEST_FIXTURE_DIR
#error "LANTERN_TEST_FIXTURE_DIR must be defined"
#endif

#define JSON_INITIAL_TOKENS 256
#define LABEL_MAX_LENGTH 64
#define MAX_LABELS 128

struct stored_vote_entry {
    bool has_vote;
    LanternVote vote;
};

struct stored_state_entry {
    LanternRoot root;
    uint8_t *data;
    size_t length;
    struct stored_vote_entry *votes;
    size_t vote_count;
};

static void stored_state_entries_reset(struct stored_state_entry **entries_ptr, size_t *count_ptr, size_t *cap_ptr) {
    if (!entries_ptr || !count_ptr || !cap_ptr) {
        return;
    }
    struct stored_state_entry *entries = *entries_ptr;
    if (entries) {
        for (size_t i = 0; i < *count_ptr; ++i) {
            free(entries[i].data);
            entries[i].data = NULL;
            entries[i].length = 0;
            free(entries[i].votes);
            entries[i].votes = NULL;
            entries[i].vote_count = 0;
        }
        free(entries);
    }
    *entries_ptr = NULL;
    *count_ptr = 0;
    *cap_ptr = 0;
}

static struct stored_state_entry *stored_state_find(
    struct stored_state_entry *entries,
    size_t count,
    const LanternRoot *root) {
    if (!entries || !root) {
        return NULL;
    }
    for (size_t i = 0; i < count; ++i) {
        if (memcmp(entries[i].root.bytes, root->bytes, LANTERN_ROOT_SIZE) == 0) {
            return &entries[i];
        }
    }
    return NULL;
}

static int stored_state_add(
    struct stored_state_entry **entries_ptr,
    size_t *count_ptr,
    size_t *cap_ptr,
    const LanternRoot *root,
    uint8_t *data,
    size_t length,
    struct stored_vote_entry *votes,
    size_t vote_count) {
    if (!entries_ptr || !count_ptr || !cap_ptr || !root || !data) {
        free(data);
        free(votes);
        return -1;
    }
    struct stored_state_entry *entries = *entries_ptr;
    size_t count = *count_ptr;
    size_t cap = *cap_ptr;

    struct stored_state_entry *existing = stored_state_find(entries, count, root);
    if (existing) {
        free(existing->data);
        existing->data = data;
        existing->length = length;
        free(existing->votes);
        existing->votes = votes;
        existing->vote_count = vote_count;
        return 0;
    }

    if (count == cap) {
        size_t new_cap = cap == 0 ? 8u : cap * 2u;
        if (new_cap < cap) {
            free(data);
            free(votes);
            return -1;
        }
        struct stored_state_entry *expanded = realloc(entries, new_cap * sizeof(*expanded));
        if (!expanded) {
            free(data);
            free(votes);
            return -1;
        }
        entries = expanded;
        *entries_ptr = entries;
        *cap_ptr = new_cap;
    }

    entries[count].root = *root;
    entries[count].data = data;
    entries[count].length = length;
    entries[count].votes = votes;
    entries[count].vote_count = vote_count;
    *count_ptr = count + 1u;
    return 0;
}

static int encode_state_to_buffer(const LanternState *state, uint8_t **out_data, size_t *out_len) {
    if (!state || !out_data || !out_len) {
        return -1;
    }
    size_t buffer_size = 1u << 18; /* 256 KiB initial */
    uint8_t *buffer = malloc(buffer_size);
    if (!buffer) {
        return -1;
    }
    while (true) {
        size_t written = 0;
        int status = lantern_ssz_encode_state(state, buffer, buffer_size, &written);
        if (status == 0) {
            uint8_t *copy = malloc(written);
            if (!copy) {
                free(buffer);
                return -1;
            }
            memcpy(copy, buffer, written);
            free(buffer);
            *out_data = copy;
            *out_len = written;
            return 0;
        }
        if (buffer_size > (1u << 24)) { /* 16 MiB cap to avoid runaway */
            free(buffer);
            return -1;
        }
        size_t new_size = buffer_size * 2u;
        uint8_t *resized = realloc(buffer, new_size);
        if (!resized) {
            free(buffer);
            return -1;
        }
        buffer = resized;
        buffer_size = new_size;
    }
}

static int stored_state_save(
    struct stored_state_entry **entries_ptr,
    size_t *count_ptr,
    size_t *cap_ptr,
    const LanternRoot *root,
    const LanternState *state) {
    if (!entries_ptr || !count_ptr || !cap_ptr || !root || !state) {
        return -1;
    }
    uint8_t *encoded = NULL;
    size_t encoded_len = 0;
    if (encode_state_to_buffer(state, &encoded, &encoded_len) != 0) {
        return -1;
    }

    size_t vote_capacity = lantern_state_validator_capacity(state);
    struct stored_vote_entry *votes = NULL;
    if (vote_capacity > 0) {
        votes = calloc(vote_capacity, sizeof(*votes));
        if (!votes) {
            free(encoded);
            return -1;
        }
        for (size_t i = 0; i < vote_capacity; ++i) {
            if (!lantern_state_validator_has_vote(state, i)) {
                continue;
            }
            LanternVote vote;
            if (lantern_state_get_validator_vote(state, i, &vote) != 0) {
                free(votes);
                free(encoded);
                return -1;
            }
            votes[i].has_vote = true;
            votes[i].vote = vote;
        }
    }

    const char *debug_hash = getenv("LANTERN_DEBUG_STATE_HASH");
    if (debug_hash && debug_hash[0] != '\0') {
        LanternRoot original_root;
        if (lantern_hash_tree_root_state(state, &original_root) == 0) {
            LanternState decoded;
            lantern_state_init(&decoded);
            if (lantern_ssz_decode_state(&decoded, encoded, encoded_len) == 0) {
                LanternRoot decoded_root;
                if (lantern_hash_tree_root_state(&decoded, &decoded_root) == 0) {
                    char original_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
                    char decoded_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
                    char key_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
                    if (lantern_bytes_to_hex(
                            original_root.bytes,
                            LANTERN_ROOT_SIZE,
                            original_hex,
                            sizeof(original_hex),
                            1)
                        == 0
                        && lantern_bytes_to_hex(
                            decoded_root.bytes,
                            LANTERN_ROOT_SIZE,
                            decoded_hex,
                            sizeof(decoded_hex),
                            1)
                            == 0
                        && lantern_bytes_to_hex(
                            root->bytes,
                            LANTERN_ROOT_SIZE,
                            key_hex,
                            sizeof(key_hex),
                            1)
                            == 0) {
                        fprintf(
                            stderr,
                            "stored state key=%s original=%s decoded=%s\n",
                            key_hex,
                            original_hex,
                            decoded_hex);
                    }
                }
            }
            lantern_state_reset(&decoded);
        }
    }

    if (stored_state_add(entries_ptr, count_ptr, cap_ptr, root, encoded, encoded_len, votes, vote_capacity) != 0) {
        free(votes);
        free(encoded);
        return -1;
    }
    return 0;
}

static int stored_state_restore(
    struct stored_state_entry *entries,
    size_t count,
    const LanternRoot *root,
    LanternState *state) {
    if (!entries || !root || !state) {
        return -1;
    }
    struct stored_state_entry *entry = stored_state_find(entries, count, root);
    if (!entry) {
        return -1;
    }
    if (lantern_ssz_decode_state(state, entry->data, entry->length) != 0) {
        return -1;
    }
    uint64_t validator_count = state->config.num_validators;
    if (validator_count == 0) {
        return -1;
    }
    if (lantern_state_prepare_validator_votes(state, validator_count) != 0) {
        return -1;
    }
    size_t capacity = lantern_state_validator_capacity(state);
    size_t copy_count = entry->vote_count < capacity ? entry->vote_count : capacity;
    if (entry->votes) {
        for (size_t i = 0; i < copy_count; ++i) {
            if (!entry->votes[i].has_vote) {
                continue;
            }
            if (lantern_state_set_validator_vote(state, i, &entry->votes[i].vote) != 0) {
                return -1;
            }
        }
    }
    const char *debug_hash = getenv("LANTERN_DEBUG_STATE_HASH");
    if (debug_hash && debug_hash[0] != '\0') {
        LanternRoot restored_root;
        if (lantern_hash_tree_root_state(state, &restored_root) == 0) {
            char restored_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
            if (lantern_bytes_to_hex(
                    restored_root.bytes,
                    LANTERN_ROOT_SIZE,
                    restored_hex,
                    sizeof(restored_hex),
                    1)
                == 0) {
                fprintf(
                    stderr,
                    "restored state slot %" PRIu64 " root: %s\n",
                    (unsigned long long)state->slot,
                    restored_hex);
            }
        }
    }
    return 0;
}

static int sync_state_to_fork_choice_head(
    LanternForkChoice *store,
    LanternState *state,
    struct stored_state_entry **entries_ptr,
    size_t *count_ptr,
    LanternRoot *current_head_root) {
    if (!store || !state || !entries_ptr || !count_ptr || !current_head_root) {
        return -1;
    }
    LanternRoot head_root;
    if (lantern_fork_choice_current_head(store, &head_root) != 0) {
        return -1;
    }
    if (memcmp(head_root.bytes, current_head_root->bytes, LANTERN_ROOT_SIZE) == 0) {
        return 0;
    }
    struct stored_state_entry *entry = stored_state_find(*entries_ptr, *count_ptr, &head_root);
    if (!entry) {
        return -1;
    }
    lantern_state_reset(state);
    if (stored_state_restore(*entries_ptr, *count_ptr, &head_root, state) != 0) {
        return -1;
    }
    lantern_state_attach_fork_choice(state, store);
    *current_head_root = head_root;
    return 0;
}

struct json_document {
    char *text;
    size_t length;
    jsmntok_t *tokens;
    int token_count;
};

struct label_entry {
    char name[LABEL_MAX_LENGTH];
    LanternRoot root;
    bool in_use;
};

struct label_registry {
    struct label_entry entries[MAX_LABELS];
};

static void label_registry_init(struct label_registry *registry) {
    if (!registry) {
        return;
    }
    memset(registry, 0, sizeof(*registry));
}

static int label_registry_assign(
    struct label_registry *registry,
    const char *label,
    const LanternRoot *root) {
    if (!registry || !label || !root) {
        return -1;
    }
    for (size_t i = 0; i < MAX_LABELS; ++i) {
        struct label_entry *entry = &registry->entries[i];
        if (!entry->in_use) {
            continue;
        }
        if (strcmp(entry->name, label) == 0) {
            if (memcmp(entry->root.bytes, root->bytes, sizeof(entry->root.bytes)) != 0) {
                fprintf(stderr, "label '%s' mapped to unexpected root\n", label);
                return -1;
            }
            return 0;
        }
    }
    for (size_t i = 0; i < MAX_LABELS; ++i) {
        struct label_entry *entry = &registry->entries[i];
        if (entry->in_use) {
            continue;
        }
        size_t len = strlen(label);
        if (len >= sizeof(entry->name)) {
            len = sizeof(entry->name) - 1u;
        }
        memcpy(entry->name, label, len);
        entry->name[len] = '\0';
        entry->root = *root;
        entry->in_use = true;
        return 0;
    }
    fprintf(stderr, "label registry full\n");
    return -1;
}

static void json_document_reset(struct json_document *doc) {
    if (!doc) {
        return;
    }
    free(doc->tokens);
    doc->tokens = NULL;
    doc->token_count = 0;
    doc->length = 0;
    free(doc->text);
    doc->text = NULL;
}

static int json_document_init(struct json_document *doc, char *text) {
    if (!doc || !text) {
        free(text);
        return -1;
    }
    doc->text = text;
    doc->length = strlen(text);
    doc->tokens = NULL;
    doc->token_count = 0;

    int capacity = JSON_INITIAL_TOKENS;
    while (capacity <= 32768) {
        jsmntok_t *tokens = (jsmntok_t *)malloc((size_t)capacity * sizeof(jsmntok_t));
        if (!tokens) {
            json_document_reset(doc);
            return -1;
        }

        jsmn_parser parser;
        jsmn_init(&parser);
        int result = jsmn_parse(&parser, doc->text, doc->length, tokens, capacity);
        if (result >= 0) {
            doc->tokens = tokens;
            doc->token_count = result;
            return 0;
        }
        free(tokens);
        if (result == JSMN_ERROR_NOMEM) {
            capacity *= 2;
            continue;
        }
        json_document_reset(doc);
        return -1;
    }

    json_document_reset(doc);
    return -1;
}

static const jsmntok_t *json_token(const struct json_document *doc, int index) {
    if (!doc || index < 0 || index >= doc->token_count) {
        return NULL;
    }
    return &doc->tokens[index];
}

static int json_skip_token(const struct json_document *doc, int index) {
    const jsmntok_t *tok = json_token(doc, index);
    if (!tok) {
        return -1;
    }
    index += 1;
    if (tok->type == JSMN_ARRAY) {
        for (int i = 0; i < tok->size; ++i) {
            index = json_skip_token(doc, index);
            if (index < 0) {
                return -1;
            }
        }
    } else if (tok->type == JSMN_OBJECT) {
        for (int i = 0; i < tok->size; ++i) {
            index = json_skip_token(doc, index);
            if (index < 0) {
                return -1;
            }
            index = json_skip_token(doc, index);
            if (index < 0) {
                return -1;
            }
        }
    }
    return index;
}

static bool json_token_equals(
    const struct json_document *doc,
    int index,
    const char *value) {
    const jsmntok_t *tok = json_token(doc, index);
    if (!tok || tok->type != JSMN_STRING || !value) {
        return false;
    }
    size_t len = strlen(value);
    size_t tok_len = (size_t)(tok->end - tok->start);
    if (tok_len != len) {
        return false;
    }
    return strncmp(doc->text + tok->start, value, len) == 0;
}

static int json_object_get_field(
    const struct json_document *doc,
    int object_index,
    const char *field) {
    const jsmntok_t *obj = json_token(doc, object_index);
    if (!obj || obj->type != JSMN_OBJECT) {
        return -1;
    }
    int index = object_index + 1;
    for (int i = 0; i < obj->size; ++i) {
        int key_index = index;
        int value_index = json_skip_token(doc, key_index);
        if (value_index < 0) {
            return -1;
        }
        if (json_token_equals(doc, key_index, field)) {
            return value_index;
        }
        index = json_skip_token(doc, value_index);
        if (index < 0) {
            return -1;
        }
    }
    return -1;
}

static int json_array_get_length(
    const struct json_document *doc,
    int array_index) {
    const jsmntok_t *arr = json_token(doc, array_index);
    if (!arr || arr->type != JSMN_ARRAY) {
        return -1;
    }
    return arr->size;
}

static int json_array_get_element(
    const struct json_document *doc,
    int array_index,
    int position) {
    const jsmntok_t *arr = json_token(doc, array_index);
    if (!arr || arr->type != JSMN_ARRAY || position < 0 || position >= arr->size) {
        return -1;
    }
    int index = array_index + 1;
    for (int i = 0; i < arr->size; ++i) {
        if (i == position) {
            return index;
        }
        index = json_skip_token(doc, index);
        if (index < 0) {
            return -1;
        }
    }
    return -1;
}

static int json_object_get_value_at(
    const struct json_document *doc,
    int object_index,
    int position) {
    const jsmntok_t *obj = json_token(doc, object_index);
    if (!obj || obj->type != JSMN_OBJECT || position < 0 || position >= obj->size) {
        return -1;
    }
    int index = object_index + 1;
    for (int i = 0; i < obj->size; ++i) {
        int key_index = index;
        index = json_skip_token(doc, key_index);
        if (index < 0) {
            return -1;
        }
        if (i == position) {
            return index;
        }
        index = json_skip_token(doc, index);
        if (index < 0) {
            return -1;
        }
    }
    return -1;
}

static int json_token_to_uint64(
    const struct json_document *doc,
    int index,
    uint64_t *out_value) {
    if (!out_value) {
        return -1;
    }
    const jsmntok_t *tok = json_token(doc, index);
    if (!tok || (tok->type != JSMN_PRIMITIVE && tok->type != JSMN_STRING)) {
        return -1;
    }
    size_t len = (size_t)(tok->end - tok->start);
    char buffer[64];
    if (len >= sizeof(buffer)) {
        return -1;
    }
    memcpy(buffer, doc->text + tok->start, len);
    buffer[len] = '\0';
    char *endptr = NULL;
    errno = 0;
    unsigned long long value = strtoull(buffer, &endptr, 10);
    if (errno != 0 || endptr == buffer || *endptr != '\0') {
        return -1;
    }
    *out_value = (uint64_t)value;
    return 0;
}

static const char *json_token_string(
    const struct json_document *doc,
    int index,
    size_t *out_length) {
    if (out_length) {
        *out_length = 0;
    }
    const jsmntok_t *tok = json_token(doc, index);
    if (!tok || tok->type != JSMN_STRING) {
        return NULL;
    }
    if (out_length) {
        *out_length = (size_t)(tok->end - tok->start);
    }
    return doc->text + tok->start;
}

static int parse_hex_bytes(
    const char *hex,
    size_t len,
    uint8_t *out,
    size_t out_len) {
    if (!hex || !out) {
        return -1;
    }
    if (len < 2 || hex[0] != '0' || (hex[1] != 'x' && hex[1] != 'X')) {
        return -1;
    }
    hex += 2;
    len -= 2;
    if (len != out_len * 2) {
        return -1;
    }
    for (size_t i = 0; i < out_len; ++i) {
        char buf[3];
        buf[0] = hex[i * 2];
        buf[1] = hex[(i * 2) + 1];
        buf[2] = '\0';
        char *endptr = NULL;
        errno = 0;
        unsigned long value = strtoul(buf, &endptr, 16);
        if (errno != 0 || !endptr || *endptr != '\0') {
            return -1;
        }
        out[i] = (uint8_t)value;
    }
    return 0;
}

static int json_token_to_root(
    const struct json_document *doc,
    int index,
    LanternRoot *root) {
    if (!root) {
        return -1;
    }
    size_t len = 0;
    const char *str = json_token_string(doc, index, &len);
    if (!str) {
        return -1;
    }
    return parse_hex_bytes(str, len, root->bytes, sizeof(root->bytes));
}

static int parse_anchor_state(
    const struct json_document *doc,
    int anchor_state_idx,
    LanternState *state,
    LanternCheckpoint *latest_justified,
    LanternCheckpoint *latest_finalized,
    uint64_t *genesis_time,
    uint64_t *validator_count) {
    if (!doc || !state || !latest_justified || !latest_finalized || !genesis_time || !validator_count) {
        return -1;
    }

    int config_idx = json_object_get_field(doc, anchor_state_idx, "config");
    if (config_idx < 0) {
        return -1;
    }
    int genesis_idx = json_object_get_field(doc, config_idx, "genesisTime");
    if (genesis_idx < 0) {
        return -1;
    }
    if (json_token_to_uint64(doc, genesis_idx, genesis_time) != 0) {
        return -1;
    }

    int validators_idx = json_object_get_field(doc, anchor_state_idx, "validators");
    if (validators_idx < 0) {
        return -1;
    }
    int data_idx = json_object_get_field(doc, validators_idx, "data");
    if (data_idx < 0) {
        return -1;
    }
    int count = json_array_get_length(doc, data_idx);
    if (count < 0) {
        return -1;
    }
    uint8_t *validator_pubkeys = NULL;
    if (count > 0) {
        size_t total_bytes = (size_t)count * LANTERN_VALIDATOR_PUBKEY_SIZE;
        validator_pubkeys = (uint8_t *)malloc(total_bytes);
        if (!validator_pubkeys) {
            return -1;
        }
        memset(validator_pubkeys, 0, total_bytes);
        for (int i = 0; i < count; ++i) {
            int entry_idx = json_array_get_element(doc, data_idx, i);
            if (entry_idx < 0) {
                free(validator_pubkeys);
                return -1;
            }
            int pubkey_idx = json_object_get_field(doc, entry_idx, "pubkey");
            if (pubkey_idx < 0) {
                free(validator_pubkeys);
                return -1;
            }
            size_t pk_len = 0;
            const char *pk_str = json_token_string(doc, pubkey_idx, &pk_len);
            if (!pk_str) {
                free(validator_pubkeys);
                return -1;
            }
            if (parse_hex_bytes(
                    pk_str,
                    pk_len,
                    validator_pubkeys + (i * LANTERN_VALIDATOR_PUBKEY_SIZE),
                    LANTERN_VALIDATOR_PUBKEY_SIZE)
                != 0) {
                free(validator_pubkeys);
                return -1;
            }
        }
    }
    *validator_count = (uint64_t)count;

    lantern_state_init(state);
    if (lantern_state_generate_genesis(state, *genesis_time, *validator_count) != 0) {
        free(validator_pubkeys);
        return -1;
    }
    if (lantern_state_prepare_validator_votes(state, *validator_count) != 0) {
        free(validator_pubkeys);
        return -1;
    }
    if (lantern_hash_tree_root_validators(
            validator_pubkeys,
            (size_t)count,
            &state->validators_root)
        != 0) {
        free(validator_pubkeys);
        return -1;
    }
    free(validator_pubkeys);

    int slot_idx = json_object_get_field(doc, anchor_state_idx, "slot");
    if (slot_idx >= 0) {
        uint64_t slot = 0;
        if (json_token_to_uint64(doc, slot_idx, &slot) != 0) {
            return -1;
        }
        state->slot = slot;
    }

    int justified_idx = json_object_get_field(doc, anchor_state_idx, "latestJustified");
    int finalized_idx = json_object_get_field(doc, anchor_state_idx, "latestFinalized");
    if (justified_idx < 0 || finalized_idx < 0) {
        return -1;
    }
    int root_idx = json_object_get_field(doc, justified_idx, "root");
    int root_slot_idx = json_object_get_field(doc, justified_idx, "slot");
    if (json_token_to_root(doc, root_idx, &latest_justified->root) != 0) {
        return -1;
    }
    if (json_token_to_uint64(doc, root_slot_idx, &latest_justified->slot) != 0) {
        return -1;
    }
    root_idx = json_object_get_field(doc, finalized_idx, "root");
    root_slot_idx = json_object_get_field(doc, finalized_idx, "slot");
    if (json_token_to_root(doc, root_idx, &latest_finalized->root) != 0) {
        return -1;
    }
    if (json_token_to_uint64(doc, root_slot_idx, &latest_finalized->slot) != 0) {
        return -1;
    }
    state->latest_justified = *latest_justified;
    state->latest_finalized = *latest_finalized;

    int header_idx = json_object_get_field(doc, anchor_state_idx, "latestBlockHeader");
    if (header_idx < 0) {
        return -1;
    }
    uint64_t header_slot = 0;
    int field_idx = json_object_get_field(doc, header_idx, "slot");
    if (json_token_to_uint64(doc, field_idx, &header_slot) != 0) {
        return -1;
    }
    state->latest_block_header.slot = header_slot;

    field_idx = json_object_get_field(doc, header_idx, "proposerIndex");
    if (json_token_to_uint64(doc, field_idx, &state->latest_block_header.proposer_index) != 0) {
        return -1;
    }

    field_idx = json_object_get_field(doc, header_idx, "parentRoot");
    if (json_token_to_root(doc, field_idx, &state->latest_block_header.parent_root) != 0) {
        return -1;
    }

    field_idx = json_object_get_field(doc, header_idx, "stateRoot");
    if (json_token_to_root(doc, field_idx, &state->latest_block_header.state_root) != 0) {
        return -1;
    }

    field_idx = json_object_get_field(doc, header_idx, "bodyRoot");
    if (json_token_to_root(doc, field_idx, &state->latest_block_header.body_root) != 0) {
        return -1;
    }

    return 0;
}

static int parse_attestations(
    const struct json_document *doc,
    int body_idx,
    LanternBlockBody *body) {
    if (!body) {
        return -1;
    }
    lantern_block_body_init(body);
    int att_idx = json_object_get_field(doc, body_idx, "attestations");
    if (att_idx < 0) {
        return 0;
    }
    int data_idx = json_object_get_field(doc, att_idx, "data");
    if (data_idx < 0) {
        return 0;
    }
    int length = json_array_get_length(doc, data_idx);
    if (length < 0) {
        return -1;
    }
    for (int i = 0; i < length; ++i) {
        int entry_idx = json_array_get_element(doc, data_idx, i);
        if (entry_idx < 0) {
            return -1;
        }
        LanternSignedVote vote;
        memset(&vote, 0, sizeof(vote));

        int validator_idx = json_object_get_field(doc, entry_idx, "validator_id");
        if (validator_idx < 0) {
            return -1;
        }
        if (json_token_to_uint64(doc, validator_idx, &vote.data.validator_id) != 0) {
            return -1;
        }

        int data_obj_idx = json_object_get_field(doc, entry_idx, "data");
        if (data_obj_idx < 0) {
            return -1;
        }

        int field_idx = json_object_get_field(doc, data_obj_idx, "slot");
        if (json_token_to_uint64(doc, field_idx, &vote.data.slot) != 0) {
            return -1;
        }

        field_idx = json_object_get_field(doc, data_obj_idx, "head");
        if (field_idx < 0) {
            return -1;
        }
        int root_idx = json_object_get_field(doc, field_idx, "root");
        if (json_token_to_root(doc, root_idx, &vote.data.head.root) != 0) {
            return -1;
        }
        root_idx = json_object_get_field(doc, field_idx, "slot");
        if (json_token_to_uint64(doc, root_idx, &vote.data.head.slot) != 0) {
            return -1;
        }

        field_idx = json_object_get_field(doc, data_obj_idx, "target");
        if (field_idx < 0) {
            return -1;
        }
        root_idx = json_object_get_field(doc, field_idx, "root");
        if (json_token_to_root(doc, root_idx, &vote.data.target.root) != 0) {
            return -1;
        }
        root_idx = json_object_get_field(doc, field_idx, "slot");
        if (json_token_to_uint64(doc, root_idx, &vote.data.target.slot) != 0) {
            return -1;
        }

        field_idx = json_object_get_field(doc, data_obj_idx, "source");
        if (field_idx < 0) {
            return -1;
        }
        root_idx = json_object_get_field(doc, field_idx, "root");
        if (json_token_to_root(doc, root_idx, &vote.data.source.root) != 0) {
            return -1;
        }
        root_idx = json_object_get_field(doc, field_idx, "slot");
        if (json_token_to_uint64(doc, root_idx, &vote.data.source.slot) != 0) {
            return -1;
        }

        memset(vote.signature.bytes, 0, sizeof(vote.signature.bytes));
        if (lantern_attestations_append(&body->attestations, &vote) != 0) {
            return -1;
        }
    }
    return 0;
}

static int parse_block(
    const struct json_document *doc,
    int object_index,
    LanternBlock *block) {
    if (!doc || !block) {
        return -1;
    }
    memset(block, 0, sizeof(*block));
    lantern_block_body_init(&block->body);

    int idx = json_object_get_field(doc, object_index, "slot");
    if (json_token_to_uint64(doc, idx, &block->slot) != 0) {
        return -1;
    }

    idx = json_object_get_field(doc, object_index, "proposer_index");
    if (idx < 0) {
        idx = json_object_get_field(doc, object_index, "proposerIndex");
    }
    if (json_token_to_uint64(doc, idx, &block->proposer_index) != 0) {
        return -1;
    }

    idx = json_object_get_field(doc, object_index, "parent_root");
    if (idx < 0) {
        idx = json_object_get_field(doc, object_index, "parentRoot");
    }
    if (json_token_to_root(doc, idx, &block->parent_root) != 0) {
        return -1;
    }

    idx = json_object_get_field(doc, object_index, "state_root");
    if (idx < 0) {
        idx = json_object_get_field(doc, object_index, "stateRoot");
    }
    if (json_token_to_root(doc, idx, &block->state_root) != 0) {
        return -1;
    }

    int body_idx = json_object_get_field(doc, object_index, "body");
    if (body_idx >= 0) {
        if (parse_attestations(doc, body_idx, &block->body) != 0) {
            return -1;
        }
    }

    return 0;
}

static void reset_block(LanternBlock *block) {
    if (!block) {
        return;
    }
    lantern_block_body_reset(&block->body);
}

static int parse_signed_block(
    const struct json_document *doc,
    int block_idx,
    LanternSignedBlock *out_block) {
    if (!out_block) {
        return -1;
    }
    if (parse_block(doc, block_idx, &out_block->message) != 0) {
        return -1;
    }
    memset(out_block->signature.bytes, 0, sizeof(out_block->signature.bytes));
    return 0;
}

static int load_text_file(const char *path, char **out_buf) {
    if (!path || !out_buf) {
        return -1;
    }
    FILE *file = fopen(path, "rb");
    if (!file) {
        perror("fopen");
        return -1;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return -1;
    }
    long size = ftell(file);
    if (size < 0) {
        fclose(file);
        return -1;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return -1;
    }
    char *buffer = (char *)malloc((size_t)size + 1u);
    if (!buffer) {
        fclose(file);
        return -1;
    }
    size_t read_len = fread(buffer, 1u, (size_t)size, file);
    fclose(file);
    if (read_len != (size_t)size) {
        free(buffer);
        return -1;
    }
    buffer[size] = '\0';
    *out_buf = buffer;
    return 0;
}

static int run_state_transition_fixture(const char *path);
static int run_fork_choice_fixture(const char *path);

static int for_each_json(
    const char *root,
    int (*callback)(const char *path)) {
    if (!root || !callback) {
        return -1;
    }
    DIR *dir = opendir(root);
    if (!dir) {
        perror("opendir");
        return -1;
    }
    int status = 0;
    struct dirent *entry = NULL;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        char child_path[1024];
        int written = snprintf(child_path, sizeof(child_path), "%s/%s", root, entry->d_name);
        if (written <= 0 || written >= (int)sizeof(child_path)) {
            status = -1;
            break;
        }
        if (entry->d_type == DT_DIR) {
            if (for_each_json(child_path, callback) != 0) {
                status = -1;
                break;
            }
            continue;
        }
        const char *ext = strrchr(entry->d_name, '.');
        if (!ext || strcmp(ext, ".json") != 0) {
            continue;
        }
        if (callback(child_path) != 0) {
            status = -1;
            break;
        }
    }
    closedir(dir);
    return status;
}

static int run_state_transition_fixture(const char *path) {
    char *text = NULL;
    if (load_text_file(path, &text) != 0) {
        fprintf(stderr, "failed to read %s\n", path);
        return -1;
    }

    struct json_document doc;
    if (json_document_init(&doc, text) != 0) {
        fprintf(stderr, "failed to parse %s\n", path);
        return -1;
    }
    if (doc.token_count <= 0) {
        json_document_reset(&doc);
        return -1;
    }

    int root_idx = 0;
    int case_idx = json_object_get_value_at(&doc, root_idx, 0);
    if (case_idx < 0) {
        json_document_reset(&doc);
        return -1;
    }

    const char *fixture_filter = getenv("LANTERN_STATE_FIXTURE");
    if (fixture_filter && strstr(path, fixture_filter) == NULL) {
        json_document_reset(&doc);
        return 0;
    }

    const char *debug_hash = getenv("LANTERN_DEBUG_STATE_HASH");
    if (debug_hash && debug_hash[0] != '\0') {
        fprintf(stderr, "fixture: %s\n", path);
    }

    int pre_idx = json_object_get_field(&doc, case_idx, "pre");
    int blocks_idx = json_object_get_field(&doc, case_idx, "blocks");
    int post_idx = json_object_get_field(&doc, case_idx, "post");
    int expect_exception_idx = json_object_get_field(&doc, case_idx, "expectException");
    bool expect_failure = expect_exception_idx >= 0;

    LanternState state;
    LanternCheckpoint latest_justified;
    LanternCheckpoint latest_finalized;
    uint64_t genesis_time = 0;
    uint64_t validator_count = 0;
    if (parse_anchor_state(
            &doc,
            pre_idx,
            &state,
            &latest_justified,
            &latest_finalized,
            &genesis_time,
            &validator_count)
        != 0) {
        json_document_reset(&doc);
        return -1;
    }

    bool observed_failure = false;
    int block_count = 0;
    if (blocks_idx >= 0) {
        block_count = json_array_get_length(&doc, blocks_idx);
        if (block_count < 0) {
            lantern_state_reset(&state);
            json_document_reset(&doc);
            return -1;
        }
    }

    for (int i = 0; i < block_count; ++i) {
        int block_idx = json_array_get_element(&doc, blocks_idx, i);
        if (block_idx < 0) {
            lantern_state_reset(&state);
            json_document_reset(&doc);
            return -1;
        }

        LanternSignedBlock signed_block;
        if (parse_signed_block(&doc, block_idx, &signed_block) != 0) {
            lantern_state_reset(&state);
            json_document_reset(&doc);
            return -1;
        }

        int status = lantern_state_transition(&state, &signed_block);
        reset_block(&signed_block.message);

        if (status != 0) {
            observed_failure = true;
            break;
        }
    }

    int result = 0;
    if (expect_failure) {
        if (!(observed_failure || block_count == 0)) {
            fprintf(stderr, "expected failure did not occur in %s\n", path);
            result = -1;
        }
    } else {
        if (observed_failure) {
            fprintf(stderr, "unexpected failure while processing %s\n", path);
            result = -1;
        } else if (post_idx < 0) {
            fprintf(stderr, "missing post state in %s\n", path);
            result = -1;
        } else {
            int field_idx = json_object_get_field(&doc, post_idx, "slot");
            if (field_idx >= 0) {
                uint64_t expected_slot = 0;
                if (json_token_to_uint64(&doc, field_idx, &expected_slot) != 0 || state.slot != expected_slot) {
                    fprintf(
                        stderr,
                        "post slot mismatch in %s: expected %" PRIu64 " got %" PRIu64 "\n",
                        path,
                        expected_slot,
                        state.slot);
                    result = -1;
                }
            }

            if (result == 0) {
                field_idx = json_object_get_field(&doc, post_idx, "validatorCount");
                if (field_idx >= 0) {
                    uint64_t expected_count = 0;
                    if (json_token_to_uint64(&doc, field_idx, &expected_count) != 0
                        || state.config.num_validators != expected_count) {
                        fprintf(
                            stderr,
                            "post validator count mismatch in %s: expected %" PRIu64 " got %" PRIu64 "\n",
                            path,
                            expected_count,
                            state.config.num_validators);
                        result = -1;
                    }
                }
            }
        }
    }

    lantern_state_reset(&state);
    json_document_reset(&doc);
    return result;
}

static int run_fork_choice_fixture(const char *path) {
    char *text = NULL;
    struct stored_state_entry *stored_states = NULL;
    size_t stored_states_count = 0;
    size_t stored_states_cap = 0;
    if (load_text_file(path, &text) != 0) {
        fprintf(stderr, "failed to read %s\n", path);
        stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
        return -1;
    }

    struct json_document doc;
    if (json_document_init(&doc, text) != 0) {
        fprintf(stderr, "failed to parse %s\n", path);
        stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
        return -1;
    }
    if (doc.token_count <= 0) {
        json_document_reset(&doc);
        return -1;
    }

    int root_idx = 0;
    int case_idx = json_object_get_value_at(&doc, root_idx, 0);
    if (case_idx < 0) {
        json_document_reset(&doc);
        stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
        return -1;
    }

    const char *fixture_filter = getenv("LANTERN_FORK_CHOICE_FIXTURE");
    if (fixture_filter && strstr(path, fixture_filter) == NULL) {
        json_document_reset(&doc);
        stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
        return 0;
    }

    const char *debug_hash = getenv("LANTERN_DEBUG_STATE_HASH");
    if (debug_hash && debug_hash[0] != '\0') {
        fprintf(stderr, "fork fixture: %s\n", path);
    }

    int anchor_state_idx = json_object_get_field(&doc, case_idx, "anchorState");
    int anchor_block_idx = json_object_get_field(&doc, case_idx, "anchorBlock");
    int steps_idx = json_object_get_field(&doc, case_idx, "steps");
    if (anchor_state_idx < 0 || anchor_block_idx < 0 || steps_idx < 0) {
        json_document_reset(&doc);
        stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
        return -1;
    }

    LanternState state;
    LanternCheckpoint latest_justified;
    LanternCheckpoint latest_finalized;
    uint64_t genesis_time = 0;
    uint64_t validator_count = 0;
    if (parse_anchor_state(
            &doc,
            anchor_state_idx,
            &state,
            &latest_justified,
            &latest_finalized,
            &genesis_time,
            &validator_count)
        != 0) {
        json_document_reset(&doc);
        stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
        return -1;
    }

    LanternBlock anchor_block;
    if (parse_block(&doc, anchor_block_idx, &anchor_block) != 0) {
        lantern_state_reset(&state);
        json_document_reset(&doc);
        stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
        return -1;
    }
    LanternRoot anchor_body_root;
    if (lantern_hash_tree_root_block_body(&anchor_block.body, &anchor_body_root) != 0) {
        reset_block(&anchor_block);
        lantern_state_reset(&state);
        json_document_reset(&doc);
        stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
        return -1;
    }
    state.latest_block_header.slot = anchor_block.slot;
    state.latest_block_header.proposer_index = anchor_block.proposer_index;
    state.latest_block_header.parent_root = anchor_block.parent_root;
    state.latest_block_header.state_root = anchor_block.state_root;
    state.latest_block_header.body_root = anchor_body_root;
    state.slot = anchor_block.slot;

    LanternForkChoice store;
    lantern_fork_choice_init(&store);
    LanternConfig config = {
        .num_validators = validator_count,
        .genesis_time = genesis_time,
    };
    if (lantern_fork_choice_configure(&store, &config) != 0) {
        reset_block(&anchor_block);
        lantern_state_reset(&state);
        json_document_reset(&doc);
        stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
        return -1;
    }

    LanternRoot anchor_root;
    if (lantern_hash_tree_root_block(&anchor_block, &anchor_root) != 0) {
        reset_block(&anchor_block);
        lantern_fork_choice_reset(&store);
        lantern_state_reset(&state);
        json_document_reset(&doc);
        stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
        return -1;
    }

    if (lantern_fork_choice_set_anchor(&store, &anchor_block, &latest_justified, &latest_finalized, &anchor_root) != 0) {
        reset_block(&anchor_block);
        lantern_fork_choice_reset(&store);
        lantern_state_reset(&state);
        json_document_reset(&doc);
        stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
        return -1;
    }

    lantern_state_attach_fork_choice(&state, &store);

    if (stored_state_save(&stored_states, &stored_states_count, &stored_states_cap, &anchor_root, &state) != 0) {
        reset_block(&anchor_block);
        lantern_fork_choice_reset(&store);
        lantern_state_reset(&state);
        json_document_reset(&doc);
        stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
        return -1;
    }
    LanternRoot canonical_head_block_root = anchor_root;

    struct label_registry labels;
    label_registry_init(&labels);

    int step_count = json_array_get_length(&doc, steps_idx);
    if (step_count < 0) {
        reset_block(&anchor_block);
        lantern_fork_choice_reset(&store);
        lantern_state_reset(&state);
        json_document_reset(&doc);
        stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
        return -1;
    }

    for (int i = 0; i < step_count; ++i) {
        int step_idx = json_array_get_element(&doc, steps_idx, i);
        if (step_idx < 0) {
            reset_block(&anchor_block);
            lantern_fork_choice_reset(&store);
            lantern_state_reset(&state);
            json_document_reset(&doc);
            stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
            return -1;
        }

        int block_idx = json_object_get_field(&doc, step_idx, "block");
        if (block_idx < 0) {
            continue;
        }

        LanternSignedBlock signed_block;
        if (parse_signed_block(&doc, block_idx, &signed_block) != 0) {
            reset_block(&anchor_block);
            lantern_fork_choice_reset(&store);
            lantern_state_reset(&state);
            json_document_reset(&doc);
            stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
            return -1;
        }

        uint64_t now = genesis_time + (signed_block.message.slot * store.seconds_per_slot);
        if (lantern_fork_choice_advance_time(&store, now, true) != 0) {
            reset_block(&signed_block.message);
            reset_block(&anchor_block);
            lantern_fork_choice_reset(&store);
            lantern_state_reset(&state);
            json_document_reset(&doc);
            stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
            return -1;
        }

        LanternRoot block_root;
        if (lantern_hash_tree_root_block(&signed_block.message, &block_root) != 0) {
            reset_block(&signed_block.message);
            reset_block(&anchor_block);
            lantern_fork_choice_reset(&store);
            lantern_state_reset(&state);
            json_document_reset(&doc);
            stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
            return -1;
        }

        LanternState branch_state;
        bool branch_state_initialized = false;
        bool transition_performed = false;
        LanternState *active_state = &state;
        bool extends_canonical =
            memcmp(canonical_head_block_root.bytes, signed_block.message.parent_root.bytes, LANTERN_ROOT_SIZE) == 0;

        LanternCheckpoint block_justified = state.latest_justified;
        LanternCheckpoint block_finalized = state.latest_finalized;

        if (extends_canonical) {
            if (signed_block.message.slot > state.slot) {
                if (lantern_state_transition(&state, &signed_block) != 0) {
                    reset_block(&signed_block.message);
                    reset_block(&anchor_block);
                    lantern_fork_choice_reset(&store);
                    lantern_state_reset(&state);
                    json_document_reset(&doc);
                    stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                    return -1;
                }
                transition_performed = true;
                block_justified = state.latest_justified;
                block_finalized = state.latest_finalized;
                if (debug_hash && debug_hash[0] != '\0') {
                    LanternRoot post_transition_root;
                    if (lantern_hash_tree_root_state(&state, &post_transition_root) == 0) {
                        char post_transition_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
                        if (lantern_bytes_to_hex(
                                post_transition_root.bytes,
                                LANTERN_ROOT_SIZE,
                                post_transition_hex,
                                sizeof(post_transition_hex),
                                1)
                            == 0) {
                            fprintf(stderr, "state after transition root=%s\n", post_transition_hex);
                        }
                    }
                }
            } else {
                active_state = &state;
                block_justified = state.latest_justified;
                block_finalized = state.latest_finalized;
            }
        } else {
            struct stored_state_entry *parent_entry =
                stored_state_find(stored_states, stored_states_count, &signed_block.message.parent_root);
            if (!parent_entry) {
                reset_block(&signed_block.message);
                reset_block(&anchor_block);
                lantern_fork_choice_reset(&store);
                lantern_state_reset(&state);
                json_document_reset(&doc);
                stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                return -1;
            }
            lantern_state_init(&branch_state);
            branch_state_initialized = true;
            if (stored_state_restore(stored_states, stored_states_count, &signed_block.message.parent_root, &branch_state) != 0) {
                lantern_state_reset(&branch_state);
                reset_block(&signed_block.message);
                reset_block(&anchor_block);
                lantern_fork_choice_reset(&store);
                lantern_state_reset(&state);
                json_document_reset(&doc);
                stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                return -1;
            }
            active_state = &branch_state;
            if (lantern_state_transition(active_state, &signed_block) != 0) {
                lantern_state_reset(&branch_state);
                reset_block(&signed_block.message);
                reset_block(&anchor_block);
                lantern_fork_choice_reset(&store);
                lantern_state_reset(&state);
                json_document_reset(&doc);
                stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                return -1;
            }
            transition_performed = true;
            block_justified = active_state->latest_justified;
            block_finalized = active_state->latest_finalized;
        }

        uint64_t parent_slot = 0;
        bool has_parent_info = false;
        for (size_t b = 0; b < LANTERN_ROOT_SIZE; ++b) {
            if (signed_block.message.parent_root.bytes[b] != 0) {
                has_parent_info = true;
                break;
            }
        }
        if (has_parent_info) {
            if (lantern_fork_choice_block_info(&store, &signed_block.message.parent_root, &parent_slot, NULL, NULL) != 0) {
                if (branch_state_initialized) {
                    lantern_state_reset(&branch_state);
                }
                reset_block(&signed_block.message);
                reset_block(&anchor_block);
                lantern_fork_choice_reset(&store);
                lantern_state_reset(&state);
                json_document_reset(&doc);
                stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                return -1;
            }
        }

        LanternVote proposer_vote;
        memset(&proposer_vote, 0, sizeof(proposer_vote));
        proposer_vote.validator_id = signed_block.message.proposer_index;
        proposer_vote.slot = signed_block.message.slot;
        proposer_vote.head.root = block_root;
        proposer_vote.head.slot = signed_block.message.slot;
        proposer_vote.target.root = block_root;
        proposer_vote.target.slot = signed_block.message.slot;
        proposer_vote.source.root = signed_block.message.parent_root;
        proposer_vote.source.slot = has_parent_info ? parent_slot : 0;

        if (debug_hash && debug_hash[0] != '\0') {
            char block_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
            if (lantern_bytes_to_hex(block_root.bytes, LANTERN_ROOT_SIZE, block_hex, sizeof(block_hex), 1) != 0) {
                block_hex[0] = '\0';
            }
            fprintf(
                stderr,
                "fork step %d slot %" PRIu64 " extends=%d transition=%d block=%s\n",
                i,
                signed_block.message.slot,
                extends_canonical ? 1 : 0,
                transition_performed ? 1 : 0,
                block_hex[0] ? block_hex : "0x0");
        }

        if (transition_performed) {
            if (debug_hash && debug_hash[0] != '\0') {
                LanternRoot pre_vote_root;
                if (lantern_hash_tree_root_state(active_state, &pre_vote_root) == 0) {
                    char pre_vote_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
                    if (lantern_bytes_to_hex(
                            pre_vote_root.bytes,
                            LANTERN_ROOT_SIZE,
                            pre_vote_hex,
                            sizeof(pre_vote_hex),
                            1)
                        == 0) {
                        fprintf(stderr, "state before vote root=%s\n", pre_vote_hex);
                    }
                }
            }
            if (lantern_state_set_validator_vote(active_state, (size_t)proposer_vote.validator_id, &proposer_vote) != 0) {
                if (branch_state_initialized) {
                    lantern_state_reset(&branch_state);
                }
                reset_block(&signed_block.message);
                reset_block(&anchor_block);
                lantern_fork_choice_reset(&store);
                lantern_state_reset(&state);
                json_document_reset(&doc);
                stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                return -1;
            }
            if (debug_hash && debug_hash[0] != '\0') {
                LanternRoot post_vote_root;
                if (lantern_hash_tree_root_state(active_state, &post_vote_root) == 0) {
                    char post_vote_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
                    if (lantern_bytes_to_hex(
                            post_vote_root.bytes,
                            LANTERN_ROOT_SIZE,
                            post_vote_hex,
                            sizeof(post_vote_hex),
                            1)
                        == 0) {
                        fprintf(stderr, "state after vote root=%s\n", post_vote_hex);
                    }
                }
            }
            if (stored_state_save(&stored_states, &stored_states_count, &stored_states_cap, &block_root, active_state) != 0) {
                if (branch_state_initialized) {
                    lantern_state_reset(&branch_state);
                }
                reset_block(&signed_block.message);
                reset_block(&anchor_block);
                lantern_fork_choice_reset(&store);
                lantern_state_reset(&state);
                json_document_reset(&doc);
                stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                return -1;
            }
        } else if (!stored_state_find(stored_states, stored_states_count, &block_root)) {
            if (stored_state_save(&stored_states, &stored_states_count, &stored_states_cap, &block_root, &state) != 0) {
                if (branch_state_initialized) {
                    lantern_state_reset(&branch_state);
                }
                reset_block(&signed_block.message);
                reset_block(&anchor_block);
                lantern_fork_choice_reset(&store);
                lantern_state_reset(&state);
                json_document_reset(&doc);
                stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                return -1;
            }
        }

        LanternCheckpoint post_justified = block_justified;
        LanternCheckpoint post_finalized = block_finalized;
        if (lantern_fork_choice_add_block(&store, &signed_block.message, &post_justified, &post_finalized, &block_root) != 0) {
            if (branch_state_initialized) {
                lantern_state_reset(&branch_state);
            }
            reset_block(&signed_block.message);
            reset_block(&anchor_block);
            lantern_fork_choice_reset(&store);
            lantern_state_reset(&state);
            json_document_reset(&doc);
            stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
            return -1;
        }

        LanternSignedVote signed_proposer_vote;
        memset(&signed_proposer_vote, 0, sizeof(signed_proposer_vote));
        signed_proposer_vote.data = proposer_vote;
        if (lantern_fork_choice_add_vote(&store, &signed_proposer_vote, false) != 0) {
            if (branch_state_initialized) {
                lantern_state_reset(&branch_state);
            }
            reset_block(&signed_block.message);
            reset_block(&anchor_block);
            lantern_fork_choice_reset(&store);
            lantern_state_reset(&state);
            json_document_reset(&doc);
            stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
            return -1;
        }

        if (extends_canonical && transition_performed) {
            canonical_head_block_root = block_root;
        }

        if (sync_state_to_fork_choice_head(&store, &state, &stored_states, &stored_states_count, &canonical_head_block_root) != 0) {
            if (branch_state_initialized) {
                lantern_state_reset(&branch_state);
            }
            reset_block(&signed_block.message);
            reset_block(&anchor_block);
            lantern_fork_choice_reset(&store);
            lantern_state_reset(&state);
            json_document_reset(&doc);
            stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
            return -1;
        }

        if (branch_state_initialized) {
            lantern_state_reset(&branch_state);
        }

        int checks_idx = json_object_get_field(&doc, step_idx, "checks");
        if (checks_idx >= 0) {
            LanternRoot head_root;
            if (lantern_fork_choice_current_head(&store, &head_root) != 0) {
                reset_block(&signed_block.message);
                reset_block(&anchor_block);
                lantern_fork_choice_reset(&store);
                lantern_state_reset(&state);
                json_document_reset(&doc);
                stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                return -1;
            }

            int head_slot_idx = json_object_get_field(&doc, checks_idx, "headSlot");
            if (head_slot_idx >= 0) {
                uint64_t expected_slot = 0;
                if (json_token_to_uint64(&doc, head_slot_idx, &expected_slot) != 0) {
                    reset_block(&signed_block.message);
                    reset_block(&anchor_block);
                    lantern_fork_choice_reset(&store);
                    lantern_state_reset(&state);
                    json_document_reset(&doc);
                    stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                    return -1;
                }
                uint64_t actual_slot = 0;
                if (lantern_fork_choice_block_info(&store, &head_root, &actual_slot, NULL, NULL) != 0) {
                    reset_block(&signed_block.message);
                    reset_block(&anchor_block);
                    lantern_fork_choice_reset(&store);
                    lantern_state_reset(&state);
                    json_document_reset(&doc);
                    stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                    return -1;
                }
                if (actual_slot != expected_slot) {
                    fprintf(
                        stderr,
                        "head slot mismatch in %s (step %d): expected %" PRIu64 " got %" PRIu64 "\n",
                        path,
                        i,
                        expected_slot,
                        actual_slot);
                    reset_block(&signed_block.message);
                    reset_block(&anchor_block);
                    lantern_fork_choice_reset(&store);
                    lantern_state_reset(&state);
                    json_document_reset(&doc);
                    stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                    return -1;
                }
            }

            int head_label_idx = json_object_get_field(&doc, checks_idx, "headRootLabel");
            if (head_label_idx >= 0) {
                size_t label_len = 0;
                const char *label = json_token_string(&doc, head_label_idx, &label_len);
                if (!label || label_len == 0) {
                    reset_block(&signed_block.message);
                    reset_block(&anchor_block);
                    lantern_fork_choice_reset(&store);
                    lantern_state_reset(&state);
                    json_document_reset(&doc);
                    stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                    return -1;
                }
                char label_buf[LABEL_MAX_LENGTH];
                if (label_len >= sizeof(label_buf)) {
                    label_len = sizeof(label_buf) - 1u;
                }
                memcpy(label_buf, label, label_len);
                label_buf[label_len] = '\0';
                if (label_registry_assign(&labels, label_buf, &head_root) != 0) {
                    reset_block(&signed_block.message);
                    reset_block(&anchor_block);
                    lantern_fork_choice_reset(&store);
                    lantern_state_reset(&state);
                    json_document_reset(&doc);
                    stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                    return -1;
                }
            }

            int att_target_idx = json_object_get_field(&doc, checks_idx, "attestationTargetSlot");
            if (att_target_idx >= 0) {
                uint64_t expected_slot = 0;
                if (json_token_to_uint64(&doc, att_target_idx, &expected_slot) != 0) {
                    reset_block(&signed_block.message);
                    reset_block(&anchor_block);
                    lantern_fork_choice_reset(&store);
                    lantern_state_reset(&state);
                    json_document_reset(&doc);
                    stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                    return -1;
                }
                LanternCheckpoint head_cp;
                LanternCheckpoint target_cp;
                LanternCheckpoint source_cp;
                if (lantern_state_compute_vote_checkpoints(&state, &head_cp, &target_cp, &source_cp) != 0) {
                    reset_block(&signed_block.message);
                    reset_block(&anchor_block);
                    lantern_fork_choice_reset(&store);
                    lantern_state_reset(&state);
                    json_document_reset(&doc);
                    stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                    return -1;
                }
                if (target_cp.slot != expected_slot) {
                    fprintf(
                        stderr,
                        "attestation target mismatch in %s (step %d): expected %" PRIu64 " got %" PRIu64 "\n",
                        path,
                        i,
                        expected_slot,
                        target_cp.slot);
                    reset_block(&signed_block.message);
                    reset_block(&anchor_block);
                    lantern_fork_choice_reset(&store);
                    lantern_state_reset(&state);
                    json_document_reset(&doc);
                    stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                    return -1;
                }
            }

            int att_checks_idx = json_object_get_field(&doc, checks_idx, "attestationChecks");
            if (att_checks_idx >= 0) {
                int length = json_array_get_length(&doc, att_checks_idx);
                if (length < 0) {
                    reset_block(&signed_block.message);
                    reset_block(&anchor_block);
                    lantern_fork_choice_reset(&store);
                    lantern_state_reset(&state);
                    json_document_reset(&doc);
                    stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                    return -1;
                }
                for (int entry = 0; entry < length; ++entry) {
                    int check_idx = json_array_get_element(&doc, att_checks_idx, entry);
                    if (check_idx < 0) {
                        reset_block(&signed_block.message);
                        reset_block(&anchor_block);
                        lantern_fork_choice_reset(&store);
                        lantern_state_reset(&state);
                        json_document_reset(&doc);
                        stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                        return -1;
                    }

                    uint64_t validator_id = 0;
                    int validator_idx = json_object_get_field(&doc, check_idx, "validator");
                    if (validator_idx < 0 || json_token_to_uint64(&doc, validator_idx, &validator_id) != 0) {
                        reset_block(&signed_block.message);
                        reset_block(&anchor_block);
                        lantern_fork_choice_reset(&store);
                        lantern_state_reset(&state);
                        json_document_reset(&doc);
                        stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                        return -1;
                    }
                    size_t validator = (size_t)validator_id;
                    if (validator >= store.validator_count) {
                        reset_block(&signed_block.message);
                        reset_block(&anchor_block);
                        lantern_fork_choice_reset(&store);
                        lantern_state_reset(&state);
                        json_document_reset(&doc);
                        stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                        return -1;
                    }

                    size_t location_len = 0;
                    int location_idx = json_object_get_field(&doc, check_idx, "location");
                    const char *location = json_token_string(&doc, location_idx, &location_len);
                    if (!location) {
                        reset_block(&signed_block.message);
                        reset_block(&anchor_block);
                        lantern_fork_choice_reset(&store);
                        lantern_state_reset(&state);
                        json_document_reset(&doc);
                        stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                        return -1;
                    }

                    const struct lantern_fork_choice_vote_entry *vote_entry = NULL;
                    bool expect_new = false;
                    if (location_len == 3 && strncmp(location, "new", 3) == 0) {
                        vote_entry = &store.new_votes[validator];
                        expect_new = true;
                    } else if (location_len == 5 && strncmp(location, "known", 5) == 0) {
                        vote_entry = &store.known_votes[validator];
                    } else {
                        reset_block(&signed_block.message);
                        reset_block(&anchor_block);
                        lantern_fork_choice_reset(&store);
                        lantern_state_reset(&state);
                        json_document_reset(&doc);
                        stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                        return -1;
                    }

                    if (!vote_entry->has_checkpoint) {
                        fprintf(
                            stderr,
                            "attestation missing checkpoint in %s (step %d): validator %" PRIu64 " (%s)\n",
                            path,
                            i,
                            validator_id,
                            expect_new ? "new" : "known");
                        reset_block(&signed_block.message);
                        reset_block(&anchor_block);
                        lantern_fork_choice_reset(&store);
                        lantern_state_reset(&state);
                        json_document_reset(&doc);
                        stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                        return -1;
                    }

                    LanternVote vote;
                    if (lantern_state_get_validator_vote(&state, validator, &vote) != 0) {
                        reset_block(&signed_block.message);
                        reset_block(&anchor_block);
                        lantern_fork_choice_reset(&store);
                        lantern_state_reset(&state);
                        json_document_reset(&doc);
                        stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                        return -1;
                    }

                    if (expect_new != store.new_votes[validator].has_checkpoint) {
                        fprintf(
                            stderr,
                            "attestation location mismatch in %s (step %d): validator %" PRIu64 "\n",
                            path,
                            i,
                            validator_id);
                        reset_block(&signed_block.message);
                        reset_block(&anchor_block);
                        lantern_fork_choice_reset(&store);
                        lantern_state_reset(&state);
                        json_document_reset(&doc);
                        stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                        return -1;
                    }

                    int field_idx = json_object_get_field(&doc, check_idx, "attestationSlot");
                    if (field_idx >= 0) {
                        uint64_t expected_slot = 0;
                        if (json_token_to_uint64(&doc, field_idx, &expected_slot) != 0 || vote.slot != expected_slot) {
                            fprintf(
                                stderr,
                                "attestation slot mismatch in %s (step %d): validator %" PRIu64 "\n",
                                path,
                                i,
                                validator_id);
                            reset_block(&signed_block.message);
                            reset_block(&anchor_block);
                            lantern_fork_choice_reset(&store);
                            lantern_state_reset(&state);
                            json_document_reset(&doc);
                            stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                            return -1;
                        }
                    }

                    field_idx = json_object_get_field(&doc, check_idx, "headSlot");
                    if (field_idx >= 0) {
                        uint64_t expected_slot = 0;
                        if (json_token_to_uint64(&doc, field_idx, &expected_slot) != 0 || vote.head.slot != expected_slot) {
                            fprintf(
                                stderr,
                                "attestation head slot mismatch in %s (step %d): validator %" PRIu64 "\n",
                                path,
                                i,
                                validator_id);
                            reset_block(&signed_block.message);
                            reset_block(&anchor_block);
                            lantern_fork_choice_reset(&store);
                            lantern_state_reset(&state);
                            json_document_reset(&doc);
                            stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                            return -1;
                        }
                    }

                    field_idx = json_object_get_field(&doc, check_idx, "sourceSlot");
                    if (field_idx >= 0) {
                        uint64_t expected_slot = 0;
                        if (json_token_to_uint64(&doc, field_idx, &expected_slot) != 0 || vote.source.slot != expected_slot) {
                            fprintf(
                                stderr,
                                "attestation source slot mismatch in %s (step %d): validator %" PRIu64 "\n",
                                path,
                                i,
                                validator_id);
                            reset_block(&signed_block.message);
                            reset_block(&anchor_block);
                            lantern_fork_choice_reset(&store);
                            lantern_state_reset(&state);
                            json_document_reset(&doc);
                            stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
                            return -1;
                        }
                    }

                    field_idx = json_object_get_field(&doc, check_idx, "targetSlot");
                    if (field_idx >= 0) {
                        uint64_t expected_slot = 0;
                        if (json_token_to_uint64(&doc, field_idx, &expected_slot) != 0
                            || vote_entry->checkpoint.slot != expected_slot) {
                            fprintf(
                                stderr,
                                "attestation target slot mismatch in %s (step %d): validator %" PRIu64 "\n",
                                path,
                                i,
                                validator_id);
                            reset_block(&signed_block.message);
                            reset_block(&anchor_block);
                            lantern_fork_choice_reset(&store);
                            lantern_state_reset(&state);
                            json_document_reset(&doc);
                            return -1;
                        }
                    }
                }
            }
        }

        reset_block(&signed_block.message);
    }

    reset_block(&anchor_block);
    lantern_fork_choice_reset(&store);
    lantern_state_reset(&state);
    json_document_reset(&doc);
    stored_state_entries_reset(&stored_states, &stored_states_count, &stored_states_cap);
    return 0;
}

int main(void) {
    char state_transition_root[1024];
    int written = snprintf(
        state_transition_root,
        sizeof(state_transition_root),
        "%s/consensus/state_transition",
        LANTERN_TEST_FIXTURE_DIR);
    if (written <= 0 || written >= (int)sizeof(state_transition_root)) {
        fprintf(stderr, "fixture path too long\n");
        return 1;
    }
    if (for_each_json(state_transition_root, run_state_transition_fixture) != 0) {
        return 1;
    }

    char fork_choice_root[1024];
    written = snprintf(
        fork_choice_root,
        sizeof(fork_choice_root),
        "%s/consensus/fork_choice",
        LANTERN_TEST_FIXTURE_DIR);
    if (written <= 0 || written >= (int)sizeof(fork_choice_root)) {
        fprintf(stderr, "fixture path too long\n");
        return 1;
    }

    if (for_each_json(fork_choice_root, run_fork_choice_fixture) != 0) {
        return 1;
    }

    puts("lantern_consensus_vectors OK");
    return 0;
}
