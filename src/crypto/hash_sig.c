#include "lantern/crypto/hash_sig.h"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define JSMN_PARENT_LINKS
#include "jsmn.h"

#include "pq-bindings-c-rust.h"

#define HASH_SIG_JSON_SECRET_REQUIRED_COUNT 7u
#define HASH_SIG_JSON_PUBLIC_REQUIRED_COUNT 2u

static const char *const k_secret_required_fields[HASH_SIG_JSON_SECRET_REQUIRED_COUNT] = {
    "prf_key",
    "parameter",
    "activation_epoch",
    "num_active_epochs",
    "top_tree",
    "left_bottom_tree",
    "right_bottom_tree",
};
static const char *const k_public_required_fields[HASH_SIG_JSON_PUBLIC_REQUIRED_COUNT] = {
    "root",
    "parameter",
};

static bool data_is_json_blob(const uint8_t *data, size_t length) {
    if (!data || length == 0) {
        return false;
    }
    for (size_t i = 0; i < length; ++i) {
        unsigned char ch = data[i];
        if (isspace(ch)) {
            continue;
        }
        return ch == '{' || ch == '[';
    }
    return false;
}

static int read_file_bytes(const char *path, uint8_t **out_data, size_t *out_length) {
    if (!path || !out_data || !out_length) {
        return -1;
    }
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    long file_size = ftell(fp);
    if (file_size < 0) {
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }
    uint8_t *buffer = malloc((size_t)file_size);
    if (!buffer) {
        fclose(fp);
        return -1;
    }
    size_t read_len = fread(buffer, 1, (size_t)file_size, fp);
    fclose(fp);
    if (read_len != (size_t)file_size) {
        free(buffer);
        return -1;
    }
    *out_data = buffer;
    *out_length = read_len;
    return 0;
}

static int parse_json_tokens(const char *json, size_t length, jsmntok_t **out_tokens, size_t *out_count) {
    if (!json || !out_tokens || !out_count) {
        return -1;
    }
    size_t capacity = 1024u;
    while (capacity < 1u << 20) {
        jsmntok_t *tokens = malloc(capacity * sizeof(*tokens));
        if (!tokens) {
            return -1;
        }
        jsmn_parser parser;
        jsmn_init(&parser);
        int parsed = jsmn_parse(&parser, json, length, tokens, (unsigned int)capacity);
        if (parsed >= 0) {
            *out_tokens = tokens;
            *out_count = (size_t)parsed;
            return 0;
        }
        free(tokens);
        if (parsed != JSMN_ERROR_NOMEM) {
            return -1;
        }
        capacity *= 2u;
    }
    return -1;
}

static bool token_matches(const char *json, const jsmntok_t *tok, const char *text) {
    if (!json || !tok || !text) {
        return false;
    }
    int length = tok->end - tok->start;
    if (length <= 0) {
        return false;
    }
    size_t text_len = strlen(text);
    if ((size_t)length != text_len) {
        return false;
    }
    return strncmp(json + tok->start, text, text_len) == 0;
}

static int validate_json_fields(
    const char *json,
    size_t length,
    const char *const *fields,
    size_t field_count) {
    if (!json || length == 0 || !fields || field_count == 0) {
        return -1;
    }
    jsmntok_t *tokens = NULL;
    size_t token_count = 0;
    if (parse_json_tokens(json, length, &tokens, &token_count) != 0) {
        return -1;
    }
    if (token_count == 0 || tokens[0].type != JSMN_OBJECT) {
        free(tokens);
        return -1;
    }
    bool found[16];
    if (field_count > sizeof(found) / sizeof(found[0])) {
        free(tokens);
        return -1;
    }
    memset(found, 0, sizeof(found));
    for (size_t i = 1; i < token_count; ++i) {
        const jsmntok_t *tok = &tokens[i];
        if (tok->parent != 0 || tok->type != JSMN_STRING) {
            continue;
        }
        for (size_t field = 0; field < field_count; ++field) {
            if (!found[field] && token_matches(json, tok, fields[field])) {
                found[field] = true;
                break;
            }
        }
    }
    free(tokens);
    for (size_t field = 0; field < field_count; ++field) {
        if (!found[field]) {
            return -1;
        }
    }
    return 0;
}

static int load_secret_from_json(const char *json, size_t length, struct PQSignatureSchemeSecretKey **out_key) {
    if (validate_json_fields(json, length, k_secret_required_fields, HASH_SIG_JSON_SECRET_REQUIRED_COUNT) != 0) {
        return -1;
    }
    enum PQSigningError rc = pq_secret_key_from_json((const uint8_t *)json, length, out_key);
    return (rc == Success && out_key && *out_key) ? 0 : -1;
}

static int load_public_from_json(const char *json, size_t length, struct PQSignatureSchemePublicKey **out_key) {
    if (validate_json_fields(json, length, k_public_required_fields, HASH_SIG_JSON_PUBLIC_REQUIRED_COUNT) != 0) {
        return -1;
    }
    enum PQSigningError rc = pq_public_key_from_json((const uint8_t *)json, length, out_key);
    return (rc == Success && out_key && *out_key) ? 0 : -1;
}

int lantern_hash_sig_load_secret_bytes(
    const uint8_t *data,
    size_t length,
    struct PQSignatureSchemeSecretKey **out_key) {
    if (!data || length == 0 || !out_key) {
        return -1;
    }
    if (data_is_json_blob(data, length)) {
        char *json = malloc(length + 1u);
        if (!json) {
            return -1;
        }
        memcpy(json, data, length);
        json[length] = '\0';
        int rc = load_secret_from_json(json, length, out_key);
        free(json);
        return rc;
    }
    enum PQSigningError rc = pq_secret_key_deserialize(data, length, out_key);
    return (rc == Success && out_key && *out_key) ? 0 : -1;
}

int lantern_hash_sig_load_public_bytes(
    const uint8_t *data,
    size_t length,
    struct PQSignatureSchemePublicKey **out_key) {
    if (!data || length == 0 || !out_key) {
        return -1;
    }
    if (data_is_json_blob(data, length)) {
        char *json = malloc(length + 1u);
        if (!json) {
            return -1;
        }
        memcpy(json, data, length);
        json[length] = '\0';
        int rc = load_public_from_json(json, length, out_key);
        free(json);
        return rc;
    }
    enum PQSigningError rc = pq_public_key_deserialize(data, length, out_key);
    return (rc == Success && out_key && *out_key) ? 0 : -1;
}

int lantern_hash_sig_load_secret_file(
    const char *path,
    struct PQSignatureSchemeSecretKey **out_key) {
    if (!path || !out_key) {
        return -1;
    }
    uint8_t *data = NULL;
    size_t length = 0;
    if (read_file_bytes(path, &data, &length) != 0) {
        return -1;
    }
    int rc = lantern_hash_sig_load_secret_bytes(data, length, out_key);
    free(data);
    return rc;
}

int lantern_hash_sig_load_public_file(
    const char *path,
    struct PQSignatureSchemePublicKey **out_key) {
    if (!path || !out_key) {
        return -1;
    }
    uint8_t *data = NULL;
    size_t length = 0;
    if (read_file_bytes(path, &data, &length) != 0) {
        return -1;
    }
    int rc = lantern_hash_sig_load_public_bytes(data, length, out_key);
    free(data);
    return rc;
}

bool lantern_hash_sig_is_available(void) {
    /*
     * pq_get_lifetime() is part of the public c-hash-sig API.  A non-zero
     * lifetime means the Rust bindings initialised correctly and returned the
     * scheme configuration constants.
     */
    return pq_get_lifetime() > 0u;
}
