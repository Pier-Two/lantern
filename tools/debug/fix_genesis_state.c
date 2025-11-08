#include "lantern/consensus/hash.h"
#include "lantern/consensus/ssz.h"
#include "lantern/consensus/state.h"
#include "lantern/support/strings.h"

#include <errno.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_file(const char *path, uint8_t **out_data, size_t *out_len) {
    if (!path || !out_data || !out_len) {
        return -1;
    }
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "failed to open %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    long size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }
    uint8_t *buffer = (uint8_t *)malloc((size_t)size);
    if (!buffer) {
        fclose(fp);
        return -1;
    }
    size_t read = fread(buffer, 1, (size_t)size, fp);
    fclose(fp);
    if (read != (size_t)size) {
        free(buffer);
        return -1;
    }
    *out_data = buffer;
    *out_len = (size_t)size;
    return 0;
}

static int write_file(const char *path, const uint8_t *data, size_t len) {
    if (!path || !data) {
        return -1;
    }
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        fprintf(stderr, "failed to write %s: %s\n", path, strerror(errno));
        return -1;
    }
    size_t written = fwrite(data, 1, len, fp);
    fclose(fp);
    if (written != len) {
        fprintf(stderr, "short write on %s\n", path);
        return -1;
    }
    return 0;
}

static void zero_root(LanternRoot *root) {
    if (root) {
        memset(root->bytes, 0, sizeof(root->bytes));
    }
}

static void format_root(const LanternRoot *root, char *out, size_t out_len) {
    if (!root || !out || out_len == 0) {
        return;
    }
    if (lantern_bytes_to_hex(root->bytes, LANTERN_ROOT_SIZE, out, out_len, 1) != 0) {
        out[0] = '\0';
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s /path/to/genesis.ssz\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *path = argv[1];
    uint8_t *input = NULL;
    size_t input_len = 0;
    if (read_file(path, &input, &input_len) != 0) {
        return EXIT_FAILURE;
    }

    LanternState state;
    lantern_state_init(&state);

    if (lantern_ssz_decode_state(&state, input, input_len) != 0) {
        fprintf(stderr, "failed to decode %s\n", path);
        free(input);
        lantern_state_reset(&state);
        return EXIT_FAILURE;
    }

    if (lantern_root_list_resize(&state.historical_block_hashes, 0) != 0) {
        fprintf(stderr, "failed to reset historical_block_hashes\n");
        free(input);
        lantern_state_reset(&state);
        return EXIT_FAILURE;
    }
    if (lantern_bitlist_resize(&state.justified_slots, 0) != 0) {
        fprintf(stderr, "failed to reset justified_slots\n");
        free(input);
        lantern_state_reset(&state);
        return EXIT_FAILURE;
    }

    zero_root(&state.latest_justified.root);
    state.latest_justified.slot = 0;
    zero_root(&state.latest_finalized.root);
    state.latest_finalized.slot = 0;

    LanternBlockBody empty_body;
    lantern_block_body_init(&empty_body);
    LanternRoot empty_body_root;
    if (lantern_hash_tree_root_block_body(&empty_body, &empty_body_root) != 0) {
        fprintf(stderr, "failed to hash empty body\n");
        lantern_block_body_reset(&empty_body);
        free(input);
        lantern_state_reset(&state);
        return EXIT_FAILURE;
    }
    lantern_block_body_reset(&empty_body);
    state.latest_block_header.body_root = empty_body_root;

    LanternRoot computed_state_root;
    if (lantern_hash_tree_root_state(&state, &computed_state_root) != 0) {
        fprintf(stderr, "failed to hash state\n");
        free(input);
        lantern_state_reset(&state);
        return EXIT_FAILURE;
    }
    state.latest_block_header.state_root = computed_state_root;

    LanternRoot header_root;
    if (lantern_hash_tree_root_block_header(&state.latest_block_header, &header_root) != 0) {
        fprintf(stderr, "failed to hash block header\n");
        free(input);
        lantern_state_reset(&state);
        return EXIT_FAILURE;
    }

    char state_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
    char header_hex[(LANTERN_ROOT_SIZE * 2u) + 3u];
    format_root(&computed_state_root, state_hex, sizeof(state_hex));
    format_root(&header_root, header_hex, sizeof(header_hex));
    fprintf(
        stderr,
        "updated genesis: state_root=%s header_root=%s\n",
        state_hex[0] ? state_hex : "0x0",
        header_hex[0] ? header_hex : "0x0");

    size_t output_cap = input_len == 0 ? 1024 : input_len;
    uint8_t *output = NULL;
    size_t encoded_len = 0;
    int encode_rc = -1;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        size_t candidate_cap = output_cap << attempt;
        uint8_t *candidate = (uint8_t *)malloc(candidate_cap);
        if (!candidate) {
            continue;
        }
        encode_rc = lantern_ssz_encode_state(&state, candidate, candidate_cap, &encoded_len);
        if (encode_rc == 0) {
            output = candidate;
            output_cap = candidate_cap;
            break;
        }
        free(candidate);
    }

    if (encode_rc != 0 || !output) {
        fprintf(stderr, "failed to encode state\n");
        free(input);
        lantern_state_reset(&state);
        return EXIT_FAILURE;
    }

    if (write_file(path, output, encoded_len) != 0) {
        free(output);
        free(input);
        lantern_state_reset(&state);
        return EXIT_FAILURE;
    }

    free(output);
    free(input);
    lantern_state_reset(&state);
    return EXIT_SUCCESS;
}
