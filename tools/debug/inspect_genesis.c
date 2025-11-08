#include "lantern/consensus/hash.h"
#include "lantern/consensus/ssz.h"
#include "lantern/consensus/state.h"
#include "lantern/support/strings.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_file(const char *path, uint8_t **out_data, size_t *out_len) {
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

static void format_root(const LanternRoot *root, char *out, size_t out_len) {
    if (lantern_bytes_to_hex(root->bytes, LANTERN_ROOT_SIZE, out, out_len, 1) != 0) {
        if (out_len > 0) {
            out[0] = '\0';
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s /path/to/genesis.ssz\n", argv[0]);
        return 1;
    }

    uint8_t *data = NULL;
    size_t len = 0;
    if (read_file(argv[1], &data, &len) != 0) {
        return 1;
    }

    LanternState state;
    lantern_state_init(&state);

    if (lantern_ssz_decode_state(&state, data, len) != 0) {
        fprintf(stderr, "failed to decode genesis state\n");
        free(data);
        lantern_state_reset(&state);
        return 1;
    }
    free(data);

    LanternRoot computed_state_root;
    LanternRoot header_root;
    if (lantern_hash_tree_root_state(&state, &computed_state_root) != 0) {
        fprintf(stderr, "failed to hash state\n");
        lantern_state_reset(&state);
        return 1;
    }
    if (lantern_hash_tree_root_block_header(&state.latest_block_header, &header_root) != 0) {
        memset(&header_root, 0, sizeof(header_root));
    }

    char root_hex[2 * LANTERN_ROOT_SIZE + 3];
    char header_hex[sizeof(root_hex)];
    char header_state_hex[sizeof(root_hex)];
    char parent_hex[sizeof(root_hex)];
    char justified_hex[sizeof(root_hex)];
    char finalized_hex[sizeof(root_hex)];

    format_root(&computed_state_root, root_hex, sizeof(root_hex));
    format_root(&header_root, header_hex, sizeof(header_hex));
    format_root(&state.latest_block_header.state_root, header_state_hex, sizeof(header_state_hex));
    format_root(&state.latest_block_header.parent_root, parent_hex, sizeof(parent_hex));
    format_root(&state.latest_justified.root, justified_hex, sizeof(justified_hex));
    format_root(&state.latest_finalized.root, finalized_hex, sizeof(finalized_hex));

    printf("config.num_validators=%" PRIu64 "\n", state.config.num_validators);
    printf("config.genesis_time=%" PRIu64 "\n", state.config.genesis_time);
    printf("state.slot=%" PRIu64 "\n", state.slot);
    printf("latest_block_header.slot=%" PRIu64 "\n", state.latest_block_header.slot);
    printf("latest_block_header.proposer=%" PRIu64 "\n", state.latest_block_header.proposer_index);
    printf("latest_block_header.parent_root=%s\n", parent_hex);
    printf("latest_block_header.state_root=%s\n", header_state_hex);
    printf("latest_block_header.body_root=%s\n", header_hex);
    printf("computed_state_root=%s\n", root_hex);
    printf("latest_justified.slot=%" PRIu64 " root=%s\n", state.latest_justified.slot, justified_hex);
    printf("latest_finalized.slot=%" PRIu64 " root=%s\n", state.latest_finalized.slot, finalized_hex);
    printf("historical_block_hashes=%zu entries\n", state.historical_block_hashes.length);
    printf("justified_slots bits=%zu\n", state.justified_slots.bit_length);
    printf("justification_roots=%zu entries\n", state.justification_roots.length);

    lantern_state_reset(&state);
    return 0;
}
