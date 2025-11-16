#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lantern/consensus/containers.h"
#include "lantern/consensus/ssz.h"
#include "lantern/encoding/snappy.h"
#include "lantern/networking/gossip_payloads.h"

static uint8_t *read_file(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "failed to open %s\n", path);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    long len = ftell(fp);
    if (len < 0) {
        fclose(fp);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }
    uint8_t *buffer = (uint8_t *)malloc((size_t)len);
    if (!buffer) {
        fclose(fp);
        return NULL;
    }
    size_t read = fread(buffer, 1, (size_t)len, fp);
    fclose(fp);
    if (read != (size_t)len) {
        free(buffer);
        return NULL;
    }
    if (out_len) {
        *out_len = (size_t)len;
    }
    return buffer;
}

static int write_file(const char *path, const uint8_t *data, size_t len) {
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        fprintf(stderr, "failed to open %s for writing\n", path);
        return -1;
    }
    size_t written = fwrite(data, 1, len, fp);
    fclose(fp);
    return written == len ? 0 : -1;
}

static int encode_vote_fixture(const char *input_path, const char *output_path) {
    size_t len = 0;
    uint8_t *data = read_file(input_path, &len);
    if (!data) {
        return -1;
    }
    if (len != LANTERN_SIGNED_VOTE_SSZ_SIZE) {
        fprintf(stderr, "vote fixture length mismatch (expected %zu, got %zu)\n", (size_t)LANTERN_SIGNED_VOTE_SSZ_SIZE, len);
        free(data);
        return -1;
    }
    LanternSignedVote vote;
    memset(&vote, 0, sizeof(vote));
    if (lantern_ssz_decode_signed_vote(&vote, data, len) != 0) {
        fprintf(stderr, "failed to decode signed vote fixture\n");
        free(data);
        return -1;
    }
    size_t max_compressed = 0;
    if (lantern_snappy_max_compressed_size(len, &max_compressed) != LANTERN_SNAPPY_OK) {
        free(data);
        return -1;
    }
    uint8_t *snappy = (uint8_t *)malloc(max_compressed);
    if (!snappy) {
        free(data);
        return -1;
    }
    size_t snappy_len = max_compressed;
    int encode_rc = lantern_gossip_encode_signed_vote_snappy(&vote, snappy, max_compressed, &snappy_len);
    free(data);
    if (encode_rc != 0) {
        free(snappy);
        fprintf(stderr, "failed to encode signed vote fixture\n");
        return -1;
    }
    int write_rc = write_file(output_path, snappy, snappy_len);
    free(snappy);
    return write_rc;
}

static int encode_block_fixture(const char *input_path, const char *output_path) {
    size_t len = 0;
    uint8_t *data = read_file(input_path, &len);
    if (!data) {
        return -1;
    }
    LanternSignedBlock block;
    lantern_signed_block_with_attestation_init(&block);
    int decode_rc = lantern_ssz_decode_signed_block(&block, data, len);
    free(data);
    if (decode_rc != 0) {
        fprintf(stderr, "failed to decode signed block fixture\n");
        lantern_signed_block_with_attestation_reset(&block);
        return -1;
    }
    size_t max_compressed = 0;
    if (lantern_snappy_max_compressed_size(len, &max_compressed) != LANTERN_SNAPPY_OK) {
        lantern_signed_block_with_attestation_reset(&block);
        return -1;
    }
    uint8_t *snappy = (uint8_t *)malloc(max_compressed);
    if (!snappy) {
        lantern_signed_block_with_attestation_reset(&block);
        return -1;
    }
    size_t snappy_len = max_compressed;
    int encode_rc = lantern_gossip_encode_signed_block_snappy(&block, snappy, max_compressed, &snappy_len);
    lantern_signed_block_with_attestation_reset(&block);
    if (encode_rc != 0) {
        free(snappy);
        fprintf(stderr, "failed to encode signed block fixture\n");
        return -1;
    }
    int write_rc = write_file(output_path, snappy, snappy_len);
    free(snappy);
    return write_rc;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s vote|block input.ssz output.snappy\n", argv[0]);
        return 1;
    }
    const char *kind = argv[1];
    const char *input_path = argv[2];
    const char *output_path = argv[3];
    int rc = -1;
    if (strcmp(kind, "vote") == 0) {
        rc = encode_vote_fixture(input_path, output_path);
    } else if (strcmp(kind, "block") == 0) {
        rc = encode_block_fixture(input_path, output_path);
    } else {
        fprintf(stderr, "unknown kind: %s\n", kind);
        return 1;
    }
    return rc == 0 ? 0 : 1;
}
