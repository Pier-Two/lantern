#include "lantern/enr.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const char *kExampleEnr =
    "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0"
    "gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8";

static int expect_pair(const struct lantern_enr_record *record, const char *key, const void *value, size_t len) {
    const struct lantern_enr_key_value *pair = lantern_enr_record_find(record, key);
    if (!pair) {
        fprintf(stderr, "missing ENR key %s\n", key);
        return 1;
    }
    if (pair->value_len != len) {
        fprintf(stderr, "length mismatch for %s\n", key);
        return 1;
    }
    if (len > 0 && memcmp(pair->value, value, len) != 0) {
        fprintf(stderr, "value mismatch for %s\n", key);
        return 1;
    }
    return 0;
}

static int test_decode_single(void) {
    struct lantern_enr_record record;
    lantern_enr_record_init(&record);

    if (lantern_enr_record_decode(kExampleEnr, &record) != 0) {
        fprintf(stderr, "decode failed\n");
        lantern_enr_record_reset(&record);
        return 1;
    }


    int failed = 0;
    if (record.sequence != 1) {
        fprintf(stderr, "sequence mismatch\n");
        failed = 1;
    }
    if (record.signature_len != 64) {
        fprintf(stderr, "signature length mismatch\n");
        failed = 1;
    }
    const char id_value[] = "v4";
    const uint8_t ip_value[] = {0x7f, 0x00, 0x00, 0x01};
    const uint8_t udp_value[] = {0x76, 0x5f};
    if (expect_pair(&record, "id", id_value, sizeof(id_value) - 1) != 0) {
        failed = 1;
    }
    if (expect_pair(&record, "ip", ip_value, sizeof(ip_value)) != 0) {
        failed = 1;
    }
    if (expect_pair(&record, "udp", udp_value, sizeof(udp_value)) != 0) {
        failed = 1;
    }

    lantern_enr_record_reset(&record);
    return failed ? 1 : 0;
}

static int test_record_list(void) {
    struct lantern_enr_record_list list;
    lantern_enr_record_list_init(&list);

    int result = 1;
    if (lantern_enr_record_list_append(&list, kExampleEnr) != 0) {
        fprintf(stderr, "append failed\n");
        goto cleanup;
    }
    if (lantern_enr_record_list_append(&list, kExampleEnr) != 0) {
        fprintf(stderr, "append second failed\n");
        goto cleanup;
    }
    if (list.count != 2) {
        fprintf(stderr, "list count mismatch\n");
        goto cleanup;
    }
    if (list.records[0].sequence != 1 || list.records[1].sequence != 1) {
        fprintf(stderr, "unexpected sequence in list\n");
        goto cleanup;
    }
    result = 0;

cleanup:
    lantern_enr_record_list_reset(&list);
    return result;
}

int main(void) {
    if (test_decode_single() != 0) {
        return 1;
    }
    if (test_record_list() != 0) {
        return 1;
    }
    return 0;
}
