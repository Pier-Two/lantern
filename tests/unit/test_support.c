#include "lantern/support/hex.h"
#include "lantern/support/log.h"
#include "lantern/support/secure_mem.h"
#include "lantern/support/string_list.h"
#include "lantern/support/strings.h"
#include "lantern/support/time.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int test_string_boundaries(void)
{
    uint8_t byte = 0;
    uint8_t decoded[2] = {0xa5u, 0x5au};
    char output[4] = "x";

    if (lantern_string_duplicate_len("x", SIZE_MAX) != NULL)
    {
        return 1;
    }
    if (lantern_hex_decode("", &byte, (SIZE_MAX / 2u) + 1u) == LANTERN_HEX_OK)
    {
        return 1;
    }
    if (lantern_hex_encode(&byte, (SIZE_MAX / 2u) + 1u, output,
                             sizeof(output), false) == LANTERN_HEX_OK ||
        output[0] != '\0')
    {
        return 1;
    }
    if (lantern_hex_decode("00xz", decoded, sizeof(decoded)) !=
            LANTERN_HEX_ERR_INVALID ||
        decoded[0] != 0xa5u || decoded[1] != 0x5au)
    {
        return 1;
    }
    output[0] = 'x';
    if (lantern_hex_encode(NULL, 1u, output, sizeof(output), false) !=
            LANTERN_HEX_ERR_INVALID ||
        output[0] != '\0')
    {
        return 1;
    }
    output[0] = 'x';
    size_t source_len = 7u;
    if (lantern_string_copy(output, sizeof(output), NULL, &source_len) !=
            LANTERN_STRING_COPY_ERR_INVALID ||
        output[0] != '\0' || source_len != 7u)
    {
        return 1;
    }
    if (lantern_string_copy(output, sizeof(output), "abcd", &source_len) !=
            LANTERN_STRING_COPY_TRUNCATED ||
        strcmp(output, "abc") != 0 || source_len != 4u)
    {
        return 1;
    }
    if (lantern_string_copy(output, sizeof(output), "ab", &source_len) !=
            LANTERN_STRING_COPY_OK ||
        strcmp(output, "ab") != 0 || source_len != 2u)
    {
        return 1;
    }

    return 0;
}

static int test_string_list_boundaries(void)
{
    struct lantern_string_list list;
    lantern_string_list_init(&list);
    if (lantern_string_list_append(&list, "alpha") != LANTERN_STRING_LIST_OK)
    {
        return 1;
    }
    if (lantern_string_list_copy(&list, &list) != LANTERN_STRING_LIST_OK ||
        lantern_string_list_count(&list) != 1u ||
        strcmp(lantern_string_list_get(&list, 0u), "alpha") != 0 ||
        lantern_string_list_get(&list, 1u) != NULL)
    {
        lantern_string_list_reset(&list);
        return 1;
    }
    if (lantern_string_list_remove(&list, "missing") !=
            LANTERN_STRING_LIST_NOT_FOUND ||
        lantern_string_list_remove(NULL, "missing") !=
            LANTERN_STRING_LIST_ERR_INVALID ||
        lantern_string_list_remove(&list, "alpha") !=
            LANTERN_STRING_LIST_OK ||
        lantern_string_list_count(&list) != 0u)
    {
        lantern_string_list_reset(&list);
        return 1;
    }
    lantern_string_list_reset(&list);

    if (lantern_string_list_append(NULL, "invalid") !=
            LANTERN_STRING_LIST_ERR_INVALID ||
        lantern_string_list_count(&list) != 0u)
    {
        return 1;
    }
    lantern_string_list_reset(&list);
    return 0;
}

static int test_secure_zero(void)
{
    uint8_t secret[] = {1u, 2u, 3u, 4u};
    lantern_secure_zero(secret, sizeof(secret));
    for (size_t i = 0; i < sizeof(secret); ++i)
    {
        if (secret[i] != 0u)
        {
            return 1;
        }
    }

    return 0;
}

static int test_time_helpers(void)
{
    double first;
    double second;
    if (lantern_time_now_seconds(&first) != LANTERN_TIME_OK ||
        lantern_time_now_seconds(&second) != LANTERN_TIME_OK || first < 0.0 ||
        second < first)
    {
        return 1;
    }

    double elapsed = -1.0;
    if (lantern_time_elapsed_seconds(1.0, 2.5, &elapsed) != LANTERN_TIME_OK ||
        elapsed != 1.5 ||
        lantern_time_elapsed_seconds(-1.0, second, &elapsed) !=
            LANTERN_TIME_ERR_INVALID ||
        elapsed != 0.0 ||
        lantern_time_elapsed_seconds(2.0, 1.0, &elapsed) !=
            LANTERN_TIME_ERR_INVALID ||
        elapsed != 0.0 ||
        lantern_time_elapsed_seconds(NAN, 2.0, &elapsed) !=
            LANTERN_TIME_ERR_INVALID ||
        elapsed != 0.0 ||
        lantern_time_now_seconds(NULL) != LANTERN_TIME_ERR_INVALID ||
        lantern_time_elapsed_seconds(1.0, 2.0, NULL) !=
            LANTERN_TIME_ERR_INVALID)
    {
        return 1;
    }

    return 0;
}

struct log_capture
{
    struct lantern_log_record record;
    char timestamp[32];
    char message[128];
    size_t call_count;
};

static enum lantern_log_timestamp_result capture_timestamp(
    void *context, char buffer[32])
{
    (void)context;
    return snprintf(buffer, 32, "2026-09-03T00:00:00.000Z") == 24
               ? LANTERN_LOG_TIMESTAMP_AVAILABLE
               : LANTERN_LOG_TIMESTAMP_UNAVAILABLE;
}

static enum lantern_log_sink_result capture_log(
    void *context, const struct lantern_log_record *record)
{
    struct log_capture *capture = context;
    capture->call_count += 1u;
    capture->record = *record;
    (void)snprintf(capture->timestamp, sizeof(capture->timestamp), "%s",
                   record->timestamp);
    (void)snprintf(capture->message, sizeof(capture->message), "%s",
                   record->message);
    capture->record.timestamp = capture->timestamp;
    capture->record.message = capture->message;
    return LANTERN_LOG_SINK_OK;
}

static enum lantern_log_sink_result reject_log(
    void *context, const struct lantern_log_record *record)
{
    (void)context;
    (void)record;
    return LANTERN_LOG_SINK_ERR_WRITE;
}

static int test_log_metadata(void)
{
    struct log_capture capture = {0};
    const struct lantern_log_config config = {
        .min_level = LANTERN_LOG_LEVEL_INFO,
        .timestamp = capture_timestamp,
        .sink = capture_log,
        .context = &capture,
    };

    const struct lantern_log_metadata metadata = {
        .validator = "validator-a",
        .peer = "peer-b",
        .slot = 7u,
        .has_slot = true,
    };
    if (lantern_log_set_level((enum lantern_log_level)-1) !=
            LANTERN_LOG_ERR_INVALID ||
        lantern_log_set_level(LANTERN_LOG_LEVEL_INFO) != LANTERN_LOG_OK)
    {
        return 1;
    }
    if (lantern_log_emit(&config, LANTERN_LOG_LEVEL_DEBUG, "support",
                         &metadata, "filtered") != LANTERN_LOG_OK ||
        capture.call_count != 0u)
    {
        return 1;
    }
    if (lantern_log_emit(&config, LANTERN_LOG_LEVEL_INFO, "support",
                         &metadata, "message %d", 3) != LANTERN_LOG_OK)
    {
        return 1;
    }

    if (capture.record.level != LANTERN_LOG_LEVEL_INFO ||
        strcmp(capture.record.timestamp,
               "2026-09-03T00:00:00.000Z") != 0 ||
        strcmp(capture.record.component, "support") != 0 ||
        capture.record.metadata != &metadata ||
        strcmp(capture.record.message, "message 3") != 0 ||
        capture.call_count != 1u)
    {
        return 1;
    }

    char long_message[1100];
    memset(long_message, 'x', sizeof(long_message) - 1u);
    long_message[sizeof(long_message) - 1u] = '\0';
    if (lantern_log_emit(&config, LANTERN_LOG_LEVEL_INFO, "support", NULL,
                         "%s", long_message) != LANTERN_LOG_TRUNCATED ||
        capture.call_count != 2u)
    {
        return 1;
    }

    const struct lantern_log_config rejecting_config = {
        .min_level = LANTERN_LOG_LEVEL_INFO,
        .timestamp = NULL,
        .sink = reject_log,
        .context = NULL,
    };
    return lantern_log_emit(&rejecting_config, LANTERN_LOG_LEVEL_INFO,
                            "support", NULL, "rejected") ==
                   LANTERN_LOG_ERR_SINK
               ? 0
               : 1;
}

int main(void)
{
    if (test_string_boundaries() != 0 || test_string_list_boundaries() != 0 ||
        test_secure_zero() != 0 || test_time_helpers() != 0 ||
        test_log_metadata() != 0)
    {
        fprintf(stderr, "support tests failed\n");
        return 1;
    }

    return 0;
}
