#include "lantern/support/log.h"
#include "lantern/support/secure_mem.h"
#include "lantern/support/string_list.h"
#include "lantern/support/strings.h"
#include "lantern/support/time.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int test_string_boundaries(void)
{
    uint8_t byte = 0;
    char output[4] = "x";

    if (lantern_string_duplicate_len("x", SIZE_MAX) != NULL)
    {
        return 1;
    }
    if (lantern_hex_decode("", &byte, (SIZE_MAX / 2u) + 1u) == 0)
    {
        return 1;
    }
    if (lantern_bytes_to_hex(&byte, (SIZE_MAX / 2u) + 1u, output,
                             sizeof(output), false) == 0 ||
        output[0] != '\0')
    {
        return 1;
    }

    return 0;
}

static int test_string_list_boundaries(void)
{
    struct lantern_string_list list;
    lantern_string_list_init(&list);
    if (lantern_string_list_append(&list, "alpha") != 0)
    {
        return 1;
    }
    if (lantern_string_list_copy(&list, &list) != 0 || list.len != 1u ||
        strcmp(list.items[0], "alpha") != 0)
    {
        lantern_string_list_reset(&list);
        return 1;
    }
    lantern_string_list_reset(&list);

    list.len = SIZE_MAX;
    if (lantern_string_list_append(&list, "overflow") == 0)
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
    double first = lantern_time_now_seconds();
    double second = lantern_time_now_seconds();
    if (first < 0.0 || second < first)
    {
        return 1;
    }
    if (lantern_time_elapsed_seconds(-1.0, second) != 0.0 ||
        lantern_time_elapsed_seconds(2.0, 1.0) != 0.0 ||
        lantern_time_elapsed_seconds(1.0, 2.5) != 1.5)
    {
        return 1;
    }

    return 0;
}

static int test_log_metadata(void)
{
    FILE *capture = tmpfile();
    if (!capture)
    {
        return 1;
    }

    int saved_stdout = dup(STDOUT_FILENO);
    if (saved_stdout < 0 || fflush(stdout) != 0 ||
        dup2(fileno(capture), STDOUT_FILENO) < 0)
    {
        if (saved_stdout >= 0)
        {
            close(saved_stdout);
        }
        fclose(capture);
        return 1;
    }

    const struct lantern_log_metadata metadata = {
        .validator = "validator-a",
        .peer = "peer-b",
        .slot = 7u,
        .has_slot = true,
    };
    lantern_log_set_level(LANTERN_LOG_LEVEL_INFO);
    lantern_log_info("support", &metadata, "message %d", 3);

    int restore_result = dup2(saved_stdout, STDOUT_FILENO);
    close(saved_stdout);
    if (restore_result < 0 || fseek(capture, 0, SEEK_SET) != 0)
    {
        fclose(capture);
        return 1;
    }

    char text[2048];
    size_t length = fread(text, 1u, sizeof(text) - 1u, capture);
    text[length] = '\0';
    fclose(capture);

    return strstr(text, "validator=validator-a") &&
                   strstr(text, "peer=peer-b") && strstr(text, "slot=7") &&
                   strstr(text, "message 3")
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
