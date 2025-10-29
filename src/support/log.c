#include "lantern/support/log.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static char g_node_id[96] = {0};
static enum LanternLogLevel g_min_level = LANTERN_LOG_LEVEL_DEBUG;

static const char *level_to_string(enum LanternLogLevel level) {
    switch (level) {
    case LANTERN_LOG_LEVEL_TRACE:
        return "TRACE";
    case LANTERN_LOG_LEVEL_DEBUG:
        return "DEBUG";
    case LANTERN_LOG_LEVEL_INFO:
        return "INFO";
    case LANTERN_LOG_LEVEL_WARN:
        return "WARN";
    case LANTERN_LOG_LEVEL_ERROR:
        return "ERROR";
    default:
        return "INFO";
    }
}

void lantern_log_set_node_id(const char *node_id) {
    if (!node_id) {
        g_node_id[0] = '\0';
        return;
    }
    size_t len = strlen(node_id);
    if (len >= sizeof(g_node_id)) {
        len = sizeof(g_node_id) - 1;
    }
    memcpy(g_node_id, node_id, len);
    g_node_id[len] = '\0';
}

void lantern_log_reset_node_id(void) {
    g_node_id[0] = '\0';
}

void lantern_log_set_level(enum LanternLogLevel level) {
    g_min_level = level;
}

enum LanternLogLevel lantern_log_get_level(void) {
    return g_min_level;
}

static int equals_ignore_case(const char *lhs, const char *rhs) {
    if (!lhs || !rhs) {
        return 0;
    }
    while (*lhs && *rhs) {
        unsigned char a = (unsigned char)(*lhs);
        unsigned char b = (unsigned char)(*rhs);
        if (tolower(a) != tolower(b)) {
            return 0;
        }
        ++lhs;
        ++rhs;
    }
    return *lhs == '\0' && *rhs == '\0';
}

static int parse_level(const char *text, enum LanternLogLevel *out_level) {
    if (!text || !out_level) {
        return -1;
    }
    if (equals_ignore_case(text, "trace")) {
        *out_level = LANTERN_LOG_LEVEL_TRACE;
        return 0;
    }
    if (equals_ignore_case(text, "debug")) {
        *out_level = LANTERN_LOG_LEVEL_DEBUG;
        return 0;
    }
    if (equals_ignore_case(text, "info")) {
        *out_level = LANTERN_LOG_LEVEL_INFO;
        return 0;
    }
    if (equals_ignore_case(text, "warn") || equals_ignore_case(text, "warning")) {
        *out_level = LANTERN_LOG_LEVEL_WARN;
        return 0;
    }
    if (equals_ignore_case(text, "error")) {
        *out_level = LANTERN_LOG_LEVEL_ERROR;
        return 0;
    }
    return -1;
}

int lantern_log_set_level_from_string(const char *text, enum LanternLogLevel *out_level) {
    enum LanternLogLevel parsed = LANTERN_LOG_LEVEL_INFO;
    if (parse_level(text, &parsed) != 0) {
        return -1;
    }
    lantern_log_set_level(parsed);
    if (out_level) {
        *out_level = parsed;
    }
    return 0;
}

static void append_field(char **cursor, size_t *remaining, const char *key, const char *value) {
    if (!cursor || !*cursor || !remaining || *remaining == 0) {
        return;
    }
    int written = snprintf(*cursor, *remaining, " %s=%s", key, value ? value : "-");
    if (written < 0) {
        return;
    }
    size_t w = (size_t)written;
    if (w >= *remaining) {
        *remaining = 0;
        return;
    }
    *cursor += w;
    *remaining -= w;
}

static void append_numeric_field(
    char **cursor,
    size_t *remaining,
    const char *key,
    uint64_t value,
    bool present) {
    if (!present) {
        append_field(cursor, remaining, key, "-");
        return;
    }
    if (!cursor || !*cursor || !remaining || *remaining == 0) {
        return;
    }
    int written = snprintf(*cursor, *remaining, " %s=%" PRIu64, key, value);
    if (written < 0) {
        return;
    }
    size_t w = (size_t)written;
    if (w >= *remaining) {
        *remaining = 0;
        return;
    }
    *cursor += w;
    *remaining -= w;
}

static void append_escaped_message(char **cursor, size_t *remaining, const char *message) {
    if (!cursor || !*cursor || !remaining || *remaining == 0) {
        return;
    }
    if (!message) {
        message = "";
    }
    if (*remaining <= 0) {
        return;
    }
    **cursor = ' ';
    *cursor += 1;
    *remaining -= 1;
    if (*remaining == 0) {
        return;
    }
    **cursor = 'm';
    *cursor += 1;
    *remaining -= 1;
    if (*remaining == 0) {
        return;
    }
    **cursor = 's';
    *cursor += 1;
    *remaining -= 1;
    if (*remaining == 0) {
        return;
    }
    **cursor = 'g';
    *cursor += 1;
    *remaining -= 1;
    if (*remaining == 0) {
        return;
    }
    **cursor = '=';
    *cursor += 1;
    *remaining -= 1;
    if (*remaining == 0) {
        return;
    }
    **cursor = '"';
    *cursor += 1;
    *remaining -= 1;
    const char *ptr = message;
    while (*ptr && *remaining > 1) {
        if (*ptr == '"' || *ptr == '\\') {
            if (*remaining <= 2) {
                break;
            }
            **cursor = '\\';
            *cursor += 1;
            *remaining -= 1;
        }
        **cursor = *ptr;
        *cursor += 1;
        *remaining -= 1;
        ptr += 1;
    }
    if (*remaining == 0) {
        return;
    }
    **cursor = '"';
    *cursor += 1;
    *remaining -= 1;
}

static void format_timestamp(char buffer[32]) {
    struct timespec ts;
    if (timespec_get(&ts, TIME_UTC) != TIME_UTC) {
        buffer[0] = '\0';
        return;
    }
    struct tm tm_result;
    if (!gmtime_r(&ts.tv_sec, &tm_result)) {
        buffer[0] = '\0';
        return;
    }
    size_t len = strftime(buffer, 32, "%Y-%m-%dT%H:%M:%S", &tm_result);
    if (len == 0) {
        buffer[0] = '\0';
        return;
    }
    int written = snprintf(buffer + len, 32 - len, ".%03ldZ", ts.tv_nsec / 1000000L);
    if (written < 0) {
        buffer[0] = '\0';
        return;
    }
}

void lantern_log_log(
    enum LanternLogLevel level,
    const char *component,
    const struct lantern_log_metadata *metadata,
    const char *fmt,
    va_list args) {
    if (level < g_min_level) {
        return;
    }

    char formatted[1024];
    int msg_written = vsnprintf(formatted, sizeof(formatted), fmt ? fmt : "", args);
    if (msg_written < 0) {
        formatted[0] = '\0';
    } else if ((size_t)msg_written >= sizeof(formatted)) {
        formatted[sizeof(formatted) - 1] = '\0';
    }

    char timestamp[32];
    format_timestamp(timestamp);

    char line[1400];
    int prefix_written = snprintf(
        line,
        sizeof(line),
        "lantern ts=%s level=%s component=%s",
        timestamp[0] ? timestamp : "-",
        level_to_string(level),
        component ? component : "-");
    if (prefix_written < 0) {
        return;
    }
    size_t used = (size_t)prefix_written;
    if (used >= sizeof(line)) {
        used = sizeof(line) - 1;
    }
    char *cursor = line + used;
    size_t remaining = sizeof(line) - used;

    append_field(&cursor, &remaining, "node", g_node_id[0] ? g_node_id : "-");
    const char *validator = metadata && metadata->validator ? metadata->validator : "-";
    append_field(&cursor, &remaining, "validator", validator);
    const char *peer = metadata && metadata->peer ? metadata->peer : "-";
    append_field(&cursor, &remaining, "peer", peer);
    uint64_t slot = metadata && metadata->has_slot ? metadata->slot : 0;
    append_numeric_field(&cursor, &remaining, "slot", slot, metadata && metadata->has_slot);
    append_escaped_message(&cursor, &remaining, formatted);

    if (remaining == 0) {
        line[sizeof(line) - 2] = '"';
        line[sizeof(line) - 1] = '\0';
    } else {
        if ((size_t)(cursor - line) >= sizeof(line) - 1) {
            line[sizeof(line) - 2] = '"';
            line[sizeof(line) - 1] = '\0';
        } else {
            *cursor = '\0';
        }
    }

    fprintf(level >= LANTERN_LOG_LEVEL_WARN ? stderr : stdout, "%s\n", line);
    fflush(level >= LANTERN_LOG_LEVEL_WARN ? stderr : stdout);
}

static void log_variadic(
    enum LanternLogLevel level,
    const char *component,
    const struct lantern_log_metadata *metadata,
    const char *fmt,
    va_list args) {
    lantern_log_log(level, component, metadata, fmt, args);
}

void lantern_log_trace(
    const char *component,
    const struct lantern_log_metadata *metadata,
    const char *fmt,
    ...) {
    va_list args;
    va_start(args, fmt);
    log_variadic(LANTERN_LOG_LEVEL_TRACE, component, metadata, fmt, args);
    va_end(args);
}

void lantern_log_debug(
    const char *component,
    const struct lantern_log_metadata *metadata,
    const char *fmt,
    ...) {
    va_list args;
    va_start(args, fmt);
    log_variadic(LANTERN_LOG_LEVEL_DEBUG, component, metadata, fmt, args);
    va_end(args);
}

void lantern_log_info(
    const char *component,
    const struct lantern_log_metadata *metadata,
    const char *fmt,
    ...) {
    va_list args;
    va_start(args, fmt);
    log_variadic(LANTERN_LOG_LEVEL_INFO, component, metadata, fmt, args);
    va_end(args);
}

void lantern_log_warn(
    const char *component,
    const struct lantern_log_metadata *metadata,
    const char *fmt,
    ...) {
    va_list args;
    va_start(args, fmt);
    log_variadic(LANTERN_LOG_LEVEL_WARN, component, metadata, fmt, args);
    va_end(args);
}

void lantern_log_error(
    const char *component,
    const struct lantern_log_metadata *metadata,
    const char *fmt,
    ...) {
    va_list args;
    va_start(args, fmt);
    log_variadic(LANTERN_LOG_LEVEL_ERROR, component, metadata, fmt, args);
    va_end(args);
}
