#include "lantern/support/log.h"

#include <ctype.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static pthread_mutex_t s_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static atomic_int s_min_level = LANTERN_LOG_LEVEL_INFO;
static bool equals_ignore_case(const char *lhs, const char *rhs);

static const char *level_to_string(enum lantern_log_level level)
{
    switch (level)
    {
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

void lantern_log_set_level(enum lantern_log_level level)
{
    if (level < LANTERN_LOG_LEVEL_TRACE || level > LANTERN_LOG_LEVEL_ERROR)
    {
        return;
    }

    atomic_store_explicit(&s_min_level, level, memory_order_relaxed);
}

static bool equals_ignore_case(const char *lhs, const char *rhs)
{
    if (!lhs || !rhs)
    {
        return false;
    }

    while (*lhs && *rhs)
    {
        unsigned char a = (unsigned char)(*lhs);
        unsigned char b = (unsigned char)(*rhs);
        if (tolower(a) != tolower(b))
        {
            return false;
        }

        ++lhs;
        ++rhs;
    }

    return *lhs == '\0' && *rhs == '\0';
}

static int parse_level(const char *text, enum lantern_log_level *out_level)
{
    if (!text || !out_level)
    {
        return -1;
    }

    if (equals_ignore_case(text, "trace"))
    {
        *out_level = LANTERN_LOG_LEVEL_TRACE;
        return 0;
    }

    if (equals_ignore_case(text, "debug"))
    {
        *out_level = LANTERN_LOG_LEVEL_DEBUG;
        return 0;
    }

    if (equals_ignore_case(text, "info"))
    {
        *out_level = LANTERN_LOG_LEVEL_INFO;
        return 0;
    }

    if (equals_ignore_case(text, "warn") || equals_ignore_case(text, "warning"))
    {
        *out_level = LANTERN_LOG_LEVEL_WARN;
        return 0;
    }

    if (equals_ignore_case(text, "error"))
    {
        *out_level = LANTERN_LOG_LEVEL_ERROR;
        return 0;
    }

    return -1;
}

int lantern_log_set_level_from_string(const char *text,
                                      enum lantern_log_level *out_level)
{
    enum lantern_log_level parsed = LANTERN_LOG_LEVEL_INFO;
    if (parse_level(text, &parsed) != 0)
    {
        return -1;
    }

    lantern_log_set_level(parsed);
    if (out_level)
    {
        *out_level = parsed;
    }

    return 0;
}

static void format_timestamp(char buffer[32])
{
    struct timespec ts;
    if (timespec_get(&ts, TIME_UTC) != TIME_UTC)
    {
        buffer[0] = '\0';
        return;
    }

    struct tm tm_result;
    if (!gmtime_r(&ts.tv_sec, &tm_result))
    {
        buffer[0] = '\0';
        return;
    }

    int written =
        snprintf(buffer, 32, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                 tm_result.tm_year + 1900, tm_result.tm_mon + 1,
                 tm_result.tm_mday, tm_result.tm_hour, tm_result.tm_min,
                 tm_result.tm_sec, ts.tv_nsec / 1000000L);
    if (written < 0 || written >= 32)
    {
        buffer[0] = '\0';
    }
}

static void format_component_tag(const char *component, char out[16])
{
    char lowered[11];
    const char *text = component && component[0] ? component : "?";
    size_t i = 0;
    for (; i < sizeof(lowered) - 1u && text[i]; ++i)
    {
        lowered[i] = (char)tolower((unsigned char)text[i]);
    }
    lowered[i] = '\0';

    (void)snprintf(out, 16, "[%s]", lowered);
}

void lantern_log(enum lantern_log_level level, const char *component,
                 const struct lantern_log_metadata *metadata, const char *fmt,
                 ...)
{
    int min_level = atomic_load_explicit(&s_min_level, memory_order_relaxed);
    if ((int)level < min_level || !fmt)
    {
        return;
    }

    va_list args;
    va_start(args, fmt);

    char formatted[1024];
    int msg_written = vsnprintf(formatted, sizeof(formatted), fmt, args);
    va_end(args);
    if (msg_written < 0)
    {
        formatted[0] = '\0';
    }
    else if ((size_t)msg_written >= sizeof(formatted))
    {
        formatted[sizeof(formatted) - 1] = '\0';
    }

    char timestamp[32];
    format_timestamp(timestamp);

    FILE *target = level >= LANTERN_LOG_LEVEL_WARN ? stderr : stdout;
    char tag[16];
    format_component_tag(component, tag);
    static const char unknown_timestamp[] = "????"
                                            "-??"
                                            "-??T??:??:??.???Z";

    if (pthread_mutex_lock(&s_log_mutex) != 0)
    {
        return;
    }

    /* Logging is best-effort because callers cannot recover from stream errors.
     */
    (void)fprintf(target, "%s  %-5s  %-12s",
                  timestamp[0] ? timestamp : unknown_timestamp,
                  level_to_string(level), tag);
    if (metadata && metadata->validator)
    {
        (void)fprintf(target, " validator=%s", metadata->validator);
    }
    if (metadata && metadata->peer)
    {
        (void)fprintf(target, " peer=%s", metadata->peer);
    }
    if (metadata && metadata->has_slot)
    {
        (void)fprintf(target, " slot=%" PRIu64, metadata->slot);
    }
    (void)fprintf(target, " %s\n", formatted);
    (void)fflush(target);
    (void)pthread_mutex_unlock(&s_log_mutex);
}
