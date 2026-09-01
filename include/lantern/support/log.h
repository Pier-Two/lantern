#ifndef LANTERN_SUPPORT_LOG_H
#define LANTERN_SUPPORT_LOG_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /** Log message severity. */
    enum lantern_log_level
    {
        LANTERN_LOG_LEVEL_TRACE = 0,
        LANTERN_LOG_LEVEL_DEBUG,
        LANTERN_LOG_LEVEL_INFO,
        LANTERN_LOG_LEVEL_WARN,
        LANTERN_LOG_LEVEL_ERROR,
    };

    /** Borrowed context that remains valid for one log call. */
    struct lantern_log_metadata
    {
        /** Validator or node identifier, or NULL when unavailable. */
        const char *validator;

        /** Peer identifier, or NULL when unavailable. */
        const char *peer;

        /** Consensus slot when has_slot is true. */
        uint64_t slot;

        /** True when slot contains a valid consensus slot. */
        bool has_slot;
    };

    /**
     * Set the minimum severity that the logger writes.
     *
     * This function is thread-safe.
     *
     * @param level Minimum severity.
     *
     * Values outside enum lantern_log_level do not change the current severity.
     */
    void lantern_log_set_level(enum lantern_log_level level);

    /**
     * Parse and set the minimum log severity.
     *
     * This function is thread-safe.
     *
     * @param text Severity name.
     * @param out_level Parsed severity, or NULL when it is not required.
     * @return Zero on success, or -1 when text is invalid.
     */
    int lantern_log_set_level_from_string(const char *text,
                                          enum lantern_log_level *out_level);

#if defined(__GNUC__) || defined(__clang__)
#define LANTERN_LOG_FORMAT(position, arguments)                                \
    __attribute__((format(printf, position, arguments)))
#else
#define LANTERN_LOG_FORMAT(position, arguments)
#endif

    /**
     * Write a best-effort trace message with borrowed context.
     *
     * This function is thread-safe and borrows all pointers for the call.
     */
    void lantern_log_trace(const char *component,
                           const struct lantern_log_metadata *metadata,
                           const char *fmt, ...) LANTERN_LOG_FORMAT(3, 4);

    /**
     * Write a best-effort debug message with borrowed context.
     *
     * This function is thread-safe and borrows all pointers for the call.
     */
    void lantern_log_debug(const char *component,
                           const struct lantern_log_metadata *metadata,
                           const char *fmt, ...) LANTERN_LOG_FORMAT(3, 4);

    /**
     * Write a best-effort information message with borrowed context.
     *
     * This function is thread-safe and borrows all pointers for the call.
     */
    void lantern_log_info(const char *component,
                          const struct lantern_log_metadata *metadata,
                          const char *fmt, ...) LANTERN_LOG_FORMAT(3, 4);

    /**
     * Write a best-effort warning message with borrowed context.
     *
     * This function is thread-safe and borrows all pointers for the call.
     */
    void lantern_log_warn(const char *component,
                          const struct lantern_log_metadata *metadata,
                          const char *fmt, ...) LANTERN_LOG_FORMAT(3, 4);

    /**
     * Write a best-effort error message with borrowed context.
     *
     * This function is thread-safe and borrows all pointers for the call.
     */
    void lantern_log_error(const char *component,
                           const struct lantern_log_metadata *metadata,
                           const char *fmt, ...) LANTERN_LOG_FORMAT(3, 4);

#undef LANTERN_LOG_FORMAT

#ifdef __cplusplus
}
#endif

#endif /* LANTERN_SUPPORT_LOG_H */
