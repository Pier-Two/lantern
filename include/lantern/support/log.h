#ifndef LANTERN_SUPPORT_LOG_H
#define LANTERN_SUPPORT_LOG_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/** Orders message severities from diagnostic trace output through errors. */
enum lantern_log_level
{
    LANTERN_LOG_LEVEL_TRACE = 0,
    LANTERN_LOG_LEVEL_DEBUG,
    LANTERN_LOG_LEVEL_INFO,
    LANTERN_LOG_LEVEL_WARN,
    LANTERN_LOG_LEVEL_ERROR,
};

/**
 * Supplies optional borrowed context for one log call.
 *
 * The caller owns all referenced text and must keep it valid until the call
 * returns. A zero-initialized value supplies no context.
 */
struct lantern_log_metadata
{
    /** This borrowed validator or node identifier can be `NULL`. */
    const char *validator;

    /** This borrowed peer identifier can be `NULL`. */
    const char *peer;

    /** This consensus slot is valid only when `has_slot` is true. */
    uint64_t slot;

    /** This value states whether `slot` contains a valid consensus slot. */
    bool has_slot;
};

/**
 * Supplies one immutable record to a sink callback.
 *
 * The record and all referenced data remain valid only until the sink callback
 * returns. The sink must not retain any pointer from the record.
 */
struct lantern_log_record
{
    /** This value supplies the message severity. */
    enum lantern_log_level level;

    /** This borrowed null-terminated string supplies the formatted
     * timestamp. */
    const char *timestamp;

    /** This borrowed component name can be `NULL`. */
    const char *component;

    /** This borrowed message context can be `NULL`. */
    const struct lantern_log_metadata *metadata;

    /** This borrowed null-terminated string supplies the formatted message. */
    const char *message;
};

/** Distinguishes an available timestamp from clock or conversion failure. */
enum lantern_log_timestamp_result
{
    LANTERN_LOG_TIMESTAMP_AVAILABLE = 0,
    LANTERN_LOG_TIMESTAMP_UNAVAILABLE = 1,
};

/**
 * Write one null-terminated timestamp for a log record.
 *
 * The callback must not retain `buffer`. The caller determines whether
 * concurrent calls can share `context`.
 *
 * @param[in,out] context Callback state from `lantern_log_config`. This value
 * can be `NULL`.
 * @param[out] buffer Buffer for a null-terminated timestamp of at most 31
 * bytes.
 * @return `LANTERN_LOG_TIMESTAMP_AVAILABLE` after writing a complete
 * timestamp.
 * @return `LANTERN_LOG_TIMESTAMP_UNAVAILABLE` when no timestamp is available.
 * The caller ignores `buffer`.
 */
typedef enum lantern_log_timestamp_result (*lantern_log_timestamp_fn)(
    void *context, char buffer[32]);

/** Distinguishes successful record consumption from a sink write failure. */
enum lantern_log_sink_result
{
    LANTERN_LOG_SINK_OK = 0,
    LANTERN_LOG_SINK_ERR_WRITE = -1,
};

/**
 * Consume one immutable log record.
 *
 * The callback must not retain `record` or its referenced data. The caller
 * determines whether concurrent calls can share `context`.
 *
 * @param[in,out] context Callback state from `lantern_log_config`. This value
 * can be `NULL`.
 * @param[in] record Complete borrowed record. Must not be `NULL`.
 * @return `LANTERN_LOG_SINK_OK` after consuming the record successfully.
 * @return `LANTERN_LOG_SINK_ERR_WRITE` when the sink cannot consume the record.
 */
typedef enum lantern_log_sink_result (*lantern_log_sink_fn)(
    void *context, const struct lantern_log_record *record);

/**
 * Supplies borrowed policy and environmental dependencies for log emission.
 *
 * The caller owns this configuration and `context`. Both must remain valid
 * until the emission call and both callbacks return. Concurrent use is safe
 * only when the callbacks permit concurrent access to `context`.
 */
struct lantern_log_config
{
    /** This value is the lowest severity passed to either callback. */
    enum lantern_log_level min_level;

    /** This optional callback supplies the timestamp. */
    lantern_log_timestamp_fn timestamp;

    /** This required callback consumes the completed record. */
    lantern_log_sink_fn sink;

    /** This borrowed state is passed unchanged to both callbacks. */
    void *context;
};

/**
 * Distinguishes complete or truncated emission from invalid input, formatting
 * failure, and sink failure.
 */
enum lantern_log_result
{
    LANTERN_LOG_OK = 0,
    LANTERN_LOG_TRUNCATED = 1,
    LANTERN_LOG_ERR_INVALID = -1,
    LANTERN_LOG_ERR_FORMAT = -2,
    LANTERN_LOG_ERR_SINK = -3,
};

/**
 * Set the process-default minimum log severity.
 *
 * The new threshold affects later calls to `lantern_log`. Values outside
 * `lantern_log_level` leave the threshold unchanged. This function is
 * thread-safe.
 *
 * @param[in] level Lowest severity that the process-default logger writes.
 * @return `LANTERN_LOG_OK` after changing the threshold.
 * @return `LANTERN_LOG_ERR_INVALID` when `level` is outside the enumeration.
 */
enum lantern_log_result lantern_log_set_level(enum lantern_log_level level);

/**
 * Parse text and set the process-default minimum log severity.
 *
 * Matching is case-insensitive. The accepted values are `trace`, `debug`,
 * `info`, `warn`, `warning`, and `error`. A failure leaves the process-default
 * threshold and `out_level` unchanged. This function is thread-safe.
 *
 * @param[in] text Null-terminated severity name. Must not be `NULL`.
 * @param[out] out_level Optional destination for the parsed severity. This
 * value can be `NULL`.
 * @return `LANTERN_LOG_OK` after setting the threshold and, when requested,
 * writing `out_level`.
 * @return `LANTERN_LOG_ERR_INVALID` when `text` is `NULL` or unsupported.
 */
enum lantern_log_result
lantern_log_set_level_from_string(const char *text,
                                  enum lantern_log_level *out_level);

#if defined(__GNUC__) || defined(__clang__)
#define LANTERN_LOG_FORMAT(position, arguments)                                \
    __attribute__((format(printf, position, arguments)))
#else
#define LANTERN_LOG_FORMAT(position, arguments)
#endif

/**
 * Format and emit one message through explicit logger dependencies.
 *
 * The function borrows all pointers until the callbacks return. A missing or
 * failed timestamp callback supplies `????-??-??T??:??:??.???Z` to the sink.
 * A filtered message calls neither callback. Invalid input and formatting
 * failure also call neither callback. The function does not modify `config`,
 * `component`, `metadata`, or `fmt`. Callback thread safety determines whether
 * concurrent calls can share one configuration.
 *
 * @param[in] config Borrowed configuration with a valid minimum severity and
 * non-`NULL` sink. Must not be `NULL`.
 * @param[in] level Message severity from `lantern_log_level`.
 * @param[in] component Borrowed component name. This value can be `NULL`.
 * @param[in] metadata Optional borrowed message context. This value can be
 * `NULL`.
 * @param[in] fmt Null-terminated `printf` format string. Must not be `NULL`.
 * @param[in] ... Values required by `fmt`.
 * @return `LANTERN_LOG_OK` after emitting the complete message or filtering
 * it below `config->min_level`.
 * @return `LANTERN_LOG_TRUNCATED` after emitting the first 1023 message bytes.
 * @return `LANTERN_LOG_ERR_INVALID` when the configuration, level, sink, or
 * format string is invalid.
 * @return `LANTERN_LOG_ERR_FORMAT` when `vsnprintf` cannot format the message.
 * @return `LANTERN_LOG_ERR_SINK` when the sink returns
 * `LANTERN_LOG_SINK_ERR_WRITE`.
 */
enum lantern_log_result
lantern_log_emit(const struct lantern_log_config *config,
                 enum lantern_log_level level, const char *component,
                 const struct lantern_log_metadata *metadata, const char *fmt,
                 ...) LANTERN_LOG_FORMAT(5, 6);

/**
 * Write a message with the process-default logger.
 *
 * The default logger uses UTC wall time, stdout below warning severity,
 * stderr otherwise, and the threshold set by `lantern_log_set_level`. It
 * serializes each stream while it writes. The function borrows all pointers
 * until it returns and reports no formatting, truncation, timestamp, or stream
 * failure. An invalid level or format string produces no output. This function
 * is thread-safe.
 *
 * @param[in] level Message severity from `lantern_log_level`.
 * @param[in] component Borrowed component name. `NULL` produces the `?` tag.
 * @param[in] metadata Optional borrowed message context. This value can be
 * `NULL`.
 * @param[in] fmt Null-terminated `printf` format string. Must not be `NULL`.
 * @param[in] ... Values required by `fmt`.
 */
void lantern_log(enum lantern_log_level level, const char *component,
                 const struct lantern_log_metadata *metadata, const char *fmt,
                 ...) LANTERN_LOG_FORMAT(4, 5);

#undef LANTERN_LOG_FORMAT

#ifdef __cplusplus
}
#endif

#endif /* LANTERN_SUPPORT_LOG_H */
