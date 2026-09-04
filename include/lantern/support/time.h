#ifndef LANTERN_SUPPORT_TIME_H
#define LANTERN_SUPPORT_TIME_H

/**
 * @file
 * Read platform monotonic-clock values and calculate elapsed durations.
 *
 * Clock readings use seconds from a platform-defined origin and are comparable
 * only when they come from the same clock. Failures are reported through
 * `lantern_time_result`, with documented sentinel values written to valid
 * output destinations.
 */

#ifdef __cplusplus
extern "C"
{
#endif

/** Distinguishes valid time output from invalid input and clock failure. */
enum lantern_time_result
{
    LANTERN_TIME_OK = 0,
    LANTERN_TIME_ERR_INVALID = -1,
    LANTERN_TIME_ERR_CLOCK = -2,
};

/**
 * Read elapsed seconds from a platform monotonic clock.
 *
 * The platform defines the clock origin. Values from different processes or
 * clock implementations are not comparable. This function is thread-safe.
 *
 * A clock failure writes `-1.0` to `out_seconds`.
 *
 * @param[out] out_seconds Destination for seconds from the platform-defined
 * origin. Must not be `NULL`.
 * @return `LANTERN_TIME_OK` after writing a nonnegative clock reading.
 * @return `LANTERN_TIME_ERR_INVALID` when `out_seconds` is `NULL`.
 * @return `LANTERN_TIME_ERR_CLOCK` when the platform clock read fails or has
 * no valid frequency.
 */
enum lantern_time_result lantern_time_now_seconds(double *out_seconds);

/**
 * Calculate elapsed seconds between two monotonic clock readings.
 *
 * Both inputs must use the same clock and origin. The function does not modify
 * shared state and is thread-safe. Invalid readings write `0.0` to a valid
 * `out_seconds` destination.
 *
 * @param[in] started_seconds Earlier reading in seconds. A negative value is
 * invalid.
 * @param[in] finished_seconds Later reading in seconds from the same monotonic
 * clock.
 * @param[out] out_seconds Destination for elapsed seconds. Must not be `NULL`.
 * @return `LANTERN_TIME_OK` after writing the elapsed duration.
 * @return `LANTERN_TIME_ERR_INVALID` when `out_seconds` is `NULL`, an input is
 * not finite, an input is negative, or the readings are reversed.
 */
enum lantern_time_result
lantern_time_elapsed_seconds(double started_seconds, double finished_seconds,
                             double *out_seconds);

#ifdef __cplusplus
}
#endif

#endif /* LANTERN_SUPPORT_TIME_H */
