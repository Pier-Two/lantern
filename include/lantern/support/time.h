#ifndef LANTERN_SUPPORT_TIME_H
#define LANTERN_SUPPORT_TIME_H

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * Read monotonic seconds from a platform-defined origin.
     *
     * This function is thread-safe.
     *
     * @return Monotonic seconds, or -1.0 when the clock read fails.
     */
    double lantern_time_now_seconds(void);

    /**
     * Return elapsed seconds, or zero for invalid or reversed readings.
     *
     * This function is thread-safe.
     */
    double lantern_time_elapsed_seconds(double started_seconds,
                                        double finished_seconds);

#ifdef __cplusplus
}
#endif

#endif /* LANTERN_SUPPORT_TIME_H */
