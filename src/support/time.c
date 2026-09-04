#include "lantern/support/time.h"

#include <math.h>

#if defined(_WIN32)
#include <windows.h>

enum lantern_time_result lantern_time_now_seconds(double *out_seconds)
{
    if (!out_seconds)
    {
        return LANTERN_TIME_ERR_INVALID;
    }

    LARGE_INTEGER counter;
    LARGE_INTEGER frequency;

    if (!QueryPerformanceCounter(&counter) ||
        !QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0)
    {
        *out_seconds = -1.0;
        return LANTERN_TIME_ERR_CLOCK;
    }

    *out_seconds = (double)counter.QuadPart / (double)frequency.QuadPart;
    return LANTERN_TIME_OK;
}
#else
#include <time.h>

enum lantern_time_result lantern_time_now_seconds(double *out_seconds)
{
    if (!out_seconds)
    {
        return LANTERN_TIME_ERR_INVALID;
    }

    struct timespec value;

    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
    {
        *out_seconds = -1.0;
        return LANTERN_TIME_ERR_CLOCK;
    }

    *out_seconds = (double)value.tv_sec + ((double)value.tv_nsec / 1e9);
    return LANTERN_TIME_OK;
}
#endif /* _WIN32 */

enum lantern_time_result
lantern_time_elapsed_seconds(double started_seconds, double finished_seconds,
                             double *out_seconds)
{
    if (!out_seconds)
    {
        return LANTERN_TIME_ERR_INVALID;
    }

    if (!isfinite(started_seconds) || !isfinite(finished_seconds) ||
        started_seconds < 0.0 || finished_seconds < started_seconds)
    {
        *out_seconds = 0.0;
        return LANTERN_TIME_ERR_INVALID;
    }

    *out_seconds = finished_seconds - started_seconds;
    return LANTERN_TIME_OK;
}
