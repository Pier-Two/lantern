#include "lantern/support/time.h"

#if defined(_WIN32)
#include <windows.h>

static double platform_time_now_seconds(void)
{
    LARGE_INTEGER counter;
    LARGE_INTEGER frequency;
    if (!QueryPerformanceCounter(&counter) ||
        !QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0)
    {
        return -1.0;
    }

    return (double)counter.QuadPart / (double)frequency.QuadPart;
}
#else
#include <time.h>

static double platform_time_now_seconds(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
    {
        return -1.0;
    }

    return (double)value.tv_sec + ((double)value.tv_nsec / 1e9);
}
#endif /* _WIN32 */

double lantern_time_now_seconds(void)
{
    return platform_time_now_seconds();
}

double lantern_time_elapsed_seconds(double started_seconds,
                                    double finished_seconds)
{
    if (started_seconds < 0.0 || finished_seconds < started_seconds)
    {
        return 0.0;
    }

    return finished_seconds - started_seconds;
}
