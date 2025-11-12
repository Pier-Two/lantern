#include "lantern/support/time.h"

#include <sys/time.h>
#include <time.h>

#if defined(__APPLE__) && !defined(CLOCK_MONOTONIC)
#include <mach/mach_time.h>
#endif

double lantern_time_now_seconds(void) {
#if defined(CLOCK_MONOTONIC)
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (double)ts.tv_sec + ((double)ts.tv_nsec / 1e9);
    }
#elif defined(__APPLE__)
    static mach_timebase_info_data_t timebase = {0};
    static double scale = 0.0;
    if (scale == 0.0) {
        if (mach_timebase_info(&timebase) == KERN_SUCCESS && timebase.denom != 0) {
            scale = ((double)timebase.numer / (double)timebase.denom) / 1e9;
        } else {
            scale = 1.0 / 1e9;
        }
    }
    uint64_t now = mach_absolute_time();
    return (double)now * scale;
#endif
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + ((double)tv.tv_usec / 1e6);
}
