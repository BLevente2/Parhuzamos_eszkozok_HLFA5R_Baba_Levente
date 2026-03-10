#include "timer.h"
#include <time.h>

void timer_start(struct timespec *ts)
{
    clock_gettime(CLOCK_MONOTONIC, ts);
}

double timer_diff_s(const struct timespec *start, const struct timespec *end)
{
    double sec  = (double)(end->tv_sec  - start->tv_sec);
    double nsec = (double)(end->tv_nsec - start->tv_nsec);
    return sec + nsec * 1e-9;
}
