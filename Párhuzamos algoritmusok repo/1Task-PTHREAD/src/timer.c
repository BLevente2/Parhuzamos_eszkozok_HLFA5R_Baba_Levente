#include "timer.h"
#include <time.h>

void timer_start(Timer *t) {
    clock_gettime(CLOCK_MONOTONIC, &t->start);
}

void timer_stop(Timer *t) {
    clock_gettime(CLOCK_MONOTONIC, &t->end);
}

double timer_elapsed(const Timer *t) {
    double s = (double)(t->end.tv_sec - t->start.tv_sec);
    double ns = (double)(t->end.tv_nsec - t->start.tv_nsec) / 1e9;
    return s + ns;
}
