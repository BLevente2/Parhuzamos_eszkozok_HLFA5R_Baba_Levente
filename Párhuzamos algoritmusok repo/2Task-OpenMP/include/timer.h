#ifndef TIMER_H
#define TIMER_H

#include <time.h>

void timer_start(struct timespec *ts);
double timer_diff_s(const struct timespec *start, const struct timespec *end);

#endif
