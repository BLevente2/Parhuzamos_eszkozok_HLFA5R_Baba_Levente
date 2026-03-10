#ifndef PERF_STATS_H
#define PERF_STATS_H

#include <stddef.h>

double compute_throughput_MBps(size_t total_bytes, double seconds);
double compute_speedup(double serial_time, double parallel_time);
double compute_efficiency(double speedup, int num_threads);

#endif
