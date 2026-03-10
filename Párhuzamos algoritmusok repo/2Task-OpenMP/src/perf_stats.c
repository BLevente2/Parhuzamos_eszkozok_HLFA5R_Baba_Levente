#include "perf_stats.h"

double compute_throughput_MBps(size_t total_bytes, double seconds)
{
    double mb = (double)total_bytes / (1024.0 * 1024.0);
    return mb / seconds;
}

double compute_speedup(double serial_time, double parallel_time)
{
    return parallel_time > 0.0 ? serial_time / parallel_time : 0.0;
}

double compute_efficiency(double speedup, int num_threads)
{
    return num_threads > 0 ? speedup / (double)num_threads : 0.0;
}
