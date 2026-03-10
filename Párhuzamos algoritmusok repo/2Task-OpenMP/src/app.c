#include "app.h"
#include "cli.h"
#include "file_hasher.h"
#include "hashfile.h"
#include "timer.h"
#include "perf_stats.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int run_app(const ProgramOptions *opts)
{
    if (opts->mode == MODE_CREATE) {
        FileHasher fh;
        fh_init(&fh, opts->input_file, opts->block_size);
        fh_compute_parallel(&fh, opts->num_threads);
        if (hf_write(&fh, opts->output_file) != 0) {
            fprintf(stderr, "Error writing hash file\n");
            fh_free(&fh);
            return EXIT_FAILURE;
        }
        fh_free(&fh);
        return EXIT_SUCCESS;
    }

    HashFile hf;
    if (hf_read(&hf, opts->hash_file) != 0) {
        fprintf(stderr, "Error reading hash file\n");
        return EXIT_FAILURE;
    }

    FileHasher fh;
    fh_init(&fh, opts->input_file, hf.block_size);

    struct timespec t0, t1, t2, t3;
    timer_start(&t0);
    fh_compute_serial(&fh);
    timer_start(&t1);

    int ok = 1;
    for (size_t i = 0; i < fh.num_blocks; ++i) {
        if (memcmp(fh.hashes + i * fh.hash_len,
                   hf.hashes + i * hf.hash_len,
                   fh.hash_len) != 0) {
            ok = 0;
            break;
        }
    }
    printf("Serial integrity: %s\n", ok ? "OK" : "FAIL");

    double serial_time = timer_diff_s(&t0, &t1);

    timer_start(&t2);
    fh_compute_parallel(&fh, opts->num_threads);
    timer_start(&t3);

    ok = 1;
    for (size_t i = 0; i < fh.num_blocks; ++i) {
        if (memcmp(fh.hashes + i * fh.hash_len,
                   hf.hashes + i * hf.hash_len,
                   fh.hash_len) != 0) {
            ok = 0;
            break;
        }
    }
    printf("Parallel integrity: %s\n", ok ? "OK" : "FAIL");

    double parallel_time = timer_diff_s(&t2, &t3);

    size_t total_bytes = fh.num_blocks * fh.block_size;
    double th_serial   = compute_throughput_MBps(total_bytes, serial_time);
    double th_parallel = compute_throughput_MBps(total_bytes, parallel_time);
    double speedup     = compute_speedup(serial_time, parallel_time);
    double efficiency  = compute_efficiency(speedup, opts->num_threads);

    printf("Serial   : %.6f s (%.2f MB/s)\n",   serial_time,   th_serial);
    printf("Parallel : %.6f s (%.2f MB/s)\n",   parallel_time, th_parallel);
    printf("Speed-up : %.2f×\n",                speedup);
    printf("Efficiency: %.2f per thread\n",     efficiency);

    fh_free(&fh);
    hf_free(&hf);
    return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
    ProgramOptions opts = {0};
    if (parse_cli(argc, argv, &opts) != 0) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
    return run_app(&opts);
}
