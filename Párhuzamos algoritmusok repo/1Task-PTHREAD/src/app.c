#include "app.h"
#include "file_scanner.h"
#include "hash_store.h"
#include "sha256.h"
#include "util.h"
#include "timer.h"
#include "thread_manager.h"
#include "checker.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

int parse_args(int argc, char **argv, AppMode *mode,
               const char **first_path, const char **second_path,
               size_t *thread_count) {
    if (argc < 4) return -1;
    if (strcmp(argv[1], "create") == 0 && argc == 4) {
        *mode = MODE_CREATE;
        *first_path  = argv[2];
        *second_path = argv[3];
        return 0;
    }
    if (strcmp(argv[1], "check") == 0 && argc == 5) {
        *mode = MODE_CHECK;
        *first_path  = argv[2];
        *second_path = argv[3];
        *thread_count = (size_t)atoi(argv[4]);
        return 0;
    }
    return -1;
}

int app_create(const char *dir_path, const char *out_hash_file) {
    FileList *fl = fs_scan_directory(dir_path);
    HashStore store;
    store.count = fl->count;
    store.records = malloc(store.count * sizeof(HashRecord));
    for (size_t i = 0; i < fl->count; ++i) {
        store.records[i].path = strdup(fl->entries[i].path);
        SHA256_CTX ctx;
        uint8_t digest[SHA256_DIGEST_LENGTH];
        sha256_init(&ctx);
        file_hash_update(&ctx, fl->entries[i].path);
        sha256_final(&ctx, digest);
        sha256_to_hex(digest, store.records[i].hex_digest);
    }
    if (hs_write(out_hash_file, &store) != 0) {
        warnf("Failed to write hash file");
        fs_free(fl);
        hs_free(&store);
        return -1;
    }
    fs_free(fl);
    hs_free(&store);
    return 0;
}

int app_check(const char *hash_file, const char *dir_path, size_t thread_count) {
    HashStore *hs = hs_read(hash_file);
    if (!hs) {
        warnf("Failed to read hash file");
        return -1;
    }
    FileList *fl = fs_scan_directory(dir_path);
    Assignment *asgn = tm_assign(fl, thread_count);
    pthread_t *threads = malloc(thread_count * sizeof(pthread_t));
    CheckerArgs *args = malloc(thread_count * sizeof(CheckerArgs));
    size_t errors = 0;
    Timer tpar;
    timer_start(&tpar);
    for (size_t t = 0; t < thread_count; ++t) {
        args[t].hs = hs;
        args[t].fl = fl;
        args[t].asgn = asgn;
        args[t].thread_id = t;
        args[t].error_count = &errors;
        args[t].bytes_processed = 0;
        pthread_create(&threads[t], NULL, checker_worker, &args[t]);
    }
    for (size_t t = 0; t < thread_count; ++t) {
        pthread_join(threads[t], NULL);
    }
    timer_stop(&tpar);
    uint64_t bytes_par = 0;
    for (size_t t = 0; t < thread_count; ++t) {
        bytes_par += args[t].bytes_processed;
    }
    double t_par = timer_elapsed(&tpar);
    double mb_par = bytes_par / (1024.0 * 1024.0) / t_par;
    Timer tser;
    size_t ser_errors = 0;
    timer_start(&tser);
    uint64_t bytes_ser = checker_serial(hs, fl, &ser_errors);
    timer_stop(&tser);
    double t_ser = timer_elapsed(&tser);
    double speedup = t_ser / t_par;
    double efficiency = speedup / thread_count;
    printf("Parallel: %.3f s, %.2f MB/s, errors: %zu\n",
           t_par, mb_par, errors);
    printf("Serial:   %.3f s, errors: %zu\n",
           t_ser, ser_errors);
    printf("Speedup:  %.2f, Efficiency/thread: %.2f\n",
           speedup, efficiency);
    printf("Press Enter to exit...");
    getchar();
    hs_free(hs);
    fs_free(fl);
    tm_free(asgn);
    free(threads);
    free(args);
    return 0;
}

int main(int argc, char **argv) {
    AppMode mode;
    const char *p1, *p2;
    size_t threads;
    if (parse_args(argc, argv, &mode, &p1, &p2, &threads) != 0) {
        fprintf(stderr,
                "Usage:\n"
                "  %s create <dir_path> <out_hash_file>\n"
                "  %s check  <hash_file> <dir_path> <thread_count>\n",
                argv[0], argv[0]);
        return 1;
    }
    int res = 0;
    if (mode == MODE_CREATE) {
        res = app_create(p1, p2);
    } else {
        res = app_check(p1, p2, threads);
    }
    return res;
}
