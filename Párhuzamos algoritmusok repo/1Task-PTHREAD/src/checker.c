#include "checker.h"
#include "util.h"
#include "sha256.h"
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

size_t checker_serial(const HashStore *hs, const FileList *fl, size_t *error_count) {
    size_t errors = 0;
    uint64_t bytes = 0;
    for (size_t i = 0; i < hs->count; ++i) {
        const char *path = fl->entries[i].path;
        SHA256_CTX ctx;
        uint8_t digest[SHA256_DIGEST_LENGTH];
        char hex[65];
        sha256_init(&ctx);
        file_hash_update(&ctx, path);
        sha256_final(&ctx, digest);
        sha256_to_hex(digest, hex);
        bytes += fl->entries[i].size;
        if (strncmp(hex, hs->records[i].hex_digest, 64) != 0) {
            warnf("Mismatch for %s", path);
            errors++;
        }
    }
    *error_count = errors;
    return bytes;
}

void *checker_worker(void *arg) {
    CheckerArgs *a = arg;
    size_t start = a->asgn->start_idx[a->thread_id];
    size_t end   = a->asgn->end_idx[a->thread_id];
    uint64_t bytes = 0;
    for (size_t i = start; i < end; ++i) {
        const char *path = a->fl->entries[i].path;
        SHA256_CTX ctx;
        uint8_t digest[SHA256_DIGEST_LENGTH];
        char hex[65];
        sha256_init(&ctx);
        file_hash_update(&ctx, path);
        sha256_final(&ctx, digest);
        sha256_to_hex(digest, hex);
        bytes += a->fl->entries[i].size;
        if (strncmp(hex, a->hs->records[i].hex_digest, 64) != 0) {
            warnf("Mismatch for %s", path);
            __sync_fetch_and_add(a->error_count, 1);
        }
    }
    a->bytes_processed = bytes;
    return NULL;
}
