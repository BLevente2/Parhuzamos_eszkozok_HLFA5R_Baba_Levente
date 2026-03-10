#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

void fatal(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(EXIT_FAILURE);
}

void warnf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

void file_hash_update(SHA256_CTX *ctx, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        warnf("Failed to open %s", path);
        return;
    }
    uint8_t buf[4096];
    size_t r;
    while ((r = fread(buf, 1, sizeof buf, f)) > 0) {
        sha256_update(ctx, buf, r);
    }
    fclose(f);
}
