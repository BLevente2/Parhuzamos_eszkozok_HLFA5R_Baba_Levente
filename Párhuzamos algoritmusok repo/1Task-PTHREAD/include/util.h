#ifndef UTIL_H
#define UTIL_H

#include <stdarg.h>
#include "sha256.h"

void    fatal(const char *fmt, ...);
void    warnf(const char *fmt, ...);
void    file_hash_update(SHA256_CTX *ctx, const char *path);

#endif
