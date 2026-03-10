#ifndef HASH_BLOCK_H
#define HASH_BLOCK_H

#include <stddef.h>

void compute_hash(const void *data, size_t len, unsigned char *out_hash, size_t *out_len);

#endif
