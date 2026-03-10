#ifndef FILE_HASHER_H
#define FILE_HASHER_H

#include <stddef.h>

typedef struct {
    const char *file_path;
    size_t block_size;
    size_t num_blocks;
    size_t hash_len;
    unsigned char *hashes;
} FileHasher;

void fh_init(FileHasher *fh, const char *file_path, size_t block_size);
void fh_compute_serial(FileHasher *fh);
void fh_compute_parallel(FileHasher *fh, int num_threads);
void fh_free(FileHasher *fh);

#endif
