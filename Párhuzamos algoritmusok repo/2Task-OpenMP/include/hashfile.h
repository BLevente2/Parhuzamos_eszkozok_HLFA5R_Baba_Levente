#ifndef HASHFILE_H
#define HASHFILE_H

#include <stddef.h>
#include "file_hasher.h"

typedef struct {
    size_t block_size;
    size_t num_blocks;
    size_t hash_len;
    unsigned char *hashes;
} HashFile;

int hf_write(const FileHasher *fh, const char *out_path);
int hf_read(HashFile *hf, const char *in_path);
void hf_free(HashFile *hf);

#endif
