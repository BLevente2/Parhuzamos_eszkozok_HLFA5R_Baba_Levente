#include "hashfile.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int hf_write(const FileHasher *fh, const char *out_path)
{
    FILE *f = fopen(out_path, "w");
    if (!f) return -1;
    fprintf(f, "%zu %zu %zu\n", fh->block_size, fh->num_blocks, fh->hash_len);
    for (size_t i = 0; i < fh->num_blocks; ++i) {
        const unsigned char *h = fh->hashes + i * fh->hash_len;
        for (size_t j = 0; j < fh->hash_len; ++j) {
            fprintf(f, "%02x", h[j]);
        }
        fprintf(f, "\n");
    }
    fclose(f);
    return 0;
}

int hf_read(HashFile *hf, const char *in_path)
{
    FILE *f = fopen(in_path, "r");
    if (!f) return -1;
    if (fscanf(f, "%zu %zu %zu\n", &hf->block_size, &hf->num_blocks, &hf->hash_len) != 3) {
        fclose(f);
        return -1;
    }
    hf->hashes = malloc(hf->num_blocks * hf->hash_len);
    if (!hf->hashes) {
        fclose(f);
        return -1;
    }
    char *line = malloc(hf->hash_len * 2 + 2);
    for (size_t i = 0; i < hf->num_blocks; ++i) {
        if (!fgets(line, hf->hash_len * 2 + 2, f)) {
            free(line);
            free(hf->hashes);
            fclose(f);
            return -1;
        }
        for (size_t j = 0; j < hf->hash_len; ++j) {
            char hex[3] = { line[2*j], line[2*j+1], '\0' };
            hf->hashes[i*hf->hash_len + j] = (unsigned char)strtol(hex, NULL, 16);
        }
    }
    free(line);
    fclose(f);
    return 0;
}

void hf_free(HashFile *hf)
{
    free(hf->hashes);
    hf->hashes = NULL;
}
