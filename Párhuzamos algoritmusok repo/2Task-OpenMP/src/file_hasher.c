#define _POSIX_C_SOURCE 200809L

#include "file_hasher.h"
#include "hash_block.h"

#include <openssl/evp.h>    // EVP_MAX_MD_SIZE
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>         // memcpy
#include <stdio.h>          // perror
#include <omp.h>

void fh_init(FileHasher *fh, const char *file_path, size_t block_size)
{
    fh->file_path  = file_path;
    fh->block_size = block_size;

    struct stat st;
    if (stat(file_path, &st) < 0) {
        perror("stat");
        exit(EXIT_FAILURE);
    }
    size_t file_size = (size_t)st.st_size;
    fh->num_blocks   = (file_size + block_size - 1) / block_size;

    // A hash hosszának meghatározása 0 bájtos adat hash-elésével
    unsigned char tmp_in[1];
    unsigned char tmp_out[EVP_MAX_MD_SIZE];
    size_t tmp_len = 0;
    compute_hash(tmp_in, 0, tmp_out, &tmp_len);
    fh->hash_len = tmp_len;

    fh->hashes = malloc(fh->num_blocks * fh->hash_len);
    if (!fh->hashes) {
        perror("malloc hashes");
        exit(EXIT_FAILURE);
    }
}

void fh_compute_serial(FileHasher *fh)
{
    int fd = open(fh->file_path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    unsigned char *in_buf  = malloc(fh->block_size);
    unsigned char *out_buf = malloc(fh->hash_len);
    if (!in_buf || !out_buf) {
        perror("malloc buffers");
        close(fd);
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < fh->num_blocks; ++i) {
        off_t offset = (off_t)i * fh->block_size;
        ssize_t bytes_read = pread(fd, in_buf, fh->block_size, offset);
        if (bytes_read < 0) {
            perror("pread");
            free(in_buf);
            free(out_buf);
            close(fd);
            exit(EXIT_FAILURE);
        }

        size_t hash_len_loc = fh->hash_len;
        compute_hash(in_buf, (size_t)bytes_read, out_buf, &hash_len_loc);

        unsigned char *dst = fh->hashes + i * hash_len_loc;
        memcpy(dst, out_buf, hash_len_loc);
    }

    free(in_buf);
    free(out_buf);
    close(fd);
}

void fh_compute_parallel(FileHasher *fh, int num_threads)
{
    int fd = open(fh->file_path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    #pragma omp parallel num_threads(num_threads)
    {
        unsigned char *in_buf  = malloc(fh->block_size);
        unsigned char *out_buf = malloc(fh->hash_len);
        if (!in_buf || !out_buf) {
            perror("malloc buffers");
            exit(EXIT_FAILURE);
        }

        size_t hash_len_loc;

        #pragma omp for
        for (size_t i = 0; i < fh->num_blocks; ++i) {
            off_t offset = (off_t)i * fh->block_size;
            ssize_t bytes_read = pread(fd, in_buf, fh->block_size, offset);
            if (bytes_read < 0) {
                perror("pread");
                free(in_buf);
                free(out_buf);
                exit(EXIT_FAILURE);
            }

            hash_len_loc = fh->hash_len;
            compute_hash(in_buf, (size_t)bytes_read, out_buf, &hash_len_loc);

            unsigned char *dst = fh->hashes + i * hash_len_loc;
            memcpy(dst, out_buf, hash_len_loc);
        }

        free(in_buf);
        free(out_buf);
    }

    close(fd);
}

void fh_free(FileHasher *fh)
{
    free(fh->hashes);
    fh->hashes = NULL;
}
