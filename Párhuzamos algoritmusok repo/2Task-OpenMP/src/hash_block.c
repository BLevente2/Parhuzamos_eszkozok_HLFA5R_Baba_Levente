#include "hash_block.h"
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

void compute_hash(const void *data, size_t len, unsigned char *out_hash, size_t *out_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, data, len);
    unsigned int digest_len = 0;
    EVP_DigestFinal_ex(ctx, out_hash, &digest_len);
    *out_len = (size_t)digest_len;
    EVP_MD_CTX_free(ctx);
}
