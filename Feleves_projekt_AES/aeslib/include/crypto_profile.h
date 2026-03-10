#ifndef CRYPTO_PROFILE_H
#define CRYPTO_PROFILE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct crypto_profile_stats_t {
    uint64_t aes_init_calls;
    uint64_t aes_init_ns;

    uint64_t aes_encrypt_block_calls;
    uint64_t aes_encrypt_block_ns;

    uint64_t aes_decrypt_block_calls;
    uint64_t aes_decrypt_block_ns;

    uint64_t cbc_encrypt_calls;
    uint64_t cbc_encrypt_ns;

    uint64_t cbc_decrypt_calls;
    uint64_t cbc_decrypt_ns;
} crypto_profile_stats_t;

void crypto_profile_reset(void);
void crypto_profile_get(crypto_profile_stats_t* out);

#ifdef CRYPTO_PROFILE
void crypto_profile_add_aes_init(uint64_t ns);
void crypto_profile_add_aes_encrypt_block(uint64_t ns);
void crypto_profile_add_aes_decrypt_block(uint64_t ns);
void crypto_profile_add_cbc_encrypt(uint64_t ns);
void crypto_profile_add_cbc_decrypt(uint64_t ns);
#endif

#ifdef __cplusplus
}
#endif

#endif
