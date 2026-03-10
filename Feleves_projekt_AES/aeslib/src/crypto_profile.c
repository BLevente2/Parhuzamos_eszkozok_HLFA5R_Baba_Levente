#include "crypto_profile.h"

#include <string.h>

static crypto_profile_stats_t g_stats;

void crypto_profile_reset(void)
{
    memset(&g_stats, 0, sizeof(g_stats));
}

void crypto_profile_get(crypto_profile_stats_t* out)
{
    if (!out) {
        return;
    }
    *out = g_stats;
}

#ifdef CRYPTO_PROFILE
void crypto_profile_add_aes_init(uint64_t ns)
{
    g_stats.aes_init_calls++;
    g_stats.aes_init_ns += ns;
}

void crypto_profile_add_aes_encrypt_block(uint64_t ns)
{
    g_stats.aes_encrypt_block_calls++;
    g_stats.aes_encrypt_block_ns += ns;
}

void crypto_profile_add_aes_decrypt_block(uint64_t ns)
{
    g_stats.aes_decrypt_block_calls++;
    g_stats.aes_decrypt_block_ns += ns;
}

void crypto_profile_add_cbc_encrypt(uint64_t ns)
{
    g_stats.cbc_encrypt_calls++;
    g_stats.cbc_encrypt_ns += ns;
}

void crypto_profile_add_cbc_decrypt(uint64_t ns)
{
    g_stats.cbc_decrypt_calls++;
    g_stats.cbc_decrypt_ns += ns;
}
#endif
