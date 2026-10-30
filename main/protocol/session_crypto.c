#include "session_crypto.h"
#include "esp_log.h"
#include <string.h>

static const char *TAG = "SESSION_CRYPTO";
uint8_t temp_private_key[CRYPTO_PRIVKEY_SIZE];

void session_crypto_init(void)
{
    if (crypto_secp256k1_gen_privkey(temp_private_key) != 0) {
        ESP_LOGE(TAG, "Failed to generate ephemeral session private key");
    } else {
        ESP_LOGI(TAG, "Ephemeral session private key generated");
    }
}

int session_crypto_get_temp_pubkey(uint8_t temp_pubkey[CRYPTO_PUBKEY_SIZE])
{
    return crypto_secp256k1_get_public(temp_private_key, temp_pubkey);
}

int session_crypto_decrypt(const uint8_t *aes_key, const uint8_t iv[CRYPTO_IV_SIZE],
                           const uint8_t *ciphertext, size_t cipher_len,
                           uint8_t **plaintext, size_t *plain_len)
{
    if (!aes_key || !iv || !ciphertext || !plaintext || !plain_len) return -1;
    return crypto_aes_decrypt_padded(aes_key, 16, iv, ciphertext, cipher_len, plaintext, plain_len);
}
