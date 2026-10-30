#ifndef SESSION_CRYPTO_H
#define SESSION_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include "signer_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

extern uint8_t temp_private_key[CRYPTO_PRIVKEY_SIZE];

/**
 * @brief Initialize ephemeral session keys
 */
void session_crypto_init(void);

/**
 * @brief Get temporary ephemeral public key for initial pairing
 */
int session_crypto_get_temp_pubkey(uint8_t temp_pubkey[CRYPTO_PUBKEY_SIZE]);

/**
 * @brief Decrypt outer AES transport session payload
 */
int session_crypto_decrypt(const uint8_t *aes_key, const uint8_t iv[CRYPTO_IV_SIZE],
                           const uint8_t *ciphertext, size_t cipher_len,
                           uint8_t **plaintext, size_t *plain_len);

#ifdef __cplusplus
}
#endif

#endif // SESSION_CRYPTO_H
