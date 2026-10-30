#ifndef SIGNER_CRYPTO_H
#define SIGNER_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CRYPTO_PRIVKEY_SIZE        32
#define CRYPTO_PUBKEY_SIZE         32 // x-only 32 bytes
#define CRYPTO_SIG_SIZE            64 // BIP-340 Schnorr signature
#define CRYPTO_SHARED_SECRET_SIZE  32 // ECDH x-coordinate
#define CRYPTO_SHA256_SIZE         32
#define CRYPTO_IV_SIZE             16
#define CRYPTO_AES_KEY_SIZE        32 // AES-256
#define CRYPTO_CHACHA_KEY_SIZE     32
#define CRYPTO_CHACHA_NONCE_SIZE   12
#define CRYPTO_POLY1305_TAG_SIZE   16

/**
 * @brief Initialize the global crypto subsystem (libsecp256k1 context, TRNG)
 * @return 0 on success, -1 on failure
 */
int crypto_init(void);

/**
 * @brief Run crypto self-test for secp256k1 (Schnorr, ECDH, pubkey) and symmetric ciphers
 * @return 0 on success, -1 on failure
 */
int crypto_self_test(void);

/* ========================================================================= */
/* secp256k1 Operations (libsecp256k1 backend)                               */
/* ========================================================================= */

/**
 * @brief Generate a valid random 32-byte secp256k1 private key
 * @param privkey Output buffer (32 bytes)
 * @return 0 on success, -1 on failure
 */
int crypto_secp256k1_gen_privkey(uint8_t privkey[CRYPTO_PRIVKEY_SIZE]);

/**
 * @brief Check if a private key is valid (1 <= privkey < curve order)
 * @param privkey 32-byte private key
 * @return true if valid, false otherwise
 */
bool crypto_secp256k1_seckey_verify(const uint8_t privkey[CRYPTO_PRIVKEY_SIZE]);

/**
 * @brief Derive a 32-byte x-only compressed public key from private key
 * @param privkey 32-byte private key
 * @param pubkey Output buffer for 32-byte x-only public key
 * @return 0 on success, -1 on failure
 */
int crypto_secp256k1_get_public(const uint8_t privkey[CRYPTO_PRIVKEY_SIZE],
                                uint8_t pubkey[CRYPTO_PUBKEY_SIZE]);

/**
 * @brief Sign a 32-byte message hash using BIP-340 Schnorr signature
 * @param privkey 32-byte private key
 * @param msg_hash 32-byte message hash
 * @param aux_rand 32-byte auxiliary random nonce (NULL or 32-byte random data)
 * @param sig Output buffer for 64-byte signature
 * @return 0 on success, -1 on failure
 */
int crypto_secp256k1_schnorr_sign(const uint8_t privkey[CRYPTO_PRIVKEY_SIZE],
                                  const uint8_t msg_hash[32],
                                  const uint8_t aux_rand[32],
                                  uint8_t sig[CRYPTO_SIG_SIZE]);

/**
 * @brief Verify a 64-byte BIP-340 Schnorr signature
 * @param pubkey 32-byte x-only public key
 * @param msg_hash 32-byte message hash
 * @param sig 64-byte signature
 * @return 0 if valid signature, -1 otherwise
 */
int crypto_secp256k1_schnorr_verify(const uint8_t pubkey[CRYPTO_PUBKEY_SIZE],
                                    const uint8_t msg_hash[32],
                                    const uint8_t sig[CRYPTO_SIG_SIZE]);

/**
 * @brief Perform ECDH point multiplication to compute shared X-coordinate
 * @param our_privkey Our 32-byte private key
 * @param their_pubkey Peer's 32-byte x-only public key
 * @param shared_x Output buffer for 32-byte shared x-coordinate
 * @return 0 on success, -1 on failure
 */
int crypto_secp256k1_ecdh(const uint8_t our_privkey[CRYPTO_PRIVKEY_SIZE],
                          const uint8_t their_pubkey[CRYPTO_PUBKEY_SIZE],
                          uint8_t shared_x[CRYPTO_SHARED_SECRET_SIZE]);

/* ========================================================================= */
/* Symmetric Ciphers, Hashes, and TRNG (Hardware / mbedTLS backend)          */
/* ========================================================================= */

/**
 * @brief Fill buffer with cryptographically secure hardware random bytes
 */
int crypto_trng_fill(uint8_t *buf, size_t len);

/**
 * @brief Compute SHA-256 hash
 */
int crypto_sha256(const uint8_t *data, size_t len, uint8_t hash[32]);

/**
 * @brief Compute tagged SHA-256 (SHA256(SHA256(tag) || SHA256(tag) || data))
 */
int crypto_tagged_sha256(const char *tag, const uint8_t *data, size_t len, uint8_t hash[32]);

/**
 * @brief Compute HMAC-SHA256
 */
int crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t output[32]);

/**
 * @brief Compute HKDF-Extract + HKDF-Expand (RFC 5869) using SHA-256
 */
int crypto_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                       const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *okm, size_t okm_len);

/**
 * @brief Raw AES-CBC encrypt (input length must be multiple of 16)
 */
int crypto_aes_cbc_encrypt(const uint8_t *key, size_t key_len, const uint8_t iv[16],
                           const uint8_t *input, size_t input_len, uint8_t **output);

/**
 * @brief Raw AES-CBC decrypt (input length must be multiple of 16)
 */
int crypto_aes_cbc_decrypt(const uint8_t *key, size_t key_len, const uint8_t iv[16],
                           const uint8_t *input, size_t input_len, uint8_t **output);

/**
 * @brief PKCS#7 padded AES-CBC encrypt (allocates output buffer)
 */
int crypto_aes_encrypt_padded(const uint8_t *key, size_t key_len, const uint8_t iv[16],
                              const uint8_t *input, size_t input_len,
                              uint8_t **output, size_t *output_len);

/**
 * @brief PKCS#7 unpadded AES-CBC decrypt (allocates output buffer)
 */
int crypto_aes_decrypt_padded(const uint8_t *key, size_t key_len, const uint8_t iv[16],
                              const uint8_t *input, size_t input_len,
                              uint8_t **output, size_t *output_len);

/**
 * @brief ChaCha20-Poly1305 AEAD encrypt (RFC 8439)
 */
int crypto_chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                                     const uint8_t *aad, size_t aad_len,
                                     const uint8_t *plaintext, size_t plaintext_len,
                                     uint8_t *ciphertext, uint8_t tag[16]);

/**
 * @brief ChaCha20-Poly1305 AEAD decrypt (RFC 8439)
 */
int crypto_chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                                     const uint8_t *aad, size_t aad_len,
                                     const uint8_t *ciphertext, size_t ciphertext_len,
                                     const uint8_t tag[16], uint8_t *plaintext);

/* Base64 Utilities */
char *crypto_base64_encode(const unsigned char *data, size_t input_length);
unsigned char *crypto_base64_decode(const char *data, size_t input_length, size_t *output_length);

#ifdef __cplusplus
}
#endif

#endif // SIGNER_CRYPTO_H
