#ifndef NOSTR_NIP44_H
#define NOSTR_NIP44_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief NIP-44 v2 direct message encryption (HKDF-SHA256, ChaCha20-Poly1305, Base64)
 * @param our_privkey 32-byte private key
 * @param their_pubkey 32-byte peer public key
 * @param text Plaintext string to encrypt
 * @param encrypted_content Output allocated base64 string
 * @return 0 on success, -1 on failure
 */
int nostr_nip44_encrypt(const uint8_t *our_privkey, const uint8_t *their_pubkey,
                        const char *text, char **encrypted_content);

/**
 * @brief NIP-44 v2 direct message decryption
 * @param our_privkey 32-byte private key
 * @param their_pubkey 32-byte peer public key
 * @param encrypted_content Base64 encoded payload
 * @param decrypted_text Output allocated plaintext string
 * @return 0 on success, -1 on failure
 */
int nostr_nip44_decrypt(const uint8_t *our_privkey, const uint8_t *their_pubkey,
                        const char *encrypted_content, char **decrypted_text);

#ifdef __cplusplus
}
#endif

#endif // NOSTR_NIP44_H
