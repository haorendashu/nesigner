#ifndef NOSTR_NIP04_H
#define NOSTR_NIP04_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief NIP-04 direct message encryption (AES-256-CBC with PKCS#7 padding and Base64)
 * @param our_privkey 32-byte private key
 * @param their_pubkey 32-byte peer public key
 * @param text Plaintext string to encrypt
 * @param encrypted_content Output allocated string in format "<base64_cipher>?iv=<base64_iv>"
 * @return 0 on success, -1 on failure
 */
int nostr_nip04_encrypt(const uint8_t *our_privkey, const uint8_t *their_pubkey,
                        const char *text, char **encrypted_content);

/**
 * @brief NIP-04 direct message decryption
 * @param our_privkey 32-byte private key
 * @param their_pubkey 32-byte peer public key
 * @param encrypted_content Formatted ciphertext string "<base64_cipher>?iv=<base64_iv>"
 * @param decrypted_text Output allocated plaintext string
 * @return 0 on success, -1 on failure
 */
int nostr_nip04_decrypt(const uint8_t *our_privkey, const uint8_t *their_pubkey,
                        const char *encrypted_content, char **decrypted_text);

#ifdef __cplusplus
}
#endif

#endif // NOSTR_NIP04_H
