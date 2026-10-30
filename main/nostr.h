#ifndef NOSTR_H
#define NOSTR_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "cJSON.h"
#include "signer_crypto.h"
#include "nostr_nip01.h"
#include "nostr_nip04.h"
#include "nostr_nip44.h"
#include "nostr_ecdh_cache.h"
#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

// 别名与兼容接口
static inline int gen_private_key(uint8_t private_key_bin[32]) {
    return crypto_secp256k1_gen_privkey(private_key_bin);
}

static inline int get_public(const uint8_t *privkey_bin, uint8_t *pubkey_bin) {
    return crypto_secp256k1_get_public(privkey_bin, pubkey_bin);
}

static inline int gen_event_id(const char *pubkey_hex, uint32_t created_at, uint16_t kind,
                               cJSON *tags, const char *content, char *event_id_hex) {
    return nostr_nip01_gen_event_id(pubkey_hex, created_at, kind, tags, content, event_id_hex);
}

static inline int sign(const uint8_t *privkey_bin, const uint8_t *message_bin, uint8_t *sig_bin) {
    return nostr_nip01_sign_event(privkey_bin, message_bin, sig_bin);
}

static inline int nip04_encrypt(const uint8_t *our_privkey_bin, const uint8_t *their_pubkey_bin,
                                const char *text, char **encrypted_content) {
    return nostr_nip04_encrypt(our_privkey_bin, their_pubkey_bin, text, encrypted_content);
}

static inline int nip04_decrypt(const uint8_t *our_privkey_bin, const uint8_t *their_pubkey_bin,
                                const char *encrypted_content, char **decrypted_text) {
    return nostr_nip04_decrypt(our_privkey_bin, their_pubkey_bin, encrypted_content, decrypted_text);
}

static inline int nip44_encrypt(const uint8_t *our_privkey_bin, const uint8_t *their_pubkey_bin,
                                const char *text, char **encrypted_content) {
    return nostr_nip44_encrypt(our_privkey_bin, their_pubkey_bin, text, encrypted_content);
}

static inline int nip44_decrypt(const uint8_t *our_privkey_bin, const uint8_t *their_pubkey_bin,
                                const char *encrypted_content, char **decrypted_text) {
    return nostr_nip44_decrypt(our_privkey_bin, their_pubkey_bin, encrypted_content, decrypted_text);
}

static inline int aes_encrypt_padded(const uint8_t *key, size_t key_len, const uint8_t *iv,
                                     const uint8_t *input, size_t input_len,
                                     uint8_t **output, size_t *output_len) {
    return crypto_aes_encrypt_padded(key, key_len, iv, input, input_len, output, output_len);
}

static inline int aes_decrypt_padded(const uint8_t *key, size_t key_len, const uint8_t *iv,
                                     const uint8_t *input, size_t input_len,
                                     uint8_t **output, size_t *output_len) {
    return crypto_aes_decrypt_padded(key, key_len, iv, input, input_len, output, output_len);
}

#ifdef __cplusplus
}
#endif

#endif // NOSTR_H
