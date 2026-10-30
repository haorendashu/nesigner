#include "nostr_nip04.h"
#include "nostr_ecdh_cache.h"
#include "signer_crypto.h"
#include "esp_log.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char *TAG = "NOSTR_NIP04";

static int get_shared_secret(const uint8_t *our_privkey, const uint8_t *their_pubkey, uint8_t shared_x[32])
{
    uint8_t our_pubkey[32];
    if (crypto_secp256k1_get_public(our_privkey, our_pubkey) != 0) {
        return -1;
    }

    if (nostr_ecdh_cache_get(our_pubkey, their_pubkey, shared_x)) {
        return 0; // Cache HIT!
    }

    // Cache MISS: compute ECDH via Crypto HAL
    if (crypto_secp256k1_ecdh(our_privkey, their_pubkey, shared_x) != 0) {
        ESP_LOGE(TAG, "Failed to compute ECDH");
        return -1;
    }

    nostr_ecdh_cache_put(our_pubkey, their_pubkey, shared_x);
    return 0;
}

int nostr_nip04_encrypt(const uint8_t *our_privkey, const uint8_t *their_pubkey,
                        const char *text, char **encrypted_content)
{
    if (!our_privkey || !their_pubkey || !text || !encrypted_content) return -1;

    uint8_t shared_x[32];
    if (get_shared_secret(our_privkey, their_pubkey, shared_x) != 0) {
        return -1;
    }

    uint8_t iv[16];
    crypto_trng_fill(iv, 16);

    uint8_t *ciphertext = NULL;
    size_t cipher_len = 0;
    if (crypto_aes_encrypt_padded(shared_x, 32, iv, (const uint8_t *)text, strlen(text),
                                  &ciphertext, &cipher_len) != 0) {
        ESP_LOGE(TAG, "AES encrypt padded failed");
        return -1;
    }

    char *b64_cipher = crypto_base64_encode(ciphertext, cipher_len);
    char *b64_iv = crypto_base64_encode(iv, 16);
    free(ciphertext);

    if (!b64_cipher || !b64_iv) {
        free(b64_cipher);
        free(b64_iv);
        return -1;
    }

    size_t total_len = strlen(b64_cipher) + 4 + strlen(b64_iv) + 1; // "?iv=" is 4 chars
    *encrypted_content = (char *)malloc(total_len);
    if (!*encrypted_content) {
        free(b64_cipher);
        free(b64_iv);
        return -1;
    }

    snprintf(*encrypted_content, total_len, "%s?iv=%s", b64_cipher, b64_iv);
    free(b64_cipher);
    free(b64_iv);
    return 0;
}

int nostr_nip04_decrypt(const uint8_t *our_privkey, const uint8_t *their_pubkey,
                        const char *encrypted_content, char **decrypted_text)
{
    if (!our_privkey || !their_pubkey || !encrypted_content || !decrypted_text) return -1;

    const char *separator = strstr(encrypted_content, "?iv=");
    if (!separator) {
        ESP_LOGE(TAG, "Invalid NIP-04 format: missing ?iv= delimiter");
        return -1;
    }

    size_t b64_cipher_len = separator - encrypted_content;
    const char *b64_iv_str = separator + 4;
    size_t b64_iv_len = strlen(b64_iv_str);

    char *b64_cipher_str = (char *)malloc(b64_cipher_len + 1);
    if (!b64_cipher_str) return -1;
    memcpy(b64_cipher_str, encrypted_content, b64_cipher_len);
    b64_cipher_str[b64_cipher_len] = '\0';

    size_t cipher_len = 0;
    uint8_t *ciphertext = crypto_base64_decode(b64_cipher_str, b64_cipher_len, &cipher_len);
    free(b64_cipher_str);

    size_t iv_len = 0;
    uint8_t *iv = crypto_base64_decode(b64_iv_str, b64_iv_len, &iv_len);

    if (!ciphertext || !iv || iv_len != 16) {
        ESP_LOGE(TAG, "Base64 decode failed for ciphertext or IV");
        free(ciphertext);
        free(iv);
        return -1;
    }

    uint8_t shared_x[32];
    if (get_shared_secret(our_privkey, their_pubkey, shared_x) != 0) {
        free(ciphertext);
        free(iv);
        return -1;
    }

    uint8_t *plaintext = NULL;
    size_t plain_len = 0;
    int ret = crypto_aes_decrypt_padded(shared_x, 32, iv, ciphertext, cipher_len,
                                        &plaintext, &plain_len);
    free(ciphertext);
    free(iv);

    if (ret != 0 || !plaintext) {
        ESP_LOGE(TAG, "AES decrypt padded failed");
        return -1;
    }

    *decrypted_text = (char *)malloc(plain_len + 1);
    if (!*decrypted_text) {
        free(plaintext);
        return -1;
    }
    memcpy(*decrypted_text, plaintext, plain_len);
    (*decrypted_text)[plain_len] = '\0';
    free(plaintext);

    return 0;
}
