#include "nostr_nip44.h"
#include "nostr_ecdh_cache.h"
#include "signer_crypto.h"
#include "esp_log.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "NOSTR_NIP44";

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

static int derive_key(const uint8_t *shared_secret, const uint8_t *nonce,
                      uint8_t *chacha_key, uint8_t *chacha_nonce, uint8_t *hmac_key)
{
    const uint8_t salt[] = {0x6e, 0x69, 0x70, 0x34, 0x34, 0x2d, 0x76, 0x32}; // "nip44-v2"
    uint8_t keys[76];

    if (crypto_hkdf_sha256(salt, sizeof(salt), shared_secret, 32, nonce, 32, keys, sizeof(keys)) != 0) {
        ESP_LOGE(TAG, "HKDF key derivation failed");
        return -1;
    }

    memcpy(chacha_key, keys, 32);
    memcpy(chacha_nonce, keys + 32, 12);
    memcpy(hmac_key, keys + 44, 32);
    return 0;
}

static size_t calc_padded_len(size_t len)
{
    if (len == 0) return 0;
    if (len <= 32) return 32;

    size_t bitlen = 0;
    size_t n = len - 1;
    while (n > 0) {
        bitlen++;
        n >>= 1;
    }
    size_t next_power = (size_t)1 << bitlen;
    size_t chunk_size = (next_power <= 256) ? 32 : next_power / 8;
    return chunk_size * ((len + chunk_size - 1) / chunk_size);
}

static uint8_t *nip44_pad(const char *text, size_t *padded_len)
{
    size_t text_len = strlen(text);
    if (text_len > 65535) return NULL;

    size_t total_padded = calc_padded_len(text_len);
    uint8_t *padded = (uint8_t *)calloc(1, 2 + total_padded);
    if (!padded) return NULL;

    padded[0] = (text_len >> 8) & 0xFF;
    padded[1] = text_len & 0xFF;
    memcpy(padded + 2, text, text_len);

    *padded_len = total_padded + 2;
    return padded;
}

static char *nip44_unpad(const uint8_t *padded, size_t padded_len)
{
    if (padded_len < 3) return NULL;

    uint16_t unpadded_len = (padded[0] << 8) | padded[1];
    if (unpadded_len < 1 || unpadded_len > 65535) return NULL;

    size_t expected_padded = calc_padded_len(unpadded_len);
    if (expected_padded + 2 != padded_len) return NULL;

    size_t padding_start = 2 + unpadded_len;
    for (size_t i = padding_start; i < padded_len; i++) {
        if (padded[i] != 0) return NULL;
    }

    char *result = (char *)malloc(unpadded_len + 1);
    if (!result) return NULL;
    memcpy(result, padded + 2, unpadded_len);
    result[unpadded_len] = '\0';
    return result;
}

int nostr_nip44_encrypt(const uint8_t *our_privkey, const uint8_t *their_pubkey,
                        const char *text, char **encrypted_content)
{
    if (!our_privkey || !their_pubkey || !text || !encrypted_content) return -1;

    uint8_t shared_x[32];
    if (get_shared_secret(our_privkey, their_pubkey, shared_x) != 0) {
        return -1;
    }

    uint8_t nonce[32];
    crypto_trng_fill(nonce, 32);

    uint8_t chacha_key[32], chacha_nonce[12], hmac_key[32];
    if (derive_key(shared_x, nonce, chacha_key, chacha_nonce, hmac_key) != 0) {
        return -1;
    }

    size_t padded_len = 0;
    uint8_t *padded_text = nip44_pad(text, &padded_len);
    if (!padded_text) return -1;

    // payload: version (1) + nonce (32) + ciphertext (padded_len) + mac (32)
    size_t payload_size = 1 + 32 + padded_len + 32;
    uint8_t *payload = (uint8_t *)malloc(payload_size);
    if (!payload) {
        free(padded_text);
        return -1;
    }

    payload[0] = 0x02; // version
    memcpy(payload + 1, nonce, 32);

    // ChaCha20 encryption directly into payload + 33
    int ret = crypto_chacha20_stream(chacha_key, chacha_nonce, padded_text, padded_len, payload + 33);
    free(padded_text);

    if (ret != 0) {
        free(payload);
        return -1;
    }

    // HMAC-SHA256 over (nonce || ciphertext) = payload[1 .. 33 + padded_len]
    uint8_t mac[32];
    if (crypto_hmac_sha256(hmac_key, 32, payload + 1, 32 + padded_len, mac) != 0) {
        free(payload);
        return -1;
    }

    memcpy(payload + 33 + padded_len, mac, 32);

    *encrypted_content = crypto_base64_encode(payload, payload_size);
    free(payload);

    return *encrypted_content != NULL ? 0 : -1;
}

int nostr_nip44_decrypt(const uint8_t *our_privkey, const uint8_t *their_pubkey,
                        const char *encrypted_content, char **decrypted_text)
{
    if (!our_privkey || !their_pubkey || !encrypted_content || !decrypted_text) return -1;

    size_t payload_len = 0;
    uint8_t *payload = crypto_base64_decode(encrypted_content, strlen(encrypted_content), &payload_len);
    if (!payload) {
        ESP_LOGE(TAG, "Base64 decode failed");
        return -1;
    }

    // Min payload: version(1) + nonce(32) + min_cipher(34) + mac(32) = 99 bytes
    if (payload_len < 99 || payload[0] != 0x02) {
        ESP_LOGE(TAG, "Invalid payload length or version");
        free(payload);
        return -1;
    }

    const uint8_t *nonce = payload + 1;
    size_t cipher_len = payload_len - 1 - 32 - 32;
    const uint8_t *ciphertext = payload + 33;
    const uint8_t *received_mac = payload + 33 + cipher_len;

    uint8_t shared_x[32];
    if (get_shared_secret(our_privkey, their_pubkey, shared_x) != 0) {
        free(payload);
        return -1;
    }

    uint8_t chacha_key[32], chacha_nonce[12], hmac_key[32];
    if (derive_key(shared_x, nonce, chacha_key, chacha_nonce, hmac_key) != 0) {
        free(payload);
        return -1;
    }

    uint8_t calculated_mac[32];
    if (crypto_hmac_sha256(hmac_key, 32, nonce, 32 + cipher_len, calculated_mac) != 0) {
        free(payload);
        return -1;
    }

    // Constant-time MAC comparison
    int diff = 0;
    for (size_t i = 0; i < 32; i++) {
        diff |= (calculated_mac[i] ^ received_mac[i]);
    }
    if (diff != 0) {
        ESP_LOGE(TAG, "HMAC validation failed");
        free(payload);
        return -1;
    }

    uint8_t *padded_text = (uint8_t *)malloc(cipher_len);
    if (!padded_text) {
        free(payload);
        return -1;
    }

    int ret = crypto_chacha20_stream(chacha_key, chacha_nonce, ciphertext, cipher_len, padded_text);
    free(payload);

    if (ret != 0) {
        free(padded_text);
        return -1;
    }

    *decrypted_text = nip44_unpad(padded_text, cipher_len);
    free(padded_text);

    return *decrypted_text != NULL ? 0 : -1;
}
