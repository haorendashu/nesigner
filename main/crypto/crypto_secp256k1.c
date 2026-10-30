#include "signer_crypto.h"
#include "secp256k1.h"
#include "secp256k1_schnorrsig.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_ecdh.h"
#include "esp_random.h"
#include "esp_log.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "CRYPTO_SECP256K1";
static secp256k1_context *s_ctx = NULL;

static int raw_xonly_hashfp(unsigned char *output,
                            const unsigned char *x32,
                            const unsigned char *y32,
                            void *data)
{
    (void)y32;
    (void)data;
    memcpy(output, x32, 32);
    return 1;
}

int crypto_init(void)
{
    if (s_ctx != NULL) {
        return 0; // already initialized
    }

    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!s_ctx) {
        ESP_LOGE(TAG, "Failed to create secp256k1 context");
        return -1;
    }

    // Randomize context to protect against side-channel analysis
    uint8_t seed[32];
    esp_fill_random(seed, sizeof(seed));
    if (!secp256k1_context_randomize(s_ctx, seed)) {
        ESP_LOGW(TAG, "Context randomization returned failure (non-fatal)");
    }

    ESP_LOGI(TAG, "secp256k1 context initialized successfully");
    return 0;
}

int crypto_secp256k1_gen_privkey(uint8_t privkey[CRYPTO_PRIVKEY_SIZE])
{
    if (crypto_init() != 0) {
        return -1;
    }

    do {
        esp_fill_random(privkey, CRYPTO_PRIVKEY_SIZE);
    } while (!secp256k1_ec_seckey_verify(s_ctx, privkey));

    return 0;
}

bool crypto_secp256k1_seckey_verify(const uint8_t privkey[CRYPTO_PRIVKEY_SIZE])
{
    if (crypto_init() != 0) {
        return false;
    }
    return secp256k1_ec_seckey_verify(s_ctx, privkey) == 1;
}

int crypto_secp256k1_get_public(const uint8_t privkey[CRYPTO_PRIVKEY_SIZE],
                                uint8_t pubkey[CRYPTO_PUBKEY_SIZE])
{
    if (crypto_init() != 0) {
        return -1;
    }

    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(s_ctx, &keypair, privkey)) {
        ESP_LOGE(TAG, "Failed to create keypair from private key");
        return -1;
    }

    secp256k1_xonly_pubkey xonly_pub;
    if (!secp256k1_keypair_xonly_pub(s_ctx, &xonly_pub, NULL, &keypair)) {
        ESP_LOGE(TAG, "Failed to derive x-only public key");
        return -1;
    }

    if (!secp256k1_xonly_pubkey_serialize(s_ctx, pubkey, &xonly_pub)) {
        ESP_LOGE(TAG, "Failed to serialize x-only public key");
        return -1;
    }

    return 0;
}

int crypto_secp256k1_schnorr_sign(const uint8_t privkey[CRYPTO_PRIVKEY_SIZE],
                                  const uint8_t msg_hash[32],
                                  const uint8_t aux_rand[32],
                                  uint8_t sig[CRYPTO_SIG_SIZE])
{
    if (crypto_init() != 0) {
        return -1;
    }

    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(s_ctx, &keypair, privkey)) {
        ESP_LOGE(TAG, "Failed to create keypair for Schnorr sign");
        return -1;
    }

    uint8_t random_aux[32];
    const uint8_t *aux = aux_rand;
    if (aux == NULL) {
        esp_fill_random(random_aux, sizeof(random_aux));
        aux = random_aux;
    }

    if (!secp256k1_schnorrsig_sign32(s_ctx, sig, msg_hash, &keypair, aux)) {
        ESP_LOGE(TAG, "Schnorr sign failed");
        return -1;
    }

    return 0;
}

int crypto_secp256k1_schnorr_verify(const uint8_t pubkey[CRYPTO_PUBKEY_SIZE],
                                    const uint8_t msg_hash[32],
                                    const uint8_t sig[CRYPTO_SIG_SIZE])
{
    if (crypto_init() != 0) {
        return -1;
    }

    secp256k1_xonly_pubkey xonly_pub;
    if (!secp256k1_xonly_pubkey_parse(s_ctx, &xonly_pub, pubkey)) {
        return -1;
    }

    if (!secp256k1_schnorrsig_verify(s_ctx, sig, msg_hash, 32, &xonly_pub)) {
        return -1;
    }

    return 0;
}

int crypto_secp256k1_ecdh(const uint8_t our_privkey[CRYPTO_PRIVKEY_SIZE],
                          const uint8_t their_pubkey[CRYPTO_PUBKEY_SIZE],
                          uint8_t shared_x[CRYPTO_SHARED_SECRET_SIZE])
{
    if (crypto_init() != 0) {
        return -1;
    }

    // Convert Nostr 32-byte x-only public key into 33-byte compressed point (0x02 prefix)
    uint8_t compressed[33];
    compressed[0] = 0x02;
    memcpy(compressed + 1, their_pubkey, 32);

    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_parse(s_ctx, &pub, compressed, sizeof(compressed))) {
        ESP_LOGE(TAG, "Failed to parse peer public key for ECDH");
        return -1;
    }

    if (!secp256k1_ecdh(s_ctx, shared_x, &pub, our_privkey, raw_xonly_hashfp, NULL)) {
        ESP_LOGE(TAG, "ECDH calculation failed");
        return -1;
    }

    return 0;
}

int crypto_self_test(void)
{
    ESP_LOGI(TAG, "Starting crypto self-test...");

    // 1. Test keygen and public key derivation
    uint8_t priv_a[32], pub_a[32];
    uint8_t priv_b[32], pub_b[32];
    if (crypto_secp256k1_gen_privkey(priv_a) != 0 || crypto_secp256k1_get_public(priv_a, pub_a) != 0) {
        ESP_LOGE(TAG, "Self-test: Keygen A failed");
        return -1;
    }
    if (crypto_secp256k1_gen_privkey(priv_b) != 0 || crypto_secp256k1_get_public(priv_b, pub_b) != 0) {
        ESP_LOGE(TAG, "Self-test: Keygen B failed");
        return -1;
    }

    // 2. Test BIP-340 Schnorr sign and verify
    uint8_t msg_hash[32];
    memset(msg_hash, 0x42, sizeof(msg_hash));
    uint8_t sig[64];
    if (crypto_secp256k1_schnorr_sign(priv_a, msg_hash, NULL, sig) != 0) {
        ESP_LOGE(TAG, "Self-test: Schnorr sign failed");
        return -1;
    }
    if (crypto_secp256k1_schnorr_verify(pub_a, msg_hash, sig) != 0) {
        ESP_LOGE(TAG, "Self-test: Schnorr verify failed");
        return -1;
    }

    // 3. Test ECDH symmetry: a * B == b * A
    uint8_t shared_ab[32];
    uint8_t shared_ba[32];
    if (crypto_secp256k1_ecdh(priv_a, pub_b, shared_ab) != 0 ||
        crypto_secp256k1_ecdh(priv_b, pub_a, shared_ba) != 0) {
        ESP_LOGE(TAG, "Self-test: ECDH computation failed");
        return -1;
    }
    if (memcmp(shared_ab, shared_ba, 32) != 0) {
        ESP_LOGE(TAG, "Self-test: ECDH symmetry mismatch");
        return -1;
    }

    // 4. Test AES-CBC padded encryption roundtrip
    uint8_t aes_key[32];
    uint8_t iv[16];
    crypto_trng_fill(aes_key, 32);
    crypto_trng_fill(iv, 16);
    const char *test_msg = "Hello Nostr Hardware Signer!";
    size_t test_msg_len = strlen(test_msg);
    uint8_t *ciphertext = NULL;
    size_t cipher_len = 0;
    if (crypto_aes_encrypt_padded(aes_key, 32, iv, (const uint8_t *)test_msg, test_msg_len,
                                  &ciphertext, &cipher_len) != 0) {
        ESP_LOGE(TAG, "Self-test: AES encrypt failed");
        return -1;
    }
    uint8_t *decrypted = NULL;
    size_t dec_len = 0;
    if (crypto_aes_decrypt_padded(aes_key, 32, iv, ciphertext, cipher_len,
                                  &decrypted, &dec_len) != 0) {
        free(ciphertext);
        ESP_LOGE(TAG, "Self-test: AES decrypt failed");
        return -1;
    }
    if (dec_len != test_msg_len || memcmp(decrypted, test_msg, test_msg_len) != 0) {
        free(ciphertext);
        free(decrypted);
        ESP_LOGE(TAG, "Self-test: AES roundtrip mismatch");
        return -1;
    }
    free(ciphertext);
    free(decrypted);

    // 5. Test ChaCha20-Poly1305 roundtrip
    uint8_t chacha_key[32], nonce[12], tag[16];
    crypto_trng_fill(chacha_key, 32);
    crypto_trng_fill(nonce, 12);
    uint8_t chacha_ct[64];
    uint8_t chacha_pt[64];
    if (crypto_chacha20_poly1305_encrypt(chacha_key, nonce, NULL, 0,
                                         (const uint8_t *)test_msg, test_msg_len,
                                         chacha_ct, tag) != 0) {
        ESP_LOGE(TAG, "Self-test: ChaCha20-Poly1305 encrypt failed");
        return -1;
    }
    if (crypto_chacha20_poly1305_decrypt(chacha_key, nonce, NULL, 0,
                                         chacha_ct, test_msg_len,
                                         tag, chacha_pt) != 0) {
        ESP_LOGE(TAG, "Self-test: ChaCha20-Poly1305 decrypt failed");
        return -1;
    }
    if (memcmp(chacha_pt, test_msg, test_msg_len) != 0) {
        ESP_LOGE(TAG, "Self-test: ChaCha20-Poly1305 roundtrip mismatch");
        return -1;
    }

    ESP_LOGI(TAG, "Crypto self-test PASSED successfully!");
    return 0;
}
