#include "signer_crypto.h"
#include "esp_random.h"
#include "esp_log.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"
#include "mbedtls/md.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/base64.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "CRYPTO_MBEDTLS";

int crypto_trng_fill(uint8_t *buf, size_t len)
{
    if (buf == NULL && len > 0) return -1;
    esp_fill_random(buf, len);
    return 0;
}

int crypto_sha256(const uint8_t *data, size_t len, uint8_t hash[32])
{
    if (!data || !hash) return -1;
    return mbedtls_sha256(data, len, hash, 0) == 0 ? 0 : -1;
}

int crypto_tagged_sha256(const char *tag, const uint8_t *data, size_t len, uint8_t hash[32])
{
    if (!tag || !data || !hash) return -1;

    uint8_t tag_hash[32];
    if (mbedtls_sha256((const uint8_t *)tag, strlen(tag), tag_hash, 0) != 0) {
        return -1;
    }

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    if (mbedtls_sha256_starts(&ctx, 0) != 0 ||
        mbedtls_sha256_update(&ctx, tag_hash, 32) != 0 ||
        mbedtls_sha256_update(&ctx, tag_hash, 32) != 0 ||
        mbedtls_sha256_update(&ctx, data, len) != 0 ||
        mbedtls_sha256_finish(&ctx, hash) != 0) {
        mbedtls_sha256_free(&ctx);
        return -1;
    }

    mbedtls_sha256_free(&ctx);
    return 0;
}

int crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t output[32])
{
    if (!key || !data || !output) return -1;

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info) return -1;

    return mbedtls_md_hmac(md_info, key, key_len, data, data_len, output) == 0 ? 0 : -1;
}

int crypto_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                       const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *okm, size_t okm_len)
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info) return -1;

    return mbedtls_hkdf(md_info, salt, salt_len, ikm, ikm_len, info, info_len, okm, okm_len) == 0 ? 0 : -1;
}

/* PKCS#7 Helpers */
static void pkcs7_pad(uint8_t *data, size_t data_len, size_t block_size)
{
    uint8_t padding = block_size - (data_len % block_size);
    for (size_t i = 0; i < padding; i++) {
        data[data_len + i] = padding;
    }
}

static size_t pkcs7_unpad(const uint8_t *data, size_t data_len, size_t block_size)
{
    if (data_len == 0 || data_len % block_size != 0) return 0;
    uint8_t padding = data[data_len - 1];
    if (padding == 0 || padding > block_size || padding > data_len) return 0;
    for (size_t i = 0; i < padding; i++) {
        if (data[data_len - 1 - i] != padding) return 0;
    }
    return data_len - padding;
}

int crypto_aes_cbc_encrypt(const uint8_t *key, size_t key_len, const uint8_t iv[16],
                           const uint8_t *input, size_t input_len, uint8_t **output)
{
    if (!key || !iv || !input || !output || (input_len % 16 != 0)) return -1;

    int keybits = (key_len == 32) ? 256 : ((key_len == 16) ? 128 : -1);
    if (keybits < 0) return -1;

    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);

    if (mbedtls_aes_setkey_enc(&aes_ctx, key, keybits) != 0) {
        mbedtls_aes_free(&aes_ctx);
        return -1;
    }

    *output = (uint8_t *)malloc(input_len);
    if (!*output) {
        mbedtls_aes_free(&aes_ctx);
        return -1;
    }

    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    int ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, input_len, iv_copy, input, *output);
    mbedtls_aes_free(&aes_ctx);

    if (ret != 0) {
        free(*output);
        *output = NULL;
        return -1;
    }
    return 0;
}

int crypto_aes_cbc_decrypt(const uint8_t *key, size_t key_len, const uint8_t iv[16],
                           const uint8_t *input, size_t input_len, uint8_t **output)
{
    if (!key || !iv || !input || !output || (input_len % 16 != 0)) return -1;

    int keybits = (key_len == 32) ? 256 : ((key_len == 16) ? 128 : -1);
    if (keybits < 0) return -1;

    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);

    if (mbedtls_aes_setkey_dec(&aes_ctx, key, keybits) != 0) {
        mbedtls_aes_free(&aes_ctx);
        return -1;
    }

    *output = (uint8_t *)malloc(input_len);
    if (!*output) {
        mbedtls_aes_free(&aes_ctx);
        return -1;
    }

    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    int ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, input_len, iv_copy, input, *output);
    mbedtls_aes_free(&aes_ctx);

    if (ret != 0) {
        free(*output);
        *output = NULL;
        return -1;
    }
    return 0;
}

int crypto_aes_encrypt_padded(const uint8_t *key, size_t key_len, const uint8_t iv[16],
                              const uint8_t *input, size_t input_len,
                              uint8_t **output, size_t *output_len)
{
    size_t padding_len = 16 - (input_len % 16);
    size_t padded_len = input_len + padding_len;

    uint8_t *padded_input = (uint8_t *)malloc(padded_len);
    if (!padded_input) return -1;

    memcpy(padded_input, input, input_len);
    pkcs7_pad(padded_input, input_len, 16);

    int ret = crypto_aes_cbc_encrypt(key, key_len, iv, padded_input, padded_len, output);
    free(padded_input);

    if (ret == 0) {
        *output_len = padded_len;
    }
    return ret;
}

int crypto_aes_decrypt_padded(const uint8_t *key, size_t key_len, const uint8_t iv[16],
                              const uint8_t *input, size_t input_len,
                              uint8_t **output, size_t *output_len)
{
    uint8_t *decrypted = NULL;
    int ret = crypto_aes_cbc_decrypt(key, key_len, iv, input, input_len, &decrypted);
    if (ret != 0) return -1;

    size_t unpadded_len = pkcs7_unpad(decrypted, input_len, 16);
    if (unpadded_len == 0) {
        free(decrypted);
        return -1;
    }

    *output = decrypted;
    *output_len = unpadded_len;
    return 0;
}

int crypto_chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                                     const uint8_t *aad, size_t aad_len,
                                     const uint8_t *plaintext, size_t plaintext_len,
                                     uint8_t *ciphertext, uint8_t tag[16])
{
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);

    if (mbedtls_chachapoly_setkey(&ctx, key) != 0) {
        mbedtls_chachapoly_free(&ctx);
        return -1;
    }

    int ret = mbedtls_chachapoly_encrypt_and_tag(&ctx, plaintext_len, nonce, aad, aad_len,
                                                 plaintext, ciphertext, tag);
    mbedtls_chachapoly_free(&ctx);
    return ret == 0 ? 0 : -1;
}

int crypto_chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                                     const uint8_t *aad, size_t aad_len,
                                     const uint8_t *ciphertext, size_t ciphertext_len,
                                     const uint8_t tag[16], uint8_t *plaintext)
{
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);

    if (mbedtls_chachapoly_setkey(&ctx, key) != 0) {
        mbedtls_chachapoly_free(&ctx);
        return -1;
    }

    int ret = mbedtls_chachapoly_auth_decrypt(&ctx, ciphertext_len, nonce, aad, aad_len,
                                              tag, ciphertext, plaintext);
    mbedtls_chachapoly_free(&ctx);
    return ret == 0 ? 0 : -1;
}

char *crypto_base64_encode(const unsigned char *data, size_t input_length)
{
    size_t output_length = ((input_length + 2) / 3) * 4 + 1;
    char *encoded_data = (char *)malloc(output_length);
    if (!encoded_data) return NULL;

    size_t olen = 0;
    if (mbedtls_base64_encode((unsigned char *)encoded_data, output_length, &olen, data, input_length) != 0) {
        free(encoded_data);
        return NULL;
    }
    encoded_data[olen] = '\0';
    return encoded_data;
}

unsigned char *crypto_base64_decode(const char *data, size_t input_length, size_t *output_length)
{
    size_t max_output_size = input_length * 3 / 4;
    unsigned char *decoded_data = (unsigned char *)malloc(max_output_size + 1);
    if (!decoded_data) {
        *output_length = 0;
        return NULL;
    }

    if (mbedtls_base64_decode(decoded_data, max_output_size, output_length, (const unsigned char *)data, input_length) != 0) {
        free(decoded_data);
        *output_length = 0;
        return NULL;
    }
    decoded_data[*output_length] = '\0';
    return decoded_data;
}
