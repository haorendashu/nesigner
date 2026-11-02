#include "signer_crypto.h"
#include "esp_random.h"
#include "esp_log.h"
#include "psa/crypto.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "CRYPTO_PSA";

/* TRNG */
int crypto_trng_fill(uint8_t *buf, size_t len)
{
    if (buf == NULL && len > 0) return -1;
    esp_fill_random(buf, len);
    return 0;
}

/* SHA-256 */
int crypto_sha256(const uint8_t *data, size_t len, uint8_t hash[32])
{
    if (!data || !hash) return -1;
    size_t hash_len = 0;
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256, data, len, hash, 32, &hash_len);
    return (status == PSA_SUCCESS && hash_len == 32) ? 0 : -1;
}

/* BIP-340 Tagged SHA-256: SHA256(SHA256(tag) || SHA256(tag) || data) */
int crypto_tagged_sha256(const char *tag, const uint8_t *data, size_t len, uint8_t hash[32])
{
    if (!tag || !data || !hash) return -1;

    uint8_t tag_hash[32];
    size_t tag_hash_len = 0;
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256, (const uint8_t *)tag, strlen(tag), tag_hash, 32, &tag_hash_len);
    if (status != PSA_SUCCESS || tag_hash_len != 32) {
        return -1;
    }

    psa_hash_operation_t op = psa_hash_operation_init();
    status = psa_hash_setup(&op, PSA_ALG_SHA_256);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    status = psa_hash_update(&op, tag_hash, 32);
    if (status != PSA_SUCCESS) {
        psa_hash_abort(&op);
        return -1;
    }

    status = psa_hash_update(&op, tag_hash, 32);
    if (status != PSA_SUCCESS) {
        psa_hash_abort(&op);
        return -1;
    }

    status = psa_hash_update(&op, data, len);
    if (status != PSA_SUCCESS) {
        psa_hash_abort(&op);
        return -1;
    }

    size_t out_len = 0;
    status = psa_hash_finish(&op, hash, 32, &out_len);
    return (status == PSA_SUCCESS && out_len == 32) ? 0 : -1;
}

/* HMAC-SHA256 */
int crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t output[32])
{
    if (!key || !data || !output) return -1;

    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);

    psa_key_id_t key_id = 0;
    psa_status_t status = psa_import_key(&attr, key, key_len, &key_id);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    size_t mac_length = 0;
    status = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), data, data_len, output, 32, &mac_length);
    psa_destroy_key(key_id);

    return (status == PSA_SUCCESS && mac_length == 32) ? 0 : -1;
}

/* HKDF-SHA256 */
int crypto_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                       const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *okm, size_t okm_len)
{
    if (!ikm || !okm || okm_len == 0) return -1;

    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);

    psa_key_id_t key_id = 0;
    psa_status_t status = psa_import_key(&attr, ikm, ikm_len, &key_id);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    status = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (status != PSA_SUCCESS) {
        psa_destroy_key(key_id);
        return -1;
    }

    if (salt != NULL && salt_len > 0) {
        status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt, salt_len);
        if (status != PSA_SUCCESS) {
            psa_key_derivation_abort(&op);
            psa_destroy_key(key_id);
            return -1;
        }
    }

    status = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, key_id);
    if (status != PSA_SUCCESS) {
        psa_key_derivation_abort(&op);
        psa_destroy_key(key_id);
        return -1;
    }

    if (info != NULL && info_len > 0) {
        status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, info, info_len);
        if (status != PSA_SUCCESS) {
            psa_key_derivation_abort(&op);
            psa_destroy_key(key_id);
            return -1;
        }
    }

    status = psa_key_derivation_output_bytes(&op, okm, okm_len);
    psa_key_derivation_abort(&op);
    psa_destroy_key(key_id);

    return (status == PSA_SUCCESS) ? 0 : -1;
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

/* AES-CBC Encrypt */
int crypto_aes_cbc_encrypt(const uint8_t *key, size_t key_len, const uint8_t iv[16],
                           const uint8_t *input, size_t input_len, uint8_t **output)
{
    if (!key || !iv || !input || !output || (input_len == 0) || (input_len % 16 != 0)) return -1;
    if (key_len != 16 && key_len != 32) return -1;

    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_CBC_NO_PADDING);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);

    psa_key_id_t key_id = 0;
    psa_status_t status = psa_import_key(&attr, key, key_len, &key_id);
    if (status != PSA_SUCCESS) return -1;

    *output = (uint8_t *)malloc(input_len);
    if (!*output) {
        psa_destroy_key(key_id);
        return -1;
    }

    psa_cipher_operation_t op = psa_cipher_operation_init();
    status = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CBC_NO_PADDING);
    if (status != PSA_SUCCESS) {
        free(*output);
        *output = NULL;
        psa_destroy_key(key_id);
        return -1;
    }

    status = psa_cipher_set_iv(&op, iv, 16);
    if (status != PSA_SUCCESS) {
        psa_cipher_abort(&op);
        free(*output);
        *output = NULL;
        psa_destroy_key(key_id);
        return -1;
    }

    size_t out_len = 0;
    status = psa_cipher_update(&op, input, input_len, *output, input_len, &out_len);
    if (status == PSA_SUCCESS) {
        size_t finish_len = 0;
        status = psa_cipher_finish(&op, *output + out_len, input_len - out_len, &finish_len);
    } else {
        psa_cipher_abort(&op);
    }

    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        free(*output);
        *output = NULL;
        return -1;
    }
    return 0;
}

/* AES-CBC Decrypt */
int crypto_aes_cbc_decrypt(const uint8_t *key, size_t key_len, const uint8_t iv[16],
                           const uint8_t *input, size_t input_len, uint8_t **output)
{
    if (!key || !iv || !input || !output || (input_len == 0) || (input_len % 16 != 0)) return -1;
    if (key_len != 16 && key_len != 32) return -1;

    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_CBC_NO_PADDING);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);

    psa_key_id_t key_id = 0;
    psa_status_t status = psa_import_key(&attr, key, key_len, &key_id);
    if (status != PSA_SUCCESS) return -1;

    *output = (uint8_t *)malloc(input_len);
    if (!*output) {
        psa_destroy_key(key_id);
        return -1;
    }

    psa_cipher_operation_t op = psa_cipher_operation_init();
    status = psa_cipher_decrypt_setup(&op, key_id, PSA_ALG_CBC_NO_PADDING);
    if (status != PSA_SUCCESS) {
        free(*output);
        *output = NULL;
        psa_destroy_key(key_id);
        return -1;
    }

    status = psa_cipher_set_iv(&op, iv, 16);
    if (status != PSA_SUCCESS) {
        psa_cipher_abort(&op);
        free(*output);
        *output = NULL;
        psa_destroy_key(key_id);
        return -1;
    }

    size_t out_len = 0;
    status = psa_cipher_update(&op, input, input_len, *output, input_len, &out_len);
    if (status == PSA_SUCCESS) {
        size_t finish_len = 0;
        status = psa_cipher_finish(&op, *output + out_len, input_len - out_len, &finish_len);
    } else {
        psa_cipher_abort(&op);
    }

    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
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

/* ChaCha20-Poly1305 AEAD */
int crypto_chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                                     const uint8_t *aad, size_t aad_len,
                                     const uint8_t *plaintext, size_t plaintext_len,
                                     uint8_t *ciphertext, uint8_t tag[16])
{
    if (!key || !nonce || !ciphertext || !tag) return -1;
    if (plaintext_len > 0 && !plaintext) return -1;

    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_CHACHA20_POLY1305);
    psa_set_key_type(&attr, PSA_KEY_TYPE_CHACHA20);

    psa_key_id_t key_id = 0;
    psa_status_t status = psa_import_key(&attr, key, 32, &key_id);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    size_t out_size = plaintext_len + 16;
    uint8_t *out_buf = (uint8_t *)malloc(out_size);
    if (!out_buf) {
        psa_destroy_key(key_id);
        return -1;
    }

    size_t out_len = 0;
    status = psa_aead_encrypt(key_id, PSA_ALG_CHACHA20_POLY1305,
                              nonce, 12,
                              aad, aad_len,
                              plaintext, plaintext_len,
                              out_buf, out_size, &out_len);

    psa_destroy_key(key_id);

    if (status == PSA_SUCCESS && out_len == out_size) {
        if (plaintext_len > 0) {
            memcpy(ciphertext, out_buf, plaintext_len);
        }
        memcpy(tag, out_buf + plaintext_len, 16);
        free(out_buf);
        return 0;
    }

    free(out_buf);
    return -1;
}

int crypto_chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                                     const uint8_t *aad, size_t aad_len,
                                     const uint8_t *ciphertext, size_t ciphertext_len,
                                     const uint8_t tag[16], uint8_t *plaintext)
{
    if (!key || !nonce || !tag) return -1;
    if (ciphertext_len > 0 && (!ciphertext || !plaintext)) return -1;

    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_CHACHA20_POLY1305);
    psa_set_key_type(&attr, PSA_KEY_TYPE_CHACHA20);

    psa_key_id_t key_id = 0;
    psa_status_t status = psa_import_key(&attr, key, 32, &key_id);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    size_t in_size = ciphertext_len + 16;
    uint8_t *in_buf = (uint8_t *)malloc(in_size);
    if (!in_buf) {
        psa_destroy_key(key_id);
        return -1;
    }

    if (ciphertext_len > 0) {
        memcpy(in_buf, ciphertext, ciphertext_len);
    }
    memcpy(in_buf + ciphertext_len, tag, 16);

    size_t out_len = 0;
    status = psa_aead_decrypt(key_id, PSA_ALG_CHACHA20_POLY1305,
                              nonce, 12,
                              aad, aad_len,
                              in_buf, in_size,
                              plaintext, ciphertext_len, &out_len);

    free(in_buf);
    psa_destroy_key(key_id);

    return (status == PSA_SUCCESS && out_len == ciphertext_len) ? 0 : -1;
}

/* ChaCha20 Stream Cipher (RFC 7539 / 8439) */
int crypto_chacha20_stream(const uint8_t key[32], const uint8_t nonce[12],
                           const uint8_t *input, size_t len, uint8_t *output)
{
    if (!key || !nonce || !output) return -1;
    if (len == 0) return 0;
    if (!input) return -1;

    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_STREAM_CIPHER);
    psa_set_key_type(&attr, PSA_KEY_TYPE_CHACHA20);

    psa_key_id_t key_id = 0;
    psa_status_t status = psa_import_key(&attr, key, 32, &key_id);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    psa_cipher_operation_t op = psa_cipher_operation_init();
    status = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_STREAM_CIPHER);
    if (status != PSA_SUCCESS) {
        psa_destroy_key(key_id);
        return -1;
    }

    status = psa_cipher_set_iv(&op, nonce, 12);
    if (status != PSA_SUCCESS) {
        psa_cipher_abort(&op);
        psa_destroy_key(key_id);
        return -1;
    }

    size_t out_len = 0;
    status = psa_cipher_update(&op, input, len, output, len, &out_len);
    if (status == PSA_SUCCESS) {
        size_t finish_len = 0;
        status = psa_cipher_finish(&op, output + out_len, len - out_len, &finish_len);
    } else {
        psa_cipher_abort(&op);
    }

    psa_destroy_key(key_id);
    return (status == PSA_SUCCESS) ? 0 : -1;
}

/* Standalone RFC 4648 Standard Base64 */
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *crypto_base64_encode(const unsigned char *data, size_t input_length)
{
    if (!data) return NULL;
    size_t output_length = 4 * ((input_length + 2) / 3);
    char *encoded_data = (char *)malloc(output_length + 1);
    if (!encoded_data) return NULL;

    size_t i = 0, j = 0;
    while (i < input_length) {
        size_t rem = input_length - i;
        uint32_t octet_a = data[i++];
        uint32_t octet_b = (rem > 1) ? data[i++] : 0;
        uint32_t octet_c = (rem > 2) ? data[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        encoded_data[j++] = b64_table[(triple >> 18) & 0x3F];
        encoded_data[j++] = b64_table[(triple >> 12) & 0x3F];
        encoded_data[j++] = (rem > 1) ? b64_table[(triple >> 6) & 0x3F] : '=';
        encoded_data[j++] = (rem > 2) ? b64_table[triple & 0x3F] : '=';
    }

    encoded_data[output_length] = '\0';
    return encoded_data;
}

static int b64_char_value(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

unsigned char *crypto_base64_decode(const char *data, size_t input_length, size_t *output_length)
{
    if (!data || !output_length) return NULL;
    if (input_length % 4 != 0) {
        *output_length = 0;
        return NULL;
    }

    size_t padding = 0;
    if (input_length > 0 && data[input_length - 1] == '=') padding++;
    if (input_length > 1 && data[input_length - 2] == '=') padding++;

    size_t decoded_len = (input_length / 4) * 3 - padding;
    unsigned char *decoded_data = (unsigned char *)malloc(decoded_len + 1);
    if (!decoded_data) {
        *output_length = 0;
        return NULL;
    }

    for (size_t i = 0, j = 0; i < input_length;) {
        int v0 = b64_char_value(data[i++]);
        int v1 = b64_char_value(data[i++]);
        char c2 = data[i++];
        char c3 = data[i++];
        int v2 = (c2 == '=') ? 0 : b64_char_value(c2);
        int v3 = (c3 == '=') ? 0 : b64_char_value(c3);

        if (v0 < 0 || v1 < 0 || (c2 != '=' && v2 < 0) || (c3 != '=' && v3 < 0)) {
            free(decoded_data);
            *output_length = 0;
            return NULL;
        }

        uint32_t triple = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;

        if (j < decoded_len) decoded_data[j++] = (triple >> 16) & 0xFF;
        if (c2 != '=' && j < decoded_len) decoded_data[j++] = (triple >> 8) & 0xFF;
        if (c3 != '=' && j < decoded_len) decoded_data[j++] = triple & 0xFF;
    }

    decoded_data[decoded_len] = '\0';
    *output_length = decoded_len;
    return decoded_data;
}
