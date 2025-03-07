#ifndef NOSTR_H
#define NOSTR_H

#include <stdio.h>
#include <string.h>
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/sha256.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/base64.h"
#include "cJSON.h"

#define NOSTR_EVENT_ID_BIN_LEN 32
#define NOSTR_EVENT_ID_HEX_LEN 64
#define NOSTR_EVENT_SIG_BIN_LEN 64
#define NOSTR_EVENT_SIG_HEX_LEN 128

// 将16进制字符串转换为二进制
int hex_to_bin(const char *hex, uint8_t *bin, size_t bin_size);

// 将二进制转换为16进制字符串
void bin_to_hex(const uint8_t *bin, size_t bin_size, char *hex);

// 核心逻辑：私钥生成公钥
int get_public(const uint8_t *privkey_bin, uint8_t *pubkey_bin);

// 计算 Nostr Event ID
int gen_event_id(const char *pubkey_hex, uint32_t created_at, uint16_t kind,
                 cJSON *tags, const char *content, char *event_id_hex);

// 签名函数
int sign(const uint8_t *privkey_bin, const uint8_t *message_bin, uint8_t *sig_bin);

// Base64 编码函数（使用mbedtls实现）
char *base64_encode(const unsigned char *data, size_t input_length);

// Base64 解码函数（使用mbedtls实现）
unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length);

// PKCS#7 填充函数（严格遵循 RFC 2315 标准）
void pkcs7_pad(uint8_t *data, size_t data_len, size_t block_size);

// PKCS#7 移除填充函数（严格验证所有填充字节）
size_t pkcs7_unpad(uint8_t *data, size_t data_len, size_t block_size);

// NIP04Encrypt 函数（修复内存泄漏和 IV 处理）
int nip04_encrypt(const uint8_t *our_privkey_bin, const uint8_t *their_pubkey_bin, const char *text, char **encrypted_content);

// NIP04Decrypt 函数（修复 Base64 长度和内存泄漏）
int nip04_decrypt(const uint8_t *our_privkey_bin, const uint8_t *their_pubkey_bin, const char *encrypted_content, char **decrypted_text);

// 计算 HMAC-SHA256
int hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *output);

// NIP44加密函数
int nip44_encrypt(const uint8_t *our_privkey_bin, const uint8_t *their_pubkey_bin,
                  const char *text, char **encrypted_content);

// NIP44解密函数
int nip44_decrypt(const uint8_t *our_privkey_bin, const uint8_t *their_pubkey_bin,
                  const char *encrypted_content, char **decrypted_text);

#endif