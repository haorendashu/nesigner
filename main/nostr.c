#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/entropy.h"
#include "mbedtls/sha256.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/base64.h"
#include "cJSON.h"

// 将16进制字符串转换为二进制
int hex_to_bin(const char *hex, uint8_t *bin, size_t bin_size)
{
    if (strlen(hex) != 2 * bin_size)
        return -1;
    for (size_t i = 0; i < bin_size; i++)
    {
        if (sscanf(hex + 2 * i, "%2hhx", &bin[i]) != 1)
            return -1;
    }
    return 0;
}

// 将二进制转换为16进制字符串
void bin_to_hex(const uint8_t *bin, size_t bin_size, char *hex)
{
    for (size_t i = 0; i < bin_size; i++)
    {
        sprintf(hex + 2 * i, "%02x", bin[i]);
    }
}

// 初始化随机数生成器和加载 secp256k1 曲线
static int init_crypto_context(mbedtls_ecp_group *grp, mbedtls_ctr_drbg_context *ctr_drbg)
{
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(ctr_drbg);

    // 用熵源初始化 CTR_DRBG
    if (mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0)
    {
        ESP_LOGE("Nostr", "Failed to seed CTR_DRBG");
        mbedtls_ctr_drbg_free(ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return -1;
    }

    // 加载 secp256k1 曲线
    mbedtls_ecp_group_init(grp);
    if (mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256K1) != 0)
    {
        ESP_LOGE("Nostr", "Failed to load secp256k1 curve");
        mbedtls_ctr_drbg_free(ctr_drbg);
        mbedtls_entropy_free(&entropy);
        mbedtls_ecp_group_free(grp);
        return -1;
    }

    mbedtls_entropy_free(&entropy);
    return 0;
}

// 核心逻辑：私钥生成公钥
int get_public(const uint8_t *privkey_bin, uint8_t *pubkey_bin)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point pub;
    mbedtls_mpi d;
    mbedtls_ctr_drbg_context ctr_drbg;
    uint8_t temp_pubkey[33]; // 压缩公钥需要33字节

    if (init_crypto_context(&grp, &ctr_drbg) != 0)
        return -1;

    mbedtls_ecp_point_init(&pub);
    mbedtls_mpi_init(&d);

    // 直接读取二进制私钥
    mbedtls_mpi_read_binary(&d, privkey_bin, 32);

    // 计算公钥 Q = d * G
    if (mbedtls_ecp_mul(&grp, &pub, &d, &grp.G, mbedtls_ctr_drbg_random, &ctr_drbg) != 0)
    {
        ESP_LOGE("Nostr", "ECP multiply failed");
        goto cleanup;
    }

    // 获取压缩格式的公钥（33字节）
    size_t olen;
    if (mbedtls_ecp_point_write_binary(&grp, &pub, MBEDTLS_ECP_PF_COMPRESSED,
                                       &olen, temp_pubkey, sizeof(temp_pubkey)) != 0)
    {
        ESP_LOGE("Nostr", "Failed to write public key");
        goto cleanup;
    }

    // 提取 x 坐标（跳过压缩标志字节）
    if (olen != 33 || (temp_pubkey[0] != 0x02 && temp_pubkey[0] != 0x03))
    {
        ESP_LOGE("Nostr", "Unexpected public key format");
        goto cleanup;
    }
    memcpy(pubkey_bin, temp_pubkey + 1, 32);

cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&pub);
    mbedtls_mpi_free(&d);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return 0;
}

// 计算 Nostr Event ID
int gen_event_id(const char *pubkey_hex, uint32_t created_at, uint16_t kind,
                 cJSON *tags, const char *content, char *event_id_hex)
{
    // 1. 构建事件数组
    cJSON *event_array = cJSON_CreateArray();
    cJSON_AddItemToArray(event_array, cJSON_CreateNumber(0));          // 固定值 0
    cJSON_AddItemToArray(event_array, cJSON_CreateString(pubkey_hex)); // pubkey
    cJSON_AddItemToArray(event_array, cJSON_CreateNumber(created_at)); // created_at
    cJSON_AddItemToArray(event_array, cJSON_CreateNumber(kind));       // kind
    cJSON_AddItemToArray(event_array, cJSON_Duplicate(tags, 1));       // tags
    cJSON_AddItemToArray(event_array, cJSON_CreateString(content));    // content

    // 2. 序列化为 JSON 字符串
    char *json_str = cJSON_PrintUnformatted(event_array);
    if (!json_str)
    {
        ESP_LOGE("Nostr", "Failed to serialize event data to JSON");
        cJSON_Delete(event_array);
        return -1;
    }

    // 3. 计算 SHA256 哈希
    uint8_t hash[32];
    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0); // 0 表示 SHA256，1 表示 SHA224
    mbedtls_sha256_update(&sha256_ctx, (const uint8_t *)json_str, strlen(json_str));
    mbedtls_sha256_finish(&sha256_ctx, hash);
    mbedtls_sha256_free(&sha256_ctx);

    // 4. 转换为小写十六进制字符串
    bin_to_hex(hash, sizeof(hash), event_id_hex);

    // 清理资源
    cJSON_Delete(event_array);
    free(json_str);

    return 0;
}

// 签名函数
int sign(const uint8_t *privkey_bin, const uint8_t *message_bin, uint8_t *sig_bin)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point r, pub;
    mbedtls_mpi d, k, e, s;
    // uint8_t message_bin[32], sig_bin[64];
    mbedtls_ctr_drbg_context ctr_drbg;

    if (init_crypto_context(&grp, &ctr_drbg) != 0)
    {
        return -1;
    }

    mbedtls_ecp_point_init(&r);
    mbedtls_ecp_point_init(&pub);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&k);
    mbedtls_mpi_init(&e);
    mbedtls_mpi_init(&s);

    // if (hex_to_bin(message_hex, message_bin, sizeof(message_bin)) != 0)
    // {
    //     ESP_LOGE("Nostr", "Invalid message hex");
    //     goto cleanup;
    // }
    mbedtls_mpi_read_binary(&d, privkey_bin, sizeof(privkey_bin));

    // 生成随机数 k
    if (mbedtls_mpi_fill_random(&k, 32, mbedtls_ctr_drbg_random, &ctr_drbg) != 0)
    {
        ESP_LOGE("Nostr", "Failed to generate random k");
        goto cleanup;
    }
    mbedtls_mpi_mod_mpi(&k, &k, &grp.N);

    // 计算 R = k * G
    if (mbedtls_ecp_mul(&grp, &r, &k, &grp.G, mbedtls_ctr_drbg_random, &ctr_drbg) != 0)
    {
        ESP_LOGE("Nostr", "ECP multiply failed");
        goto cleanup;
    }
    // 检查点 R 是否在曲线上
    if (mbedtls_ecp_check_pubkey(&grp, &r) != 0)
    {
        ESP_LOGE("Nostr", "Point R is not on the curve");
        goto cleanup;
    }

    // 计算 e = H(R || P || m)
    uint8_t r_bin[33];
    uint8_t pubkey_bin[33];
    size_t olen;
    if (mbedtls_ecp_point_write_binary(&grp, &r, MBEDTLS_ECP_PF_COMPRESSED,
                                       &olen, r_bin, sizeof(r_bin)) != 0)
    {
        ESP_LOGE("Nostr", "Failed to write R");
        goto cleanup;
    }
    if (mbedtls_ecp_mul(&grp, &pub, &d, &grp.G, mbedtls_ctr_drbg_random, &ctr_drbg) != 0)
    {
        ESP_LOGE("Nostr", "ECP multiply failed");
        goto cleanup;
    }
    if (mbedtls_ecp_point_write_binary(&grp, &pub, MBEDTLS_ECP_PF_COMPRESSED,
                                       &olen, pubkey_bin, sizeof(pubkey_bin)) != 0)
    {
        ESP_LOGE("Nostr", "Failed to write public key");
        goto cleanup;
    }
    uint8_t hash_input[32 + 33 + 32];
    memcpy(hash_input, r_bin + 1, 32); // 跳过压缩标志字节
    memcpy(hash_input + 32, pubkey_bin, 33);
    memcpy(hash_input + 32 + 33, message_bin, 32);
    uint8_t hash[32];
    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, hash_input, sizeof(hash_input));
    mbedtls_sha256_finish(&sha256_ctx, hash);
    mbedtls_sha256_free(&sha256_ctx);
    mbedtls_mpi_read_binary(&e, hash, sizeof(hash));

    // 计算 s = k + e * d
    mbedtls_mpi_mul_mpi(&e, &e, &d);
    mbedtls_mpi_add_mpi(&s, &k, &e);
    mbedtls_mpi_mod_mpi(&s, &s, &grp.N);

    // 构建签名
    memcpy(sig_bin, r_bin + 1, 32); // 跳过压缩标志字节
    mbedtls_mpi_write_binary(&s, sig_bin + 32, 32);

    // // 转换为十六进制字符串
    // bin_to_hex(sig_bin, sizeof(sig_bin), sig_hex);
cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&r);
    mbedtls_ecp_point_free(&pub);
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&k);
    mbedtls_mpi_free(&e);
    mbedtls_mpi_free(&s);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return 0;
}

// Base64 编码函数（使用mbedtls实现）
char *base64_encode(const unsigned char *data, size_t input_length)
{
    // 手动计算 Base64 编码后所需的缓冲区大小
    size_t output_length = ((input_length + 2) / 3) * 4 + 1; // +1 是为了给字符串结束符 '\0' 预留空间
    char *encoded_data = (char *)malloc(output_length);
    if (encoded_data == NULL)
        return NULL;

    size_t olen;
    if (mbedtls_base64_encode((unsigned char *)encoded_data, output_length, &olen, data, input_length) != 0)
    {
        free(encoded_data);
        return NULL;
    }
    // 确保编码后的字符串以 '\0' 结尾
    encoded_data[olen] = '\0';
    return encoded_data;
}

// Base64 解码函数（使用mbedtls实现）
unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length)
{
    // 为了解码结果分配一个相对较大的初始空间
    size_t max_output_size = input_length * 3 / 4;
    unsigned char *decoded_data = (unsigned char *)malloc(max_output_size);
    if (decoded_data == NULL)
    {
        *output_length = 0;
        return NULL;
    }

    if (mbedtls_base64_decode(decoded_data, max_output_size, output_length, (const unsigned char *)data, input_length) != 0)
    {
        free(decoded_data);
        *output_length = 0;
        return NULL;
    }

    // 如果实际解码长度小于初始分配的大小，重新分配内存以节省空间（可选步骤）
    if (*output_length < max_output_size)
    {
        unsigned char *reallocated = (unsigned char *)realloc(decoded_data, *output_length);
        if (reallocated != NULL)
        {
            decoded_data = reallocated;
        }
    }

    return decoded_data;
}

// 计算共享密钥
static int compute_shared_secret(const uint8_t *our_privkey_bin, const uint8_t *their_pubkey_bin, uint8_t *shared_x)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point their_pub, shared_point;
    mbedtls_mpi our_priv;
    uint8_t temp_pubkey_bin[33];
    mbedtls_ctr_drbg_context ctr_drbg;
    int ret = -1;

    if (init_crypto_context(&grp, &ctr_drbg) != 0)
    {
        return -1;
    }

    mbedtls_ecp_point_init(&their_pub);
    mbedtls_ecp_point_init(&shared_point);
    mbedtls_mpi_init(&our_priv);

    memcpy(temp_pubkey_bin + 1, their_pubkey_bin, 32);
    temp_pubkey_bin[0] = 0x02; // 强制使用压缩格式

    // 解析公钥点
    if (mbedtls_ecp_point_read_binary(&grp, &their_pub, temp_pubkey_bin, 33) != 0)
    {
        ESP_LOGE("NIP44", "公钥解析失败");
        goto cleanup;
    }

    // 验证公钥有效性
    if (mbedtls_ecp_check_pubkey(&grp, &their_pub) != 0)
    {
        ESP_LOGE("NIP44", "无效的公钥点");
        goto cleanup;
    }

    uint8_t our_privkey_bin_copy[32];
    memcpy(our_privkey_bin_copy, our_privkey_bin, 32); // 拷贝，避免被修改
    mbedtls_mpi_read_binary(&our_priv, our_privkey_bin_copy, 32);

    // 计算共享点
    if (mbedtls_ecp_mul(&grp, &shared_point, &our_priv, &their_pub, mbedtls_ctr_drbg_random, &ctr_drbg) != 0)
    {
        ESP_LOGE("NIP44", "椭圆曲线乘法失败");
        goto cleanup;
    }

    // 验证共享点有效性
    if (mbedtls_ecp_check_pubkey(&grp, &shared_point) != 0)
    {
        ESP_LOGE("NIP44", "无效的共享点");
        goto cleanup;
    }

    // 提取X坐标
    size_t olen;
    uint8_t shared_point_bin[33];
    if (mbedtls_ecp_point_write_binary(&grp, &shared_point, MBEDTLS_ECP_PF_COMPRESSED,
                                       &olen, shared_point_bin, sizeof(shared_point_bin)) != 0)
    {
        ESP_LOGE("NIP44", "共享点序列化失败");
        goto cleanup;
    }

    // 调试输出
    // char debug_buf[65] = {0};
    // bin_to_hex(shared_point_bin + 1, 32, debug_buf);
    // ESP_LOGI("NIP44", "共享点X坐标: %s", debug_buf);

    memcpy(shared_x, shared_point_bin + 1, 32);
    ret = 0;

cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&their_pub);
    mbedtls_ecp_point_free(&shared_point);
    mbedtls_mpi_free(&our_priv);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return ret;
}

// PKCS#7 填充函数（严格遵循 RFC 2315 标准）
void pkcs7_pad(uint8_t *data, size_t data_len, size_t block_size)
{
    size_t padding_len = block_size - (data_len % block_size);
    if (padding_len == 0)
    {
        padding_len = block_size; // 关键修复：当数据长度正好是块大小的整数倍时，填充一个完整块
    }
    for (size_t i = 0; i < padding_len; i++)
    {
        data[data_len + i] = (uint8_t)padding_len;
    }
}

// PKCS#7 移除填充函数（严格验证所有填充字节）
size_t pkcs7_unpad(uint8_t *data, size_t data_len, size_t block_size)
{
    if (data_len == 0 || data_len % block_size != 0)
    {
        ESP_LOGE("NIP04", "Invalid data length for PKCS#7 unpadding");
        return 0;
    }
    uint8_t padding_len = data[data_len - 1];
    if (padding_len == 0 || padding_len > block_size)
    {
        ESP_LOGE("NIP04", "Invalid padding length: %d", padding_len);
        return 0;
    }
    // 检查所有填充字节是否等于 padding_len
    for (size_t i = 1; i <= padding_len; i++)
    {
        if (data[data_len - i] != padding_len)
        {
            ESP_LOGE("NIP04", "Invalid padding byte at offset %d: expected 0x%02x, got 0x%02x",
                     data_len - i, padding_len, data[data_len - i]);
            return 0;
        }
    }
    return data_len - padding_len;
}

// NIP04Encrypt 函数（修复内存泄漏和 IV 处理）
int nip04_encrypt(const uint8_t *our_privkey_bin, const uint8_t *their_pubkey_bin, const char *text, char **encrypted_content)
{

    uint8_t shared_x[32];
    if (compute_shared_secret(our_privkey_bin, their_pubkey_bin, shared_x) != 0)
    {
        ESP_LOGE("NIP04", "Failed to compute shared secret");
        return -1;
    }

    // 生成随机 IV
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0)
    {
        ESP_LOGE("NIP04", "CTR_DRBG seeding failed");
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return -1;
    }

    uint8_t iv[16];
    if (mbedtls_ctr_drbg_random(&ctr_drbg, iv, sizeof(iv)) != 0)
    {
        ESP_LOGE("NIP04", "IV generation failed");
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return -1;
    }
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    // 初始化 AES 上下文
    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    if (mbedtls_aes_setkey_enc(&aes_ctx, shared_x, 256) != 0)
    {
        ESP_LOGE("NIP04", "AES key setup failed");
        mbedtls_aes_free(&aes_ctx);
        return -1;
    }

    // 处理明文并填充
    size_t text_len = strlen(text);
    size_t padded_len = ((text_len + 15) / 16) * 16; // 强制对齐到 16 字节
    uint8_t *padded_text = (uint8_t *)malloc(padded_len);
    if (!padded_text)
    {
        ESP_LOGE("NIP04", "Memory allocation failed for padded text");
        mbedtls_aes_free(&aes_ctx);
        return -1;
    }
    memset(padded_text, 0, padded_len); // 显式初始化
    memcpy(padded_text, text, text_len);
    pkcs7_pad(padded_text, text_len, 16); // 应用修复后的填充

    // 加密数据
    uint8_t *encrypted_text = (uint8_t *)malloc(padded_len);
    if (!encrypted_text)
    {
        ESP_LOGE("NIP04", "Memory allocation failed for encrypted text");
        mbedtls_aes_free(&aes_ctx);
        free(padded_text);
        return -1;
    }

    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16); // 拷贝 IV，避免被 mbedtls_aes_crypt_cbc 修改
    if (mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, padded_len, iv_copy, padded_text, encrypted_text) != 0)
    {
        ESP_LOGE("NIP04", "AES encryption failed");
        mbedtls_aes_free(&aes_ctx);
        free(padded_text);
        free(encrypted_text);
        return -1;
    }

    mbedtls_aes_free(&aes_ctx);
    free(padded_text);

    // Base64 编码
    char *encrypted_text_b64 = base64_encode(encrypted_text, padded_len);
    char *iv_b64 = base64_encode(iv, sizeof(iv));
    free(encrypted_text);

    if (!encrypted_text_b64 || !iv_b64)
    {
        ESP_LOGE("NIP04", "Base64 encoding failed");
        free(encrypted_text_b64);
        free(iv_b64);
        return -1;
    }

    // 构建最终加密内容
    size_t content_len = strlen(encrypted_text_b64) + strlen(iv_b64) + 5; // "?iv=" + NULL
    *encrypted_content = (char *)malloc(content_len);
    if (!*encrypted_content)
    {
        ESP_LOGE("NIP04", "Memory allocation failed for encrypted content");
        free(encrypted_text_b64);
        free(iv_b64);
        return -1;
    }
    snprintf(*encrypted_content, content_len, "%s?iv=%s", encrypted_text_b64, iv_b64);
    free(encrypted_text_b64);
    free(iv_b64);

    return 0;
}

// NIP04Decrypt 函数（修复 Base64 长度和内存泄漏）
int nip04_decrypt(const uint8_t *our_privkey_bin, const uint8_t *their_pubkey_bin, const char *encrypted_content, char **decrypted_text)
{

    uint8_t shared_x[32];
    if (compute_shared_secret(our_privkey_bin, their_pubkey_bin, shared_x) != 0)
    {
        ESP_LOGE("NIP04", "Shared secret computation failed");
        return -1;
    }

    // 分离加密数据和 IV
    char *iv_start = strstr(encrypted_content, "?iv=");
    if (!iv_start || iv_start == encrypted_content)
    {
        ESP_LOGE("NIP04", "Invalid encrypted content format");
        return -1;
    }
    size_t encrypted_text_b64_len = iv_start - encrypted_content;
    char *encrypted_text_b64 = (char *)malloc(encrypted_text_b64_len + 1);
    if (!encrypted_text_b64)
    {
        ESP_LOGE("NIP04", "Memory allocation failed for encrypted text");
        return -1;
    }
    memcpy(encrypted_text_b64, encrypted_content, encrypted_text_b64_len);
    encrypted_text_b64[encrypted_text_b64_len] = '\0';

    char *iv_b64 = iv_start + 4;
    size_t iv_b64_len = strlen(iv_b64);

    // Base64 解码
    size_t encrypted_text_len, iv_len;
    uint8_t *encrypted_text = base64_decode(encrypted_text_b64, encrypted_text_b64_len, &encrypted_text_len);
    free(encrypted_text_b64);
    if (!encrypted_text || encrypted_text_len % 16 != 0)
    {
        ESP_LOGE("NIP04", "Invalid encrypted text (length=%d)", encrypted_text_len);
        if (encrypted_text)
            free(encrypted_text);
        return -1;
    }

    uint8_t *iv = base64_decode(iv_b64, iv_b64_len, &iv_len);
    if (!iv || iv_len != 16)
    {
        ESP_LOGE("NIP04", "Invalid IV (length=%d)", iv_len);
        free(encrypted_text);
        free(iv);
        return -1;
    }

    // 初始化 AES 上下文
    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    if (mbedtls_aes_setkey_dec(&aes_ctx, shared_x, 256) != 0)
    {
        ESP_LOGE("NIP04", "AES key setup failed");
        mbedtls_aes_free(&aes_ctx);
        free(encrypted_text);
        free(iv);
        return -1;
    }

    // 解密数据
    uint8_t *decrypted_bytes = (uint8_t *)malloc(encrypted_text_len);
    if (!decrypted_bytes)
    {
        ESP_LOGE("NIP04", "Memory allocation failed for decrypted bytes");
        mbedtls_aes_free(&aes_ctx);
        free(encrypted_text);
        free(iv);
        return -1;
    }

    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16); // 拷贝 IV，避免被 mbedtls_aes_crypt_cbc 修改
    if (mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, encrypted_text_len, iv_copy, encrypted_text, decrypted_bytes) != 0)
    {
        ESP_LOGE("NIP04", "AES decryption failed");
        mbedtls_aes_free(&aes_ctx);
        free(encrypted_text);
        free(iv);
        free(decrypted_bytes);
        return -1;
    }

    mbedtls_aes_free(&aes_ctx);
    free(encrypted_text);
    free(iv);

    // 移除填充
    size_t unpadded_len = pkcs7_unpad(decrypted_bytes, encrypted_text_len, 16);
    if (unpadded_len == 0)
    {
        ESP_LOGE("NIP04", "PKCS#7 unpadding failed");
        free(decrypted_bytes);
        return -1;
    }

    // 复制解密后的文本
    *decrypted_text = (char *)malloc(unpadded_len + 1);
    if (!*decrypted_text)
    {
        ESP_LOGE("NIP04", "Memory allocation failed for decrypted text");
        free(decrypted_bytes);
        return -1;
    }
    memcpy(*decrypted_text, decrypted_bytes, unpadded_len);
    (*decrypted_text)[unpadded_len] = '\0';
    free(decrypted_bytes);

    return 0;
}

// 密钥派生函数（严格遵循NIP44规范）
static int derive_key(const uint8_t *shared_secret, const uint8_t *nonce,
                      uint8_t *chacha_key, uint8_t *chacha_nonce, uint8_t *hmac_key)
{
    const uint8_t salt[] = {0x6e, 0x69, 0x70, 0x34, 0x34, 0x2d, 0x76, 0x32}; // "nip44-v2"的二进制表示
    uint8_t prk[32];

    // 提取阶段使用固定salt
    // HKDF-Extract(salt=固定值, IKM=shared_secret)
    if (mbedtls_hkdf_extract(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                             salt, 8, // 注意这里长度是8字节
                             shared_secret, 32,
                             prk) != 0)
    {
        ESP_LOGE("NIP44", "HKDF提取失败");
        return -1;
    }

    // 扩展阶段使用nonce作为info
    uint8_t keys[76];
    if (mbedtls_hkdf_expand(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                            prk, 32,
                            nonce, 32, // nonce作为info
                            keys, 76) != 0)
    {
        ESP_LOGE("NIP44", "HKDF扩展失败");
        return -1;
    }

    memcpy(chacha_key, keys, 32);
    memcpy(chacha_nonce, keys + 32, 12);
    memcpy(hmac_key, keys + 44, 32);
    return 0;
}

// 计算需要填充到的长度
static size_t calc_padded_len(size_t len)
{
    if (len == 0)
        return 0;
    if (len <= 32)
        return 32;

    // 计算 (len - 1) 的二进制位数
    size_t bitlen = 0;
    size_t n = len - 1;
    while (n > 0)
    {
        bitlen++;
        n >>= 1;
    }
    size_t next_power = (size_t)1 << bitlen;

    // 确定块大小
    size_t chunk_size = (next_power <= 256) ? 32 : next_power / 8;
    // 计算并返回填充后的长度
    return chunk_size * ((len + chunk_size - 1) / chunk_size);
}

// NIP44专用padding函数（带长度前缀） 带大端序长度前缀的填充
static uint8_t *nip44_pad(const char *text, size_t *padded_len)
{
    size_t text_len = strlen(text);
    if (text_len > 65535)
        return NULL;

    size_t total_padded = calc_padded_len(text_len);
    uint8_t *padded = calloc(1, 2 + total_padded);

    // 写入大端序长度前缀
    padded[0] = (text_len >> 8) & 0xFF;
    padded[1] = text_len & 0xFF;
    memcpy(padded + 2, text, text_len);

    *padded_len = total_padded + 2;
    return padded;
}

// NIP44专用unpadding函数（带严格校验）
static char *nip44_unpad(const uint8_t *padded, size_t padded_len)
{
    // 最小长度校验（前缀2字节 + 至少1字节数据）
    if (padded_len < 3)
    {
        ESP_LOGE("NIP44", "Padded data too short");
        return NULL;
    }

    // 解析原始长度
    uint16_t unpadded_len = (padded[0] << 8) | padded[1];

    // 长度有效性校验
    if (unpadded_len < 1 || unpadded_len > 65535)
    {
        ESP_LOGE("NIP44", "Invalid length in padding header: %d", unpadded_len);
        return NULL;
    }

    // 计算期望的填充长度
    size_t expected_padded = calc_padded_len(unpadded_len);
    if (expected_padded + 2 != padded_len)
    {
        ESP_LOGE("NIP44", "Length mismatch: expected %d, got %d", expected_padded, padded_len);
        return NULL;
    }

    // 数据区域校验（填充必须全零）
    size_t padding_start = 2 + unpadded_len;
    for (size_t i = padding_start; i < padded_len; i++)
    {
        if (padded[i] != 0)
        {
            ESP_LOGE("NIP44", "Non-zero padding at position %d", i);
            return NULL;
        }
    }

    // 提取原始数据
    char *result = (char *)malloc(unpadded_len + 1);
    if (!result)
        return NULL;
    memcpy(result, padded + 2, unpadded_len);
    result[unpadded_len] = '\0';
    return result;
}

// 计算 HMAC-SHA256
int hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *output)
{
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    if (mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1) != 0)
    {
        ESP_LOGE("NIP44", "Failed to setup HMAC context");
        mbedtls_md_free(&ctx);
        return -1;
    }

    if (mbedtls_md_hmac_starts(&ctx, key, key_len) != 0 ||
        mbedtls_md_hmac_update(&ctx, data, data_len) != 0 ||
        mbedtls_md_hmac_finish(&ctx, output) != 0)
    {
        ESP_LOGE("NIP44", "HMAC calculation failed");
        mbedtls_md_free(&ctx);
        return -1;
    }

    mbedtls_md_free(&ctx);
    return 0;
}

// NIP44加密函数
int nip44_encrypt(const uint8_t *our_privkey_bin, const uint8_t *their_pubkey_bin,
                  const char *text, char **encrypted_content)
{

    uint8_t shared_x[32];
    uint8_t *cipher = NULL;
    uint8_t *payload = NULL;
    uint8_t *padded_text = NULL;
    uint8_t *mac_input = NULL;
    mbedtls_chacha20_context ctx;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    int ret = -1;

    mbedtls_chacha20_init(&ctx);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    // 1. Compute shared secret
    if (compute_shared_secret(our_privkey_bin, their_pubkey_bin, shared_x) != 0)
    {
        ESP_LOGE("NIP44", "Shared secret computation failed");
        goto cleanup;
    }

    // 2. Generate random nonce (32 bytes)
    uint8_t nonce[32];
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0 ||
        mbedtls_ctr_drbg_random(&ctr_drbg, nonce, sizeof(nonce)) != 0)
    {
        ESP_LOGE("NIP44", "Nonce generation failed");
        goto cleanup;
    }

    // 3. Key derivation (HKDF)
    uint8_t chacha_key[32], chacha_nonce[12], hmac_key[32];
    if (derive_key(shared_x, nonce, chacha_key, chacha_nonce, hmac_key) != 0)
    {
        ESP_LOGE("NIP44", "Key derivation failed");
        goto cleanup;
    }

    // 4. Apply NIP44 padding
    size_t padded_len;
    if ((padded_text = nip44_pad(text, &padded_len)) == NULL)
    {
        ESP_LOGE("NIP44", "Padding failed");
        goto cleanup;
    }

    // 5. ChaCha20 encryption
    if ((cipher = malloc(padded_len)) == NULL)
    {
        ESP_LOGE("NIP44", "Memory allocation failed");
        goto cleanup;
    }
    if (mbedtls_chacha20_setkey(&ctx, chacha_key) != 0 ||
        mbedtls_chacha20_starts(&ctx, chacha_nonce, 0) != 0 ||
        mbedtls_chacha20_update(&ctx, padded_len, padded_text, cipher) != 0)
    {
        ESP_LOGE("NIP44", "Encryption failed");
        goto cleanup;
    }

    // 6. Compute HMAC-SHA256 (nonce || cipher)
    if ((mac_input = malloc(32 + padded_len)) == NULL)
    {
        ESP_LOGE("NIP44", "Memory allocation failed");
        goto cleanup;
    }
    memcpy(mac_input, nonce, 32);
    memcpy(mac_input + 32, cipher, padded_len);

    uint8_t mac[32];
    if (hmac_sha256(hmac_key, 32, mac_input, 32 + padded_len, mac) != 0)
    {
        ESP_LOGE("NIP44", "HMAC calculation failed");
        goto cleanup;
    }

    // 7. Build payload: version(1) + nonce(32) + cipher + mac(32)
    const size_t payload_size = 1 + 32 + padded_len + 32;
    if ((payload = malloc(payload_size)) == NULL)
    {
        ESP_LOGE("NIP44", "Memory allocation failed");
        goto cleanup;
    }
    payload[0] = 0x02; // version
    memcpy(payload + 1, nonce, 32);
    memcpy(payload + 33, cipher, padded_len);
    memcpy(payload + 33 + padded_len, mac, 32);

    // 8. Base64 encode
    if ((*encrypted_content = base64_encode(payload, payload_size)) == NULL)
    {
        ESP_LOGE("NIP44", "Base64 encoding failed");
        goto cleanup;
    }

    ret = 0;

cleanup:
    mbedtls_chacha20_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    if (padded_text)
        free(padded_text);
    if (cipher)
        free(cipher);
    if (payload)
        free(payload);
    if (mac_input)
        free(mac_input);
    return ret;
}

// NIP44解密函数
int nip44_decrypt(const uint8_t *our_privkey_bin, const uint8_t *their_pubkey_bin,
                  const char *encrypted_content, char **decrypted_text)
{

    uint8_t *payload = NULL;
    uint8_t *mac_input = NULL;
    mbedtls_chacha20_context ctx;
    int ret = -1;
    size_t payload_len;

    mbedtls_chacha20_init(&ctx);

    // 1. Base64 decode
    payload = base64_decode(encrypted_content, strlen(encrypted_content), &payload_len);
    if (!payload || payload_len < 45 || payload[0] != 0x02)
    {
        ESP_LOGE("NIP44", "Invalid payload (len=%d, version=%d)",
                 payload_len, payload ? payload[0] : -1);
        goto cleanup;
    }

    // 2. Parse components
    const uint8_t *nonce = payload + 1;
    const uint8_t *cipher = payload + 33;
    const size_t cipher_len = payload_len - 33 - 32;
    const uint8_t *mac = payload + 33 + cipher_len;

    // 3. Compute shared secret
    uint8_t shared_x[32];
    if (compute_shared_secret(our_privkey_bin, their_pubkey_bin, shared_x) != 0)
    {
        ESP_LOGE("NIP44", "Shared secret computation failed");
        goto cleanup;
    }

    // 4. Key derivation (using received nonce)
    uint8_t chacha_key[32], chacha_nonce[12], hmac_key[32];
    if (derive_key(shared_x, nonce, chacha_key, chacha_nonce, hmac_key) != 0)
    {
        ESP_LOGE("NIP44", "Key derivation failed");
        goto cleanup;
    }

    // 5. Verify HMAC
    if ((mac_input = malloc(32 + cipher_len)) == NULL)
    {
        ESP_LOGE("NIP44", "Memory allocation failed");
        goto cleanup;
    }
    memcpy(mac_input, nonce, 32);
    memcpy(mac_input + 32, cipher, cipher_len);

    uint8_t computed_mac[32];
    if (hmac_sha256(hmac_key, 32, mac_input, 32 + cipher_len, computed_mac) != 0)
    {
        ESP_LOGE("NIP44", "HMAC calculation failed");
        goto cleanup;
    }
    if (memcmp(mac, computed_mac, 32) != 0)
    {
        ESP_LOGE("NIP44", "HMAC mismatch");
        goto cleanup;
    }

    // 6. Decrypt
    uint8_t *decrypted = malloc(cipher_len);
    if (mbedtls_chacha20_setkey(&ctx, chacha_key) != 0 ||
        mbedtls_chacha20_starts(&ctx, chacha_nonce, 0) != 0 ||
        mbedtls_chacha20_update(&ctx, cipher_len, cipher, decrypted) != 0)
    {
        ESP_LOGE("NIP44", "Decryption failed");
        if (decrypted)
            free(decrypted);
        goto cleanup;
    }

    // 7. Unpad
    char *unpadded = nip44_unpad(decrypted, cipher_len);
    if (decrypted)
        free(decrypted);
    if (!unpadded)
    {
        ESP_LOGE("NIP44", "Unpadding failed");
        goto cleanup;
    }

    *decrypted_text = unpadded;
    ret = 0;

cleanup:
    mbedtls_chacha20_free(&ctx);
    if (payload)
        free(payload);
    if (mac_input)
        free(mac_input);
    return ret;
}