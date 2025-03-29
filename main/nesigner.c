#include <stdio.h>
#include <string.h>
#include "driver/uart.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "mbedtls/aes.h"
#include "msg_type.h"
#include "nostr.h"
#include "store.h"
#include "msg_result.h"
#include "utils.h"
#include "tinyusb.h"
#include "tusb_cdc_acm.h"
#include "sdkconfig.h"

// #define UART_PORT_NUM UART_NUM_0 // 使用 UART0（USB-JTAG/Serial 控制器）
#define UART_PORT_NUM UART_NUM_2 // 使用 UART0（USB-JTAG/Serial 控制器）
#define UART_BAUD_RATE 115200    // 波特率
#define TYPE_SIZE 2              // 消息类型长度（固定 2 字节）
#define RESULT_SIZE 2            // 消息结果长度（固定 2 字节）（仅在result中有）
#define ID_SIZE 16               // 消息 ID 长度（固定 16 字节）
#define PUBKEY_SIZE 32           // 消息 PUBKEY 长度（固定 32 字节）
#define IV_SIZE 16               // IV 长度（固定 16 字节）
#define CRC_SIZE 2               // CRC长度（固定 2 字节）
#define HEADER_SIZE 4            // 消息头长度（固定 4 字节）
#define MAX_MESSAGE_SIZE 1024    // 最大消息长度
#define READ_TIMEOUT_MS 10000    // 读取超时时间（毫秒）
#define TASK_STACK_SIZE 4096     // Task 栈大小
#define QUEUE_SIZE 10            // 消息队列大小

static const char *TAG = "NESIGNER";

// Requst 消息结构：
// | 2字节类型 | 16字节ID | 32字节PUBKEY | 16字节加密 IV | 2字节CRC | 4字节长度头 | N字节加密数据 |
// Response 消息结构：
// | 2字节类型 | 16字节ID | 2字节结果 | 32字节PUBKEY | 16字节加密 IV | 2字节CRC | 4字节长度头 | N字节加密数据 |

// AES配置
#define AES_KEY_SIZE 256
// static const uint8_t aes_key[] = "0123456789ABCDEF0123456789ABCDEF"; // 32字节密钥

uint8_t temp_private_key[PRIVATE_KEY_LEN];

// 生成随机 IV 的函数
void generate_random_iv(uint8_t iv[IV_SIZE])
{
    for (int i = 0; i < IV_SIZE; i += 4)
    {
        // 生成 32 位随机数
        uint32_t random_num = esp_random();
        // 将 32 位随机数拆分成 4 个 8 位字节并存储到 IV 数组中
        iv[i] = (random_num >> 24) & 0xFF;
        iv[i + 1] = (random_num >> 16) & 0xFF;
        iv[i + 2] = (random_num >> 8) & 0xFF;
        iv[i + 3] = random_num & 0xFF;
    }
}

uint16_t crc16(uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++)
    {
        crc ^= (uint16_t)data[i] << 8;
        for (int j = 0; j < 8; j++)
        {
            crc = (crc & 0x8000) ? (crc << 1) ^ 0x1021 : (crc << 1);
        }
    }
    return crc;
}

// 消息结构体
typedef struct
{
    uint8_t itf; // Index of CDC device interface
    uint16_t message_type;
    uint8_t message_id[ID_SIZE];
    uint8_t pubkey[PUBKEY_SIZE];
    uint8_t iv[IV_SIZE];
    uint8_t *message; // encrypted message
    int message_len;
} message_t;

// 消息队列句柄
QueueHandle_t message_queue;

bool is_timeout(uint64_t start_time, uint64_t timeout_ms)
{
    uint64_t current_time = esp_timer_get_time() / 1000; // 转换为毫秒
    return (current_time - start_time) >= timeout_ms;
}

// 读取固定长度的数据
bool read_fixed_length_data(uint8_t *buffer, int length, uint64_t timeout_ms)
{
    int received = 0;
    uint64_t start_time = esp_timer_get_time() / 1000; // 记录开始时间

    while (received < length)
    {
        int len = uart_read_bytes(UART_PORT_NUM, buffer + received, length - received, 20 / portTICK_PERIOD_MS);
        if (len > 0)
        {
            received += len;
            start_time = esp_timer_get_time() / 1000; // 重置开始时间
        }

        // 检查是否超时
        if (is_timeout(start_time, timeout_ms))
        {
            return false; // 读取超时
        }
    }
    return true; // 成功读取
}

// 发送响应消息
void send_response(uint8_t itf, uint16_t message_result, uint16_t message_type, const uint8_t *message_id, const uint8_t *pubkey, const uint8_t *iv,
                   const uint8_t *message, int message_len)
{
    uint8_t type_bin[TYPE_SIZE] = {(message_type >> 8) & 0xFF,
                                   message_type & 0xFF};

    uint8_t result_bin[RESULT_SIZE] = {(message_result >> 8) & 0xFF,
                                       message_result & 0xFF};

    uint8_t header[HEADER_SIZE] = {
        (message_len >> 24) & 0xFF,
        (message_len >> 16) & 0xFF,
        (message_len >> 8) & 0xFF,
        message_len & 0xFF};

    if (itf == -1)
    {
        // send by uart
        uart_write_bytes(UART_PORT_NUM, (char *)&type_bin, TYPE_SIZE);
        uart_write_bytes(UART_PORT_NUM, (char *)message_id, ID_SIZE); // 直接发送二进制ID
        uart_write_bytes(UART_PORT_NUM, (char *)&result_bin, RESULT_SIZE);
        uart_write_bytes(UART_PORT_NUM, (char *)pubkey, PUBKEY_SIZE); // 发送hex格式
        uart_write_bytes(UART_PORT_NUM, (char *)iv, IV_SIZE);         // 直接发送二进制IV
        if (message_len > 0 && message != NULL)
        {
            uint16_t crc = crc16(message, message_len);
            uint8_t crc_bytes[] = {crc >> 8, crc & 0xFF};
            uart_write_bytes(UART_PORT_NUM, (char *)crc_bytes, CRC_SIZE);  // crc
            uart_write_bytes(UART_PORT_NUM, (char *)header, HEADER_SIZE);  // header
            uart_write_bytes(UART_PORT_NUM, (char *)message, message_len); // content
        }
        else
        {
            char empty_crc[2] = {0};
            uart_write_bytes(UART_PORT_NUM, empty_crc, CRC_SIZE);         // crc
            uart_write_bytes(UART_PORT_NUM, (char *)header, HEADER_SIZE); // header
        }
    }
    else
    {
        // send by uart
        tinyusb_cdcacm_write_queue(itf, (char *)&type_bin, TYPE_SIZE);
        tinyusb_cdcacm_write_queue(itf, (char *)message_id, ID_SIZE); // 直接发送二进制ID
        tinyusb_cdcacm_write_queue(itf, (char *)&result_bin, RESULT_SIZE);
        tinyusb_cdcacm_write_queue(itf, (char *)pubkey, PUBKEY_SIZE); // 发送hex格式
        tinyusb_cdcacm_write_queue(itf, (char *)iv, IV_SIZE);         // 直接发送二进制IV
        if (message_len > 0 && message != NULL)
        {
            uint16_t crc = crc16(message, message_len);
            uint8_t crc_bytes[] = {crc >> 8, crc & 0xFF};
            tinyusb_cdcacm_write_queue(itf, (char *)crc_bytes, CRC_SIZE);  // crc
            tinyusb_cdcacm_write_queue(itf, (char *)header, HEADER_SIZE);  // header
            tinyusb_cdcacm_write_queue(itf, (char *)message, message_len); // content
        }
        else
        {
            char empty_crc[2] = {0};
            tinyusb_cdcacm_write_queue(itf, empty_crc, CRC_SIZE);         // crc
            tinyusb_cdcacm_write_queue(itf, (char *)header, HEADER_SIZE); // header
        }
        esp_err_t err = tinyusb_cdcacm_write_flush(itf, 10000);
        if (err != ESP_OK)
        {
            ESP_LOGE(TAG, "CDC ACM write flush error: %s", esp_err_to_name(err));
        }

        // size_t buffer_size = TYPE_SIZE + ID_SIZE + RESULT_SIZE + PUBKEY_SIZE + IV_SIZE + CRC_SIZE + HEADER_SIZE + message_len;
        // uint8_t *buffer = malloc(buffer_size);

        // memcpy(buffer, type_bin, TYPE_SIZE);
        // memcpy(buffer + TYPE_SIZE, message_id, ID_SIZE);
        // memcpy(buffer + ID_SIZE, &result_bin, RESULT_SIZE);
        // memcpy(buffer + RESULT_SIZE, pubkey, PUBKEY_SIZE);
        // memcpy(buffer + PUBKEY_SIZE, iv, IV_SIZE);
        // if (message_len > 0 && message != NULL)
        // {
        //     uint16_t crc = crc16(message, message_len);
        //     uint8_t crc_bytes[] = {crc >> 8, crc & 0xFF};
        //     memcpy(buffer + IV_SIZE, crc_bytes, CRC_SIZE);
        //     memcpy(buffer + CRC_SIZE, header, HEADER_SIZE);
        //     memcpy(buffer + HEADER_SIZE, message, message_len);
        // }
        // else
        // {
        //     char empty_crc[2] = {0};
        //     memcpy(buffer + IV_SIZE, empty_crc, CRC_SIZE);
        //     memcpy(buffer + CRC_SIZE, header, HEADER_SIZE);
        // }

        // printByteArrayAsDec(buffer, buffer_size);

        // // send by usb
        // // ESP_LOGI(TAG, "buffer_size: %d CONFIG_TINYUSB_CDC_RX_BUFSIZE", buffer_size, CONFIG_TINYUSB_CDC_RX_BUFSIZE);
        // // size_t sended_size = 0;
        // // const size_t max_chunk_size = 64;
        // // while (sended_size < buffer_size)
        // // {
        // //     size_t current_send_size = sended_size + max_chunk_size > buffer_size ? buffer_size - sended_size : max_chunk_size;
        // //     size_t current_sended_size = tinyusb_cdcacm_write_queue(itf, buffer + sended_size, current_send_size);
        // //     ESP_LOGI(TAG, "itf %d current_send_size %d current_sended_size: %d sended_size %d", itf, current_send_size, current_sended_size, sended_size);
        // //     sended_size += current_sended_size;
        // // }
        // // esp_err_t err = tinyusb_cdcacm_write_flush(itf, 1000);
        // // if (err != ESP_OK)
        // // {
        // //     ESP_LOGE(TAG, "CDC ACM write flush error: %s", esp_err_to_name(err));
        // // }

        // ESP_LOGI(TAG, "buffer_size: %d CONFIG_TINYUSB_CDC_RX_BUFSIZE", buffer_size, CONFIG_TINYUSB_CDC_RX_BUFSIZE);
        // size_t sended_size = tinyusb_cdcacm_write_queue(itf, buffer, buffer_size);
        // ESP_LOGI(TAG, "USB write size: %d", sended_size);
        // esp_err_t err = tinyusb_cdcacm_write_flush(itf, 0);
        // if (err != ESP_OK)
        // {
        //     ESP_LOGE(TAG, "CDC ACM write flush error: %s", esp_err_to_name(err));
        // }
        // free(buffer);
    }
}

void send_response_with_encrypt(uint8_t itf, uint8_t *aesKey, uint16_t message_result, uint16_t message_type, const uint8_t *message_id, const uint8_t *pubkey, const uint8_t *iv,
                                const uint8_t *message, int message_len)
{
    if (message_len > 0 && aesKey != NULL)
    {
        uint8_t *encrypted = NULL;
        size_t encrypted_len;
        if (aes_encrypt_padded(aesKey, 16, iv, message, message_len, &encrypted, &encrypted_len) != 0)
        {
            ESP_LOGE(TAG, "AES encryption failed");
            return;
        }

        send_response(itf, message_result, message_type, message_id, pubkey, iv, encrypted, encrypted_len);
        free(encrypted);
    }
    else
    {
        send_response(itf, message_result, message_type, message_id, pubkey, iv, message, message_len);
    }
}

// 处理消息的 Task
void handle_uart_message_task(void *pvParameters)
{
    while (1)
    {
        message_t msg;
        if (xQueueReceive(message_queue, &msg, portMAX_DELAY))
        {
            ESP_LOGI(TAG, "msg received from queue");

            uint8_t iv[IV_SIZE];
            generate_random_iv(iv);

            printf("message_type %d\n", msg.message_type);

            if (msg.message_type == MSG_TYPE_PING)
            {
                send_response(msg.itf, MSG_RESULT_OK, msg.message_type, msg.message_id, msg.pubkey, msg.iv, msg.message, 0);
                goto cleanup;
            }
            else if (msg.message_type == MSG_TYPE_ECHO)
            {
                send_response(msg.itf, MSG_RESULT_OK, msg.message_type, msg.message_id, msg.pubkey, msg.iv, msg.message, msg.message_len);
                goto cleanup;
            }
            else if (msg.message_type == MSG_TYPE_GET_TEMP_PUBKEY)
            {
                uint8_t temp_pubkey[PUBKEY_LEN];
                if (get_public(temp_private_key, temp_pubkey) == -1)
                {
                    goto sendfail;
                }
                send_response(msg.itf, MSG_RESULT_OK, msg.message_type, msg.message_id, msg.pubkey, msg.iv, temp_pubkey, PUBKEY_LEN);
                goto cleanup;
            }
            else if (msg.message_type == MSG_TYPE_UPDATE_KEY)
            {
                if (msg.message_len < PRIVATE_KEY_LEN + AES_KEY_LEN)
                {
                    goto sendillegal;
                }

                char *decrypted_content = NULL;
                char encrypted_content[msg.message_len + 1] = {};
                memcpy(encrypted_content, msg.message, msg.message_len);
                encrypted_content[msg.message_len] = 0;
                if (nip44_decrypt(temp_private_key, msg.pubkey, encrypted_content, &decrypted_content) != 0)
                {
                    goto sendillegal;
                }

                uint8_t private_key_bin[PRIVATE_KEY_LEN];
                uint8_t aes_key_bin[AES_KEY_LEN];
                memcpy(private_key_bin, decrypted_content, PRIVATE_KEY_LEN);
                memcpy(aes_key_bin, decrypted_content + PRIVATE_KEY_LEN, AES_KEY_LEN);

                // char private_key_hex[PRIVATE_KEY_LEN * 2 + 1] = {};
                // private_key_hex[PRIVATE_KEY_LEN * 2] = 0;
                // bin_to_hex(private_key_bin, PRIVATE_KEY_LEN, private_key_hex);
                // char aes_key_hex[AES_KEY_LEN * 2 + 1] = {};
                // aes_key_hex[AES_KEY_LEN * 2] = 0;
                // bin_to_hex(aes_key_bin, AES_KEY_LEN, aes_key_hex);

                // ESP_LOGI("Test", "private_key_hex %s aes_key_hex %s", private_key_hex, aes_key_hex);

                KeyPair *keyPair = malloc(sizeof(KeyPair));
                memcpy(keyPair->aesKey, aes_key_bin, AES_KEY_LEN);
                memcpy(keyPair->privateKey, private_key_bin, PRIVATE_KEY_LEN);

                if (addAndSaveKeyPair(keyPair))
                {
                    send_response(msg.itf, MSG_RESULT_OK, msg.message_type, msg.message_id, msg.pubkey, msg.iv, NULL, 0);
                }
                else
                {
                    goto sendfail;
                }

                goto cleanup;
            }
            else if (msg.message_type == MSG_TYPE_NOSTR_GET_PUBLIC_KEY || msg.message_type == MSG_TYPE_REMOVE_KEY)
            {
                // try to use keyparis to aes decrypt message
                for (size_t i = 0; i < keypair_count; i++)
                {
                    // printf("GET PUBKEY: item %d\n", i);
                    KeyPair keypair = keypairs[i];
                    uint8_t *decrypted = NULL;
                    size_t decrypted_len;
                    if (aes_decrypt_padded(keypair.aesKey, 16, msg.iv, msg.message, msg.message_len,
                                           &decrypted, &decrypted_len) != 0)
                    {
                        ESP_LOGE("NIP04", "AES decryption failed");
                        goto sendillegal;
                    }
                    printByteArrayAsDec((char *)decrypted, decrypted_len);

                    if (memcmp(decrypted, msg.iv, IV_SIZE) == 0)
                    {
                        // If the decrypt content equal iv, find the aesKey!
                        free(decrypted);
                        printf("find key!\n");

                        // char pubkey_hex[PUBKEY_LEN * 2 + 1] = {};
                        // pubkey_hex[PUBKEY_LEN * 2] = 0;
                        // bin_to_hex(keypair.pubkey, PUBKEY_LEN, pubkey_hex);
                        // ESP_LOGI("Test", "pubkey_hex %s", pubkey_hex);

                        if (msg.message_type == MSG_TYPE_NOSTR_GET_PUBLIC_KEY)
                        {
                            send_response_with_encrypt(msg.itf, keypair.aesKey, MSG_RESULT_OK, msg.message_type, msg.message_id, keypair.pubkey, iv, keypair.pubkey, PUBKEY_LEN);
                            goto cleanup;
                        }
                        else if (msg.message_type == MSG_TYPE_REMOVE_KEY)
                        {
                            printf("begin to remove kp\n");
                            if (removeAndSaveKeyPair(keypair.aesKey))
                            {
                                printf("remove success \n");
                                send_response(msg.itf, MSG_RESULT_OK, msg.message_type, msg.message_id, msg.pubkey, iv, NULL, 0);
                                goto cleanup;
                            }
                            else
                            {
                                printf("remove fail \n");
                                goto sendfail;
                            }
                        }
                    }
                    free(decrypted);
                }

                send_response(msg.itf, MSG_RESULT_KEY_NOT_FOUND, msg.message_type, msg.message_id, msg.pubkey, msg.iv, NULL, 0);
                goto cleanup;
            }

            KeyPair *keypair;

            if (msg.message_len > 0)
            {
                keypair = findKeyPairByPubkey(msg.pubkey);
                if (keypair == NULL)
                {
                    // can't find the keypair,
                    send_response(msg.itf, MSG_RESULT_KEY_NOT_FOUND, msg.message_type, msg.message_id, msg.pubkey, msg.iv, NULL, 0);
                    goto cleanup;
                }
            }
            else
            {
                send_response(msg.itf, MSG_RESULT_CONTENT_NOT_ALLOW_EMPTY, msg.message_type, msg.message_id, msg.pubkey, msg.iv, NULL, 0);
                goto cleanup;
            }

            // 解密数据
            uint8_t *decrypted = NULL;
            size_t decrypted_len;
            if (aes_decrypt_padded(keypair->aesKey, 16, msg.iv, msg.message, msg.message_len,
                                   &decrypted, &decrypted_len) != 0)
            {
                ESP_LOGE("NIP04", "AES decryption failed");
                goto sendillegal;
            }

            if (msg.message_type == MSG_TYPE_NOSTR_SIGN_EVENT)
            {
                if (decrypted_len != NOSTR_EVENT_ID_BIN_LEN)
                {
                    goto sendillegal;
                }

                uint8_t sig_bin[NOSTR_EVENT_SIG_BIN_LEN];

                if (sign(keypair->privateKey, decrypted, sig_bin) != 0)
                {
                    free(decrypted);
                    goto sendfail;
                }

                send_response_with_encrypt(msg.itf, keypair->aesKey, MSG_RESULT_OK, msg.message_type, msg.message_id, msg.pubkey, iv, sig_bin, NOSTR_EVENT_SIG_BIN_LEN);
            }
            else if (msg.message_type == MSG_TYPE_NOSTR_NIP04_ENCRYPT || msg.message_type == MSG_TYPE_NOSTR_NIP04_DECRYPT || msg.message_type == MSG_TYPE_NOSTR_NIP44_ENCRYPT || msg.message_type == MSG_TYPE_NOSTR_NIP44_DECRYPT)
            {
                uint8_t their_pubkey_bin[PUBKEY_LEN];
                memcpy(their_pubkey_bin, decrypted, PUBKEY_LEN);

                size_t source_len = decrypted_len - PUBKEY_LEN;
                char source_text[source_len + 1] = {};
                memcpy(source_text, decrypted + PUBKEY_LEN, source_len);
                source_text[source_len] = 0;

                char *result_content = NULL;

                if (msg.message_type == MSG_TYPE_NOSTR_NIP04_ENCRYPT)
                {
                    if (nip04_encrypt(keypair->privateKey, their_pubkey_bin, source_text, &result_content) != 0)
                    {
                        free(decrypted);
                        goto sendfail;
                    }

                    send_response_with_encrypt(msg.itf, keypair->aesKey, MSG_RESULT_OK, msg.message_type, msg.message_id, msg.pubkey, iv, (uint8_t *)result_content, strlen(result_content));
                }
                else if (msg.message_type == MSG_TYPE_NOSTR_NIP04_DECRYPT)
                {
                    if (nip04_decrypt(keypair->privateKey, their_pubkey_bin, source_text, &result_content) != 0)
                    {
                        free(decrypted);
                        goto sendfail;
                    }

                    send_response_with_encrypt(msg.itf, keypair->aesKey, MSG_RESULT_OK, msg.message_type, msg.message_id, msg.pubkey, iv, (uint8_t *)result_content, strlen(result_content));
                }
                else if (msg.message_type == MSG_TYPE_NOSTR_NIP44_ENCRYPT)
                {
                    if (nip44_encrypt(keypair->privateKey, their_pubkey_bin, source_text, &result_content) != 0)
                    {
                        free(decrypted);
                        goto sendfail;
                    }

                    send_response_with_encrypt(msg.itf, keypair->aesKey, MSG_RESULT_OK, msg.message_type, msg.message_id, msg.pubkey, iv, (uint8_t *)result_content, strlen(result_content));
                }
                else if (msg.message_type == MSG_TYPE_NOSTR_NIP44_DECRYPT)
                {
                    char *result_content = NULL;
                    if (nip44_decrypt(keypair->privateKey, their_pubkey_bin, source_text, &result_content) != 0)
                    {
                        free(decrypted);
                        goto sendfail;
                    }

                    send_response_with_encrypt(msg.itf, keypair->aesKey, MSG_RESULT_OK, msg.message_type, msg.message_id, msg.pubkey, iv, (uint8_t *)result_content, strlen(result_content));
                }
            }

            free(decrypted);
            goto cleanup;

        sendillegal:
            send_response(msg.itf, MSG_RESULT_CONTENT_ILLEGAL, msg.message_type, msg.message_id, msg.pubkey, msg.iv, NULL, 0);
            goto cleanup;
        sendfail:
            send_response(msg.itf, MSG_RESULT_FAIL, msg.message_type, msg.message_id, msg.pubkey, msg.iv, NULL, 0);
            goto cleanup;
        cleanup:
            free(msg.message);
        }
    }
}

void uart_config()
{
    // 配置 UART
    uart_config_t uart_config = {
        .baud_rate = UART_BAUD_RATE,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    // 安装 UART 驱动程序
    ESP_ERROR_CHECK(uart_set_pin(UART_PORT_NUM, GPIO_NUM_4, GPIO_NUM_5, -1, -1));
    ESP_ERROR_CHECK(uart_driver_install(UART_PORT_NUM, MAX_MESSAGE_SIZE * 2, 0, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(UART_PORT_NUM, &uart_config));
}

void uart_data_receive()
{
    uint8_t type[TYPE_SIZE];     // 用于存储消息类型
    uint8_t id[ID_SIZE];         // 用于存储消息 ID
    uint8_t pubkey[PUBKEY_SIZE]; // 用于Pubkey
    uint8_t iv[IV_SIZE];         // 用于 IV
    uint8_t crc[CRC_SIZE];       // 用于 CRC
    uint8_t header[HEADER_SIZE]; // 用于存储消息头

    while (1)
    {
        // 读取消息类型
        if (!read_fixed_length_data(type, TYPE_SIZE, READ_TIMEOUT_MS))
            continue;

        // 解析消息类型
        uint16_t message_type = (type[0] << 8) | type[1];
        ESP_LOGI(TAG, "message_type %d %d %d", message_type, type[0], type[1]);

        // 直接读取二进制ID
        if (!read_fixed_length_data(id, ID_SIZE, READ_TIMEOUT_MS))
            continue;

        printByteArrayAsDec((char *)id, ID_SIZE);

        // 读取二进制pubkey
        if (!read_fixed_length_data(pubkey, PUBKEY_SIZE, READ_TIMEOUT_MS))
            continue;

        printByteArrayAsDec((char *)pubkey, PUBKEY_SIZE);

        // 读取二进制iv
        if (!read_fixed_length_data(iv, IV_SIZE, READ_TIMEOUT_MS))
            continue;

        printByteArrayAsDec((char *)iv, IV_SIZE);

        // 读取二进制crc
        if (!read_fixed_length_data(crc, CRC_SIZE, READ_TIMEOUT_MS))
            continue;

        printByteArrayAsDec((char *)crc, CRC_SIZE);

        // 读取消息头
        if (!read_fixed_length_data(header, HEADER_SIZE, READ_TIMEOUT_MS))
            continue;

        printByteArrayAsDec((char *)header, HEADER_SIZE);

        // 解析消息头，获取消息长度
        uint32_t total_len = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];
        ESP_LOGI(TAG, "total_len %d %d %d %d %d", (int)total_len, header[0], header[1], header[2], header[3]);

        // 读取加密数据
        uint8_t *encrypted = malloc(total_len);
        if (!read_fixed_length_data(encrypted, total_len, READ_TIMEOUT_MS))
        {
            free(encrypted);
            continue;
        }

        // 验证CRC
        uint16_t received_crc = (crc[0] << 8) | crc[1];
        if (crc16(encrypted, total_len) != received_crc)
        {
            char id_hex[ID_SIZE * 2 + 1];
            bin_to_hex(id, ID_SIZE, id_hex);
            ESP_LOGE(TAG, "CRC Error ID: %s", id_hex);
            free(encrypted);
            continue;
        }

        // 构造消息
        message_t msg = {
            .itf = -1,
            .message_type = message_type,
            .message_len = total_len};
        memcpy(msg.message_id, id, ID_SIZE);
        memcpy(msg.pubkey, pubkey, PUBKEY_SIZE);
        memcpy(msg.iv, iv, IV_SIZE);
        msg.message = malloc(total_len);
        memcpy(msg.message, encrypted, total_len);
        xQueueSend(message_queue, &msg, 0);
        free(encrypted);

        ESP_LOGI(TAG, "msg sended to queue");
    }
}

/**
 * @brief USB Message Queue
 */
static QueueHandle_t usb_msg_queue;
typedef struct
{
    uint8_t buf[CONFIG_TINYUSB_CDC_RX_BUFSIZE + 1]; // Data buffer
    size_t buf_len;                                 // Number of bytes received
    uint8_t itf;                                    // Index of CDC device interface
} usb_message_t;

// 自定义 USB 配置
#define USB_VID 0x2323 // 自定义厂商ID
#define USB_PID 0x3434 // 自定义产品ID

// USB 设备描述符
static tusb_desc_device_t descriptor_dev = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,
    .bDeviceClass = TUSB_CLASS_VENDOR_SPECIFIC,
    .bDeviceSubClass = 0x00,
    .bDeviceProtocol = 0x00,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor = USB_VID,
    .idProduct = USB_PID,
    .bcdDevice = 0x0100,
    .iManufacturer = 0x01,
    .iProduct = 0x02,
    .iSerialNumber = 0x03,
    .bNumConfigurations = 0x01};

static uint8_t usb_msg_buffer[CONFIG_TINYUSB_CDC_RX_BUFSIZE * 8];

static size_t usb_msg_buffer_size = 0;

static uint8_t rx_buf[CONFIG_TINYUSB_CDC_RX_BUFSIZE * 4];

/**
 * @brief CDC device RX callback
 *
 * CDC device signals, that new data were received
 *
 * @param[in] itf   CDC device index
 * @param[in] event CDC event type
 */
void tinyusb_cdc_rx_callback(int itf, cdcacm_event_t *event)
{
    /* initialization */
    size_t rx_size = 0;

    /* read */
    esp_err_t ret = tinyusb_cdcacm_read(itf, rx_buf, CONFIG_TINYUSB_CDC_RX_BUFSIZE, &rx_size);
    if (ret == ESP_OK)
    {
        // /* Print received data*/
        // ESP_LOGI(TAG, "Data from channel %d:", itf);
        // ESP_LOG_BUFFER_HEXDUMP(TAG, rx_buf, rx_size, ESP_LOG_INFO);

        // /* write back */
        // tinyusb_cdcacm_write_queue(itf, rx_buf, rx_size);
        // esp_err_t err = tinyusb_cdcacm_write_flush(itf, 0);
        // if (err != ESP_OK)
        // {
        //     ESP_LOGE(TAG, "CDC ACM write flush error: %s", esp_err_to_name(err));
        // }

        memcpy(usb_msg_buffer + usb_msg_buffer_size, rx_buf, rx_size);
        usb_msg_buffer_size += rx_size;

        ESP_LOGI(TAG, "message size %d %d", usb_msg_buffer_size, (TYPE_SIZE + ID_SIZE + PUBKEY_SIZE + IV_SIZE + CRC_SIZE + HEADER_SIZE));
        if (usb_msg_buffer_size < (TYPE_SIZE + ID_SIZE + PUBKEY_SIZE + IV_SIZE + CRC_SIZE + HEADER_SIZE))
        {
            return;
        }

        size_t offset = 0;

        uint8_t type[TYPE_SIZE];
        memcpy(type, usb_msg_buffer + offset, TYPE_SIZE);
        offset += TYPE_SIZE;

        uint8_t id[ID_SIZE];
        memcpy(id, usb_msg_buffer + offset, ID_SIZE);
        offset += ID_SIZE;

        uint8_t pubkey[PUBKEY_SIZE];
        memcpy(pubkey, usb_msg_buffer + offset, PUBKEY_SIZE);
        offset += PUBKEY_SIZE;

        uint8_t iv[IV_SIZE];
        memcpy(iv, usb_msg_buffer + offset, IV_SIZE);
        offset += IV_SIZE;

        uint8_t crc[CRC_SIZE];
        memcpy(crc, usb_msg_buffer + offset, CRC_SIZE);
        offset += CRC_SIZE;

        uint8_t header[HEADER_SIZE];
        memcpy(header, usb_msg_buffer + offset, HEADER_SIZE);
        offset += HEADER_SIZE;

        // 解析数据长度
        uint32_t data_len = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];

        ESP_LOGI(TAG, "data_len %d", data_len);

        // 检查是否有足够的数据读取加密内容
        if (usb_msg_buffer_size < offset + data_len)
            return; // 数据不足，等待更多

        uint8_t *encrypted = malloc(data_len);
        if (!encrypted)
        {
            ESP_LOGE(TAG, "Failed to allocate memory for encrypted data");
            return;
        }
        memcpy(encrypted, usb_msg_buffer + offset, data_len);
        offset += data_len;

        // copy remain data to buffer
        usb_msg_buffer_size -= offset; // remain data size
        memcpy(usb_msg_buffer, usb_msg_buffer + offset, usb_msg_buffer_size);

        // 验证CRC
        uint16_t received_crc = (crc[0] << 8) | crc[1];
        if (crc16(encrypted, data_len) != received_crc)
        {
            ESP_LOGE(TAG, "CRC check failed");
            free(encrypted);
            return;
        }

        // 构造消息
        message_t message = {
            .itf = itf,
            .message_type = (type[0] << 8) | type[1],
            .message_len = data_len};
        memcpy(message.message_id, id, ID_SIZE);
        memcpy(message.pubkey, pubkey, PUBKEY_SIZE);
        memcpy(message.iv, iv, IV_SIZE);
        message.message = malloc(data_len);
        if (message.message)
        {
            memcpy(message.message, encrypted, data_len);
            // 发送到队列
            if (xQueueSend(message_queue, &message, pdMS_TO_TICKS(100)) != pdPASS)
            {
                ESP_LOGE(TAG, "Failed to send message to queue");
                free(message.message);
            }
        }
        else
        {
            ESP_LOGE(TAG, "Failed to allocate message buffer");
        }

        free(encrypted);
    }
    else
    {
        ESP_LOGE(TAG, "Read Error");
    }
}

/**
 * @brief CDC device line change callback
 *
 * CDC device signals, that the DTR, RTS states changed
 *
 * @param[in] itf   CDC device index
 * @param[in] event CDC event type
 */
void tinyusb_cdc_line_state_changed_callback(int itf, cdcacm_event_t *event)
{
    int dtr = event->line_state_changed_data.dtr;
    int rts = event->line_state_changed_data.rts;
    ESP_LOGI(TAG, "Line state changed on channel %d: DTR:%d, RTS:%d", itf, dtr, rts);
}

void usb_config()
{
    char *string_descriptor = "nesigner";
    const char *str_ptr = string_descriptor;

    const tinyusb_config_t tusb_cfg = {
        .device_descriptor = &descriptor_dev,
        .string_descriptor = &str_ptr,
        .external_phy = false,
#if (TUD_OPT_HIGH_SPEED)
        .fs_configuration_descriptor = NULL,
        .hs_configuration_descriptor = NULL,
        .qualifier_descriptor = NULL,
#else
        .configuration_descriptor = NULL,
#endif // TUD_OPT_HIGH_SPEED
    };

    ESP_ERROR_CHECK(tinyusb_driver_install(&tusb_cfg));

    tinyusb_config_cdcacm_t acm_cfg = {
        .usb_dev = TINYUSB_USBDEV_0,
        .cdc_port = TINYUSB_CDC_ACM_0,
        .rx_unread_buf_sz = 64,
        .callback_rx = &tinyusb_cdc_rx_callback, // the first way to register a callback
        .callback_rx_wanted_char = NULL,
        .callback_line_state_changed = NULL,
        .callback_line_coding_changed = NULL};

    ESP_ERROR_CHECK(tusb_cdc_acm_init(&acm_cfg));
    /* the second way to register a callback */
    ESP_ERROR_CHECK(tinyusb_cdcacm_register_callback(
        TINYUSB_CDC_ACM_0,
        CDC_EVENT_LINE_STATE_CHANGED,
        &tinyusb_cdc_line_state_changed_callback));

#if (CONFIG_TINYUSB_CDC_COUNT > 1)
    acm_cfg.cdc_port = TINYUSB_CDC_ACM_1;
    ESP_ERROR_CHECK(tusb_cdc_acm_init(&acm_cfg));
    ESP_ERROR_CHECK(tinyusb_cdcacm_register_callback(
        TINYUSB_CDC_ACM_1,
        CDC_EVENT_LINE_STATE_CHANGED,
        &tinyusb_cdc_line_state_changed_callback));
#endif

    ESP_LOGI(TAG, "USB initialization DONE");
}

void app_main(void)
{
    // 关闭所有日志输出
    // esp_log_level_set("*", ESP_LOG_NONE);

    if (gen_private_key(temp_private_key) == -1)
    {
        ESP_LOGI("Test", "gen temp private key fail");
        return;
    }

    initStorage();

    // 创建消息队列
    message_queue = xQueueCreate(QUEUE_SIZE, sizeof(message_t));
    if (message_queue == NULL)
    {
        ESP_LOGE(TAG, "Failed to create message queue");
        return;
    }

    uart_config();

    usb_config();

    // 创建处理消息的 Task
    xTaskCreate(handle_uart_message_task, "handle_uart_message_task", TASK_STACK_SIZE, NULL, 5, NULL);

    // 注意：UART0 的引脚是固定的（GPIO20 和 GPIO21），不需要手动设置引脚
    ESP_LOGI(TAG, "nesigner started");

    uart_data_receive();
}