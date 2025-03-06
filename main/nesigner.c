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

// 修改为直接使用二进制IV
void aes_encrypt(uint8_t *aesKey, uint8_t *input, uint8_t *output, size_t len, uint8_t *iv)
{
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, aesKey, AES_KEY_SIZE);

    size_t nc_off = 0;
    uint8_t stream_block[16];
    uint8_t local_iv[16];
    memcpy(local_iv, iv, 16); // 复制IV以防止修改原始数据

    mbedtls_aes_crypt_ctr(&aes, len, &nc_off, local_iv, stream_block, input, output);
    mbedtls_aes_free(&aes);
}

// AES解密
void aes_decrypt(uint8_t *aesKey, const uint8_t *input, uint8_t *output, size_t len, const uint8_t *iv)
{
    aes_encrypt(aesKey, input, output, len, iv); // CTR模式解密相同
}

// 消息结构体
typedef struct
{
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
void send_response(uint16_t message_result, uint16_t message_type, const uint8_t *message_id, const uint8_t *pubkey, const uint8_t *iv,
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

    uart_write_bytes(UART_PORT_NUM, (char *)&type_bin, TYPE_SIZE);
    uart_write_bytes(UART_PORT_NUM, (char *)message_id, ID_SIZE); // 直接发送二进制ID
    uart_write_bytes(UART_PORT_NUM, (char *)&result_bin, RESULT_SIZE);
    uart_write_bytes(UART_PORT_NUM, (char *)pubkey, PUBKEY_SIZE); // 发送hex格式
    uart_write_bytes(UART_PORT_NUM, (char *)iv, IV_SIZE);         // 直接发送二进制IV
    if (message_len > 0 && message != NULL)
    {
        uint16_t crc = crc16(message, message_len);
        uint8_t crc_bytes[] = {crc >> 8, crc & 0xFF};
        uart_write_bytes(UART_PORT_NUM, (char *)crc_bytes, 2);         // crc
        uart_write_bytes(UART_PORT_NUM, (char *)header, HEADER_SIZE);  // header
        uart_write_bytes(UART_PORT_NUM, (char *)message, message_len); // content
    }
    else
    {
        uart_write_bytes(UART_PORT_NUM, (char *){0, 0}, 2);           // crc
        uart_write_bytes(UART_PORT_NUM, (char *)header, HEADER_SIZE); // header
    }
}

void send_response_with_encrypt(uint8_t *aesKey, uint16_t message_result, uint16_t message_type, const uint8_t *message_id, const uint8_t *pubkey, const uint8_t *iv,
                                const uint8_t *message, int message_len)
{
    if (message_len > 0 && aesKey != NULL)
    {
        uint8_t *encrypted = malloc(message_len);
        aes_encrypt(aesKey, message, encrypted, message_len, iv);
        send_response(message_result, message_type, message_id, pubkey, iv, encrypted, message_len);
        free(encrypted);
    }
    else
    {
        send_response(message_result, message_type, message_id, pubkey, iv, message, message_len);
    }
}

// 处理消息的 Task
void handle_message_task(void *pvParameters)
{
    while (1)
    {
        message_t msg;
        if (xQueueReceive(message_queue, &msg, portMAX_DELAY))
        {

            uint8_t iv[IV_SIZE];
            generate_random_iv(iv);

            if (msg.message_type == MSG_TYPE_PING)
            {
                send_response(MSG_RESULT_OK, msg.message_type, msg.message_id, msg.pubkey, msg.iv, msg.message, 0);
                goto cleanup;
            }
            else if (msg.message_type == MSG_TYPE_ECHO)
            {
                send_response(MSG_RESULT_OK, msg.message_type, msg.message_id, msg.pubkey, msg.iv, msg.message, msg.message_len);
                goto cleanup;
            }
            else if (msg.message_type == MSG_TYPE_UPDATE_KEY)
            {
                goto cleanup;
            }
            else if (msg.message_type == MSG_TYPE_NOSTR_GET_PUBLIC_KEY)
            {
                // try to use keyparis to aes decrypt message
                for (size_t i = 0; i < keypair_count; i++)
                {
                    KeyPair keypair = keypairs[i];
                    uint8_t *decrypted = malloc(msg.message_len);
                    aes_decrypt(keypair.aesKey, msg.message, decrypted, msg.message_len, msg.iv);

                    if (memcmp(decrypted, msg.iv, IV_SIZE) == 0)
                    {
                        // If the decrypt content equal iv, find the aesKey!
                        char pubkey_hex[64] = {0};
                        bin_to_hex(keypair.pubkey, PUBKEY_LEN, pubkey_hex);

                        send_response_with_encrypt(keypair.aesKey, MSG_RESULT_OK, msg.message_type, msg.message_id, keypair.pubkey, iv, (const uint8_t *)pubkey_hex, 64);

                        free(pubkey_hex);
                        goto cleanup;
                    }
                }
            }

            KeyPair *keypair;

            if (msg.message_len > 0)
            {
                keypair = findKeyPairByPubkey(msg.pubkey);
                if (keypair == NULL)
                {
                    // TODO can't find the keypair,
                    send_response(MSG_RESULT_KEY_NOT_FOUND, msg.message_type, msg.message_id, msg.pubkey, msg.iv, NULL, 0);
                    goto cleanup;
                }
            }
            else
            {
                send_response(MSG_RESULT_CONTENT_NOT_ALLOW_EMPTY, msg.message_type, msg.message_id, msg.pubkey, msg.iv, NULL, 0);
                goto cleanup;
            }

            // 解密数据
            uint8_t *decrypted = malloc(msg.message_len);
            aes_decrypt(keypair->aesKey, msg.message, decrypted, msg.message_len, msg.iv); // 直接使用二进制ID作为IV

            switch (msg.message_type)
            {
            case MSG_TYPE_REMOVE_KEY:
                break;

            case MSG_TYPE_NOSTR_SIGN_EVENT:
                break;
            case MSG_TYPE_NOSTR_NIP04_ENCRYPT:
                break;
            case MSG_TYPE_NOSTR_NIP04_DECRYPT:
                break;
            case MSG_TYPE_NOSTR_NIP44_ENCRYPT:
                break;
            case MSG_TYPE_NOSTR_NIP44_DECRYPT:
                break;

            default:
                break;
            }

            free(decrypted);

        cleanup:
            free(msg.message);
        }
    }
}

// 以十进制形式打印字节数组
// void printByteArrayAsDec(const char *arr, size_t len)
// {
//     for (size_t i = 0; i < len; i++)
//     {
//         printf("%u ", arr[i]);
//         if ((i + 1) % 10 == 0)
//         {
//             printf("\n");
//         }
//     }
//     printf("\n");
// }

void app_main(void)
{
    // 关闭所有日志输出
    // esp_log_level_set("*", ESP_LOG_NONE);

    initStorage();

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

    // 创建消息队列
    message_queue = xQueueCreate(QUEUE_SIZE, sizeof(message_t));
    if (message_queue == NULL)
    {
        ESP_LOGE(TAG, "Failed to create message queue");
        return;
    }

    // 创建处理消息的 Task
    xTaskCreate(handle_message_task, "handle_message_task", TASK_STACK_SIZE, NULL, 5, NULL);

    // 注意：UART0 的引脚是固定的（GPIO20 和 GPIO21），不需要手动设置引脚
    ESP_LOGI(TAG, "nesigner UART started");

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
        ESP_LOGI(TAG, "message_type %d %d", type[0], type[1]);

        // 直接读取二进制ID
        if (!read_fixed_length_data(id, ID_SIZE, READ_TIMEOUT_MS))
            continue;

        // printByteArrayAsDec((char *)id, ID_SIZE);

        // 读取二进制pubkey
        if (!read_fixed_length_data(pubkey, PUBKEY_SIZE, READ_TIMEOUT_MS))
            continue;

        // printByteArrayAsDec((char *)pubkey, PUBKEY_SIZE);

        // 读取二进制iv
        if (!read_fixed_length_data(iv, IV_SIZE, READ_TIMEOUT_MS))
            continue;

        // 读取二进制crc
        if (!read_fixed_length_data(crc, CRC_SIZE, READ_TIMEOUT_MS))
            continue;

        // 读取消息头
        if (!read_fixed_length_data(header, HEADER_SIZE, READ_TIMEOUT_MS))
            continue;

        // printByteArrayAsDec((char *)header, HEADER_SIZE);

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
            .message_type = message_type,
            .message_len = total_len};
        memcpy(msg.message_id, id, ID_SIZE);
        memcpy(msg.pubkey, pubkey, PUBKEY_SIZE);
        memcpy(msg.iv, iv, IV_SIZE);
        msg.message = encrypted;

        if (xQueueSend(message_queue, &msg, 0) != pdTRUE)
        {
        }
        free(encrypted);
    }

    free(type);
    free(id);
    free(pubkey);
    free(header);
}