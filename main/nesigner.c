#include <stdio.h>
#include <string.h>
#include "driver/uart.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "mbedtls/aes.h"

#define UART_PORT_NUM UART_NUM_0 // 使用 UART0（USB-JTAG/Serial 控制器）
#define UART_BAUD_RATE 115200    // 波特率
#define TYPE_SIZE 2              // 消息类型长度（固定 2 字节）
#define ID_SIZE 16               // 消息 ID 长度（固定 16 字节）
#define HEADER_SIZE 4            // 消息头长度（固定 4 字节）
#define MAX_MESSAGE_SIZE 1024    // 最大消息长度
#define READ_TIMEOUT_MS 1000     // 读取超时时间（毫秒）
#define TASK_STACK_SIZE 4096     // Task 栈大小
#define QUEUE_SIZE 10            // 消息队列大小

static const char *TAG = "NESIGNER";

// 消息结构：
// | 2字节类型 | 16字节ID | 4字节长度头 | N字节加密数据 | 2字节CRC |

// AES配置
#define AES_KEY_SIZE 128
static const uint8_t aes_key[] = "0123456789ABCDEF"; // 16字节密钥

// 使用消息ID作为IV（必须保证是16字节）
static void setup_iv(const char *message_id, uint8_t *iv)
{
    memcpy(iv, message_id, ID_SIZE);
    // 如果ID_SIZE < 16需要填充，但这里ID_SIZE已经是16
}

// CRC16-CCITT配置
uint16_t crc16(const uint8_t *data, size_t len)
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

// AES加密（使用消息ID作为IV）
void aes_encrypt(const uint8_t *input, uint8_t *output, size_t len, const char *message_id)
{
    mbedtls_aes_context aes;
    uint8_t iv[16];
    setup_iv(message_id, iv);

    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, aes_key, AES_KEY_SIZE);

    size_t nc_off = 0;
    uint8_t stream_block[16];
    mbedtls_aes_crypt_ctr(&aes, len, &nc_off, iv, stream_block, input, output);
    mbedtls_aes_free(&aes);
}

// AES解密（使用消息ID作为IV）
void aes_decrypt(const uint8_t *input, uint8_t *output, size_t len, const char *message_id)
{
    aes_encrypt(input, output, len, message_id); // CTR模式解密相同
}

// 消息结构体
typedef struct
{
    int message_type;
    char message_id[ID_SIZE + 1];
    uint8_t *message;
    int message_len;
} message_t;

// 消息队列句柄
QueueHandle_t message_queue;

// 检查是否超时
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
            // ESP_LOGE(TAG, "Read timeout, expected %d bytes, received %d bytes", length, received);
            return false; // 读取超时
        }
    }

    return true; // 成功读取
}

// 发送响应消息
void send_response(int message_type, const char *message_id, const uint8_t *message, int message_len)
{
    // 加密数据
    uint8_t *encrypted = malloc(message_len);
    aes_encrypt(message, encrypted, message_len, message_id);

    // 计算CRC
    uint16_t crc = crc16(encrypted, message_len);
    uint8_t crc_bytes[] = {crc >> 8, crc & 0xFF};

    // 构造消息头（加密数据+CRC的总长度）
    uint32_t total_len = message_len + 2; // 加密数据长度 + CRC长度
    uint8_t header[HEADER_SIZE];
    header[0] = (total_len >> 24) & 0xFF;
    header[1] = (total_len >> 16) & 0xFF;
    header[2] = (total_len >> 8) & 0xFF;
    header[3] = total_len & 0xFF;

    // 发送各字段
    uart_write_bytes(UART_PORT_NUM, (char *)&message_type, TYPE_SIZE);
    uart_write_bytes(UART_PORT_NUM, message_id, ID_SIZE);
    uart_write_bytes(UART_PORT_NUM, (char *)header, HEADER_SIZE);
    uart_write_bytes(UART_PORT_NUM, (char *)encrypted, message_len);
    uart_write_bytes(UART_PORT_NUM, (char *)crc_bytes, 2);

    free(encrypted);
    ESP_LOGI(TAG, "Sent response, ID: %s", message_id);
}

// 处理消息的 Task
void handle_message_task(void *pvParameters)
{
    while (1)
    {
        message_t msg;
        if (xQueueReceive(message_queue, &msg, portMAX_DELAY))
        {
            // 处理逻辑保持不变...
            send_response(msg.message_type, msg.message_id, msg.message, msg.message_len);
            free(msg.message);
        }
    }
}

void app_main(void)
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

    uint8_t *type = (uint8_t *)malloc(TYPE_SIZE);           // 用于存储消息类型
    uint8_t *id = (uint8_t *)malloc(ID_SIZE);               // 用于存储消息 ID
    uint8_t *header = (uint8_t *)malloc(HEADER_SIZE);       // 用于存储消息头
    uint8_t *message = (uint8_t *)malloc(MAX_MESSAGE_SIZE); // 用于存储消息体

    while (1)
    {
        // 读取消息类型
        if (!read_fixed_length_data(type, TYPE_SIZE, READ_TIMEOUT_MS))
            continue;

        // 解析消息类型
        char type_str[TYPE_SIZE + 1];
        memcpy(type_str, type, TYPE_SIZE);
        type_str[TYPE_SIZE] = '\0';        // 添加字符串结束符
        int message_type = atoi(type_str); // 将消息类型转换为整数

        // 读取16字节消息ID
        if (!read_fixed_length_data(id, ID_SIZE, READ_TIMEOUT_MS))
            continue;
        char id_str[ID_SIZE + 1];
        memcpy(id_str, id, ID_SIZE);
        id_str[ID_SIZE] = '\0';

        // 读取消息头
        if (!read_fixed_length_data(header, HEADER_SIZE, READ_TIMEOUT_MS))
            continue;

        // 解析消息头，获取消息长度
        uint32_t total_len = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];

        // 读取加密数据+CRC
        uint8_t *encrypted_with_crc = malloc(total_len);
        if (!read_fixed_length_data(encrypted_with_crc, total_len, READ_TIMEOUT_MS))
        {
            free(encrypted_with_crc);
            continue;
        }

        // 验证CRC
        uint16_t received_crc = (encrypted_with_crc[total_len - 2] << 8) | encrypted_with_crc[total_len - 1];
        if (crc16(encrypted_with_crc, total_len - 2) != received_crc)
        {
            ESP_LOGE(TAG, "CRC Error ID: %s", id_str);
            free(encrypted_with_crc);
            continue;
        }

        // 解密数据（使用消息ID作为IV）
        uint8_t *decrypted = malloc(total_len - 2);
        aes_decrypt(encrypted_with_crc, decrypted, total_len - 2, id_str);

        // 构造消息
        message_t msg = {
            .message_type = message_type,
            .message_len = total_len - 2};
        strncpy(msg.message_id, id_str, ID_SIZE + 1);
        msg.message = decrypted;

        if (xQueueSend(message_queue, &msg, 0) != pdTRUE)
        {
            free(decrypted);
        }
        free(encrypted_with_crc);
    }

    free(type);
    free(id);
    free(header);
    free(message);
}