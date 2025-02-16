#include <stdio.h>
#include <string.h>
#include "driver/uart.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_timer.h"

#define UART_PORT_NUM UART_NUM_0 // 使用 UART0（USB-JTAG/Serial 控制器）
#define UART_BAUD_RATE 115200    // 波特率
#define TYPE_SIZE 2              // 消息类型长度（固定 2 字节）
#define HEADER_SIZE 5            // 消息头长度（固定 5 字节）
#define MAX_MESSAGE_SIZE 1024    // 最大消息长度
#define READ_TIMEOUT_MS 1000     // 读取超时时间（毫秒）

static const char *TAG = "UART_ECHO";

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
            ESP_LOGE(TAG, "Read timeout, expected %d bytes, received %d bytes", length, received);
            return false; // 读取超时
        }
    }

    return true; // 成功读取
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

    // 注意：UART0 的引脚是固定的（GPIO20 和 GPIO21），不需要手动设置引脚
    ESP_LOGI(TAG, "UART echo example started");

    uint8_t *type = (uint8_t *)malloc(TYPE_SIZE);           // 用于存储消息类型
    uint8_t *header = (uint8_t *)malloc(HEADER_SIZE);       // 用于存储消息头
    uint8_t *message = (uint8_t *)malloc(MAX_MESSAGE_SIZE); // 用于存储消息体

    while (1)
    {
        // 第一步：读取消息类型（固定 2 字节）
        if (!read_fixed_length_data(type, TYPE_SIZE, READ_TIMEOUT_MS))
        {
            ESP_LOGE(TAG, "Failed to read message type");
            continue; // 跳过不完整的消息类型
        }

        // 解析消息类型
        char type_str[TYPE_SIZE + 1];
        memcpy(type_str, type, TYPE_SIZE);
        type_str[TYPE_SIZE] = '\0';        // 添加字符串结束符
        int message_type = atoi(type_str); // 将消息类型转换为整数

        // 第二步：读取消息头（固定 5 字节）
        if (!read_fixed_length_data(header, HEADER_SIZE, READ_TIMEOUT_MS))
        {
            ESP_LOGE(TAG, "Failed to read message header");
            continue; // 跳过不完整的消息头
        }

        // 解析消息头，获取消息长度
        char header_str[HEADER_SIZE + 1];
        memcpy(header_str, header, HEADER_SIZE);
        header_str[HEADER_SIZE] = '\0';     // 添加字符串结束符
        int message_len = atoi(header_str); // 将消息头转换为整数

        if (message_len <= 0 || message_len > MAX_MESSAGE_SIZE)
        {
            ESP_LOGE(TAG, "Invalid message length: %d", message_len);
            continue; // 跳过无效长度
        }

        // 第三步：读取消息体
        if (!read_fixed_length_data(message, message_len, READ_TIMEOUT_MS))
        {
            ESP_LOGE(TAG, "Failed to read message body");
            continue; // 跳过不完整的消息体
        }

        // 回显消息
        uart_write_bytes(UART_PORT_NUM, (const char *)message, message_len);
        ESP_LOGI(TAG, "Type: %d, Echoed: %.*s", message_type, message_len, message);
    }

    free(type);
    free(header);
    free(message);
}