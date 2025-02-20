#include <stdio.h>
#include <string.h>
#include "driver/uart.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

#define UART_PORT_NUM UART_NUM_0 // 使用 UART0（USB-JTAG/Serial 控制器）
#define UART_BAUD_RATE 115200    // 波特率
#define TYPE_SIZE 2              // 消息类型长度（固定 2 字节）
#define ID_SIZE 8                // 消息 ID 长度（固定 8 字节）
#define HEADER_SIZE 5            // 消息头长度（固定 5 字节）
#define MAX_MESSAGE_SIZE 1024    // 最大消息长度
#define READ_TIMEOUT_MS 1000     // 读取超时时间（毫秒）
#define TASK_STACK_SIZE 4096     // Task 栈大小
#define QUEUE_SIZE 10            // 消息队列大小

static const char *TAG = "UART_ECHO";

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
    char header[HEADER_SIZE + 1];
    snprintf(header, HEADER_SIZE + 1, "%05d", message_len); // 生成 5 字节长度头

    // 发送消息类型
    uart_write_bytes(UART_PORT_NUM, (const char *)&message_type, TYPE_SIZE);

    // 发送消息 ID
    uart_write_bytes(UART_PORT_NUM, message_id, ID_SIZE);

    // 发送消息头
    uart_write_bytes(UART_PORT_NUM, header, HEADER_SIZE);

    // 发送消息体
    uart_write_bytes(UART_PORT_NUM, (const char *)message, message_len);

    ESP_LOGI(TAG, "Sent response, Type: %d, ID: %s, Length: %d", message_type, message_id, message_len);
}

// 处理消息的 Task
void handle_message_task(void *pvParameters)
{
    while (1)
    {
        message_t msg;
        if (xQueueReceive(message_queue, &msg, portMAX_DELAY) == pdTRUE)
        {
            // 根据消息类型调用不同的处理逻辑
            switch (msg.message_type)
            {
            case 1:
                ESP_LOGI(TAG, "Handling Type 1 message, ID: %s, Content: %.*s", msg.message_id, msg.message_len, msg.message);
                vTaskDelay(1000 / portTICK_PERIOD_MS); // 模拟耗时操作
                break;
            case 2:
                ESP_LOGI(TAG, "Handling Type 2 message, ID: %s, Content: %.*s", msg.message_id, msg.message_len, msg.message);
                vTaskDelay(2000 / portTICK_PERIOD_MS); // 模拟耗时操作
                break;
            default:
                ESP_LOGE(TAG, "Unknown message type: %d", msg.message_type);
                break;
            }

            // 发送响应消息
            send_response(msg.message_type, msg.message_id, msg.message, msg.message_len);

            // 释放消息内存
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
    ESP_LOGI(TAG, "UART echo example started");

    uint8_t *type = (uint8_t *)malloc(TYPE_SIZE);           // 用于存储消息类型
    uint8_t *id = (uint8_t *)malloc(ID_SIZE);               // 用于存储消息 ID
    uint8_t *header = (uint8_t *)malloc(HEADER_SIZE);       // 用于存储消息头
    uint8_t *message = (uint8_t *)malloc(MAX_MESSAGE_SIZE); // 用于存储消息体

    while (1)
    {
        // 第一步：读取消息类型（固定 2 字节）
        if (!read_fixed_length_data(type, TYPE_SIZE, READ_TIMEOUT_MS))
        {
            // ESP_LOGE(TAG, "Failed to read message type");
            continue; // 跳过不完整的消息类型
        }

        // 解析消息类型
        char type_str[TYPE_SIZE + 1];
        memcpy(type_str, type, TYPE_SIZE);
        type_str[TYPE_SIZE] = '\0';        // 添加字符串结束符
        int message_type = atoi(type_str); // 将消息类型转换为整数

        // 第二步：读取消息 ID（固定 8 字节）
        if (!read_fixed_length_data(id, ID_SIZE, READ_TIMEOUT_MS))
        {
            // ESP_LOGE(TAG, "Failed to read message ID");
            continue; // 跳过不完整的消息 ID
        }

        // 解析消息 ID
        char id_str[ID_SIZE + 1];
        memcpy(id_str, id, ID_SIZE);
        id_str[ID_SIZE] = '\0'; // 添加字符串结束符

        // 第三步：读取消息头（固定 5 字节）
        if (!read_fixed_length_data(header, HEADER_SIZE, READ_TIMEOUT_MS))
        {
            // ESP_LOGE(TAG, "Failed to read message header");
            continue; // 跳过不完整的消息头
        }

        // 解析消息头，获取消息长度
        char header_str[HEADER_SIZE + 1];
        memcpy(header_str, header, HEADER_SIZE);
        header_str[HEADER_SIZE] = '\0';     // 添加字符串结束符
        int message_len = atoi(header_str); // 将消息头转换为整数

        if (message_len <= 0 || message_len > MAX_MESSAGE_SIZE)
        {
            // ESP_LOGE(TAG, "Invalid message length: %d", message_len);
            continue; // 跳过无效长度
        }

        // 第四步：读取消息体
        if (!read_fixed_length_data(message, message_len, READ_TIMEOUT_MS))
        {
            // ESP_LOGE(TAG, "Failed to read message body");
            continue; // 跳过不完整的消息体
        }

        // 将消息放入队列
        message_t msg;
        msg.message_type = message_type;
        strncpy(msg.message_id, id_str, ID_SIZE + 1);
        msg.message = (uint8_t *)malloc(message_len);
        memcpy(msg.message, message, message_len);
        msg.message_len = message_len;

        if (xQueueSend(message_queue, &msg, 0) != pdTRUE)
        {
            ESP_LOGE(TAG, "Failed to send message to queue");
            free(msg.message); // 释放内存
        }
    }

    free(type);
    free(id);
    free(header);
    free(message);
}