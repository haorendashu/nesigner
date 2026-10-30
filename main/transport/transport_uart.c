#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "signer_transport.h"
#include "sdkconfig.h"

static const char *TAG = "TRANSPORT_UART";

#define UART_BUF_SIZE 1024

static signer_rx_callback_t s_rx_callback = NULL;
static TaskHandle_t s_rx_task_handle = NULL;
static bool s_running = false;

static void uart_rx_task(void *pvParameters)
{
    uint8_t rx_buf[UART_BUF_SIZE];
    ESP_LOGI(TAG, "UART RX task started on port %d", CONFIG_SIGNER_UART_PORT_NUM);

    while (s_running)
    {
        int read_len = uart_read_bytes(CONFIG_SIGNER_UART_PORT_NUM, rx_buf, sizeof(rx_buf), pdMS_TO_TICKS(50));
        if (read_len > 0)
        {
            if (s_rx_callback != NULL)
            {
                s_rx_callback(SIGNER_ITF_UART, rx_buf, (size_t)read_len);
            }
        }
    }

    vTaskDelete(NULL);
}

static esp_err_t transport_uart_send(uint8_t itf, const uint8_t *data, size_t len)
{
    (void)itf;
    size_t total_sent = 0;
    const uint8_t *data_ptr = data;
    size_t remaining = len;

    while (remaining > 0)
    {
        int sent = uart_write_bytes(CONFIG_SIGNER_UART_PORT_NUM, (const char *)data_ptr, remaining);
        if (sent < 0)
        {
            ESP_LOGE(TAG, "UART write error");
            return ESP_FAIL;
        }
        else if (sent == 0)
        {
            vTaskDelay(pdMS_TO_TICKS(1));
            continue;
        }
        total_sent += sent;
        data_ptr += sent;
        remaining -= sent;
    }
    return ESP_OK;
}

static esp_err_t transport_uart_init(signer_rx_callback_t rx_cb)
{
    s_rx_callback = rx_cb;

    uart_config_t uart_config = {
        .baud_rate = CONFIG_SIGNER_UART_BAUD_RATE,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    esp_err_t err = uart_set_pin(
        CONFIG_SIGNER_UART_PORT_NUM,
        CONFIG_SIGNER_UART_TX_PIN,
        CONFIG_SIGNER_UART_RX_PIN,
        UART_PIN_NO_CHANGE,
        UART_PIN_NO_CHANGE
    );
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to set UART pins: %s", esp_err_to_name(err));
        return err;
    }

    err = uart_driver_install(CONFIG_SIGNER_UART_PORT_NUM, UART_BUF_SIZE * 2, 0, 0, NULL, 0);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to install UART driver: %s", esp_err_to_name(err));
        return err;
    }

    err = uart_param_config(CONFIG_SIGNER_UART_PORT_NUM, &uart_config);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to config UART params: %s", esp_err_to_name(err));
        return err;
    }

    s_running = true;
    BaseType_t task_ret = xTaskCreate(
        uart_rx_task,
        "uart_rx_task",
        4096,
        NULL,
        8,
        &s_rx_task_handle
    );

    if (task_ret != pdPASS)
    {
        ESP_LOGE(TAG, "Failed to create UART RX task");
        uart_driver_delete(CONFIG_SIGNER_UART_PORT_NUM);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "UART transport initialized successfully");
    return ESP_OK;
}

const signer_transport_backend_t g_signer_transport_uart = {
    .name = "uart",
    .init = transport_uart_init,
    .send = transport_uart_send,
};
