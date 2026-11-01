#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "signer_transport.h"
#include "sdkconfig.h"
#include "soc/soc_caps.h"

#if defined(CONFIG_SIGNER_TRANSPORT_USB_SERIAL_JTAG) && (defined(CONFIG_SOC_USB_SERIAL_JTAG_SUPPORTED) || defined(SOC_USB_SERIAL_JTAG_SUPPORTED))

#include "driver/usb_serial_jtag.h"

static const char *TAG = "TRANSPORT_USJ";

#define USJ_RX_BUF_SIZE 512
#define USJ_TX_BUF_SIZE 512

static signer_rx_callback_t s_rx_callback = NULL;
static TaskHandle_t s_rx_task_handle = NULL;
static bool s_running = false;

static void usb_serial_jtag_rx_task(void *pvParameters)
{
    uint8_t rx_buf[USJ_RX_BUF_SIZE];
    ESP_LOGI(TAG, "USB Serial/JTAG RX task started");

    while (s_running)
    {
        int read_len = usb_serial_jtag_read_bytes(rx_buf, sizeof(rx_buf), pdMS_TO_TICKS(50));
        if (read_len > 0)
        {
            if (s_rx_callback != NULL)
            {
                s_rx_callback(SIGNER_ITF_DEFAULT, rx_buf, (size_t)read_len);
            }
        }
    }

    vTaskDelete(NULL);
}

static esp_err_t transport_usb_serial_jtag_send(uint8_t itf, const uint8_t *data, size_t len)
{
    (void)itf;
    size_t total_sent = 0;
    const uint8_t *data_ptr = data;
    size_t remaining = len;
    uint32_t start_time = esp_timer_get_time() / 1000;
    const uint32_t timeout_ms = 3000;

    while (remaining > 0)
    {
        if (!usb_serial_jtag_is_connected())
        {
            ESP_LOGW(TAG, "USB Serial/JTAG not connected to host");
            return ESP_ERR_NOT_FOUND;
        }

        int sent = usb_serial_jtag_write_bytes(data_ptr, remaining, pdMS_TO_TICKS(500));
        if (sent < 0)
        {
            ESP_LOGE(TAG, "USB Serial/JTAG write error");
            return ESP_FAIL;
        }
        else if (sent == 0)
        {
            if ((esp_timer_get_time() / 1000 - start_time) >= timeout_ms)
            {
                ESP_LOGE(TAG, "USB Serial/JTAG write timeout (%zu/%zu sent)", total_sent, len);
                return ESP_ERR_TIMEOUT;
            }
            vTaskDelay(pdMS_TO_TICKS(5));
            continue;
        }
        total_sent += sent;
        data_ptr += sent;
        remaining -= sent;
    }
    return ESP_OK;
}

static esp_err_t transport_usb_serial_jtag_init(signer_rx_callback_t rx_cb)
{
    s_rx_callback = rx_cb;

    usb_serial_jtag_driver_config_t usj_config = {
        .tx_buffer_size = USJ_TX_BUF_SIZE * 2,
        .rx_buffer_size = USJ_RX_BUF_SIZE * 2,
    };

    esp_err_t ret = usb_serial_jtag_driver_install(&usj_config);
    if (ret != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to install USB Serial/JTAG driver: %s", esp_err_to_name(ret));
        return ret;
    }

    s_running = true;
    BaseType_t task_ret = xTaskCreate(
        usb_serial_jtag_rx_task,
        "usj_rx_task",
        4096,
        NULL,
        8,
        &s_rx_task_handle
    );

    if (task_ret != pdPASS)
    {
        ESP_LOGE(TAG, "Failed to create USB Serial/JTAG RX task");
        usb_serial_jtag_driver_uninstall();
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "USB Serial/JTAG transport initialized successfully");
    return ESP_OK;
}

const signer_transport_backend_t g_signer_transport_usb_serial_jtag = {
    .name = "usb_serial_jtag",
    .init = transport_usb_serial_jtag_init,
    .send = transport_usb_serial_jtag_send,
};

#endif // CONFIG_SIGNER_TRANSPORT_USB_SERIAL_JTAG && SOC_USB_SERIAL_JTAG_SUPPORTED
