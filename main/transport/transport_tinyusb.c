#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "signer_transport.h"
#include "sdkconfig.h"
#include "soc/soc_caps.h"

#if defined(CONFIG_SIGNER_TRANSPORT_TINYUSB) && (defined(CONFIG_SOC_USB_OTG_SUPPORTED) || defined(SOC_USB_OTG_SUPPORTED))

#include "tinyusb.h"
#include "tusb_cdc_acm.h"

static const char *TAG = "TRANSPORT_TUSB";

#define USB_VID 0x2323
#define USB_PID 0x3434

static signer_rx_callback_t s_rx_callback = NULL;
static uint8_t s_rx_buf[CONFIG_TINYUSB_CDC_RX_BUFSIZE * 4];

// Device descriptor with custom VID/PID
static tusb_desc_device_t s_descriptor_dev = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,
    .bDeviceClass = TUSB_CLASS_MISC,
    .bDeviceSubClass = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol = MISC_PROTOCOL_IAD,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor = USB_VID,
    .idProduct = USB_PID,
    .bcdDevice = 0x0100,
    .iManufacturer = 0x01,
    .iProduct = 0x02,
    .iSerialNumber = 0x03,
    .bNumConfigurations = 0x01
};

#if (TUD_OPT_HIGH_SPEED)
// Device qualifier descriptor required for High-Speed devices with custom device descriptor
static const tusb_desc_device_qualifier_t s_descriptor_qualifier = {
    .bLength = sizeof(tusb_desc_device_qualifier_t),
    .bDescriptorType = TUSB_DESC_DEVICE_QUALIFIER,
    .bcdUSB = 0x0200,
    .bDeviceClass = TUSB_CLASS_MISC,
    .bDeviceSubClass = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol = MISC_PROTOCOL_IAD,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    .bNumConfigurations = 0x01,
    .bReserved = 0
};
#endif

static void tinyusb_cdc_rx_callback(int itf, cdcacm_event_t *event)
{
    size_t rx_size = 0;
    esp_err_t ret = tinyusb_cdcacm_read(itf, s_rx_buf, sizeof(s_rx_buf), &rx_size);
    if (ret == ESP_OK && rx_size > 0 && s_rx_callback != NULL)
    {
        s_rx_callback((uint8_t)itf, s_rx_buf, rx_size);
    }
}

static void tinyusb_cdc_line_state_changed_callback(int itf, cdcacm_event_t *event)
{
    int dtr = event->line_state_changed_data.dtr;
    int rts = event->line_state_changed_data.rts;
    ESP_LOGI(TAG, "Line state changed on channel %d: DTR:%d, RTS:%d", itf, dtr, rts);
}

static esp_err_t transport_tinyusb_send(uint8_t itf, const uint8_t *data, size_t len)
{
    size_t total_sent = 0;
    const uint8_t *data_ptr = data;
    size_t remaining = len;
    uint32_t start_time = esp_timer_get_time() / 1000;
    const uint32_t timeout_ms = 5000;

    while (remaining > 0)
    {
        size_t send_length = tinyusb_cdcacm_write_queue(itf, (const char *)data_ptr, remaining);

        if (send_length == 0)
        {
            if ((esp_timer_get_time() / 1000 - start_time) >= timeout_ms)
            {
                ESP_LOGE(TAG, "USB send timeout");
                return ESP_ERR_TIMEOUT;
            }
            tinyusb_cdcacm_write_flush(itf, pdMS_TO_TICKS(10));
            continue;
        }

        total_sent += send_length;
        data_ptr += send_length;
        remaining -= send_length;
    }

    esp_err_t flush_err = tinyusb_cdcacm_write_flush(itf, 10000);
    if (flush_err != ESP_OK)
    {
        ESP_LOGE(TAG, "CDC ACM write flush error: %s", esp_err_to_name(flush_err));
        return flush_err;
    }
    return ESP_OK;
}

static esp_err_t transport_tinyusb_init(signer_rx_callback_t rx_cb)
{
    s_rx_callback = rx_cb;

    static const char *string_desc_arr[] = {
        [0] = "",               // Language ID
        [1] = "haorendashu",    // iManufacturer
        [2] = "nesigner",       // iProduct
        [3] = "123456",         // iSerialNumber
        [4] = "A nostr signer", // iInterface
    };

    const tinyusb_config_t tusb_cfg = {
        .device_descriptor = &s_descriptor_dev,
        .string_descriptor = string_desc_arr,
        .external_phy = false,
        .configuration_descriptor = NULL,
#if (TUD_OPT_HIGH_SPEED)
        .fs_configuration_descriptor = NULL,
        .hs_configuration_descriptor = NULL,
        .qualifier_descriptor = &s_descriptor_qualifier,
#endif
    };

    esp_err_t err = tinyusb_driver_install(&tusb_cfg);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to install TinyUSB driver: %s", esp_err_to_name(err));
        return err;
    }

    tinyusb_config_cdcacm_t acm_cfg = {
        .usb_dev = TINYUSB_USBDEV_0,
        .cdc_port = TINYUSB_CDC_ACM_0,
        .rx_unread_buf_sz = 64,
        .callback_rx = &tinyusb_cdc_rx_callback,
        .callback_rx_wanted_char = NULL,
        .callback_line_state_changed = NULL,
        .callback_line_coding_changed = NULL
    };

    err = tusb_cdc_acm_init(&acm_cfg);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to init CDC ACM 0: %s", esp_err_to_name(err));
        return err;
    }

    err = tinyusb_cdcacm_register_callback(
        TINYUSB_CDC_ACM_0,
        CDC_EVENT_LINE_STATE_CHANGED,
        &tinyusb_cdc_line_state_changed_callback);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to register line state callback: %s", esp_err_to_name(err));
        return err;
    }

#if (CONFIG_TINYUSB_CDC_COUNT > 1)
    acm_cfg.cdc_port = TINYUSB_CDC_ACM_1;
    tusb_cdc_acm_init(&acm_cfg);
    tinyusb_cdcacm_register_callback(
        TINYUSB_CDC_ACM_1,
        CDC_EVENT_LINE_STATE_CHANGED,
        &tinyusb_cdc_line_state_changed_callback);
#endif

    ESP_LOGI(TAG, "TinyUSB CDC-ACM transport initialized successfully");
    return ESP_OK;
}

const signer_transport_backend_t g_signer_transport_tinyusb = {
    .name = "tinyusb",
    .init = transport_tinyusb_init,
    .send = transport_tinyusb_send,
};

#endif // CONFIG_SIGNER_TRANSPORT_TINYUSB && SOC_USB_OTG_SUPPORTED
