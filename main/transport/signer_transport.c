#include "signer_transport.h"
#include "esp_log.h"
#include "sdkconfig.h"
#include "soc/soc_caps.h"

static const char *TAG = "TRANSPORT";

#if defined(CONFIG_SIGNER_TRANSPORT_TINYUSB) && (defined(CONFIG_SOC_USB_OTG_SUPPORTED) || defined(SOC_USB_OTG_SUPPORTED))
extern const signer_transport_backend_t g_signer_transport_tinyusb;
#define ACTIVE_BACKEND (&g_signer_transport_tinyusb)
#elif defined(CONFIG_SIGNER_TRANSPORT_USB_SERIAL_JTAG) && (defined(CONFIG_SOC_USB_SERIAL_JTAG_SUPPORTED) || defined(SOC_USB_SERIAL_JTAG_SUPPORTED))
extern const signer_transport_backend_t g_signer_transport_usb_serial_jtag;
#define ACTIVE_BACKEND (&g_signer_transport_usb_serial_jtag)
#elif defined(CONFIG_SIGNER_TRANSPORT_UART)
extern const signer_transport_backend_t g_signer_transport_uart;
#define ACTIVE_BACKEND (&g_signer_transport_uart)
#else
#define ACTIVE_BACKEND NULL
#endif

static const signer_transport_backend_t *s_active_backend = ACTIVE_BACKEND;

esp_err_t signer_transport_init(signer_rx_callback_t rx_cb)
{
    if (s_active_backend == NULL || s_active_backend->init == NULL)
    {
        ESP_LOGE(TAG, "No valid transport backend configured");
        return ESP_ERR_NOT_SUPPORTED;
    }
    ESP_LOGI(TAG, "Initializing transport: %s", s_active_backend->name);
    return s_active_backend->init(rx_cb);
}

esp_err_t signer_transport_send(uint8_t itf, const uint8_t *data, size_t len)
{
    if (s_active_backend == NULL || s_active_backend->send == NULL)
    {
        return ESP_ERR_NOT_SUPPORTED;
    }
    return s_active_backend->send(itf, data, len);
}

const signer_transport_backend_t *signer_transport_get_active(void)
{
    return s_active_backend;
}
