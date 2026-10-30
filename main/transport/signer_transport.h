#ifndef SIGNER_TRANSPORT_H
#define SIGNER_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SIGNER_ITF_DEFAULT 0
#define SIGNER_ITF_UART    255

/**
 * @brief Callback invoked when raw data is received from the transport.
 *
 * @param itf Interface identifier (e.g. CDC ACM index, or SIGNER_ITF_UART)
 * @param data Pointer to received byte buffer
 * @param len Number of bytes received
 */
typedef void (*signer_rx_callback_t)(uint8_t itf, const uint8_t *data, size_t len);

/**
 * @brief Transport operations interface structure.
 */
typedef struct {
    const char *name;
    esp_err_t (*init)(signer_rx_callback_t rx_cb);
    esp_err_t (*send)(uint8_t itf, const uint8_t *data, size_t len);
} signer_transport_backend_t;

/**
 * @brief Initialize the configured default transport backend.
 *
 * @param rx_cb Callback to receive incoming data bytes
 * @return ESP_OK on success
 */
esp_err_t signer_transport_init(signer_rx_callback_t rx_cb);

/**
 * @brief Send data through the active transport.
 *
 * @param itf Target interface identifier
 * @param data Buffer to transmit
 * @param len Length of data in bytes
 * @return ESP_OK on success
 */
esp_err_t signer_transport_send(uint8_t itf, const uint8_t *data, size_t len);

/**
 * @brief Get the active transport backend pointer.
 */
const signer_transport_backend_t *signer_transport_get_active(void);

#ifdef __cplusplus
}
#endif

#endif // SIGNER_TRANSPORT_H
