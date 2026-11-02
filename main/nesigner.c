#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "signer_protocol.h"
#include "packet_codec.h"
#include "session_crypto.h"
#include "command_router.h"
#include "signer_crypto.h"
#include "psa/crypto.h"
#include "nostr_ecdh_cache.h"
#include "nostr_nip44.h"
#include "signer_storage.h"
#include "signer_transport.h"
#include "memory_pool.h"
#include "sdkconfig.h"

static const char *TAG = "NESIGNER";

QueueHandle_t message_queue = NULL;
QueueHandle_t response_queue = NULL;

#define PROTOCOL_BUFFER_SIZE 4096
static uint8_t s_proto_msg_buffer[PROTOCOL_BUFFER_SIZE];
static size_t s_proto_msg_buffer_size = 0;
static uint64_t s_start_read_time = 0;

static void on_raw_rx_data(uint8_t itf, const uint8_t *data, size_t rx_size)
{
    uint64_t current_time = esp_timer_get_time() / 1000;
    if (s_start_read_time > 0 && (current_time - s_start_read_time) >= 2000) {
        ESP_LOGW(TAG, "Transport read timeout, resetting rx buffer (%zu bytes discarded)", s_proto_msg_buffer_size);
        s_proto_msg_buffer_size = 0;
        s_start_read_time = 0;
    }

    if (s_start_read_time == 0) {
        s_start_read_time = current_time;
    }

    if (s_proto_msg_buffer_size + rx_size > PROTOCOL_BUFFER_SIZE) {
        ESP_LOGE(TAG, "Protocol buffer overflow, resetting");
        s_proto_msg_buffer_size = 0;
        s_start_read_time = 0;
        return;
    }

    memcpy(s_proto_msg_buffer + s_proto_msg_buffer_size, data, rx_size);
    s_proto_msg_buffer_size += rx_size;

    while (s_proto_msg_buffer_size >= REQUEST_HEAD_LEN) {
        // Fast header check: message type high byte must be 0, low byte <= 20
        uint16_t msg_type = ((uint16_t)s_proto_msg_buffer[0] << 8) | s_proto_msg_buffer[1];
        if (s_proto_msg_buffer[0] != 0 || s_proto_msg_buffer[1] > 20) {
            memmove(s_proto_msg_buffer, s_proto_msg_buffer + 1, --s_proto_msg_buffer_size);
            continue;
        }

        // Header length offset: TYPE(2) + ID(16) + PUBKEY(32) + IV(16) = 66
        uint32_t data_len = ((uint32_t)s_proto_msg_buffer[66] << 24) |
                            ((uint32_t)s_proto_msg_buffer[67] << 16) |
                            ((uint32_t)s_proto_msg_buffer[68] << 8)  |
                            (uint32_t)s_proto_msg_buffer[69];

        // Sanity check data_len against max allowable buffer space
        if (data_len > (PROTOCOL_BUFFER_SIZE - REQUEST_HEAD_LEN - CRC_SIZE)) {
            memmove(s_proto_msg_buffer, s_proto_msg_buffer + 1, --s_proto_msg_buffer_size);
            continue;
        }

        size_t whole_msg_len = REQUEST_HEAD_LEN + data_len + CRC_SIZE;
        if (s_proto_msg_buffer_size < whole_msg_len) {
            return;
        }

        uint16_t received_crc = ((uint16_t)s_proto_msg_buffer[REQUEST_HEAD_LEN + data_len] << 8) |
                                s_proto_msg_buffer[REQUEST_HEAD_LEN + data_len + 1];
        uint16_t computed_crc = crc16(s_proto_msg_buffer, REQUEST_HEAD_LEN + data_len);
        if (computed_crc != received_crc) {
            ESP_LOGW(TAG, "CRC check failed (rec=0x%04x, calc=0x%04x), sliding 1 byte", received_crc, computed_crc);
            memmove(s_proto_msg_buffer, s_proto_msg_buffer + 1, --s_proto_msg_buffer_size);
            continue;
        }

        message_t message = {
            .itf = itf,
            .message_type = msg_type,
            .message_len = data_len,
            .message = NULL
        };
        memcpy(message.message_id, s_proto_msg_buffer + 2, ID_SIZE);
        memcpy(message.pubkey, s_proto_msg_buffer + 18, PUBKEY_SIZE);
        memcpy(message.iv, s_proto_msg_buffer + 50, IV_SIZE);

        if (data_len > 0) {
            message.message = (uint8_t *)malloc(data_len);
            if (!message.message) {
                ESP_LOGE(TAG, "Failed to allocate memory for payload");
                s_proto_msg_buffer_size -= whole_msg_len;
                memmove(s_proto_msg_buffer, s_proto_msg_buffer + whole_msg_len, s_proto_msg_buffer_size);
                s_start_read_time = 0;
                return;
            }
            memcpy(message.message, s_proto_msg_buffer + REQUEST_HEAD_LEN, data_len);
        }

        s_proto_msg_buffer_size -= whole_msg_len;
        memmove(s_proto_msg_buffer, s_proto_msg_buffer + whole_msg_len, s_proto_msg_buffer_size);

        if (xQueueSend(message_queue, &message, pdMS_TO_TICKS(100)) != pdPASS) {
            ESP_LOGE(TAG, "Failed to send message to queue - queue full");
            if (data_len > 0) {
                free(message.message);
            }
        }

        s_start_read_time = 0;
    }
}

static void handle_message_task(void *pvParameters)
{
    while (1) {
        message_t msg;
        if (xQueueReceive(message_queue, &msg, portMAX_DELAY)) {
            command_router_dispatch(&msg);
            if (msg.message != NULL) {
                free(msg.message);
            }
        }
    }
}

static void handle_response_task(void *pvParameters)
{
    while (1) {
        response_t response;
        if (xQueueReceive(response_queue, &response, portMAX_DELAY)) {
            signer_transport_send(response.itf, response.data, response.data_len);

            if (response.pool_buffer != NULL) {
                memory_pool_release(response.pool_buffer);
            } else {
                free(response.data);
            }
        }
    }
}

static void run_startup_benchmarks(void)
{
    ESP_LOGI(TAG, "=== Running Cryptographic & Protocol Benchmarks ===");
    uint8_t priv_a[32], pub_a[32];
    uint8_t priv_b[32], pub_b[32];
    crypto_secp256k1_gen_privkey(priv_a);
    crypto_secp256k1_get_public(priv_a, pub_a);
    crypto_secp256k1_gen_privkey(priv_b);
    crypto_secp256k1_get_public(priv_b, pub_b);

    // BIP-340 Schnorr Sign
    uint8_t msg[32];
    memset(msg, 0xaa, sizeof(msg));
    uint8_t sig[64];
    int64_t t0 = esp_timer_get_time();
    crypto_secp256k1_schnorr_sign(priv_a, msg, NULL, sig);
    int64_t t_sign_us = esp_timer_get_time() - t0;

    // BIP-340 Schnorr Verify
    t0 = esp_timer_get_time();
    crypto_secp256k1_schnorr_verify(pub_a, msg, sig);
    int64_t t_verify_us = esp_timer_get_time() - t0;

    // NIP-44 Encrypt (ECDH Cache Miss)
    nostr_ecdh_cache_clear();
    const char *test_msg = "Nostr hardware benchmark payload 1234567890";
    char *nip44_ct = NULL;
    t0 = esp_timer_get_time();
    nostr_nip44_encrypt(priv_a, pub_b, test_msg, &nip44_ct);
    int64_t t_nip44_miss_us = esp_timer_get_time() - t0;

    // NIP-44 Decrypt (ECDH Cache Hit)
    char *nip44_pt = NULL;
    t0 = esp_timer_get_time();
    nostr_nip44_decrypt(priv_b, pub_a, nip44_ct, &nip44_pt);
    int64_t t_nip44_hit_us = esp_timer_get_time() - t0;

    if (nip44_ct) free(nip44_ct);
    if (nip44_pt) free(nip44_pt);

    ESP_LOGI(TAG, "Benchmark Results:");
    ESP_LOGI(TAG, "  - BIP-340 Schnorr Sign:       %lld us (%lld.%02lld ms)", t_sign_us, t_sign_us / 1000, (t_sign_us % 1000) / 10);
    ESP_LOGI(TAG, "  - BIP-340 Schnorr Verify:     %lld us (%lld.%02lld ms)", t_verify_us, t_verify_us / 1000, (t_verify_us % 1000) / 10);
    ESP_LOGI(TAG, "  - NIP-44 Encrypt (Cache Miss): %lld us (%lld.%02lld ms)", t_nip44_miss_us, t_nip44_miss_us / 1000, (t_nip44_miss_us % 1000) / 10);
    ESP_LOGI(TAG, "  - NIP-44 Decrypt (Cache Hit):  %lld us (%lld.%02lld ms)", t_nip44_hit_us, t_nip44_hit_us / 1000, (t_nip44_hit_us % 1000) / 10);
    int64_t ratio = t_nip44_hit_us > 0 ? (t_nip44_miss_us / t_nip44_hit_us) : 0;
    ESP_LOGI(TAG, "  - ECDH Cache Acceleration:    ~%lldx faster", ratio);
    ESP_LOGI(TAG, "===================================================");
}

void app_main(void)
{
    ESP_LOGI(TAG, "Starting nesigner firmware...");

    if (!memory_pool_init()) {
        ESP_LOGE(TAG, "Failed to initialize memory pool");
        return;
    }

    psa_status_t psa_status = psa_crypto_init();
    if (psa_status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to initialize PSA crypto subsystem: %d", (int)psa_status);
        return;
    }

    if (crypto_init() != 0) {
        ESP_LOGE(TAG, "Failed to initialize crypto subsystem");
        return;
    }

    // Run self-test to verify secp256k1 & symmetric ciphers
    if (crypto_self_test() != 0) {
        ESP_LOGE(TAG, "Crypto self-test failed!");
    }

    session_crypto_init();
    nostr_ecdh_cache_init();
    signer_storage_init();

    // Run on-boot cryptographic performance benchmarks
    run_startup_benchmarks();

    message_queue = xQueueCreate(QUEUE_SIZE, sizeof(message_t));
    if (message_queue == NULL) {
        ESP_LOGE(TAG, "Failed to create message queue");
        return;
    }

    response_queue = xQueueCreate(QUEUE_SIZE, sizeof(response_t));
    if (response_queue == NULL) {
        ESP_LOGE(TAG, "Failed to create response queue");
        return;
    }

    esp_err_t err = signer_transport_init(on_raw_rx_data);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize signer transport: %s", esp_err_to_name(err));
        return;
    }

    xTaskCreate(handle_message_task, "handle_msg_task", TASK_STACK_SIZE, NULL, 10, NULL);
    xTaskCreate(handle_response_task, "handle_resp_task", 8192, NULL, 8, NULL);

    ESP_LOGI(TAG, "nesigner started successfully with modular Crypto HAL & LRU cache");
}
