#include "packet_codec.h"
#include "signer_crypto.h"
#include "signer_transport.h"
#include "esp_log.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "PACKET_CODEC";

uint16_t crc16(const uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int j = 0; j < 8; j++) {
            crc = (crc & 0x8000) ? (crc << 1) ^ 0x1021 : (crc << 1);
        }
    }
    return crc;
}

void generate_random_iv(uint8_t iv[IV_SIZE])
{
    crypto_trng_fill(iv, IV_SIZE);
}

void send_response(uint8_t itf, uint16_t message_result, uint16_t message_type,
                   const uint8_t *message_id, const uint8_t *pubkey, const uint8_t *iv,
                   const uint8_t *message, int message_len)
{
    uint8_t type_bin[TYPE_SIZE] = {
        (uint8_t)((message_type >> 8) & 0xFF),
        (uint8_t)(message_type & 0xFF)
    };

    uint8_t result_bin[RESULT_SIZE] = {
        (uint8_t)((message_result >> 8) & 0xFF),
        (uint8_t)(message_result & 0xFF)
    };

    uint8_t header[HEADER_SIZE] = {
        (uint8_t)((message_len >> 24) & 0xFF),
        (uint8_t)((message_len >> 16) & 0xFF),
        (uint8_t)((message_len >> 8) & 0xFF),
        (uint8_t)(message_len & 0xFF)
    };

    size_t whole_msg_len = TYPE_SIZE + ID_SIZE + RESULT_SIZE + PUBKEY_SIZE + IV_SIZE + HEADER_SIZE + message_len + CRC_SIZE;

    MessageBuffer *buffer = memory_pool_get();
    if (buffer == NULL) {
        ESP_LOGE(TAG, "Failed to allocate buffer from memory pool");
        return;
    }

    uint8_t *whole_msg = buffer->buffer;
    size_t offset = 0;

    memcpy(whole_msg + offset, type_bin, TYPE_SIZE);
    offset += TYPE_SIZE;

    memcpy(whole_msg + offset, message_id, ID_SIZE);
    offset += ID_SIZE;

    memcpy(whole_msg + offset, result_bin, RESULT_SIZE);
    offset += RESULT_SIZE;

    memcpy(whole_msg + offset, pubkey, PUBKEY_SIZE);
    offset += PUBKEY_SIZE;

    memcpy(whole_msg + offset, iv, IV_SIZE);
    offset += IV_SIZE;

    memcpy(whole_msg + offset, header, HEADER_SIZE);
    offset += HEADER_SIZE;

    if (message_len > 0 && message != NULL) {
        memcpy(whole_msg + offset, message, message_len);
        offset += message_len;
    }

    uint16_t crc = crc16(whole_msg, offset);
    uint8_t crc_bytes[] = { (uint8_t)(crc >> 8), (uint8_t)(crc & 0xFF) };
    memcpy(whole_msg + offset, crc_bytes, CRC_SIZE);

    buffer->used_size = whole_msg_len;

    if (itf >= ITF_MAX) {
        // Send directly bypass queue
        signer_transport_send(itf, whole_msg, whole_msg_len);
        memory_pool_release(buffer);
    } else {
        response_t response = {
            .itf = itf,
            .data = whole_msg,
            .data_len = whole_msg_len,
            .pool_buffer = buffer
        };

        if (xQueueSend(response_queue, &response, pdMS_TO_TICKS(100)) != pdPASS) {
            ESP_LOGE(TAG, "Failed to send response to queue");
            memory_pool_release(buffer);
        }
    }
}

void send_response_with_encrypt(uint8_t itf, uint8_t *aesKey, uint16_t message_result,
                                uint16_t message_type, const uint8_t *message_id,
                                const uint8_t *pubkey, const uint8_t *iv,
                                const uint8_t *message, int message_len)
{
    if (message_len > 0 && aesKey != NULL) {
        uint8_t *encrypted = NULL;
        size_t encrypted_len = 0;
        if (crypto_aes_encrypt_padded(aesKey, 16, iv, message, message_len, &encrypted, &encrypted_len) != 0) {
            ESP_LOGE(TAG, "Outer AES encryption failed");
            return;
        }

        send_response(itf, message_result, message_type, message_id, pubkey, iv, encrypted, (int)encrypted_len);
        free(encrypted);
    } else {
        send_response(itf, message_result, message_type, message_id, pubkey, iv, message, message_len);
    }
}
