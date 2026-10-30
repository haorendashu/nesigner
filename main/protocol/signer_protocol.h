#ifndef SIGNER_PROTOCOL_H
#define SIGNER_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "memory_pool.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TYPE_SIZE          2    // Message type length
#define RESULT_SIZE        2    // Message result length (in responses)
#define ID_SIZE            16   // Message ID length
#define PUBKEY_SIZE        32   // Pubkey length
#define IV_SIZE            16   // IV length
#define CRC_SIZE           2    // CRC length
#define HEADER_SIZE        4    // Payload length header
#define MAX_MESSAGE_SIZE   1024 // Maximum message payload length
#define READ_TIMEOUT_MS    10000
#define TASK_STACK_SIZE    16384
#define QUEUE_SIZE         50
#define ITF_MAX            255

#define REQUEST_HEAD_LEN   70   // TYPE(2) + ID(16) + PUBKEY(32) + IV(16) + LEN(4)
#define RESPONSE_HEAD_LEN  72   // TYPE(2) + ID(16) + RESULT(2) + PUBKEY(32) + IV(16) + LEN(4)

typedef struct {
    uint8_t itf;
    uint16_t message_type;
    uint8_t message_id[ID_SIZE];
    uint8_t pubkey[PUBKEY_SIZE];
    uint8_t iv[IV_SIZE];
    uint8_t *message;
    int message_len;
} message_t;

typedef struct {
    uint8_t itf;
    uint8_t *data;
    int data_len;
    MessageBuffer *pool_buffer;
} response_t;

extern QueueHandle_t message_queue;
extern QueueHandle_t response_queue;

#ifdef __cplusplus
}
#endif

#endif // SIGNER_PROTOCOL_H
