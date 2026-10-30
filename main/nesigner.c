#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "mbedtls/aes.h"
#include "msg_type.h"
#include "nostr.h"
#include "store.h"
#include "msg_result.h"
#include "utils.h"
#include "signer_transport.h"
#include "sdkconfig.h"
#include "memory_pool.h"
#include "error_handling.h"

#define TYPE_SIZE 2              // 消息类型长度（固定 2 字节）
#define RESULT_SIZE 2            // 消息结果长度（固定 2 字节）（仅在result中有）
#define ID_SIZE 16               // 消息 ID 长度（固定 16 字节）
#define PUBKEY_SIZE 32           // 消息 PUBKEY 长度（固定 32 字节）
#define IV_SIZE 16               // IV 长度（固定 16 字节）
#define CRC_SIZE 2               // CRC长度（固定 2 字节）
#define HEADER_SIZE 4            // 消息头长度（固定 4 字节）
#define MAX_MESSAGE_SIZE 1024    // 最大消息长度
#define READ_TIMEOUT_MS 10000    // 读取超时时间（毫秒）
#define TASK_STACK_SIZE 16384    // Task 栈大小（增加栈大小提高性能）
#define QUEUE_SIZE 50            // 消息队列大小（增加队列容量）
#define ITF_MAX 255              // itf can't over this num

static const char *TAG = "NESIGNER";

// Requst 消息结构：
// | 2字节类型 | 16字节ID | 32字节PUBKEY | 16字节加密 IV | 4字节长度头 | N字节加密数据 |2字节CRC |
// Response 消息结构：
// | 2字节类型 | 16字节ID | 2字节结果 | 32字节PUBKEY | 16字节加密 IV | 4字节长度头 | N字节加密数据 |2字节CRC |
#define REQUEST_HEAD_LEN 70
#define RESPONSE_HEAD_LEN 72

// AES配置
#define AES_KEY_SIZE 256
// static const uint8_t aes_key[] = "0123456789ABCDEF0123456789ABCDEF"; // 32字节密钥

uint8_t temp_private_key[PRIVATE_KEY_LEN];

// 生成随机 IV 的函数
void generate_random_iv(uint8_t iv[IV_SIZE])
{
    for (int i = 0; i < IV_SIZE; i += 4)
    {
        // 生成 32 位随机数
        uint32_t random_num = esp_random();
        // 将 32 位随机数拆分成 4 个 8 位字节并存储到 IV 数组中
        iv[i] = (random_num >> 24) & 0xFF;
        iv[i + 1] = (random_num >> 16) & 0xFF;
        iv[i + 2] = (random_num >> 8) & 0xFF;
        iv[i + 3] = random_num & 0xFF;
    }
}

uint16_t crc16(uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++)
    {
        crc ^= (uint16_t)data[i] << 8;
        for (int j = 0; j < 8; j++)
        {
            crc = (crc & 0x8000) ? (crc << 1) ^ 0x1021 : (crc << 1);
        }
    }
    return crc;
}

// 消息结构体
typedef struct
{
    uint8_t itf; // Index of transport device interface
    uint16_t message_type;
    uint8_t message_id[ID_SIZE];
    uint8_t pubkey[PUBKEY_SIZE];
    uint8_t iv[IV_SIZE];
    uint8_t *message; // encrypted message
    int message_len;
} message_t;

// 响应消息结构体
typedef struct
{
    uint8_t itf;   // Index of transport device interface
    uint8_t *data; // Complete response data
    int data_len;
    MessageBuffer *pool_buffer; // 非NULL=池缓冲区，由接收方调用memory_pool_release；NULL=堆内存，由接收方调用free
} response_t;

// 消息队列句柄
QueueHandle_t message_queue;
// 响应队列句柄
QueueHandle_t response_queue;

bool is_timeout(uint64_t start_time, uint64_t timeout_ms)
{
    uint64_t current_time = esp_timer_get_time() / 1000; // 转换为毫秒
    return (current_time - start_time) >= timeout_ms;
}

// 发送响应消息
void send_response(uint8_t itf, uint16_t message_result, uint16_t message_type, const uint8_t *message_id, const uint8_t *pubkey, const uint8_t *iv,
                   const uint8_t *message, int message_len)
{
    uint8_t type_bin[TYPE_SIZE] = {(message_type >> 8) & 0xFF,
                                   message_type & 0xFF};

    uint8_t result_bin[RESULT_SIZE] = {(message_result >> 8) & 0xFF,
                                       message_result & 0xFF};

    uint8_t header[HEADER_SIZE] = {
        (message_len >> 24) & 0xFF,
        (message_len >> 16) & 0xFF,
        (message_len >> 8) & 0xFF,
        message_len & 0xFF};

    // 创建一个临时缓冲区来存储整个消息
    size_t whole_msg_len = TYPE_SIZE + ID_SIZE + RESULT_SIZE + PUBKEY_SIZE + IV_SIZE + HEADER_SIZE + message_len + CRC_SIZE;

    // 使用内存池而不是直接malloc
    MessageBuffer *buffer = memory_pool_get();
    if (buffer == NULL)
    {
        ESP_LOGE(TAG, "Failed to get buffer from memory pool");
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
    if (message_len > 0 && message != NULL)
    {
        memcpy(whole_msg + offset, message, message_len);
        offset += message_len;
    }

    // 计算整个消息的CRC
    uint16_t crc = crc16(whole_msg, offset);
    uint8_t crc_bytes[] = {crc >> 8, crc & 0xFF};
    memcpy(whole_msg + offset, crc_bytes, CRC_SIZE);

    if (itf >= ITF_MAX)
    {
        // send directly
        buffer->used_size = whole_msg_len;
        signer_transport_send(itf, whole_msg, whole_msg_len);
        memory_pool_release(buffer);
    }
    else
    {
        buffer->used_size = whole_msg_len;
        // 将响应发入响应队列（零拷贝：直接转移池缓冲区所有权，由handle_response_task释放）
        response_t response = {
            .itf = itf,
            .data = whole_msg,
            .data_len = whole_msg_len,
            .pool_buffer = buffer};

        if (xQueueSend(response_queue, &response, pdMS_TO_TICKS(100)) != pdPASS)
        {
            ESP_LOGE(TAG, "Failed to send response to queue");
            memory_pool_release(buffer);
        }
    }
}

void send_response_with_encrypt(uint8_t itf, uint8_t *aesKey, uint16_t message_result, uint16_t message_type, const uint8_t *message_id, const uint8_t *pubkey, const uint8_t *iv,
                                const uint8_t *message, int message_len)
{
    if (message_len > 0 && aesKey != NULL)
    {
        uint8_t *encrypted = NULL;
        size_t encrypted_len;
        if (aes_encrypt_padded(aesKey, 16, iv, message, message_len, &encrypted, &encrypted_len) != 0)
        {
            ESP_LOGE(TAG, "AES encryption failed");
            return;
        }

        send_response(itf, message_result, message_type, message_id, pubkey, iv, encrypted, encrypted_len);
        free(encrypted);
    }
    else
    {
        send_response(itf, message_result, message_type, message_id, pubkey, iv, message, message_len);
    }
}

// 处理消息的 Task
void handle_message_task(void *pvParameters)
{
    while (1)
    {
        message_t msg;
        if (xQueueReceive(message_queue, &msg, portMAX_DELAY))
        {
            // ESP_LOGI(TAG, "msg received from queue");

            uint8_t iv[IV_SIZE];
            generate_random_iv(iv);

            // printf("message_type %d\n", msg.message_type);

            if (msg.message_type == MSG_TYPE_PING)
            {
                send_response(msg.itf, MSG_RESULT_OK, msg.message_type, msg.message_id, msg.pubkey, msg.iv, msg.message, 0);
                goto cleanup;
            }
            else if (msg.message_type == MSG_TYPE_ECHO)
            {
                send_response(msg.itf, MSG_RESULT_OK, msg.message_type, msg.message_id, msg.pubkey, msg.iv, msg.message, msg.message_len);
                goto cleanup;
            }
            else if (msg.message_type == MSG_TYPE_GET_TEMP_PUBKEY)
            {
                uint8_t temp_pubkey[PUBKEY_LEN];
                if (get_public(temp_private_key, temp_pubkey) == -1)
                {
                    goto sendfail;
                }
                send_response(msg.itf, MSG_RESULT_OK, msg.message_type, msg.message_id, msg.pubkey, msg.iv, temp_pubkey, PUBKEY_LEN);
                goto cleanup;
            }
            else if (msg.message_type == MSG_TYPE_UPDATE_KEY)
            {
                if (msg.message_len < PRIVATE_KEY_LEN + AES_KEY_LEN)
                {
                    goto sendillegal;
                }

                char *decrypted_content = NULL;
                // printByteArrayAsDec(msg.message, msg.message_len);
                char encrypted_content[msg.message_len + 1] = {};
                memcpy(encrypted_content, msg.message, msg.message_len);
                encrypted_content[msg.message_len] = 0;
                if (nip44_decrypt(temp_private_key, msg.pubkey, encrypted_content, &decrypted_content) != 0)
                {
                    goto sendillegal;
                }

                uint8_t private_key_hex[PRIVATE_KEY_LEN * 2 + 1];
                uint8_t aes_key_hex[AES_KEY_LEN * 2 + 1];
                private_key_hex[PRIVATE_KEY_LEN * 2] = 0;
                aes_key_hex[AES_KEY_LEN * 2] = 0;
                memcpy(private_key_hex, decrypted_content, PRIVATE_KEY_LEN * 2);
                memcpy(aes_key_hex, decrypted_content + PRIVATE_KEY_LEN * 2, AES_KEY_LEN * 2);

                char private_key_bin[PRIVATE_KEY_LEN] = {};
                hex_to_bin(private_key_hex, private_key_bin, PRIVATE_KEY_LEN);
                char aes_key_bin[AES_KEY_LEN] = {};
                hex_to_bin(aes_key_hex, aes_key_bin, AES_KEY_LEN);

                // ESP_LOGI("Test", "private_key_hex %s aes_key_hex %s", private_key_hex, aes_key_hex);

                KeyPair *keyPair = malloc(sizeof(KeyPair));
                memcpy(keyPair->aesKey, aes_key_bin, AES_KEY_LEN);
                memcpy(keyPair->privateKey, private_key_bin, PRIVATE_KEY_LEN);

                if (addAndSaveKeyPair(keyPair))
                {
                    send_response(msg.itf, MSG_RESULT_OK, msg.message_type, msg.message_id, msg.pubkey, msg.iv, NULL, 0);
                }
                else
                {
                    goto sendfail;
                }

                goto cleanup;
            }
            else if (msg.message_type == MSG_TYPE_NOSTR_GET_PUBLIC_KEY || msg.message_type == MSG_TYPE_REMOVE_KEY)
            {
                // try to use keyparis to aes decrypt message
                for (size_t i = 0; i < keypair_count; i++)
                {
                    // printf("GET PUBKEY: item %d\n", i);
                    KeyPair keypair = keypairs[i];
                    uint8_t *decrypted = NULL;
                    size_t decrypted_len;
                    if (aes_decrypt_padded(keypair.aesKey, 16, msg.iv, msg.message, msg.message_len,
                                           &decrypted, &decrypted_len) != 0)
                    {
                        // printf("this is not my key!\n");
                        continue;
                    }
                    // printByteArrayAsDec((char *)decrypted, decrypted_len);

                    if (memcmp(decrypted, msg.iv, IV_SIZE) == 0)
                    {
                        // If the decrypt content equal iv, find the aesKey!
                        free(decrypted);
                        // printf("find key!\n");

                        // char pubkey_hex[PUBKEY_LEN * 2 + 1] = {};
                        // pubkey_hex[PUBKEY_LEN * 2] = 0;
                        // bin_to_hex(keypair.pubkey, PUBKEY_LEN, pubkey_hex);
                        // ESP_LOGI("Test", "pubkey_hex %s", pubkey_hex);

                        if (msg.message_type == MSG_TYPE_NOSTR_GET_PUBLIC_KEY)
                        {
                            send_response_with_encrypt(msg.itf, keypair.aesKey, MSG_RESULT_OK, msg.message_type, msg.message_id, keypair.pubkey, iv, keypair.pubkey, PUBKEY_LEN);
                            goto cleanup;
                        }
                        else if (msg.message_type == MSG_TYPE_REMOVE_KEY)
                        {
                            // printf("begin to remove kp\n");
                            if (removeAndSaveKeyPair(keypair.aesKey))
                            {
                                // printf("remove success \n");
                                send_response(msg.itf, MSG_RESULT_OK, msg.message_type, msg.message_id, msg.pubkey, iv, NULL, 0);
                                goto cleanup;
                            }
                            else
                            {
                                // printf("remove fail \n");
                                goto sendfail;
                            }
                        }
                    }
                    free(decrypted);
                }

                send_response(msg.itf, MSG_RESULT_KEY_NOT_FOUND, msg.message_type, msg.message_id, msg.pubkey, msg.iv, NULL, 0);
                goto cleanup;
            }

            KeyPair *keypair;

            if (msg.message_len > 0)
            {
                keypair = findKeyPairByPubkey(msg.pubkey);
                if (keypair == NULL)
                {
                    // can't find the keypair,
                    send_response(msg.itf, MSG_RESULT_KEY_NOT_FOUND, msg.message_type, msg.message_id, msg.pubkey, msg.iv, NULL, 0);
                    goto cleanup;
                }
            }
            else
            {
                send_response(msg.itf, MSG_RESULT_CONTENT_NOT_ALLOW_EMPTY, msg.message_type, msg.message_id, msg.pubkey, msg.iv, NULL, 0);
                goto cleanup;
            }

            // 解密数据
            uint8_t *decrypted = NULL;
            size_t decrypted_len;
            if (aes_decrypt_padded(keypair->aesKey, 16, msg.iv, msg.message, msg.message_len,
                                   &decrypted, &decrypted_len) != 0)
            {
                ESP_LOGE("NIP04", "AES decryption failed");
                goto sendillegal;
            }

            if (msg.message_type == MSG_TYPE_NOSTR_SIGN_EVENT)
            {
                if (decrypted_len != NOSTR_EVENT_ID_BIN_LEN)
                {
                    goto sendillegal;
                }

                uint8_t sig_bin[NOSTR_EVENT_SIG_BIN_LEN];

                if (sign(keypair->privateKey, decrypted, sig_bin) != 0)
                {
                    free(decrypted);
                    goto sendfail;
                }

                send_response_with_encrypt(msg.itf, keypair->aesKey, MSG_RESULT_OK, msg.message_type, msg.message_id, msg.pubkey, iv, sig_bin, NOSTR_EVENT_SIG_BIN_LEN);
            }
            else if (msg.message_type == MSG_TYPE_NOSTR_NIP04_ENCRYPT || msg.message_type == MSG_TYPE_NOSTR_NIP04_DECRYPT || msg.message_type == MSG_TYPE_NOSTR_NIP44_ENCRYPT || msg.message_type == MSG_TYPE_NOSTR_NIP44_DECRYPT)
            {
                uint8_t their_pubkey_bin[PUBKEY_LEN];
                memcpy(their_pubkey_bin, decrypted, PUBKEY_LEN);

                size_t source_len = decrypted_len - PUBKEY_LEN;
                char source_text[source_len + 1] = {};
                memcpy(source_text, decrypted + PUBKEY_LEN, source_len);
                source_text[source_len] = 0;

                char *result_content = NULL;

                if (msg.message_type == MSG_TYPE_NOSTR_NIP04_ENCRYPT)
                {
                    if (nip04_encrypt(keypair->privateKey, their_pubkey_bin, source_text, &result_content) != 0)
                    {
                        free(decrypted);
                        goto sendfail;
                    }

                    send_response_with_encrypt(msg.itf, keypair->aesKey, MSG_RESULT_OK, msg.message_type, msg.message_id, msg.pubkey, iv, (uint8_t *)result_content, strlen(result_content));
                }
                else if (msg.message_type == MSG_TYPE_NOSTR_NIP04_DECRYPT)
                {
                    if (nip04_decrypt(keypair->privateKey, their_pubkey_bin, source_text, &result_content) != 0)
                    {
                        free(decrypted);
                        goto sendfail;
                    }

                    send_response_with_encrypt(msg.itf, keypair->aesKey, MSG_RESULT_OK, msg.message_type, msg.message_id, msg.pubkey, iv, (uint8_t *)result_content, strlen(result_content));
                }
                else if (msg.message_type == MSG_TYPE_NOSTR_NIP44_ENCRYPT)
                {
                    if (nip44_encrypt(keypair->privateKey, their_pubkey_bin, source_text, &result_content) != 0)
                    {
                        free(decrypted);
                        goto sendfail;
                    }

                    send_response_with_encrypt(msg.itf, keypair->aesKey, MSG_RESULT_OK, msg.message_type, msg.message_id, msg.pubkey, iv, (uint8_t *)result_content, strlen(result_content));
                }
                else if (msg.message_type == MSG_TYPE_NOSTR_NIP44_DECRYPT)
                {
                    char *result_content = NULL;
                    if (nip44_decrypt(keypair->privateKey, their_pubkey_bin, source_text, &result_content) != 0)
                    {
                        free(decrypted);
                        goto sendfail;
                    }

                    send_response_with_encrypt(msg.itf, keypair->aesKey, MSG_RESULT_OK, msg.message_type, msg.message_id, msg.pubkey, iv, (uint8_t *)result_content, strlen(result_content));
                }
            }

            free(decrypted);
            goto cleanup;

        sendillegal:
            send_response(msg.itf, MSG_RESULT_CONTENT_ILLEGAL, msg.message_type, msg.message_id, msg.pubkey, msg.iv, NULL, 0);
            goto cleanup;
        sendfail:
            send_response(msg.itf, MSG_RESULT_FAIL, msg.message_type, msg.message_id, msg.pubkey, msg.iv, NULL, 0);
            goto cleanup;
        cleanup:
            free(msg.message);
        }
    }
}

#define PROTOCOL_BUFFER_SIZE 4096
static uint8_t s_proto_msg_buffer[PROTOCOL_BUFFER_SIZE];
static size_t s_proto_msg_buffer_size = 0;
static uint64_t s_start_read_time = 0;

static void on_raw_rx_data(uint8_t itf, const uint8_t *data, size_t rx_size)
{
    uint64_t current_time = esp_timer_get_time() / 1000;
    if (s_start_read_time > 0 && (current_time - s_start_read_time) >= READ_TIMEOUT_MS)
    {
        ESP_LOGE(TAG, "Transport read timeout");
        s_proto_msg_buffer_size = 0;
        s_start_read_time = 0;
    }

    if (s_start_read_time == 0)
    {
        s_start_read_time = current_time;
    }

    if (s_proto_msg_buffer_size + rx_size > PROTOCOL_BUFFER_SIZE)
    {
        ESP_LOGE(TAG, "Protocol buffer overflow, resetting");
        s_proto_msg_buffer_size = 0;
        s_start_read_time = 0;
        return;
    }

    memcpy(s_proto_msg_buffer + s_proto_msg_buffer_size, data, rx_size);
    s_proto_msg_buffer_size += rx_size;

    while (s_proto_msg_buffer_size >= REQUEST_HEAD_LEN)
    {
        size_t offset = 0;

        uint8_t type[TYPE_SIZE];
        memcpy(type, s_proto_msg_buffer + offset, TYPE_SIZE);
        offset += TYPE_SIZE;

        uint8_t id[ID_SIZE];
        memcpy(id, s_proto_msg_buffer + offset, ID_SIZE);
        offset += ID_SIZE;

        uint8_t pubkey[PUBKEY_SIZE];
        memcpy(pubkey, s_proto_msg_buffer + offset, PUBKEY_SIZE);
        offset += PUBKEY_SIZE;

        uint8_t iv[IV_SIZE];
        memcpy(iv, s_proto_msg_buffer + offset, IV_SIZE);
        offset += IV_SIZE;

        uint8_t header[HEADER_SIZE];
        memcpy(header, s_proto_msg_buffer + offset, HEADER_SIZE);
        offset += HEADER_SIZE;

        uint32_t data_len = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];
        size_t whole_msg_len = REQUEST_HEAD_LEN + data_len + CRC_SIZE;

        if (s_proto_msg_buffer_size < whole_msg_len)
        {
            return;
        }

        uint8_t crc[CRC_SIZE];
        memcpy(crc, s_proto_msg_buffer + REQUEST_HEAD_LEN + data_len, CRC_SIZE);

        uint16_t received_crc = (crc[0] << 8) | crc[1];
        uint16_t computed_crc = crc16(s_proto_msg_buffer, REQUEST_HEAD_LEN + data_len);
        if (computed_crc != received_crc)
        {
            ESP_LOGE(TAG, "CRC check failed");
            s_proto_msg_buffer_size -= whole_msg_len;
            memmove(s_proto_msg_buffer, s_proto_msg_buffer + whole_msg_len, s_proto_msg_buffer_size);
            s_start_read_time = 0;
            return;
        }

        message_t message = {
            .itf = itf,
            .message_type = (type[0] << 8) | type[1],
            .message_len = data_len};
        memcpy(message.message_id, id, ID_SIZE);
        memcpy(message.pubkey, pubkey, PUBKEY_SIZE);
        memcpy(message.iv, iv, IV_SIZE);

        if (data_len > 0)
        {
            message.message = malloc(data_len);
            if (!message.message)
            {
                ESP_LOGE(TAG, "Failed to allocate memory for encrypted data");
                s_proto_msg_buffer_size -= whole_msg_len;
                memmove(s_proto_msg_buffer, s_proto_msg_buffer + whole_msg_len, s_proto_msg_buffer_size);
                s_start_read_time = 0;
                return;
            }
            memcpy(message.message, s_proto_msg_buffer + REQUEST_HEAD_LEN, data_len);
        }

        s_proto_msg_buffer_size -= whole_msg_len;
        memmove(s_proto_msg_buffer, s_proto_msg_buffer + whole_msg_len, s_proto_msg_buffer_size);

        if (xQueueSend(message_queue, &message, pdMS_TO_TICKS(100)) != pdPASS)
        {
            ESP_LOGE(TAG, "Failed to send message to queue - queue full");
            if (data_len > 0)
            {
                free(message.message);
            }
        }

        s_start_read_time = 0;
    }
}

// 处理响应的 Task
void handle_response_task(void *pvParameters)
{
    while (1)
    {
        response_t response;
        if (xQueueReceive(response_queue, &response, portMAX_DELAY))
        {
            signer_transport_send(response.itf, response.data, response.data_len);

            if (response.pool_buffer != NULL)
                memory_pool_release(response.pool_buffer);
            else
                free(response.data);
        }
    }
}

void app_main(void)
{
    if (!memory_pool_init())
    {
        ESP_LOGE(TAG, "Failed to initialize memory pool");
        return;
    }

    if (gen_private_key(temp_private_key) == -1)
    {
        ESP_LOGI("Test", "gen temp private key fail");
        memory_pool_destroy();
        return;
    }

    initStorage();

    message_queue = xQueueCreate(QUEUE_SIZE, sizeof(message_t));
    if (message_queue == NULL)
    {
        ESP_LOGE(TAG, "Failed to create message queue");
        memory_pool_destroy();
        return;
    }

    response_queue = xQueueCreate(QUEUE_SIZE, sizeof(response_t));
    if (response_queue == NULL)
    {
        ESP_LOGE(TAG, "Failed to create response queue");
        memory_pool_destroy();
        return;
    }

    esp_err_t err = signer_transport_init(on_raw_rx_data);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to initialize signer transport: %s", esp_err_to_name(err));
        return;
    }

    xTaskCreate(handle_message_task, "handle_message_task", TASK_STACK_SIZE, NULL, 10, NULL);
    xTaskCreate(handle_response_task, "handle_response_task", 8192, NULL, 8, NULL);

    ESP_LOGI(TAG, "nesigner started with multi-target transport support");
}