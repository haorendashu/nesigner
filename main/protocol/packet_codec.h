#ifndef PACKET_CODEC_H
#define PACKET_CODEC_H

#include "signer_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

uint16_t crc16(const uint8_t *data, size_t len);
void generate_random_iv(uint8_t iv[IV_SIZE]);

void send_response(uint8_t itf, uint16_t message_result, uint16_t message_type,
                   const uint8_t *message_id, const uint8_t *pubkey, const uint8_t *iv,
                   const uint8_t *message, int message_len);

void send_response_with_encrypt(uint8_t itf, uint8_t *aesKey, uint16_t message_result,
                                uint16_t message_type, const uint8_t *message_id,
                                const uint8_t *pubkey, const uint8_t *iv,
                                const uint8_t *message, int message_len);

#ifdef __cplusplus
}
#endif

#endif // PACKET_CODEC_H
