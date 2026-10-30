#ifndef NOSTR_NIP01_H
#define NOSTR_NIP01_H

#include <stdint.h>
#include <stddef.h>
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NOSTR_EVENT_ID_BIN_LEN   32
#define NOSTR_EVENT_ID_HEX_LEN   64
#define NOSTR_EVENT_SIG_BIN_LEN  64
#define NOSTR_EVENT_SIG_HEX_LEN  128

/**
 * @brief Calculate Nostr Event ID (SHA-256 of canonical JSON serialized event array)
 * @param pubkey_hex 64-character hex public key
 * @param created_at Unix timestamp
 * @param kind Event kind
 * @param tags cJSON array of tags
 * @param content Event content string
 * @param event_id_hex Output buffer of at least 65 bytes (64 hex chars + null terminator)
 * @return 0 on success, -1 on failure
 */
int nostr_nip01_gen_event_id(const char *pubkey_hex, uint32_t created_at, uint16_t kind,
                             cJSON *tags, const char *content, char *event_id_hex);

/**
 * @brief Sign an event ID hash using BIP-340 Schnorr signature via Crypto HAL
 * @param privkey_bin 32-byte private key
 * @param event_id_bin 32-byte event ID hash
 * @param sig_bin Output buffer for 64-byte signature
 * @return 0 on success, -1 on failure
 */
int nostr_nip01_sign_event(const uint8_t *privkey_bin,
                           const uint8_t *event_id_bin,
                           uint8_t *sig_bin);

#ifdef __cplusplus
}
#endif

#endif // NOSTR_NIP01_H
