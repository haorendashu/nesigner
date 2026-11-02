#include "command_router.h"
#include "packet_codec.h"
#include "session_crypto.h"
#include "signer_storage.h"
#include "signer_crypto.h"
#include "nostr_nip01.h"
#include "nostr_nip04.h"
#include "nostr_nip44.h"
#include "msg_type.h"
#include "msg_result.h"
#include "utils.h"
#include "esp_log.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "COMMAND_ROUTER";

void command_router_dispatch(const message_t *msg)
{
    if (!msg) return;

    uint8_t iv[IV_SIZE];
    generate_random_iv(iv);

    // 1. PING
    if (msg->message_type == MSG_TYPE_PING) {
        send_response(msg->itf, MSG_RESULT_OK, msg->message_type, msg->message_id, msg->pubkey, msg->iv, msg->message, 0);
        return;
    }

    // 2. ECHO
    if (msg->message_type == MSG_TYPE_ECHO) {
        send_response(msg->itf, MSG_RESULT_OK, msg->message_type, msg->message_id, msg->pubkey, msg->iv, msg->message, msg->message_len);
        return;
    }

    // 3. GET_TEMP_PUBKEY
    if (msg->message_type == MSG_TYPE_GET_TEMP_PUBKEY) {
        uint8_t temp_pubkey[PUBKEY_LEN];
        if (session_crypto_get_temp_pubkey(temp_pubkey) != 0) {
            send_response(msg->itf, MSG_RESULT_KEY_NOT_FOUND, msg->message_type, msg->message_id, msg->pubkey, msg->iv, NULL, 0);
            return;
        }
        send_response(msg->itf, MSG_RESULT_OK, msg->message_type, msg->message_id, msg->pubkey, msg->iv, temp_pubkey, PUBKEY_LEN);
        return;
    }

    // 4. UPDATE_KEY (add new keypair encrypted with temp_private_key)
    if (msg->message_type == MSG_TYPE_UPDATE_KEY) {
        if (msg->message_len < PRIVATE_KEY_LEN + AES_KEY_LEN) {
            const char *err = "Payload too short";
            send_response(msg->itf, MSG_RESULT_CONTENT_ILLEGAL, msg->message_type, msg->message_id, msg->pubkey, msg->iv, (const uint8_t *)err, strlen(err));
            return;
        }

        char *decrypted_content = NULL;
        char *encrypted_content = (char *)malloc(msg->message_len + 1);
        if (!encrypted_content) {
            const char *err = "Out of memory";
            send_response(msg->itf, MSG_RESULT_KEY_NOT_FOUND, msg->message_type, msg->message_id, msg->pubkey, msg->iv, (const uint8_t *)err, strlen(err));
            return;
        }
        memcpy(encrypted_content, msg->message, msg->message_len);
        encrypted_content[msg->message_len] = '\0';

        if (nostr_nip44_decrypt(temp_private_key, msg->pubkey, encrypted_content, &decrypted_content) != 0) {
            free(encrypted_content);
            const char *err = "NIP-44 decrypt failed (HMAC/Base64)";
            send_response(msg->itf, MSG_RESULT_CONTENT_ILLEGAL, msg->message_type, msg->message_id, msg->pubkey, msg->iv, (const uint8_t *)err, strlen(err));
            return;
        }
        free(encrypted_content);

        if (!decrypted_content || strlen(decrypted_content) < PRIVATE_KEY_LEN * 2 + AES_KEY_LEN * 2) {
            if (decrypted_content) free(decrypted_content);
            const char *err = "Decrypted content too short (<96 hex chars)";
            send_response(msg->itf, MSG_RESULT_CONTENT_ILLEGAL, msg->message_type, msg->message_id, msg->pubkey, msg->iv, (const uint8_t *)err, strlen(err));
            return;
        }

        char private_key_hex[PRIVATE_KEY_LEN * 2 + 1];
        char aes_key_hex[AES_KEY_LEN * 2 + 1];
        private_key_hex[PRIVATE_KEY_LEN * 2] = '\0';
        aes_key_hex[AES_KEY_LEN * 2] = '\0';

        memcpy(private_key_hex, decrypted_content, PRIVATE_KEY_LEN * 2);
        memcpy(aes_key_hex, decrypted_content + PRIVATE_KEY_LEN * 2, AES_KEY_LEN * 2);
        free(decrypted_content);

        KeyPair kp;
        if (hex_to_bin(private_key_hex, kp.privateKey, PRIVATE_KEY_LEN) != 0 ||
            hex_to_bin(aes_key_hex, kp.aesKey, AES_KEY_LEN) != 0) {
            const char *err = "Invalid hex in decrypted key";
            send_response(msg->itf, MSG_RESULT_CONTENT_ILLEGAL, msg->message_type, msg->message_id, msg->pubkey, msg->iv, (const uint8_t *)err, strlen(err));
            return;
        }

        if (signer_storage_add(&kp)) {
            send_response(msg->itf, MSG_RESULT_OK, msg->message_type, msg->message_id, msg->pubkey, msg->iv, NULL, 0);
        } else {
            const char *err = "Failed to save keypair to NVS";
            send_response(msg->itf, MSG_RESULT_KEY_NOT_FOUND, msg->message_type, msg->message_id, msg->pubkey, msg->iv, (const uint8_t *)err, strlen(err));
        }
        return;
    }

    // 5. GET_PUBLIC_KEY / REMOVE_KEY (scan keypairs by attempting decrypt)
    if (msg->message_type == MSG_TYPE_NOSTR_GET_PUBLIC_KEY || msg->message_type == MSG_TYPE_REMOVE_KEY) {
        for (size_t i = 0; i < keypair_count; i++) {
            KeyPair kp = keypairs[i];
            uint8_t *decrypted = NULL;
            size_t decrypted_len = 0;
            if (crypto_aes_decrypt_padded(kp.aesKey, 16, msg->iv, msg->message, msg->message_len,
                                          &decrypted, &decrypted_len) != 0) {
                continue;
            }

            if (decrypted_len == IV_SIZE && memcmp(decrypted, msg->iv, IV_SIZE) == 0) {
                free(decrypted);
                if (msg->message_type == MSG_TYPE_NOSTR_GET_PUBLIC_KEY) {
                    send_response_with_encrypt(msg->itf, kp.aesKey, MSG_RESULT_OK, msg->message_type,
                                               msg->message_id, kp.pubkey, iv, kp.pubkey, PUBKEY_LEN);
                    return;
                } else if (msg->message_type == MSG_TYPE_REMOVE_KEY) {
                    if (signer_storage_remove(kp.aesKey)) {
                        send_response(msg->itf, MSG_RESULT_OK, msg->message_type, msg->message_id, msg->pubkey, iv, NULL, 0);
                    } else {
                        send_response(msg->itf, MSG_RESULT_KEY_NOT_FOUND, msg->message_type, msg->message_id, msg->pubkey, iv, NULL, 0);
                    }
                    return;
                }
            }
            free(decrypted);
        }

        send_response(msg->itf, MSG_RESULT_KEY_NOT_FOUND, msg->message_type, msg->message_id, msg->pubkey, msg->iv, NULL, 0);
        return;
    }

    // Messages below require existing keypair matching msg->pubkey
    if (msg->message_len <= 0) {
        send_response(msg->itf, MSG_RESULT_CONTENT_NOT_ALLOW_EMPTY, msg->message_type, msg->message_id, msg->pubkey, msg->iv, NULL, 0);
        return;
    }

    KeyPair *keypair = signer_storage_find_by_pubkey(msg->pubkey);
    if (!keypair) {
        send_response(msg->itf, MSG_RESULT_KEY_NOT_FOUND, msg->message_type, msg->message_id, msg->pubkey, msg->iv, NULL, 0);
        return;
    }

    uint8_t *decrypted = NULL;
    size_t decrypted_len = 0;
    if (crypto_aes_decrypt_padded(keypair->aesKey, 16, msg->iv, msg->message, msg->message_len,
                                  &decrypted, &decrypted_len) != 0) {
        ESP_LOGE(TAG, "AES decryption of payload failed");
        send_response(msg->itf, MSG_RESULT_CONTENT_ILLEGAL, msg->message_type, msg->message_id, msg->pubkey, msg->iv, NULL, 0);
        return;
    }

    // 6. SIGN_EVENT
    if (msg->message_type == MSG_TYPE_NOSTR_SIGN_EVENT) {
        if (decrypted_len != NOSTR_EVENT_ID_BIN_LEN) {
            free(decrypted);
            send_response(msg->itf, MSG_RESULT_CONTENT_ILLEGAL, msg->message_type, msg->message_id, msg->pubkey, msg->iv, NULL, 0);
            return;
        }

        uint8_t sig_bin[NOSTR_EVENT_SIG_BIN_LEN];
        if (nostr_nip01_sign_event(keypair->privateKey, decrypted, sig_bin) != 0) {
            free(decrypted);
            send_response(msg->itf, MSG_RESULT_KEY_NOT_FOUND, msg->message_type, msg->message_id, msg->pubkey, iv, NULL, 0);
            return;
        }

        free(decrypted);
        send_response_with_encrypt(msg->itf, keypair->aesKey, MSG_RESULT_OK, msg->message_type,
                                   msg->message_id, msg->pubkey, iv, sig_bin, NOSTR_EVENT_SIG_BIN_LEN);
        return;
    }

    // 7. NIP-04 & NIP-44 ENCRYPT / DECRYPT
    if (msg->message_type == MSG_TYPE_NOSTR_NIP04_ENCRYPT ||
        msg->message_type == MSG_TYPE_NOSTR_NIP04_DECRYPT ||
        msg->message_type == MSG_TYPE_NOSTR_NIP44_ENCRYPT ||
        msg->message_type == MSG_TYPE_NOSTR_NIP44_DECRYPT) {

        if (decrypted_len < PUBKEY_LEN) {
            free(decrypted);
            send_response(msg->itf, MSG_RESULT_CONTENT_ILLEGAL, msg->message_type, msg->message_id, msg->pubkey, msg->iv, NULL, 0);
            return;
        }

        uint8_t their_pubkey_bin[PUBKEY_LEN];
        memcpy(their_pubkey_bin, decrypted, PUBKEY_LEN);

        size_t source_len = decrypted_len - PUBKEY_LEN;
        char *source_text = (char *)malloc(source_len + 1);
        if (!source_text) {
            free(decrypted);
            send_response(msg->itf, MSG_RESULT_KEY_NOT_FOUND, msg->message_type, msg->message_id, msg->pubkey, iv, NULL, 0);
            return;
        }
        memcpy(source_text, decrypted + PUBKEY_LEN, source_len);
        source_text[source_len] = '\0';
        free(decrypted);

        char *result_content = NULL;
        int status = -1;

        if (msg->message_type == MSG_TYPE_NOSTR_NIP04_ENCRYPT) {
            status = nostr_nip04_encrypt(keypair->privateKey, their_pubkey_bin, source_text, &result_content);
        } else if (msg->message_type == MSG_TYPE_NOSTR_NIP04_DECRYPT) {
            status = nostr_nip04_decrypt(keypair->privateKey, their_pubkey_bin, source_text, &result_content);
        } else if (msg->message_type == MSG_TYPE_NOSTR_NIP44_ENCRYPT) {
            status = nostr_nip44_encrypt(keypair->privateKey, their_pubkey_bin, source_text, &result_content);
        } else if (msg->message_type == MSG_TYPE_NOSTR_NIP44_DECRYPT) {
            status = nostr_nip44_decrypt(keypair->privateKey, their_pubkey_bin, source_text, &result_content);
        }
        free(source_text);

        if (status == 0 && result_content != NULL) {
            send_response_with_encrypt(msg->itf, keypair->aesKey, MSG_RESULT_OK, msg->message_type,
                                       msg->message_id, msg->pubkey, iv,
                                       (const uint8_t *)result_content, (int)strlen(result_content));
            free(result_content);
        } else {
            send_response(msg->itf, MSG_RESULT_KEY_NOT_FOUND, msg->message_type, msg->message_id, msg->pubkey, iv, NULL, 0);
        }
        return;
    }

    free(decrypted);
    send_response(msg->itf, MSG_RESULT_KEY_NOT_FOUND, msg->message_type, msg->message_id, msg->pubkey, msg->iv, NULL, 0);
}
