#include "nostr_nip01.h"
#include "signer_crypto.h"
#include "utils.h"
#include "esp_log.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "NOSTR_NIP01";

int nostr_nip01_gen_event_id(const char *pubkey_hex, uint32_t created_at, uint16_t kind,
                             cJSON *tags, const char *content, char *event_id_hex)
{
    if (!pubkey_hex || !content || !event_id_hex) {
        return -1;
    }

    cJSON *event_array = cJSON_CreateArray();
    if (!event_array) {
        ESP_LOGE(TAG, "Failed to allocate cJSON array for event ID");
        return -1;
    }

    cJSON_AddItemToArray(event_array, cJSON_CreateNumber(0));
    cJSON_AddItemToArray(event_array, cJSON_CreateString(pubkey_hex));
    cJSON_AddItemToArray(event_array, cJSON_CreateNumber(created_at));
    cJSON_AddItemToArray(event_array, cJSON_CreateNumber(kind));
    cJSON_AddItemToArray(event_array, cJSON_Duplicate(tags, 1));
    cJSON_AddItemToArray(event_array, cJSON_CreateString(content));

    char *json_str = cJSON_PrintUnformatted(event_array);
    cJSON_Delete(event_array);

    if (!json_str) {
        ESP_LOGE(TAG, "Failed to serialize event array to JSON");
        return -1;
    }

    uint8_t hash[32];
    int ret = crypto_sha256((const uint8_t *)json_str, strlen(json_str), hash);
    free(json_str);

    if (ret != 0) {
        return -1;
    }

    bin_to_hex(hash, 32, event_id_hex);
    return 0;
}

int nostr_nip01_sign_event(const uint8_t *privkey_bin,
                           const uint8_t *event_id_bin,
                           uint8_t *sig_bin)
{
    if (!privkey_bin || !event_id_bin || !sig_bin) {
        return -1;
    }

    // BIP-340 Schnorr sign using Crypto HAL (which provides 10x acceleration via libsecp256k1)
    return crypto_secp256k1_schnorr_sign(privkey_bin, event_id_bin, NULL, sig_bin);
}
