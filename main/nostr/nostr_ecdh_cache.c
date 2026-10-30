#include "nostr_ecdh_cache.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include <string.h>

static const char *TAG = "NOSTR_ECDH_CACHE";

typedef struct {
    uint8_t our_pubkey[32];
    uint8_t their_pubkey[32];
    uint8_t shared_secret[32];
    uint32_t access_tick;
    bool valid;
} ecdh_cache_entry_t;

static ecdh_cache_entry_t s_cache[NOSTR_ECDH_CACHE_CAPACITY];
static uint32_t s_access_counter = 0;
static SemaphoreHandle_t s_mutex = NULL;

void nostr_ecdh_cache_init(void)
{
    if (s_mutex == NULL) {
        s_mutex = xSemaphoreCreateMutex();
    }
    nostr_ecdh_cache_clear();
}

void nostr_ecdh_cache_clear(void)
{
    if (s_mutex && xSemaphoreTake(s_mutex, portMAX_DELAY) == pdTRUE) {
        memset(s_cache, 0, sizeof(s_cache));
        s_access_counter = 0;
        xSemaphoreGive(s_mutex);
    } else {
        memset(s_cache, 0, sizeof(s_cache));
        s_access_counter = 0;
    }
}

bool nostr_ecdh_cache_get(const uint8_t our_pubkey[32],
                          const uint8_t their_pubkey[32],
                          uint8_t shared_secret[32])
{
    if (!our_pubkey || !their_pubkey || !shared_secret) return false;

    if (s_mutex == NULL) {
        nostr_ecdh_cache_init();
    }

    bool hit = false;
    if (xSemaphoreTake(s_mutex, portMAX_DELAY) == pdTRUE) {
        for (size_t i = 0; i < NOSTR_ECDH_CACHE_CAPACITY; i++) {
            if (s_cache[i].valid &&
                memcmp(s_cache[i].our_pubkey, our_pubkey, 32) == 0 &&
                memcmp(s_cache[i].their_pubkey, their_pubkey, 32) == 0) {
                memcpy(shared_secret, s_cache[i].shared_secret, 32);
                s_cache[i].access_tick = ++s_access_counter;
                hit = true;
                break;
            }
        }
        xSemaphoreGive(s_mutex);
    }

    if (hit) {
        ESP_LOGD(TAG, "ECDH cache HIT");
    }
    return hit;
}

void nostr_ecdh_cache_put(const uint8_t our_pubkey[32],
                          const uint8_t their_pubkey[32],
                          const uint8_t shared_secret[32])
{
    if (!our_pubkey || !their_pubkey || !shared_secret) return;

    if (s_mutex == NULL) {
        nostr_ecdh_cache_init();
    }

    if (xSemaphoreTake(s_mutex, portMAX_DELAY) == pdTRUE) {
        size_t target_idx = 0;
        uint32_t min_tick = UINT32_MAX;
        bool found_slot = false;

        // 1. Search for existing entry to update, or first empty slot
        for (size_t i = 0; i < NOSTR_ECDH_CACHE_CAPACITY; i++) {
            if (s_cache[i].valid &&
                memcmp(s_cache[i].our_pubkey, our_pubkey, 32) == 0 &&
                memcmp(s_cache[i].their_pubkey, their_pubkey, 32) == 0) {
                target_idx = i;
                found_slot = true;
                break;
            }
            if (!s_cache[i].valid && !found_slot) {
                target_idx = i;
                found_slot = true;
            }
            if (s_cache[i].valid && s_cache[i].access_tick < min_tick) {
                min_tick = s_cache[i].access_tick;
                if (!found_slot) {
                    target_idx = i;
                }
            }
        }

        // If all valid and no existing match, target_idx holds least recently used
        memcpy(s_cache[target_idx].our_pubkey, our_pubkey, 32);
        memcpy(s_cache[target_idx].their_pubkey, their_pubkey, 32);
        memcpy(s_cache[target_idx].shared_secret, shared_secret, 32);
        s_cache[target_idx].access_tick = ++s_access_counter;
        s_cache[target_idx].valid = true;

        xSemaphoreGive(s_mutex);
    }
}
