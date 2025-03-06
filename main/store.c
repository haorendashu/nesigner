#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "nostr.h"
#include "store.h"

static const char *NVS_NAMESPACE = "keypair_store";

KeyPair *keypairs = NULL;
size_t keypair_count = 0;

/* 辅助函数 ------------------------------------------------------------*/

// 保存函数
static bool save_to_nvs()
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle) != ESP_OK)
    {
        return false;
    }

    // 转换为存储格式
    StoredKeyPair *storage = malloc(keypair_count * sizeof(StoredKeyPair));
    if (!storage)
    {
        nvs_close(handle);
        return false;
    }

    for (size_t i = 0; i < keypair_count; i++)
    {
        memcpy(storage[i].aesKey, keypairs[i].aesKey, AES_KEY_LEN);
        memcpy(storage[i].privateKey, keypairs[i].privateKey, PRIVATE_KEY_LEN);
    }

    esp_err_t err = nvs_set_blob(handle, "keypairs", storage,
                                 keypair_count * sizeof(StoredKeyPair));
    free(storage);

    if (err != ESP_OK)
    {
        nvs_close(handle);
        return false;
    }

    err = nvs_commit(handle);
    nvs_close(handle);
    return err == ESP_OK;
}

/* 核心接口 ------------------------------------------------------------*/

bool loadAllKeyPairs()
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle) != ESP_OK)
    {
        return true; // 视为空数据
    }

    size_t required_size = 0;
    if (nvs_get_blob(handle, "keypairs", NULL, &required_size) != ESP_OK)
    {
        nvs_close(handle);
        return true;
    }

    if (required_size % sizeof(StoredKeyPair) != 0)
    {
        nvs_close(handle);
        return false;
    }

    StoredKeyPair *storage = malloc(required_size);
    if (!storage || nvs_get_blob(handle, "keypairs", storage, &required_size) != ESP_OK)
    {
        nvs_close(handle);
        free(storage);
        return false;
    }
    nvs_close(handle);

    size_t count = required_size / sizeof(StoredKeyPair);
    KeyPair *new_pairs = malloc(count * sizeof(KeyPair));
    if (!new_pairs)
    {
        free(storage);
        return false;
    }

    for (size_t i = 0; i < count; i++)
    {
        memcpy(new_pairs[i].aesKey, storage[i].aesKey, AES_KEY_LEN);
        memcpy(new_pairs[i].privateKey, storage[i].privateKey, PRIVATE_KEY_LEN);

        if (get_public(new_pairs[i].privateKey, new_pairs[i].pubkey) != 0)
        {
            free(storage);
            free(new_pairs);
            return false;
        }
    }

    free(keypairs);
    keypairs = new_pairs;
    keypair_count = count;
    free(storage);
    return true;
}

bool addAndSaveKeyPair(const KeyPair *pair)
{
    // 简化参数校验（仅检查指针有效性）
    if (!pair)
        return false;

    KeyPair *new_ptr = realloc(keypairs, (keypair_count + 1) * sizeof(KeyPair));
    if (!new_ptr)
        return false;

    keypairs = new_ptr;
    memcpy(keypairs[keypair_count].aesKey, pair->aesKey, AES_KEY_LEN);
    memcpy(keypairs[keypair_count].privateKey, pair->privateKey, PRIVATE_KEY_LEN);

    if (get_public(pair->privateKey, keypairs[keypair_count].pubkey) != 0)
    {
        return false;
    }

    keypair_count++;
    return save_to_nvs();
}

bool removeAndSaveKeyPair(const uint8_t *aesKey)
{
    if (!aesKey)
        return false;

    for (size_t i = 0; i < keypair_count; i++)
    {
        if (memcmp(keypairs[i].aesKey, aesKey, AES_KEY_LEN) == 0)
        {
            // 移动剩余元素
            if (i < keypair_count - 1)
            {
                memmove(&keypairs[i], &keypairs[i + 1],
                        (keypair_count - i - 1) * sizeof(KeyPair));
            }

            KeyPair *new_ptr = realloc(keypairs, (keypair_count - 1) * sizeof(KeyPair));
            if (!new_ptr && keypair_count > 1)
            {
                return false;
            }

            keypairs = new_ptr;
            keypair_count--;
            return save_to_nvs();
        }
    }
    return false;
}

KeyPair *findKeyPairByPubkey(const uint8_t *pubkey)
{
    if (!pubkey)
        return NULL;

    for (size_t i = 0; i < keypair_count; i++)
    {
        if (memcmp(keypairs[i].pubkey, pubkey, PUBKEY_LEN) == 0)
        {
            return &keypairs[i];
        }
    }
    return NULL;
}

void initStorage()
{
    esp_err_t ret = nvs_flash_init();
    ESP_ERROR_CHECK(ret);

    if (!loadAllKeyPairs())
    {
        ESP_LOGE("STORAGE", "Failed to load keypairs");
    }
}