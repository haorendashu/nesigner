#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "nvs_flash.h"
#include "nostr.h"
#include "store.h"

static const char *NVS_NAMESPACE = "keypair_store";

static KeyPair *keypairs = NULL;
static size_t keypair_count = 0;

/* 辅助函数 ------------------------------------------------------------*/

// 验证HEX字符串格式
static bool is_valid_hex(const char *str, size_t expect_len)
{
    if (strnlen(str, expect_len + 1) != expect_len)
        return false;
    for (size_t i = 0; i < expect_len; i++)
    {
        if (!isxdigit((unsigned char)str[i]))
            return false;
    }
    return true;
}

// 安全保存到NVS
static bool save_to_nvs()
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle) != ESP_OK)
    {
        return false;
    }

    esp_err_t err = nvs_set_blob(handle, "keypairs", keypairs,
                                 keypair_count * sizeof(StoredKeyPair));
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

bool loadAll()
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

    // 验证数据完整性
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
    KeyPair *new_pairs = calloc(count, sizeof(KeyPair));
    if (!new_pairs)
    {
        free(storage);
        return false;
    }

    // 转换存储格式并计算公钥
    for (size_t i = 0; i < count; i++)
    {
        memcpy(new_pairs[i].aesKey, storage[i].aesKey, 33);
        memcpy(new_pairs[i].privateKey, storage[i].privateKey, 65);

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

bool addAndSave(const KeyPair *pair)
{
    // 严格参数校验
    if (!is_valid_hex(pair->aesKey, 32) ||
        !is_valid_hex(pair->privateKey, 64) ||
        strnlen(pair->aesKey, 33) != 32 ||
        strnlen(pair->privateKey, 65) != 64)
    {
        return false;
    }

    KeyPair *new_ptr = realloc(keypairs, (keypair_count + 1) * sizeof(KeyPair));
    if (!new_ptr)
        return false;

    keypairs = new_ptr;
    memcpy(keypairs[keypair_count].aesKey, pair->aesKey, 33);
    memcpy(keypairs[keypair_count].privateKey, pair->privateKey, 65);

    // 计算公钥
    if (get_public(pair->privateKey, keypairs[keypair_count].pubkey) != 0)
    {
        return false;
    }

    keypair_count++;
    return save_to_nvs();
}

bool removeAndSave(const char *aesKey)
{
    if (!is_valid_hex(aesKey, 32))
        return false;

    for (size_t i = 0; i < keypair_count; i++)
    {
        if (memcmp(keypairs[i].aesKey, aesKey, 32) == 0)
        {
            // 内存移动优化
            if (i < keypair_count - 1)
            {
                memmove(&keypairs[i], &keypairs[i + 1],
                        (keypair_count - i - 1) * sizeof(KeyPair));
            }

            KeyPair *new_ptr = realloc(keypairs, (keypair_count - 1) * sizeof(KeyPair));
            if (keypair_count > 1 && !new_ptr)
                return false;

            keypairs = new_ptr;
            keypair_count--;
            return save_to_nvs();
        }
    }
    return false;
}

const KeyPair *findByAesKey(const char *aesKey)
{
    if (!is_valid_hex(aesKey, 32))
        return NULL;

    for (size_t i = 0; i < keypair_count; i++)
    {
        if (memcmp(keypairs[i].aesKey, aesKey, 32) == 0)
        {
            return &keypairs[i];
        }
    }
    return NULL;
}

void init_storage()
{
    esp_err_t ret = nvs_flash_init();
    // if (ret == ESP_ERR_NVS_NO_FREE_PAGES)
    // {
    //     ESP_ERROR_CHECK(nvs_flash_erase());
    //     ret = nvs_flash_init();
    // }
    ESP_ERROR_CHECK(ret);

    if (!loadAll())
    {
        ESP_LOGE("STORAGE", "Failed to load keypairs");
    }
}