#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "nostr.h"
#include "store.h"
#include "utils.h"

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

    esp_err_t err;

    // 处理空数组：直接写入长度为0的blob
    if (keypair_count == 0)
    {
        err = nvs_set_blob(handle, "keypairs", NULL, 0); // 关键修改点
        if (err != ESP_OK)
        {
            nvs_close(handle);
            return false;
        }
        err = nvs_commit(handle);
        nvs_close(handle);
        return err == ESP_OK;
    }

    // 非空数组的正常处理
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

    err = nvs_set_blob(handle, "keypairs", storage, keypair_count * sizeof(StoredKeyPair));
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

        char pubkey_hex[PUBKEY_LEN * 2 + 1] = {0};
        bin_to_hex(new_pairs[i].pubkey, PUBKEY_LEN, pubkey_hex);
        char aeskey_hex[AES_KEY_LEN * 2 + 1] = {0};
        bin_to_hex(new_pairs[i].aesKey, AES_KEY_LEN, aeskey_hex);
        printf("Loaded Pubkey: %s %s \n", aeskey_hex, pubkey_hex);
        printByteArrayAsDec((char *)(new_pairs[i].pubkey), PUBKEY_LEN);
    }

    free(keypairs);
    keypairs = new_pairs;
    keypair_count = count;
    free(storage);
    return true;
}

bool addAndSaveKeyPair(const KeyPair *pair)
{
    if (!pair)
        return false;

    // 检查是否已存在相同的 aesKey
    for (size_t i = 0; i < keypair_count; i++)
    {
        if (memcmp(keypairs[i].aesKey, pair->aesKey, AES_KEY_LEN) == 0)
        {
            // 备份旧数据以便回滚
            uint8_t old_private[PRIVATE_KEY_LEN];
            uint8_t old_pubkey[PUBKEY_LEN];
            memcpy(old_private, keypairs[i].privateKey, PRIVATE_KEY_LEN);
            memcpy(old_pubkey, keypairs[i].pubkey, PUBKEY_LEN);

            // 更新 privateKey
            memcpy(keypairs[i].privateKey, pair->privateKey, PRIVATE_KEY_LEN);

            // 重新生成公钥
            if (get_public(pair->privateKey, keypairs[i].pubkey) != 0)
            {
                // 生成失败，回滚旧数据
                memcpy(keypairs[i].privateKey, old_private, PRIVATE_KEY_LEN);
                memcpy(keypairs[i].pubkey, old_pubkey, PUBKEY_LEN);
                return false;
            }

            // 保存到NVS
            if (!save_to_nvs())
            {
                // 保存失败，回滚旧数据
                memcpy(keypairs[i].privateKey, old_private, PRIVATE_KEY_LEN);
                memcpy(keypairs[i].pubkey, old_pubkey, PUBKEY_LEN);
                return false;
            }

            return true;
        }
    }

    // 不存在则新增：先验证公私钥再分配内存
    KeyPair new_entry;
    memcpy(&new_entry, pair, sizeof(KeyPair));

    // 预生成公钥
    if (get_public(new_entry.privateKey, new_entry.pubkey) != 0)
    {
        return false;
    }

    // 分配新内存
    KeyPair *new_pairs = realloc(keypairs, (keypair_count + 1) * sizeof(KeyPair));
    if (!new_pairs)
    {
        return false;
    }

    // 复制数据到新数组
    keypairs = new_pairs;
    memcpy(&keypairs[keypair_count], &new_entry, sizeof(KeyPair));
    keypair_count++;

    // 持久化存储
    if (!save_to_nvs())
    {
        // 存储失败，回滚内存
        keypair_count--;
        KeyPair *shrunk = realloc(keypairs, keypair_count * sizeof(KeyPair));
        if (shrunk)
        {
            keypairs = shrunk;
        }
        return false;
    }

    return true;
}

bool removeAndSaveKeyPair(const uint8_t *aesKey)
{
    if (!aesKey || keypair_count == 0)
        return false;

    // 查找目标索引
    size_t target_idx = keypair_count;
    for (size_t i = 0; i < keypair_count; i++)
    {
        if (memcmp(keypairs[i].aesKey, aesKey, AES_KEY_LEN) == 0)
        {
            target_idx = i;
            break;
        }
    }
    if (target_idx == keypair_count)
        return false; // 未找到

    // 创建新数组（避免直接修改原数组）
    size_t new_count = keypair_count - 1;
    KeyPair *new_keypairs = NULL;
    if (new_count > 0)
    {
        new_keypairs = malloc(new_count * sizeof(KeyPair));
        if (!new_keypairs)
            return false;

        // 复制除目标外的元素
        memcpy(new_keypairs, keypairs, target_idx * sizeof(KeyPair));
        if (target_idx < new_count)
        {
            memcpy(new_keypairs + target_idx,
                   keypairs + target_idx + 1,
                   (new_count - target_idx) * sizeof(KeyPair));
        }
    }

    // 备份旧数据以便回滚
    KeyPair *old_keypairs = keypairs;
    size_t old_count = keypair_count;

    // 更新全局变量
    keypairs = new_keypairs;
    keypair_count = new_count;

    // 尝试保存到NVS
    if (!save_to_nvs())
    {
        // 保存失败，回滚旧数据
        free(new_keypairs);
        keypairs = old_keypairs;
        keypair_count = old_count;
        return false;
    }

    // 保存成功，释放旧内存
    free(old_keypairs);
    return true;
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

    // clean all data, this is for test!!!
    // nvs_flash_erase();

    if (!loadAllKeyPairs())
    {
        ESP_LOGE("STORAGE", "Failed to load keypairs");
    }
}