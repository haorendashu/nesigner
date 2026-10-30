#include "signer_storage.h"
#include "signer_crypto.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "STORAGE_NVS";
static const char *NVS_NAMESPACE = "keypair_store";

KeyPair *keypairs = NULL;
size_t keypair_count = 0;

static bool save_to_nvs(void)
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle) != ESP_OK) {
        return false;
    }

    esp_err_t err;
    if (keypair_count == 0) {
        err = nvs_set_blob(handle, "keypairs", NULL, 0);
        if (err != ESP_OK) {
            nvs_close(handle);
            return false;
        }
        err = nvs_commit(handle);
        nvs_close(handle);
        return err == ESP_OK;
    }

    StoredKeyPair *storage = (StoredKeyPair *)malloc(keypair_count * sizeof(StoredKeyPair));
    if (!storage) {
        nvs_close(handle);
        return false;
    }

    for (size_t i = 0; i < keypair_count; i++) {
        memcpy(storage[i].aesKey, keypairs[i].aesKey, AES_KEY_LEN);
        memcpy(storage[i].privateKey, keypairs[i].privateKey, PRIVATE_KEY_LEN);
    }

    err = nvs_set_blob(handle, "keypairs", storage, keypair_count * sizeof(StoredKeyPair));
    free(storage);

    if (err != ESP_OK) {
        nvs_close(handle);
        return false;
    }

    err = nvs_commit(handle);
    nvs_close(handle);
    return err == ESP_OK;
}

bool signer_storage_load_all(void)
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle) != ESP_OK) {
        return true; // Empty store
    }

    size_t required_size = 0;
    esp_err_t err = nvs_get_blob(handle, "keypairs", NULL, &required_size);
    if (err != ESP_OK || required_size == 0) {
        nvs_close(handle);
        return true;
    }

    StoredKeyPair *storage = (StoredKeyPair *)malloc(required_size);
    if (!storage) {
        nvs_close(handle);
        return false;
    }

    err = nvs_get_blob(handle, "keypairs", storage, &required_size);
    nvs_close(handle);

    if (err != ESP_OK) {
        free(storage);
        return false;
    }

    if (keypairs) {
        free(keypairs);
    }

    keypair_count = required_size / sizeof(StoredKeyPair);
    keypairs = (KeyPair *)malloc(keypair_count * sizeof(KeyPair));
    if (!keypairs) {
        free(storage);
        keypair_count = 0;
        return false;
    }

    for (size_t i = 0; i < keypair_count; i++) {
        memcpy(keypairs[i].aesKey, storage[i].aesKey, AES_KEY_LEN);
        memcpy(keypairs[i].privateKey, storage[i].privateKey, PRIVATE_KEY_LEN);
        crypto_secp256k1_get_public(keypairs[i].privateKey, keypairs[i].pubkey);
    }

    free(storage);
    ESP_LOGI(TAG, "Loaded %zu keypairs from NVS", keypair_count);
    return true;
}

bool signer_storage_add(const KeyPair *pair)
{
    if (!pair) return false;

    for (size_t i = 0; i < keypair_count; i++) {
        if (memcmp(keypairs[i].aesKey, pair->aesKey, AES_KEY_LEN) == 0) {
            memcpy(keypairs[i].privateKey, pair->privateKey, PRIVATE_KEY_LEN);
            crypto_secp256k1_get_public(keypairs[i].privateKey, keypairs[i].pubkey);
            return save_to_nvs();
        }
    }

    KeyPair *temp = (KeyPair *)realloc(keypairs, (keypair_count + 1) * sizeof(KeyPair));
    if (!temp) return false;

    keypairs = temp;
    memcpy(keypairs[keypair_count].aesKey, pair->aesKey, AES_KEY_LEN);
    memcpy(keypairs[keypair_count].privateKey, pair->privateKey, PRIVATE_KEY_LEN);
    crypto_secp256k1_get_public(keypairs[keypair_count].privateKey, keypairs[keypair_count].pubkey);

    keypair_count++;
    return save_to_nvs();
}

bool signer_storage_remove(const uint8_t *aesKey)
{
    if (!aesKey) return false;

    int index = -1;
    for (size_t i = 0; i < keypair_count; i++) {
        if (memcmp(keypairs[i].aesKey, aesKey, AES_KEY_LEN) == 0) {
            index = i;
            break;
        }
    }

    if (index == -1) return false;

    for (size_t i = index; i < keypair_count - 1; i++) {
        keypairs[i] = keypairs[i + 1];
    }

    keypair_count--;

    if (keypair_count == 0) {
        free(keypairs);
        keypairs = NULL;
    } else {
        KeyPair *temp = (KeyPair *)realloc(keypairs, keypair_count * sizeof(KeyPair));
        if (temp) {
            keypairs = temp;
        }
    }

    return save_to_nvs();
}

KeyPair *signer_storage_find_by_pubkey(const uint8_t *pubkey)
{
    if (!pubkey) return NULL;
    for (size_t i = 0; i < keypair_count; i++) {
        if (memcmp(keypairs[i].pubkey, pubkey, PUBKEY_LEN) == 0) {
            return &keypairs[i];
        }
    }
    return NULL;
}

KeyPair *signer_storage_find_by_aes_key(const uint8_t *aesKey)
{
    if (!aesKey) return NULL;
    for (size_t i = 0; i < keypair_count; i++) {
        if (memcmp(keypairs[i].aesKey, aesKey, AES_KEY_LEN) == 0) {
            return &keypairs[i];
        }
    }
    return NULL;
}

void signer_storage_init(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    signer_storage_load_all();
}
