#ifndef SIGNER_STORAGE_H
#define SIGNER_STORAGE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AES_KEY_LEN     16 // 16 bytes
#define PRIVATE_KEY_LEN 32 // 32 bytes
#define PUBKEY_LEN      32 // 32 bytes

#pragma pack(push, 1)
typedef struct {
    uint8_t aesKey[AES_KEY_LEN];
    uint8_t privateKey[PRIVATE_KEY_LEN];
} StoredKeyPair;
#pragma pack(pop)

typedef struct {
    uint8_t aesKey[AES_KEY_LEN];
    uint8_t privateKey[PRIVATE_KEY_LEN];
    uint8_t pubkey[PUBKEY_LEN]; // Runtime derived
} KeyPair;

extern KeyPair *keypairs;
extern size_t keypair_count;

void signer_storage_init(void);
bool signer_storage_load_all(void);
bool signer_storage_add(const KeyPair *pair);
bool signer_storage_remove(const uint8_t *aesKey);
KeyPair *signer_storage_find_by_pubkey(const uint8_t *pubkey);
KeyPair *signer_storage_find_by_aes_key(const uint8_t *aesKey);

#ifdef __cplusplus
}
#endif

#endif // SIGNER_STORAGE_H
