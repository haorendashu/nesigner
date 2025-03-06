#ifndef STORE_H
#define STORE_H

// 固定长度定义（包含null终止符）
#define AES_KEY_LEN 16     // 16字符
#define PRIVATE_KEY_LEN 32 // 32字节
#define PUBKEY_LEN 32      // 32字节

// 存储结构体（紧凑二进制格式）
#pragma pack(push, 1)
typedef struct
{
    uint8_t aesKey[AES_KEY_LEN];
    uint8_t privateKey[PRIVATE_KEY_LEN];
} StoredKeyPair;
#pragma pack(pop)

// 内存结构体
typedef struct
{
    uint8_t aesKey[AES_KEY_LEN];
    uint8_t privateKey[PRIVATE_KEY_LEN];
    uint8_t pubkey[PUBKEY_LEN]; // 运行时计算
} KeyPair;

extern KeyPair *keypairs;
extern size_t keypair_count;

bool loadAllKeyPairs();

bool addAndSaveKeyPair(const KeyPair *pair);

bool removeAndSaveKeyPair(const uint8_t *aesKey);

KeyPair *findKeyPairByPubkey(const uint8_t *pubkey);

void initStorage();

#endif