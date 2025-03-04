#ifndef STORE_H
#define STORE_H

// 固定长度定义（包含null终止符）
#define AES_KEY_LEN 33     // 32字节AES (64字符)
#define PRIVATE_KEY_LEN 65 // 64字符hex（32字节）
#define PUBKEY_LEN 65      // 64字符hex（32字节）

// 存储结构体（紧凑二进制格式）
#pragma pack(push, 1)
typedef struct
{
    char aesKey[33];     // 32字符 + null
    char privateKey[65]; // 64字符 + null
} StoredKeyPair;
#pragma pack(pop)

// 内存结构体
typedef struct
{
    char aesKey[33];
    char privateKey[65];
    char pubkey[65]; // 运行时计算
} KeyPair;

bool loadAll();

bool addAndSave(const KeyPair *pair);

bool removeAndSave(const char *aesKey);

#endif