#ifndef MEMORY_POOL_H
#define MEMORY_POOL_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief 内存缓冲池管理
 *
 * 用于减少嵌入式系统中频繁malloc/free的开销，
 * 预分配固定大小的缓冲区池，提高性能
 */

// Must cover: header + payload + CRC. Current worst-case is 1098 bytes.
// Use a small safety margin and alignment.
#define MAX_BUFFER_SIZE 1152
// Increase pool size to handle higher concurrency.
#define BUFFER_POOL_SIZE 20

typedef struct
{
    uint8_t buffer[MAX_BUFFER_SIZE];
    bool in_use;
} MessageBuffer;

/**
 * @brief 初始化内存缓冲池
 * @return true 初始化成功, false 初始化失败
 */
bool memory_pool_init(void);

/**
 * @brief 从缓冲池获取一个可用缓冲区
 * @return 指向缓冲区的指针，如果没有可用缓冲区返回NULL
 */
MessageBuffer *memory_pool_get(void);

/**
 * @brief 将缓冲区归还到缓冲池
 * @param buf 要归还的缓冲区指针
 */
void memory_pool_release(MessageBuffer *buf);

/**
 * @brief 获取当前缓冲池使用情况
 * @param total 输出参数，缓冲区总数
 * @param used 输出参数，已使用的缓冲区数
 */
void memory_pool_stats(int *total, int *used);

/**
 * @brief 销毁内存缓冲池（清理资源）
 */
void memory_pool_destroy(void);

#endif // MEMORY_POOL_H
