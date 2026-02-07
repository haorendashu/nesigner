#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "memory_pool.h"

static const char *TAG = "MEMORY_POOL";

static MessageBuffer buffer_pool[BUFFER_POOL_SIZE];
static SemaphoreHandle_t pool_mutex = NULL;
static bool pool_initialized = false;

bool memory_pool_init(void)
{
    if (pool_initialized)
    {
        return true;
    }

    // 创建互斥信号量保护缓冲池
    pool_mutex = xSemaphoreCreateMutex();
    if (pool_mutex == NULL)
    {
        ESP_LOGE(TAG, "Failed to create mutex");
        return false;
    }

    // 初始化所有缓冲区
    memset(buffer_pool, 0, sizeof(buffer_pool));
    for (int i = 0; i < BUFFER_POOL_SIZE; i++)
    {
        buffer_pool[i].in_use = false;
    }

    pool_initialized = true;
    ESP_LOGI(TAG, "Memory pool initialized with %d buffers", BUFFER_POOL_SIZE);
    return true;
}

MessageBuffer *memory_pool_get(void)
{
    if (!pool_initialized || pool_mutex == NULL)
    {
        ESP_LOGE(TAG, "Memory pool not initialized");
        return NULL;
    }

    // 获取互斥锁
    if (xSemaphoreTake(pool_mutex, pdMS_TO_TICKS(1000)) != pdTRUE)
    {
        ESP_LOGE(TAG, "Failed to acquire pool mutex");
        return NULL;
    }

    MessageBuffer *result = NULL;

    // 查找第一个未被使用的缓冲区
    for (int i = 0; i < BUFFER_POOL_SIZE; i++)
    {
        if (!buffer_pool[i].in_use)
        {
            buffer_pool[i].in_use = true;
            result = &buffer_pool[i];
            ESP_LOGD(TAG, "Allocated buffer %d", i);
            break;
        }
    }

    xSemaphoreGive(pool_mutex);

    if (result == NULL)
    {
        ESP_LOGW(TAG, "No available buffer in pool");
    }

    return result;
}

void memory_pool_release(MessageBuffer *buf)
{
    if (buf == NULL)
    {
        return;
    }

    if (!pool_initialized || pool_mutex == NULL)
    {
        ESP_LOGE(TAG, "Memory pool not initialized");
        return;
    }

    if (xSemaphoreTake(pool_mutex, pdMS_TO_TICKS(1000)) != pdTRUE)
    {
        ESP_LOGE(TAG, "Failed to acquire pool mutex");
        return;
    }

    // 查找缓冲区在池中的位置
    for (int i = 0; i < BUFFER_POOL_SIZE; i++)
    {
        if (&buffer_pool[i] == buf)
        {
            buffer_pool[i].in_use = false;
            memset(buffer_pool[i].buffer, 0, MAX_BUFFER_SIZE);
            ESP_LOGD(TAG, "Released buffer %d", i);
            break;
        }
    }

    xSemaphoreGive(pool_mutex);
}

void memory_pool_stats(int *total, int *used)
{
    if (!pool_initialized || pool_mutex == NULL)
    {
        if (total)
            *total = 0;
        if (used)
            *used = 0;
        return;
    }

    if (xSemaphoreTake(pool_mutex, pdMS_TO_TICKS(1000)) != pdTRUE)
    {
        if (total)
            *total = 0;
        if (used)
            *used = 0;
        return;
    }

    int used_count = 0;
    for (int i = 0; i < BUFFER_POOL_SIZE; i++)
    {
        if (buffer_pool[i].in_use)
        {
            used_count++;
        }
    }

    if (total)
        *total = BUFFER_POOL_SIZE;
    if (used)
        *used = used_count;

    xSemaphoreGive(pool_mutex);
}

void memory_pool_destroy(void)
{
    if (pool_mutex != NULL)
    {
        vSemaphoreDelete(pool_mutex);
        pool_mutex = NULL;
    }

    pool_initialized = false;
    ESP_LOGI(TAG, "Memory pool destroyed");
}
