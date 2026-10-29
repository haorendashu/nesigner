#ifndef ERROR_HANDLING_H
#define ERROR_HANDLING_H

#include "esp_log.h"
#include <stdlib.h>
#include <string.h>

/**
 * @brief 统一的错误处理和资源清理宏
 *
 * 用于替代goto语句，提供更清晰的错误处理流程
 */

/**
 * @brief 条件检查宏，如果条件为假则设置错误并跳转到cleanup标签
 * @param condition 要检查的条件
 * @param err_code 错误代码
 * @param tag 日志标签
 * @param msg 错误消息
 */
#define CHECK_RETURN(condition, err_code, tag, msg) \
    do                                              \
    {                                               \
        if (!(condition))                           \
        {                                           \
            ESP_LOGE(tag, msg);                     \
            ret = err_code;                         \
            goto cleanup;                           \
        }                                           \
    } while (0)

/**
 * @brief 条件检查宏（无日志版本）
 * @param condition 要检查的条件
 * @param err_code 错误代码
 */
#define CHECK_RETURN_SILENT(condition, err_code) \
    do                                           \
    {                                            \
        if (!(condition))                        \
        {                                        \
            ret = err_code;                      \
            goto cleanup;                        \
        }                                        \
    } while (0)

/**
 * @brief 指针检查和释放宏
 * @param ptr 指针
 */
#define CLEANUP_POINTER(ptr) \
    do                       \
    {                        \
        if ((ptr) != NULL)   \
        {                    \
            free(ptr);       \
            (ptr) = NULL;    \
        }                    \
    } while (0)

/**
 * @brief 安全清除内存（防止敏感数据泄露）
 * @param ptr 指针
 * @param size 要清除的字节数
 */
#define SECURE_CLEANUP(ptr, size)     \
    do                                \
    {                                 \
        if ((ptr) != NULL)            \
        {                             \
            memset((ptr), 0, (size)); \
            free(ptr);                \
            (ptr) = NULL;             \
        }                             \
    } while (0)

/**
 * @brief 多个指针清理宏
 */
#define CLEANUP_ARRAY(arr, count)             \
    do                                        \
    {                                         \
        if ((arr) != NULL)                    \
        {                                     \
            for (int i = 0; i < (count); i++) \
            {                                 \
                CLEANUP_POINTER((arr)[i]);    \
            }                                 \
            CLEANUP_POINTER(arr);             \
        }                                     \
    } while (0)

/**
 * @brief 用于FreeRTOS资源的清理宏
 * @param handle 句柄
 */
#define CLEANUP_FREERTOS_HANDLE(handle) \
    do                                  \
    {                                   \
        if ((handle) != NULL)           \
        {                               \
            (handle) = NULL;            \
        }                               \
    } while (0)

/**
 * @brief 日志断言宏（条件不成立时记录并返回）
 * @param condition 条件
 * @param tag 日志标签
 * @param msg 日志消息
 * @param ret_val 返回值
 */
#define LOG_ASSERT(condition, tag, msg, ret_val) \
    do                                           \
    {                                            \
        if (!(condition))                        \
        {                                        \
            ESP_LOGE(tag, msg);                  \
            return (ret_val);                    \
        }                                        \
    } while (0)

#endif // ERROR_HANDLING_H
