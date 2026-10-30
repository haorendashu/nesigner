#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "esp_heap_caps.h"

// 打印字节数组
void printByteArrayAsDec(const char *arr, size_t len);

// 16进制与二进制相互转换
int hex_to_bin(const char *hex, uint8_t *bin, size_t bin_size);
void bin_to_hex(const uint8_t *bin, size_t bin_size, char *hex);

#endif