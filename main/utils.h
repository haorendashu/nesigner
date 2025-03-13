#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <string.h>
#include "esp_heap_caps.h"

// 以十进制形式打印字节数组
void printByteArrayAsDec(const char *arr, size_t len);

#endif