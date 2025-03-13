#include <stdio.h>

// 以十进制形式打印字节数组
void printByteArrayAsDec(const char *arr, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%u ", arr[i]);
        if ((i + 1) % 10 == 0)
        {
            printf("\n");
        }
    }
    printf("\n");
}