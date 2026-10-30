#include "utils.h"

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

int hex_to_bin(const char *hex, uint8_t *bin, size_t bin_size)
{
    if (!hex || !bin || strlen(hex) != 2 * bin_size)
        return -1;
    for (size_t i = 0; i < bin_size; i++)
    {
        if (sscanf(hex + 2 * i, "%2hhx", &bin[i]) != 1)
            return -1;
    }
    return 0;
}

void bin_to_hex(const uint8_t *bin, size_t bin_size, char *hex)
{
    if (!bin || !hex) return;
    for (size_t i = 0; i < bin_size; i++)
    {
        sprintf(hex + 2 * i, "%02x", bin[i]);
    }
    hex[2 * bin_size] = '\0';
}