#include "nostr.h"

// Backward-compatibility bridge
int hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *output)
{
    return crypto_hmac_sha256(key, key_len, data, data_len, output);
}
