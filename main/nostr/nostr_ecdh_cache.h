#ifndef NOSTR_ECDH_CACHE_H
#define NOSTR_ECDH_CACHE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NOSTR_ECDH_CACHE_CAPACITY 16

/**
 * @brief Initialize the ECDH LRU cache
 */
void nostr_ecdh_cache_init(void);

/**
 * @brief Clear all entries in the cache
 */
void nostr_ecdh_cache_clear(void);

/**
 * @brief Retrieve a cached ECDH shared secret
 * @param our_pubkey Our 32-byte public key
 * @param their_pubkey Peer's 32-byte public key
 * @param shared_secret Output buffer (32 bytes)
 * @return true if cache hit, false if cache miss
 */
bool nostr_ecdh_cache_get(const uint8_t our_pubkey[32],
                          const uint8_t their_pubkey[32],
                          uint8_t shared_secret[32]);

/**
 * @brief Store an ECDH shared secret in the LRU cache
 * @param our_pubkey Our 32-byte public key
 * @param their_pubkey Peer's 32-byte public key
 * @param shared_secret 32-byte computed shared secret
 */
void nostr_ecdh_cache_put(const uint8_t our_pubkey[32],
                          const uint8_t their_pubkey[32],
                          const uint8_t shared_secret[32]);

#ifdef __cplusplus
}
#endif

#endif // NOSTR_ECDH_CACHE_H
