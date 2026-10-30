#ifndef STORE_H
#define STORE_H

#include "signer_storage.h"

// Forwarding wrappers for backwards compatibility
static inline bool loadAllKeyPairs(void) {
    return signer_storage_load_all();
}

static inline bool addAndSaveKeyPair(const KeyPair *pair) {
    return signer_storage_add(pair);
}

static inline bool removeAndSaveKeyPair(const uint8_t *aesKey) {
    return signer_storage_remove(aesKey);
}

static inline KeyPair *findKeyPairByPubkey(const uint8_t *pubkey) {
    return signer_storage_find_by_pubkey(pubkey);
}

static inline void initStorage(void) {
    signer_storage_init();
}

#endif // STORE_H
