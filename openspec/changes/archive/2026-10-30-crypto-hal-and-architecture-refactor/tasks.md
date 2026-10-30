# Tasks

## 1. Dependency Integration & Crypto HAL Foundation

- [x] 1.1 Integrate `libsecp256k1` via `main/idf_component.yml`, enable 32-bit (10x26) arithmetic and Schnorr/ECDH modules, and verify compilation succeeds across target configurations.
- [x] 1.2 Implement `main/crypto/signer_crypto.h` and `main/crypto/crypto_secp256k1.c` wrapping key generation, BIP-340 Schnorr sign, and ECDH scalar multiplication; verify with standard test vectors.
- [x] 1.3 Implement `main/crypto/crypto_mbedtls.c` wrapping AES-256-CBC, ChaCha20-Poly1305, SHA-256, and hardware TRNG (`esp_random`); verify symmetric encryption and decryption roundtrip.

## 2. Nostr Protocol Decoupling & Conversation Cache

- [x] 2.1 Implement `main/nostr/nostr_ecdh_cache.c/.h` LRU session key cache; verify hit, miss, and eviction logic with mock public keys.
- [x] 2.2 Implement `main/nostr/nostr_nip01.c/.h` delegating to Crypto HAL for event serialization, SHA-256 hashing, and BIP-340 signing; verify NIP-01 output against test events.
- [x] 2.3 Implement `main/nostr/nostr_nip04.c/.h` and `main/nostr/nostr_nip44.c/.h` integrating Crypto HAL and the LRU conversation cache; verify encryption and decryption roundtrips.

## 3. Storage HAL Decoupling

- [x] 3.1 Extract persistent keypair management from `store.c` into `main/storage/signer_storage.h` and `main/storage/storage_nvs.c`; verify add, find, list, and remove keypair operations.

## 4. Protocol Framing & Dispatch Decoupling

- [x] 4.1 Extract packet framing, CRC16 calculation, and memory pool zero-copy handling from `nesigner.c` into `main/protocol/packet_codec.c/.h`; verify packet encode/decode integrity.
- [x] 4.2 Extract transport-layer AES session security into `main/protocol/session_crypto.c/.h` and message routing into `main/protocol/command_router.c/.h`; verify command routing across all message types.
- [x] 4.3 Refactor `main/nesigner.c` as a clean application entry point and FreeRTOS task coordinator; verify end-to-end PING, GET_PUBKEY, SIGN, and NIP04/44 message flows.

## 5. Multi-Target Build & Performance Verification

- [x] 5.1 Verify compilation across supported targets (`esp32s3`, `esp32c3`, `esp32c5`, `esp32p4`).
- [x] 5.2 Benchmark BIP-340 Schnorr signing and NIP-44 batch decryption latency to verify expected 5x–10x acceleration.
