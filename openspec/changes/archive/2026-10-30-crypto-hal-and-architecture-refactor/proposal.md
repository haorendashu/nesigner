# Proposal: Crypto HAL and Modular Architecture Refactoring

## Why

The current nesigner firmware concentrates multiple responsibilities within monolithic files (`nesigner.c`, `nostr.c`, `store.c`), tightly coupling Nostr protocol operations to generic mbedTLS cryptographic APIs. In real-world usage, this creates significant performance bottlenecks: generic mbedTLS secp256k1 elliptic curve scalar multiplication takes 100–160ms per BIP-340 Schnorr signature, and batch NIP-04/NIP-44 direct message decryption takes seconds due to redundant ECDH point multiplications. Decoupling the codebase into a clean, modular architecture (protocol framing, Nostr protocol, Crypto HAL, and Storage HAL) while introducing an optimized `libsecp256k1` crypto backend and an LRU conversation session cache enables order-of-magnitude performance gains (5x–10x faster signatures, near-instantaneous batch decryption) while preserving 100% wire-protocol compatibility.

## What Changes

- **Crypto Hardware Abstraction Layer (`crypto/`)**:
  - Introduce `signer_crypto.h` defining clean cryptographic primitive interfaces (BIP-340 Schnorr sign/verify, ECDH scalar multiplication, key generation, AES-256-CBC, ChaCha20-Poly1305, SHA-256, and hardware TRNG).
  - Implement `crypto_secp256k1` backend powered by Bitcoin Core's `libsecp256k1` via the ESP-IDF Component Manager, enabling fast 10x26-limb arithmetic, GLV endomorphism, and fixed-base precomputed tables.
  - Implement `crypto_mbedtls` fallback and hardware accelerator bridges (ESP-IDF native hardware AES, SHA-256, and `esp_random` TRNG).
- **Nostr Protocol Layer (`nostr/`)**:
  - Decouple Nostr NIP implementations (`nostr_nip01`, `nostr_nip04`, `nostr_nip44`) from underlying cryptographic engines.
  - Introduce `nostr_ecdh_cache` (LRU conversation key cache) to eliminate redundant point multiplications during batch private message decryptions.
- **Protocol Framing & Session Dispatch Layer (`protocol/`)**:
  - Extract binary packet codec (Type, ID, CRC16, memory pool integration) from `nesigner.c` into `packet_codec`.
  - Extract outer transport-layer AES envelope encryption/decryption into `session_crypto`.
  - Extract message dispatch routing into `command_router`.
- **Storage HAL (`storage/`)**:
  - Abstract keypair persistent storage into `signer_storage.h` and implement `storage_nvs.c` decoupled from business logic.
- **Dependency & Build Configuration**:
  - Manage `libsecp256k1` using ESP-IDF Component Manager (`main/idf_component.yml`) with 32-bit embedded optimizations.

### Out of Scope
- Modifying the external binary wire protocol (packet layout, command IDs, and encryption envelope remain 100% backward compatible with existing Web and Flutter SDKs).
- Implementing Bluetooth LE (BLE) or Wi-Fi transports (reserved for future changes).

## Capabilities

### New Capabilities
- `crypto-hal`: Unified cryptographic abstraction layer providing standardized primitives for secp256k1 (Schnorr, ECDH, keygen), symmetric ciphers (AES-CBC, ChaCha20-Poly1305), hashing, and hardware random number generation across multiple backends.
- `nostr-service`: Modular Nostr protocol implementation covering NIP-01, NIP-04, NIP-44, and conversation session caching independent of underlying cryptographic providers.

### Modified Capabilities
*(None; device-transport and target-config requirements remain unchanged)*

## Impact
- **Performance**: BIP-340 signing latency drops from ~130ms to ~15ms; batch NIP-04/44 decryption drops from seconds to milliseconds.
- **Firmware Size**: Adding `libsecp256k1` with 32-bit field and Schnorr/ECDH modules adds approximately 70–90KB of flash, well within ESP32 partition limits.
- **Maintainability**: Clear separation between transport, wire framing, Nostr business rules, cryptographic primitives, and persistent storage.
- **Client Compatibility**: Existing `js_nesigner_sdk` and `flutter_nesigner_sdk` clients function identically with zero code changes.
