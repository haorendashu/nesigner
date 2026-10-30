# Design: Crypto HAL and Modular Architecture Refactoring

## Context

Following the multi-target support change (which established `main/transport/` for TinyUSB, USB-Serial-JTAG, and UART across ESP32-S3, C3, C5, and P4), the firmware's remaining logic remains tightly bundled in `nesigner.c` (636 lines) and `nostr.c` (1176 lines). 

Crypto operations currently rely on generic `mbedtls_ecp` and `mbedtls_mpi` routines. While mbedTLS is standard in ESP-IDF, its generic Weierstrass curve algorithms perform redundant arbitrary-precision divisions and lack specialized Koblitz curve optimizations (such as GLV endomorphism, 10x26 limbs, and generator base precomputed tables), causing BIP-340 signatures to take ~130ms on 240MHz ESP32-S3. Furthermore, repeated NIP-04/NIP-44 operations recompute ECDH shared secrets from scratch for every single message.

## Goals / Non-Goals

**Goals:**
- Decouple the codebase into clean architectural tiers: `protocol/`, `nostr/`, `crypto/`, `storage/`, and `transport/`.
- Achieve 5x–10x acceleration for BIP-340 Schnorr signatures and key generation by integrating `libsecp256k1`.
- Accelerate batch NIP-04 and NIP-44 private message operations via an LRU conversation session key cache.
- Maintain 100% backward compatibility with existing Web Serial and Flutter SDKs.
- Ensure seamless multi-target builds across ESP32-S3, ESP32-C3, ESP32-C5, and ESP32-P4.

**Non-Goals:**
- Changing the binary wire frame format or message ID protocol.
- Adding BLE or Wi-Fi network stacks in this change.
- Physical tamper-resistance certification (e.g. Common Criteria EAL6+).

## Decisions

### Decision 1: Multi-Tiered Modular Structure
Extract monolithic files into cohesive domain modules:
```
main/
├── nesigner.c              // Entry point & FreeRTOS task loop
├── memory_pool.c/.h        // Existing zero-copy pool
├── protocol/               // Frame codec, session AES envelope, and command dispatch
├── nostr/                  // NIP-01, NIP-04, NIP-44, and ECDH LRU cache
├── crypto/                 // Crypto HAL (signer_crypto.h, secp256k1, mbedtls/hw bridges)
├── storage/                // Storage HAL (signer_storage.h, storage_nvs.c)
└── transport/              // Device transports (already decoupled)
```
*Rationale*: Provides strict boundaries so cryptographic implementations, transport mechanisms, and protocol semantics can evolve or be tested independently.

### Decision 2: Integrate `libsecp256k1` via ESP-IDF Component Manager
Use the ESP-IDF Component Manager (`main/idf_component.yml`) to manage `libsecp256k1`, configured with:
- `USE_FIELD_10X26=1`: Optimal for 32-bit Xtensa and RISC-V architectures.
- `ENABLE_MODULE_SCHNORRSIG=1`: Native BIP-340 Schnorr sign and verify.
- `ENABLE_MODULE_EXTRAKEYS=1`: x-only public keys.
- `ENABLE_MODULE_ECDH=1`: Constant-time scalar multiplication.

*Alternatives considered*:
- *mbedTLS optimization*: Generic architecture cannot easily incorporate secp256k1 endomorphism without heavy fork maintenance.
- *micro-ecc (uECC)*: Lacks native BIP-340 Schnorr support and side-channel resistance.

### Decision 3: LRU Conversation Session Cache for NIP-04 / NIP-44
Introduce an in-memory LRU cache holding up to 16 recent conversation keys (derived from `(our_pub, their_pub)` pairs).
- When a message arrives, check the LRU cache:
  - **Hit**: Skip ECDH point multiplication entirely; proceed directly to symmetric decryption.
  - **Miss**: Perform ECDH via `libsecp256k1`, compute conversation key, insert into cache (evicting least recently used entry).
*Rationale*: Nostr direct messaging involves chat threads with repeat recipients. Bypassing ECDH on repeated messages turns 70ms operations into 0.05ms memory lookups.

### Decision 4: Leverage Target SoC Hardware Accelerators for Symmetric Ciphers & TRNG
The Crypto HAL bridges to ESP-IDF hardware drivers:
- AES-256-CBC: Hardware AES accelerator (`CONFIG_MBEDTLS_HARDWARE_AES=y`).
- SHA-256: Hardware SHA accelerator (`CONFIG_MBEDTLS_HARDWARE_SHA=y`).
- Random numbers: Hardware True Random Number Generator (`esp_random()`).

## Risks / Trade-offs

- **[Flash Footprint Increase]** → `libsecp256k1` compiled with 10x26 limbs and precomputed tables adds ~70–90KB flash.
  *Mitigation*: Firmware size is well under 1.5MB; default 4MB/8MB/16MB flash configurations have ample headroom.
- **[Heap Consumption for Crypto Context & LRU Cache]** → `secp256k1_context` and 16 LRU cache entries consume ~4KB RAM.
  *Mitigation*: Pre-allocated statically or initialized once at boot without runtime allocation churn.
- **[Refactoring Regressions]** → Moving message dispatching and serialization risks subtle protocol regressions.
  *Mitigation*: Retain identical binary structs, payload offsets, CRC16 verification, and test vectors.
