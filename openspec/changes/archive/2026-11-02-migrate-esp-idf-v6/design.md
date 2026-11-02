# Design: ESP-IDF v6.1 Migration

## Context

See `proposal.md` for background and motivation. The project currently runs on ESP-IDF v5.4 with Python 3.9 and Mbed TLS 3.x. Migrating to ESP-IDF v6.1 requires establishing a Python 3.10+ toolchain, adapting cryptographic operations to Mbed TLS 4.0 / PSA Crypto, and managing `cJSON` as an external registry component.

## Goals / Non-Goals

**Goals:**
- Install an isolated ESP-IDF v6.1 environment in `/Users/dashu/esp/v6.1/esp-idf` without disturbing `/Users/dashu/esp/v5.4`.
- Re-implement cryptographic primitives in `crypto_mbedtls.c` using PSA Crypto APIs while maintaining identical behavior and interface contracts in `signer_crypto.h`.
- Update component manifests and build configurations for `espressif/cjson`.
- Successfully compile, flash, and verify operation on ESP32-C5 (Revision v1.2) over `/dev/tty.usbmodem1101`.

**Non-Goals:**
- Changing external protocol formats, Nostr NIP behaviors, or transport drivers.
- Replacing the optimized `secp256k1` component backend.

## Decisions

### Decision 1: Parallel Side-by-Side Installation (`/Users/dashu/esp/v6.1`)
- **Choice**: Clone/install ESP-IDF v6.1 into `/Users/dashu/esp/v6.1/esp-idf` and use a dedicated Python 3.10 virtualenv (`idf6.1_py3.10_env`).
- **Rationale**: Isolates the v6.1 toolchain, preserving `/Users/dashu/esp/v5.4/esp-idf` for instant rollback if necessary.
- **Alternatives Considered**: In-place upgrade of `/Users/dashu/esp/v5.4` (rejected due to git conflicts and high risk of broken state).

### Decision 2: Native PSA Crypto API for Cryptographic Primitives
- **Choice**: Directly implement SHA256, HMAC, HKDF, AES-CBC, and ChaCha20-Poly1305 using PSA Crypto APIs (`psa/crypto.h`), and initialize the PSA subsystem via `psa_crypto_init()` during startup.
- **Rationale**: Mbed TLS 4.0 in ESP-IDF v6.x removes legacy `mbedtls_*` functions. Implementing PSA Crypto provides direct hardware accelerator integration and future-proof compatibility.
- **Alternatives Considered**: Legacy compatibility macros / shims (rejected because Espressif v6.x removes many underlying symbols).

### Decision 3: Managed Component for cJSON
- **Choice**: Declare `espressif/cjson: "^1.7.18"` in `main/idf_component.yml`.
- **Rationale**: In ESP-IDF v6.x, cJSON is excised from the built-in system components. Using the IDF Component Manager fetches the official version transparently.

## Risks / Trade-offs

- **[Risk] Compilation failure due to `-Werror` strictness**  
  → *Mitigation*: Ensure all new PSA crypto code compiles cleanly without warnings; configure target compiler flags if third-party `secp256k1` has minor conversion warnings.
- **[Risk] PSA Crypto subsystem not initialized before early crypto call**  
  → *Mitigation*: Insert `psa_crypto_init()` at the very start of `app_main()` in `nesigner.c` with error verification.
- **[Risk] Long toolchain download times**  
  → *Mitigation*: GCC 14.2 compilers are already cached in `.espressif/tools`; `install.sh` will link existing packages where applicable.

## Migration & Rollback Plan

1. Setup `/Users/dashu/esp/v6.1/esp-idf` with `./install.sh`.
2. Update `main/idf_component.yml`, `main/crypto/crypto_mbedtls.c`, and `main/nesigner.c`.
3. Update `.vscode/settings.json` to point `idf.currentSetup` to `/Users/dashu/esp/v6.1/esp-idf`.
4. Perform clean build and flash for `esp32c5`.
5. **Rollback**: If issues occur, revert the git working copy and point `.vscode/settings.json` back to `/Users/dashu/esp/v5.4/esp-idf`.
