# Proposal: Migrate to ESP-IDF v6.1

## Why

The project currently targets ESP-IDF v5.4, which only supports early engineering samples (Beta, rev v0.0 - v0.99) for ESP32-C5. Flashing to production ESP32-C5 silicon (Revision v1.2 / ECO2) is blocked by `esptool` revision range checks (`bootloader.bin requires chip revision in range [v0.0 - v0.99]`) and secondary bootloader compatibility checks. Upgrading to ESP-IDF v6.1 provides native first-class support for ESP32-C5 ECO2 hardware, modernized C runtime (PicolibC), and long-term framework maintenance.

## What Changes

- **Target Hardware Support**: Upgrade build framework to ESP-IDF v6.1, enabling native bootloader and application support for ESP32-C5 Revision v1.0~v1.99.
- **Component Dependencies**: Add `espressif/cjson: "^1.7.18"` to `main/idf_component.yml` since cJSON was removed from ESP-IDF built-in components in v6.x. Update IDF version dependency to `>=6.1.0`.
- **Cryptographic Backend**: **BREAKING** Upgrade `crypto_mbedtls.c` to use Mbed TLS 4.0 / PSA Crypto APIs (`psa_hash_*`, `psa_cipher_*`, `psa_aead_*`, `psa_key_derivation_*`), replacing deprecated `mbedtls_sha256`, `mbedtls_aes_crypt_cbc`, `mbedtls_chachapoly_*`, and `mbedtls_hkdf` functions. Call `psa_crypto_init()` during startup.
- **Environment & Build Config**: Transition to Python 3.10+ virtual environment and ESP-IDF v6.1 toolchain. Update VS Code project settings (`.vscode/settings.json`) to point to the v6.1 installation.

## Capabilities

### New Capabilities
<!-- None -->

### Modified Capabilities
- `target-config`: Update target framework requirements to ESP-IDF v6.1+, expand component dependencies to include `espressif/cjson`, and ensure all supported target chips (ESP32-S3, C3, C5, C6, S2, P4) build cleanly with v6.1 toolchains.

## Impact

- **Affected Code**: `main/crypto/crypto_mbedtls.c`, `main/nesigner.c`, `main/idf_component.yml`, `main/CMakeLists.txt`, `.vscode/settings.json`.
- **Dependencies**: ESP-IDF v6.1, Python 3.10+, `espressif/cjson` component from ESP Component Registry.
- **Compatibility**: Preserves external cryptographic interface `signer_crypto.h`, ensuring protocol, session, Nostr NIPs, and transport layers remain completely unaffected.
