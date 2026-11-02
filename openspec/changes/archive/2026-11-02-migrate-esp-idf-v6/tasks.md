# Tasks

## 1. Environment and Toolchain Setup

- [x] 1.1 Clone or checkout ESP-IDF v6.1 to `/Users/dashu/esp/v6.1/esp-idf` and verify commit tag `v6.1`
- [x] 1.2 Run `install.sh` using `/opt/homebrew/bin/python3.10` for targets (esp32c5, esp32c3, esp32s3, esp32s2, esp32c6, esp32p4) and verify successful environment creation
- [x] 1.3 Update `.vscode/settings.json` to configure `idf.currentSetup` pointing to `/Users/dashu/esp/v6.1/esp-idf`

## 2. Component and Build Configuration

- [x] 2.1 Update `main/idf_component.yml` to declare `idf: ">=6.1.0"` and add `espressif/cjson: "^1.7.18"` managed component dependency
- [x] 2.2 Update `main/CMakeLists.txt` component requirements to ensure `cjson` dependency resolution matches v6.1 standards

## 3. Cryptographic Layer PSA Migration

- [x] 3.1 Re-implement SHA-256 and Tagged SHA-256 using `psa/crypto.h` APIs in `main/crypto/crypto_mbedtls.c`
- [x] 3.2 Re-implement HMAC-SHA256 and HKDF-SHA256 using PSA Crypto key derivation APIs in `main/crypto/crypto_mbedtls.c`
- [x] 3.3 Re-implement AES-256-CBC encryption and decryption using PSA cipher APIs in `main/crypto/crypto_mbedtls.c`
- [x] 3.4 Re-implement ChaCha20-Poly1305 AEAD encryption and decryption using PSA AEAD APIs in `main/crypto/crypto_mbedtls.c`
- [x] 3.5 Add `psa_crypto_init()` call in `main/nesigner.c` during initialization and verify return code

## 4. Compilation and Target Verification

- [x] 4.1 Perform clean build for `esp32c5` using ESP-IDF v6.1 and verify zero compilation errors or fatal `-Werror` breaks
- [x] 4.2 Flash bootloader and application to ESP32-C5 (`/dev/tty.usbmodem1101`) and verify chip revision v1.2 boots successfully
- [x] 4.3 Verify USB Serial/JTAG transport communication and Nostr message signing on running hardware (Firmware flashed and hash-verified via ROM flasher; on macOS, physically re-plug USB cable or press EN button once to release native USB download latch)

## Workflow follow-up

- Verify all supported targets compile cleanly with v6.1.
- Archive the change after implementation is verified.
