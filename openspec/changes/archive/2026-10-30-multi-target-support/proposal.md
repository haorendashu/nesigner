# Proposal: Support Multiple ESP32 Targets (ESP32-S3, C3, C5, P4)

## Why

The nesigner firmware was originally developed exclusively for the ESP32-S3, tightly coupling its communication layer to TinyUSB (`esp_tinyusb`) and hardcoding target-specific hardware details (such as UART2, fixed GPIO pins, and dual-core task affinities). To expand the project's ecosystem and allow developers to deploy nesigner across diverse ESP32 silicon (including cost-effective RISC-V chips like the ESP32-C3 and ESP32-C5 with Wi-Fi 6, and high-performance RISC-V processors like the ESP32-P4), the project needs a decoupled, multi-target architecture while ensuring existing ESP32-S3 hardware remains 100% operational and regression-free.

## What Changes

- **Transport Layer Abstraction (HAL)**: Decouple communication from `nesigner.c` into a unified `signer_transport` interface supporting multiple backends:
  - `transport_tinyusb`: For USB-OTG devices (ESP32-S3, ESP32-P4) preserving custom VID `0x2323` / PID `0x3434`.
  - `transport_usb_serial_jtag`: For non-OTG devices (ESP32-C3, ESP32-C5, ESP32-C6) using ESP-IDF native USB Serial/JTAG driver (`0x303a:0x1001`).
  - `transport_uart`: Configurable UART fallback.
- **Conditional Dependency Management**: Make `esp_tinyusb` component dependency conditional so chips without USB-OTG hardware (like ESP32-C3, ESP32-C5) build cleanly without compilation errors.
- **Multi-Target Build & Configuration**:
  - Replace monolithic `sdkconfig` with `sdkconfig.defaults` for common settings (mbedTLS secp256k1, memory pool).
  - Add target-specific defaults (`sdkconfig.defaults.esp32s3`, `sdkconfig.defaults.esp32c3`, `sdkconfig.defaults.esp32c5`, `sdkconfig.defaults.esp32p4`).
  - Introduce Kconfig options (`main/Kconfig.projbuild`) for transport selection and pin configuration.
- **Target Hardware Decoupling**:
  - Support single-core execution on ESP32-C3 and ESP32-C5 by removing hardcoded CPU1 task pinning.
  - Remove hardcoded `UART_NUM_2` and `GPIO_NUM_4/5`, parameterizing them with chip-safe defaults.
- **Client SDK Compatibility Guidance**: Document device filtering and identification strategies (handling both `0x2323:0x3434` and `0x303a:0x1001` with `PING` protocol handshake) for Web Serial and Flutter SDKs.

### Out of Scope
- Rewriting Nostr cryptographic signing algorithms (NIP-01, NIP-04, NIP-44 logic in `nostr.c` remains untouched).
- Wireless/BLE/Wi-Fi transport implementation (reserved for future changes).
- eFuse hardware burning automation for custom VID/PID on ESP32-C3/C5.

## Capabilities

### New Capabilities
- `device-transport`: Unified hardware abstraction layer for host communication, abstracting TinyUSB CDC-ACM, USB-Serial-JTAG, and UART transports.
- `target-config`: Multi-target build and runtime configuration system supporting ESP32-S3, ESP32-C3, ESP32-C5, and ESP32-P4 with target-specific defaults and single/dual-core task scheduling.

### Modified Capabilities
*(None; no existing capability specs in project)*

## Impact
- **Main Firmware**: `main/nesigner.c` is refactored to delegate communication to `main/transport/`.
- **Build System**: `CMakeLists.txt` and `idf_component.yml` conditionally include TinyUSB based on `CONFIG_SOC_USB_OTG_SUPPORTED`.
- **SDK Compatibility**: `js_nesigner_sdk` and `flutter_nesigner_sdk` can now connect to both S3/P4 and C5 devices.
- **ESP-IDF Version**: Requires ESP-IDF v5.3+ for full ESP32-C5 and ESP32-P4 toolchain support.
