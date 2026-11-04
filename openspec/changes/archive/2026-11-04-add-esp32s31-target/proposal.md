# Proposal

## Why

The ESP32-S31 is Espressif's high-performance dual-core 32-bit RISC-V SoC (clocked up to 320 MHz) equipped with native High-Speed USB 2.0 OTG, advanced security features (hardware AES/SHA with DMA, PUF, ECC), and Wi-Fi 6 / 802.15.4 connectivity, officially supported in ESP-IDF v6.1+. Adding first-class support for `esp32s31` enables nesigner users to leverage S31 boards with high-throughput USB CDC communication and accelerated cryptographic processing.

## What Changes

- Add target configuration defaults `sdkconfig.defaults.esp32s31` setting default CPU frequency to 320 MHz, enabling USB High-Speed TinyUSB CDC-ACM transport, and enabling mbedTLS hardware acceleration for AES and SHA.
- Update `main/idf_component.yml` to include `esp32s31` under `espressif/esp_tinyusb` dependency rules.
- Update `main/Kconfig.projbuild` to support `IDF_TARGET_ESP32S31` with default UART port/pin assignments and transport options.
- Update `CMakeLists.txt` and project documentation (`README.md`) to document ESP32-S31 target build, flash instructions, and transport capabilities.
- Update `target-config` and `device-transport` specs to include ESP32-S31 requirements and test scenarios.

## Capabilities

### New Capabilities
*(None)*

### Modified Capabilities
- `target-config`: Add ESP32-S31 target default configuration requirements, dual-core RISC-V scheduling compatibility, and conditional component dependency rules.
- `device-transport`: Add ESP32-S31 USB-OTG TinyUSB CDC-ACM transport enumeration and communication scenarios.

## Impact

- **Affected files**:
  - `sdkconfig.defaults.esp32s31` (new file)
  - `main/idf_component.yml` (TinyUSB dependency rule)
  - `main/Kconfig.projbuild` (UART and transport selection options)
  - `README.md` (target support matrix, build commands, and USB descriptors)
- **Toolchain**: Requires ESP-IDF v6.1+ where `esp32s31` target is natively supported.
- **Breaking changes**: None. Existing target builds remain unchanged.
