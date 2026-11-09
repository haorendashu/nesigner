# target-config Specification

## Purpose

Defines build system and runtime configurations supporting seamless targeting of ESP32-S3, ESP32-C3, ESP32-C5, ESP32-C6, ESP32-S2, ESP32-P4, and ESP32-S31 devices with chip-appropriate peripheral mapping, FreeRTOS core scheduling, and component dependencies.

## Requirements

### Requirement: Modular Target Configuration Defaults
The build system SHALL maintain shared default configuration parameters in `sdkconfig.defaults` and target-specific overrides in dedicated target defaults files for ESP32-S3, ESP32-C3, ESP32-C5, ESP32-C6, ESP32-S2, ESP32-P4, and ESP32-S31, compatible with ESP-IDF v6.1+ toolchains and silicon revisions.

#### Scenario: Building for ESP32-S3
- **WHEN** building firmware with target set to `esp32s3` under ESP-IDF v6.1+
- **THEN** the build system applies `sdkconfig.defaults` and `sdkconfig.defaults.esp32s3`, enabling secp256k1 and TinyUSB support

#### Scenario: Building for ESP32-C3
- **WHEN** building firmware with target set to `esp32c3` under ESP-IDF v6.1+
- **THEN** the build system applies `sdkconfig.defaults` and `sdkconfig.defaults.esp32c3`, enabling USB Serial/JTAG and single-core FreeRTOS settings

#### Scenario: Building for ESP32-C5
- **WHEN** building firmware with target set to `esp32c5` for production silicon (Revision v1.0~v1.99) under ESP-IDF v6.1+
- **THEN** the build system applies `sdkconfig.defaults` and `sdkconfig.defaults.esp32c5`, creating bootloader and application binaries compatible with Revision v1.2 hardware without revision mismatch errors

#### Scenario: Building for ESP32-C6
- **WHEN** building firmware with target set to `esp32c6` under ESP-IDF v6.1+
- **THEN** the build system applies `sdkconfig.defaults` and `sdkconfig.defaults.esp32c6`, enabling USB Serial/JTAG and single-core FreeRTOS settings

#### Scenario: Building for ESP32-S2
- **WHEN** building firmware with target set to `esp32s2` under ESP-IDF v6.1+
- **THEN** the build system applies `sdkconfig.defaults` and `sdkconfig.defaults.esp32s2`, enabling TinyUSB support on CPU0 and single-core FreeRTOS settings

#### Scenario: Building for ESP32-P4
- **WHEN** building firmware with target set to `esp32p4` under ESP-IDF v6.1+
- **THEN** the build system applies `sdkconfig.defaults` and `sdkconfig.defaults.esp32p4`, configuring high-performance RISC-V clocking and high-speed USB settings

#### Scenario: Building for ESP32-S31
- **WHEN** building firmware with target set to `esp32s31` under ESP-IDF v6.1+
- **THEN** the build system applies `sdkconfig.defaults` and `sdkconfig.defaults.esp32s31`, configuring 320MHz dual-core RISC-V clocking, hardware AES/SHA drivers, and USB High-Speed TinyUSB settings

### Requirement: Single-Core and Dual-Core Runtime Compatibility
The runtime task creation SHALL dynamically adapt to the target processor core count, executing on CPU0 on single-core devices and utilizing dual-core distribution on multi-core devices without triggering configuration panics.

#### Scenario: Task scheduling on single-core chip
- **WHEN** firmware initializes FreeRTOS tasks on a single-core ESP32-C3, ESP32-C5, ESP32-C6, or ESP32-S2 device
- **THEN** all background tasks (message handling, transport pump, response processing) run on core 0 without pinning to non-existent core 1

#### Scenario: Task scheduling on dual-core chip
- **WHEN** firmware initializes on a dual-core ESP32-S3, ESP32-P4, or ESP32-S31 device
- **THEN** crypto processing and communication tasks are scheduled across available cores

### Requirement: Conditional Component Dependency
The component manager manifest and CMake build configuration SHALL require `espressif/cjson` across all targets while omitting `esp_tinyusb` when building for targets that lack USB-OTG hardware support. The build system SHALL NOT depend on legacy `components/cJSON` or `.gitmodules` submodules.

#### Scenario: Component dependency resolution on non-OTG target
- **WHEN** resolving dependencies for `esp32c5` or `esp32c6` under ESP-IDF v6.1+
- **THEN** the build system resolves `espressif/cjson` from the registry and omits the `esp_tinyusb` component, completing build configuration cleanly

#### Scenario: Component dependency resolution on OTG target
- **WHEN** resolving dependencies for `esp32s2`, `esp32s3`, `esp32p4`, or `esp32s31` under ESP-IDF v6.1+
- **THEN** the `espressif/cjson` and `esp_tinyusb` components are fetched and linked into the firmware binary

### Requirement: Vendored secp256k1 Cryptographic Engine Dependency
The build system SHALL integrate `secp256k1` as a vendored local component located under `components/secp256k1`, providing constant-time Schnorr signature and ECDH acceleration across all hardware targets without requiring network access or external Git submodules during build.

#### Scenario: Clean clone build without submodules or network
- **WHEN** building firmware on a fresh clone where external submodules are uninitialized and network access is unavailable
- **THEN** CMake locates `components/secp256k1`, registers the component with 10x26 arithmetic and Schnorr/ECDH modules enabled, and successfully compiles `libsecp256k1.a`

#### Scenario: Multi-target compilation with vendored secp256k1
- **WHEN** compiling firmware for any supported target (`esp32s3`, `esp32c3`, `esp32c5`, `esp32c6`, `esp32s2`, `esp32p4`, `esp32s31`)
- **THEN** the compiler links against the local `secp256k1` component library headers and symbols without missing header or linkage errors
