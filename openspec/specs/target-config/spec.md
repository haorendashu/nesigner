# target-config Specification

## Purpose

Defines build system and runtime configurations supporting seamless targeting of ESP32-S3, ESP32-C3, ESP32-C5, ESP32-C6, ESP32-S2, and ESP32-P4 devices with chip-appropriate peripheral mapping, FreeRTOS core scheduling, and component dependencies.

## Requirements

### Requirement: Modular Target Configuration Defaults
The build system SHALL maintain shared default configuration parameters in `sdkconfig.defaults` and target-specific overrides in dedicated target defaults files for ESP32-S3, ESP32-C3, ESP32-C5, ESP32-C6, ESP32-S2, and ESP32-P4.

#### Scenario: Building for ESP32-S3
- **WHEN** building firmware with target set to `esp32s3`
- **THEN** the build system applies `sdkconfig.defaults` and `sdkconfig.defaults.esp32s3`, enabling secp256k1 and TinyUSB support

#### Scenario: Building for ESP32-C3
- **WHEN** building firmware with target set to `esp32c3`
- **THEN** the build system applies `sdkconfig.defaults` and `sdkconfig.defaults.esp32c3`, enabling USB Serial/JTAG and single-core FreeRTOS settings

#### Scenario: Building for ESP32-C5
- **WHEN** building firmware with target set to `esp32c5`
- **THEN** the build system applies `sdkconfig.defaults` and `sdkconfig.defaults.esp32c5`, enabling USB Serial/JTAG and single-core FreeRTOS settings

#### Scenario: Building for ESP32-C6
- **WHEN** building firmware with target set to `esp32c6`
- **THEN** the build system applies `sdkconfig.defaults` and `sdkconfig.defaults.esp32c6`, enabling USB Serial/JTAG and single-core FreeRTOS settings

#### Scenario: Building for ESP32-S2
- **WHEN** building firmware with target set to `esp32s2`
- **THEN** the build system applies `sdkconfig.defaults` and `sdkconfig.defaults.esp32s2`, enabling TinyUSB support on CPU0 and single-core FreeRTOS settings

#### Scenario: Building for ESP32-P4
- **WHEN** building firmware with target set to `esp32p4`
- **THEN** the build system applies `sdkconfig.defaults` and `sdkconfig.defaults.esp32p4`, configuring high-performance RISC-V clocking and high-speed USB settings

### Requirement: Single-Core and Dual-Core Runtime Compatibility
The runtime task creation SHALL dynamically adapt to the target processor core count, executing on CPU0 on single-core devices and utilizing dual-core distribution on multi-core devices without triggering configuration panics.

#### Scenario: Task scheduling on single-core chip
- **WHEN** firmware initializes FreeRTOS tasks on a single-core ESP32-C3, ESP32-C5, ESP32-C6, or ESP32-S2 device
- **THEN** all background tasks (message handling, transport pump, response processing) run on core 0 without pinning to non-existent core 1

#### Scenario: Task scheduling on dual-core chip
- **WHEN** firmware initializes on a dual-core ESP32-S3 or ESP32-P4 device
- **THEN** crypto processing and communication tasks are scheduled across available cores

### Requirement: Conditional Component Dependency
The component manager manifest and CMake build configuration SHALL omit `esp_tinyusb` when building for targets that lack USB-OTG hardware support.

#### Scenario: Component dependency resolution on non-OTG target
- **WHEN** resolving dependencies for `esp32c5` or `esp32c6`
- **THEN** the build system does not require or compile the `esp_tinyusb` component, completing build configuration cleanly

#### Scenario: Component dependency resolution on OTG target
- **WHEN** resolving dependencies for `esp32s2`, `esp32s3`, or `esp32p4`
- **THEN** the `esp_tinyusb` component is fetched and linked into the firmware binary
