# Spec Delta: target-config

## ADDED Requirements

### Requirement: Vendored secp256k1 Cryptographic Engine Dependency
The build system SHALL integrate `secp256k1` as a vendored local component located under `components/secp256k1`, providing constant-time Schnorr signature and ECDH acceleration across all hardware targets without requiring network access or external Git submodules during build.

#### Scenario: Clean clone build without submodules or network
- **WHEN** building firmware on a fresh clone where external submodules are uninitialized and network access is unavailable
- **THEN** CMake locates `components/secp256k1`, registers the component with 10x26 arithmetic and Schnorr/ECDH modules enabled, and successfully compiles `libsecp256k1.a`

#### Scenario: Multi-target compilation with vendored secp256k1
- **WHEN** compiling firmware for any supported target (`esp32s3`, `esp32c3`, `esp32c5`, `esp32c6`, `esp32s2`, `esp32p4`, `esp32s31`)
- **THEN** the compiler links against the local `secp256k1` component library headers and symbols without missing header or linkage errors

## MODIFIED Requirements

### Requirement: Conditional Component Dependency
The component manager manifest and CMake build configuration SHALL require `espressif/cjson` across all targets while omitting `esp_tinyusb` when building for targets that lack USB-OTG hardware support. The build system SHALL NOT depend on legacy `components/cJSON` or `.gitmodules` submodules.

#### Scenario: Component dependency resolution on non-OTG target
- **WHEN** resolving dependencies for `esp32c5` or `esp32c6` under ESP-IDF v6.1+
- **THEN** the build system resolves `espressif/cjson` from the registry and omits the `esp_tinyusb` component, completing build configuration cleanly

#### Scenario: Component dependency resolution on OTG target
- **WHEN** resolving dependencies for `esp32s2`, `esp32s3`, `esp32p4`, or `esp32s31` under ESP-IDF v6.1+
- **THEN** the `espressif/cjson` and `esp_tinyusb` components are fetched and linked into the firmware binary
