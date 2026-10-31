# Proposal: Support ESP32-C6 and ESP32-S2 Targets

## Why

Developers and users have access to a wide variety of Espressif development boards. Adding support for ESP32-C6 (a cost-effective Wi-Fi 6 RISC-V SoC with native USB Serial/JTAG) and ESP32-S2 (a single-core Xtensa SoC with native USB-OTG) expands the hardware compatibility of the `nesigner` Nostr hardware signer, allowing users to run signer firmware on their existing C6 and S2 dev boards without requiring new hardware.

## What Changes

- Add target-specific default configurations (`sdkconfig.defaults.esp32c6` and `sdkconfig.defaults.esp32s2`).
- Configure ESP32-C6 to use native USB Serial/JTAG (`CONFIG_SIGNER_TRANSPORT_USB_SERIAL_JTAG=y`, VID `0x303a`, PID `0x1001`) with secondary console disabled.
- Configure ESP32-S2 to use TinyUSB CDC-ACM (`CONFIG_SIGNER_TRANSPORT_TINYUSB=y`, VID `0x2323`, PID `0x3434`) with CPU0 task affinity.
- Verify `idf_component.yml` rules include `esp32s2` for `espressif/esp_tinyusb` dependency resolution and omit it for `esp32c6`.
- Update project documentation (`README.md`) with build instructions and transport compatibility matrix for ESP32-C6 and ESP32-S2.

## Capabilities

### New Capabilities
<!-- None: existing target-config and device-transport capabilities cover these behaviors. -->

### Modified Capabilities
- `target-config`: Add ESP32-C6 and ESP32-S2 build target configurations, single-core FreeRTOS task scheduling rules, and component dependency rules.
- `device-transport`: Add ESP32-C6 to the native USB Serial/JTAG transport specification and ESP32-S2 to the TinyUSB CDC-ACM transport specification.

## Impact

- **Build System**: New `sdkconfig.defaults.esp32c6` and `sdkconfig.defaults.esp32s2` files.
- **Kconfig**: Ensure `main/Kconfig.projbuild` default UART and transport options correctly recognize `IDF_TARGET_ESP32C6` and `IDF_TARGET_ESP32S2`.
- **Component Manager**: `main/idf_component.yml` already contains `esp32s2` in its TinyUSB target list; verify no component conflicts arise when targeting `esp32c6`.
- **Documentation**: Update `README.md` target matrix, build commands, and client SDK compatibility guidance.
