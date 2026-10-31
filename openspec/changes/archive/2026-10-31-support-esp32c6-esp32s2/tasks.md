# Tasks: Support ESP32-C6 and ESP32-S2 Targets

## 1. Target Configurations and Defaults

- [x] 1.1 Create `sdkconfig.defaults.esp32c6` with `CONFIG_IDF_TARGET="esp32c6"`, native USB Serial/JTAG transport (`CONFIG_SIGNER_TRANSPORT_USB_SERIAL_JTAG=y`), secondary console disabled (`CONFIG_ESP_CONSOLE_SECONDARY_NONE=y`), and UART fallback defaults; verify file syntax.
- [x] 1.2 Create `sdkconfig.defaults.esp32s2` with `CONFIG_IDF_TARGET="esp32s2"`, TinyUSB transport (`CONFIG_SIGNER_TRANSPORT_TINYUSB=y`), single-core task affinity (`CONFIG_TINYUSB_TASK_AFFINITY_CPU0=y`), and TinyUSB CDC buffers; verify file syntax.

## 2. Kconfig and Build Infrastructure Updates

- [x] 2.1 Update `main/Kconfig.projbuild` to ensure default UART pins and ports appropriately handle `IDF_TARGET_ESP32C6` and `IDF_TARGET_ESP32S2`.
- [x] 2.2 Validate component manager dependencies in `main/idf_component.yml` to ensure `espressif/esp_tinyusb` correctly fetches for `esp32s2` and is excluded for `esp32c6`.

## 3. Build Verification

- [x] 3.1 Run `idf.py set-target esp32c6` and build firmware to verify clean compilation with native USB Serial/JTAG.
- [x] 3.2 Run `idf.py set-target esp32s2` and build firmware to verify clean compilation with TinyUSB CDC-ACM.

## 4. Documentation Updates

- [x] 4.1 Update `README.md` target matrix, build instructions, udev rules, and client SDK compatibility guidance to document ESP32-C6 and ESP32-S2 support.
