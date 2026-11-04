# Tasks

## 1. Target and Component Configuration

- [x] 1.1 Create `sdkconfig.defaults.esp32s31` configuring 320 MHz CPU frequency (`CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ_320=y`), High-Speed TinyUSB CDC-ACM transport buffers (`CONFIG_SIGNER_TRANSPORT_TINYUSB=y`), and hardware mbedTLS AES/SHA acceleration flags, verifying file creation and syntax.
- [x] 1.2 Update `main/idf_component.yml` to include `esp32s31` in the `espressif/esp_tinyusb` target inclusion rule (`target in [esp32s2, esp32s3, esp32p4, esp32s31]`), verifying valid YAML formatting.
- [x] 1.3 Update `main/Kconfig.projbuild` to support `IDF_TARGET_ESP32S31` in UART port and pin configuration defaults and transport prompt descriptions, verifying Kconfig syntax.

## 2. Documentation and Verification

- [x] 2.1 Update `README.md` to document ESP32-S31 in the Supported Targets & Transport Matrix, build/flash instructions (`idf.py set-target esp32s31`), and USB VID/PID table, verifying Markdown rendering.
- [x] 2.2 Validate the complete change artifacts and requirement consistency using `openspec validate add-esp32s31-target` and verify clean validation status.
