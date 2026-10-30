# Tasks: Multi-Target ESP32 Support

## 1. Build System & Target Configuration Scaffolding

- [x] 1.1 Create `main/Kconfig.projbuild` declaring transport choices (`CONFIG_SIGNER_TRANSPORT_TINYUSB`, `CONFIG_SIGNER_TRANSPORT_USB_SERIAL_JTAG`, `CONFIG_SIGNER_TRANSPORT_UART`) and UART pin configurations. Verify options appear in `idf.py menuconfig`.
- [x] 1.2 Create `sdkconfig.defaults` with shared settings (`CONFIG_MBEDTLS_ECP_DP_SECP256K1_ENABLED=y`, FreeRTOS 1000Hz tick rate, NVS). Verify settings are applied across targets.
- [x] 1.3 Create target-specific defaults: `sdkconfig.defaults.esp32s3`, `sdkconfig.defaults.esp32c5`, and `sdkconfig.defaults.esp32p4`. Verify each target applies its respective configuration file.
- [x] 1.4 Update `main/idf_component.yml` to specify minimum IDF version `>=5.3.0` and make `espressif/esp_tinyusb` conditional for targets with USB-OTG. Verify `esp32c5` configuration does not require TinyUSB.

## 2. Transport Hardware Abstraction Layer (HAL)

- [x] 2.1 Define the transport abstraction interface in `main/transport/signer_transport.h` with `init(rx_cb)` and `send(data, len)`. Verify interface headers compile cleanly.
- [x] 2.2 Extract TinyUSB CDC-ACM driver into `main/transport/transport_tinyusb.c`, preserving custom VID `0x2323`, PID `0x3434`, descriptors, and queue handling. Verify compilation on ESP32-S3.
- [x] 2.3 Implement the USB Serial/JTAG backend in `main/transport/transport_usb_serial_jtag.c` using `driver/usb_serial_jtag.h` and a background receiver task. Verify compilation on ESP32-C5.
- [x] 2.4 Update `main/CMakeLists.txt` to conditionally compile the appropriate transport source file based on Kconfig. Verify CMake correctly selects files for S3 and C5.

## 3. Core Firmware Decoupling & Hardware Parameterization

- [x] 3.1 Refactor `main/nesigner.c` to delegate host communication to `signer_transport` instead of direct TinyUSB calls. Verify message parsing and response queues remain operational.
- [x] 3.2 Remove hardcoded `UART_NUM_2` and fixed GPIO 4/5, parameterizing UART configurations using Kconfig defaults safe for C5 (UART1) and S3/P4. Verify UART initialization succeeds.
- [x] 3.3 Audit FreeRTOS task creation in `main/nesigner.c` and transport backends to remove hardcoded `CPU1` pinning, allowing tasks to run with `tskNO_AFFINITY` on both single-core (C5) and multi-core (S3, P4) devices. Verify startup on single-core configurations.

## 4. Multi-Target Build Verification & Documentation

- [x] 4.1 Build for ESP32-S3 (`idf.py set-target esp32s3 && idf.py build`) and verify complete binary generation and TinyUSB enumeration.
- [x] 4.2 Build for ESP32-C5 (`idf.py set-target esp32c5 && idf.py build`) and verify complete binary generation and USB Serial/JTAG initialization.
- [x] 4.3 Build for ESP32-P4 (`idf.py set-target esp32p4 && idf.py build`) and verify complete binary generation.
- [x] 4.4 Build for ESP32-C3 (`idf.py set-target esp32c3 && idf.py build`) and verify complete binary generation with USB Serial/JTAG transport.
- [x] 4.5 Update `README.md` with multi-target build instructions (`idf.py set-target`) and client SDK compatibility guidance (handling VID `0x2323` and `0x303a`). Verify documentation accuracy.
