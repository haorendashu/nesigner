# Design: Multi-Target ESP32 Support Architecture

## Context

The nesigner codebase previously ran solely on ESP32-S3. All host USB communication was directly bound to `esp_tinyusb` APIs within `main/nesigner.c`, which also hardcoded dual-core task priorities (`CPU1`), UART controller `UART_NUM_2`, and board-specific pins (`GPIO_NUM_4/5`). 

Chips like the ESP32-C5 feature a 32-bit RISC-V core with Wi-Fi 6 and Bluetooth 5, but lack USB-OTG hardware—meaning `esp_tinyusb` cannot be compiled or run on C5. Instead, C5 provides a built-in USB Serial/JTAG controller (`driver/usb_serial_jtag.h`) with fixed vendor/product IDs (`0x303a:0x1001`). Meanwhile, the ESP32-P4 features dual-core high-speed RISC-V with USB 2.0 High-Speed OTG (supporting TinyUSB in HS mode).

See `proposal.md` for background and motivation, and `specs/` for behavioral requirements.

## Goals / Non-Goals

**Goals:**
- **Zero Regression on ESP32-S3**: Preserve 100% existing functionality, USB descriptors (`0x2323:0x3434`), throughput, and reliability on ESP32-S3.
- **Hardware Abstraction Layer (HAL)**: Decouple communication mechanics from business logic (`nostr.c`, `store.c`, `memory_pool.c`).
- **Clean ESP32-C3 / ESP32-C5 Support**: Provide a lightweight USB Serial/JTAG transport driver for C3 and C5 without TinyUSB dependency.
- **ESP32-P4 Readiness**: Prepare configuration and transport pathways for P4 high-speed USB and RISC-V.
- **Standardized Multi-Target Config**: Use ESP-IDF idiomatic `sdkconfig.defaults` and `sdkconfig.defaults.<target>`.

**Non-Goals:**
- Implementing Bluetooth/Wi-Fi remote signer protocols in this change.
- Writing to eFuse to alter USB Serial/JTAG hardware IDs on C5.
- Changing Nostr protocol message formats or encryption schemes.

## Architecture & Decisions

### 1. Transport Layer Abstraction (HAL)

```
+--------------------------------------------------------------------+
|                Protocol & Nostr Engine (nesigner.c)                |
|      (Frames, CRC16, AES-CBC, secp256k1, memory pool, NVS)         |
+--------------------------------------------------------------------+
                                  |
                                  v
+--------------------------------------------------------------------+
|               Signer Transport Interface (transport.h)             |
|   - signer_transport_init(rx_cb)                                   |
|   - signer_transport_send(data, len)                               |
+--------------------------------------------------------------------+
            |                                         |
 (Target: S3, P4 / USB-OTG)              (Target: C5 / USB Serial/JTAG)
            v                                         v
+-----------------------+                 +--------------------------+
|  transport_tinyusb.c  |                 | transport_usb_serial.c   |
| - Custom VID/PID      |                 | - Native IDF Driver      |
| - CDC callbacks       |                 | - Rx Background Task     |
| - EP buffer flush     |                 | - Stream byte parsing    |
+-----------------------+                 +--------------------------+
```

**Decision**: Define a minimal C interface in `main/transport/signer_transport.h`:
```c
typedef void (*signer_rx_callback_t)(const uint8_t *data, size_t len);

typedef struct {
    esp_err_t (*init)(signer_rx_callback_t rx_cb);
    esp_err_t (*send)(const uint8_t *data, size_t len);
} signer_transport_backend_t;

extern const signer_transport_backend_t *signer_transport_get_default(void);
```

*Rationale*:
- Low overhead: Directly calls the selected backend function pointer without virtual table complexity.
- Asynchronous Rx: Inbound bytes are passed directly to the frame assembler, matching the existing `usb_msg_buffer` assembly in `nesigner.c`.
*Alternatives considered*:
- FreeRTOS stream buffers between transport and protocol: Adds unnecessary buffer copies when `memory_pool` is already used for zero-copy handling.

---

### 2. Component Dependency & CMake Segregation

**Decision**:
- Only link `espressif/esp_tinyusb` when `CONFIG_SOC_USB_OTG_SUPPORTED` is true or `CONFIG_SIGNER_TRANSPORT_TINYUSB` is selected.
- In `CMakeLists.txt`, select the transport source file dynamically:
```cmake
if(CONFIG_SIGNER_TRANSPORT_TINYUSB)
    list(APPEND TRANSPORT_SRCS "transport/transport_tinyusb.c")
elseif(CONFIG_SIGNER_TRANSPORT_USB_SERIAL_JTAG)
    list(APPEND TRANSPORT_SRCS "transport/transport_usb_serial_jtag.c")
elseif(CONFIG_SIGNER_TRANSPORT_UART)
    list(APPEND TRANSPORT_SRCS "transport/transport_uart.c")
endif()
```
- For `idf_component.yml`, use `rules` or target restrictions:
```yaml
dependencies:
  idf:
    version: ">=5.3.0"
  espressif/esp_tinyusb:
    version: "^1.7.2"
    rules:
      - if: "target in [esp32s2, esp32s3, esp32p4]"
```

*Rationale*: Prevents compilation failure on ESP32-C5 caused by the missing USB-OTG peripheral.

---

### 3. Multi-Target Build & Kconfig Strategy

**Decision**:
- Create `sdkconfig.defaults`:
  - `CONFIG_MBEDTLS_ECP_DP_SECP256K1_ENABLED=y`
  - `CONFIG_FREERTOS_HZ=1000`
- Create `sdkconfig.defaults.esp32s3`:
  - `CONFIG_SIGNER_TRANSPORT_TINYUSB=y`
  - `CONFIG_TINYUSB_CDC_ENABLED=y`
  - `CONFIG_TINYUSB_TASK_AFFINITY_CPU1=y`
- Create `sdkconfig.defaults.esp32c5`:
  - `CONFIG_SIGNER_TRANSPORT_USB_SERIAL_JTAG=y`
  - Single-core task affinity (no CPU1)
- Create `sdkconfig.defaults.esp32p4`:
  - `CONFIG_SIGNER_TRANSPORT_TINYUSB=y`
  - High-performance settings

---

### 4. Client SDK Multi-Device Identification Strategy

**Decision**:
1. **Web SDK (`js_nesigner_sdk`)**: Update `navigator.serial.requestPort({ filters })` to accept both:
   - `{ usbVendorId: 0x2323, usbProductId: 0x3434 }` (S3/P4)
   - `{ usbVendorId: 0x303a, usbProductId: 0x1001 }` (C5/C3/C6)
2. **Flutter SDK (`flutter_nesigner_sdk`)**:
   - For desktop and mobile, prioritize the existing `BaseSerialPort` (standard COM/CDC-ACM driver) channel for cross-chip compatibility.
   - For device validation, send a `MSG_TYPE_PING (0)` packet; only valid nesigner devices will reply with a signed/formatted response.

## Risks / Trade-offs

- **[Risk]** Host OS CDC driver conflicts on Windows/macOS with USB Serial/JTAG.
  → *Mitigation*: Unlike custom WinUSB endpoints that require Zadig, native USB Serial/JTAG is natively handled by Windows `usbser.sys` and macOS CDC without custom drivers.
- **[Risk]** Single-core ESP32-C5 task starvation if USB reader blocks CPU.
  → *Mitigation*: The USB-Serial-JTAG read task runs at priority 8 with `vTaskDelay` or event-driven yield, allowing `handle_message_task` (priority 10) to process crypto payloads immediately.
- **[Risk]** ESP-IDF version incompatibility (ESP32-C5 and P4 requiring IDF v5.3+).
  → *Mitigation*: Keep baseline IDF version requirement at `>=5.3.0` in `idf_component.yml`. S3 is fully verified on IDF v5.3+.

## Migration Plan

1. Extract TinyUSB code from `main/nesigner.c` into `main/transport/transport_tinyusb.c`.
2. Build and verify ESP32-S3 firmware against existing test suite and SDK.
3. Add `main/transport/transport_usb_serial_jtag.c` and target defaults for `esp32c5`.
4. Build target `esp32c5` and verify UART / USB-Serial-JTAG communication.
