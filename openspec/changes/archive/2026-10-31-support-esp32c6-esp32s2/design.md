# Technical Design: ESP32-C6 and ESP32-S2 Target Support

## Context

`nesigner` uses an abstracted hardware transport layer (`signer_transport`) and ESP-IDF modular target configuration files (`sdkconfig.defaults.<target>`) to target different Espressif SoCs. See `proposal.md` for motivation and background.

Currently supported targets:
- **ESP32-S3**: Xtensa Dual-Core, USB-OTG (TinyUSB, custom VID:PID `0x2323:0x3434`).
- **ESP32-C3**: RISC-V Single-Core, USB Serial/JTAG (VID:PID `0x303a:0x1001`).
- **ESP32-C5**: RISC-V Single-Core, USB Serial/JTAG (VID:PID `0x303a:0x1001`).
- **ESP32-P4**: RISC-V Dual-Core, USB-OTG High-Speed (TinyUSB, custom VID:PID `0x2323:0x3434`).

Hardware characteristics of the new targets:
- **ESP32-C6**: 160MHz 32-bit RISC-V single-core SoC. Contains a built-in USB Serial/JTAG controller (`SOC_USB_SERIAL_JTAG_SUPPORTED`), identical in transport capability to ESP32-C3/C5. Does not support USB-OTG.
- **ESP32-S2**: 240MHz 32-bit Xtensa LX7 single-core SoC. Contains a full-speed USB-OTG peripheral (`SOC_USB_OTG_SUPPORTED`), identical in USB capability to ESP32-S3. Does not contain USB Serial/JTAG.

## Goals / Non-Goals

**Goals:**
- Provide zero-configuration compilation via `idf.py set-target esp32c6` and `idf.py set-target esp32s2`.
- Map ESP32-C6 to native USB Serial/JTAG transport and disable secondary console to prevent frame corruption.
- Map ESP32-S2 to TinyUSB CDC-ACM transport with CPU0 task affinity.
- Maintain clean dependency resolution without pulling unnecessary components (e.g. omit `esp_tinyusb` on C6).
- Document build steps and client SDK filter requirements in `README.md`.

**Non-Goals:**
- Supporting wireless networking (Wi-Fi 6, BLE, Zigbee/Thread) on C6; nesigner operates over direct serial/USB protocols.
- Classic ESP32 support (deferred to a separate change focused on UART0 console isolation).
- Altering Nostr protocol wire format or cryptographic algorithms.

## Decisions

### Decision 1: Transport Backend Selection
- **ESP32-C6**: Use `CONFIG_SIGNER_TRANSPORT_USB_SERIAL_JTAG=y`.
  - *Rationale*: C6 silicon features native hardware USB Serial/JTAG. It requires no external components or software USB stack, consuming minimal memory and CPU overhead.
  - *Console Isolation*: Set `CONFIG_ESP_CONSOLE_SECONDARY_NONE=y` so debug logs do not interleave with binary Nostr protocol frames.
  - *Alternative Considered*: TinyUSB was rejected because C6 lacks USB-OTG hardware.
- **ESP32-S2**: Use `CONFIG_SIGNER_TRANSPORT_TINYUSB=y`.
  - *Rationale*: S2 silicon features native USB-OTG hardware and lacks USB Serial/JTAG. TinyUSB CDC-ACM provides USB connectivity with custom VID:PID `0x2323:0x3434`.
  - *Alternative Considered*: Standard UART was rejected as primary transport because USB-OTG provides direct plug-and-play USB connectivity on S2 development boards.

### Decision 2: FreeRTOS Core Scheduling & Affinity
- Both ESP32-C6 and ESP32-S2 are single-core processors.
- ESP32-S3 default configs assign TinyUSB tasks to CPU1 (`CONFIG_TINYUSB_TASK_AFFINITY_CPU1=y`).
- For ESP32-S2, we explicitly configure `CONFIG_TINYUSB_TASK_AFFINITY_CPU0=y`.
  - *Rationale*: Pinning to CPU1 on a single-core chip causes FreeRTOS configuration errors and runtime panics.

### Decision 3: UART Fallback Pin Mapping in Kconfig
- `main/Kconfig.projbuild` already has default conditions for port selection:
  - `default 1 if IDF_TARGET_ESP32C5 || IDF_TARGET_ESP32C3 || IDF_TARGET_ESP32C6`
- Verify and add default GPIO mappings for C6 and S2 UART fallback:
  - C6: TX GPIO 16, RX GPIO 17 (standard UART0) or TX GPIO 21, RX GPIO 22 (UART1).
  - S2: TX GPIO 17, RX GPIO 18 (UART1) or default GPIOs.

### Decision 4: Component Manager Dependencies
- In `main/idf_component.yml`:
  ```yaml
  espressif/esp_tinyusb:
    version: '^1.7.2'
    rules:
      - if: "target in [esp32s2, esp32s3, esp32p4]"
  ```
  The rule already includes `esp32s2` and excludes `esp32c6`. No structural modifications to `idf_component.yml` are required, but its behavior will be validated during build.

## Risks / Trade-offs

- **[Risk] S2 Memory Constraints**: ESP32-S2 has 320 KB SRAM compared to S3's 512 KB SRAM.
  - *Mitigation*: `nesigner` memory architecture uses static pool allocation with modest stack sizes (16 KB main task, 4 KB transport task) and secp256k1 context caching. Peak memory usage is well under 120 KB, leaving over 150 KB free heap.
- **[Risk] Client Host Discovery**: Web Serial or desktop host software may only scan for one VID/PID pair.
  - *Mitigation*: Document both VID:PID combinations (`0x2323:0x3434` for S2/S3/P4, `0x303a:0x1001` for C3/C5/C6) in `README.md` and Client SDK instructions.
