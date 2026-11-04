# Design

## Context

See `proposal.md` for motivation. The `nesigner` firmware currently supports six ESP32 targets (`esp32s3`, `esp32s2`, `esp32c3`, `esp32c5`, `esp32c6`, and `esp32p4`). ESP-IDF v6.1 natively integrates support for `esp32s31`, a dual-core 32-bit RISC-V processor operating up to 320 MHz, featuring native High-Speed USB 2.0 (UTMI PHY), GDMA-assisted AES/SHA hardware accelerators, and TRNG.

## Goals / Non-Goals

**Goals:**
- Provide a dedicated target configuration defaults file `sdkconfig.defaults.esp32s31` enabling 320 MHz CPU frequency, High-Speed TinyUSB CDC-ACM transport, and hardware AES/SHA accelerators.
- Integrate `esp32s31` into `main/idf_component.yml` to automatically pull `espressif/esp_tinyusb` for OTG builds.
- Configure `main/Kconfig.projbuild` UART pin fallback and transport selection defaults for `IDF_TARGET_ESP32S31`.
- Ensure dual-core FreeRTOS task scheduling splits USB transport pump and cryptographic computation across Core 0 and Core 1.
- Update project documentation and build matrix with S31 commands and specifications.

**Non-Goals:**
- Hardware ECC acceleration for secp256k1: The S31 hardware ECC engine only accelerates Weierstrass curves (NIST P-192/P-256/P-384, SM2). Nostr secp256k1 BIP-340 Schnorr signatures continue to use `libsecp256k1`, leveraging 320 MHz CPU clock and compiler optimization.
- Modifying client-side Web/Desktop SDK protocol: Custom VID:PID (`0x2323:0x3434`) aligns with existing S3/P4 desktop and web detection filters.

## Decisions

### Decision 1: Default Transport Selection
- **Choice**: Default to TinyUSB CDC-ACM (`CONFIG_SIGNER_TRANSPORT_TINYUSB=y`) using High-Speed USB 2.0.
- **Rationale**: ESP32-S31 includes internal UTMI High-Speed PHY. Using TinyUSB matches S3 and P4 architectures with custom VID:PID (`0x2323:0x3434`), allowing existing client SDKs to automatically detect the device. Native USB Serial/JTAG remains available as a secondary fallback.
- **Alternatives Considered**: Native USB Serial/JTAG as default. Rejected because it uses standard Espressif VID:PID (`0x303a:0x1001`), which requires generic port selection and lacks custom device identification.

### Decision 2: Cryptographic Acceleration Strategy
- **Choice**: Enable hardware AES and SHA engines in mbedTLS (`CONFIG_MBEDTLS_HARDWARE_AES=y`, `CONFIG_MBEDTLS_HARDWARE_SHA=y`) with GDMA; run `libsecp256k1` with 64 KiB precomputed scalar tables.
- **Rationale**: Nostr uses SHA-256 for event IDs, BIP-340 tagged hashes, and NIP-44 HKDF, and AES-256-CBC for NIP-04. These are offloaded to hardware GDMA engines. `secp256k1` scalar multiplication is purely CPU-bound and gains maximum performance from the 320 MHz RISC-V clock and precomputed lookup tables.
- **Alternatives Considered**: Attempting to use the hardware ECC peripheral for secp256k1. Rejected because hardware state machine does not support Koblitz curve equations.

### Decision 3: Multicore Task Pinning and Buffer Sizing
- **Choice**: Allocate 1024-byte TinyUSB CDC RX/TX buffers (identical to P4), pinning the USB communication pump to Core 0 while executing Nostr cryptographic signing on Core 1.
- **Rationale**: Prevents USB packet drops during heavy signature calculations or multi-event batches.

### Decision 4: TinyUSB High-Speed OTG Port Mapping for ESP32-S31
- **Choice**: Map TinyUSB High-Speed OTG to `CFG_TUSB_RHPORT0_MODE = OPT_MODE_DEVICE | OPT_MODE_HIGH_SPEED` and route ESP-IDF system console output to USB Serial/JTAG (`CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y`).
- **Rationale**: On ESP32-P4, High-Speed OTG was at Port 1 because Port 0 was mapped to OTG 1.1 FS. ESP32-S31 has only one OTG controller (internal UTMI High-Speed PHY), which TinyUSB DWC2 exposes as port index 0 (`_dwc2_controller[0]`). Configuring RHPORT0 enables High-Speed mode without out-of-bounds array faults. Routing system console to USB Serial/JTAG keeps the TinyUSB OTG CDC-ACM channel cleanly isolated for framed binary Nostr protocol packets.

## Risks / Trade-offs

- **[Risk] Build failure on toolchains earlier than ESP-IDF v6.1**  
  → *Mitigation*: Specify minimum IDF version `>=6.1.0` in `main/idf_component.yml` and explicitly document toolchain requirements in `README.md`.
- **[Risk] USB High-Speed Signal Integrity**  
  → *Mitigation*: Use 1024-byte CDC buffers and DMA-backed transfers to accommodate burst packet rates.
