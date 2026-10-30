# Spec Delta: device-transport

## Purpose

Provides a hardware-abstracted transport layer allowing the nesigner firmware to exchange structured Nostr frames with host applications across USB-OTG, USB Serial/JTAG, and UART interfaces.

## ADDED Requirements

### Requirement: TinyUSB Transport on USB-OTG Targets
On hardware targets equipped with USB-OTG peripherals, the system SHALL establish a CDC-ACM communication interface using custom vendor ID 0x2323 and product ID 0x3434, supporting bi-directional frame delivery and line state notifications.

#### Scenario: Host connection over TinyUSB
- **WHEN** an ESP32-S3 or ESP32-P4 device is connected to a host USB port
- **THEN** the device enumerates with VID 0x2323, PID 0x3434 and accepts Nostr protocol frames over the CDC endpoint

#### Scenario: Line state changed
- **WHEN** the host changes DTR or RTS line states on the TinyUSB CDC interface
- **THEN** the firmware receives the state change notification without dropping queued message buffers

### Requirement: Native USB Serial/JTAG Transport on Non-OTG Targets
On hardware targets lacking USB-OTG peripherals, the system SHALL communicate using the silicon's built-in USB Serial/JTAG controller, receiving and transmitting Nostr protocol frames through the hardware CDC-ACM channel.

#### Scenario: Host communication over USB Serial/JTAG
- **WHEN** an ESP32-C3 or ESP32-C5 device is connected to a host USB port
- **THEN** the device communicates over the native USB Serial/JTAG channel using default Espressif identification (VID 0x303a, PID 0x1001)

#### Scenario: Data reception without buffer overflow
- **WHEN** incoming bytes arrive faster than protocol frame parsing
- **THEN** data is read into intermediate ring buffers and forwarded to the protocol parser queue without blocking hardware interrupts

### Requirement: Configurable UART Fallback Transport
The system SHALL provide a hardware UART transport backend that can be configured through build settings to operate on target-supported UART ports and pins.

#### Scenario: Frame reception via UART
- **WHEN** valid framed binary messages arrive on configured UART RX pins
- **THEN** the firmware validates the frame CRC and dispatches the payload to the request processing queue

#### Scenario: Response transmission via UART
- **WHEN** a signed Nostr response or error is ready for output
- **THEN** the data is packetized with header and CRC16 and transmitted over UART TX

### Requirement: Unified Message Frame Delivery
The transport abstraction SHALL deliver incoming raw bytes to the frame parser in consistent order regardless of the underlying hardware transport backend in use.

#### Scenario: Protocol frame boundary recognition
- **WHEN** a full request frame containing type, message ID, public key, IV, length header, encrypted data, and CRC arrives on any active transport
- **THEN** the message parser successfully validates the CRC and enqueues the message for Nostr processing
