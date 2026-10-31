# Spec Delta: device-transport

## MODIFIED Requirements

### Requirement: TinyUSB Transport on USB-OTG Targets
On hardware targets equipped with USB-OTG peripherals, the system SHALL establish a CDC-ACM communication interface using custom vendor ID 0x2323 and product ID 0x3434, supporting bi-directional frame delivery and line state notifications.

#### Scenario: Host connection over TinyUSB
- **WHEN** an ESP32-S2, ESP32-S3, or ESP32-P4 device is connected to a host USB port
- **THEN** the device enumerates with VID 0x2323, PID 0x3434 and accepts Nostr protocol frames over the CDC endpoint

#### Scenario: Line state changed
- **WHEN** the host changes DTR or RTS line states on the TinyUSB CDC interface
- **THEN** the firmware receives the state change notification without dropping queued message buffers

### Requirement: Native USB Serial/JTAG Transport on Non-OTG Targets
On hardware targets lacking USB-OTG peripherals, the system SHALL communicate using the silicon's built-in USB Serial/JTAG controller, receiving and transmitting Nostr protocol frames through the hardware CDC-ACM channel.

#### Scenario: Host communication over USB Serial/JTAG
- **WHEN** an ESP32-C3, ESP32-C5, or ESP32-C6 device is connected to a host USB port
- **THEN** the device communicates over the native USB Serial/JTAG channel using default Espressif identification (VID 0x303a, PID 0x1001)

#### Scenario: Data reception without buffer overflow
- **WHEN** incoming bytes arrive faster than protocol frame parsing
- **THEN** data is read into intermediate ring buffers and forwarded to the protocol parser queue without blocking hardware interrupts
