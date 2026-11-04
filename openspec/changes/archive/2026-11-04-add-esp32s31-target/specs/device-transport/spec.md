# Spec Delta

## MODIFIED Requirements

### Requirement: TinyUSB Transport on USB-OTG Targets
On hardware targets equipped with USB-OTG peripherals (ESP32-S2, ESP32-S3, ESP32-P4, and ESP32-S31), the system SHALL establish a CDC-ACM communication interface using custom vendor ID 0x2323 and product ID 0x3434, supporting bi-directional frame delivery and line state notifications.

#### Scenario: Host connection over TinyUSB
- **WHEN** an ESP32-S2, ESP32-S3, ESP32-P4, or ESP32-S31 device is connected to a host USB port
- **THEN** the device enumerates with VID 0x2323, PID 0x3434 and accepts Nostr protocol frames over the CDC endpoint

#### Scenario: Line state changed
- **WHEN** the host changes DTR or RTS line states on the TinyUSB CDC interface
- **THEN** the firmware receives the state change notification without dropping queued message buffers

#### Scenario: Device enumeration on ESP32-S31 High-Speed OTG
- **WHEN** an ESP32-S31 board is connected to a host USB port via its native USB-OTG High-Speed interface
- **THEN** the device enumerates as a High-Speed USB 2.0 device with VID 0x2323, PID 0x3434, Product "nesigner", and Serial Number "123456"

#### Scenario: Full-duplex protocol communication over High-Speed CDC-ACM
- **WHEN** a client transmits framed Nostr protocol requests (PING, ECHO, GET_TEMP_PUBKEY) over the TinyUSB CDC-ACM port
- **THEN** the firmware parses the requests, executes the cryptographic or protocol commands, and transmits valid framed responses with matching CRC16 verification
