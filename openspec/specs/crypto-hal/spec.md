# crypto-hal Specification

## Purpose

Provides a unified cryptographic hardware abstraction layer for secp256k1 elliptic curve operations, symmetric encryption, hashing, and hardware random number generation across multiple backends.

## Requirements

### Requirement: Unified secp256k1 operations
The cryptographic layer SHALL provide uniform, constant-time secp256k1 key generation, BIP-340 Schnorr signing, and ECDH point multiplication independent of the underlying cryptographic provider.

#### Scenario: Schnorr signature generation
- **WHEN** a 32-byte private key, 32-byte message hash, and 32-byte auxiliary random nonce are provided
- **THEN** the system returns a valid 64-byte BIP-340 Schnorr signature matching secp256k1 curve parameters

#### Scenario: Public key derivation
- **WHEN** a valid 32-byte private key is supplied
- **THEN** the system produces the corresponding 32-byte compressed x-only public key

#### Scenario: ECDH scalar multiplication
- **WHEN** our 32-byte private key and a peer's 32-byte x-only public key are supplied
- **THEN** the system computes the 32-byte shared x-coordinate scalar point

### Requirement: Symmetric ciphers and hashing abstraction
The cryptographic layer SHALL abstract AES-256-CBC, ChaCha20-Poly1305 AEAD, and SHA-256 hashing operations, utilizing target hardware accelerators when available.

#### Scenario: Hardware-accelerated AES-CBC encryption and decryption
- **WHEN** 16-byte aligned payload, 32-byte key, and 16-byte IV are passed
- **THEN** the system performs encryption or decryption utilizing on-chip AES hardware acceleration

#### Scenario: ChaCha20-Poly1305 AEAD operation
- **WHEN** plaintext, 32-byte key, 12-byte nonce, and associated authenticated data are passed
- **THEN** the system computes ciphertext with a 16-byte Poly1305 authentication tag conforming to RFC 8439

### Requirement: True hardware random number generation
The cryptographic layer SHALL generate cryptographically secure random bytes directly from the on-chip hardware true random number generator (TRNG).

#### Scenario: Hardware entropy extraction
- **WHEN** the system requests random bytes for nonce generation or ephemeral key creation
- **THEN** the buffer is populated with entropy sourced from the target SoC's hardware RNG peripheral
