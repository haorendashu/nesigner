# Spec Delta

## Purpose

Implements Nostr protocol services (NIP-01, NIP-04, NIP-44) and high-performance conversation session caching independent of specific cryptographic backends.

## ADDED Requirements

### Requirement: NIP-01 event creation and signing
The Nostr service SHALL serialize Nostr events according to NIP-01, generate canonical event IDs via SHA-256, and produce BIP-340 signatures using the Crypto HAL.

#### Scenario: Event ID generation and signing
- **WHEN** event parameters (pubkey, timestamp, kind, tags, and content) are provided
- **THEN** the canonical JSON serialization is hashed with SHA-256 and signed via the Crypto HAL

### Requirement: NIP-04 legacy encrypted direct messages
The Nostr service SHALL implement NIP-04 direct message encryption and decryption using secp256k1 shared secret derivation, PKCS#7 padding, AES-256-CBC, and Base64 encoding.

#### Scenario: Successful NIP-04 message roundtrip
- **WHEN** plaintext text and a recipient public key are passed for encryption
- **THEN** ciphertext formatted as base64(encrypted)?iv=base64(iv) is generated and decryptable by the corresponding keypair

### Requirement: NIP-44 v2 direct message encryption
The Nostr service SHALL implement NIP-44 v2 message encryption and decryption using HKDF key derivation, length-prefixed padding, and ChaCha20-Poly1305 AEAD.

#### Scenario: NIP-44 message encryption with padding
- **WHEN** plaintext text and recipient public key are provided
- **THEN** the message is padded to power-of-two boundaries, encrypted with ChaCha20-Poly1305, and prepended with version 0x02 and nonce

### Requirement: Conversation session key caching
The Nostr service SHALL maintain an LRU cache of derived conversation keys to bypass redundant ECDH point multiplications during repeated operations with known peers.

#### Scenario: Cache hit on consecutive messages
- **WHEN** multiple messages are encrypted or decrypted with the same peer public key
- **THEN** the first operation computes and caches the conversation key, and subsequent operations reuse the cached key without re-computing ECDH scalar multiplication
