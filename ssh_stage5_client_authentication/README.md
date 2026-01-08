# SSH Stage 5: Client Authentication (Public Key)

This project implements SSH client authentication using public key cryptography on top of Stage 4's server authentication.

## Overview

Stage 5 adds public key authentication as an alternative to password authentication. Clients can authenticate using RSA key pairs, providing a more secure and convenient authentication method.

## Features

- **Public Key Authentication**: RSA-based authentication using SSH key pairs
- **Key Generation**: Generate SSH key pairs using `keygen` command
- **Multiple Auth Methods**: Supports both password and public key authentication
- **Key Management**: Basic key encoding/decoding in SSH format

## Protocol Flow

1. **Version Exchange** (from Stage 2)
2. **Key Exchange** (from Stage 3)
3. **Service Request**: Client requests `ssh-userauth` service
4. **Service Accept**: Server accepts service request
5. **Authentication**:
   - **Public Key Method**: Client sends public key (with or without signature)
   - **Password Method**: Client sends password (fallback)
6. **Authentication Response**: Server validates and responds

## Building

```bash
cargo build --release
```

## Usage

### Generate SSH Key Pair

```bash
cargo run -- keygen --private-key id_rsa --public-key id_rsa.pub
```

### Run Server

```bash
cargo run -- server --port 2222
```

### Run Client with Public Key

```bash
cargo run -- client --host localhost --port 2222 --user test -i id_rsa
```

### Run Client with Password (fallback)

```bash
cargo run -- client --host localhost --port 2222 --user test -P test123
```

## Public Key Authentication Flow

### Step 1: Key Check (without signature)
- Client sends public key without signature
- Server checks if public key is registered for the user
- Server responds with success/failure

### Step 2: Authentication (with signature)
- Client creates signature over: `session_id + username + service_name + "publickey" + has_signature + algorithm + public_key_blob`
- Client sends public key with signature
- Server verifies signature using stored public key
- Server responds with success/failure

## Key Format

Public keys are stored in SSH format:
```
ssh-rsa <base64_encoded_key_data>
```

The base64 data contains:
- Algorithm name: "ssh-rsa"
- Public exponent (e): Big-endian integer
- Modulus (n): Big-endian integer

## Project Structure

```
src/
├── main.rs                 # CLI entry point with keygen command
├── lib.rs                  # Library root
├── keys.rs                 # RSA key pair generation and management
├── authentication.rs       # Authentication protocol (updated for public key)
├── client/
│   └── connection.rs       # Client connection handler
└── server/
    └── handler.rs          # Server connection handler
```

## Implementation Notes

- **Simplified RSA**: Uses smaller key sizes (512 bits) for educational purposes
- **In-Memory Database**: Public keys are stored in memory (resets on restart)
- **Key Loading**: Key file loading is partially implemented (generates new keys for demo)
- **Signature Verification**: Uses SHA-256 for hashing and RSA for signing

## Security Notes

⚠️ **Important**: This is an educational implementation. In production:

1. **Use larger keys**: At least 2048-bit RSA keys
2. **Secure key storage**: Private keys should be encrypted
3. **Key file format**: Support standard SSH key formats (OpenSSH, PEM)
4. **Signature algorithm**: Use proper PKCS#1 v1.5 or PSS padding
5. **Key rotation**: Implement key expiration and rotation policies

## Differences from Stage 4

- Added `keys.rs` module for RSA key pair management
- Updated `authentication.rs` to support public key method
- Added `keygen` command to generate key pairs
- Updated client/server to pass `session_id` for signature creation
- Enhanced `UserDatabase` to store public keys

## Next Steps

Future enhancements could include:
- Full key file loading/saving
- Support for other key types (ECDSA, Ed25519)
- Encrypted private key storage
- Authorized_keys file support
- Key agent integration

