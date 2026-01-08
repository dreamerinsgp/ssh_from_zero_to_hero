# SSH Stage 4: Server Authentication

This project implements SSH server authentication (user authentication) on top of the key exchange implementation from Stage 3.

## Overview

Stage 4 adds user authentication functionality to the SSH implementation. After completing the key exchange, the client requests the user authentication service and attempts to authenticate with the server using password-based authentication.

## Features

- **Service Request/Accept**: Client requests `ssh-userauth` service, server accepts
- **User Authentication**: Password-based authentication
- **Authentication Messages**: 
  - `SSH_MSG_USERAUTH_REQUEST` (50)
  - `SSH_MSG_USERAUTH_SUCCESS` (52)
  - `SSH_MSG_USERAUTH_FAILURE` (51)
- **User Database**: Simple in-memory user database for testing

## Protocol Flow

1. **Version Exchange** (from Stage 2)
2. **Key Exchange** (from Stage 3)
3. **Service Request**: Client sends `SSH_MSG_SERVICE_REQUEST` for `ssh-userauth`
4. **Service Accept**: Server responds with `SSH_MSG_SERVICE_ACCEPT`
5. **Authentication Request**: Client sends `SSH_MSG_USERAUTH_REQUEST` with username and password
6. **Authentication Response**: Server responds with `SSH_MSG_USERAUTH_SUCCESS` or `SSH_MSG_USERAUTH_FAILURE`

## Building

```bash
cargo build --release
```

## Running

### Server

```bash
cargo run -- server --port 2222
```

### Client

```bash
# With password
cargo run -- client --host localhost --port 2222 --user admin --password admin123

# Without password (will use "none" method, which will fail)
cargo run -- client --host localhost --port 2222 --user admin
```

## Default Users

The server includes a simple in-memory user database with the following test users:

- `admin` / `admin123`
- `test` / `test123`
- `user` / `password`

## Project Structure

```
src/
├── main.rs                 # CLI entry point
├── lib.rs                  # Library root
├── version.rs              # Version string handling
├── message.rs              # SSH message types and packet handling
├── key_exchange.rs         # Key exchange implementation (from Stage 3)
├── authentication.rs       # Authentication protocol implementation
├── client/
│   ├── mod.rs
│   ├── connection.rs       # Main client connection handler
│   ├── version_exchange.rs # Client version exchange
│   └── key_exchange.rs     # Client key exchange
└── server/
    ├── mod.rs
    ├── tcp.rs              # TCP server listener
    ├── handler.rs          # Connection handler
    ├── version_exchange.rs # Server version exchange
    └── key_exchange.rs     # Server key exchange
```

## Authentication Module

The `authentication.rs` module provides:

- **Client-side functions**: Request service, send auth requests, receive responses
- **Server-side functions**: Handle service requests, authenticate users, send responses
- **User Database**: Simple in-memory user authentication

### Supported Authentication Methods

- `none`: No authentication (rejected by server)
- `password`: Password-based authentication

## Next Steps

Future stages could include:
- Public key authentication
- Encrypted packet transmission using session keys
- Channel management
- Command execution

## Notes

- This is an educational implementation and should not be used in production
- Password authentication is implemented but passwords are transmitted in plaintext (encryption would be added in later stages)
- The user database is in-memory and resets on server restart

