# SSH Authentication Flow - Stage 4

This document describes the complete authentication flow in the SSH Stage 4 implementation.

## Overview

Authentication happens **after** key exchange is completed. The client requests the user authentication service and then attempts to authenticate using password-based authentication.

## Complete Flow Diagram

```
┌─────────┐                                    ┌─────────┐
│ Client  │                                    │ Server  │
└────┬────┘                                    └────┬────┘
     │                                              │
     │ 1. Version Exchange                         │
     │─────────────────────────────────────────────>│
     │<─────────────────────────────────────────────│
     │                                              │
     │ 2. Key Exchange                              │
     │─────────────────────────────────────────────>│
     │<─────────────────────────────────────────────│
     │                                              │
     │ 3. SERVICE REQUEST (ssh-userauth)           │
     │─────────────────────────────────────────────>│
     │                                              │
     │ 4. SERVICE ACCEPT                           │
     │<─────────────────────────────────────────────│
     │                                              │
     │ 5. USERAUTH REQUEST (username + password)   │
     │─────────────────────────────────────────────>│
     │                                              │
     │ 6. USERAUTH SUCCESS / FAILURE               │
     │<─────────────────────────────────────────────│
     │                                              │
```

## Detailed Step-by-Step Flow

### Phase 1: Prerequisites (from previous stages)

1. **TCP Connection**: Client establishes TCP connection to server
2. **Version Exchange**: Client and server exchange version strings
3. **Key Exchange**: Diffie-Hellman key exchange completes, session keys derived

### Phase 2: Service Request (Lines 111-122 in authentication.rs)

**Client Side:**
```rust
client::request_service(stream)
```

**What happens:**
- Client sends `SSH_MSG_SERVICE_REQUEST` (message type 5)
- Service name: `"ssh-userauth"`
- Packet format: `[5][length]["ssh-userauth"]`

**Server Side:**
```rust
server::receive_service_request(stream)
```

**What happens:**
- Server receives and validates `SSH_MSG_SERVICE_REQUEST`
- Extracts service name: `"ssh-userauth"`
- Validates it matches expected service

### Phase 3: Service Accept (Lines 270-281 in authentication.rs)

**Server Side:**
```rust
server::send_service_accept(stream, "ssh-userauth")
```

**What happens:**
- Server sends `SSH_MSG_SERVICE_ACCEPT` (message type 6)
- Packet format: `[6][length]["ssh-userauth"]`

**Client Side:**
```rust
client::receive_service_accept(stream)
```

**What happens:**
- Client receives and validates `SSH_MSG_SERVICE_ACCEPT`
- Confirms service is ready for authentication

### Phase 4: Authentication Request (Lines 145-152, 31-43 in authentication.rs)

**Client Side:**
```rust
let auth_request = UserAuthRequest::new_password(username, password);
client::send_auth_request(stream, &auth_request)
```

**What happens:**
- Client creates `UserAuthRequest` with:
  - `username`: The username to authenticate
  - `service_name`: `"ssh-connection"` (the service being requested)
  - `method_name`: `"password"` (authentication method)
  - `method_specific_data`: `[0][password_length][password_bytes]`
    - First byte: `0` = change_password = false
    - Followed by password string

- Client sends `SSH_MSG_USERAUTH_REQUEST` (message type 50)
- Packet format: `[50][username][service_name][method_name][method_data]`

**Server Side:**
```rust
server::receive_auth_request(stream)
```

**What happens:**
- Server receives `SSH_MSG_USERAUTH_REQUEST`
- Parses username, service name, method name, and method-specific data

### Phase 5: Authentication Processing (Lines 332-346 in authentication.rs)

**Server Side:**
```rust
match auth_request.method_name {
    "password" => {
        let password = parse_password(&auth_request.method_specific_data)?;
        user_db.authenticate(&auth_request.username, &password)
    }
    "none" => false,  // Rejected
    _ => false,       // Unsupported method
}
```

**What happens:**
- Server extracts password from method-specific data
- Looks up username in `UserDatabase`
- Compares provided password with stored password
- Returns `true` if match, `false` otherwise

**UserDatabase Structure:**
```rust
HashMap<String, String>  // username -> password
Default users:
  - "admin" -> "admin123"
  - "test" -> "test123"
  - "user" -> "password"
```

### Phase 6: Authentication Response (Lines 292-312 in authentication.rs)

**Success Case:**

**Server Side:**
```rust
server::send_auth_success(stream)
```

**What happens:**
- Server sends `SSH_MSG_USERAUTH_SUCCESS` (message type 52)
- Packet format: `[52]` (no additional data)

**Client Side:**
```rust
client::receive_auth_response(stream)
```

**What happens:**
- Client receives `SSH_MSG_USERAUTH_SUCCESS`
- Returns `true` (success)
- Authentication complete!

**Failure Case:**

**Server Side:**
```rust
server::send_auth_failure(stream, "password,none", false)
```

**What happens:**
- Server sends `SSH_MSG_USERAUTH_FAILURE` (message type 51)
- Packet format: `[51][auth_methods][partial_success]`
  - `auth_methods`: Comma-separated list of available methods (`"password,none"`)
  - `partial_success`: `0` = false (no partial success)

**Client Side:**
```rust
client::receive_auth_response(stream)
```

**What happens:**
- Client receives `SSH_MSG_USERAUTH_FAILURE`
- Extracts available authentication methods
- Returns `false` (failure)
- Client can retry with different credentials or method

## Code Flow Paths

### Client Flow (client/connection.rs → authentication::client)

```
connect()
  ├─> perform_version_exchange()
  ├─> perform_key_exchange()
  └─> client::authenticate()
        ├─> request_service()           [Step 1]
        ├─> receive_service_accept()     [Step 2]
        ├─> send_auth_request()        [Step 3]
        └─> receive_auth_response()     [Step 4]
```

### Server Flow (server/handler.rs → authentication::server)

```
handle_connection()
  ├─> perform_version_exchange()
  ├─> perform_key_exchange()
  └─> server::authenticate()
        ├─> receive_service_request()   [Step 1]
        ├─> send_service_accept()      [Step 2]
        ├─> receive_auth_request()     [Step 3]
        ├─> UserDatabase::authenticate()[Step 4]
        └─> send_auth_success/failure() [Step 5]
```

## Message Types Used

| Message Type | Value | Direction | Description |
|-------------|-------|-----------|-------------|
| `SSH_MSG_SERVICE_REQUEST` | 5 | Client → Server | Request authentication service |
| `SSH_MSG_SERVICE_ACCEPT` | 6 | Server → Client | Accept service request |
| `SSH_MSG_USERAUTH_REQUEST` | 50 | Client → Server | Send authentication credentials |
| `SSH_MSG_USERAUTH_SUCCESS` | 52 | Server → Client | Authentication succeeded |
| `SSH_MSG_USERAUTH_FAILURE` | 51 | Server → Client | Authentication failed |

## Authentication Methods

### Supported Methods

1. **`password`**: Password-based authentication
   - Format: `[change_password: u8][password: string]`
   - Currently implemented and working

2. **`none`**: No authentication
   - Always rejected by server
   - Used when client doesn't provide password

### Future Methods (not yet implemented)

- **`publickey`**: Public key authentication
- **`keyboard-interactive`**: Interactive authentication

## Example Execution Flow

### Successful Authentication

```
Client: cargo run -- client --host localhost --port 2222 --user test -P test123

1. Client → Server: SSH_MSG_SERVICE_REQUEST ("ssh-userauth")
2. Server → Client: SSH_MSG_SERVICE_ACCEPT ("ssh-userauth")
3. Client → Server: SSH_MSG_USERAUTH_REQUEST (username="test", method="password")
4. Server: Validates password against database
5. Server → Client: SSH_MSG_USERAUTH_SUCCESS
6. ✅ Authentication successful!
```

### Failed Authentication

```
Client: cargo run -- client --host localhost --port 2222 --user test -P wrongpass

1. Client → Server: SSH_MSG_SERVICE_REQUEST ("ssh-userauth")
2. Server → Client: SSH_MSG_SERVICE_ACCEPT ("ssh-userauth")
3. Client → Server: SSH_MSG_USERAUTH_REQUEST (username="test", method="password")
4. Server: Validates password - MISMATCH
5. Server → Client: SSH_MSG_USERAUTH_FAILURE (methods="password,none")
6. ❌ Authentication failed!
```

### No Password Provided

```
Client: cargo run -- client --host localhost --port 2222 --user test

1. Client → Server: SSH_MSG_SERVICE_REQUEST ("ssh-userauth")
2. Server → Client: SSH_MSG_SERVICE_ACCEPT ("ssh-userauth")
3. Client → Server: SSH_MSG_USERAUTH_REQUEST (username="test", method="none")
4. Server: Rejects "none" method
5. Server → Client: SSH_MSG_USERAUTH_FAILURE (methods="password,none")
6. ❌ Authentication failed!
```

## Security Notes

⚠️ **Important**: This is an educational implementation. In production:

1. **Passwords are transmitted in plaintext** - In real SSH, encryption would be applied using the session keys derived during key exchange
2. **No rate limiting** - Real servers implement rate limiting to prevent brute force attacks
3. **In-memory database** - Real servers use secure password storage (hashed passwords, etc.)
4. **No password hashing** - Passwords are stored and compared in plaintext

## Key Functions Reference

### Client Functions (`authentication::client`)

- `request_service()` - Request authentication service
- `receive_service_accept()` - Receive service acceptance
- `send_auth_request()` - Send authentication request
- `receive_auth_response()` - Receive authentication result
- `authenticate()` - Complete authentication flow (calls all above)

### Server Functions (`authentication::server`)

- `receive_service_request()` - Receive service request
- `send_service_accept()` - Send service acceptance
- `receive_auth_request()` - Receive authentication request
- `send_auth_success()` - Send success response
- `send_auth_failure()` - Send failure response
- `authenticate()` - Complete authentication flow (calls all above)

### Data Structures

- `UserAuthRequest` - Authentication request message
- `UserDatabase` - In-memory user credential storage

