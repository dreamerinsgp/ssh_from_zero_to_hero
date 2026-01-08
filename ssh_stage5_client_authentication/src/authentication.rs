use anyhow::{Result, Context};
use crate::message::{MessageType, read_string, write_string, read_packet, write_packet};
use crate::keys::SshKeyPair;
use num_bigint::BigUint;

/// Authentication methods supported
pub const AUTH_METHOD_NONE: &str = "none";
pub const AUTH_METHOD_PASSWORD: &str = "password";
pub const AUTH_METHOD_PUBLICKEY: &str = "publickey";

/// Service name for user authentication
pub const SERVICE_USERAUTH: &str = "ssh-userauth";

/// UserAuthRequest message structure
#[derive(Debug, Clone)]
pub struct UserAuthRequest {
    pub username: String,
    pub service_name: String,
    pub method_name: String,
    pub method_specific_data: Vec<u8>,
}

impl UserAuthRequest {
    pub fn new_none(username: &str) -> Self {
        Self {
            username: username.to_string(),
            service_name: "ssh-connection".to_string(),
            method_name: AUTH_METHOD_NONE.to_string(),
            method_specific_data: Vec::new(),
        }
    }

    pub fn new_password(username: &str, password: &str) -> Self {
        let mut method_data = Vec::new();
        // For password method: [boolean change_password][string password]
        method_data.push(0); // change_password = false
        write_string(&mut method_data, password);
        
        Self {
            username: username.to_string(),
            service_name: "ssh-connection".to_string(),
            method_name: AUTH_METHOD_PASSWORD.to_string(),
            method_specific_data: method_data,
        }
    }

    pub fn new_publickey(username: &str, key_pair: &SshKeyPair, _session_id: &[u8]) -> Result<Self> {
        let mut method_data = Vec::new();
        
        // For publickey method: [boolean has_signature][string algorithm_name][string public_key_blob][string signature]
        // First, send without signature (has_signature = false) to check if key is acceptable
        method_data.push(0); // has_signature = false
        
        // Algorithm name
        write_string(&mut method_data, "ssh-rsa");
        
        // Public key blob: [string algorithm_name][string n][string e]
        let mut public_key_blob = Vec::new();
        write_string(&mut public_key_blob, "ssh-rsa");
        
        let n_bytes = key_pair.n.to_bytes_be();
        write_string(&mut public_key_blob, &String::from_utf8_lossy(&n_bytes));
        
        let e_bytes = key_pair.e.to_bytes_be();
        write_string(&mut public_key_blob, &String::from_utf8_lossy(&e_bytes));
        
        write_string(&mut method_data, &String::from_utf8_lossy(&public_key_blob));
        
        Ok(Self {
            username: username.to_string(),
            service_name: "ssh-connection".to_string(),
            method_name: AUTH_METHOD_PUBLICKEY.to_string(),
            method_specific_data: method_data,
        })
    }

    pub fn new_publickey_with_signature(username: &str, key_pair: &SshKeyPair, session_id: &[u8]) -> Result<Self> {
        // Create signature data: session_id + username + service_name + "ssh-connection" + "publickey" + has_signature + algorithm + public_key_blob
        let mut sig_data = Vec::new();
        sig_data.extend_from_slice(session_id);
        write_string(&mut sig_data, username);
        write_string(&mut sig_data, "ssh-connection");
        write_string(&mut sig_data, "publickey");
        sig_data.push(1); // has_signature = true
        write_string(&mut sig_data, "ssh-rsa");
        
        // Public key blob
        let mut public_key_blob = Vec::new();
        write_string(&mut public_key_blob, "ssh-rsa");
        let n_bytes = key_pair.n.to_bytes_be();
        write_string(&mut public_key_blob, &String::from_utf8_lossy(&n_bytes));
        let e_bytes = key_pair.e.to_bytes_be();
        write_string(&mut public_key_blob, &String::from_utf8_lossy(&e_bytes));
        write_string(&mut sig_data, &String::from_utf8_lossy(&public_key_blob));
        
        // Sign the data
        let signature = key_pair.sign(&sig_data)?;
        
        let mut method_data = Vec::new();
        method_data.push(1); // has_signature = true
        write_string(&mut method_data, "ssh-rsa");
        
        // Public key blob
        write_string(&mut method_data, &String::from_utf8_lossy(&public_key_blob));
        
        // Signature
        write_string(&mut method_data, &String::from_utf8_lossy(&signature));
        
        Ok(Self {
            username: username.to_string(),
            service_name: "ssh-connection".to_string(),
            method_name: AUTH_METHOD_PUBLICKEY.to_string(),
            method_specific_data: method_data,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.push(MessageType::UserAuthRequest.to_u8());
        write_string(&mut buffer, &self.username);
        write_string(&mut buffer, &self.service_name);
        write_string(&mut buffer, &self.method_name);
        buffer.extend_from_slice(&self.method_specific_data);
        buffer
    }

    pub fn from_bytes(buffer: &[u8]) -> Result<Self> {
        let mut offset = 0;
        
        if buffer.is_empty() {
            anyhow::bail!("Empty buffer");
        }
        
        let msg_type = MessageType::from_u8(buffer[offset])?;
        if msg_type != MessageType::UserAuthRequest {
            anyhow::bail!("Expected UserAuthRequest message, got {:?}", msg_type);
        }
        offset += 1;
        
        let username = read_string(buffer, &mut offset)?;
        let service_name = read_string(buffer, &mut offset)?;
        let method_name = read_string(buffer, &mut offset)?;
        
        let method_specific_data = if offset < buffer.len() {
            buffer[offset..].to_vec()
        } else {
            Vec::new()
        };
        
        Ok(Self {
            username,
            service_name,
            method_name,
            method_specific_data,
        })
    }
}

/// Parse password from method-specific data
pub fn parse_password(method_data: &[u8]) -> Result<String> {
    let mut offset = 0;
    
    if method_data.is_empty() {
        anyhow::bail!("Empty method data");
    }
    
    // Skip change_password boolean
    if offset >= method_data.len() {
        anyhow::bail!("Not enough bytes for change_password");
    }
    offset += 1;
    
    // Read password string
    let password = read_string(method_data, &mut offset)?;
    Ok(password)
}

/// Parse public key from method-specific data
pub fn parse_publickey(method_data: &[u8]) -> Result<(bool, String, Vec<u8>, Option<Vec<u8>>)> {
    let mut offset = 0;
    
    if method_data.is_empty() {
        anyhow::bail!("Empty method data");
    }
    
    // Read has_signature boolean
    let has_signature = method_data[offset] != 0;
    offset += 1;
    
    // Read algorithm name
    let algorithm = read_string(method_data, &mut offset)?;
    
    // Read public key blob
    let public_key_blob = read_string(method_data, &mut offset)?;
    let public_key_blob_bytes = public_key_blob.as_bytes().to_vec();
    
    // Read signature if present
    let signature = if has_signature && offset < method_data.len() {
        Some(read_string(method_data, &mut offset)?.as_bytes().to_vec())
    } else {
        None
    };
    
    Ok((has_signature, algorithm, public_key_blob_bytes, signature))
}

/// Client-side authentication functions
pub mod client {
    use super::*;
    use std::net::TcpStream;

    /// Request user authentication service
    pub fn request_service(stream: &mut TcpStream) -> Result<()> {
        let mut request = Vec::new();
        request.push(MessageType::ServiceRequest.to_u8());
        write_string(&mut request, SERVICE_USERAUTH);
        
        write_packet(stream, &request)
            .context("Failed to send service request")?;
        println!("Sent service request: {}", SERVICE_USERAUTH);
        
        Ok(())
    }

    /// Receive service accept
    pub fn receive_service_accept(stream: &mut TcpStream) -> Result<String> {
        let payload = read_packet(stream)
            .context("Failed to read service accept")?;
        
        if payload.is_empty() {
            anyhow::bail!("Empty service accept payload");
        }
        
        let msg_type = MessageType::from_u8(payload[0])?;
        if msg_type != MessageType::ServiceAccept {
            anyhow::bail!("Expected ServiceAccept, got {:?}", msg_type);
        }
        
        let mut offset = 1;
        let service_name = read_string(&payload, &mut offset)?;
        println!("Received service accept: {}", service_name);
        
        Ok(service_name)
    }

    /// Send user authentication request
    pub fn send_auth_request(stream: &mut TcpStream, request: &UserAuthRequest) -> Result<()> {
        let request_bytes = request.to_bytes();
        write_packet(stream, &request_bytes)
            .context("Failed to send auth request")?;
        println!("Sent auth request: username={}, method={}", request.username, request.method_name);
        Ok(())
    }

    /// Receive authentication response (success or failure)
    pub fn receive_auth_response(stream: &mut TcpStream) -> Result<bool> {
        let payload = read_packet(stream)
            .context("Failed to read auth response")?;
        
        if payload.is_empty() {
            anyhow::bail!("Empty auth response payload");
        }
        
        let msg_type = MessageType::from_u8(payload[0])?;
        
        match msg_type {
            MessageType::UserAuthSuccess => {
                println!("Received UserAuthSuccess");
                Ok(true)
            }
            MessageType::UserAuthFailure => {
                let mut offset = 1;
                let auth_methods = read_string(&payload, &mut offset)?;
                let partial_success = if offset < payload.len() {
                    payload[offset] != 0
                } else {
                    false
                };
                println!("Received UserAuthFailure: methods={}, partial={}", auth_methods, partial_success);
                Ok(false)
            }
            _ => {
                anyhow::bail!("Unexpected message type in auth response: {:?}", msg_type);
            }
        }
    }

    /// Perform complete authentication flow
    pub fn authenticate(stream: &mut TcpStream, username: &str, password: Option<&str>, key_pair: Option<&SshKeyPair>, session_id: Option<&[u8]>) -> Result<()> {
        // Step 1: Request user authentication service
        request_service(stream)?;
        
        // Step 2: Receive service accept
        receive_service_accept(stream)?;
        
        // Step 3: Send authentication request
        if let Some(key) = key_pair {
            // Try public key authentication
            if let Some(sid) = session_id {
                // First, send public key without signature to check if it's acceptable
                let auth_request = UserAuthRequest::new_publickey(username, key, sid)?;
                send_auth_request(stream, &auth_request)?;
                
                // Receive response
                let success = receive_auth_response(stream)?;
                
                if success {
                    println!("Authentication successful!");
                    return Ok(());
                }
                
                // If not successful, try with signature
                let auth_request = UserAuthRequest::new_publickey_with_signature(username, key, sid)?;
                send_auth_request(stream, &auth_request)?;
                
                let success = receive_auth_response(stream)?;
                if success {
                    println!("Authentication successful!");
                    return Ok(());
                }
            } else {
                anyhow::bail!("Session ID required for public key authentication");
            }
        }
        
        // Fall back to password authentication
        let auth_request = if let Some(pwd) = password {
            UserAuthRequest::new_password(username, pwd)
        } else {
            UserAuthRequest::new_none(username)
        };
        
        send_auth_request(stream, &auth_request)?;
        
        // Step 4: Receive authentication response
        let success = receive_auth_response(stream)?;
        
        if success {
            println!("Authentication successful!");
            Ok(())
        } else {
            anyhow::bail!("Authentication failed");
        }
    }
}

/// Server-side authentication functions
pub mod server {
    use super::*;
    use std::net::TcpStream;
    use std::collections::HashMap;

    /// Simple in-memory user database
    pub struct UserDatabase {
        users: HashMap<String, String>, // username -> password
        public_keys: HashMap<String, (BigUint, BigUint)>, // username -> (n, e) public key
    }

    impl UserDatabase {
        pub fn new() -> Self {
            let mut users = HashMap::new();
            // Add some default users for testing
            users.insert("admin".to_string(), "admin123".to_string());
            users.insert("test".to_string(), "test123".to_string());
            users.insert("user".to_string(), "password".to_string());
            
            let public_keys = HashMap::new();
            
            Self { users, public_keys }
        }

        pub fn authenticate_password(&self, username: &str, password: &str) -> bool {
            self.users.get(username)
                .map(|stored_password| stored_password == password)
                .unwrap_or(false)
        }

        pub fn add_user(&mut self, username: String, password: String) {
            self.users.insert(username, password);
        }

        pub fn add_public_key(&mut self, username: String, n: BigUint, e: BigUint) {
            self.public_keys.insert(username, (n, e));
        }

        pub fn authenticate_publickey(&self, username: &str, n: &BigUint, e: &BigUint, signature: &[u8], session_id: &[u8]) -> bool {
            if let Some((stored_n, stored_e)) = self.public_keys.get(username) {
                // Check if public key matches
                if stored_n != n || stored_e != e {
                    return false;
                }
                
                // Verify signature
                // Create signature data: session_id + username + service_name + "ssh-connection" + "publickey" + has_signature + algorithm + public_key_blob
                let mut sig_data = Vec::new();
                sig_data.extend_from_slice(session_id);
                crate::message::write_string(&mut sig_data, username);
                crate::message::write_string(&mut sig_data, "ssh-connection");
                crate::message::write_string(&mut sig_data, "publickey");
                sig_data.push(1); // has_signature = true
                crate::message::write_string(&mut sig_data, "ssh-rsa");
                
                // Public key blob
                let mut public_key_blob = Vec::new();
                crate::message::write_string(&mut public_key_blob, "ssh-rsa");
                let n_bytes = n.to_bytes_be();
                crate::message::write_string(&mut public_key_blob, &String::from_utf8_lossy(&n_bytes));
                let e_bytes = e.to_bytes_be();
                crate::message::write_string(&mut public_key_blob, &String::from_utf8_lossy(&e_bytes));
                crate::message::write_string(&mut sig_data, &String::from_utf8_lossy(&public_key_blob));
                
                // Verify signature: signature^e mod n should equal hash(sig_data)
                use sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(&sig_data);
                let hash = hasher.finalize();
                let hash_bigint = BigUint::from_bytes_be(&hash);
                
                let sig_bigint = BigUint::from_bytes_be(signature);
                let recovered_hash = sig_bigint.modpow(e, n);
                
                hash_bigint == recovered_hash
            } else {
                false
            }
        }
    }

    /// Receive service request
    pub fn receive_service_request(stream: &mut TcpStream) -> Result<String> {
        let payload = read_packet(stream)
            .context("Failed to read service request")?;
        
        if payload.is_empty() {
            anyhow::bail!("Empty service request payload");
        }
        
        let msg_type = MessageType::from_u8(payload[0])?;
        if msg_type != MessageType::ServiceRequest {
            anyhow::bail!("Expected ServiceRequest, got {:?}", msg_type);
        }
        
        let mut offset = 1;
        let service_name = read_string(&payload, &mut offset)?;
        println!("Received service request: {}", service_name);
        
        Ok(service_name)
    }

    /// Send service accept
    pub fn send_service_accept(stream: &mut TcpStream, service_name: &str) -> Result<()> {
        let mut response = Vec::new();
        response.push(MessageType::ServiceAccept.to_u8());
        write_string(&mut response, service_name);
        
        write_packet(stream, &response)
            .context("Failed to send service accept")?;
        println!("Sent service accept: {}", service_name);
        
        Ok(())
    }

    /// Receive user authentication request
    pub fn receive_auth_request(stream: &mut TcpStream) -> Result<UserAuthRequest> {
        let payload = read_packet(stream)
            .context("Failed to read auth request")?;
        
        UserAuthRequest::from_bytes(&payload)
            .context("Failed to parse auth request")
    }

    /// Send authentication success
    pub fn send_auth_success(stream: &mut TcpStream) -> Result<()> {
        let response = vec![MessageType::UserAuthSuccess.to_u8()];
        write_packet(stream, &response)
            .context("Failed to send auth success")?;
        println!("Sent UserAuthSuccess");
        Ok(())
    }

    /// Send authentication failure
    pub fn send_auth_failure(stream: &mut TcpStream, auth_methods: &str, partial_success: bool) -> Result<()> {
        let mut response = Vec::new();
        response.push(MessageType::UserAuthFailure.to_u8());
        write_string(&mut response, auth_methods);
        response.push(if partial_success { 1 } else { 0 });
        
        write_packet(stream, &response)
            .context("Failed to send auth failure")?;
        println!("Sent UserAuthFailure: methods={}, partial={}", auth_methods, partial_success);
        Ok(())
    }

    /// Perform complete authentication flow on server side
    pub fn authenticate(stream: &mut TcpStream, user_db: &UserDatabase, session_id: &[u8]) -> Result<String> {
        // Step 1: Receive service request
        let service_name = receive_service_request(stream)?;
        
        if service_name != SERVICE_USERAUTH {
            anyhow::bail!("Unexpected service name: {}", service_name);
        }
        
        // Step 2: Send service accept
        send_service_accept(stream, &service_name)?;
        
        // Step 3: Receive authentication request
        let auth_request = receive_auth_request(stream)?;
        
        println!("Received auth request: username={}, method={}", auth_request.username, auth_request.method_name);
        
        // Step 4: Authenticate user
        let authenticated = match auth_request.method_name.as_str() {
            AUTH_METHOD_NONE => {
                // For "none" method, we'll reject it
                false
            }
            AUTH_METHOD_PASSWORD => {
                let password = parse_password(&auth_request.method_specific_data)
                    .context("Failed to parse password")?;
                user_db.authenticate_password(&auth_request.username, &password)
            }
            AUTH_METHOD_PUBLICKEY => {
                let (has_signature, algorithm, public_key_blob, signature_opt) = 
                    parse_publickey(&auth_request.method_specific_data)
                        .context("Failed to parse public key data")?;
                
                if algorithm != "ssh-rsa" {
                    println!("Unsupported public key algorithm: {}", algorithm);
                    false
                } else if !has_signature {
                    // Client is checking if public key is acceptable
                    // Parse public key from blob
                    let mut offset = 0;
                    let _alg = crate::message::read_string(&public_key_blob, &mut offset)?;
                    let n_str = crate::message::read_string(&public_key_blob, &mut offset)?;
                    let e_str = crate::message::read_string(&public_key_blob, &mut offset)?;
                    
                    let n = BigUint::from_bytes_be(n_str.as_bytes());
                    let e = BigUint::from_bytes_be(e_str.as_bytes());
                    
                    // Check if we have this public key registered
                    user_db.public_keys.get(&auth_request.username)
                        .map(|(stored_n, stored_e)| stored_n == &n && stored_e == &e)
                        .unwrap_or(false)
                } else {
                    // Client is authenticating with signature
                    let signature = signature_opt.ok_or_else(|| anyhow::anyhow!("Missing signature"))?;
                    
                    // Parse public key from blob
                    let mut offset = 0;
                    let _alg = crate::message::read_string(&public_key_blob, &mut offset)?;
                    let n_str = crate::message::read_string(&public_key_blob, &mut offset)?;
                    let e_str = crate::message::read_string(&public_key_blob, &mut offset)?;
                    
                    let n = BigUint::from_bytes_be(n_str.as_bytes());
                    let e = BigUint::from_bytes_be(e_str.as_bytes());
                    
                    user_db.authenticate_publickey(&auth_request.username, &n, &e, &signature, session_id)
                }
            }
            _ => {
                println!("Unsupported authentication method: {}", auth_request.method_name);
                false
            }
        };
        
        // Step 5: Send response
        if authenticated {
            send_auth_success(stream)?;
            Ok(auth_request.username)
        } else {
            // Send available auth methods
            let auth_methods = format!("{},{},{}", AUTH_METHOD_PUBLICKEY, AUTH_METHOD_PASSWORD, AUTH_METHOD_NONE);
            send_auth_failure(stream, &auth_methods, false)?;
            anyhow::bail!("Authentication failed for user: {}", auth_request.username);
        }
    }
}

