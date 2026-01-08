use anyhow::{Result, Context};
use crate::message::{MessageType, read_string, write_string, read_packet, write_packet};

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
    pub fn authenticate(stream: &mut TcpStream, username: &str, password: Option<&str>) -> Result<()> {
        // Step 1: Request user authentication service
        request_service(stream)?;
        
        // Step 2: Receive service accept
        receive_service_accept(stream)?;
        
        // Step 3: Send authentication request
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
    }

    impl UserDatabase {
        pub fn new() -> Self {
            let mut users = HashMap::new();
            // Add some default users for testing
            users.insert("admin".to_string(), "admin123".to_string());
            users.insert("test".to_string(), "test123".to_string());
            users.insert("user".to_string(), "password".to_string());
            
            Self { users }
        }

        pub fn authenticate(&self, username: &str, password: &str) -> bool {
            self.users.get(username)
                .map(|stored_password| stored_password == password)
                .unwrap_or(false)
        }

        pub fn add_user(&mut self, username: String, password: String) {
            self.users.insert(username, password);
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
    pub fn authenticate(stream: &mut TcpStream, user_db: &UserDatabase) -> Result<String> {
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
                user_db.authenticate(&auth_request.username, &password)
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
            let auth_methods = format!("{},{}", AUTH_METHOD_PASSWORD, AUTH_METHOD_NONE);
            send_auth_failure(stream, &auth_methods, false)?;
            anyhow::bail!("Authentication failed for user: {}", auth_request.username);
        }
    }
}

