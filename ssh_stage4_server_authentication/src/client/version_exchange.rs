use std::net::TcpStream;
use std::io::{Read, Write};
use anyhow::{Result, Context};
use crate::version::VersionString;

/// Perform SSH version exchange on the client side
/// Returns (stream, server_version, client_version)
pub fn perform_version_exchange(mut stream: TcpStream, username: &str) -> Result<(TcpStream, VersionString, VersionString)> {
    // Client receives server version string first
    let mut buffer = Vec::new();
    let mut single_byte = [0u8; 1];
    
    loop {
        stream.read_exact(&mut single_byte)
            .context("Failed to read from server")?;
        
        buffer.push(single_byte[0]);
        
        // Check if we've received \r\n (end of version string)
        if buffer.len() >= 2 && buffer[buffer.len() - 2] == b'\r' && buffer[buffer.len() - 1] == b'\n' {
            break;
        }
        
        // Safety check: version strings shouldn't exceed 255 bytes
        if buffer.len() > 255 {
            anyhow::bail!("Version string too long (exceeds 255 bytes)");
        }
    }
    
    let server_version = VersionString::parse(&buffer)
        .context("Failed to parse server version string")?;
    
    println!("Received server version: {}", server_version);
    
    // Validate protocol version compatibility
    if server_version.protocol != "2.0" {
        anyhow::bail!("Unsupported protocol version: {}", server_version.protocol);
    }
    
    // Client sends its version string
    let client_version = VersionString::new("2.0", "ssh_stage4_server_authentication", Some(username));
    let client_version_bytes = client_version.to_bytes();
    
    stream.write_all(&client_version_bytes)
        .context("Failed to send client version string")?;
    
    println!("Sent client version: {}", client_version);
    
    Ok((stream, server_version, client_version))
}

