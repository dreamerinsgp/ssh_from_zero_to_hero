use std::net::TcpStream;
use std::io::{Read, Write};
use anyhow::{Result, Context};
use crate::version::VersionString;

/// Perform SSH version exchange on the server side
/// Returns (stream, server_version, client_version)
pub fn perform_version_exchange(mut stream: TcpStream) -> Result<(TcpStream, VersionString, VersionString)> {
    // Server sends its version string immediately after TCP connection
    let server_version = VersionString::new("2.0", "ssh_stage4_server_authentication", None);
    let server_version_bytes = server_version.to_bytes();
    
    stream.write_all(&server_version_bytes)
        .context("Failed to send server version string")?;
    
    println!("Sent server version: {}", server_version);
    
    // Read client version string
    let mut buffer = Vec::new();
    let mut single_byte = [0u8; 1];
    
    loop {
        stream.read_exact(&mut single_byte)
            .context("Failed to read from client")?;
        
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
    
    let client_version = VersionString::parse(&buffer)
        .context("Failed to parse client version string")?;
    
    println!("Received client version: {}", client_version);
    
    // Validate protocol version compatibility
    if client_version.protocol != "2.0" {
        anyhow::bail!("Unsupported protocol version: {}", client_version.protocol);
    }
    
    Ok((stream, server_version, client_version))
}

