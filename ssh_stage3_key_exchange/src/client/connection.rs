use std::net::TcpStream;
use anyhow::{Result, Context};
use crate::client::version_exchange::perform_version_exchange;
use crate::client::key_exchange::perform_key_exchange;

/// Connect to SSH server and perform version exchange and key exchange
pub fn connect(host: &str, port: u16, username: &str) -> Result<()> {
    let address = format!("{}:{}", host, port);
    println!("Connecting to {}...", address);

    let stream = TcpStream::connect(&address)
        .context(format!("Failed to connect to {}", address))?;

    println!("TCP connection established");
    println!("Performing version exchange...");
    
    let (stream, server_version, client_version) = perform_version_exchange(stream, username)?;
    
    println!("Version exchange completed successfully!");
    println!("Server version: {}", server_version);
    println!("Client version: {}", client_version);
    
    println!("\n=== Starting Key Exchange ===");
    let (_negotiated, _session_keys) = perform_key_exchange(stream, &client_version, &server_version)?;
    
    println!("\n=== SSH Connection Established ===");
    println!("Key exchange completed. Session keys derived.");
    
    Ok(())
}

