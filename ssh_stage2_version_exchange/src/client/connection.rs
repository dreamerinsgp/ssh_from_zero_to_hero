use std::net::TcpStream;
use anyhow::{Result, Context};
use crate::client::version_exchange::perform_version_exchange;

/// Connect to SSH server and perform version exchange
pub fn connect(host: &str, port: u16, username: &str) -> Result<()> {
    let address = format!("{}:{}", host, port);
    println!("Connecting to {}...", address);

    let stream = TcpStream::connect(&address)
        .context(format!("Failed to connect to {}", address))?;

    println!("TCP connection established");
    println!("Performing version exchange...");
    
    let (server_version, client_version) = perform_version_exchange(stream, username)?;
    
    println!("Version exchange completed successfully!");
    println!("Server version: {}", server_version);
    println!("Client version: {}", client_version);
    
    Ok(())
}

