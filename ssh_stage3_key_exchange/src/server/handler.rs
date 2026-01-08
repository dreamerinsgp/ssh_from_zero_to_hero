use std::net::TcpStream;
use anyhow::Result;
use crate::server::version_exchange::perform_version_exchange;
use crate::server::key_exchange::perform_key_exchange;

pub fn handle_connection(stream: TcpStream) -> Result<()> {
    println!("Connection established, performing version exchange...");
    
    let (stream, server_version, client_version) = perform_version_exchange(stream)?;
    
    println!("Version exchange completed successfully!");
    println!("Server version: {}", server_version);
    println!("Client version: {}", client_version);
    
    println!("\n=== Starting Key Exchange ===");
    let (_negotiated, _session_keys) = perform_key_exchange(stream, &client_version, &server_version)?;
    
    println!("\n=== SSH Connection Established ===");
    println!("Key exchange completed. Session keys derived.");
    
    Ok(())
}

