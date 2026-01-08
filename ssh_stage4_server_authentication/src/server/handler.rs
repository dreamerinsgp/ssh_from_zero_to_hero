use std::net::TcpStream;
use anyhow::Result;
use crate::server::version_exchange::perform_version_exchange;
use crate::server::key_exchange::perform_key_exchange;
use crate::authentication::server::{authenticate, UserDatabase};

pub fn handle_connection(stream: TcpStream) -> Result<()> {
    println!("Connection established, performing version exchange...");
    
    let (stream, server_version, client_version) = perform_version_exchange(stream)?;
    
    println!("Version exchange completed successfully!");
    println!("Server version: {}", server_version);
    println!("Client version: {}", client_version);
    
    println!("\n=== Starting Key Exchange ===");
    let (_negotiated, _session_keys, mut stream) = perform_key_exchange(stream, &client_version, &server_version)?;
    
    println!("\n=== Starting Server Authentication ===");
    let user_db = UserDatabase::new();
    let username = authenticate(&mut stream, &user_db)?;
    
    println!("\n=== SSH Connection Established ===");
    println!("Key exchange completed. Session keys derived.");
    println!("Authentication completed successfully for user: {}", username);
    
    Ok(())
}

