use std::net::TcpStream;
use anyhow::Result;
use crate::server::version_exchange::perform_version_exchange;

pub fn handle_connection(stream: TcpStream) -> Result<()> {
    println!("Connection established, performing version exchange...");
    
    let (server_version, client_version) = perform_version_exchange(stream)?;
    
    println!("Version exchange completed successfully!");
    println!("Server version: {}", server_version);
    println!("Client version: {}", client_version);
    
    Ok(())
}

