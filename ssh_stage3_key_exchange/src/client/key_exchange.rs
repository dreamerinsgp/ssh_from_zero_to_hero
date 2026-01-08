use std::net::TcpStream;
use anyhow::{Result, Context};
use crate::key_exchange::{
    KexInit, negotiate_algorithms, DiffieHellman, compute_exchange_hash,
    derive_session_keys, SessionKeys, NegotiatedAlgorithms
};
use crate::message::{read_packet, write_packet};
use crate::version::VersionString;

/// Perform SSH key exchange on the client side
/// Returns negotiated algorithms and session keys
pub fn perform_key_exchange(
    mut stream: TcpStream,
    client_version: &VersionString,
    server_version: &VersionString,
) -> Result<(NegotiatedAlgorithms, SessionKeys)> {
    println!("Starting key exchange...");
    
    // Step 1: Client sends SSH_MSG_KEXINIT
    let client_kex = KexInit::new();
    let client_kex_bytes = client_kex.to_bytes();
    write_packet(&mut stream, &client_kex_bytes)
        .context("Failed to send client KEXINIT")?;
    println!("Sent client KEXINIT");
    
    // Step 2: Client receives server SSH_MSG_KEXINIT
    let server_kex_payload = read_packet(&mut stream)
        .context("Failed to read server KEXINIT")?;
    let server_kex = KexInit::from_bytes(&server_kex_payload)
        .context("Failed to parse server KEXINIT")?;
    println!("Received server KEXINIT");
    
    // Step 3: Negotiate algorithms
    let negotiated = negotiate_algorithms(&client_kex, &server_kex)
        .context("Failed to negotiate algorithms")?;
    println!("Negotiated algorithms:");
    println!("  KEX: {}", negotiated.kex_algorithm);
    println!("  Host key: {}", negotiated.host_key_algorithm);
    println!("  Encryption (C->S): {}", negotiated.encryption_client_to_server);
    println!("  Encryption (S->C): {}", negotiated.encryption_server_to_client);
    
    // Step 4: Perform Diffie-Hellman key exchange
    if negotiated.kex_algorithm == "diffie-hellman-group14-sha256" {
        perform_dh_key_exchange(
            &mut stream,
            &negotiated,
            client_version,
            server_version,
            &client_kex.to_bytes(),
            &server_kex.to_bytes(),
        )
    } else {
        anyhow::bail!("Unsupported key exchange algorithm: {}", negotiated.kex_algorithm);
    }
}

fn perform_dh_key_exchange(
    stream: &mut TcpStream,
    negotiated: &NegotiatedAlgorithms,
    client_version: &VersionString,
    server_version: &VersionString,
    client_kex_bytes: &[u8],
    server_kex_bytes: &[u8],
) -> Result<(NegotiatedAlgorithms, SessionKeys)> {
    println!("Performing Diffie-Hellman key exchange...");
    
    // Client generates DH key pair
    let client_dh = DiffieHellman::new();
    let client_public_key_bytes = client_dh.public_key_bytes();
    
    // Send client public key
    let mut dh_message = Vec::new();
    dh_message.push(30); // SSH_MSG_KEXDH_INIT
    dh_message.extend_from_slice(&client_public_key_bytes);
    write_packet(stream, &dh_message)
        .context("Failed to send client DH public key")?;
    println!("Sent client DH public key");
    
    // Receive server public key and host key
    let server_dh_payload = read_packet(stream)
        .context("Failed to read server DH response")?;
    
    if server_dh_payload.is_empty() {
        anyhow::bail!("Empty server DH response");
    }
    
    let msg_type = server_dh_payload[0];
    if msg_type != 31 {
        anyhow::bail!("Expected SSH_MSG_KEXDH_REPLY (31), got {}", msg_type);
    }
    
    let mut offset = 1;
    
    // Parse server host key (K_S)
    let k_s_length = u32::from_be_bytes([
        server_dh_payload[offset],
        server_dh_payload[offset + 1],
        server_dh_payload[offset + 2],
        server_dh_payload[offset + 3],
    ]) as usize;
    offset += 4;
    
    if offset + k_s_length > server_dh_payload.len() {
        anyhow::bail!("Invalid host key length");
    }
    let k_s = &server_dh_payload[offset..offset + k_s_length];
    offset += k_s_length;
    
    // Parse server DH public key (f)
    let server_public_key = DiffieHellman::parse_public_key(&server_dh_payload, &mut offset)
        .context("Failed to parse server DH public key")?;
    
    // Parse signature (for now, we'll skip validation)
    let _signature_length = u32::from_be_bytes([
        server_dh_payload[offset],
        server_dh_payload[offset + 1],
        server_dh_payload[offset + 2],
        server_dh_payload[offset + 3],
    ]) as usize;
    offset += 4;
    
    if offset + _signature_length > server_dh_payload.len() {
        anyhow::bail!("Invalid signature length");
    }
    let _signature = &server_dh_payload[offset..offset + _signature_length];
    
    println!("Received server DH public key");
    
    // Compute shared secret
    let shared_secret = client_dh.compute_shared_secret(&server_public_key);
    println!("Computed shared secret");
    
    // Compute exchange hash H
    let h = compute_exchange_hash(
        &client_version.to_string(),
        &server_version.to_string(),
        client_kex_bytes,
        server_kex_bytes,
        k_s,
        &client_dh.e,
        &server_public_key,
        &shared_secret,
    );
    
    // Session ID is the exchange hash H
    let session_id = h.clone();
    
    // Derive session keys
    let session_keys = derive_session_keys(&shared_secret, &h, &session_id);
    println!("Derived session keys");
    
    // Send SSH_MSG_NEWKEYS
    let newkeys_msg = vec![21]; // SSH_MSG_NEWKEYS
    write_packet(stream, &newkeys_msg)
        .context("Failed to send NEWKEYS")?;
    println!("Sent SSH_MSG_NEWKEYS");
    
    // Receive SSH_MSG_NEWKEYS from server
    let server_newkeys_payload = read_packet(stream)
        .context("Failed to read server NEWKEYS")?;
    
    if server_newkeys_payload.is_empty() || server_newkeys_payload[0] != 21 {
        anyhow::bail!("Expected SSH_MSG_NEWKEYS from server");
    }
    println!("Received SSH_MSG_NEWKEYS");
    
    println!("Key exchange completed successfully!");
    
    Ok((negotiated.clone(), session_keys))
}

