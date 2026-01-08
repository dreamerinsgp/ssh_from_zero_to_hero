use std::net::TcpStream;
use anyhow::{Result, Context};
use crate::key_exchange::{
    KexInit, negotiate_algorithms, DiffieHellman, compute_exchange_hash,
    derive_session_keys, SessionKeys, NegotiatedAlgorithms
};
use crate::message::{read_packet, write_packet};
use crate::version::VersionString;

/// Perform SSH key exchange on the server side
/// Returns negotiated algorithms, session keys, and the stream
pub fn perform_key_exchange(
    mut stream: TcpStream,
    client_version: &VersionString,
    server_version: &VersionString,
) -> Result<(NegotiatedAlgorithms, SessionKeys, TcpStream)> {
    println!("Starting key exchange...");
    
    // Step 1: Server receives client SSH_MSG_KEXINIT
    let client_kex_payload = read_packet(&mut stream)
        .context("Failed to read client KEXINIT")?;
    let client_kex = KexInit::from_bytes(&client_kex_payload)
        .context("Failed to parse client KEXINIT")?;
    println!("Received client KEXINIT");
    
    // Step 2: Server sends SSH_MSG_KEXINIT
    let server_kex = KexInit::new();
    let server_kex_bytes = server_kex.to_bytes();
    write_packet(&mut stream, &server_kex_bytes)
        .context("Failed to send server KEXINIT")?;
    println!("Sent server KEXINIT");
    
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
            stream,
            &negotiated,
            client_version,
            server_version,
            &client_kex_payload,
            &server_kex_bytes,
        )
    } else {
        anyhow::bail!("Unsupported key exchange algorithm: {}", negotiated.kex_algorithm);
    }
}

fn perform_dh_key_exchange(
    mut stream: TcpStream,
    negotiated: &NegotiatedAlgorithms,
    client_version: &VersionString,
    server_version: &VersionString,
    client_kex_bytes: &[u8],
    server_kex_bytes: &[u8],
) -> Result<(NegotiatedAlgorithms, SessionKeys, TcpStream)> {
    println!("Performing Diffie-Hellman key exchange...");
    
    // Receive client public key
    let client_dh_payload = read_packet(&mut stream)
        .context("Failed to read client DH public key")?;
    
    if client_dh_payload.is_empty() {
        anyhow::bail!("Empty client DH message");
    }
    
    let msg_type = client_dh_payload[0];
    if msg_type != 30 {
        anyhow::bail!("Expected SSH_MSG_KEXDH_INIT (30), got {}", msg_type);
    }
    
    let mut offset = 1;
    let client_public_key = DiffieHellman::parse_public_key(&client_dh_payload, &mut offset)
        .context("Failed to parse client DH public key")?;
    println!("Received client DH public key");
    
    // Server generates DH key pair
    let server_dh = DiffieHellman::new();
    println!("Generated server DH key pair");
    
    // Compute shared secret
    let shared_secret = server_dh.compute_shared_secret(&client_public_key);
    println!("Computed shared secret");
    
    // Generate a dummy host key (in real implementation, this would be the server's actual host key)
    let k_s = b"ssh-rsa-dummy-host-key";
    
    // Compute exchange hash H
    let h = compute_exchange_hash(
        &client_version.to_string(),
        &server_version.to_string(),
        client_kex_bytes,
        server_kex_bytes,
        k_s,
        &client_public_key,
        &server_dh.e,
        &shared_secret,
    );
    
    // Session ID is the exchange hash H
    let session_id = h.clone();
    
    // Derive session keys
    let session_keys = derive_session_keys(&shared_secret, &h, &session_id);
    println!("Derived session keys");
    
    // Send SSH_MSG_KEXDH_REPLY
    let mut reply = Vec::new();
    reply.push(31); // SSH_MSG_KEXDH_REPLY
    
    // Host key (K_S)
    reply.extend_from_slice(&(k_s.len() as u32).to_be_bytes());
    reply.extend_from_slice(k_s);
    
    // Server DH public key (f)
    let server_public_key_bytes = server_dh.public_key_bytes();
    reply.extend_from_slice(&server_public_key_bytes);
    
    // Signature (dummy for now)
    let signature = b"dummy-signature";
    reply.extend_from_slice(&(signature.len() as u32).to_be_bytes());
    reply.extend_from_slice(signature);
    
    write_packet(&mut stream, &reply)
        .context("Failed to send server DH reply")?;
    println!("Sent server DH reply");
    
    // Receive SSH_MSG_NEWKEYS from client
    let client_newkeys_payload = read_packet(&mut stream)
        .context("Failed to read client NEWKEYS")?;
    
    if client_newkeys_payload.is_empty() || client_newkeys_payload[0] != 21 {
        anyhow::bail!("Expected SSH_MSG_NEWKEYS from client");
    }
    println!("Received SSH_MSG_NEWKEYS");
    
    // Send SSH_MSG_NEWKEYS
    let newkeys_msg = vec![21]; // SSH_MSG_NEWKEYS
    write_packet(&mut stream, &newkeys_msg)
        .context("Failed to send NEWKEYS")?;
    println!("Sent SSH_MSG_NEWKEYS");
    
    println!("Key exchange completed successfully!");
    
    Ok((negotiated.clone(), session_keys, stream))
}

