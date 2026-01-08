// Import TcpStream from the standard library's net module
// TcpStream represents a TCP connection between client and server
use std::net::TcpStream;
// Import Read and Write traits from the standard library's io module
// Read trait provides methods for reading bytes from a stream
// Write trait provides methods for writing bytes to a stream
use std::io::{Read, Write};
// Import Result and Context from the anyhow crate for error handling
// Result is a generic result type that can represent success or failure
// Context provides methods to add context to errors for better error messages
use anyhow::{Result, Context};
// Import VersionString from our own crate's version module
// VersionString represents an SSH protocol version string
use crate::version::VersionString;

/// Perform SSH version exchange on the server side
/// Returns (stream, server_version, client_version)
// Function signature: public function that takes ownership of a TcpStream
// The 'mut' keyword allows us to mutate the stream (read/write operations)
// Returns a Result containing a tuple of (stream, server_version, client_version) on success
pub fn perform_version_exchange(mut stream: TcpStream) -> Result<(TcpStream, VersionString, VersionString)> {
    // Server sends its version string immediately after TCP connection
    // Create a new VersionString instance for the server
    // Parameters: protocol version "2.0", software name "ssh_stage3_key_exchange", optional comments None
    let server_version = VersionString::new("2.0", "ssh_stage3_key_exchange", None);
    // Convert the VersionString struct into its byte representation
    // This produces the actual bytes that will be sent over the network (e.g., "SSH-2.0-ssh_stage2_version_exchange\r\n")
    let server_version_bytes = server_version.to_bytes();
    
    // Write all bytes of the server version string to the TCP stream
    // write_all ensures all bytes are written, not just some of them
    // The & operator creates a reference to the byte slice
    // .context() adds error context if writing fails
    // The ? operator propagates the error if writing fails, otherwise continues
    stream.write_all(&server_version_bytes)
        .context("Failed to send server version string")?;
    
    // Print a debug message showing what version string was sent
    // This helps with debugging and understanding the protocol flow
    println!("Sent server version: {}", server_version);
    
    // Read client version string
    // Version strings can be up to 255 characters, but we'll read until \r\n
    // Create a mutable, growable vector to store bytes as we read them
    // Vec<u8> is a vector of unsigned 8-bit integers (bytes)
    let mut buffer = Vec::new();
    // Create a fixed-size array of 1 byte to read one byte at a time
    // [0u8; 1] means an array of 1 element, initialized to 0, of type u8
    let mut single_byte = [0u8; 1];
    
    // Start an infinite loop to read bytes one at a time
    // We'll break out when we receive the \r\n terminator
    loop {
        // Read exactly one byte from the TCP stream into our single_byte buffer
        // read_exact reads exactly the number of bytes needed to fill the buffer
        // .context() adds error context if reading fails
        // The ? operator propagates the error if reading fails, otherwise continues
        stream.read_exact(&mut single_byte)
            .context("Failed to read from client")?;
        
        // Add the byte we just read to our buffer vector
        // single_byte[0] accesses the first (and only) element of the array
        // push() adds the byte to the end of the vector
        buffer.push(single_byte[0]);
        
        // Check if we've received \r\n (end of version string)
        // buffer.len() >= 2 ensures we have at least 2 bytes before checking
        // buffer[buffer.len() - 2] gets the second-to-last byte (should be \r)
        // buffer[buffer.len() - 1] gets the last byte (should be \n)
        // b'\r' and b'\n' are byte literals for carriage return and newline
        // If both conditions are true, we've found the end of the version string
        if buffer.len() >= 2 && buffer[buffer.len() - 2] == b'\r' && buffer[buffer.len() - 1] == b'\n' {
            // Break out of the loop since we've received the complete version string
            break;
        }
        
        // Safety check: version strings shouldn't exceed 255 bytes
        // According to SSH protocol specification, version strings are limited to 255 bytes
        // This prevents potential buffer overflow attacks or malformed input
        if buffer.len() > 255 {
            // Return an error immediately if the version string is too long
            // anyhow::bail! macro creates an error and returns it from the function
            anyhow::bail!("Version string too long (exceeds 255 bytes)");
        }
    }
    
    // Parse the collected bytes into a VersionString struct
    // &buffer creates a reference to the buffer (slice of bytes)
    // parse() attempts to interpret the bytes as an SSH version string
    // .context() adds error context if parsing fails
    // The ? operator propagates the error if parsing fails, otherwise continues
    let client_version = VersionString::parse(&buffer)
        .context("Failed to parse client version string")?;
    
    // Print a debug message showing what version string was received
    // This helps with debugging and understanding the protocol flow
    println!("Received client version: {}", client_version);
    
    // Validate protocol version compatibility
    // Check if the client's protocol version matches what we support
    // client_version.protocol accesses the protocol field of the VersionString struct
    // We only support protocol version "2.0" (SSH-2.0)
    if client_version.protocol != "2.0" {
        // Return an error if the protocol version is not supported
        // anyhow::bail! macro creates an error with a formatted message
        // The {} placeholder is filled with the actual protocol version from the client
        anyhow::bail!("Unsupported protocol version: {}", client_version.protocol);
    }
    
    // Return success with a tuple containing the stream and both version strings
    // Ok() wraps the tuple in a Result::Ok variant
    // The tuple (stream, server_version, client_version) contains the stream and both VersionString instances
    // This allows the caller to know both what was sent and what was received, and continue using the stream
    Ok((stream, server_version, client_version))
}

