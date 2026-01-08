use anyhow::{Result, Context};
use std::io::{Read, Write};

/// SSH message types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MessageType {
    Disconnect = 1,
    Ignore = 2,
    Unimplemented = 3,
    Debug = 4,
    ServiceRequest = 5,
    ServiceAccept = 6,
    KeyExchangeInit = 20,
    NewKeys = 21,
}

impl MessageType {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(MessageType::Disconnect),
            2 => Ok(MessageType::Ignore),
            3 => Ok(MessageType::Unimplemented),
            4 => Ok(MessageType::Debug),
            5 => Ok(MessageType::ServiceRequest),
            6 => Ok(MessageType::ServiceAccept),
            20 => Ok(MessageType::KeyExchangeInit),
            21 => Ok(MessageType::NewKeys),
            _ => anyhow::bail!("Unknown message type: {}", value),
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Read a packet from the stream
/// SSH packet format: [packet_length(4)][padding_length(1)][payload][padding][mac]
/// For now, we'll implement a simplified version without encryption
pub fn read_packet<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    // Read packet length (4 bytes, big-endian)
    let mut length_bytes = [0u8; 4];
    reader.read_exact(&mut length_bytes)
        .context("Failed to read packet length")?;
    let packet_length = u32::from_be_bytes(length_bytes) as usize;

    if packet_length == 0 {
        anyhow::bail!("Invalid packet length: 0");
    }

    if packet_length > 35000 {
        anyhow::bail!("Packet too large: {} bytes", packet_length);
    }

    // Read padding length (1 byte)
    let mut padding_length_bytes = [0u8; 1];
    reader.read_exact(&mut padding_length_bytes)
        .context("Failed to read padding length")?;
    let padding_length = padding_length_bytes[0] as usize;

    // Read payload (packet_length - padding_length - 1 bytes)
    let payload_length = packet_length - padding_length - 1;
    let mut payload = vec![0u8; payload_length];
    reader.read_exact(&mut payload)
        .context("Failed to read packet payload")?;

    // Skip padding
    let mut padding = vec![0u8; padding_length];
    reader.read_exact(&mut padding)
        .context("Failed to read packet padding")?;

    Ok(payload)
}

/// Write a packet to the stream
pub fn write_packet<W: Write>(writer: &mut W, payload: &[u8]) -> Result<()> {
    // Calculate padding length (minimum 4 bytes, must make total length multiple of block size)
    // For simplicity, we'll use a fixed padding of 4 bytes
    let padding_length = 4u8;
    let packet_length = (payload.len() + padding_length as usize + 1) as u32;

    // Write packet length
    writer.write_all(&packet_length.to_be_bytes())
        .context("Failed to write packet length")?;

    // Write padding length
    writer.write_all(&[padding_length])
        .context("Failed to write padding length")?;

    // Write payload
    writer.write_all(payload)
        .context("Failed to write packet payload")?;

    // Write padding (zeros)
    let padding = vec![0u8; padding_length as usize];
    writer.write_all(&padding)
        .context("Failed to write packet padding")?;

    writer.flush()
        .context("Failed to flush packet")?;

    Ok(())
}

/// Read a string from the packet buffer
pub fn read_string(buffer: &[u8], offset: &mut usize) -> Result<String> {
    if *offset + 4 > buffer.len() {
        anyhow::bail!("Not enough bytes for string length");
    }

    let length = u32::from_be_bytes([
        buffer[*offset],
        buffer[*offset + 1],
        buffer[*offset + 2],
        buffer[*offset + 3],
    ]) as usize;
    *offset += 4;

    if *offset + length > buffer.len() {
        anyhow::bail!("Not enough bytes for string data");
    }

    let string_bytes = &buffer[*offset..*offset + length];
    *offset += length;

    String::from_utf8(string_bytes.to_vec())
        .context("Invalid UTF-8 in string")
}

/// Write a string to the buffer
pub fn write_string(buffer: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buffer.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(bytes);
}

/// Read a name list (comma-separated string) from the packet buffer
pub fn read_name_list(buffer: &[u8], offset: &mut usize) -> Result<Vec<String>> {
    let list_str = read_string(buffer, offset)?;
    if list_str.is_empty() {
        Ok(vec![])
    } else {
        Ok(list_str.split(',').map(|s| s.to_string()).collect())
    }
}

/// Write a name list to the buffer
pub fn write_name_list(buffer: &mut Vec<u8>, list: &[String]) {
    let list_str = list.join(",");
    write_string(buffer, &list_str);
}

