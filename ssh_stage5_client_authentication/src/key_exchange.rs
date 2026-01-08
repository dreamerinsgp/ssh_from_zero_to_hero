use anyhow::Result;
use crate::message::{MessageType, read_name_list, write_name_list};
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand::{rngs::OsRng, RngCore};
use sha2::{Sha256, Digest};

/// Supported key exchange algorithms
pub const KEX_ALGORITHMS: &[&str] = &["diffie-hellman-group14-sha256"];
pub const HOST_KEY_ALGORITHMS: &[&str] = &["ssh-rsa"];
pub const ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER: &[&str] = &["aes256-ctr"];
pub const ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT: &[&str] = &["aes256-ctr"];
pub const MAC_ALGORITHMS_CLIENT_TO_SERVER: &[&str] = &["hmac-sha2-256"];
pub const MAC_ALGORITHMS_SERVER_TO_CLIENT: &[&str] = &["hmac-sha2-256"];
pub const COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER: &[&str] = &["none"];
pub const COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT: &[&str] = &["none"];
pub const LANGUAGES_CLIENT_TO_SERVER: &[&str] = &[];
pub const LANGUAGES_SERVER_TO_CLIENT: &[&str] = &[];

/// Diffie-Hellman group 14 parameters (RFC 3526)
/// p = 2^1536 - 2^1472 - 1 + 2^64 * { [2^1406 pi] + 741804 }
pub const DH_GROUP14_GENERATOR: &str = "2";
pub const DH_GROUP14_PRIME: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

/// KEXINIT message structure
#[derive(Debug, Clone)]
pub struct KexInit {
    pub cookie: [u8; 16],
    pub kex_algorithms: Vec<String>,
    pub server_host_key_algorithms: Vec<String>,
    pub encryption_algorithms_client_to_server: Vec<String>,
    pub encryption_algorithms_server_to_client: Vec<String>,
    pub mac_algorithms_client_to_server: Vec<String>,
    pub mac_algorithms_server_to_client: Vec<String>,
    pub compression_algorithms_client_to_server: Vec<String>,
    pub compression_algorithms_server_to_client: Vec<String>,
    pub languages_client_to_server: Vec<String>,
    pub languages_server_to_client: Vec<String>,
    pub first_kex_packet_follows: bool,
    pub reserved: u32,
}

impl KexInit {
    pub fn new() -> Self {
        let mut cookie = [0u8; 16];
        OsRng.fill_bytes(&mut cookie);

        Self {
            cookie,
            kex_algorithms: KEX_ALGORITHMS.iter().map(|s| s.to_string()).collect(),
            server_host_key_algorithms: HOST_KEY_ALGORITHMS.iter().map(|s| s.to_string()).collect(),
            encryption_algorithms_client_to_server: ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER.iter().map(|s| s.to_string()).collect(),
            encryption_algorithms_server_to_client: ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT.iter().map(|s| s.to_string()).collect(),
            mac_algorithms_client_to_server: MAC_ALGORITHMS_CLIENT_TO_SERVER.iter().map(|s| s.to_string()).collect(),
            mac_algorithms_server_to_client: MAC_ALGORITHMS_SERVER_TO_CLIENT.iter().map(|s| s.to_string()).collect(),
            compression_algorithms_client_to_server: COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER.iter().map(|s| s.to_string()).collect(),
            compression_algorithms_server_to_client: COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT.iter().map(|s| s.to_string()).collect(),
            languages_client_to_server: LANGUAGES_CLIENT_TO_SERVER.iter().map(|s| s.to_string()).collect(),
            languages_server_to_client: LANGUAGES_SERVER_TO_CLIENT.iter().map(|s| s.to_string()).collect(),
            first_kex_packet_follows: false,
            reserved: 0,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        
        // Message type
        buffer.push(MessageType::KeyExchangeInit.to_u8());
        
        // Cookie (16 bytes)
        buffer.extend_from_slice(&self.cookie);
        
        // Name lists
        write_name_list(&mut buffer, &self.kex_algorithms);
        write_name_list(&mut buffer, &self.server_host_key_algorithms);
        write_name_list(&mut buffer, &self.encryption_algorithms_client_to_server);
        write_name_list(&mut buffer, &self.encryption_algorithms_server_to_client);
        write_name_list(&mut buffer, &self.mac_algorithms_client_to_server);
        write_name_list(&mut buffer, &self.mac_algorithms_server_to_client);
        write_name_list(&mut buffer, &self.compression_algorithms_client_to_server);
        write_name_list(&mut buffer, &self.compression_algorithms_server_to_client);
        write_name_list(&mut buffer, &self.languages_client_to_server);
        write_name_list(&mut buffer, &self.languages_server_to_client);
        
        // First kex packet follows (boolean)
        buffer.push(if self.first_kex_packet_follows { 1 } else { 0 });
        
        // Reserved (4 bytes)
        buffer.extend_from_slice(&self.reserved.to_be_bytes());
        
        buffer
    }

    pub fn from_bytes(buffer: &[u8]) -> Result<Self> {
        let mut offset = 0;
        
        if buffer.is_empty() {
            anyhow::bail!("Empty buffer");
        }
        
        let msg_type = MessageType::from_u8(buffer[offset])?;
        if msg_type != MessageType::KeyExchangeInit {
            anyhow::bail!("Expected KEXINIT message, got {:?}", msg_type);
        }
        offset += 1;
        
        if offset + 16 > buffer.len() {
            anyhow::bail!("Not enough bytes for cookie");
        }
        let cookie = buffer[offset..offset + 16].try_into().unwrap();
        offset += 16;
        
        let kex_algorithms = read_name_list(buffer, &mut offset)?;
        let server_host_key_algorithms = read_name_list(buffer, &mut offset)?;
        let encryption_algorithms_client_to_server = read_name_list(buffer, &mut offset)?;
        let encryption_algorithms_server_to_client = read_name_list(buffer, &mut offset)?;
        let mac_algorithms_client_to_server = read_name_list(buffer, &mut offset)?;
        let mac_algorithms_server_to_client = read_name_list(buffer, &mut offset)?;
        let compression_algorithms_client_to_server = read_name_list(buffer, &mut offset)?;
        let compression_algorithms_server_to_client = read_name_list(buffer, &mut offset)?;
        let languages_client_to_server = read_name_list(buffer, &mut offset)?;
        let languages_server_to_client = read_name_list(buffer, &mut offset)?;
        
        if offset >= buffer.len() {
            anyhow::bail!("Not enough bytes for first_kex_packet_follows");
        }
        let first_kex_packet_follows = buffer[offset] != 0;
        offset += 1;
        
        if offset + 4 > buffer.len() {
            anyhow::bail!("Not enough bytes for reserved");
        }
        let reserved = u32::from_be_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
        ]);
        
        Ok(Self {
            cookie,
            kex_algorithms,
            server_host_key_algorithms,
            encryption_algorithms_client_to_server,
            encryption_algorithms_server_to_client,
            mac_algorithms_client_to_server,
            mac_algorithms_server_to_client,
            compression_algorithms_client_to_server,
            compression_algorithms_server_to_client,
            languages_client_to_server,
            languages_server_to_client,
            first_kex_packet_follows,
            reserved,
        })
    }
}

/// Negotiate algorithms between client and server
pub fn negotiate_algorithms(client_kex: &KexInit, server_kex: &KexInit) -> Result<NegotiatedAlgorithms> {
    // Find first common algorithm in each category
    let kex_algorithm = client_kex.kex_algorithms.iter()
        .find(|&alg| server_kex.kex_algorithms.contains(alg))
        .ok_or_else(|| anyhow::anyhow!("No common key exchange algorithm"))?;
    
    let host_key_algorithm = client_kex.server_host_key_algorithms.iter()
        .find(|&alg| server_kex.server_host_key_algorithms.contains(alg))
        .ok_or_else(|| anyhow::anyhow!("No common host key algorithm"))?;
    
    let encryption_client_to_server = client_kex.encryption_algorithms_client_to_server.iter()
        .find(|&alg| server_kex.encryption_algorithms_client_to_server.contains(alg))
        .ok_or_else(|| anyhow::anyhow!("No common encryption algorithm (client->server)"))?;
    
    let encryption_server_to_client = client_kex.encryption_algorithms_server_to_client.iter()
        .find(|&alg| server_kex.encryption_algorithms_server_to_client.contains(alg))
        .ok_or_else(|| anyhow::anyhow!("No common encryption algorithm (server->client)"))?;
    
    let mac_client_to_server = client_kex.mac_algorithms_client_to_server.iter()
        .find(|&alg| server_kex.mac_algorithms_client_to_server.contains(alg))
        .ok_or_else(|| anyhow::anyhow!("No common MAC algorithm (client->server)"))?;
    
    let mac_server_to_client = client_kex.mac_algorithms_server_to_client.iter()
        .find(|&alg| server_kex.mac_algorithms_server_to_client.contains(alg))
        .ok_or_else(|| anyhow::anyhow!("No common MAC algorithm (server->client)"))?;
    
    let compression_client_to_server = client_kex.compression_algorithms_client_to_server.iter()
        .find(|&alg| server_kex.compression_algorithms_client_to_server.contains(alg))
        .ok_or_else(|| anyhow::anyhow!("No common compression algorithm (client->server)"))?;
    
    let compression_server_to_client = client_kex.compression_algorithms_server_to_client.iter()
        .find(|&alg| server_kex.compression_algorithms_server_to_client.contains(alg))
        .ok_or_else(|| anyhow::anyhow!("No common compression algorithm (server->client)"))?;
    
    Ok(NegotiatedAlgorithms {
        kex_algorithm: kex_algorithm.clone(),
        host_key_algorithm: host_key_algorithm.clone(),
        encryption_client_to_server: encryption_client_to_server.clone(),
        encryption_server_to_client: encryption_server_to_client.clone(),
        mac_client_to_server: mac_client_to_server.clone(),
        mac_server_to_client: mac_server_to_client.clone(),
        compression_client_to_server: compression_client_to_server.clone(),
        compression_server_to_client: compression_server_to_client.clone(),
    })
}

#[derive(Debug, Clone)]
pub struct NegotiatedAlgorithms {
    pub kex_algorithm: String,
    pub host_key_algorithm: String,
    pub encryption_client_to_server: String,
    pub encryption_server_to_client: String,
    pub mac_client_to_server: String,
    pub mac_server_to_client: String,
    pub compression_client_to_server: String,
    pub compression_server_to_client: String,
}

/// Perform Diffie-Hellman key exchange
pub struct DiffieHellman {
    pub p: BigUint,
    pub g: BigUint,
    pub x: BigUint, // Private key
    pub e: BigUint, // Public key (g^x mod p)
}

impl DiffieHellman {
    pub fn new() -> Self {
        let p = BigUint::parse_bytes(DH_GROUP14_PRIME.as_bytes(), 16).unwrap();
        let g = BigUint::parse_bytes(DH_GROUP14_GENERATOR.as_bytes(), 10).unwrap();
        
        // Generate random private key (1 < x < p-1)
        let mut rng = OsRng;
        let p_minus_one = &p - BigUint::one();
        let x = rng.gen_biguint_range(&BigUint::one(), &p_minus_one);
        
        // Compute public key: e = g^x mod p
        let e = g.modpow(&x, &p);
        
        Self { p, g, x, e }
    }

    pub fn compute_shared_secret(&self, other_public: &BigUint) -> BigUint {
        // K = other_public^x mod p
        other_public.modpow(&self.x, &self.p)
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        let bytes = self.e.to_bytes_be();
        let mut result = Vec::new();
        result.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        result.extend_from_slice(&bytes);
        result
    }

    pub fn parse_public_key(buffer: &[u8], offset: &mut usize) -> Result<BigUint> {
        if *offset + 4 > buffer.len() {
            anyhow::bail!("Not enough bytes for public key length");
        }
        
        let length = u32::from_be_bytes([
            buffer[*offset],
            buffer[*offset + 1],
            buffer[*offset + 2],
            buffer[*offset + 3],
        ]) as usize;
        *offset += 4;
        
        if *offset + length > buffer.len() {
            anyhow::bail!("Not enough bytes for public key data");
        }
        
        let key_bytes = &buffer[*offset..*offset + length];
        *offset += length;
        
        Ok(BigUint::from_bytes_be(key_bytes))
    }
}

/// Compute exchange hash H for key derivation
pub fn compute_exchange_hash(
    v_c: &str,
    v_s: &str,
    i_c: &[u8],
    i_s: &[u8],
    k_s: &[u8],
    e_c: &BigUint,
    e_s: &BigUint,
    k: &BigUint,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    
    // H = SHA256(V_C || V_S || I_C || I_S || K_S || e_c || e_s || K)
    write_string_to_hasher(&mut hasher, v_c);
    write_string_to_hasher(&mut hasher, v_s);
    write_bytes_to_hasher(&mut hasher, i_c);
    write_bytes_to_hasher(&mut hasher, i_s);
    write_bytes_to_hasher(&mut hasher, k_s);
    write_biguint_to_hasher(&mut hasher, e_c);
    write_biguint_to_hasher(&mut hasher, e_s);
    write_biguint_to_hasher(&mut hasher, k);
    
    hasher.finalize().to_vec()
}

fn write_string_to_hasher(hasher: &mut Sha256, s: &str) {
    let bytes = s.as_bytes();
    hasher.update(&(bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
}

fn write_bytes_to_hasher(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
}

fn write_biguint_to_hasher(hasher: &mut Sha256, n: &BigUint) {
    let bytes = n.to_bytes_be();
    write_bytes_to_hasher(hasher, &bytes);
}

/// Derive session keys from shared secret and exchange hash
pub fn derive_session_keys(
    k: &BigUint,
    h: &[u8],
    session_id: &[u8],
) -> SessionKeys {
    // K1 = HASH(K || H || "A" || session_id)
    // K2 = HASH(K || H || "B" || session_id)
    // etc.
    
    let mut hasher = Sha256::new();
    hasher.update(&k.to_bytes_be());
    hasher.update(h);
    hasher.update(b"A");
    hasher.update(session_id);
    let iv_client_to_server = hasher.finalize().to_vec();
    
    let mut hasher = Sha256::new();
    hasher.update(&k.to_bytes_be());
    hasher.update(h);
    hasher.update(b"B");
    hasher.update(session_id);
    let iv_server_to_client = hasher.finalize().to_vec();
    
    let mut hasher = Sha256::new();
    hasher.update(&k.to_bytes_be());
    hasher.update(h);
    hasher.update(b"C");
    hasher.update(session_id);
    let encryption_key_client_to_server = hasher.finalize().to_vec();
    
    let mut hasher = Sha256::new();
    hasher.update(&k.to_bytes_be());
    hasher.update(h);
    hasher.update(b"D");
    hasher.update(session_id);
    let encryption_key_server_to_client = hasher.finalize().to_vec();
    
    let mut hasher = Sha256::new();
    hasher.update(&k.to_bytes_be());
    hasher.update(h);
    hasher.update(b"E");
    hasher.update(session_id);
    let integrity_key_client_to_server = hasher.finalize().to_vec();
    
    let mut hasher = Sha256::new();
    hasher.update(&k.to_bytes_be());
    hasher.update(h);
    hasher.update(b"F");
    hasher.update(session_id);
    let integrity_key_server_to_client = hasher.finalize().to_vec();
    
    SessionKeys {
        iv_client_to_server,
        iv_server_to_client,
        encryption_key_client_to_server,
        encryption_key_server_to_client,
        integrity_key_client_to_server,
        integrity_key_server_to_client,
    }
}

#[derive(Debug, Clone)]
pub struct SessionKeys {
    pub iv_client_to_server: Vec<u8>,
    pub iv_server_to_client: Vec<u8>,
    pub encryption_key_client_to_server: Vec<u8>,
    pub encryption_key_server_to_client: Vec<u8>,
    pub integrity_key_client_to_server: Vec<u8>,
    pub integrity_key_server_to_client: Vec<u8>,
}

