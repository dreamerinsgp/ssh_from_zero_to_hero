use anyhow::{Result, Context};
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use std::fs;
use std::path::Path;

/// SSH RSA key pair (simplified implementation)
pub struct SshKeyPair {
    pub n: BigUint,  // Modulus
    pub e: BigUint,  // Public exponent
    pub d: BigUint,  // Private exponent
    pub p: BigUint,  // Prime 1
    pub q: BigUint,  // Prime 2
}

impl SshKeyPair {
    /// Generate a new RSA key pair (simplified - uses smaller keys for demo)
    pub fn generate() -> Result<Self> {
        let mut rng = OsRng;
        
        // For educational purposes, use smaller key size (512 bits)
        // In production, use at least 2048 bits
        let bit_size = 512;
        
        // Generate two large primes
        let p = rng.gen_biguint(bit_size / 2);
        let q = rng.gen_biguint(bit_size / 2);
        
        // Compute n = p * q
        let n = &p * &q;
        
        // Compute phi(n) = (p-1) * (q-1)
        let p_minus_one = &p - BigUint::one();
        let q_minus_one = &q - BigUint::one();
        let phi_n = &p_minus_one * &q_minus_one;
        
        // Public exponent (commonly 65537)
        let e = BigUint::from(65537u32);
        
        // Private exponent d = e^(-1) mod phi(n)
        // Simplified: for demo purposes, we'll use a simple approach
        // In production, use extended Euclidean algorithm
        let d = Self::mod_inverse(&e, &phi_n)?;
        
        Ok(Self {
            n,
            e,
            d,
            p,
            q,
        })
    }

    /// Modular inverse using extended Euclidean algorithm
    fn mod_inverse(a: &BigUint, m: &BigUint) -> Result<BigUint> {
        // Extended Euclidean algorithm
        let mut old_r = a.clone();
        let mut r = m.clone();
        let mut old_s = BigUint::one();
        let mut s = BigUint::from(0u32);
        
        while r != BigUint::from(0u32) {
            let quotient = &old_r / &r;
            let (new_r, new_s) = (
                &old_r - &quotient * &r,
                &old_s - &quotient * &s,
            );
            old_r = r;
            r = new_r;
            old_s = s;
            s = new_s;
        }
        
        if old_r > BigUint::one() {
            anyhow::bail!("Modular inverse does not exist");
        }
        
        // Ensure result is positive
        if old_s < BigUint::from(0u32) {
            Ok(&old_s + m)
        } else {
            Ok(old_s)
        }
    }

    /// Get public key components
    pub fn public_key(&self) -> (BigUint, BigUint) {
        (self.n.clone(), self.e.clone())
    }

    /// Sign data with private key
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Hash the data
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        
        // Sign: signature = hash^d mod n
        let hash_bigint = BigUint::from_bytes_be(&hash);
        let signature = hash_bigint.modpow(&self.d, &self.n);
        
        Ok(signature.to_bytes_be())
    }

    /// Verify signature with public key
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        // Hash the data
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let hash_bigint = BigUint::from_bytes_be(&hash);
        
        // Verify: hash' = signature^e mod n
        let sig_bigint = BigUint::from_bytes_be(signature);
        let recovered_hash = sig_bigint.modpow(&self.e, &self.n);
        
        hash_bigint == recovered_hash
    }

    /// Encode public key in SSH format
    pub fn encode_ssh_public_key(&self) -> Vec<u8> {
        encode_ssh_public_key(&self.n, &self.e)
    }

    /// Save public key to file in SSH format
    pub fn save_public_key(&self, path: &Path) -> Result<()> {
        let key_data = self.encode_ssh_public_key();
        use base64::Engine;
        let base64_key = base64::engine::general_purpose::STANDARD.encode(&key_data);
        let ssh_format = format!("ssh-rsa {}\n", base64_key);
        fs::write(path, ssh_format)
            .context("Failed to write public key file")?;
        Ok(())
    }

    /// Load public key from SSH format file
    pub fn load_public_key(path: &Path) -> Result<(BigUint, BigUint)> {
        let content = fs::read_to_string(path)
            .context("Failed to read public key file")?;
        
        let parts: Vec<&str> = content.trim().split_whitespace().collect();
        if parts.len() < 2 || parts[0] != "ssh-rsa" {
            anyhow::bail!("Invalid SSH public key format");
        }
        
        use base64::Engine;
        let key_data = base64::engine::general_purpose::STANDARD.decode(parts[1])
            .context("Failed to decode base64 public key")?;
        
        decode_ssh_public_key(&key_data)
    }
}

/// Simplified SSH public key format encoder
pub fn encode_ssh_public_key(n: &num_bigint::BigUint, e: &num_bigint::BigUint) -> Vec<u8> {
    let mut result = Vec::new();
    
    // Write "ssh-rsa" string
    result.extend_from_slice(b"ssh-rsa");
    
    // Write e (public exponent)
    let e_bytes = e.to_bytes_be();
    result.extend_from_slice(&(e_bytes.len() as u32).to_be_bytes());
    result.extend_from_slice(&e_bytes);
    
    // Write n (modulus)
    let n_bytes = n.to_bytes_be();
    result.extend_from_slice(&(n_bytes.len() as u32).to_be_bytes());
    result.extend_from_slice(&n_bytes);
    
    result
}

/// Decode SSH public key format
pub fn decode_ssh_public_key(data: &[u8]) -> Result<(num_bigint::BigUint, num_bigint::BigUint)> {
    use num_bigint::BigUint;
    
    let mut offset = 0;
    
    // Read "ssh-rsa" string
    if offset + 7 > data.len() || &data[offset..offset+7] != b"ssh-rsa" {
        anyhow::bail!("Invalid SSH key format");
    }
    offset += 7;
    
    // Read e (public exponent)
    if offset + 4 > data.len() {
        anyhow::bail!("Invalid key data");
    }
    let e_len = u32::from_be_bytes([
        data[offset], data[offset+1], data[offset+2], data[offset+3]
    ]) as usize;
    offset += 4;
    
    if offset + e_len > data.len() {
        anyhow::bail!("Invalid key data");
    }
    let e_bytes = &data[offset..offset + e_len];
    offset += e_len;
    
    // Read n (modulus)
    if offset + 4 > data.len() {
        anyhow::bail!("Invalid key data");
    }
    let n_len = u32::from_be_bytes([
        data[offset], data[offset+1], data[offset+2], data[offset+3]
    ]) as usize;
    offset += 4;
    
    if offset + n_len > data.len() {
        anyhow::bail!("Invalid key data");
    }
    let n_bytes = &data[offset..offset + n_len];
    
    let e = BigUint::from_bytes_be(e_bytes);
    let n = BigUint::from_bytes_be(n_bytes);
    
    Ok((n, e))
}

