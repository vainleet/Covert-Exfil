use anyhow::{anyhow, Result};
use data_encoding::BASE32_NOPAD;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
    Nonce,
};

pub mod encoding {
    use super::*;

    pub fn to_base32(data: &[u8]) -> String {
        BASE32_NOPAD.encode(data).to_lowercase()
    }

    pub fn from_base32(s: &str) -> Result<Vec<u8>> {
        let upper = s.to_ascii_uppercase();

        BASE32_NOPAD.decode(upper.as_bytes())
            .map_err(|e| anyhow!("Base32 decode failed: {:?}", e))
    }
}

pub mod rate_limit {
    use rand::Rng;
    use tokio::time::{sleep, Duration};

    pub async fn jittered_delay(min_ms: u64, max_ms: u64) {
        let delay = rand::thread_rng().gen_range(min_ms..=max_ms);
        sleep(Duration::from_millis(delay)).await;
    }
}

pub fn encrypt_aes_gcm(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("AES-GCM encryption failed: {}", e))
}

pub fn decrypt_aes_gcm(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("AES-GCM decryption failed: {}", e))
}