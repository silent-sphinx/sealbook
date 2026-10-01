use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

pub const COLLECTION_KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
const PAD_LEN_PREFIX: usize = 4;
/// The table stops at 32 KiB because `pad`'s `next_power_of_two` fallback
/// continues it exactly, so listing more entries would only add a second place
/// to keep in step with `MAX_PADDED_OBJECT_SIZE`.
///
/// Buckets are deliberately coarse. `padded_size` is stored and served in the
/// clear, so doubling steps reveal a plaintext length only to within a factor of
/// two, and an edit usually leaves it unchanged. Finer buckets would pin a large
/// object's length closely and turn each revision into a size delta.
const BUCKETS: [usize; 8] = [256, 512, 1024, 2048, 4096, 8192, 16384, 32768];

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CollectionKey(pub [u8; COLLECTION_KEY_LEN]);

impl CollectionKey {
    pub fn generate() -> Self {
        let mut key = [0u8; COLLECTION_KEY_LEN];
        rand::thread_rng().fill_bytes(&mut key);
        Self(key)
    }

    pub fn from_bytes(bytes: [u8; COLLECTION_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; COLLECTION_KEY_LEN] {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct EncryptedObject {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub padded_size: usize,
}

pub fn encrypt_object(
    key: &CollectionKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedObject, CryptoError> {
    let padded = pad(plaintext);
    let padded_size = padded.len();
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key.0));
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: &padded, aad })
        .map_err(|_| CryptoError::AeadEncrypt)?;

    Ok(EncryptedObject {
        nonce: nonce_bytes,
        ciphertext,
        padded_size,
    })
}

pub fn decrypt_object(
    key: &CollectionKey,
    encrypted: &EncryptedObject,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key.0));
    let nonce = XNonce::from_slice(&encrypted.nonce);
    let padded = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &encrypted.ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AeadDecrypt)?;
    unpad(&padded)
}

pub fn object_aad(object_id: &[u8], collection_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(object_id.len() + collection_id.len());
    aad.extend_from_slice(object_id);
    aad.extend_from_slice(collection_id);
    aad
}

fn pad(plaintext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(plaintext.len() + PAD_LEN_PREFIX);
    out.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
    out.extend_from_slice(plaintext);
    let target = BUCKETS
        .iter()
        .copied()
        .find(|bucket| *bucket >= out.len())
        .unwrap_or_else(|| out.len().next_power_of_two().max(out.len()));
    out.resize(target, 0);
    out
}

fn unpad(padded: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if padded.len() < PAD_LEN_PREFIX {
        return Err(CryptoError::Padding);
    }
    let len = u32::from_be_bytes(padded[0..PAD_LEN_PREFIX].try_into().unwrap()) as usize;
    let end = PAD_LEN_PREFIX
        .checked_add(len)
        .ok_or(CryptoError::Padding)?;
    if end > padded.len() {
        return Err(CryptoError::Padding);
    }
    Ok(padded[PAD_LEN_PREFIX..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_aad_bind() {
        let key = CollectionKey::generate();
        let aad = object_aad(b"obj", b"col");
        let enc = encrypt_object(&key, b"hello contact", &aad).unwrap();
        assert!(enc.padded_size >= 256);
        let plain = decrypt_object(&key, &enc, &aad).unwrap();
        assert_eq!(plain, b"hello contact");

        let bad_aad = object_aad(b"obj", b"other");
        assert!(decrypt_object(&key, &enc, &bad_aad).is_err());
    }

    #[test]
    fn padding_above_the_bucket_table_is_a_power_of_two() {
        assert_eq!(pad(b"x").len(), 256);
        assert_eq!(pad(&vec![0u8; 600 * 1024]).len(), 1024 * 1024);
        assert_eq!(pad(&vec![0u8; 3 * 1024 * 1024]).len(), 4 * 1024 * 1024);
    }
}
