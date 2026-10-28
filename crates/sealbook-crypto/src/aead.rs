use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
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

pub const ATTACHMENT_KEY_LEN: usize = 32;

/// Encrypts one attachment chunk at a time, so a multi-megabyte photo never has
/// to pass through `encrypt_object`'s whole-buffer, power-of-two-padded path.
///
/// Deliberately not derived from a `CollectionKey`: the key lives inside the
/// owning note's plaintext JSON, sealed under that note's `CollectionKey` like
/// any other field, while the chunk ciphertext itself sits outside the
/// manifest-committed object set and is never re-encrypted on rotation. Keeping
/// the two keys independent is what makes that split safe.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AttachmentKey(pub [u8; ATTACHMENT_KEY_LEN]);

impl AttachmentKey {
    pub fn generate() -> Self {
        let mut key = [0u8; ATTACHMENT_KEY_LEN];
        rand::thread_rng().fill_bytes(&mut key);
        Self(key)
    }

    pub fn from_bytes(bytes: [u8; ATTACHMENT_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; ATTACHMENT_KEY_LEN] {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct EncryptedChunk {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Binds attachment identity and chunk position into the AAD, so a chunk cannot
/// be replayed under another attachment's key, reordered, or substituted with a
/// different chunk of the same attachment without the AEAD tag failing.
pub fn attachment_chunk_aad(
    attachment_id: &[u8],
    collection_id: &[u8],
    chunk_index: u32,
    chunk_count: u32,
) -> Vec<u8> {
    let mut aad =
        Vec::with_capacity(attachment_id.len() + collection_id.len() + 4 + 4);
    aad.extend_from_slice(attachment_id);
    aad.extend_from_slice(collection_id);
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad.extend_from_slice(&chunk_count.to_be_bytes());
    aad
}

/// Seals one chunk's plaintext. Unlike `encrypt_object`, this never pads: a
/// fixed, caller-chosen chunk size already bounds how closely the server can
/// infer an attachment's length, and padding multi-megabyte chunks to the next
/// power of two would double storage and transfer cost for large photos.
pub fn encrypt_chunk(
    key: &AttachmentKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedChunk, CryptoError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key.0));
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::AeadEncrypt)?;

    Ok(EncryptedChunk {
        nonce: nonce_bytes,
        ciphertext,
    })
}

pub fn decrypt_chunk(
    key: &AttachmentKey,
    encrypted: &EncryptedChunk,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key.0));
    let nonce = XNonce::from_slice(&encrypted.nonce);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &encrypted.ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AeadDecrypt)
}

/// Rolls per-chunk plaintext hashes into one value identifying a whole
/// attachment, fed chunk by chunk so a sender never holds the whole file.
///
/// The owning note stores this single hash rather than the per-chunk list, and
/// a downloader recomputes it across the chunks it receives. A withheld,
/// reordered or substituted chunk changes the result, so a client can refuse a
/// tampered download without the server being trusted to serve honestly. The
/// chunk count is folded in last so a truncated set cannot pass as a shorter
/// whole.
pub struct AttachmentHasher {
    chunks: Sha256,
    count: u32,
}

impl Default for AttachmentHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl AttachmentHasher {
    pub fn new() -> Self {
        Self {
            chunks: Sha256::new(),
            count: 0,
        }
    }

    /// One chunk's plaintext digest, the unit the roll-up is built from.
    pub fn chunk_digest(chunk_plaintext: &[u8]) -> [u8; 32] {
        Sha256::digest(chunk_plaintext).into()
    }

    pub fn update(&mut self, chunk_plaintext: &[u8]) {
        self.update_digest(&Self::chunk_digest(chunk_plaintext));
    }

    /// Rolls in a chunk whose digest was taken elsewhere, for a caller that
    /// hashes each chunk as it is produced and assembles the result later.
    pub fn update_digest(&mut self, chunk_digest: &[u8; 32]) {
        self.chunks.update(chunk_digest);
        self.count += 1;
    }

    pub fn finalize(self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.chunks.finalize());
        h.update(self.count.to_be_bytes());
        h.finalize().into()
    }
}

/// The bucket a plaintext of this length pads into, without doing the padding.
///
/// What a caller batching writes needs: the request it is about to send is
/// bounded by the padded sizes, and sealing each object to find out would mean
/// sealing before knowing whether it fits.
pub fn padded_len(plaintext_len: usize) -> usize {
    let len = plaintext_len + PAD_LEN_PREFIX;
    BUCKETS
        .iter()
        .copied()
        .find(|bucket| *bucket >= len)
        .unwrap_or_else(|| len.next_power_of_two().max(len))
}

fn pad(plaintext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(plaintext.len() + PAD_LEN_PREFIX);
    out.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
    out.extend_from_slice(plaintext);
    out.resize(padded_len(plaintext.len()), 0);
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
    fn the_predicted_padded_length_is_the_one_padding_produces() {
        for len in [0, 1, 255, 252, 253, 4096, 600 * 1024, 5 * 1024 * 1024] {
            assert_eq!(
                pad(&vec![0u8; len]).len(),
                padded_len(len),
                "padded_len disagrees with pad at {len}"
            );
        }
    }

    #[test]
    fn padding_above_the_bucket_table_is_a_power_of_two() {
        assert_eq!(pad(b"x").len(), 256);
        assert_eq!(pad(&vec![0u8; 600 * 1024]).len(), 1024 * 1024);
        assert_eq!(pad(&vec![0u8; 3 * 1024 * 1024]).len(), 4 * 1024 * 1024);
        assert_eq!(pad(&vec![0u8; 5 * 1024 * 1024]).len(), 8 * 1024 * 1024);
    }

    #[test]
    fn chunk_round_trip_and_aad_bind() {
        let key = AttachmentKey::generate();
        let aad = attachment_chunk_aad(b"att", b"col", 2, 5);
        let enc = encrypt_chunk(&key, b"photo bytes", &aad).unwrap();
        let plain = decrypt_chunk(&key, &enc, &aad).unwrap();
        assert_eq!(plain, b"photo bytes");

        // A chunk cannot be reused at a different index, under a different
        // attachment, or with a different total count.
        for bad in [
            attachment_chunk_aad(b"att", b"col", 3, 5),
            attachment_chunk_aad(b"other", b"col", 2, 5),
            attachment_chunk_aad(b"att", b"col", 2, 6),
        ] {
            assert!(decrypt_chunk(&key, &enc, &bad).is_err());
        }
    }

    #[test]
    fn the_attachment_hash_detects_reorder_and_truncation() {
        let full = |chunks: &[&[u8]]| {
            let mut h = AttachmentHasher::new();
            for c in chunks {
                h.update(c);
            }
            h.finalize()
        };

        let base = full(&[b"a", b"b", b"c"]);
        // Reordering the chunks changes the hash.
        assert_ne!(base, full(&[b"b", b"a", b"c"]));
        // Dropping the last chunk changes the hash, even though the remaining
        // chunk hashes are a prefix of the original stream.
        assert_ne!(base, full(&[b"a", b"b"]));
        // The same chunks in the same order reproduce it.
        assert_eq!(base, full(&[b"a", b"b", b"c"]));
    }
}
