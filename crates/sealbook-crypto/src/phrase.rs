use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::aead::{CollectionKey, COLLECTION_KEY_LEN, NONCE_LEN};
use crate::error::CryptoError;
use crate::recovery::RecoveryWrap;
use crate::sign::{signing_from_seeds, DeviceSigningPublic, DualSignature, SIGNING_SEED_LEN};

pub const PHRASE_CIPHERSUITE: &str = "aead-phrase-hkdf-sha256";
/// Identifies the recovery-proof key scheme carried in `phrase_scheme`.
pub const PHRASE_SCHEME: &str = "hybrid-mldsa65-ed25519-v1";
pub const PHRASE_ENTROPY_LEN: usize = 32;
pub const PHRASE_LOOKUP_ID_LEN: usize = 32;
const WRAP_INFO: &[u8] = b"sealbook-phrase-wrap-v1";
const LOOKUP_INFO: &[u8] = b"sealbook-phrase-lookup-v1";
const MLDSA_SEED_INFO: &[u8] = b"sealbook-phrase-mldsa-v1";
const ED25519_SEED_INFO: &[u8] = b"sealbook-phrase-ed25519-v1";
const AAD: &[u8] = b"sealbook-phrase-ck";

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bip39_words.rs"));

pub fn generate_phrase() -> Result<(String, [u8; PHRASE_ENTROPY_LEN]), CryptoError> {
    let mut entropy = [0u8; PHRASE_ENTROPY_LEN];
    rand::thread_rng().fill_bytes(&mut entropy);
    let phrase = mnemonic_from_entropy(&entropy)?;
    Ok((phrase, entropy))
}

pub fn generate_pair_code() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| {
            let value = u16::from_le_bytes(*chunk) as usize;
            BIP39_ENGLISH[value % BIP39_ENGLISH.len()]
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn entropy_from_phrase(phrase: &str) -> Result<[u8; PHRASE_ENTROPY_LEN], CryptoError> {
    parse_mnemonic(phrase)
}

/// Opaque account handle derived from the phrase.
///
/// This is what a client presents to look up its phrase key wrap. It is
/// deliberately *not* the recovery public key, so that the key needed to check
/// a recovery proof is never handed out before that proof is supplied.
pub fn phrase_lookup_id(
    entropy: &[u8; PHRASE_ENTROPY_LEN],
) -> Result<[u8; PHRASE_LOOKUP_ID_LEN], CryptoError> {
    derive_from_entropy(entropy, LOOKUP_INFO)
}

/// Derives the hybrid ML-DSA-65 + Ed25519 recovery key pair from phrase entropy.
pub fn phrase_recovery_keys(
    entropy: &[u8; PHRASE_ENTROPY_LEN],
) -> Result<(crate::sign::DeviceSigningSecrets, DeviceSigningPublic), CryptoError> {
    let mut mldsa_seed = derive_from_entropy(entropy, MLDSA_SEED_INFO)?;
    let mut ed25519_seed = derive_from_entropy(entropy, ED25519_SEED_INFO)?;
    let pair = signing_from_seeds(&mldsa_seed, &ed25519_seed);
    mldsa_seed.zeroize();
    ed25519_seed.zeroize();
    Ok(pair)
}

/// Convenience wrapper returning only the public half.
pub fn phrase_recovery_public(
    entropy: &[u8; PHRASE_ENTROPY_LEN],
) -> Result<DeviceSigningPublic, CryptoError> {
    Ok(phrase_recovery_keys(entropy)?.1)
}

pub fn sign_phrase_recovery(
    entropy: &[u8; PHRASE_ENTROPY_LEN],
    message: &[u8],
) -> Result<DualSignature, CryptoError> {
    let (secrets, _) = phrase_recovery_keys(entropy)?;
    crate::sign::sign(&secrets, message)
}

pub fn verify_phrase_recovery(
    public: &DeviceSigningPublic,
    message: &[u8],
    signature: &DualSignature,
) -> Result<(), CryptoError> {
    crate::sign::verify(public, message, signature)
}

/// A recovery public key that no phrase can produce a valid proof for.
///
/// The server keeps one of these so that a recovery attempt against an unknown
/// account performs the same work as one against a real account.
pub fn dummy_phrase_recovery_public() -> Result<DeviceSigningPublic, CryptoError> {
    let mut entropy = [0u8; PHRASE_ENTROPY_LEN];
    rand::thread_rng().fill_bytes(&mut entropy);
    let public = phrase_recovery_public(&entropy)?;
    entropy.zeroize();
    Ok(public)
}

fn derive_from_entropy(
    entropy: &[u8; PHRASE_ENTROPY_LEN],
    info: &[u8],
) -> Result<[u8; SIGNING_SEED_LEN], CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, entropy);
    let mut out = [0u8; SIGNING_SEED_LEN];
    hk.expand(info, &mut out).map_err(|_| CryptoError::Hkdf)?;
    Ok(out)
}

pub fn wrap_for_phrase(
    entropy: &[u8; PHRASE_ENTROPY_LEN],
    key: &CollectionKey,
) -> Result<RecoveryWrap, CryptoError> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    wrap_for_phrase_with_nonce(entropy, key, &nonce)
}

/// Wraps under a caller-supplied nonce.
///
/// For a wrap that has to come out the same every time it is built. The nonce
/// must not be reused under one `entropy`.
pub fn wrap_for_phrase_with_nonce(
    entropy: &[u8; PHRASE_ENTROPY_LEN],
    key: &CollectionKey,
    nonce: &[u8; NONCE_LEN],
) -> Result<RecoveryWrap, CryptoError> {
    let mut kek = phrase_kek(entropy)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&kek));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: &key.0,
                aad: AAD,
            },
        )
        .map_err(|_| CryptoError::AeadEncrypt)?;
    kek.zeroize();
    Ok(RecoveryWrap {
        nonce: *nonce,
        ciphertext,
        ciphersuite: PHRASE_CIPHERSUITE.to_string(),
    })
}

pub fn unwrap_for_phrase(
    entropy: &[u8; PHRASE_ENTROPY_LEN],
    wrap: &RecoveryWrap,
) -> Result<CollectionKey, CryptoError> {
    let mut kek = phrase_kek(entropy)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&kek));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&wrap.nonce),
            Payload {
                msg: &wrap.ciphertext,
                aad: AAD,
            },
        )
        .map_err(|_| CryptoError::AeadDecrypt)?;
    kek.zeroize();
    if plaintext.len() != COLLECTION_KEY_LEN {
        return Err(CryptoError::Encoding);
    }
    let mut bytes = [0u8; COLLECTION_KEY_LEN];
    bytes.copy_from_slice(&plaintext);
    Ok(CollectionKey::from_bytes(bytes))
}

fn phrase_kek(entropy: &[u8; PHRASE_ENTROPY_LEN]) -> Result<[u8; COLLECTION_KEY_LEN], CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, entropy);
    let mut kek = [0u8; COLLECTION_KEY_LEN];
    hk.expand(WRAP_INFO, &mut kek)
        .map_err(|_| CryptoError::Hkdf)?;
    Ok(kek)
}

fn mnemonic_from_entropy(entropy: &[u8; 32]) -> Result<String, CryptoError> {
    let checksum = Sha256::digest(entropy)[0];
    let mut bits = Vec::with_capacity(33);
    bits.extend_from_slice(entropy);
    bits.push(checksum);
    let mut words = Vec::with_capacity(24);
    for i in 0..24 {
        let bit = i * 11;
        let idx = take_11(&bits, bit)?;
        words.push(BIP39_ENGLISH[idx]);
    }
    Ok(words.join(" "))
}

fn parse_mnemonic(phrase: &str) -> Result<[u8; 32], CryptoError> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    if words.len() != 24 {
        return Err(CryptoError::Encoding);
    }
    let mut bits = [0u8; 33];
    for (i, word) in words.iter().enumerate() {
        let idx = BIP39_ENGLISH
            .iter()
            .position(|w| *w == *word)
            .ok_or(CryptoError::Encoding)?;
        put_11(&mut bits, i * 11, idx as u16)?;
    }
    let mut entropy = [0u8; 32];
    entropy.copy_from_slice(&bits[..32]);
    let checksum = Sha256::digest(entropy)[0];
    if checksum != bits[32] {
        return Err(CryptoError::Encoding);
    }
    Ok(entropy)
}

fn take_11(bytes: &[u8], bit: usize) -> Result<usize, CryptoError> {
    let mut v = 0usize;
    for i in 0..11 {
        let pos = bit + i;
        let byte = *bytes.get(pos / 8).ok_or(CryptoError::Encoding)?;
        let b = (byte >> (7 - (pos % 8))) & 1;
        v = (v << 1) | b as usize;
    }
    Ok(v)
}

fn put_11(bytes: &mut [u8], bit: usize, value: u16) -> Result<(), CryptoError> {
    for i in 0..11 {
        let pos = bit + i;
        let byte = bytes.get_mut(pos / 8).ok_or(CryptoError::Encoding)?;
        let shift = 7 - (pos % 8);
        *byte &= !(1 << shift);
        if (value >> (10 - i)) & 1 == 1 {
            *byte |= 1 << shift;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phrase_round_trip() {
        let key = CollectionKey::generate();
        let (phrase, entropy) = generate_phrase().unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);
        assert_eq!(entropy_from_phrase(&phrase).unwrap(), entropy);
        let wrap = wrap_for_phrase(&entropy, &key).unwrap();
        let opened = unwrap_for_phrase(&entropy, &wrap).unwrap();
        assert_eq!(opened.as_bytes(), key.as_bytes());
        let other = generate_phrase().unwrap().1;
        assert!(unwrap_for_phrase(&other, &wrap).is_err());
    }

    #[test]
    fn recovery_keys_are_stable_and_phrase_specific() {
        let entropy = [7u8; PHRASE_ENTROPY_LEN];
        let first = phrase_recovery_public(&entropy).unwrap();
        let again = phrase_recovery_public(&entropy).unwrap();
        assert_eq!(first.mldsa_pk, again.mldsa_pk);
        assert_eq!(first.ed25519_pk, again.ed25519_pk);
        assert_eq!(
            phrase_lookup_id(&entropy).unwrap(),
            phrase_lookup_id(&entropy).unwrap()
        );

        let other = phrase_recovery_public(&[8u8; PHRASE_ENTROPY_LEN]).unwrap();
        assert_ne!(first.mldsa_pk, other.mldsa_pk);
        assert_ne!(first.ed25519_pk, other.ed25519_pk);
        assert_ne!(
            phrase_lookup_id(&entropy).unwrap(),
            phrase_lookup_id(&[8u8; PHRASE_ENTROPY_LEN]).unwrap()
        );
    }

    #[test]
    fn lookup_id_does_not_leak_the_recovery_key() {
        let entropy = [3u8; PHRASE_ENTROPY_LEN];
        let lookup = phrase_lookup_id(&entropy).unwrap();
        let public = phrase_recovery_public(&entropy).unwrap();
        assert_ne!(lookup.as_slice(), public.ed25519_pk.as_slice());
        assert!(!public.mldsa_pk.windows(32).any(|w| w == lookup));
    }

    #[test]
    fn recovery_proof_round_trip() {
        let entropy = [11u8; PHRASE_ENTROPY_LEN];
        let public = phrase_recovery_public(&entropy).unwrap();
        let proof = sign_phrase_recovery(&entropy, b"transcript").unwrap();
        verify_phrase_recovery(&public, b"transcript", &proof).unwrap();
        assert!(verify_phrase_recovery(&public, b"other", &proof).is_err());
    }

    #[test]
    fn recovery_proof_requires_both_signatures() {
        let entropy = [13u8; PHRASE_ENTROPY_LEN];
        let public = phrase_recovery_public(&entropy).unwrap();

        let mut proof = sign_phrase_recovery(&entropy, b"transcript").unwrap();
        proof.mldsa.clear();
        assert!(verify_phrase_recovery(&public, b"transcript", &proof).is_err());

        let mut proof = sign_phrase_recovery(&entropy, b"transcript").unwrap();
        proof.ed25519.clear();
        assert!(verify_phrase_recovery(&public, b"transcript", &proof).is_err());

        // A proof that is valid classically but forged post-quantum must fail:
        // swap in an ML-DSA signature from a different phrase.
        let mut proof = sign_phrase_recovery(&entropy, b"transcript").unwrap();
        let foreign = sign_phrase_recovery(&[14u8; PHRASE_ENTROPY_LEN], b"transcript").unwrap();
        proof.mldsa = foreign.mldsa;
        assert!(verify_phrase_recovery(&public, b"transcript", &proof).is_err());
    }

    #[test]
    fn dummy_recovery_public_never_verifies() {
        let entropy = [15u8; PHRASE_ENTROPY_LEN];
        let proof = sign_phrase_recovery(&entropy, b"transcript").unwrap();
        let dummy = dummy_phrase_recovery_public().unwrap();
        assert!(verify_phrase_recovery(&dummy, b"transcript", &proof).is_err());
    }
}
