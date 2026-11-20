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
use crate::hpke_wrap::{WrapBinding, WrapForm};
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
/// The phrase wrap's AAD before it was bound to a collection and epoch. Only
/// opened, never sealed, so an account whose owner has lost every device can
/// still recover during the migration.
const AAD_LEGACY: &[u8] = b"sealbook-phrase-ck";
const AAD_PREFIX: &[u8] = b"sealbook-phrase-ck-v2";

/// A collection key sealed under a key derived from the recovery phrase.
#[derive(Clone, Debug)]
pub struct PhraseWrap {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub ciphersuite: String,
}

fn bound_aad(binding: &WrapBinding) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_PREFIX.len() + 24);
    aad.extend_from_slice(AAD_PREFIX);
    aad.extend_from_slice(binding.collection_id.as_bytes());
    aad.extend_from_slice(&binding.key_epoch.to_be_bytes());
    aad
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bip39_words.rs"));

pub fn generate_phrase() -> Result<(String, [u8; PHRASE_ENTROPY_LEN]), CryptoError> {
    let mut entropy = [0u8; PHRASE_ENTROPY_LEN];
    rand::thread_rng().fill_bytes(&mut entropy);
    let phrase = mnemonic_from_entropy(&entropy)?;
    Ok((phrase, entropy))
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
    binding: &WrapBinding,
) -> Result<PhraseWrap, CryptoError> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    wrap_for_phrase_with_nonce(entropy, key, binding, &nonce)
}

/// Wraps under a caller-supplied nonce.
///
/// For a wrap that has to come out the same every time it is built. The nonce
/// must not be reused under one `entropy`.
pub fn wrap_for_phrase_with_nonce(
    entropy: &[u8; PHRASE_ENTROPY_LEN],
    key: &CollectionKey,
    binding: &WrapBinding,
    nonce: &[u8; NONCE_LEN],
) -> Result<PhraseWrap, CryptoError> {
    let ciphertext = seal_phrase(entropy, key, &bound_aad(binding), nonce)?;
    Ok(PhraseWrap {
        nonce: *nonce,
        ciphertext,
        ciphersuite: PHRASE_CIPHERSUITE.to_string(),
    })
}

/// A wrap in the form that carried no binding, for fixtures and for tests of the
/// migration path. Nothing in the product seals this form any more.
#[doc(hidden)]
pub fn wrap_for_phrase_legacy_with_nonce(
    entropy: &[u8; PHRASE_ENTROPY_LEN],
    key: &CollectionKey,
    nonce: &[u8; NONCE_LEN],
) -> Result<PhraseWrap, CryptoError> {
    let ciphertext = seal_phrase(entropy, key, AAD_LEGACY, nonce)?;
    Ok(PhraseWrap {
        nonce: *nonce,
        ciphertext,
        ciphersuite: PHRASE_CIPHERSUITE.to_string(),
    })
}

fn seal_phrase(
    entropy: &[u8; PHRASE_ENTROPY_LEN],
    key: &CollectionKey,
    aad: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let mut kek = phrase_kek(entropy)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&kek));
    let sealed = cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: &key.0, aad })
        .map_err(|_| CryptoError::AeadEncrypt);
    kek.zeroize();
    sealed
}

/// Opens a phrase wrap bound to `binding`, and reports which form opened.
///
/// The bound form is tried first, then the constant-AAD form that earlier builds
/// sealed. Core allows the legacy form only while an account is migrating.
pub fn unwrap_for_phrase(
    entropy: &[u8; PHRASE_ENTROPY_LEN],
    wrap: &PhraseWrap,
    binding: &WrapBinding,
) -> Result<(CollectionKey, WrapForm), CryptoError> {
    if let Ok(key) = open_phrase(entropy, wrap, &bound_aad(binding)) {
        return Ok((key, WrapForm::Bound));
    }
    let key = open_phrase(entropy, wrap, AAD_LEGACY)?;
    Ok((key, WrapForm::Legacy))
}

fn open_phrase(
    entropy: &[u8; PHRASE_ENTROPY_LEN],
    wrap: &PhraseWrap,
    aad: &[u8],
) -> Result<CollectionKey, CryptoError> {
    let mut kek = phrase_kek(entropy)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&kek));
    let opened = cipher
        .decrypt(
            XNonce::from_slice(&wrap.nonce),
            Payload {
                msg: &wrap.ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AeadDecrypt);
    kek.zeroize();
    let plaintext = opened?;
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
        let wrap = wrap_for_phrase(&entropy, &key, &binding(2)).unwrap();
        let (opened, form) = unwrap_for_phrase(&entropy, &wrap, &binding(2)).unwrap();
        assert_eq!(opened.as_bytes(), key.as_bytes());
        assert_eq!(form, WrapForm::Bound);
        let other = generate_phrase().unwrap().1;
        assert!(unwrap_for_phrase(&other, &wrap, &binding(2)).is_err());
    }

    fn binding(epoch: u64) -> WrapBinding {
        WrapBinding {
            collection_id: uuid::Uuid::from_u128(7),
            key_epoch: epoch,
        }
    }

    #[test]
    fn a_bound_phrase_wrap_does_not_open_for_another_epoch_or_collection() {
        let key = CollectionKey::generate();
        let entropy = [5u8; PHRASE_ENTROPY_LEN];
        let wrap = wrap_for_phrase(&entropy, &key, &binding(2)).unwrap();
        assert!(unwrap_for_phrase(&entropy, &wrap, &binding(3)).is_err());
        let other = WrapBinding {
            collection_id: uuid::Uuid::from_u128(8),
            key_epoch: 2,
        };
        assert!(unwrap_for_phrase(&entropy, &wrap, &other).is_err());
    }

    #[test]
    fn a_phrase_wrap_under_the_constant_aad_opens_and_reports_the_legacy_form() {
        let key = CollectionKey::generate();
        let entropy = [6u8; PHRASE_ENTROPY_LEN];
        let legacy = wrap_for_phrase_legacy_with_nonce(&entropy, &key, &[1u8; NONCE_LEN]).unwrap();
        let (opened, form) = unwrap_for_phrase(&entropy, &legacy, &binding(4)).unwrap();
        assert_eq!(opened.as_bytes(), key.as_bytes());
        assert_eq!(form, WrapForm::Legacy);
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
