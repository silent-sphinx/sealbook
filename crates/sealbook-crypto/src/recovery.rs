use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::aead::{CollectionKey, COLLECTION_KEY_LEN, NONCE_LEN};
use crate::error::CryptoError;

pub const KDF_SALT_LEN: usize = 16;

/// Current password-wrap suite. The Argon2id cost parameters are part of the
/// name so that a wrap made under older, weaker parameters can still be opened
/// after the defaults are raised.
pub const RECOVERY_CIPHERSUITE: &str = "aead-recovery-argon2id-m65536-t3-p1";

/// Suites this build will accept. Add to this list when raising the defaults;
/// never remove an entry while wraps using it may still exist.
pub const SUPPORTED_RECOVERY_CIPHERSUITES: &[&str] = &[RECOVERY_CIPHERSUITE];

const HKDF_INFO: &[u8] = b"sealbook-recovery-v1";

#[derive(Clone, Debug)]
pub struct RecoveryWrap {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub ciphersuite: String,
}

pub fn is_supported_recovery_ciphersuite(name: &str) -> bool {
    SUPPORTED_RECOVERY_CIPHERSUITES.contains(&name)
}

pub fn generate_kdf_salt() -> [u8; KDF_SALT_LEN] {
    let mut salt = [0u8; KDF_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

pub fn wrap_collection_key(
    password: &[u8],
    salt: &[u8],
    key: &CollectionKey,
) -> Result<RecoveryWrap, CryptoError> {
    let mut kek = recovery_kek(password, salt, RECOVERY_CIPHERSUITE)?;
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&kek));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &key.0,
                aad: b"sealbook-recovery-ck",
            },
        )
        .map_err(|_| CryptoError::AeadEncrypt)?;
    kek.zeroize();

    Ok(RecoveryWrap {
        nonce,
        ciphertext,
        ciphersuite: RECOVERY_CIPHERSUITE.to_string(),
    })
}

pub fn unwrap_collection_key(
    password: &[u8],
    salt: &[u8],
    wrap: &RecoveryWrap,
) -> Result<CollectionKey, CryptoError> {
    let mut kek = recovery_kek(password, salt, &wrap.ciphersuite)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&kek));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&wrap.nonce),
            Payload {
                msg: &wrap.ciphertext,
                aad: b"sealbook-recovery-ck",
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

/// Parses `aead-recovery-argon2id-m<KiB>-t<passes>-p<lanes>`.
fn params_from_ciphersuite(name: &str) -> Result<Params, CryptoError> {
    if !is_supported_recovery_ciphersuite(name) {
        return Err(CryptoError::Kdf);
    }
    let suffix = name
        .strip_prefix("aead-recovery-argon2id-")
        .ok_or(CryptoError::Kdf)?;
    let mut parts = suffix.split('-');
    let m_cost = parse_cost(parts.next(), 'm')?;
    let t_cost = parse_cost(parts.next(), 't')?;
    let p_cost = parse_cost(parts.next(), 'p')?;
    if parts.next().is_some() {
        return Err(CryptoError::Kdf);
    }
    Params::new(m_cost, t_cost, p_cost, Some(COLLECTION_KEY_LEN)).map_err(|_| CryptoError::Kdf)
}

fn parse_cost(part: Option<&str>, prefix: char) -> Result<u32, CryptoError> {
    part.and_then(|value| value.strip_prefix(prefix))
        .and_then(|value| value.parse().ok())
        .ok_or(CryptoError::Kdf)
}

fn recovery_kek(
    password: &[u8],
    salt: &[u8],
    ciphersuite: &str,
) -> Result<[u8; COLLECTION_KEY_LEN], CryptoError> {
    let params = params_from_ciphersuite(ciphersuite)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut stretched = [0u8; COLLECTION_KEY_LEN];
    argon
        .hash_password_into(password, salt, &mut stretched)
        .map_err(|_| CryptoError::Kdf)?;

    let hk = Hkdf::<Sha256>::new(None, &stretched);
    stretched.zeroize();
    let mut kek = [0u8; COLLECTION_KEY_LEN];
    hk.expand(HKDF_INFO, &mut kek)
        .map_err(|_| CryptoError::Hkdf)?;
    Ok(kek)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_wrap_round_trip() {
        let key = CollectionKey::generate();
        let salt = generate_kdf_salt();
        let wrap = wrap_collection_key(b"correct horse", &salt, &key).unwrap();
        let opened = unwrap_collection_key(b"correct horse", &salt, &wrap).unwrap();
        assert_eq!(opened.as_bytes(), key.as_bytes());
        assert!(unwrap_collection_key(b"wrong", &salt, &wrap).is_err());
    }

    #[test]
    fn ciphersuite_encodes_the_argon2_parameters() {
        let params = params_from_ciphersuite(RECOVERY_CIPHERSUITE).unwrap();
        assert_eq!(params.m_cost(), 65_536);
        assert_eq!(params.t_cost(), 3);
        assert_eq!(params.p_cost(), 1);
    }

    #[test]
    fn unknown_or_malformed_ciphersuites_are_rejected() {
        for name in [
            "aead-recovery-argon2id",
            "aead-recovery-argon2id-m1-t1-p1",
            "aead-recovery-argon2id-m65536-t3-p1-extra",
            "aead-recovery-scrypt-m65536-t3-p1",
            "",
        ] {
            assert!(params_from_ciphersuite(name).is_err(), "accepted {name}");
            assert!(!is_supported_recovery_ciphersuite(name), "allowed {name}");
        }
    }

    #[test]
    fn wrap_is_opened_using_its_own_parameters() {
        let key = CollectionKey::generate();
        let salt = generate_kdf_salt();
        let mut wrap = wrap_collection_key(b"pw", &salt, &key).unwrap();
        assert_eq!(wrap.ciphersuite, RECOVERY_CIPHERSUITE);
        // An unsupported suite on the wrap must fail closed rather than
        // silently falling back to the current defaults.
        wrap.ciphersuite = "aead-recovery-argon2id-m19456-t2-p1".to_string();
        assert!(unwrap_collection_key(b"pw", &salt, &wrap).is_err());
    }
}
