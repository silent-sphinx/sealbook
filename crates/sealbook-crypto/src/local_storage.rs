use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::CryptoError;

pub const LOCAL_STORAGE_KEY_LEN: usize = 32;

/// Current key-stretching suite for what a host keeps at rest under the
/// password (the device record, the offline copy, the attachment cache). The
/// cost is part of the name so a record made under an older suite stays
/// readable after the default is raised.
pub const LOCAL_STORAGE_KDF: &str = "argon2id-m65536-t3-p1";

/// Suites this build will derive for. Add to this list when raising the
/// default; never remove an entry while records using it may still exist.
pub const SUPPORTED_LOCAL_STORAGE_KDFS: &[&str] = &[LOCAL_STORAGE_KDF];

const HKDF_INFO: &[u8] = b"sealbook-local-storage-v1";

fn params_from_suite(name: &str) -> Result<Params, CryptoError> {
    if !SUPPORTED_LOCAL_STORAGE_KDFS.contains(&name) {
        return Err(CryptoError::Kdf);
    }
    let mut parts = name
        .strip_prefix("argon2id-")
        .ok_or(CryptoError::Kdf)?
        .split('-');
    let m_cost = parse_cost(parts.next(), 'm')?;
    let t_cost = parse_cost(parts.next(), 't')?;
    let p_cost = parse_cost(parts.next(), 'p')?;
    if parts.next().is_some() {
        return Err(CryptoError::Kdf);
    }
    Params::new(m_cost, t_cost, p_cost, Some(LOCAL_STORAGE_KEY_LEN)).map_err(|_| CryptoError::Kdf)
}

fn parse_cost(part: Option<&str>, prefix: char) -> Result<u32, CryptoError> {
    part.and_then(|value| value.strip_prefix(prefix))
        .and_then(|value| value.parse().ok())
        .ok_or(CryptoError::Kdf)
}

/// The AES-256 key a host seals its at-rest records under. Argon2id makes a
/// stolen record expensive to guess against, and the HKDF step separates this
/// key from any other key stretched from the same password the same way.
pub fn local_storage_key(
    password: &[u8],
    salt: &[u8],
    suite: &str,
) -> Result<[u8; LOCAL_STORAGE_KEY_LEN], CryptoError> {
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        params_from_suite(suite)?,
    );
    let mut stretched = [0u8; LOCAL_STORAGE_KEY_LEN];
    argon
        .hash_password_into(password, salt, &mut stretched)
        .map_err(|_| CryptoError::Kdf)?;
    let hk = Hkdf::<Sha256>::new(None, &stretched);
    stretched.zeroize();
    let mut key = [0u8; LOCAL_STORAGE_KEY_LEN];
    hk.expand(HKDF_INFO, &mut key)
        .map_err(|_| CryptoError::Hkdf)?;
    Ok(key)
}

const RECORD_VERSION: u8 = 1;
const RECORD_SALT_LEN: usize = 16;
const RECORD_NONCE_LEN: usize = 24;
const RECORD_HEADER_LEN: usize = 1 + RECORD_SALT_LEN + RECORD_NONCE_LEN;
const RECORD_INFO: &[u8] = b"sealbook-local-record-v1";

fn record_cipher(
    key: &[u8; LOCAL_STORAGE_KEY_LEN],
    salt: &[u8],
    name: &str,
) -> Result<XChaCha20Poly1305, CryptoError> {
    let mut info = RECORD_INFO.to_vec();
    info.extend_from_slice(name.as_bytes());
    let mut subkey = [0u8; LOCAL_STORAGE_KEY_LEN];
    Hkdf::<Sha256>::new(Some(salt), key)
        .expand(&info, &mut subkey)
        .map_err(|_| CryptoError::Hkdf)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&subkey));
    subkey.zeroize();
    Ok(cipher)
}

/// The additional data a record is bound to: its name, then what the caller says
/// places it, so one file cannot be swapped for another or moved to another
/// account.
fn record_aad(name: &str, context: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(name.len() + context.len() + 8);
    aad.extend_from_slice(&(name.len() as u32).to_be_bytes());
    aad.extend_from_slice(name.as_bytes());
    aad.extend_from_slice(&(context.len() as u32).to_be_bytes());
    aad.extend_from_slice(context);
    aad
}

/// Seals one at-rest record under `key` (from [`local_storage_key`]).
///
/// Each record draws its own salt, from which an HKDF subkey is made together
/// with `name`, so no two records share a key or a nonce space. `context` is
/// authenticated but not stored: pass the same bytes to [`local_open`].
pub fn local_seal(
    key: &[u8; LOCAL_STORAGE_KEY_LEN],
    name: &str,
    context: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut salt = [0u8; RECORD_SALT_LEN];
    let mut nonce = [0u8; RECORD_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = record_cipher(key, &salt, name)?;
    let aad = record_aad(name, context);
    let sealed = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AeadEncrypt)?;
    let mut out = Vec::with_capacity(RECORD_HEADER_LEN + sealed.len());
    out.push(RECORD_VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Opens what [`local_seal`] wrote. A wrong key, a different `name` or
/// `context`, or any change to the bytes is [`CryptoError::AeadDecrypt`].
pub fn local_open(
    key: &[u8; LOCAL_STORAGE_KEY_LEN],
    name: &str,
    context: &[u8],
    record: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if record.len() < RECORD_HEADER_LEN + 16 || record[0] != RECORD_VERSION {
        return Err(CryptoError::AeadDecrypt);
    }
    let salt = &record[1..1 + RECORD_SALT_LEN];
    let nonce = &record[1 + RECORD_SALT_LEN..RECORD_HEADER_LEN];
    let cipher = record_cipher(key, salt, name)?;
    let aad = record_aad(name, context);
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: &record[RECORD_HEADER_LEN..],
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AeadDecrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; 16] = [7; 16];

    #[test]
    fn the_same_inputs_give_the_same_key() {
        let a = local_storage_key(b"correct horse", &SALT, LOCAL_STORAGE_KDF).unwrap();
        let b = local_storage_key(b"correct horse", &SALT, LOCAL_STORAGE_KDF).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn a_different_password_or_salt_gives_another_key() {
        let base = local_storage_key(b"correct horse", &SALT, LOCAL_STORAGE_KDF).unwrap();
        assert_ne!(
            base,
            local_storage_key(b"correct horsf", &SALT, LOCAL_STORAGE_KDF).unwrap()
        );
        assert_ne!(
            base,
            local_storage_key(b"correct horse", &[8; 16], LOCAL_STORAGE_KDF).unwrap()
        );
    }

    #[test]
    fn it_is_not_the_raw_argon2id_output() {
        // Same password, salt and Argon2id cost: only the HKDF step keeps this key
        // apart from the bare stretch, which a caller could derive for something
        // else.
        let local = local_storage_key(b"correct horse", &SALT, LOCAL_STORAGE_KDF).unwrap();
        let stretched = {
            let mut out = [0u8; LOCAL_STORAGE_KEY_LEN];
            let params = Params::new(65536, 3, 1, Some(LOCAL_STORAGE_KEY_LEN)).unwrap();
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(b"correct horse", &SALT, &mut out)
                .unwrap();
            out
        };
        assert_ne!(local, stretched);
    }

    #[test]
    fn an_unlisted_suite_is_refused() {
        for suite in [
            "",
            "argon2id",
            "argon2id-m8-t1-p1",
            "argon2id-m65536-t3-p1-extra",
            "pbkdf2-sha256-600000",
        ] {
            assert!(local_storage_key(b"pw", &SALT, suite).is_err(), "{suite}");
        }
    }

    #[test]
    fn a_sealed_record_opens_with_the_same_key_name_and_context() {
        let key = [3u8; LOCAL_STORAGE_KEY_LEN];
        let sealed = local_seal(&key, "vault", b"acct", b"hello").unwrap();
        assert_eq!(
            local_open(&key, "vault", b"acct", &sealed).unwrap(),
            b"hello"
        );
        let again = local_seal(&key, "vault", b"acct", b"hello").unwrap();
        assert_ne!(sealed, again, "each record draws its own salt and nonce");
    }

    #[test]
    fn a_record_is_refused_under_another_key_name_context_or_after_a_change() {
        let key = [3u8; LOCAL_STORAGE_KEY_LEN];
        let sealed = local_seal(&key, "vault", b"acct", b"hello").unwrap();
        assert!(local_open(&[4u8; LOCAL_STORAGE_KEY_LEN], "vault", b"acct", &sealed).is_err());
        assert!(local_open(&key, "outbox", b"acct", &sealed).is_err());
        assert!(local_open(&key, "vault", b"other", &sealed).is_err());
        let mut flipped = sealed.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(local_open(&key, "vault", b"acct", &flipped).is_err());
        assert!(local_open(&key, "vault", b"acct", &sealed[..10]).is_err());
    }

    #[test]
    fn an_empty_record_round_trips() {
        let key = [3u8; LOCAL_STORAGE_KEY_LEN];
        let sealed = local_seal(&key, "n", b"", b"").unwrap();
        assert!(local_open(&key, "n", b"", &sealed).unwrap().is_empty());
    }
}
