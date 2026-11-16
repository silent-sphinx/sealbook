use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
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
/// key from the recovery wrap's, which stretches the same password the same way.
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
    fn it_is_not_the_recovery_wrap_key() {
        // Same password, salt and Argon2id cost as the recovery wrap: only the
        // HKDF label keeps the two keys apart.
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
}
