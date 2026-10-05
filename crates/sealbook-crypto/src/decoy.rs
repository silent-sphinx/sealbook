//! Keyed, deterministic material for responses that must not reveal that a
//! lookup found nothing.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::CryptoError;

pub const DECOY_KEY_LEN: usize = 32;
pub const DECOY_SEED_LEN: usize = 32;

const DECOY_SALT: &[u8] = b"sealbook-decoy-v1";

/// Derives one seed from a server-held key, a per-request context and a label
/// naming what the seed is for.
///
/// Keyed so a caller can neither predict a decoy nor recognise one, and
/// deterministic so that repeating a request is answered identically, as
/// repeating a request that hit would be.
pub fn decoy_seed(
    key: &[u8; DECOY_KEY_LEN],
    context: &[u8],
    label: &[u8],
) -> Result<[u8; DECOY_SEED_LEN], CryptoError> {
    // Labels hold no NUL, so the separator keeps label and context distinct.
    let mut info = Vec::with_capacity(label.len() + 1 + context.len());
    info.extend_from_slice(label);
    info.push(0);
    info.extend_from_slice(context);
    let mut seed = [0u8; DECOY_SEED_LEN];
    Hkdf::<Sha256>::new(Some(DECOY_SALT), key)
        .expand(&info, &mut seed)
        .map_err(|_| CryptoError::Hkdf)?;
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_is_stable_for_one_request_and_unrelated_across_requests() {
        let key = [7u8; DECOY_KEY_LEN];
        let first = decoy_seed(&key, b"alice", b"collection-id").unwrap();
        assert_eq!(first, decoy_seed(&key, b"alice", b"collection-id").unwrap());
        assert_ne!(first, decoy_seed(&key, b"bob", b"collection-id").unwrap());
        assert_ne!(first, decoy_seed(&key, b"alice", b"shape").unwrap());
        assert_ne!(
            first,
            decoy_seed(&[8u8; DECOY_KEY_LEN], b"alice", b"collection-id").unwrap()
        );
    }

    /// The label separator has to make `label || context` unambiguous, or two
    /// different requests could derive the same seed.
    #[test]
    fn a_label_cannot_run_into_the_context() {
        let key = [7u8; DECOY_KEY_LEN];
        assert_ne!(
            decoy_seed(&key, b"bob", b"ida").unwrap(),
            decoy_seed(&key, b"idabob", b"").unwrap()
        );
    }
}
