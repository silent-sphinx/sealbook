use ed25519_dalek::{
    Signature as EdSignature, Signer as EdSigner, SigningKey, Verifier as EdVerifier, VerifyingKey,
};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Generate, Keypair, MlDsa65, Seed,
    Signature as MlSignature, Signer as MlSigner, SigningKey as MlSigningKey,
    Verifier as MlVerifier, VerifyingKey as MlVerifyingKey,
};
use rand::RngCore;
use zeroize::Zeroize;

use crate::error::CryptoError;

/// Seed length for both halves of the dual signing key pair.
pub const SIGNING_SEED_LEN: usize = 32;

/// Encoded sizes of the two signature schemes, checked against the
/// implementations in `encoded_lengths_match_the_implementation`.
pub const MLDSA65_PUBLIC_KEY_LEN: usize = 1952;
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

#[derive(Clone)]
pub struct DeviceSigningSecrets {
    pub mldsa_seed: Vec<u8>,
    pub ed25519_sk: Vec<u8>,
}

impl Drop for DeviceSigningSecrets {
    fn drop(&mut self) {
        self.mldsa_seed.zeroize();
        self.ed25519_sk.zeroize();
    }
}

#[derive(Clone, Debug)]
pub struct DeviceSigningPublic {
    pub mldsa_pk: Vec<u8>,
    pub ed25519_pk: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct DualSignature {
    pub mldsa: Vec<u8>,
    pub ed25519: Vec<u8>,
}

pub fn generate_device_signing() -> Result<(DeviceSigningSecrets, DeviceSigningPublic), CryptoError>
{
    let mldsa_sk = MlSigningKey::<MlDsa65>::generate();
    let mut mldsa_seed = [0u8; SIGNING_SEED_LEN];
    mldsa_seed.copy_from_slice(&mldsa_sk.to_seed());

    let mut ed_seed = [0u8; SIGNING_SEED_LEN];
    rand::thread_rng().fill_bytes(&mut ed_seed);

    let pair = signing_from_seeds(&mldsa_seed, &ed_seed);
    mldsa_seed.zeroize();
    ed_seed.zeroize();
    Ok(pair)
}

/// Rebuilds a signing key pair from two independent 32-byte seeds.
///
/// Used both for freshly generated device keys and for recovery-phrase keys,
/// whose seeds are derived from the phrase entropy.
pub fn signing_from_seeds(
    mldsa_seed: &[u8; SIGNING_SEED_LEN],
    ed25519_seed: &[u8; SIGNING_SEED_LEN],
) -> (DeviceSigningSecrets, DeviceSigningPublic) {
    let mut seed = Seed::default();
    seed.copy_from_slice(mldsa_seed);
    let mldsa_sk = MlSigningKey::<MlDsa65>::from_seed(&seed);
    let mldsa_pk = mldsa_sk.verifying_key().encode();

    let ed_sk = SigningKey::from_bytes(ed25519_seed);
    let ed_pk = ed_sk.verifying_key();

    (
        DeviceSigningSecrets {
            mldsa_seed: mldsa_seed.to_vec(),
            ed25519_sk: ed_sk.to_bytes().to_vec(),
        },
        DeviceSigningPublic {
            mldsa_pk: mldsa_pk.to_vec(),
            ed25519_pk: ed_pk.to_bytes().to_vec(),
        },
    )
}

pub fn sign(secrets: &DeviceSigningSecrets, message: &[u8]) -> Result<DualSignature, CryptoError> {
    if secrets.mldsa_seed.len() != 32 {
        return Err(CryptoError::Encoding);
    }
    let mut seed = Seed::default();
    seed.copy_from_slice(&secrets.mldsa_seed);
    let mldsa_sk = MlSigningKey::<MlDsa65>::from_seed(&seed);
    let mldsa_sig = MlSigner::sign(&mldsa_sk, message);

    if secrets.ed25519_sk.len() != 32 {
        return Err(CryptoError::Encoding);
    }
    let mut ed_bytes = [0u8; 32];
    ed_bytes.copy_from_slice(&secrets.ed25519_sk);
    let ed_sk = SigningKey::from_bytes(&ed_bytes);
    ed_bytes.zeroize();
    let ed_sig = EdSigner::sign(&ed_sk, message);

    Ok(DualSignature {
        mldsa: mldsa_sig.encode().to_vec(),
        ed25519: ed_sig.to_bytes().to_vec(),
    })
}

pub fn verify(
    public: &DeviceSigningPublic,
    message: &[u8],
    signature: &DualSignature,
) -> Result<(), CryptoError> {
    let mut mldsa_pk = EncodedVerifyingKey::<MlDsa65>::default();
    if public.mldsa_pk.len() != mldsa_pk.len() {
        return Err(CryptoError::Signature("ml-dsa public key length".into()));
    }
    mldsa_pk.copy_from_slice(&public.mldsa_pk);
    let mldsa_vk = MlVerifyingKey::<MlDsa65>::decode(&mldsa_pk);

    let mut mldsa_sig_bytes = EncodedSignature::<MlDsa65>::default();
    if signature.mldsa.len() != mldsa_sig_bytes.len() {
        return Err(CryptoError::Signature("ml-dsa signature length".into()));
    }
    mldsa_sig_bytes.copy_from_slice(&signature.mldsa);
    let mldsa_sig = MlSignature::<MlDsa65>::decode(&mldsa_sig_bytes)
        .ok_or_else(|| CryptoError::Signature("ml-dsa signature decode".into()))?;
    MlVerifier::verify(&mldsa_vk, message, &mldsa_sig)
        .map_err(|_| CryptoError::Signature("ml-dsa verify".into()))?;

    if public.ed25519_pk.len() != 32 {
        return Err(CryptoError::Encoding);
    }
    let mut ed_pk_bytes = [0u8; 32];
    ed_pk_bytes.copy_from_slice(&public.ed25519_pk);
    let ed_pk = VerifyingKey::from_bytes(&ed_pk_bytes)
        .map_err(|err| CryptoError::Signature(err.to_string()))?;
    if signature.ed25519.len() != 64 {
        return Err(CryptoError::Encoding);
    }
    let mut ed_sig_bytes = [0u8; 64];
    ed_sig_bytes.copy_from_slice(&signature.ed25519);
    let ed_sig = EdSignature::from_bytes(&ed_sig_bytes);
    EdVerifier::verify(&ed_pk, message, &ed_sig)
        .map_err(|err| CryptoError::Signature(err.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_lengths_match_the_implementation() {
        let (_, public) = generate_device_signing().unwrap();
        assert_eq!(public.mldsa_pk.len(), MLDSA65_PUBLIC_KEY_LEN);
        assert_eq!(public.ed25519_pk.len(), ED25519_PUBLIC_KEY_LEN);
    }

    #[test]
    fn seeds_determine_the_key_pair() {
        let mldsa_seed = [1u8; SIGNING_SEED_LEN];
        let ed_seed = [2u8; SIGNING_SEED_LEN];
        let (secrets, public) = signing_from_seeds(&mldsa_seed, &ed_seed);
        let (_, again) = signing_from_seeds(&mldsa_seed, &ed_seed);
        assert_eq!(public.mldsa_pk, again.mldsa_pk);
        assert_eq!(public.ed25519_pk, again.ed25519_pk);

        let signature = sign(&secrets, b"message").unwrap();
        verify(&public, b"message", &signature).unwrap();

        let (_, different) = signing_from_seeds(&[3u8; SIGNING_SEED_LEN], &ed_seed);
        assert_ne!(public.mldsa_pk, different.mldsa_pk);
    }

    #[test]
    fn dual_sign_verify() {
        let (sk, pk) = generate_device_signing().unwrap();
        let sig = sign(&sk, b"device-enrollment").unwrap();
        verify(&pk, b"device-enrollment", &sig).unwrap();
        assert!(verify(&pk, b"other", &sig).is_err());
    }

    #[test]
    fn dual_sign_verify_rejects_missing_signature() {
        let (sk, pk) = generate_device_signing().unwrap();
        let mut sig = sign(&sk, b"device-enrollment").unwrap();

        sig.mldsa.clear();
        assert!(verify(&pk, b"device-enrollment", &sig).is_err());

        let mut sig = sign(&sk, b"device-enrollment").unwrap();
        sig.ed25519.clear();
        assert!(verify(&pk, b"device-enrollment", &sig).is_err());
    }
}
