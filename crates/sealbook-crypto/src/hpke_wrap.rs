use hkdf::Hkdf;
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::XWing, Deserializable, Kem as KemTrait, OpModeR,
    OpModeS, Serializable,
};
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::aead::CollectionKey;
use crate::error::CryptoError;

pub const XWING_CIPHERSUITE: &str = "hpke-xwing-sha256-chacha20poly1305";
pub const XWING_PUBLIC_KEY_LEN: usize = 1216;
pub const XWING_ENCAPSULATED_KEY_LEN: usize = 1120;
pub const HPKE_AEAD_TAG_LEN: usize = 16;
const HPKE_INFO: &[u8] = b"sealbook/collection-key/v1";
const HPKE_AAD: &[u8] = b"sealbook-ck";
const LOGIN_INFO: &[u8] = b"sealbook/login-challenge/v1";
const LOGIN_AAD: &[u8] = b"sealbook-login";

type Kem = XWing;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

#[derive(Clone)]
pub struct DeviceHpkeSecret(Vec<u8>);

impl Drop for DeviceHpkeSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl DeviceHpkeSecret {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, Debug)]
pub struct DeviceHpkePublic(pub Vec<u8>);

#[derive(Clone, Debug)]
pub struct DeviceHpkeWrap {
    pub enc: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub ciphersuite: &'static str,
}

pub fn generate_device_hpke() -> Result<(DeviceHpkeSecret, DeviceHpkePublic), CryptoError> {
    let (sk, pk) = Kem::gen_keypair();
    Ok((
        DeviceHpkeSecret(sk.to_bytes().to_vec()),
        DeviceHpkePublic(pk.to_bytes().to_vec()),
    ))
}

pub fn validate_device_hpke_public(public: &DeviceHpkePublic) -> Result<(), CryptoError> {
    if public.0.len() != XWING_PUBLIC_KEY_LEN {
        return Err(CryptoError::Encoding);
    }
    <Kem as KemTrait>::PublicKey::from_bytes(&public.0)
        .map(|_| ())
        .map_err(CryptoError::from)
}

pub fn wrap_for_device(
    recipient_pk: &DeviceHpkePublic,
    key: &CollectionKey,
) -> Result<DeviceHpkeWrap, CryptoError> {
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(&recipient_pk.0)?;
    let (encapped, ciphertext) =
        hpke::single_shot_seal::<Aead, Kdf, Kem>(&OpModeS::Base, &pk, HPKE_INFO, &key.0, HPKE_AAD)?;
    Ok(DeviceHpkeWrap {
        enc: encapped.to_bytes().to_vec(),
        ciphertext,
        ciphersuite: XWING_CIPHERSUITE,
    })
}

pub fn unwrap_for_device(
    secret: &DeviceHpkeSecret,
    wrap: &DeviceHpkeWrap,
) -> Result<CollectionKey, CryptoError> {
    let bytes = open_secret(secret, wrap, HPKE_INFO, HPKE_AAD)?;
    Ok(CollectionKey::from_bytes(bytes))
}

pub fn seal_login_challenge(
    recipient_pk: &DeviceHpkePublic,
    challenge: &[u8; 32],
) -> Result<DeviceHpkeWrap, CryptoError> {
    seal_secret(recipient_pk, challenge, LOGIN_INFO, LOGIN_AAD)
}

pub fn open_login_challenge(
    secret: &DeviceHpkeSecret,
    wrap: &DeviceHpkeWrap,
) -> Result<[u8; 32], CryptoError> {
    open_secret(secret, wrap, LOGIN_INFO, LOGIN_AAD)
}

pub fn generate_login_challenge() -> [u8; 32] {
    let mut challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);
    challenge
}

pub fn hybrid_session_key(
    opaque_session: &[u8],
    challenge: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(challenge), opaque_session);
    let mut out = [0u8; 32];
    hk.expand(b"sealbook-login-session-pq-v1", &mut out)
        .map_err(|_| CryptoError::Hkdf)?;
    Ok(out)
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

fn seal_secret(
    recipient_pk: &DeviceHpkePublic,
    secret: &[u8; 32],
    info: &[u8],
    aad: &[u8],
) -> Result<DeviceHpkeWrap, CryptoError> {
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(&recipient_pk.0)?;
    let (encapped, ciphertext) =
        hpke::single_shot_seal::<Aead, Kdf, Kem>(&OpModeS::Base, &pk, info, secret, aad)?;
    Ok(DeviceHpkeWrap {
        enc: encapped.to_bytes().to_vec(),
        ciphertext,
        ciphersuite: XWING_CIPHERSUITE,
    })
}

fn open_secret(
    secret: &DeviceHpkeSecret,
    wrap: &DeviceHpkeWrap,
    info: &[u8],
    aad: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(&secret.0)?;
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&wrap.enc)?;
    let plaintext = hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &sk,
        &encapped,
        info,
        wrap.ciphertext.as_slice(),
        aad,
    )?;
    let mut bytes = [0u8; 32];
    if plaintext.len() != 32 {
        return Err(CryptoError::Encoding);
    }
    bytes.copy_from_slice(&plaintext);
    Ok(bytes)
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xwing_wrap_round_trip() {
        let (sk, pk) = generate_device_hpke().unwrap();
        let key = CollectionKey::generate();
        let wrap = wrap_for_device(&pk, &key).unwrap();
        let opened = unwrap_for_device(&sk, &wrap).unwrap();
        assert_eq!(opened.as_bytes(), key.as_bytes());
        assert_eq!(wrap.ciphersuite, XWING_CIPHERSUITE);
    }

    #[test]
    fn login_challenge_round_trip() {
        let (sk, pk) = generate_device_hpke().unwrap();
        let challenge = generate_login_challenge();
        let wrap = seal_login_challenge(&pk, &challenge).unwrap();
        let opened = open_login_challenge(&sk, &wrap).unwrap();
        assert!(ct_eq(&opened, &challenge));
        let session = hybrid_session_key(b"opaque-session", &challenge).unwrap();
        assert_ne!(session, challenge);
    }
}
