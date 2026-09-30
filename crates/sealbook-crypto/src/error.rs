use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("aead encryption failed")]
    AeadEncrypt,
    #[error("aead decryption failed")]
    AeadDecrypt,
    #[error("padded payload is truncated")]
    Padding,
    #[error("argon2 kdf failed")]
    Kdf,
    #[error("hkdf failed")]
    Hkdf,
    #[error("hpke error: {0}")]
    Hpke(String),
    #[error("opaque error: {0}")]
    Opaque(String),
    #[error("signature error: {0}")]
    Signature(String),
    #[error("invalid key encoding")]
    Encoding,
}

impl From<hpke::HpkeError> for CryptoError {
    fn from(err: hpke::HpkeError) -> Self {
        Self::Hpke(err.to_string())
    }
}
