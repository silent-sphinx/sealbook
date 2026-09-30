//! Errors the client surfaces to callers.

/// What the server served did not match what a device signed for it.
///
/// This is the failure that matters most: it is what a rollback, a withheld
/// object or a substituted ciphertext looks like from the client side. It is never
/// a transient condition and must not be retried away.
#[derive(Debug, thiserror::Error)]
#[error("manifest verification failed: {0}")]
pub struct ManifestError(pub String);

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error(transparent)]
    Crypto(#[from] sealbook_crypto::CryptoError),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error("server error: {0}")]
    Server(String),
    #[error("missing local state; register or login first")]
    NoState,
    #[error("no collection key available")]
    NoCollectionKey,
    #[error("invalid nonce")]
    Nonce,
    #[error("pairing is still waiting")]
    PairPending,
    #[error("tls: {0}")]
    Tls(String),
}
