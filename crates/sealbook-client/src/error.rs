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
    /// Read through a helper that returns `String`, of an object whose plaintext
    /// is not text. Rotation carries bytes through untouched, so the object is
    /// intact; only this accessor cannot represent it.
    #[error("object {0} is not valid UTF-8")]
    NonUtf8Object(uuid::Uuid),
    #[error("object {0} has an envelope this build cannot read")]
    Envelope(uuid::Uuid),
    #[error("pairing is still waiting")]
    PairPending,
    /// A recovery enrolled this device but never rotated the collection key, so
    /// the phrase used to recover still opens the vault. Call
    /// `complete_recovery_rotation` to finish it; the server refuses writes until
    /// it is done.
    #[error(
        "this account has an unfinished recovery: the collection key must be rotated, which \
         issues a new recovery phrase"
    )]
    RecoveryRotationPending,
    #[error("tls: {0}")]
    Tls(String),
}
