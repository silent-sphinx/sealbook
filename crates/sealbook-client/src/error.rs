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
    #[error("a batch write may carry at most {max} objects, got {0}", max = sealbook_protocol::MAX_BATCH_OBJECTS)]
    BatchTooLarge(usize),
    #[error("a batch write may name each object once")]
    DuplicateInBatch,
    /// Sealing under a retired key would store a row no device can decrypt and
    /// no rotation can re-encrypt, so the write is refused instead.
    #[error(
        "the collection key has moved to epoch {expected} and this device holds epoch {held}; \
         nothing was written"
    )]
    StaleCollectionKey { expected: u64, held: u64 },
    /// Read through a helper that returns `String`, of an object whose plaintext
    /// is not text. Rotation carries bytes through untouched, so the object is
    /// intact; only this accessor cannot represent it.
    #[error("object {0} is not valid UTF-8")]
    NonUtf8Object(uuid::Uuid),
    #[error("object {0} has an envelope this build cannot read")]
    Envelope(uuid::Uuid),
    /// A downloaded attachment's chunks did not reproduce the content hash the
    /// owning note committed to: a withheld, reordered, truncated or substituted
    /// chunk. Like `Manifest`, this is never retried away.
    #[error(
        "attachment {0} failed its integrity check; the download was tampered with or corrupt"
    )]
    AttachmentIntegrity(uuid::Uuid),
    #[error(
        "server speaks protocol {0}, this build speaks {expected}; update whichever is older",
        expected = sealbook_protocol::PROTOCOL_VERSION
    )]
    ProtocolVersion(String),
    #[error("pairing is still waiting")]
    PairPending,
    /// Pages of a sync come from separate transactions, so a write landing
    /// between two of them leaves the accumulated set and the final manifest
    /// describing different states. That is a race, not a withheld object, and
    /// it has to be told apart from `Manifest`: retrying is the right answer to
    /// this one and the wrong answer to that one.
    #[error("the collection changed while it was being read; nothing is wrong, try again")]
    CollectionBusy,
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

impl From<sealbook_core::CoreError> for ClientError {
    fn from(e: sealbook_core::CoreError) -> Self {
        use sealbook_core::CoreError;
        match e {
            CoreError::Manifest { detail } => ClientError::Manifest(ManifestError(detail)),
            CoreError::Roster { detail } => {
                ClientError::Crypto(sealbook_crypto::CryptoError::Roster(detail))
            }
            // Core states the condition; the sentence that tells the user what to
            // do about it is the host's, as it is in the other two clients.
            CoreError::RosterTooOld => ClientError::Crypto(sealbook_crypto::CryptoError::Roster(
                "this device is further behind than the server's roster history reaches, \
                     so the chain from its pinned roster cannot be checked; pair this device \
                     again to anchor it on the current roster"
                    .into(),
            )),
            CoreError::Crypto { detail } | CoreError::Malformed { detail } => {
                ClientError::Crypto(sealbook_crypto::CryptoError::Roster(detail))
            }
            CoreError::Server { detail } | CoreError::Misuse { detail } => {
                ClientError::Server(detail)
            }
            CoreError::NoState => ClientError::NoState,
            CoreError::NoCollectionKey => ClientError::NoCollectionKey,
            CoreError::Nonce => ClientError::Nonce,
            CoreError::BatchTooLarge { got } => ClientError::BatchTooLarge(got as usize),
            CoreError::DuplicateInBatch => ClientError::DuplicateInBatch,
            CoreError::StaleCollectionKey { expected, held } => {
                ClientError::StaleCollectionKey { expected, held }
            }
            CoreError::Envelope { object } => ClientError::Envelope(object),
            CoreError::AttachmentIntegrity { object } => ClientError::AttachmentIntegrity(object),
            CoreError::ProtocolVersion { reported } => ClientError::ProtocolVersion(reported),
            CoreError::PairPending => ClientError::PairPending,
            CoreError::CollectionBusy => ClientError::CollectionBusy,
            CoreError::RecoveryRotationPending => ClientError::RecoveryRotationPending,
            // Each refusal states its own condition, and the CLI prints it as
            // the reason the rotation did not start.
            CoreError::Rotation { refusal } => ClientError::Server(refusal.to_string()),
        }
    }
}
