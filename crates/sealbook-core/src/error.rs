//! The one error type every core decision returns.
//!
//! Variants are part of the binding surface: the TypeScript wrapper maps them
//! onto the classes callers already catch and Kotlin matches on them, so a
//! variant is renamed or removed only together with those two.
//!
//! The free-text field is `detail`, not `message`: uniffi renders an error as a
//! Kotlin exception, where a `message` field collides with `Throwable.message`
//! and the generated file does not compile.

use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
#[serde(tag = "kind")]
pub enum CoreError {
    #[error("manifest verification failed: {detail}")]
    Manifest { detail: String },
    #[error("device roster verification failed: {detail}")]
    Roster { detail: String },
    #[error("refusing a device roster older than the one this device pinned")]
    RosterTooOld,
    #[error("crypto: {detail}")]
    Crypto { detail: String },
    #[error("server error: {detail}")]
    Server { detail: String },
    #[error("the server's answer is not in the shape this build expects: {detail}")]
    Malformed { detail: String },
    #[error("missing local state; register or login first")]
    NoState,
    #[error("no collection key available")]
    NoCollectionKey,
    #[error("invalid nonce")]
    Nonce,
    #[error("a batch write may carry at most {max} objects, got {got}", max = sealbook_protocol::MAX_BATCH_OBJECTS)]
    BatchTooLarge { got: u64 },
    #[error("a batch write may name each object once")]
    DuplicateInBatch,
    #[error(
        "the collection key has moved to epoch {expected} and this device holds epoch {held}; \
         nothing was written"
    )]
    StaleCollectionKey { expected: u64, held: u64 },
    #[error("object {object} has an envelope this build cannot read")]
    Envelope {
        #[cfg_attr(feature = "wasm", tsify(type = "string"))]
        object: Uuid,
    },
    #[error(
        "attachment {object} failed its integrity check; the download was tampered with or corrupt"
    )]
    AttachmentIntegrity {
        #[cfg_attr(feature = "wasm", tsify(type = "string"))]
        object: Uuid,
    },
    #[error(
        "server speaks protocol {reported}, this build speaks {expected}; update whichever is older",
        expected = sealbook_protocol::PROTOCOL_VERSION
    )]
    ProtocolVersion { reported: String },
    #[error("pairing is still waiting")]
    PairPending,
    /// A write landed between two pages of a read. Retrying is the right answer
    /// to this one and the wrong answer to `Manifest`.
    #[error("the collection changed while it was being read; nothing is wrong, try again")]
    CollectionBusy,
    #[error(
        "this account has an unfinished recovery: the collection key must be rotated, which \
         issues a new recovery phrase"
    )]
    RecoveryRotationPending,
    #[error("{refusal}")]
    Rotation {
        refusal: crate::rotation::RotationRefusal,
    },
    #[error("{refusal}")]
    Pair {
        refusal: crate::pairing::PairRefusal,
    },
    /// A core function called out of order by its host, not a server fault.
    #[error("core state machine misuse: {detail}")]
    Misuse { detail: String },
}

impl CoreError {
    pub fn manifest(detail: impl Into<String>) -> Self {
        CoreError::Manifest {
            detail: detail.into(),
        }
    }

    pub fn roster(detail: impl Into<String>) -> Self {
        CoreError::Roster {
            detail: detail.into(),
        }
    }

    pub fn malformed(detail: impl Into<String>) -> Self {
        CoreError::Malformed {
            detail: detail.into(),
        }
    }

    pub fn misuse(detail: impl Into<String>) -> Self {
        CoreError::Misuse {
            detail: detail.into(),
        }
    }

    /// The variant name, for a host that maps onto its own error classes
    /// without matching every variant.
    pub fn kind(&self) -> &'static str {
        match self {
            CoreError::Manifest { .. } => "Manifest",
            CoreError::Roster { .. } => "Roster",
            CoreError::RosterTooOld => "RosterTooOld",
            CoreError::Crypto { .. } => "Crypto",
            CoreError::Server { .. } => "Server",
            CoreError::Malformed { .. } => "Malformed",
            CoreError::NoState => "NoState",
            CoreError::NoCollectionKey => "NoCollectionKey",
            CoreError::Nonce => "Nonce",
            CoreError::BatchTooLarge { .. } => "BatchTooLarge",
            CoreError::DuplicateInBatch => "DuplicateInBatch",
            CoreError::StaleCollectionKey { .. } => "StaleCollectionKey",
            CoreError::Envelope { .. } => "Envelope",
            CoreError::AttachmentIntegrity { .. } => "AttachmentIntegrity",
            CoreError::ProtocolVersion { .. } => "ProtocolVersion",
            CoreError::PairPending => "PairPending",
            CoreError::CollectionBusy => "CollectionBusy",
            CoreError::RecoveryRotationPending => "RecoveryRotationPending",
            CoreError::Rotation { .. } => "Rotation",
            CoreError::Pair { .. } => "Pair",
            CoreError::Misuse { .. } => "Misuse",
        }
    }
}

impl From<sealbook_crypto::CryptoError> for CoreError {
    fn from(e: sealbook_crypto::CryptoError) -> Self {
        // A roster failure keeps its own variant: hosts raise it as a different
        // class from a key or signature failure.
        match e {
            sealbook_crypto::CryptoError::Roster(detail) => CoreError::Roster { detail },
            other => CoreError::Crypto {
                detail: other.to_string(),
            },
        }
    }
}

impl From<serde_json::Error> for CoreError {
    fn from(e: serde_json::Error) -> Self {
        CoreError::Malformed {
            detail: e.to_string(),
        }
    }
}
