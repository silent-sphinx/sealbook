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
    #[error("server error: {message}")]
    Status { status: u16, message: String },
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
    /// The account has not moved to this protocol version: its key was wrapped
    /// under the old scheme, and the server kept a copy a password protected.
    /// Call `complete_rotation`; the server refuses writes until it is done.
    #[error(
        "this account has not moved to the current protocol: the collection key must be \
         rotated, which issues a new recovery phrase"
    )]
    UpgradeRotationPending,
    /// The server served a key that does not open the vault this device holds.
    #[error("the server served a key that does not match your vault")]
    KeyMismatch,
    /// Key material in a form a migrated account no longer uses.
    #[error("the server served key material in a form this account no longer uses")]
    LegacyKeyMaterial,
    /// The collection key this device holds decrypted none of the vault's
    /// rows. Never retried away: it is the server-substituted key the roster's
    /// key commitment exists to catch, on an account that has no commitment
    /// yet.
    #[error(
        "this device's collection key opens none of the {0} object(s) in the vault; it is not \
         the key the vault is sealed under, so nothing was read"
    )]
    WrongCollectionKey(u64),
    #[error("tls: {0}")]
    Tls(String),
}

impl ClientError {
    /// The server's certificate was refused: not issued by anyone this device
    /// trusts, or not the one it has pinned.
    pub fn is_untrusted_certificate(&self) -> bool {
        let ClientError::Http(error) = self else {
            return false;
        };
        let mut source: Option<&dyn std::error::Error> = Some(error);
        while let Some(current) = source {
            if current.to_string().contains("invalid peer certificate") {
                return true;
            }
            source = current.source();
        }
        false
    }

    /// The typed password is not the account's: this device's own OPAQUE step
    /// could not open the server's credential response with it. That step fails
    /// locally, so it has no HTTP status; a revoked device is a 401 instead, and a
    /// response that does not parse is a different OPAQUE failure, so neither
    /// reads as this.
    pub fn is_wrong_password(&self) -> bool {
        // Through core the crypto error arrives as text in a roster error, so
        // both shapes are read as the crypto error's own message.
        let message = match self {
            ClientError::Crypto(sealbook_crypto::CryptoError::Roster(detail)) => detail.clone(),
            ClientError::Crypto(error) => error.to_string(),
            _ => return false,
        };
        message.starts_with("opaque error:") && message.contains("validating credentials")
    }
}

impl ClientError {
    /// The HTTP status this error carries, with 0 for a request that got no
    /// response at all (a connection, timeout or interrupted transfer), and
    /// `None` for an error that is not about the request: the host sorts those
    /// into a retry or a refusal with core's `flush_failure`, and must not
    /// treat a verification failure as one it can retry.
    pub fn http_status(&self) -> Option<u16> {
        match self {
            ClientError::Status { status, .. } => Some(*status),
            ClientError::Http(err) => match err.status() {
                Some(status) => Some(status.as_u16()),
                None if err.is_connect()
                    || err.is_timeout()
                    || err.is_request()
                    || err.is_body() =>
                {
                    Some(0)
                }
                None => None,
            },
            _ => None,
        }
    }
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
            CoreError::UpgradeRotationPending => ClientError::UpgradeRotationPending,
            CoreError::KeyMismatch => ClientError::KeyMismatch,
            CoreError::LegacyKeyMaterial => ClientError::LegacyKeyMaterial,
            CoreError::WrongCollectionKey { rows } => ClientError::WrongCollectionKey(rows),
            // Each refusal states its own condition, and the CLI prints it as
            // the reason the rotation did not start.
            CoreError::Rotation { refusal } => ClientError::Server(refusal.to_string()),
            // As above: the refusal states the condition and the CLI prints it
            // as the reason the pairing did not go through.
            CoreError::Pair { refusal } => ClientError::Server(refusal.to_string()),
            CoreError::Auth { refusal } => ClientError::Server(refusal.to_string()),
            // As above: the refusal states why the attachment was not sent or
            // not trusted, and the CLI prints it.
            CoreError::Attachment { refusal } => ClientError::Server(refusal.to_string()),
            // Not a server fault: the stored payload is from a newer client. The
            // error states which schema it declared and what this build reads.
            ref schema @ CoreError::PayloadSchema { .. } => ClientError::Server(schema.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_error_reports_its_status_and_prints_the_servers_message() {
        let error = ClientError::Status {
            status: 413,
            message: "object too large".into(),
        };
        assert_eq!(error.http_status(), Some(413));
        assert_eq!(error.to_string(), "server error: object too large");
    }

    #[test]
    fn errors_that_are_not_about_the_request_have_no_status() {
        assert_eq!(ClientError::Server("x".into()).http_status(), None);
        assert_eq!(ClientError::CollectionBusy.http_status(), None);
        assert_eq!(
            ClientError::Manifest(ManifestError("forged".into())).http_status(),
            None
        );
    }

    /// Runs OPAQUE against a record made with `registered`, signing in with
    /// `typed`, and returns the client's failure as core hands it on.
    fn login_failure(registered: &str, typed: &str, response: Option<&[u8]>) -> ClientError {
        use sealbook_crypto::opaque;
        let setup = opaque::new_server_setup();
        let (request, state) = opaque::client_register_start(registered.as_bytes()).unwrap();
        let reply = opaque::server_register_start(&setup, &request, b"alice").unwrap();
        let upload = opaque::client_register_finish(state, registered.as_bytes(), &reply).unwrap();
        let record = opaque::server_register_finish(&upload).unwrap();
        let (request, state) = opaque::client_login_start(typed.as_bytes()).unwrap();
        let (served, _) = opaque::server_login_start(&setup, &record, &request, b"alice").unwrap();
        let error =
            opaque::client_login_finish(state, typed.as_bytes(), response.unwrap_or(&served))
                .err()
                .expect("the login fails");
        ClientError::from(sealbook_core::CoreError::from(error))
    }

    #[test]
    fn a_password_that_does_not_open_the_credential_response_is_wrong() {
        let error = login_failure("right horse battery", "wrong horse battery", None);
        assert!(error.is_wrong_password(), "{error}");
    }

    #[test]
    fn a_credential_response_that_does_not_parse_is_not_a_wrong_password() {
        let error = login_failure("right horse battery", "right horse battery", Some(b"junk"));
        assert!(!error.is_wrong_password(), "{error}");
    }

    #[test]
    fn a_refused_device_or_a_roster_failure_is_not_a_wrong_password() {
        let revoked = ClientError::Status {
            status: 401,
            message: "unauthorized".into(),
        };
        assert!(!revoked.is_wrong_password());
        let roster = ClientError::Crypto(sealbook_crypto::CryptoError::Roster(
            "the roster is not signed by a known device".into(),
        ));
        assert!(!roster.is_wrong_password());
    }
}
