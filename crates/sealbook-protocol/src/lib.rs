mod b64;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Wire protocol version, reported by `GET /health/crypto`.
///
/// Clients and servers must agree exactly. There has been one released protocol,
/// so a client that sees anything else is talking to a build it does not know.
pub const PROTOCOL_VERSION: &str = "sealbook-v1";

pub const JSCONTACT_CONTENT_TYPE: &str = "application/jscontact+json";
pub const ADDRESS_BOOK_CONTENT_TYPE: &str = "application/sealbook.addressbook+json";
pub const CALENDAR_EVENT_CONTENT_TYPE: &str = "application/sealbook.calendar-event+json";
pub const CALENDAR_CONTENT_TYPE: &str = "application/sealbook.calendar+json";
pub const NOTE_CONTENT_TYPE: &str = "application/sealbook.note+json";
pub const NOTEBOOK_CONTENT_TYPE: &str = "application/sealbook.notebook+json";
pub const ADDRESS_BOOK_ID_PROP: &str = "sealbook:addressBookId";

/// Smallest and largest padded plaintext an object may carry.
///
/// These are part of the wire contract rather than a server detail: a client
/// that pads beyond `MAX_PADDED_OBJECT_SIZE` will be rejected, and the padding
/// buckets in `sealbook-crypto` start at `MIN_PADDED_OBJECT_SIZE`.
///
/// Both must be powers of two. `pad` in `sealbook-crypto` rounds up to a bucket
/// and every bucket is a power of two, so a ceiling that is not one has a top
/// slice no client can ever reach.
///
/// The maximum is deliberately consistent with the per-route request limits the
/// server applies: `MAX_OBJECT_BODY` in `sealbook-server` has to cover this many
/// bytes plus an AEAD tag, base64url-expanded, plus a signed manifest. The real
/// constraint on a vault is not this number but the per-account `max_bytes`:
/// at this ceiling, 32 objects fill a default account.
pub const MIN_PADDED_OBJECT_SIZE: usize = 256;
pub const MAX_PADDED_OBJECT_SIZE: usize = 4 * 1024 * 1024;
pub const DEFAULT_ADDRESS_BOOK_NAME: &str = "Default Address Book";
pub const DEFAULT_NOTEBOOK_NAME: &str = "Default Notebook";
/// Reserved container ids: 1 is the default address book, 2 the default
/// notebook. A new feature takes the next free number rather than reusing one.
pub const DEFAULT_ADDRESS_BOOK_ID: Uuid = Uuid::from_u128(1);
pub const DEFAULT_NOTEBOOK_ID: Uuid = Uuid::from_u128(2);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterStartRequest {
    pub username: String,
    #[serde(with = "b64")]
    pub request: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterStartResponse {
    #[serde(with = "b64")]
    pub response: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePublicKeys {
    pub device_id: Uuid,
    #[serde(with = "b64")]
    pub mldsa_pk: Vec<u8>,
    #[serde(with = "b64")]
    pub ed25519_pk: Vec<u8>,
    #[serde(with = "b64")]
    pub xwing_hpke_pk: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyWrapBody {
    pub recipient_kind: String,
    pub recipient_id: String,
    #[serde(with = "b64")]
    pub hpke_enc: Vec<u8>,
    #[serde(with = "b64")]
    pub wrapped_ck: Vec<u8>,
    pub ciphersuite: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualSignatureBody {
    #[serde(with = "b64")]
    pub mldsa: Vec<u8>,
    #[serde(with = "b64")]
    pub ed25519: Vec<u8>,
}

/// Hybrid recovery-phrase material.
///
/// `lookup_id` is an opaque handle derived from the phrase; it is what a client
/// presents to fetch its phrase key wrap. The verification keys are separate so
/// the server never has to hand them out before a proof is supplied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhraseRecoveryBody {
    #[serde(with = "b64")]
    pub mldsa_pk: Vec<u8>,
    #[serde(with = "b64")]
    pub ed25519_pk: Vec<u8>,
    #[serde(with = "b64")]
    pub lookup_id: Vec<u8>,
    pub scheme: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterFinishRequest {
    pub username: String,
    #[serde(with = "b64")]
    pub upload: Vec<u8>,
    #[serde(with = "b64")]
    pub kdf_salt: Vec<u8>,
    pub device: DevicePublicKeys,
    /// Chosen by the client, like the device id, so that the initial manifest can
    /// be signed over it before the account exists. A duplicate is a `409`.
    pub collection_id: Uuid,
    pub enrollment_signature: DualSignatureBody,
    pub key_wraps: Vec<KeyWrapBody>,
    pub phrase_recovery: PhraseRecoveryBody,
    /// Manifest for the empty collection, so an account has a signed manifest
    /// from the moment it exists and a client never has to accept an unsigned
    /// "your vault is empty" from the server.
    pub manifest: ManifestBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterFinishResponse {
    pub account_id: Uuid,
    pub collection_id: Uuid,
}

/// Step 1 of login: ask for a device-sealed challenge.
///
/// This step is unauthenticated and reveals nothing: an unknown username or
/// device gets a challenge sealed to a dummy key of the same shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginChallengeRequest {
    pub username: String,
    pub device_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginChallengeResponse {
    pub challenge_id: Uuid,
    #[serde(with = "b64")]
    pub challenge_enc: Vec<u8>,
    #[serde(with = "b64")]
    pub challenge_ct: Vec<u8>,
}

/// Step 2 of login: prove device possession, then receive the OPAQUE response.
///
/// The server releases no OPAQUE credential response until the opened challenge
/// and `device_signature` both check out. Without this, anyone could harvest an
/// OPRF evaluation for any username and attack the password offline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginStartRequest {
    pub challenge_id: Uuid,
    pub username: String,
    pub device_id: Uuid,
    #[serde(with = "b64")]
    pub challenge: Vec<u8>,
    #[serde(with = "b64")]
    pub request: Vec<u8>,
    pub device_signature: DualSignatureBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginStartResponse {
    pub login_id: Uuid,
    #[serde(with = "b64")]
    pub response: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFinishRequest {
    pub login_id: Uuid,
    pub username: String,
    pub device_id: Uuid,
    #[serde(with = "b64")]
    pub finalization: Vec<u8>,
    pub device_signature: DualSignatureBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFinishResponse {
    pub account_id: Uuid,
    pub collection_id: Uuid,
    pub session_token: String,
    #[serde(with = "b64")]
    pub kdf_salt: Vec<u8>,
    pub key_wraps: Vec<KeyWrapBody>,
    /// The epoch these wraps belong to, so a client starts in sync and only
    /// re-fetches its wrap when a rotation actually happens.
    pub key_epoch: u64,
}

/// One object as the manifest commits to it.
///
/// `content_digest` is `SHA-256(nonce || ciphertext)`. Committing to the content
/// as well as the revision is what makes a rollback detectable: without it a
/// server could serve an old ciphertext under the current revision number and
/// every check would still pass.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestEntry {
    pub id: Uuid,
    pub revision: u64,
    pub tombstone: bool,
    #[serde(with = "b64")]
    pub content_digest: Vec<u8>,
}

/// A device's signed statement of what the collection contained when it wrote.
///
/// The server recomputes `digest`, `object_count` and `latest_revision` from its
/// own tables and rejects a manifest that does not match, so a stored manifest is
/// always a device-signed commitment to the server's true state. A client
/// re-derives the digest from what it is served and compares, which is what
/// detects a withheld, rolled-back or substituted object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestBody {
    /// Monotonic per collection. A write must present exactly current + 1, which
    /// serialises concurrent writers and stops a manifest being replayed.
    pub manifest_seq: u64,
    pub key_epoch: u64,
    pub latest_revision: u64,
    pub object_count: u64,
    #[serde(with = "b64")]
    pub digest: Vec<u8>,
    /// The device that signed, so a reader knows which public key to check.
    pub device_id: Uuid,
    pub signature: DualSignatureBody,
}

/// The current manifest plus the entries it commits to.
///
/// A client that holds no local state fetches this, verifies the signature and
/// the digest, and can then trust the entry set as the collection's true shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestResponse {
    pub manifest: Option<ManifestBody>,
    pub entries: Vec<ManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutObjectRequest {
    pub id: Uuid,
    /// The revision this write claims, which must be the collection's next one.
    /// Take it from `ManifestBody::latest_revision + 1`; a mismatch is a `409`
    /// and means another device wrote first.
    pub revision: u64,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    pub padded_size: usize,
    pub content_type: String,
    pub tombstone: bool,
    /// The collection as it will stand once this write is applied.
    pub manifest: ManifestBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutObjectResponse {
    pub revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangesQuery {
    pub after: Option<u64>,
    /// Most objects to return. Clamped to `MAX_CHANGES_LIMIT`; defaults to
    /// `DEFAULT_CHANGES_LIMIT`.
    pub limit: Option<usize>,
    /// Walk the collection's current state rather than the revision log.
    ///
    /// Set after a `resync`, and kept set for the rest of that walk. A snapshot
    /// walk pages through live objects, so it completes whatever has been pruned
    /// from the log; an incremental walk needs the log and can therefore be told
    /// its watermark is too old. Tombstones are rows in the live state, so a
    /// snapshot is complete rather than merely current.
    pub snapshot: Option<bool>,
}

/// Page size for the change feed when a client does not ask for one.
pub const DEFAULT_CHANGES_LIMIT: usize = 500;
/// Largest page a client may ask for.
pub const MAX_CHANGES_LIMIT: usize = 2000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectChange {
    pub id: Uuid,
    pub revision: u64,
    pub tombstone: bool,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    pub padded_size: usize,
    pub content_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangesResponse {
    pub latest_revision: u64,
    /// Bumped whenever the collection key is rotated. A client whose cached key
    /// predates this must re-fetch its wrap before it can decrypt.
    pub key_epoch: u64,
    pub objects: Vec<ObjectChange>,
    /// True when more objects remain above the highest revision in `objects`.
    /// Continue with `after` set to that revision.
    pub has_more: bool,
    /// The collection's current signed manifest, for the client to verify what
    /// it has been served against. `None` only for a collection that has never
    /// been written by a v3 client.
    pub manifest: Option<ManifestBody>,
    /// True when the server could not serve the requested `after` incrementally,
    /// because the revisions between it and now have aged out of the revision log.
    /// `objects` is then the collection's full current state, tombstones included,
    /// and the client must replace its local state with it rather than merging.
    ///
    /// A resync pages like any other answer: keep following `has_more` with
    /// `after` set to the highest revision seen, collect the whole walk, and
    /// replace local state with the result once it completes.
    ///
    /// `#[serde(default)]` so a client built before this field existed still
    /// deserializes a response carrying it.
    #[serde(default)]
    pub resync: bool,
}

/// The requesting device's current collection-key wrap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionKeysResponse {
    pub key_epoch: u64,
    pub key_wraps: Vec<KeyWrapBody>,
}

/// One object re-encrypted under the new collection key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotatedObject {
    pub id: Uuid,
    /// Revisions a rotation assigns, which must run consecutively from the
    /// collection's next revision in the order the objects are sent.
    pub revision: u64,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    pub padded_size: usize,
    pub content_type: String,
    pub tombstone: bool,
}

/// Replaces the collection key, re-wrapping it for everyone who keeps access and
/// re-encrypting every object under it.
///
/// Every operation that must invalidate the old key goes through this one
/// request, because they all require the same work and only a client can do it:
///
/// * revoking a device (`revoke_device_id`), which already holds the old key;
/// * changing the recovery phrase, since a rotation always issues a new one;
/// * finishing a recovery, where the phrase that was just used — and anyone who
///   has ever seen it — must stop being able to decrypt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateRequest {
    /// Must be exactly one greater than the collection's current epoch.
    pub key_epoch: u64,
    /// The device to revoke as part of this rotation, if any. It must not be the
    /// device making the request.
    pub revoke_device_id: Option<Uuid>,
    #[serde(with = "b64")]
    pub kdf_salt: Vec<u8>,
    /// One wrap per device that keeps access, plus `recovery` and `phrase`.
    pub key_wraps: Vec<KeyWrapBody>,
    /// Rotating the key invalidates the old recovery phrase, so a new one is
    /// issued as part of the same operation.
    pub phrase_recovery: PhraseRecoveryBody,
    pub objects: Vec<RotatedObject>,
    pub manifest: ManifestBody,
    pub rotation_signature: DualSignatureBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateResponse {
    pub key_epoch: u64,
    pub latest_revision: u64,
}

pub fn valid_username(username: &str) -> bool {
    (3..=64).contains(&username.len())
        && username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairJoinRequest {
    pub username: String,
    pub device: DevicePublicKeys,
    pub enrollment_signature: DualSignatureBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairJoinResponse {
    pub pair_id: Uuid,
    pub pair_code: String,
    pub confirm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairStatusResponse {
    pub pair_id: Uuid,
    pub status: String,
    pub confirm: String,
    pub username: Option<String>,
    pub device: Option<DevicePublicKeys>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairApproveRequest {
    pub wrap: KeyWrapBody,
    pub grant: DualSignatureBody,
    pub confirmation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverStartRequest {
    pub username: String,
    #[serde(with = "b64")]
    pub lookup_id: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverStartResponse {
    pub wrap: KeyWrapBody,
    pub recovery_id: Uuid,
    #[serde(with = "b64")]
    pub challenge: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverFinishRequest {
    pub username: String,
    pub recovery_id: Uuid,
    #[serde(with = "b64")]
    pub challenge: Vec<u8>,
    pub phrase_proof: DualSignatureBody,
    pub device: DevicePublicKeys,
    pub enrollment_signature: DualSignatureBody,
    pub wrap: KeyWrapBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverFinishResponse {
    pub account_id: Uuid,
    pub collection_id: Uuid,
}

/// A server-issued nonce for an account mutation.
///
/// Account changes are authorised by a device signature over a transcript that
/// includes this challenge, not by the age of a session. A bearer token alone is
/// no longer enough to change the password, rename the account or delete it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountChallengeResponse {
    pub challenge_id: Uuid,
    #[serde(with = "b64")]
    pub challenge: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeUsernameRequest {
    pub new_username: String,
    #[serde(with = "b64")]
    pub upload: Vec<u8>,
    pub challenge_id: Uuid,
    #[serde(with = "b64")]
    pub challenge: Vec<u8>,
    pub signature: DualSignatureBody,
}

/// Deleting an account needs a device signature too, so that a stolen token
/// cannot destroy the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteAccountRequest {
    pub challenge_id: Uuid,
    #[serde(with = "b64")]
    pub challenge: Vec<u8>,
    pub signature: DualSignatureBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub password_change_id: Uuid,
    #[serde(with = "b64")]
    pub challenge: Vec<u8>,
    pub signature: DualSignatureBody,
    #[serde(with = "b64")]
    pub upload: Vec<u8>,
    #[serde(with = "b64")]
    pub kdf_salt: Vec<u8>,
    #[serde(with = "b64")]
    pub recovery_nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub recovery_wrapped_ck: Vec<u8>,
    pub recovery_ciphersuite: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePasswordStartRequest {
    #[serde(with = "b64")]
    pub request: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePasswordStartResponse {
    pub password_change_id: Uuid,
    #[serde(with = "b64")]
    pub response: Vec<u8>,
    /// Doubles as the account-operation challenge, so changing a password is
    /// still two round trips rather than three.
    #[serde(with = "b64")]
    pub challenge: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleStatusResponse {
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_address_book_id_is_stable() {
        assert_eq!(
            DEFAULT_ADDRESS_BOOK_ID.to_string(),
            "00000000-0000-0000-0000-000000000001"
        );
    }

    #[test]
    fn default_notebook_id_is_stable() {
        assert_eq!(
            DEFAULT_NOTEBOOK_ID.to_string(),
            "00000000-0000-0000-0000-000000000002"
        );
    }

    #[test]
    fn the_object_ceiling_is_a_padding_bucket() {
        // `pad` only ever produces powers of two, so a bound that is not one
        // declares capacity no client can use.
        assert!(MIN_PADDED_OBJECT_SIZE.is_power_of_two());
        assert!(MAX_PADDED_OBJECT_SIZE.is_power_of_two());
    }
}
