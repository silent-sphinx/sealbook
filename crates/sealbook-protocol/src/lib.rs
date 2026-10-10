mod b64;
pub mod envelope;
pub mod version;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use version::{
    merge_payload, payload_schema_readable, speaks_protocol, ProtocolReport,
    PAYLOAD_SCHEMA_VERSION, PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
};

pub const SEALED_CONTENT_TYPE: &str = "application/vnd.sealbook.sealed";

pub const JSCONTACT_CONTENT_TYPE: &str = "application/jscontact+json";
pub const ADDRESS_BOOK_CONTENT_TYPE: &str = "application/sealbook.addressbook+json";
pub const CALENDAR_EVENT_CONTENT_TYPE: &str = "application/sealbook.calendar-event+json";
pub const CALENDAR_CONTENT_TYPE: &str = "application/sealbook.calendar+json";
pub const NOTE_CONTENT_TYPE: &str = "application/sealbook.note+json";
pub const NOTEBOOK_CONTENT_TYPE: &str = "application/sealbook.notebook+json";
pub const ADDRESS_BOOK_ID_PROP: &str = "sealbook:addressBookId";

/// The `@type` and `version` of a full account export, the one file that carries
/// a whole vault decrypted. Every client that writes one writes these, so an
/// export from the CLI and one from `sealbook-web` are the same document;
/// `sealbook-web` mirrors them in `src/lib/accountExport.ts`.
pub const ACCOUNT_EXPORT_TYPE: &str = "SealbookAccountExport";
pub const ACCOUNT_EXPORT_VERSION: &str = "1.0";

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
/// constraint on a vault is not this number but the per-account `max_bytes`,
/// which the server owns and states in terms of this ceiling.
pub const MIN_PADDED_OBJECT_SIZE: usize = 256;
pub const MAX_PADDED_OBJECT_SIZE: usize = 8 * 1024 * 1024;
pub const DEFAULT_ADDRESS_BOOK_NAME: &str = "Default Address Book";
pub const DEFAULT_NOTEBOOK_NAME: &str = "Default Notebook";
pub const DEFAULT_CALENDAR_NAME: &str = "Default Calendar";

/// Colour the default calendar is created with. Unlike a name, a calendar's
/// colour is part of its payload, so the clients have to agree on one for the
/// container they each create independently.
pub const DEFAULT_CALENDAR_COLOR: &str = "#7aa2f7";

/// Reserved object ids: 1 is the default address book, 2 the default notebook,
/// 3 the default calendar, 4 the account settings object. A new feature takes
/// the next free number rather than reusing one: the settings object sat on 3
/// in the web client before the default calendar existed, and the two writers
/// then overwrote each other. Ids are listed here even when only one client
/// writes the object, so the next one cannot pick a number that is taken.
pub const DEFAULT_ADDRESS_BOOK_ID: Uuid = Uuid::from_u128(1);
pub const DEFAULT_NOTEBOOK_ID: Uuid = Uuid::from_u128(2);
pub const DEFAULT_CALENDAR_ID: Uuid = Uuid::from_u128(3);
pub const ACCOUNT_SETTINGS_ID: Uuid = Uuid::from_u128(4);

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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RosterSignerBody {
    Device { device_id: Uuid },
    Phrase,
}

/// The account's device set and phrase recovery key at one sequence number.
///
/// Signed by a member of the previous roster and MAC'd under the collection key,
/// so a client never has to take the server's word for which devices exist. See
/// `sealbook_crypto::roster`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RosterBody {
    pub roster_seq: u64,
    pub key_epoch: u64,
    pub devices: Vec<DevicePublicKeys>,
    #[serde(with = "b64")]
    pub phrase_mldsa_pk: Vec<u8>,
    #[serde(with = "b64")]
    pub phrase_ed25519_pk: Vec<u8>,
    pub signer: RosterSignerBody,
    pub signature: DualSignatureBody,
    #[serde(with = "b64")]
    pub mac: Vec<u8>,
}

impl RosterBody {
    pub fn to_roster(&self) -> sealbook_crypto::Roster {
        sealbook_crypto::Roster {
            roster_seq: self.roster_seq,
            key_epoch: self.key_epoch,
            devices: self
                .devices
                .iter()
                .map(|device| sealbook_crypto::RosterDevice {
                    device_id: device.device_id,
                    mldsa_pk: device.mldsa_pk.clone(),
                    ed25519_pk: device.ed25519_pk.clone(),
                    xwing_hpke_pk: device.xwing_hpke_pk.clone(),
                })
                .collect(),
            phrase_mldsa_pk: self.phrase_mldsa_pk.clone(),
            phrase_ed25519_pk: self.phrase_ed25519_pk.clone(),
            signer: match self.signer {
                RosterSignerBody::Device { device_id } => {
                    sealbook_crypto::RosterSigner::Device(device_id)
                }
                RosterSignerBody::Phrase => sealbook_crypto::RosterSigner::Phrase,
            },
            signature: sealbook_crypto::DualSignature {
                mldsa: self.signature.mldsa.clone(),
                ed25519: self.signature.ed25519.clone(),
            },
            mac: self.mac.clone(),
        }
    }

    /// Signs and MACs a roster over `devices`.
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        collection_id: Uuid,
        roster_seq: u64,
        key_epoch: u64,
        devices: Vec<DevicePublicKeys>,
        phrase_mldsa_pk: Vec<u8>,
        phrase_ed25519_pk: Vec<u8>,
        signer: RosterSignerBody,
        secrets: &sealbook_crypto::DeviceSigningSecrets,
        key: &sealbook_crypto::CollectionKey,
    ) -> Result<Self, sealbook_crypto::CryptoError> {
        let mut body = Self {
            roster_seq,
            key_epoch,
            devices,
            phrase_mldsa_pk,
            phrase_ed25519_pk,
            signer,
            signature: DualSignatureBody {
                mldsa: Vec::new(),
                ed25519: Vec::new(),
            },
            mac: Vec::new(),
        };
        let transcript = body.to_roster().transcript(collection_id);
        let signature = sealbook_crypto::sign(secrets, &transcript)?;
        body.signature = DualSignatureBody {
            mldsa: signature.mldsa,
            ed25519: signature.ed25519,
        };
        body.mac = sealbook_crypto::roster_mac(key, &transcript)?.to_vec();
        Ok(body)
    }

    /// Verifies a served roster history and returns the newest, which must list
    /// `self_device`. See `sealbook_crypto::verify_roster_chain` for the rules.
    pub fn verify_chain(
        collection_id: Uuid,
        pin: Option<sealbook_crypto::RosterPin>,
        chain: Vec<RosterBody>,
        key: Option<(&sealbook_crypto::CollectionKey, u64)>,
        self_device: Uuid,
    ) -> Result<RosterBody, sealbook_crypto::CryptoError> {
        let rosters: Vec<sealbook_crypto::Roster> =
            chain.iter().map(RosterBody::to_roster).collect();
        sealbook_crypto::verify_roster_chain(collection_id, pin, &rosters, key)?;
        let latest = chain
            .into_iter()
            .last()
            .expect("verified chain is non-empty");
        if !latest
            .devices
            .iter()
            .any(|device| device.device_id == self_device)
        {
            return Err(sealbook_crypto::CryptoError::Roster(
                "this device is not in the account's roster".into(),
            ));
        }
        Ok(latest)
    }

    /// The pin a client keeps once it has accepted this roster.
    pub fn pin(&self, collection_id: Uuid) -> sealbook_crypto::RosterPin {
        sealbook_crypto::RosterPin {
            roster_seq: self.roster_seq,
            transcript: self.to_roster().transcript(collection_id),
        }
    }

    pub fn from_roster(roster: sealbook_crypto::Roster) -> Self {
        Self {
            roster_seq: roster.roster_seq,
            key_epoch: roster.key_epoch,
            devices: roster
                .devices
                .into_iter()
                .map(|device| DevicePublicKeys {
                    device_id: device.device_id,
                    mldsa_pk: device.mldsa_pk,
                    ed25519_pk: device.ed25519_pk,
                    xwing_hpke_pk: device.xwing_hpke_pk,
                })
                .collect(),
            phrase_mldsa_pk: roster.phrase_mldsa_pk,
            phrase_ed25519_pk: roster.phrase_ed25519_pk,
            signer: match roster.signer {
                sealbook_crypto::RosterSigner::Device(device_id) => {
                    RosterSignerBody::Device { device_id }
                }
                sealbook_crypto::RosterSigner::Phrase => RosterSignerBody::Phrase,
            },
            signature: DualSignatureBody {
                mldsa: roster.signature.mldsa,
                ed25519: roster.signature.ed25519,
            },
            mac: roster.mac,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RosterQuery {
    /// Return every roster from this sequence on, inclusive. Omitted, only the
    /// newest is returned.
    pub from: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RosterResponse {
    /// Oldest first.
    pub rosters: Vec<RosterBody>,
    #[serde(default)]
    pub floor: u64,
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
    /// Genesis roster: this device alone, signed by itself.
    pub roster: RosterBody,
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
    /// True when a recovery enrolled a device and the collection key has still
    /// not been rotated, so the phrase used then — and any other copy of it —
    /// can still open this vault. The client must finish that rotation before
    /// the account can be written to again.
    ///
    /// `#[serde(default)]` so a client built before this field existed still
    /// deserializes a response carrying it.
    #[serde(default)]
    pub recovery_pending: bool,
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

/// Which buckets of the manifest a caller wants the entries of.
#[derive(Debug, Clone, Deserialize)]
pub struct ManifestBucketQuery {
    /// The buckets to serve, as concatenated two-digit hex: `manifest_bucket_of`
    /// of each object the caller is about to write, so `03` for one and `031f`
    /// for two. Omitted asks for the digests alone.
    ///
    /// A list rather than a single bucket because a batch write touches one
    /// bucket per object, and asking for them one request at a time would undo
    /// what batching is for.
    pub buckets: Option<String>,
}

/// Renders a bucket list for `ManifestBucketQuery::buckets`.
pub fn bucket_query(buckets: &[u8]) -> String {
    buckets
        .iter()
        .map(|bucket| format!("{bucket:02x}"))
        .collect()
}

/// Parses a `ManifestBucketQuery::buckets` list, rejecting anything malformed.
pub fn parse_bucket_query(buckets: &str) -> Option<Vec<u8>> {
    if !buckets.len().is_multiple_of(2) {
        return None;
    }
    let bytes = buckets.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let text = std::str::from_utf8(pair).ok()?;
        out.push(u8::from_str_radix(text, 16).ok()?);
    }
    out.sort_unstable();
    out.dedup();
    Some(out)
}

/// The manifest as a write needs to see it.
///
/// `ManifestResponse` carries every entry in the collection, so a write that
/// fetched it moved bytes proportional to the whole vault and importing *n*
/// objects cost O(n squared). The root is a hash of 256 bucket digests, and a
/// write changes one bucket per object, so this serves the digests plus the
/// entries of the buckets asked for: enough to check the manifest and to compute
/// the next one.
///
/// Verifying it is the same work as before, in two steps rather than one. The
/// served entries of each bucket must hash to that bucket's digest, and `buckets`
/// with `object_count` must produce the root the manifest signature covers. A
/// server withholding an object from a served bucket fails the first check, and
/// one editing a bucket digest fails the second.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestBucketsResponse {
    pub manifest: Option<ManifestBody>,
    /// The 256 bucket digests concatenated, 32 bytes each.
    #[serde(with = "b64")]
    pub buckets: Vec<u8>,
    pub object_count: u64,
    /// The buckets whose entries follow, parsed back from the request and in
    /// ascending order. A caller checks its own list against this rather than
    /// trusting that every bucket it asked for was served.
    pub served: Vec<u8>,
    /// Every entry in every bucket of `served`, or empty if none was asked for.
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

/// Most objects one batch write may carry.
///
/// The body limit is the other bound and the tighter one for large objects: a
/// batch of notes at the per-object ceiling is refused long before it reaches
/// this many. It is small objects that this caps, which is what an import of
/// contacts is.
pub const MAX_BATCH_OBJECTS: usize = 256;

/// One object inside a batch write.
///
/// The same fields `PutObjectRequest` carries per object, without the manifest:
/// a batch signs one manifest for the state all of them together produce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchObject {
    pub id: Uuid,
    /// Revisions a batch assigns, which must run consecutively from the
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

/// Several objects written under one manifest.
///
/// A single `PutObjectRequest` costs a round trip and a manifest signature each,
/// so importing *n* objects meant *n* requests against the per-minute write cap
/// with nothing else able to write in between. This applies them in one
/// transaction under one signature instead.
///
/// It does not relax the sequence rule: the manifest still has to be the
/// collection's next one, so two devices writing at the same time still collide.
/// What it changes is how much one request can carry, which is what an import
/// needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutObjectsRequest {
    /// At least one and at most `MAX_BATCH_OBJECTS`, each id appearing once.
    pub objects: Vec<BatchObject>,
    /// The collection as it will stand once every object in `objects` is
    /// applied.
    pub manifest: ManifestBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutObjectsResponse {
    /// The revision the first object in the batch took.
    pub first_revision: u64,
    /// The revision the last one took, which is the collection's latest.
    pub latest_revision: u64,
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
    #[serde(default)]
    pub tombstone_floor: u64,
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
    /// The remaining devices and the new phrase key, at the new epoch, signed by
    /// the rotating device.
    pub roster: RosterBody,
    /// Tombstones this rotation retires, which must each be below the
    /// collection's `tombstone_floor`.
    ///
    /// Not covered by `rotation_signature` and it does not need to be: `manifest`
    /// commits to the entry set the rotation leaves behind, and the server
    /// recomputes that from its own rows afterwards. Adding an id here or taking
    /// one away changes the rows and the manifest stops matching, so the signed
    /// manifest is what pins this list.
    #[serde(default)]
    pub drop_tombstones: Vec<Uuid>,
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
    /// The roster the joining device must anchor on, and which `confirm` commits
    /// to: the account's current roster sequence and its transcript.
    pub roster_seq: u64,
    #[serde(with = "b64")]
    pub roster_transcript: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairStatusResponse {
    pub pair_id: Uuid,
    pub status: String,
    pub confirm: String,
    pub username: Option<String>,
    pub device: Option<DevicePublicKeys>,
    /// The roster sequence the joining device anchored on, for the account's own
    /// devices only. It lets an approver whose roster has moved on since the
    /// pairing started say so, rather than reporting a bare code mismatch.
    pub roster_seq: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairApproveRequest {
    pub wrap: KeyWrapBody,
    pub grant: DualSignatureBody,
    pub confirmation: String,
    /// The current roster plus the new device, signed by the approver.
    pub roster: RosterBody,
}

/// Step 1 of recovery: fetch the phrase's key wrap and begin a password reset.
///
/// A recovery exists for the case where the password is what was lost, so it
/// replaces the password rather than asking for it. That needs an OPAQUE
/// registration round trip, which is what `opaque_request` starts.
///
/// Unauthenticated, like `login/challenge`, and it reveals nothing: an unknown
/// username, or a `lookup_id` that does not match, gets a dummy wrap and a
/// registration response of the same shape. The response carries no material
/// derived from the existing password, so it cannot be harvested to attack it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverStartRequest {
    pub username: String,
    #[serde(with = "b64")]
    pub lookup_id: Vec<u8>,
    #[serde(with = "b64")]
    pub opaque_request: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverStartResponse {
    pub wrap: KeyWrapBody,
    pub recovery_id: Uuid,
    #[serde(with = "b64")]
    pub challenge: Vec<u8>,
    /// The current roster and the collection it belongs to. A recovering device
    /// checks them with the collection key the phrase wrap opens; a lookup that
    /// matched nothing is answered with a decoy, so their presence says nothing
    /// about whether the account exists. Optional for the benefit of a server
    /// that predates the decoy.
    pub roster: Option<RosterBody>,
    pub collection_id: Option<Uuid>,
    #[serde(with = "b64")]
    pub opaque_response: Vec<u8>,
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
    /// The current roster plus the recovering device, signed by the phrase key.
    pub roster: RosterBody,
    /// The replacement password, as an OPAQUE registration upload, plus the KDF
    /// salt and the collection-key wrap re-made under it. `phrase_proof` covers
    /// all of it, so none of it can be substituted in flight.
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
    fn a_bucket_list_round_trips() {
        let buckets = [0u8, 3, 0x1f, 0xff];
        assert_eq!(bucket_query(&buckets), "00031fff");
        assert_eq!(parse_bucket_query("00031fff"), Some(buckets.to_vec()));
        // Sorted and deduplicated, so a caller's own sorted list can be compared
        // against the echo without reordering either.
        assert_eq!(
            parse_bucket_query("ff03ff00"),
            Some(vec![0u8, 3, 0xff]),
            "a bucket list must come back sorted and deduplicated"
        );
        assert_eq!(parse_bucket_query(""), Some(Vec::new()));
    }

    #[test]
    fn a_malformed_bucket_list_is_rejected() {
        // An odd number of digits would silently drop or shift a bucket.
        assert_eq!(parse_bucket_query("0"), None);
        assert_eq!(parse_bucket_query("031"), None);
        assert_eq!(parse_bucket_query("zz"), None);
        // Multi-byte characters, which are not two hex digits however they chunk.
        assert_eq!(parse_bucket_query("é"), None);
    }

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
    fn default_calendar_id_is_stable() {
        assert_eq!(
            DEFAULT_CALENDAR_ID.to_string(),
            "00000000-0000-0000-0000-000000000003"
        );
    }

    #[test]
    fn account_settings_id_is_stable() {
        assert_eq!(
            ACCOUNT_SETTINGS_ID.to_string(),
            "00000000-0000-0000-0000-000000000004"
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
