use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sealbook_core::{
    AppliedManifest, AttachmentLimits, AttachmentPlan, AttachmentRow, AuthRequest,
    BucketedManifest, BucketsOutcome, ChangesPage, ChunkRange, CoreAccountImport,
    CoreAccountSettings, CoreAccountSettingsDraft, CoreAddressBook, CoreAddressBookDraft,
    CoreBookmark, CoreBookmarkCollection, CoreBookmarkCollectionDraft, CoreBookmarkDraft,
    CoreBuild, CoreCalendar, CoreCalendarDraft, CoreCalendarEvent, CoreCalendarEventDraft,
    CoreContact, CoreContactDraft, CoreContactImport, CoreContactProfile, CoreDevice,
    CoreDeviceSecrets, CoreDeviceState, CoreExportAccount, CoreExportObject, CoreIcsExportEvent,
    CoreIcsImport, CoreManifestEntry, CoreNote, CoreNoteDraft, CoreNotebook, CorePairPreview,
    CoreRecurrence, CoreRoster, CoreRosterPin, CoreSealedRow, CoreSession, CoreTask, CoreTaskDraft,
    CoreTaskList, CoreTaskListDraft, HttpRequest, HttpResponse, LoggedIn, LoginStarting,
    ManifestContext, ManifestOutcome, ManifestPlan, ManifestSigner, OpaqueStart, PairApproval,
    PairJoined, PairPoll, PairStatus, PasswordChange, PasswordChangeStarted, RecoverStarted,
    Recovering, RegisterIdentity, Registering, ResealRow, RosterContext, RotationPlan,
    RotationState, RowOutcome, RowRef, SignedManifest, SweepCursor, SweepPage, VerifiedRoster,
    WalkCursor, WalkStep,
};
use sealbook_crypto::RosterPin;
use sealbook_crypto::{
    content_digest, decrypt_object, encrypt_object, enrollment_transcript, generate_device_hpke,
    generate_device_signing, generate_kdf_salt, generate_phrase, key_rotation_transcript,
    key_wraps_digest, manifest_bucket_digest, manifest_bucket_of, manifest_digest,
    manifest_transcript, object_aad, pair_confirmation, phrase_lookup_id, phrase_recovery_public,
    rotated_objects_digest, rotation_recovery_payload, sign, unwrap_collection_key,
    unwrap_for_device, wrap_collection_key, wrap_for_device, wrap_for_phrase, CollectionKey,
    DeviceHpkePublic, DeviceHpkeSecret, DeviceHpkeWrap, DeviceSigningSecrets, EncryptedObject,
    ManifestDigestEntry, ObjectDigestEntry, RecoveryWrap, WrapDigestEntry, MANIFEST_BUCKETS,
    PHRASE_CIPHERSUITE, PHRASE_SCHEME, RECOVERY_CIPHERSUITE, XWING_CIPHERSUITE,
};
use sealbook_protocol::envelope::{open_envelope, seal_envelope, Unsealed};
use sealbook_protocol::{DevicePublicKeys, RosterBody, RosterSignerBody, SEALED_CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use tsify::{Ts, Tsify};
use uuid::Uuid;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(s: &str) -> Result<Vec<u8>, JsError> {
    URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|err| JsError::new(&err.to_string()))
}

fn js_err(err: impl std::fmt::Display) -> JsError {
    JsError::new(&err.to_string())
}

fn parse_uuid(s: &str) -> Result<Uuid, JsError> {
    Uuid::parse_str(s).map_err(|err| JsError::new(&err.to_string()))
}

fn ck_from_b64(s: &str) -> Result<CollectionKey, JsError> {
    let bytes = unb64(s)?;
    if bytes.len() != 32 {
        return Err(JsError::new("collection key length"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(CollectionKey::from_bytes(key))
}

#[derive(Serialize)]
struct Enrollment {
    device_id: String,
    hpke_sk: String,
    hpke_pk: String,
    mldsa_seed: String,
    mldsa_pk: String,
    ed25519_sk: String,
    ed25519_pk: String,
    kdf_salt: String,
    collection_key: String,
    enrollment_mldsa: String,
    enrollment_ed25519: String,
    device_enc: String,
    device_wrapped_ck: String,
    recovery_nonce: String,
    recovery_wrapped_ck: String,
    phrase: String,
    phrase_nonce: String,
    phrase_wrapped_ck: String,
    phrase_mldsa_pk: String,
    phrase_ed25519_pk: String,
    phrase_lookup_id: String,
    phrase_scheme: &'static str,
    phrase_ciphersuite: &'static str,
    xwing_ciphersuite: &'static str,
    recovery_ciphersuite: &'static str,
}

#[derive(Deserialize)]
struct WrapIn {
    recipient_kind: String,
    recipient_id: String,
    hpke_enc: String,
    wrapped_ck: String,
    ciphersuite: String,
}

/// Everything a registration used to mint, kept for the web's own test shim:
/// `client.test.ts` stands in for the server and needs an account's starting
/// material without a round trip. Production registers through
/// `core_new_registration`.
#[wasm_bindgen]
pub fn create_enrollment(password: &str) -> Result<String, JsError> {
    let (hpke_sk, hpke_pk) = generate_device_hpke().map_err(js_err)?;
    let (sign_sk, sign_pk) = generate_device_signing().map_err(js_err)?;
    let ck = CollectionKey::generate();
    let salt = generate_kdf_salt();
    let recovery = wrap_collection_key(password.as_bytes(), &salt, &ck).map_err(js_err)?;
    let (phrase, phrase_entropy) = generate_phrase().map_err(js_err)?;
    let phrase_wrap = wrap_for_phrase(&phrase_entropy, &ck).map_err(js_err)?;
    let device_wrap = wrap_for_device(&hpke_pk, &ck).map_err(js_err)?;
    let device_id = Uuid::new_v4();
    let transcript = enrollment_transcript(
        device_id,
        &sign_pk.mldsa_pk,
        &sign_pk.ed25519_pk,
        &hpke_pk.0,
    );
    let sig = sign(&sign_sk, &transcript).map_err(js_err)?;
    let phrase_recovery = phrase_recovery_public(&phrase_entropy).map_err(js_err)?;
    serde_json::to_string(&Enrollment {
        device_id: device_id.to_string(),
        hpke_sk: b64(hpke_sk.as_bytes()),
        hpke_pk: b64(&hpke_pk.0),
        mldsa_seed: b64(&sign_sk.mldsa_seed),
        mldsa_pk: b64(&sign_pk.mldsa_pk),
        ed25519_sk: b64(&sign_sk.ed25519_sk),
        ed25519_pk: b64(&sign_pk.ed25519_pk),
        kdf_salt: b64(&salt),
        collection_key: b64(ck.as_bytes()),
        enrollment_mldsa: b64(&sig.mldsa),
        enrollment_ed25519: b64(&sig.ed25519),
        device_enc: b64(&device_wrap.enc),
        device_wrapped_ck: b64(&device_wrap.ciphertext),
        recovery_nonce: b64(&recovery.nonce),
        recovery_wrapped_ck: b64(&recovery.ciphertext),
        phrase,
        phrase_nonce: b64(&phrase_wrap.nonce),
        phrase_wrapped_ck: b64(&phrase_wrap.ciphertext),
        phrase_mldsa_pk: b64(&phrase_recovery.mldsa_pk),
        phrase_ed25519_pk: b64(&phrase_recovery.ed25519_pk),
        phrase_lookup_id: b64(&phrase_lookup_id(&phrase_entropy).map_err(js_err)?),
        phrase_scheme: PHRASE_SCHEME,
        phrase_ciphersuite: PHRASE_CIPHERSUITE,
        xwing_ciphersuite: XWING_CIPHERSUITE,
        recovery_ciphersuite: RECOVERY_CIPHERSUITE,
    })
    .map_err(js_err)
}

#[wasm_bindgen]
pub fn unwrap_ck(
    password: &str,
    kdf_salt_b64: &str,
    hpke_sk_b64: &str,
    device_id: &str,
    wraps_json: &str,
) -> Result<String, JsError> {
    let wraps: Vec<WrapIn> = serde_json::from_str(wraps_json).map_err(js_err)?;
    if let Some(device) = wraps
        .iter()
        .find(|w| w.recipient_kind == "device" && w.recipient_id == device_id)
    {
        let key = unwrap_for_device(
            &DeviceHpkeSecret::from_bytes(unb64(hpke_sk_b64)?),
            &DeviceHpkeWrap {
                enc: unb64(&device.hpke_enc)?,
                ciphertext: unb64(&device.wrapped_ck)?,
                ciphersuite: XWING_CIPHERSUITE,
            },
        )
        .map_err(js_err)?;
        return Ok(b64(key.as_bytes()));
    }
    if let Some(recovery) = wraps.iter().find(|w| w.recipient_kind == "recovery") {
        let nonce_bytes = unb64(&recovery.hpke_enc)?;
        if nonce_bytes.len() != 24 {
            return Err(JsError::new("recovery nonce length"));
        }
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&nonce_bytes);
        let key = unwrap_collection_key(
            password.as_bytes(),
            &unb64(kdf_salt_b64)?,
            &RecoveryWrap {
                nonce,
                ciphertext: unb64(&recovery.wrapped_ck)?,
                ciphersuite: recovery.ciphersuite.clone(),
            },
        )
        .map_err(js_err)?;
        return Ok(b64(key.as_bytes()));
    }
    Err(JsError::new("no collection key wrap"))
}

#[derive(Serialize)]
struct EncryptedOut {
    nonce: String,
    ciphertext: String,
    padded_size: usize,
}

#[wasm_bindgen]
pub fn encrypt_contact(
    ck_b64: &str,
    object_id: &str,
    collection_id: &str,
    plaintext: &str,
) -> Result<String, JsError> {
    let object_id = parse_uuid(object_id)?;
    let collection_id = parse_uuid(collection_id)?;
    let aad = object_aad(object_id.as_bytes(), collection_id.as_bytes());
    let enc = encrypt_object(&ck_from_b64(ck_b64)?, plaintext.as_bytes(), &aad).map_err(js_err)?;
    serde_json::to_string(&EncryptedOut {
        nonce: b64(&enc.nonce),
        ciphertext: b64(&enc.ciphertext),
        padded_size: enc.padded_size,
    })
    .map_err(js_err)
}

#[wasm_bindgen]
pub fn decrypt_contact(
    ck_b64: &str,
    object_id: &str,
    collection_id: &str,
    nonce_b64: &str,
    ciphertext_b64: &str,
    padded_size: usize,
) -> Result<String, JsError> {
    text(decrypt_contact_bytes(
        ck_b64,
        object_id,
        collection_id,
        nonce_b64,
        ciphertext_b64,
        padded_size,
    )?)
}

fn decrypt_contact_bytes(
    ck_b64: &str,
    object_id: &str,
    collection_id: &str,
    nonce_b64: &str,
    ciphertext_b64: &str,
    padded_size: usize,
) -> Result<Vec<u8>, JsError> {
    let object_id = parse_uuid(object_id)?;
    let collection_id = parse_uuid(collection_id)?;
    let nonce_bytes = unb64(nonce_b64)?;
    if nonce_bytes.len() != 24 {
        return Err(JsError::new("nonce length"));
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&nonce_bytes);
    let aad = object_aad(object_id.as_bytes(), collection_id.as_bytes());
    let plain = decrypt_object(
        &ck_from_b64(ck_b64)?,
        &EncryptedObject {
            nonce,
            ciphertext: unb64(ciphertext_b64)?,
            padded_size,
        },
        &aad,
    )
    .map_err(js_err)?;
    Ok(plain)
}

#[wasm_bindgen]
pub fn sealed_content_type() -> String {
    SEALED_CONTENT_TYPE.to_string()
}

/// The protocol generation and payload schema this build speaks.
///
/// Exported so `sealbook-web` can check its own copies of these strings against
/// the Rust ones in a test, rather than the two drifting unnoticed.
#[wasm_bindgen]
pub fn protocol_version() -> String {
    sealbook_protocol::PROTOCOL_VERSION.to_string()
}

#[wasm_bindgen]
pub fn payload_schema_version() -> String {
    sealbook_protocol::PAYLOAD_SCHEMA_VERSION.to_string()
}

#[derive(Serialize)]
struct OpenedOut {
    #[serde(rename = "contentType")]
    content_type: String,
    tombstone: bool,
    payload: String,
}

#[wasm_bindgen]
pub fn seal_object(
    ck_b64: &str,
    object_id: &str,
    collection_id: &str,
    content_type: &str,
    payload: &str,
) -> Result<String, JsError> {
    let object_id = parse_uuid(object_id)?;
    let collection_id = parse_uuid(collection_id)?;
    let aad = object_aad(object_id.as_bytes(), collection_id.as_bytes());
    let plain = seal_envelope(content_type, payload.as_bytes());
    let enc = encrypt_object(&ck_from_b64(ck_b64)?, &plain, &aad).map_err(js_err)?;
    serde_json::to_string(&EncryptedOut {
        nonce: b64(&enc.nonce),
        ciphertext: b64(&enc.ciphertext),
        padded_size: enc.padded_size,
    })
    .map_err(js_err)
}

/// Decrypts an object and opens its envelope.
#[wasm_bindgen]
pub fn open_object(
    ck_b64: &str,
    object_id: &str,
    collection_id: &str,
    nonce_b64: &str,
    ciphertext_b64: &str,
    padded_size: usize,
) -> Result<String, JsError> {
    let plain = decrypt_contact_bytes(
        ck_b64,
        object_id,
        collection_id,
        nonce_b64,
        ciphertext_b64,
        padded_size,
    )?;
    let opened = match open_envelope(&plain) {
        Unsealed::Envelope {
            content_type,
            tombstone,
            payload,
        } => OpenedOut {
            content_type,
            tombstone,
            payload: text(payload)?,
        },
        Unsealed::Unreadable => {
            return Err(JsError::new(
                "object has an envelope this build cannot read",
            ))
        }
    };
    serde_json::to_string(&opened).map_err(js_err)
}

fn text(bytes: Vec<u8>) -> Result<String, JsError> {
    String::from_utf8(bytes).map_err(|_| JsError::new("object payload is not valid UTF-8"))
}

/// A fresh random collection key, for rotating the vault on device revocation.
#[wasm_bindgen]
pub fn new_collection_key() -> String {
    b64(CollectionKey::generate().as_bytes())
}

#[wasm_bindgen]
pub fn new_uuid() -> String {
    Uuid::new_v4().to_string()
}

#[derive(Serialize)]
struct DeviceOut {
    device_id: String,
    hpke_sk: String,
    hpke_pk: String,
    mldsa_seed: String,
    mldsa_pk: String,
    ed25519_sk: String,
    ed25519_pk: String,
    enrollment_mldsa: String,
    enrollment_ed25519: String,
}

#[wasm_bindgen]
pub fn create_device() -> Result<String, JsError> {
    let (hpke_sk, hpke_pk) = generate_device_hpke().map_err(js_err)?;
    let (sign_sk, sign_pk) = generate_device_signing().map_err(js_err)?;
    let device_id = Uuid::new_v4();
    let transcript = enrollment_transcript(
        device_id,
        &sign_pk.mldsa_pk,
        &sign_pk.ed25519_pk,
        &hpke_pk.0,
    );
    let sig = sign(&sign_sk, &transcript).map_err(js_err)?;
    serde_json::to_string(&DeviceOut {
        device_id: device_id.to_string(),
        hpke_sk: b64(hpke_sk.as_bytes()),
        hpke_pk: b64(&hpke_pk.0),
        mldsa_seed: b64(&sign_sk.mldsa_seed),
        mldsa_pk: b64(&sign_pk.mldsa_pk),
        ed25519_sk: b64(&sign_sk.ed25519_sk),
        ed25519_pk: b64(&sign_pk.ed25519_pk),
        enrollment_mldsa: b64(&sig.mldsa),
        enrollment_ed25519: b64(&sig.ed25519),
    })
    .map_err(js_err)
}

#[wasm_bindgen]
pub fn wrap_ck_for_device(ck_b64: &str, hpke_pk_b64: &str) -> Result<String, JsError> {
    let wrap = wrap_for_device(
        &DeviceHpkePublic(unb64(hpke_pk_b64)?),
        &ck_from_b64(ck_b64)?,
    )
    .map_err(js_err)?;
    serde_json::to_string(&serde_json::json!({
        "enc": b64(&wrap.enc),
        "wrapped_ck": b64(&wrap.ciphertext),
        "ciphersuite": XWING_CIPHERSUITE,
    }))
    .map_err(js_err)
}

/// The pairing code both screens show.
///
/// Kept for the tests that stand in for the server, which computes the same
/// code; the client takes its own from core's pairing decisions.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn pair_confirmation_code(
    pair_id: &str,
    device_id: &str,
    mldsa_pk_b64: &str,
    ed25519_pk_b64: &str,
    hpke_pk_b64: &str,
    roster_seq: u64,
    roster_transcript_b64: &str,
) -> Result<String, JsError> {
    Ok(pair_confirmation(
        parse_uuid(pair_id)?,
        parse_uuid(device_id)?,
        &unb64(mldsa_pk_b64)?,
        &unb64(ed25519_pk_b64)?,
        &unb64(hpke_pk_b64)?,
        roster_seq,
        &digest32(roster_transcript_b64)?,
    ))
}

#[derive(Deserialize)]
struct RotationWrapIn {
    recipient_kind: String,
    recipient_id: String,
    hpke_enc: String,
    wrapped_ck: String,
    ciphersuite: String,
}

#[derive(Deserialize)]
struct RotationObjectIn {
    id: String,
    revision: u64,
    nonce: String,
    ciphertext: String,
    padded_size: u64,
    content_type: String,
    tombstone: bool,
}

/// The account-level recovery material a rotation installs, as the signature
/// covers it.
#[derive(Serialize, Deserialize)]
struct RotationRecoveryIn {
    kdf_salt: String,
    phrase_mldsa_pk: String,
    phrase_ed25519_pk: String,
    phrase_lookup_id: String,
    phrase_scheme: String,
}

/// Signs a collection-key rotation.
///
/// The canonical, length-prefixed digests are computed here rather than in
/// JavaScript, so the browser cannot get the framing subtly wrong and produce a
/// signature the server will reject (or, worse, one that does not actually bind
/// what was sent). `wraps_json` and `objects_json` must be in the exact order
/// they will be sent to the server.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn rotation_sign(
    mldsa_seed_b64: &str,
    ed25519_sk_b64: &str,
    collection_id: &str,
    // `revoked_device_id` may be an empty string, to rotate without revoking a
    // device — which is how a phrase change and a completed recovery rotate.
    revoked_device_id: &str,
    key_epoch: u64,
    wraps_json: &str,
    objects_json: &str,
    manifest_digest_b64: &str,
    // The KDF salt and phrase record this rotation installs, as
    // `{"kdf_salt","phrase_mldsa_pk","phrase_ed25519_pk","phrase_lookup_id","phrase_scheme"}`
    // — base64url for the four byte fields. Signed so that a modified request
    // body cannot swap in recovery material the account holder never produced.
    recovery_json: &str,
) -> Result<String, JsError> {
    let recovery: RotationRecoveryIn = serde_json::from_str(recovery_json).map_err(js_err)?;
    let wraps: Vec<RotationWrapIn> = serde_json::from_str(wraps_json).map_err(js_err)?;
    let objects: Vec<RotationObjectIn> = serde_json::from_str(objects_json).map_err(js_err)?;

    let wrap_bytes = wraps
        .iter()
        .map(|wrap| Ok((unb64(&wrap.hpke_enc)?, unb64(&wrap.wrapped_ck)?)))
        .collect::<Result<Vec<_>, JsError>>()?;
    let wrap_entries: Vec<WrapDigestEntry<'_>> = wraps
        .iter()
        .zip(wrap_bytes.iter())
        .map(|(wrap, (enc, ct))| WrapDigestEntry {
            recipient_kind: &wrap.recipient_kind,
            recipient_id: &wrap.recipient_id,
            hpke_enc: enc,
            wrapped_ck: ct,
            ciphersuite: &wrap.ciphersuite,
        })
        .collect();

    let object_bytes = objects
        .iter()
        .map(|object| {
            Ok((
                parse_uuid(&object.id)?,
                unb64(&object.nonce)?,
                unb64(&object.ciphertext)?,
            ))
        })
        .collect::<Result<Vec<_>, JsError>>()?;
    let object_entries: Vec<ObjectDigestEntry<'_>> = objects
        .iter()
        .zip(object_bytes.iter())
        .map(|(object, (id, nonce, ciphertext))| ObjectDigestEntry {
            id: *id,
            revision: object.revision,
            nonce,
            ciphertext,
            padded_size: object.padded_size,
            content_type: &object.content_type,
            tombstone: object.tombstone,
        })
        .collect();

    let revoked = if revoked_device_id.trim().is_empty() {
        None
    } else {
        Some(parse_uuid(revoked_device_id)?)
    };
    let transcript = key_rotation_transcript(
        parse_uuid(collection_id)?,
        revoked,
        key_epoch,
        &key_wraps_digest(&wrap_entries),
        &rotated_objects_digest(&object_entries),
        &digest32(manifest_digest_b64)?,
        &rotation_recovery_payload(
            &unb64(&recovery.kdf_salt)?,
            &unb64(&recovery.phrase_mldsa_pk)?,
            &unb64(&recovery.phrase_ed25519_pk)?,
            &unb64(&recovery.phrase_lookup_id)?,
            &recovery.phrase_scheme,
        ),
    );
    let secrets = DeviceSigningSecrets {
        mldsa_seed: unb64(mldsa_seed_b64)?,
        ed25519_sk: unb64(ed25519_sk_b64)?,
    };
    let sig = sign(&secrets, &transcript).map_err(js_err)?;
    serde_json::to_string(&serde_json::json!({
        "mldsa": b64(&sig.mldsa),
        "ed25519": b64(&sig.ed25519),
    }))
    .map_err(js_err)
}

fn digest32(b64_value: &str) -> Result<[u8; 32], JsError> {
    let bytes = unb64(b64_value)?;
    if bytes.len() != 32 {
        return Err(JsError::new("digest must be 32 bytes"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[derive(Serialize, Deserialize)]
struct ManifestEntryIn {
    id: String,
    revision: u64,
    tombstone: bool,
    content_digest: String,
}

fn manifest_entries(entries_json: &str) -> Result<Vec<ManifestDigestEntry>, JsError> {
    let entries: Vec<ManifestEntryIn> = serde_json::from_str(entries_json).map_err(js_err)?;
    entries
        .into_iter()
        .map(|entry| {
            Ok(ManifestDigestEntry {
                id: parse_uuid(&entry.id)?,
                revision: entry.revision,
                tombstone: entry.tombstone,
                content_digest: digest32(&entry.content_digest)?,
            })
        })
        .collect()
}

/// `SHA-256(nonce || ciphertext)`, the per-object commitment inside a manifest.
#[wasm_bindgen]
pub fn object_content_digest(nonce_b64: &str, ciphertext_b64: &str) -> Result<String, JsError> {
    Ok(b64(&content_digest(
        &unb64(nonce_b64)?,
        &unb64(ciphertext_b64)?,
    )))
}

/// Digest of a whole collection, for a manifest.
///
/// Computed here rather than in JavaScript so the canonical ordering and the
/// length-prefixed framing cannot drift from what the server does.
#[wasm_bindgen]
pub fn manifest_digest_of(entries_json: &str) -> Result<String, JsError> {
    Ok(b64(&manifest_digest(&manifest_entries(entries_json)?)))
}

/// Signs a manifest for the state a write produces.
///
/// Returns the manifest body to send, digest included, so the caller cannot sign
/// one thing and send another.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn manifest_sign(
    mldsa_seed_b64: &str,
    ed25519_sk_b64: &str,
    collection_id: &str,
    device_id: &str,
    manifest_seq: u64,
    key_epoch: u64,
    latest_revision: u64,
    entries_json: &str,
) -> Result<String, JsError> {
    let entries = manifest_entries(entries_json)?;
    let digest = manifest_digest(&entries);
    let transcript = manifest_transcript(
        parse_uuid(collection_id)?,
        manifest_seq,
        key_epoch,
        latest_revision,
        entries.len() as u64,
        &digest,
    );
    let secrets = DeviceSigningSecrets {
        mldsa_seed: unb64(mldsa_seed_b64)?,
        ed25519_sk: unb64(ed25519_sk_b64)?,
    };
    let sig = sign(&secrets, &transcript).map_err(js_err)?;
    serde_json::to_string(&serde_json::json!({
        "manifest_seq": manifest_seq,
        "key_epoch": key_epoch,
        "latest_revision": latest_revision,
        "object_count": entries.len(),
        "digest": b64(&digest),
        "device_id": device_id,
        "signature": { "mldsa": b64(&sig.mldsa), "ed25519": b64(&sig.ed25519) },
    }))
    .map_err(js_err)
}

/// The manifest bucket an object id falls in.
///
/// A write touches one bucket per object, so this is what decides which buckets
/// a write has to fetch.
#[wasm_bindgen]
pub fn manifest_bucket_of_id(id: &str) -> Result<u8, JsError> {
    Ok(manifest_bucket_of(parse_uuid(id)?))
}

/// One bucket's digest, or all zeroes for an empty bucket, matching how the root
/// is built.
fn bucket_digest(entries: &[ManifestDigestEntry]) -> [u8; 32] {
    if entries.is_empty() {
        return [0u8; 32];
    }
    manifest_bucket_digest(entries)
}

/// The 256 bucket digests of a whole entry set, concatenated.
///
/// What the server derives from its own rows, in the shape the bucketed manifest
/// endpoint serves. Computed here so the per-bucket framing cannot drift from
/// what the root is built over.
#[wasm_bindgen]
pub fn manifest_buckets_blob(entries_json: &str) -> Result<String, JsError> {
    let entries = manifest_entries(entries_json)?;
    let mut blob = Vec::with_capacity(MANIFEST_BUCKETS * 32);
    for bucket in 0..MANIFEST_BUCKETS {
        let bucket = bucket as u8;
        let members: Vec<ManifestDigestEntry> = entries
            .iter()
            .filter(|entry| manifest_bucket_of(entry.id) == bucket)
            .cloned()
            .collect();
        blob.extend_from_slice(&bucket_digest(&members));
    }
    Ok(b64(&blob))
}

fn pin_from(seq: u64, transcript_b64: &str) -> Result<Option<RosterPin>, JsError> {
    if seq == 0 {
        return Ok(None);
    }
    Ok(Some(RosterPin {
        roster_seq: seq,
        transcript: digest32(transcript_b64)?,
    }))
}

fn devices_from(devices_json: &str) -> Result<Vec<DevicePublicKeys>, JsError> {
    serde_json::from_str(devices_json).map_err(js_err)
}

/// Signs a device roster with this device's keys and MACs it under `ck`.
///
/// `devices_json` is the full device list in wire format. Returns the roster to
/// send with a registration, pairing approval or rotation.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn roster_seal_device(
    collection_id: &str,
    roster_seq: u64,
    key_epoch: u64,
    devices_json: &str,
    phrase_mldsa_pk_b64: &str,
    phrase_ed25519_pk_b64: &str,
    signer_device_id: &str,
    mldsa_seed_b64: &str,
    ed25519_sk_b64: &str,
    ck_b64: &str,
) -> Result<String, JsError> {
    let roster = RosterBody::seal(
        parse_uuid(collection_id)?,
        roster_seq,
        key_epoch,
        devices_from(devices_json)?,
        unb64(phrase_mldsa_pk_b64)?,
        unb64(phrase_ed25519_pk_b64)?,
        RosterSignerBody::Device {
            device_id: parse_uuid(signer_device_id)?,
        },
        &DeviceSigningSecrets {
            mldsa_seed: unb64(mldsa_seed_b64)?,
            ed25519_sk: unb64(ed25519_sk_b64)?,
        },
        &ck_from_b64(ck_b64)?,
    )
    .map_err(js_err)?;
    serde_json::to_string(&roster).map_err(js_err)
}

/// Verifies a served roster history from this device's pin.
///
/// `pin_seq` 0 means nothing is pinned yet, in which case `ck_b64` and
/// `key_epoch` must be the current collection key and its epoch. Throws on any
/// failure. Returns `{ roster, pin_seq, pin_transcript }`: the verified roster,
/// whose devices are the only ones to wrap for or accept signatures from, and the
/// pin to store in place of the old one.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn roster_verify(
    collection_id: &str,
    pin_seq: u64,
    pin_transcript_b64: &str,
    rosters_json: &str,
    ck_b64: &str,
    key_epoch: u64,
    self_device_id: &str,
) -> Result<String, JsError> {
    let collection = parse_uuid(collection_id)?;
    let chain: Vec<RosterBody> = serde_json::from_str(rosters_json).map_err(js_err)?;
    let key = if ck_b64.is_empty() {
        None
    } else {
        Some(ck_from_b64(ck_b64)?)
    };
    let latest = RosterBody::verify_chain(
        collection,
        pin_from(pin_seq, pin_transcript_b64)?,
        chain,
        key.as_ref().map(|key| (key, key_epoch)),
        parse_uuid(self_device_id)?,
    )
    .map_err(js_err)?;
    let pin = latest.pin(collection);
    serde_json::to_string(&serde_json::json!({
        "roster": latest,
        "pin_seq": pin.roster_seq,
        "pin_transcript": b64(&pin.transcript),
    }))
    .map_err(js_err)
}

// ── Core ──

/// The `sealbook-core` build this module was compiled against.
///
/// `scripts/build-wasm.sh` pins the checkout; this is what lets the running app
/// check that the module it loaded speaks the generation it expects.
#[wasm_bindgen]
pub fn core_build() -> Result<Ts<CoreBuild>, JsError> {
    Ok(sealbook_core::core_build().into_ts()?)
}

/// Core's errors cross as their serialized form rather than as a sentence, so
/// the host maps a variant onto its own error class instead of matching text.
fn core_err(err: sealbook_core::CoreError) -> JsError {
    JsError::new(&serde_json::to_string(&err).unwrap_or_else(|_| err.kind().to_owned()))
}

/// The request that fetches the roster history this device can check.
///
/// `path` is server-relative: the caller prefixes its own API root and adds the
/// bearer token, which core never sees.
#[wasm_bindgen]
pub fn core_roster_request(context: Ts<RosterContext>) -> Result<Ts<HttpRequest>, JsError> {
    Ok(sealbook_core::roster_request(&context.to_rust()?)
        .map_err(core_err)?
        .into_ts()?)
}

/// Verifies a served roster history from this device's pin.
///
/// The body crosses as the text the server sent rather than as bytes, because
/// `Vec<u8>` crosses as `number[]` and a roster history is tens of kilobytes.
/// `ck_b64` empty means no collection key is held, which only an already pinned
/// device can verify from. Does not move the pin; `core_pin_roster` does.
#[wasm_bindgen]
pub fn core_roster_accept(
    context: Ts<RosterContext>,
    ck_b64: &str,
    key_epoch: u64,
    status: u16,
    body: &str,
) -> Result<Ts<VerifiedRoster>, JsError> {
    let response = HttpResponse {
        status,
        headers: Vec::new(),
        body: body.as_bytes().to_vec(),
    };
    Ok(sealbook_core::roster_accept(
        &context.to_rust()?,
        &core_session(ck_b64, key_epoch)?,
        &response,
    )
    .map_err(core_err)?
    .into_ts()?)
}

/// Verifies a roster this device sealed itself, once the server has accepted it.
#[wasm_bindgen]
pub fn core_roster_accept_sealed(
    context: Ts<RosterContext>,
    ck_b64: &str,
    roster_json: &str,
) -> Result<Ts<VerifiedRoster>, JsError> {
    Ok(sealbook_core::roster_accept_sealed(
        &context.to_rust()?,
        &core_session(ck_b64, 0)?,
        roster_json,
    )
    .map_err(core_err)?
    .into_ts()?)
}

/// The roster fields to persist, refusing a pin that would move backwards.
#[wasm_bindgen]
pub fn core_pin_roster(
    context: Ts<RosterContext>,
    pin: Ts<CoreRosterPin>,
) -> Result<Ts<RosterContext>, JsError> {
    Ok(
        sealbook_core::pin_roster(&context.to_rust()?, &pin.to_rust()?)
            .map_err(core_err)?
            .into_ts()?,
    )
}

/// Whether a roster already in hand can answer for `signer`, or the chain has
/// to be walked again.
#[wasm_bindgen]
pub fn core_roster_answers_for(
    cached: Ts<CoreRoster>,
    key_epoch: Option<u64>,
    signer: Option<String>,
) -> Result<bool, JsError> {
    let signer = signer.as_deref().map(parse_uuid).transpose()?;
    Ok(sealbook_core::roster_answers_for(
        Some(&cached.to_rust()?),
        key_epoch,
        signer,
    ))
}

// ── Core: manifest ──

/// Lists on the boundary.
///
/// `Ts<T>` is defined for a type that derives `Tsify` and tsify has no impl for
/// `Vec<T>`, so each list these functions take gets a transparent newtype whose
/// TypeScript declaration is just the array. The quirk is the binding's, so the
/// wrappers live here rather than in core.
#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[serde(transparent)]
pub struct CoreDeviceList(pub Vec<CoreDevice>);

#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[serde(transparent)]
pub struct CoreManifestEntryList(pub Vec<CoreManifestEntry>);

/// The request that fetches the manifest with every entry it commits to.
#[wasm_bindgen]
pub fn core_manifest_request(context: Ts<ManifestContext>) -> Result<Ts<HttpRequest>, JsError> {
    Ok(sealbook_core::manifest_request(&context.to_rust()?).into_ts()?)
}

/// The request that fetches only the buckets these objects fall in.
#[wasm_bindgen]
pub fn core_manifest_buckets_request(
    context: Ts<ManifestContext>,
    ids: Vec<String>,
) -> Result<Ts<HttpRequest>, JsError> {
    let ids = ids
        .iter()
        .map(|id| parse_uuid(id))
        .collect::<Result<Vec<_>, JsError>>()?;
    Ok(sealbook_core::manifest_buckets_request(&context.to_rust()?, &ids).into_ts()?)
}

/// The epoch and device a served manifest must be checked against, or
/// `undefined` for a collection with no manifest.
///
/// Read before the roster is fetched, because the manifest is what says which
/// roster to fetch.
#[wasm_bindgen]
pub fn core_manifest_signer(body: &str) -> Result<Option<Ts<ManifestSigner>>, JsError> {
    match sealbook_core::manifest_signer(body.as_bytes()).map_err(core_err)? {
        Some(signer) => Ok(Some(signer.into_ts()?)),
        None => Ok(None),
    }
}

/// Checks a served manifest against the entry set it is supposed to describe.
///
/// As with the roster, the body crosses as the text the server sent: a whole
/// collection's entry set is far larger than a roster history.
#[wasm_bindgen]
pub fn core_manifest_accept(
    context: Ts<ManifestContext>,
    body: &str,
    devices: Ts<CoreDeviceList>,
) -> Result<Ts<ManifestOutcome>, JsError> {
    Ok(
        sealbook_core::manifest_accept(&context.to_rust()?, &core_ok(body), &devices.to_rust()?.0)
            .map_err(core_err)?
            .into_ts()?,
    )
}

/// Checks a bucketed manifest answer and returns what a write needs from it.
#[wasm_bindgen]
pub fn core_manifest_buckets_accept(
    context: Ts<ManifestContext>,
    ids: Vec<String>,
    body: &str,
    devices: Ts<CoreDeviceList>,
) -> Result<Ts<BucketsOutcome>, JsError> {
    let ids = ids
        .iter()
        .map(|id| parse_uuid(id))
        .collect::<Result<Vec<_>, JsError>>()?;
    Ok(sealbook_core::manifest_buckets_accept(
        &context.to_rust()?,
        &ids,
        &core_ok(body),
        &devices.to_rust()?.0,
    )
    .map_err(core_err)?
    .into_ts()?)
}

/// Checks a manifest served alongside pages of objects against the entry set
/// those pages produced.
#[wasm_bindgen]
pub fn core_manifest_verify(
    context: Ts<ManifestContext>,
    manifest_json: &str,
    entries: Ts<CoreManifestEntryList>,
    devices: Ts<CoreDeviceList>,
) -> Result<Ts<ManifestPlan>, JsError> {
    Ok(sealbook_core::manifest_verify(
        &context.to_rust()?,
        manifest_json,
        &entries.to_rust()?.0,
        &devices.to_rust()?.0,
    )
    .map_err(core_err)?
    .into_ts()?)
}

/// The rule for a server that served objects with no manifest at all.
#[wasm_bindgen]
pub fn core_manifest_absence_ok(context: Ts<ManifestContext>) -> Result<(), JsError> {
    sealbook_core::manifest_absence_ok(&context.to_rust()?).map_err(core_err)
}

/// The bucketed view of a collection whose every entry is in hand.
#[wasm_bindgen]
pub fn core_manifest_buckets_from_whole(
    plan: Ts<ManifestPlan>,
    entries: Ts<CoreManifestEntryList>,
) -> Result<Ts<BucketedManifest>, JsError> {
    Ok(
        sealbook_core::manifest_buckets_from_whole(&plan.to_rust()?, &entries.to_rust()?.0)
            .map_err(core_err)?
            .into_ts()?,
    )
}

/// Folds written entries in and returns what the next manifest must commit to.
#[wasm_bindgen]
pub fn core_manifest_apply(
    held: Ts<BucketedManifest>,
    written: Ts<CoreManifestEntryList>,
) -> Result<Ts<AppliedManifest>, JsError> {
    Ok(
        sealbook_core::manifest_apply(&held.to_rust()?, &written.to_rust()?.0)
            .map_err(core_err)?
            .into_ts()?,
    )
}

/// Signs a manifest over an entry set, for the caller that holds all of it.
#[wasm_bindgen]
pub fn core_manifest_sign(
    mldsa_seed_b64: &str,
    ed25519_sk_b64: &str,
    context: Ts<ManifestContext>,
    plan: Ts<ManifestPlan>,
    entries: Ts<CoreManifestEntryList>,
) -> Result<Ts<SignedManifest>, JsError> {
    Ok(sealbook_core::manifest_sign(
        &core_secrets(mldsa_seed_b64, ed25519_sk_b64)?,
        &context.to_rust()?,
        &plan.to_rust()?,
        &entries.to_rust()?.0,
    )
    .map_err(core_err)?
    .into_ts()?)
}

/// Signs a manifest over a root already derived from the bucket digests.
#[wasm_bindgen]
pub fn core_manifest_sign_root(
    mldsa_seed_b64: &str,
    ed25519_sk_b64: &str,
    context: Ts<ManifestContext>,
    plan: Ts<ManifestPlan>,
    applied: Ts<AppliedManifest>,
) -> Result<Ts<SignedManifest>, JsError> {
    Ok(sealbook_core::manifest_sign_root(
        &core_secrets(mldsa_seed_b64, ed25519_sk_b64)?,
        &context.to_rust()?,
        &plan.to_rust()?,
        &applied.to_rust()?,
    )
    .map_err(core_err)?
    .into_ts()?)
}

/// The manifest entry a sealed object produces.
#[wasm_bindgen]
pub fn core_manifest_entry_for(
    id: &str,
    revision: u64,
    tombstone: bool,
    nonce_b64: &str,
    ciphertext_b64: &str,
) -> Result<Ts<CoreManifestEntry>, JsError> {
    Ok(sealbook_core::manifest_entry_for(
        parse_uuid(id)?,
        revision,
        tombstone,
        nonce_b64,
        ciphertext_b64,
    )
    .map_err(core_err)?
    .into_ts()?)
}

/// The sequence to persist once a manifest has been verified.
#[wasm_bindgen]
pub fn core_accept_manifest_seq(current: u64, seq: u64) -> u64 {
    sealbook_core::accept_manifest_seq(current, seq)
}

fn core_secrets(
    mldsa_seed_b64: &str,
    ed25519_sk_b64: &str,
) -> Result<DeviceSigningSecrets, JsError> {
    Ok(DeviceSigningSecrets {
        mldsa_seed: unb64(mldsa_seed_b64)?,
        ed25519_sk: unb64(ed25519_sk_b64)?,
    })
}

/// The host's transport has already raised anything that is not a success, so
/// core only ever sees a response it is meant to read.
fn core_ok(body: &str) -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: Vec::new(),
        body: body.as_bytes().to_vec(),
    }
}

/// `roster_accept_sealed` reads the epoch off the roster, so the 0 passed here
/// is never the one the MAC is checked at.
fn core_session(ck_b64: &str, key_epoch: u64) -> Result<CoreSession, JsError> {
    let collection_key = if ck_b64.is_empty() {
        None
    } else {
        Some(ck_from_b64(ck_b64)?.0)
    };
    Ok(CoreSession {
        collection_key,
        key_epoch,
        verified_roster: None,
    })
}

// ── Core: the read path ──

#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[serde(transparent)]
pub struct RowRefList(pub Vec<RowRef>);

/// A walk that starts after `after`, or from nothing when that is 0.
#[wasm_bindgen]
pub fn core_walk_start(after: u64) -> Result<Ts<WalkCursor>, JsError> {
    Ok(sealbook_core::walk_start(after).into_ts()?)
}

/// The request for the next page of a walk.
///
/// `path` is server-relative: the caller prefixes its own API root and adds the
/// bearer token, which core never sees.
#[wasm_bindgen]
pub fn core_changes_request(
    collection_id: &str,
    cursor: Ts<WalkCursor>,
) -> Result<Ts<HttpRequest>, JsError> {
    Ok(sealbook_core::changes_request(parse_uuid(collection_id)?, &cursor.to_rust()?).into_ts()?)
}

/// What a walk reads out of a `/changes` response body.
#[wasm_bindgen]
pub fn core_changes_page_read(body: &str) -> Result<Ts<ChangesPage>, JsError> {
    Ok(sealbook_core::changes_page_read(body)
        .map_err(core_err)?
        .into_ts()?)
}

/// What the walk does with the page it was just served: another page, a restart
/// that drops the rows read so far, or the walk being complete.
#[wasm_bindgen]
pub fn core_walk_page(
    cursor: Ts<WalkCursor>,
    page: Ts<ChangesPage>,
) -> Result<Ts<WalkStep>, JsError> {
    Ok(
        sealbook_core::walk_page(&cursor.to_rust()?, &page.to_rust()?)
            .map_err(core_err)?
            .into_ts()?,
    )
}

/// The rows to keep out of a walk, as indices into the rows walked.
///
/// Indices rather than the rows, so a collection's ciphertexts do not cross
/// this boundary again to be deduplicated.
#[wasm_bindgen]
pub fn core_latest_revisions(rows: Ts<RowRefList>) -> Result<Vec<u32>, JsError> {
    Ok(sealbook_core::latest_revisions(&rows.to_rust()?.0))
}

/// Decrypts one served row and opens its envelope.
///
/// Only an unusable collection key throws: every other failure is one row's and
/// comes back as `Unreadable`, so one object this device cannot read does not
/// cost it the rest of the collection.
#[wasm_bindgen]
pub fn core_open_row(
    ck_b64: &str,
    collection_id: &str,
    row: Ts<CoreSealedRow>,
) -> Result<Ts<RowOutcome>, JsError> {
    Ok(
        sealbook_core::open_row(ck_b64, parse_uuid(collection_id)?, &row.to_rust()?)
            .map_err(core_err)?
            .into_ts()?,
    )
}

/// The rule for a collection key that moved while a read was in flight.
#[wasm_bindgen]
pub fn core_require_key_epoch(expected: u64, held: u64) -> Result<(), JsError> {
    sealbook_core::require_key_epoch(expected, held).map_err(core_err)
}

// ── Core: rotation ──

#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[serde(transparent)]
pub struct CoreSealedRowList(pub Vec<CoreSealedRow>);

/// What a rotation does with the collection it just read: which rows are
/// re-sealed and at which revision, which tombstones the manifest carries, and
/// which rows the rotation retires.
///
/// Throws on a live row this device cannot open, which no other read does: a
/// rotation re-encrypts each row from its plaintext, so counting one it cannot
/// read would drop the object from the collection for good.
#[wasm_bindgen]
pub fn core_rotation_plan(
    ck_b64: &str,
    collection_id: &str,
    state: Ts<RotationState>,
    rows: Ts<CoreSealedRowList>,
) -> Result<Ts<RotationPlan>, JsError> {
    Ok(sealbook_core::rotation_plan(
        ck_b64,
        parse_uuid(collection_id)?,
        &state.to_rust()?,
        &rows.to_rust()?.0,
    )
    .map_err(core_err)?
    .into_ts()?)
}

/// The new key wrapped for the recipients, the password and a fresh phrase, in
/// the order the rotation signature covers.
#[wasm_bindgen]
pub fn core_rotation_wraps(
    new_ck_b64: &str,
    recipients: Ts<CoreDeviceList>,
    username: &str,
    password: &str,
) -> Result<Ts<sealbook_core::CoreRotationWraps>, JsError> {
    Ok(
        sealbook_core::rotation_wraps(new_ck_b64, &recipients.to_rust()?.0, username, password)
            .map_err(core_err)?
            .into_ts()?,
    )
}

/// The devices a rotation re-wraps the new key for, from the verified roster.
#[wasm_bindgen]
pub fn core_rotation_recipients(
    self_device_id: &str,
    revoke_device_id: Option<String>,
    devices: Ts<CoreDeviceList>,
) -> Result<Ts<CoreDeviceList>, JsError> {
    let revoked = revoke_device_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .map(parse_uuid)
        .transpose()?;
    let remaining = sealbook_core::rotation_recipients(
        parse_uuid(self_device_id)?,
        revoked,
        &devices.to_rust()?.0,
    )
    .map_err(core_err)?;
    Ok(CoreDeviceList(remaining).into_ts()?)
}

/// One planned row re-sealed under the new key, at the revision the plan gave
/// it.
///
/// Sealed in here so the plaintext never becomes a JavaScript string: decoding
/// it as text would rewrite any payload that is not valid UTF-8, and a rotation
/// touches the whole collection at once.
#[wasm_bindgen]
pub fn core_reseal_row(
    old_ck_b64: &str,
    new_ck_b64: &str,
    collection_id: &str,
    row: Ts<ResealRow>,
) -> Result<Ts<CoreSealedRow>, JsError> {
    Ok(sealbook_core::reseal_row(
        old_ck_b64,
        new_ck_b64,
        parse_uuid(collection_id)?,
        &row.to_rust()?,
    )
    .map_err(core_err)?
    .into_ts()?)
}

/// The manifest entry set for a rotation, from its plan and the rows the caller
/// re-sealed.
#[wasm_bindgen]
pub fn core_rotation_entries(
    plan: Ts<RotationPlan>,
    resealed: Ts<CoreSealedRowList>,
) -> Result<Ts<CoreManifestEntryList>, JsError> {
    Ok(CoreManifestEntryList(
        sealbook_core::rotation_entries(&plan.to_rust()?, &resealed.to_rust()?.0)
            .map_err(core_err)?,
    )
    .into_ts()?)
}

// ── Core: pairing ──

/// The join request body, with the enrollment signature over the new keys.
#[wasm_bindgen]
pub fn core_pair_join_body(
    username: &str,
    device: Ts<CoreDevice>,
    mldsa_seed_b64: &str,
    ed25519_sk_b64: &str,
) -> Result<String, JsError> {
    sealbook_core::pair_join_body(
        username,
        &device.to_rust()?,
        &core_secrets(mldsa_seed_b64, ed25519_sk_b64)?,
    )
    .map_err(core_err)
}

/// Checks the join response and computes the code the joining device shows.
///
/// The code is this device's own, not the server's copy: a server that
/// substituted the keys could show the real code and keep the ones it swapped in.
#[wasm_bindgen]
pub fn core_pair_join_accept(
    device: Ts<CoreDevice>,
    body: &str,
) -> Result<Ts<PairJoined>, JsError> {
    Ok(sealbook_core::pair_join_accept(&device.to_rust()?, body)
        .map_err(core_err)?
        .into_ts()?)
}

/// Where a poll says the pairing has got to.
///
/// Takes the status code as well as the body, because an expired code is a 404
/// and not a status in the body.
#[wasm_bindgen]
pub fn core_pair_status(status: u16, body: &str) -> Result<Ts<PairStatus>, JsError> {
    Ok(sealbook_core::pair_status(status, body)
        .map_err(core_err)?
        .into_ts()?)
}

/// What a joining device does after a poll. `status` is absent when the request
/// got no answer.
#[wasm_bindgen]
pub fn core_pair_poll(status: Option<u16>, body: &str) -> Result<Ts<PairPoll>, JsError> {
    Ok(sealbook_core::pair_poll(status, body).into_ts()?)
}

/// The server-relative path that looks a pairing up, from a code as typed.
#[wasm_bindgen]
pub fn core_pair_path(pair_key: &str) -> String {
    sealbook_core::pair_path(pair_key)
}

/// The server-relative path an approval posts to.
#[wasm_bindgen]
pub fn core_pair_approve_path(pair_key: &str) -> String {
    sealbook_core::pair_approve_path(pair_key)
}

/// Reads a pairing request and checks everything that does not need the typed
/// code, against a roster this device verified from its own pin.
#[wasm_bindgen]
pub fn core_pair_preview(
    ck_b64: &str,
    key_epoch: u64,
    verified: Ts<VerifiedRoster>,
    body: &str,
) -> Result<Ts<CorePairPreview>, JsError> {
    Ok(sealbook_core::pair_preview(
        &core_session(ck_b64, key_epoch)?,
        &verified.to_rust()?,
        body,
    )
    .map_err(core_err)?
    .into_ts()?)
}

/// Approves a joining device: wraps the collection key for it, signs the grant,
/// and signs the roster step that adds it.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn core_pair_approve(
    mldsa_seed_b64: &str,
    ed25519_sk_b64: &str,
    context: Ts<RosterContext>,
    ck_b64: &str,
    key_epoch: u64,
    verified: Ts<VerifiedRoster>,
    preview: Ts<CorePairPreview>,
    typed: &str,
) -> Result<Ts<PairApproval>, JsError> {
    Ok(sealbook_core::pair_approve(
        &core_secrets(mldsa_seed_b64, ed25519_sk_b64)?,
        &context.to_rust()?,
        &core_session(ck_b64, key_epoch)?,
        &verified.to_rust()?,
        &preview.to_rust()?,
        typed,
    )
    .map_err(core_err)?
    .into_ts()?)
}

/// Strips spacing and case differences from a typed code.
#[wasm_bindgen]
pub fn core_normalize_confirmation(entered: &str) -> String {
    sealbook_core::normalize_confirmation(entered)
}

/// A code split into display groups.
#[wasm_bindgen]
pub fn core_confirmation_groups(code: &str) -> Vec<String> {
    sealbook_core::confirmation_groups(code)
}

/// A code grouped for display.
#[wasm_bindgen]
pub fn core_format_confirmation(code: &str) -> String {
    sealbook_core::format_confirmation(code)
}

// ── Core: auth and account operations ──

/// The username to send, which is the one the user typed without surrounding
/// whitespace. The server rejects a username with a space in it.
#[wasm_bindgen]
pub fn core_normalize_username(raw: &str) -> String {
    sealbook_core::normalize_username(raw)
}

/// The phrase to derive from: lowercase and single-spaced, because BIP-39 words
/// are lowercase and a pasted phrase often is not.
#[wasm_bindgen]
pub fn core_normalize_phrase(raw: &str) -> String {
    sealbook_core::normalize_phrase(raw)
}

/// Begins registering a password. Also the first round of a password change, a
/// username change and a recovery.
#[wasm_bindgen]
pub fn core_opaque_register_start(password: &str) -> Result<Ts<OpaqueStart>, JsError> {
    Ok(sealbook_core::opaque_register_start(password)
        .map_err(core_err)?
        .into_ts()?)
}

/// Finishes a registration, giving the verifier upload the server stores.
#[wasm_bindgen]
pub fn core_opaque_register_upload(
    state_b64: &str,
    password: &str,
    response_b64: &str,
) -> Result<String, JsError> {
    sealbook_core::opaque_register_upload(state_b64, password, response_b64).map_err(core_err)
}

/// Begins a login.
#[wasm_bindgen]
pub fn core_opaque_login_start(password: &str) -> Result<Ts<OpaqueStart>, JsError> {
    Ok(sealbook_core::opaque_login_start(password)
        .map_err(core_err)?
        .into_ts()?)
}

/// A new device's keys, for the host to persist.
#[wasm_bindgen]
pub fn core_new_device() -> Result<Ts<CoreDeviceSecrets>, JsError> {
    Ok(sealbook_core::new_device().map_err(core_err)?.into_ts()?)
}

/// Everything a registration mints: a device, a collection, a collection key, a
/// KDF salt and a recovery phrase.
#[wasm_bindgen]
pub fn core_new_registration() -> Result<Ts<RegisterIdentity>, JsError> {
    Ok(sealbook_core::new_registration()
        .map_err(core_err)?
        .into_ts()?)
}

#[wasm_bindgen]
pub fn core_register_start_request(
    username: &str,
    opaque_request_b64: &str,
) -> Result<Ts<AuthRequest>, JsError> {
    Ok(
        sealbook_core::register_start_request(username, opaque_request_b64)
            .map_err(core_err)?
            .into_ts()?,
    )
}

#[wasm_bindgen]
pub fn core_register_start_accept(body: &str) -> Result<String, JsError> {
    sealbook_core::register_start_accept(body).map_err(core_err)
}

/// The register finish request: the genesis roster, the first manifest and the
/// three wraps of the collection key, with the anchor to pin.
#[wasm_bindgen]
pub fn core_register_finish_request(
    username: &str,
    password: &str,
    upload_b64: &str,
    identity: Ts<RegisterIdentity>,
) -> Result<Ts<Registering>, JsError> {
    Ok(
        sealbook_core::register_finish_request(
            username,
            password,
            upload_b64,
            &identity.to_rust()?,
        )
        .map_err(core_err)?
        .into_ts()?,
    )
}

/// Reads the register finish response into the state this device persists.
#[wasm_bindgen]
pub fn core_register_accept(
    server: &str,
    username: &str,
    identity: Ts<RegisterIdentity>,
    pin: Ts<CoreRosterPin>,
    body: &str,
) -> Result<Ts<CoreDeviceState>, JsError> {
    Ok(sealbook_core::register_accept(
        server,
        username,
        &identity.to_rust()?,
        &pin.to_rust()?,
        body,
    )
    .map_err(core_err)?
    .into_ts()?)
}

#[wasm_bindgen]
pub fn core_login_challenge_request(
    username: &str,
    device_id: &str,
) -> Result<Ts<AuthRequest>, JsError> {
    Ok(
        sealbook_core::login_challenge_request(username, parse_uuid(device_id)?)
            .map_err(core_err)?
            .into_ts()?,
    )
}

/// Login step 2: open the sealed challenge and sign it with the OPAQUE request.
#[wasm_bindgen]
pub fn core_login_start_request(
    state: Ts<CoreDeviceState>,
    opaque_request_b64: &str,
    body: &str,
) -> Result<Ts<LoginStarting>, JsError> {
    Ok(
        sealbook_core::login_start_request(&state.to_rust()?, opaque_request_b64, body)
            .map_err(core_err)?
            .into_ts()?,
    )
}

/// Login step 3: complete OPAQUE and bind the finalization to this device.
#[wasm_bindgen]
pub fn core_login_finish_request(
    state: Ts<CoreDeviceState>,
    opaque_state_b64: &str,
    password: &str,
    challenge_b64: &str,
    body: &str,
) -> Result<Ts<AuthRequest>, JsError> {
    Ok(sealbook_core::login_finish_request(
        &state.to_rust()?,
        opaque_state_b64,
        password,
        challenge_b64,
        body,
    )
    .map_err(core_err)?
    .into_ts()?)
}

/// Opens the collection key and returns the state to persist. The caller must
/// sync the roster before anything reads or writes the vault.
#[wasm_bindgen]
pub fn core_login_accept(
    state: Ts<CoreDeviceState>,
    password: &str,
    body: &str,
) -> Result<Ts<LoggedIn>, JsError> {
    Ok(
        sealbook_core::login_accept(&state.to_rust()?, password, body)
            .map_err(core_err)?
            .into_ts()?,
    )
}

#[wasm_bindgen]
pub fn core_recover_start_request(
    username: &str,
    phrase: &str,
    opaque_request_b64: &str,
) -> Result<Ts<AuthRequest>, JsError> {
    Ok(
        sealbook_core::recover_start_request(username, phrase, opaque_request_b64)
            .map_err(core_err)?
            .into_ts()?,
    )
}

/// Opens the phrase wrap and checks the roster the account is on under the key
/// it opened.
#[wasm_bindgen]
pub fn core_recover_start_accept(phrase: &str, body: &str) -> Result<Ts<RecoverStarted>, JsError> {
    Ok(sealbook_core::recover_start_accept(phrase, body)
        .map_err(core_err)?
        .into_ts()?)
}

/// Enrols the recovering device and signs the roster step with the phrase.
#[wasm_bindgen]
pub fn core_recover_finish_request(
    username: &str,
    phrase: &str,
    password: &str,
    started: Ts<RecoverStarted>,
    device: Ts<CoreDeviceSecrets>,
    upload_b64: &str,
) -> Result<Ts<Recovering>, JsError> {
    Ok(sealbook_core::recover_finish_request(
        username,
        phrase,
        password,
        &started.to_rust()?,
        &device.to_rust()?,
        upload_b64,
    )
    .map_err(core_err)?
    .into_ts()?)
}

#[wasm_bindgen]
pub fn core_recover_accept(
    server: &str,
    username: &str,
    started: Ts<RecoverStarted>,
    device: Ts<CoreDeviceSecrets>,
    recovering: Ts<Recovering>,
    body: &str,
) -> Result<Ts<CoreDeviceState>, JsError> {
    Ok(sealbook_core::recover_accept(
        server,
        username,
        &started.to_rust()?,
        &device.to_rust()?,
        &recovering.to_rust()?,
        body,
    )
    .map_err(core_err)?
    .into_ts()?)
}

/// The challenge a username change or a deletion is signed over.
#[wasm_bindgen]
pub fn core_account_challenge_request() -> Result<Ts<AuthRequest>, JsError> {
    Ok(sealbook_core::account_challenge_request().into_ts()?)
}

#[wasm_bindgen]
pub fn core_change_username_request(
    state: Ts<CoreDeviceState>,
    new_username: &str,
    upload_b64: &str,
    challenge_body: &str,
) -> Result<Ts<AuthRequest>, JsError> {
    Ok(sealbook_core::change_username_request(
        &state.to_rust()?,
        new_username,
        upload_b64,
        challenge_body,
    )
    .map_err(core_err)?
    .into_ts()?)
}

#[wasm_bindgen]
pub fn core_password_change_start_request(
    opaque_request_b64: &str,
) -> Result<Ts<AuthRequest>, JsError> {
    Ok(
        sealbook_core::password_change_start_request(opaque_request_b64)
            .map_err(core_err)?
            .into_ts()?,
    )
}

#[wasm_bindgen]
pub fn core_password_change_start_accept(body: &str) -> Result<Ts<PasswordChangeStarted>, JsError> {
    Ok(sealbook_core::password_change_start_accept(body)
        .map_err(core_err)?
        .into_ts()?)
}

/// The new verifier and the collection key re-wrapped under the new password,
/// with a signature covering both.
#[wasm_bindgen]
pub fn core_change_password_request(
    state: Ts<CoreDeviceState>,
    ck_b64: &str,
    new_password: &str,
    upload_b64: &str,
    started: Ts<PasswordChangeStarted>,
) -> Result<Ts<PasswordChange>, JsError> {
    Ok(sealbook_core::change_password_request(
        &state.to_rust()?,
        &core_session(ck_b64, 0)?,
        new_password,
        upload_b64,
        &started.to_rust()?,
    )
    .map_err(core_err)?
    .into_ts()?)
}

#[wasm_bindgen]
pub fn core_delete_account_request(
    state: Ts<CoreDeviceState>,
    challenge_body: &str,
) -> Result<Ts<AuthRequest>, JsError> {
    Ok(
        sealbook_core::delete_account_request(&state.to_rust()?, challenge_body)
            .map_err(core_err)?
            .into_ts()?,
    )
}

// ── Core: attachments ──
//
// The sealed and opened chunk buffers are function arguments and returns rather
// than fields of a boundary record: wasm carries those as a `Uint8Array`, where
// a `Vec<u8>` inside a tsify record would cross element by element. Everything
// else here is a decision core owns.

#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[serde(transparent)]
pub struct ChunkRangeList(pub Vec<ChunkRange>);

#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[serde(transparent)]
pub struct AttachmentRowList(pub Vec<AttachmentRow>);

#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[serde(transparent)]
pub struct UuidList(#[tsify(type = "string[]")] pub Vec<Uuid>);

/// The protocol's ceiling, the chunk size, the nonce header and the sweep's
/// grace period. A host wanting a lower ceiling of its own applies it first.
#[wasm_bindgen]
pub fn core_attachment_limits() -> Result<Ts<AttachmentLimits>, JsError> {
    Ok(sealbook_core::attachment_limits().into_ts()?)
}

/// Decides an upload: a fresh id and key, and how the plaintext is cut up.
///
/// Throws on an empty file and on one over the protocol ceiling, so neither
/// becomes a server error the user cannot act on.
#[wasm_bindgen]
pub fn core_attachment_plan(total_plaintext_size: u64) -> Result<Ts<AttachmentPlan>, JsError> {
    Ok(sealbook_core::attachment_plan(total_plaintext_size)
        .map_err(core_err)?
        .into_ts()?)
}

/// The slices of plaintext the plan's chunks are taken from, in order.
#[wasm_bindgen]
pub fn core_attachment_ranges(plan: Ts<AttachmentPlan>) -> Result<Ts<ChunkRangeList>, JsError> {
    Ok(ChunkRangeList(sealbook_core::attachment_ranges(&plan.to_rust()?)).into_ts()?)
}

#[wasm_bindgen]
pub fn core_attachment_create_request(
    collection_id: &str,
    plan: Ts<AttachmentPlan>,
) -> Result<Ts<HttpRequest>, JsError> {
    Ok(
        sealbook_core::attachment_create_request(parse_uuid(collection_id)?, &plan.to_rust()?)
            .into_ts()?,
    )
}

#[wasm_bindgen]
pub fn core_attachment_create_accept(plan: Ts<AttachmentPlan>, body: &str) -> Result<(), JsError> {
    sealbook_core::attachment_create_accept(&plan.to_rust()?, body).map_err(core_err)
}

#[wasm_bindgen]
pub fn core_attachment_chunk_path(
    collection_id: &str,
    attachment_id: &str,
    index: u32,
) -> Result<String, JsError> {
    Ok(sealbook_core::attachment_chunk_path(
        parse_uuid(collection_id)?,
        parse_uuid(attachment_id)?,
        index,
    ))
}

/// Seals one chunk, returning its nonce followed by its ciphertext. The caller
/// splits the first `nonce_len` bytes off: the two travel apart on the wire, and
/// a second call would seal under a second nonce.
#[wasm_bindgen]
pub fn core_seal_attachment_chunk(
    key_b64: &str,
    attachment_id: &str,
    collection_id: &str,
    index: u32,
    chunk_count: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>, JsError> {
    sealbook_core::seal_attachment_chunk(
        key_b64,
        parse_uuid(attachment_id)?,
        parse_uuid(collection_id)?,
        index,
        chunk_count,
        plaintext,
    )
    .map_err(core_err)
}

/// Opens one chunk. A chunk that will not open is a tampered or corrupt
/// download, never something to retry.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn core_open_attachment_chunk(
    key_b64: &str,
    attachment_id: &str,
    collection_id: &str,
    index: u32,
    chunk_count: u32,
    nonce_b64: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>, JsError> {
    sealbook_core::open_attachment_chunk(
        key_b64,
        parse_uuid(attachment_id)?,
        parse_uuid(collection_id)?,
        index,
        chunk_count,
        nonce_b64,
        ciphertext,
    )
    .map_err(core_err)
}

/// The nonce a chunk response carried, or a refusal for one that carried none.
#[wasm_bindgen]
pub fn core_attachment_chunk_nonce(header: Option<String>) -> Result<String, JsError> {
    sealbook_core::attachment_chunk_nonce(header).map_err(core_err)
}

#[wasm_bindgen]
pub fn core_attachment_commit_request(
    collection_id: &str,
    attachment_id: &str,
) -> Result<Ts<HttpRequest>, JsError> {
    Ok(sealbook_core::attachment_commit_request(
        parse_uuid(collection_id)?,
        parse_uuid(attachment_id)?,
    )
    .into_ts()?)
}

#[wasm_bindgen]
pub fn core_attachment_commit_accept(attachment_id: &str, body: &str) -> Result<(), JsError> {
    sealbook_core::attachment_commit_accept(parse_uuid(attachment_id)?, body).map_err(core_err)
}

#[wasm_bindgen]
pub fn core_attachment_meta_request(
    collection_id: &str,
    attachment_id: &str,
) -> Result<Ts<HttpRequest>, JsError> {
    Ok(sealbook_core::attachment_meta_request(
        parse_uuid(collection_id)?,
        parse_uuid(attachment_id)?,
    )
    .into_ts()?)
}

/// Whether the server is holding the attachment this record references, checked
/// against the chunk count the record carries rather than the server's own.
#[wasm_bindgen]
pub fn core_attachment_meta_accept(
    attachment_id: &str,
    chunk_count: u32,
    body: &str,
) -> Result<(), JsError> {
    sealbook_core::attachment_meta_accept(parse_uuid(attachment_id)?, chunk_count, body)
        .map(|_| ())
        .map_err(core_err)
}

#[wasm_bindgen]
pub fn core_attachment_delete_request(
    collection_id: &str,
    attachment_id: &str,
) -> Result<Ts<HttpRequest>, JsError> {
    Ok(sealbook_core::attachment_delete_request(
        parse_uuid(collection_id)?,
        parse_uuid(attachment_id)?,
    )
    .into_ts()?)
}

/// One chunk's plaintext digest, rolled up later by `core_attachment_content_hash`.
///
/// Replaces the hasher object the web used to construct and free: the digests
/// are values, so there is nothing to leak if a download throws part way.
#[wasm_bindgen]
pub fn core_attachment_chunk_digest(plaintext: &[u8]) -> String {
    sealbook_core::attachment_chunk_digest(plaintext)
}

/// The hash the owning record commits to, rolled from every chunk's digest.
#[wasm_bindgen]
pub fn core_attachment_content_hash(digests: Vec<String>) -> Result<String, JsError> {
    sealbook_core::attachment_content_hash(&digests).map_err(core_err)
}

/// Checks a download reproduced what the record committed to.
#[wasm_bindgen]
pub fn core_attachment_verify(
    attachment_id: &str,
    expected_hash_b64: &str,
    digests: Vec<String>,
) -> Result<(), JsError> {
    sealbook_core::attachment_verify(parse_uuid(attachment_id)?, expected_hash_b64, &digests)
        .map_err(core_err)
}

#[wasm_bindgen]
pub fn core_attachment_sweep_start() -> Result<Ts<SweepCursor>, JsError> {
    Ok(sealbook_core::sweep_start().into_ts()?)
}

#[wasm_bindgen]
pub fn core_attachment_sweep_request(
    collection_id: &str,
    cursor: Ts<SweepCursor>,
) -> Result<Ts<HttpRequest>, JsError> {
    Ok(sealbook_core::sweep_request(parse_uuid(collection_id)?, &cursor.to_rust()?).into_ts()?)
}

/// One page of the listing, and where to ask next. `next` is absent once the
/// listing is exhausted, which includes a cursor the sweep already followed.
#[wasm_bindgen]
pub fn core_attachment_sweep_page(
    cursor: Ts<SweepCursor>,
    body: &str,
) -> Result<Ts<SweepPage>, JsError> {
    Ok(sealbook_core::sweep_page(&cursor.to_rust()?, body)
        .map_err(core_err)?
        .into_ts()?)
}

/// Which listed attachments are safe to delete. `now_secs` is the caller's
/// clock: core has none.
#[wasm_bindgen]
pub fn core_attachment_sweep_orphans(
    rows: Ts<AttachmentRowList>,
    referenced: Ts<UuidList>,
    now_secs: i64,
) -> Result<Ts<UuidList>, JsError> {
    Ok(UuidList(sealbook_core::sweep_orphans(
        &rows.to_rust()?.0,
        &referenced.to_rust()?.0,
        now_secs,
    ))
    .into_ts()?)
}

// ── Core: payload schemas ──
//
// The one layer with no server check behind it: objects are sealed before they
// leave, so a client writing a key the others do not read is caught by the
// shared fixture or by nothing. Core owns the key list, the writer and the
// lenient reader; this client keeps its own view models.

#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[serde(transparent)]
pub struct CoreNotebookList(pub Vec<CoreNotebook>);

/// Every key a note writer owns, which is the union across all four clients
/// rather than the subset this one's editor can show.
#[wasm_bindgen]
pub fn core_note_keys() -> Vec<String> {
    sealbook_core::NOTE_KEYS
        .iter()
        .map(|key| key.to_string())
        .collect()
}

#[wasm_bindgen]
pub fn core_notebook_keys() -> Vec<String> {
    sealbook_core::NOTEBOOK_KEYS
        .iter()
        .map(|key| key.to_string())
        .collect()
}

#[wasm_bindgen]
pub fn core_default_notebook_id() -> String {
    sealbook_core::default_notebook_id()
}

#[wasm_bindgen]
pub fn core_resolve_notebook_id(notebook_id: Option<String>) -> String {
    sealbook_core::resolve_notebook_id(notebook_id)
}

/// Reads a stored note payload. Lenient throughout: a payload that will not
/// parse comes back as a row the user can still find and delete.
#[wasm_bindgen]
pub fn core_note_parse(id: &str, raw: &str) -> Result<Ts<CoreNote>, JsError> {
    Ok(sealbook_core::note_parse(id, raw).into_ts()?)
}

/// Serialises a note onto `draft.raw`. `now` is the caller's clock: core has
/// none. Throws on a payload from a newer schema major, which this build may
/// read but must not write over.
#[wasm_bindgen]
pub fn core_note_write(draft: Ts<CoreNoteDraft>, now: &str) -> Result<String, JsError> {
    sealbook_core::note_write(&draft.to_rust()?, now).map_err(core_err)
}

#[wasm_bindgen]
pub fn core_notebook_parse(id: &str, raw: &str) -> Result<Ts<CoreNotebook>, JsError> {
    Ok(sealbook_core::notebook_parse(id, raw).into_ts()?)
}

#[wasm_bindgen]
pub fn core_notebook_write(name: &str, previous_raw: Option<String>) -> Result<String, JsError> {
    sealbook_core::notebook_write(name, previous_raw.as_deref()).map_err(core_err)
}

/// The name to show for a note's notebook. A notebook that is gone shows the
/// default notebook's name rather than nothing.
#[wasm_bindgen]
pub fn core_notebook_name_by_id(
    notebooks: Ts<CoreNotebookList>,
    notebook_id: Option<String>,
) -> Result<String, JsError> {
    Ok(sealbook_core::notebook_name_by_id(
        &notebooks.to_rust()?.0,
        notebook_id,
    ))
}

/// A notebook's colour, derived from its id.
#[wasm_bindgen]
pub fn core_notebook_tone(id: &str) -> String {
    sealbook_core::notebook_tone(id)
}

#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[serde(transparent)]
pub struct CoreBookmarkCollectionList(pub Vec<CoreBookmarkCollection>);

/// Every key a bookmark writer owns, which is the union across all four clients.
#[wasm_bindgen]
pub fn core_bookmark_keys() -> Vec<String> {
    sealbook_core::BOOKMARK_KEYS
        .iter()
        .map(|key| key.to_string())
        .collect()
}

#[wasm_bindgen]
pub fn core_bookmark_collection_keys() -> Vec<String> {
    sealbook_core::BOOKMARK_COLLECTION_KEYS
        .iter()
        .map(|key| key.to_string())
        .collect()
}

#[wasm_bindgen]
pub fn core_default_bookmark_collection_id() -> String {
    sealbook_core::default_bookmark_collection_id()
}

#[wasm_bindgen]
pub fn core_resolve_collection_id(collection_id: Option<String>) -> String {
    sealbook_core::resolve_collection_id(collection_id)
}

/// The address as it should be stored: trimmed, and given `https://` when it was
/// typed as a bare host.
#[wasm_bindgen]
pub fn core_normalize_url(url: &str) -> String {
    sealbook_core::normalize_url(url)
}

#[wasm_bindgen]
pub fn core_normalize_tags(tags: Vec<String>) -> Vec<String> {
    sealbook_core::normalize_tags(&tags)
}

/// Reads a stored bookmark payload. Lenient throughout: a payload that will not
/// parse comes back as a row the user can still find and delete.
#[wasm_bindgen]
pub fn core_bookmark_parse(id: &str, raw: &str) -> Result<Ts<CoreBookmark>, JsError> {
    Ok(sealbook_core::bookmark_parse(id, raw).into_ts()?)
}

/// Serialises a bookmark onto `draft.raw`. `now` is the caller's clock. Throws on
/// a payload from a newer schema major.
#[wasm_bindgen]
pub fn core_bookmark_write(draft: Ts<CoreBookmarkDraft>, now: &str) -> Result<String, JsError> {
    sealbook_core::bookmark_write(&draft.to_rust()?, now).map_err(core_err)
}

#[wasm_bindgen]
pub fn core_bookmark_collection_parse(
    id: &str,
    raw: &str,
) -> Result<Ts<CoreBookmarkCollection>, JsError> {
    Ok(sealbook_core::bookmark_collection_parse(id, raw).into_ts()?)
}

#[wasm_bindgen]
pub fn core_bookmark_collection_write(
    draft: Ts<CoreBookmarkCollectionDraft>,
) -> Result<String, JsError> {
    sealbook_core::bookmark_collection_write(&draft.to_rust()?).map_err(core_err)
}

/// The name to show for a bookmark's collection. One that is gone shows the
/// default collection's name rather than nothing.
#[wasm_bindgen]
pub fn core_bookmark_collection_name_by_id(
    collections: Ts<CoreBookmarkCollectionList>,
    collection_id: Option<String>,
) -> Result<String, JsError> {
    Ok(sealbook_core::bookmark_collection_name_by_id(
        &collections.to_rust()?.0,
        collection_id,
    ))
}

/// A collection's colour: its root's explicit colour, else one hashed from the
/// root's id.
#[wasm_bindgen]
pub fn core_bookmark_collection_tone(
    collections: Ts<CoreBookmarkCollectionList>,
    id: &str,
) -> Result<String, JsError> {
    Ok(sealbook_core::bookmark_collection_tone(
        &collections.to_rust()?.0,
        id,
    ))
}

#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[serde(transparent)]
pub struct CoreTaskListList(pub Vec<CoreTaskList>);

/// Every key a task writer owns.
#[wasm_bindgen]
pub fn core_task_keys() -> Vec<String> {
    sealbook_core::TASK_KEYS
        .iter()
        .map(|key| key.to_string())
        .collect()
}

#[wasm_bindgen]
pub fn core_task_list_keys() -> Vec<String> {
    sealbook_core::TASK_LIST_KEYS
        .iter()
        .map(|key| key.to_string())
        .collect()
}

#[wasm_bindgen]
pub fn core_default_task_list_id() -> String {
    sealbook_core::default_task_list_id()
}

#[wasm_bindgen]
pub fn core_resolve_task_list_id(task_list_id: Option<String>) -> String {
    sealbook_core::resolve_task_list_id(task_list_id)
}

/// A due value as it should be stored, or `undefined` where it names no real
/// moment.
#[wasm_bindgen]
pub fn core_normalize_due_date(value: &str) -> Option<String> {
    sealbook_core::normalize_due_date(value)
}

/// Reads a stored task payload. Lenient throughout: a payload that will not
/// parse comes back as a row the user can still find and delete.
#[wasm_bindgen]
pub fn core_task_parse(id: &str, raw: &str) -> Result<Ts<CoreTask>, JsError> {
    Ok(sealbook_core::task_parse(id, raw).into_ts()?)
}

/// Serialises a task onto `draft.raw`. `now` is the caller's clock. Throws on a
/// payload from a newer schema major.
#[wasm_bindgen]
pub fn core_task_write(draft: Ts<CoreTaskDraft>, now: &str) -> Result<String, JsError> {
    sealbook_core::task_write(&draft.to_rust()?, now).map_err(core_err)
}

#[wasm_bindgen]
pub fn core_task_list_parse(id: &str, raw: &str) -> Result<Ts<CoreTaskList>, JsError> {
    Ok(sealbook_core::task_list_parse(id, raw).into_ts()?)
}

#[wasm_bindgen]
pub fn core_task_list_write(draft: Ts<CoreTaskListDraft>) -> Result<String, JsError> {
    sealbook_core::task_list_write(&draft.to_rust()?).map_err(core_err)
}

/// The name to show for a task's list. One that is gone shows the default
/// list's name rather than nothing.
#[wasm_bindgen]
pub fn core_task_list_name_by_id(
    lists: Ts<CoreTaskListList>,
    task_list_id: Option<String>,
) -> Result<String, JsError> {
    Ok(sealbook_core::task_list_name_by_id(
        &lists.to_rust()?.0,
        task_list_id,
    ))
}

/// A list's colour: its root's explicit colour, else one hashed from the root's
/// id.
#[wasm_bindgen]
pub fn core_task_list_tone(lists: Ts<CoreTaskListList>, id: &str) -> Result<String, JsError> {
    Ok(sealbook_core::task_list_tone(&lists.to_rust()?.0, id))
}

#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[serde(transparent)]
pub struct CoreCalendarList(pub Vec<CoreCalendar>);

/// Every key a calendar writer owns, and every key an event writer owns: the
/// union across all four clients rather than the subset this one's editor shows.
#[wasm_bindgen]
pub fn core_calendar_keys() -> Vec<String> {
    sealbook_core::CALENDAR_KEYS
        .iter()
        .map(|key| key.to_string())
        .collect()
}

#[wasm_bindgen]
pub fn core_calendar_event_keys() -> Vec<String> {
    sealbook_core::CALENDAR_EVENT_KEYS
        .iter()
        .map(|key| key.to_string())
        .collect()
}

#[wasm_bindgen]
pub fn core_default_calendar_id() -> String {
    sealbook_core::default_calendar_id()
}

/// Reads a stored calendar payload. Lenient throughout: one that will not parse
/// comes back as a named row the user can still find and delete.
#[wasm_bindgen]
pub fn core_calendar_parse(id: &str, raw: &str) -> Result<Ts<CoreCalendar>, JsError> {
    Ok(sealbook_core::calendar_parse(id, raw).into_ts()?)
}

/// Serialises a calendar onto `draft.raw`, so the colour and the flags a host
/// did not change survive the write. Throws on a payload from a newer schema
/// major, which this build may read but must not write over.
#[wasm_bindgen]
pub fn core_calendar_write(draft: Ts<CoreCalendarDraft>) -> Result<String, JsError> {
    sealbook_core::calendar_write(&draft.to_rust()?).map_err(core_err)
}

/// The days a repeat rule lands on between two dates, as `YYYY-MM-DD`. The
/// host attaches the time of day and the zone.
#[wasm_bindgen]
pub fn core_recurrence_days(
    anchor: &str,
    rule: Ts<CoreRecurrence>,
    from: &str,
    to: &str,
) -> Result<Vec<String>, JsError> {
    Ok(sealbook_core::recurrence_days(
        anchor,
        &rule.to_rust()?,
        from,
        to,
    ))
}

/// The first day of a repeat rule later than `after`, or `None` once spent.
#[wasm_bindgen]
pub fn core_recurrence_next(
    anchor: &str,
    rule: Ts<CoreRecurrence>,
    after: &str,
) -> Result<Option<String>, JsError> {
    Ok(sealbook_core::recurrence_next(
        anchor,
        &rule.to_rust()?,
        after,
    ))
}

/// Whether the text is a real calendar day, which `Date.parse` is not strict
/// enough to say.
#[wasm_bindgen]
pub fn core_is_calendar_day(text: &str) -> bool {
    sealbook_core::is_calendar_day(text)
}

#[wasm_bindgen]
pub fn core_event_parse(id: &str, raw: &str) -> Result<Ts<CoreCalendarEvent>, JsError> {
    Ok(sealbook_core::event_parse(id, raw).into_ts()?)
}

/// Serialises an event onto `draft.raw`. A repeat rule core cannot name rides
/// through in `unreadable_recurrence` rather than being dropped.
#[wasm_bindgen]
pub fn core_event_write(draft: Ts<CoreCalendarEventDraft>) -> Result<String, JsError> {
    sealbook_core::event_write(&draft.to_rust()?).map_err(core_err)
}

/// The name to show for an event's calendar. A calendar that is gone shows the
/// default calendar's name; an event in no calendar has no name to show.
#[wasm_bindgen]
pub fn core_calendar_name_by_id(
    calendars: Ts<CoreCalendarList>,
    calendar_id: Option<String>,
) -> Result<Option<String>, JsError> {
    Ok(sealbook_core::calendar_name_by_id(
        &calendars.to_rust()?.0,
        calendar_id,
    ))
}

#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[serde(transparent)]
pub struct CoreAddressBookList(pub Vec<CoreAddressBook>);

fn key_list(keys: &[&str]) -> Vec<String> {
    keys.iter().map(|key| key.to_string()).collect()
}

/// Every key a card writer owns: the union across all four clients, legacy
/// spellings included, rather than the subset this one's editor shows.
#[wasm_bindgen]
pub fn core_contact_keys() -> Vec<String> {
    key_list(sealbook_core::CONTACT_KEYS)
}

#[wasm_bindgen]
pub fn core_address_book_keys() -> Vec<String> {
    key_list(sealbook_core::ADDRESS_BOOK_KEYS)
}

#[wasm_bindgen]
pub fn core_contact_profile_keys() -> Vec<String> {
    key_list(sealbook_core::PROFILE_KEYS)
}

#[wasm_bindgen]
pub fn core_default_address_book_id() -> String {
    sealbook_core::default_address_book_id()
}

/// A blank id, or the sidebar's `all`, is the default address book.
#[wasm_bindgen]
pub fn core_resolve_address_book_id(id: Option<String>) -> String {
    sealbook_core::resolve_address_book_id(id)
}

/// Reads a stored card. Lenient throughout: one that will not parse comes back
/// as a named row the user can still find and delete.
#[wasm_bindgen]
pub fn core_contact_parse(id: &str, raw: &str) -> Result<Ts<CoreContact>, JsError> {
    Ok(sealbook_core::contact_parse(id, raw).into_ts()?)
}

/// Serialises a card onto `draft.raw`, so the entries the editor does not show
/// survive the write. `now` is the caller's clock. Throws on a payload from a
/// newer schema major, which this build may read but must not write over.
#[wasm_bindgen]
pub fn core_contact_write(draft: Ts<CoreContactDraft>, now: &str) -> Result<String, JsError> {
    sealbook_core::contact_write(&draft.to_rust()?, now).map_err(core_err)
}

#[wasm_bindgen]
pub fn core_address_book_parse(id: &str, raw: &str) -> Result<Ts<CoreAddressBook>, JsError> {
    Ok(sealbook_core::address_book_parse(id, raw).into_ts()?)
}

#[wasm_bindgen]
pub fn core_address_book_write(draft: Ts<CoreAddressBookDraft>) -> Result<String, JsError> {
    sealbook_core::address_book_write(&draft.to_rust()?).map_err(core_err)
}

/// The name to show for a card's address book. A book that is gone shows the
/// default book's name.
#[wasm_bindgen]
pub fn core_address_book_name_by_id(
    books: Ts<CoreAddressBookList>,
    address_book_id: Option<String>,
) -> Result<String, JsError> {
    Ok(sealbook_core::address_book_name_by_id(
        &books.to_rust()?.0,
        address_book_id,
    ))
}

/// Reads a profile from its JSON text, for the importers that carry one outside
/// a card. Undefined for text that is not a profile.
#[wasm_bindgen]
pub fn core_contact_profile_parse(raw: &str) -> Result<Option<Ts<CoreContactProfile>>, JsError> {
    match sealbook_core::profile_parse(raw) {
        Some(profile) => Ok(Some(profile.into_ts()?)),
        None => Ok(None),
    }
}

/// A profile as JSON text, or undefined when nothing in it would survive a write.
#[wasm_bindgen]
pub fn core_contact_profile_write(
    profile: Ts<CoreContactProfile>,
) -> Result<Option<String>, JsError> {
    Ok(sealbook_core::profile_write(&profile.to_rust()?))
}

/// Every key the settings writer owns.
#[wasm_bindgen]
pub fn core_account_settings_keys() -> Vec<String> {
    sealbook_core::ACCOUNT_SETTINGS_KEYS
        .iter()
        .map(|key| key.to_string())
        .collect()
}

/// The settings of an account that has never chosen.
#[wasm_bindgen]
pub fn core_default_account_settings() -> Result<Ts<CoreAccountSettings>, JsError> {
    Ok(sealbook_core::default_account_settings().into_ts()?)
}

/// Reads a stored settings payload. Lenient throughout: one that will not parse
/// reads as the defaults.
#[wasm_bindgen]
pub fn core_settings_parse(raw: &str) -> Result<Ts<CoreAccountSettings>, JsError> {
    Ok(sealbook_core::settings_parse(raw).into_ts()?)
}

/// Serialises settings onto `draft.raw`. Throws on a payload from a newer schema
/// major.
#[wasm_bindgen]
pub fn core_settings_write(draft: Ts<CoreAccountSettingsDraft>) -> Result<String, JsError> {
    sealbook_core::settings_write(&draft.to_rust()?).map_err(core_err)
}

/// The settings with one feature flipped, or unchanged when that would leave
/// none on.
#[wasm_bindgen]
pub fn core_settings_with_feature(
    settings: Ts<CoreAccountSettings>,
    feature: &str,
    enabled: bool,
) -> Result<Ts<CoreAccountSettings>, JsError> {
    Ok(sealbook_core::settings_with_feature(&settings.to_rust()?, feature, enabled).into_ts()?)
}

#[wasm_bindgen]
pub fn core_can_disable_feature(
    settings: Ts<CoreAccountSettings>,
    feature: &str,
) -> Result<bool, JsError> {
    Ok(sealbook_core::can_disable_feature(
        &settings.to_rust()?,
        feature,
    ))
}

#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[serde(transparent)]
pub struct ContactDraftList(pub Vec<CoreContactDraft>);

/// The cards in a vCard file, as drafts for `address_book_id`, and the ones left out.
#[wasm_bindgen]
pub fn core_vcard_import(
    text: &str,
    address_book_id: &str,
) -> Result<Ts<CoreContactImport>, JsError> {
    Ok(sealbook_core::vcard_import(text, address_book_id).into_ts()?)
}

#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[serde(transparent)]
pub struct IcsExportList(pub Vec<CoreIcsExportEvent>);

/// The events in a calendar file. Times written in a zone come back as local
/// wall-clock time and the zone's name, for the host to resolve.
#[wasm_bindgen]
pub fn core_ics_parse(input: &str) -> Result<Ts<CoreIcsImport>, JsError> {
    Ok(sealbook_core::ics_parse(input).into_ts()?)
}

/// An RFC 5545 calendar holding the events. `now` is the caller's clock.
#[wasm_bindgen]
pub fn core_ics_write(
    events: Ts<IcsExportList>,
    calendar_name: &str,
    now: &str,
) -> Result<String, JsError> {
    Ok(sealbook_core::ics_write(
        &events.to_rust()?.0,
        calendar_name,
        now,
    ))
}

/// The contacts in a CSV file, as drafts for the address book unless a row names its own,
/// and the rows left out.
#[wasm_bindgen]
pub fn core_csv_import(
    text: &str,
    address_book_id: &str,
) -> Result<Ts<CoreContactImport>, JsError> {
    Ok(sealbook_core::csv_import(text, address_book_id).into_ts()?)
}

/// A CSV file holding the cards, each row's book named from `books`.
#[wasm_bindgen]
pub fn core_csv_write(
    contacts: Ts<ContactDraftList>,
    books: Ts<CoreAddressBookList>,
) -> Result<String, JsError> {
    Ok(sealbook_core::csv_write(
        &contacts.to_rust()?.0,
        &books.to_rust()?.0,
    ))
}

/// A vCard 3.0 file holding the cards.
#[wasm_bindgen]
pub fn core_vcard_write(contacts: Ts<ContactDraftList>) -> Result<String, JsError> {
    Ok(sealbook_core::vcard_write(&contacts.to_rust()?.0))
}

#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[serde(transparent)]
pub struct ExportObjectList(pub Vec<CoreExportObject>);

/// The account export document for a vault.
#[wasm_bindgen]
pub fn core_account_export_write(
    account: Ts<CoreExportAccount>,
    objects: Ts<ExportObjectList>,
    unreadable: u32,
    exported_at: &str,
) -> Result<String, JsError> {
    Ok(sealbook_core::account_export_write(
        &account.to_rust()?,
        &objects.to_rust()?.0,
        unreadable,
        exported_at,
    ))
}

/// Reads an export document. Throws with a sentence fit to show the user.
#[wasm_bindgen]
pub fn core_account_export_parse(document: &str) -> Result<Ts<CoreAccountImport>, JsError> {
    Ok(sealbook_core::account_export_parse(document)
        .map_err(core_err)?
        .into_ts()?)
}

#[wasm_bindgen]
pub fn core_account_export_filename(username: &str, day: &str) -> String {
    sealbook_core::account_export_filename(username, day)
}
