use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sealbook_crypto::{
    content_digest, decrypt_object, encrypt_object, key_rotation_transcript, key_wraps_digest,
    manifest_digest, object_aad, pair_confirmation, rotated_objects_digest,
    rotation_recovery_payload, sign, unwrap_collection_key, unwrap_for_device, wrap_for_device,
    CollectionKey, DeviceHpkePublic, DeviceHpkeSecret, DeviceHpkeWrap, DeviceSigningSecrets,
    EncryptedObject, ManifestDigestEntry, ObjectDigestEntry, RecoveryWrap, WrapDigestEntry,
    XWING_CIPHERSUITE,
};
use sealbook_protocol::envelope::{open_envelope, seal_envelope, Unsealed};
use sealbook_protocol::{DevicePublicKeys, RosterBody, RosterSignerBody, SEALED_CONTENT_TYPE};
use uuid::Uuid;

uniffi::setup_scaffolding!();

// sealbook-core carries its own uniffi namespace. Without this the linker drops
// its scaffolding from the cdylib and bindgen emits no Kotlin for it.
sealbook_core::uniffi_reexport_scaffolding!();

// ── Helpers ──

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(s: &str) -> Result<Vec<u8>, CryptoError> {
    URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|e| CryptoError::General { msg: e.to_string() })
}

fn parse_uuid(s: &str) -> Result<Uuid, CryptoError> {
    Uuid::parse_str(s).map_err(|e| CryptoError::General { msg: e.to_string() })
}

fn ck_from_b64(s: &str) -> Result<CollectionKey, CryptoError> {
    let bytes = unb64(s)?;
    if bytes.len() != 32 {
        return Err(CryptoError::General {
            msg: "collection key must be 32 bytes".into(),
        });
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(CollectionKey::from_bytes(key))
}

// ── Error ──

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CryptoError {
    #[error("{msg}")]
    General { msg: String },
}

impl From<sealbook_crypto::CryptoError> for CryptoError {
    fn from(e: sealbook_crypto::CryptoError) -> Self {
        CryptoError::General { msg: e.to_string() }
    }
}

// ── OPAQUE Registration ──

// ── Enrollment ──

// ── OPAQUE Login ──

// ── Collection Key Unwrap ──

#[uniffi::export]
pub fn unwrap_ck(
    password: String,
    kdf_salt_b64: String,
    hpke_sk_b64: String,
    device_id: String,
    wraps_json: String,
) -> Result<String, CryptoError> {
    #[derive(serde::Deserialize)]
    struct WrapIn {
        recipient_kind: String,
        recipient_id: String,
        hpke_enc: String,
        wrapped_ck: String,
        ciphersuite: String,
    }

    let wraps: Vec<WrapIn> = serde_json::from_str(&wraps_json)
        .map_err(|e| CryptoError::General { msg: e.to_string() })?;

    if let Some(device) = wraps
        .iter()
        .find(|w| w.recipient_kind == "device" && w.recipient_id == device_id)
    {
        let key = unwrap_for_device(
            &DeviceHpkeSecret::from_bytes(unb64(&hpke_sk_b64)?),
            &DeviceHpkeWrap {
                enc: unb64(&device.hpke_enc)?,
                ciphertext: unb64(&device.wrapped_ck)?,
                ciphersuite: XWING_CIPHERSUITE,
            },
        )?;
        return Ok(b64(key.as_bytes()));
    }
    if let Some(recovery) = wraps.iter().find(|w| w.recipient_kind == "recovery") {
        let nonce_bytes = unb64(&recovery.hpke_enc)?;
        if nonce_bytes.len() != 24 {
            return Err(CryptoError::General {
                msg: "recovery nonce must be 24 bytes".into(),
            });
        }
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&nonce_bytes);
        let key = unwrap_collection_key(
            password.as_bytes(),
            &unb64(&kdf_salt_b64)?,
            &RecoveryWrap {
                nonce,
                ciphertext: unb64(&recovery.wrapped_ck)?,
                ciphersuite: recovery.ciphersuite.clone(),
            },
        )?;
        return Ok(b64(key.as_bytes()));
    }
    Err(CryptoError::General {
        msg: "no collection key wrap found".into(),
    })
}

// ── Encrypt / Decrypt ──

#[derive(uniffi::Record)]
pub struct EncryptedResult {
    pub nonce: String,
    pub ciphertext: String,
    pub padded_size: u64,
}

#[uniffi::export]
pub fn encrypt_contact(
    ck_b64: String,
    object_id: String,
    collection_id: String,
    plaintext: String,
) -> Result<EncryptedResult, CryptoError> {
    let oid = parse_uuid(&object_id)?;
    let cid = parse_uuid(&collection_id)?;
    let aad = object_aad(oid.as_bytes(), cid.as_bytes());
    let enc = encrypt_object(&ck_from_b64(&ck_b64)?, plaintext.as_bytes(), &aad)?;
    Ok(EncryptedResult {
        nonce: b64(&enc.nonce),
        ciphertext: b64(&enc.ciphertext),
        padded_size: enc.padded_size as u64,
    })
}

#[uniffi::export]
pub fn decrypt_contact(
    ck_b64: String,
    object_id: String,
    collection_id: String,
    nonce_b64: String,
    ciphertext_b64: String,
    padded_size: u64,
) -> Result<String, CryptoError> {
    text(decrypt_object_bytes(
        &ck_b64,
        &object_id,
        &collection_id,
        &nonce_b64,
        &ciphertext_b64,
        padded_size,
    )?)
}

fn decrypt_object_bytes(
    ck_b64: &str,
    object_id: &str,
    collection_id: &str,
    nonce_b64: &str,
    ciphertext_b64: &str,
    padded_size: u64,
) -> Result<Vec<u8>, CryptoError> {
    let oid = parse_uuid(object_id)?;
    let cid = parse_uuid(collection_id)?;
    let nonce_bytes = unb64(nonce_b64)?;
    if nonce_bytes.len() != 24 {
        return Err(CryptoError::General {
            msg: "nonce must be 24 bytes".into(),
        });
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&nonce_bytes);
    let aad = object_aad(oid.as_bytes(), cid.as_bytes());
    Ok(decrypt_object(
        &ck_from_b64(ck_b64)?,
        &EncryptedObject {
            nonce,
            ciphertext: unb64(ciphertext_b64)?,
            padded_size: padded_size as usize,
        },
        &aad,
    )?)
}

/// What `content_type` every object must be `PUT` under. The real type goes in
/// the envelope instead, so the server is told the same thing about all of them.
#[uniffi::export]
pub fn sealed_content_type() -> String {
    SEALED_CONTENT_TYPE.to_string()
}

#[derive(uniffi::Record)]
pub struct OpenedObject {
    /// Authenticated by the AEAD along with the payload, so it is the type a
    /// caller parses by rather than the label the server serves.
    pub content_type: String,
    pub tombstone: bool,
    pub payload: String,
}

/// Seals `payload` under `content_type` and encrypts the envelope.
///
/// Callers use this rather than `encrypt_contact` plus an envelope of their own:
/// one implementation of the format, shared with the Rust client.
#[uniffi::export]
pub fn seal_object(
    ck_b64: String,
    object_id: String,
    collection_id: String,
    content_type: String,
    payload: String,
) -> Result<EncryptedResult, CryptoError> {
    let oid = parse_uuid(&object_id)?;
    let cid = parse_uuid(&collection_id)?;
    let aad = object_aad(oid.as_bytes(), cid.as_bytes());
    let plain = seal_envelope(&content_type, payload.as_bytes());
    let enc = encrypt_object(&ck_from_b64(&ck_b64)?, &plain, &aad)?;
    Ok(EncryptedResult {
        nonce: b64(&enc.nonce),
        ciphertext: b64(&enc.ciphertext),
        padded_size: enc.padded_size as u64,
    })
}

/// Decrypts an object and opens its envelope.
#[uniffi::export]
pub fn open_object(
    ck_b64: String,
    object_id: String,
    collection_id: String,
    nonce_b64: String,
    ciphertext_b64: String,
    padded_size: u64,
) -> Result<OpenedObject, CryptoError> {
    let plain = decrypt_object_bytes(
        &ck_b64,
        &object_id,
        &collection_id,
        &nonce_b64,
        &ciphertext_b64,
        padded_size,
    )?;
    match open_envelope(&plain) {
        Unsealed::Envelope {
            content_type,
            tombstone,
            payload,
        } => Ok(OpenedObject {
            content_type,
            tombstone,
            payload: text(payload)?,
        }),
        Unsealed::Unreadable => Err(CryptoError::General {
            msg: "object has an envelope this build cannot read".into(),
        }),
    }
}

fn text(bytes: Vec<u8>) -> Result<String, CryptoError> {
    String::from_utf8(bytes).map_err(|_| CryptoError::General {
        msg: "object payload is not valid UTF-8".into(),
    })
}

// ── Device Creation ──

// ── Collection Key Wrapping ──

#[derive(uniffi::Record)]
pub struct WrapResult {
    pub enc: String,
    pub wrapped_ck: String,
    pub ciphersuite: String,
}

#[uniffi::export]
pub fn wrap_ck_for_device(ck_b64: String, hpke_pk_b64: String) -> Result<WrapResult, CryptoError> {
    let wrap = wrap_for_device(
        &DeviceHpkePublic(unb64(&hpke_pk_b64)?),
        &ck_from_b64(&ck_b64)?,
    )?;
    Ok(WrapResult {
        enc: b64(&wrap.enc),
        wrapped_ck: b64(&wrap.ciphertext),
        ciphersuite: XWING_CIPHERSUITE.to_string(),
    })
}

// ── Phrase Recovery ──

// ── Pair Grant Signing ──

#[derive(uniffi::Record)]
pub struct DualSigResult {
    pub mldsa: String,
    pub ed25519: String,
}

/// The pairing code both screens show.
///
/// Kept for the tests that stand in for the server, which computes the same
/// code; the app takes its own from core's pairing decisions.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn pair_confirmation_code(
    pair_id: String,
    device_id: String,
    mldsa_pk_b64: String,
    ed25519_pk_b64: String,
    hpke_pk_b64: String,
    roster_seq: u64,
    roster_transcript_b64: String,
) -> Result<String, CryptoError> {
    Ok(pair_confirmation(
        parse_uuid(&pair_id)?,
        parse_uuid(&device_id)?,
        &unb64(&mldsa_pk_b64)?,
        &unb64(&ed25519_pk_b64)?,
        &unb64(&hpke_pk_b64)?,
        roster_seq,
        &digest32(&roster_transcript_b64)?,
    ))
}

// ── Utility ──

/// A fresh random collection key, for rotating the vault on device revocation.
#[uniffi::export]
pub fn new_collection_key() -> String {
    b64(CollectionKey::generate().as_bytes())
}

#[uniffi::export]
pub fn new_uuid() -> String {
    Uuid::new_v4().to_string()
}

// ── Collection Key Rotation ──

#[derive(uniffi::Record)]
pub struct RotationWrap {
    pub recipient_kind: String,
    pub recipient_id: String,
    pub hpke_enc: String,
    pub wrapped_ck: String,
    pub ciphersuite: String,
}

#[derive(uniffi::Record)]
pub struct RotationObject {
    pub id: String,
    pub revision: u64,
    pub nonce: String,
    pub ciphertext: String,
    pub padded_size: u64,
    pub content_type: String,
    pub tombstone: bool,
}

/// The account-level recovery material a rotation installs, as the signature
/// covers it. The four byte fields are base64url.
#[derive(uniffi::Record)]
pub struct RotationRecovery {
    pub kdf_salt: String,
    pub phrase_mldsa_pk: String,
    pub phrase_ed25519_pk: String,
    pub phrase_lookup_id: String,
    pub phrase_scheme: String,
}

/// Signs a collection-key rotation.
///
/// The canonical, length-prefixed digests are computed here rather than on the
/// Kotlin side, so the caller cannot get the framing wrong. Both lists must be
/// in the exact order they will be sent to the server.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn rotation_sign(
    mldsa_seed_b64: String,
    ed25519_sk_b64: String,
    collection_id: String,
    // Empty to rotate without revoking a device, which is how a phrase change and
    // a completed recovery rotate.
    revoked_device_id: String,
    key_epoch: u64,
    wraps: Vec<RotationWrap>,
    objects: Vec<RotationObject>,
    manifest_digest_b64: String,
    // The KDF salt and phrase record this rotation installs. Signed so that a
    // modified request body cannot swap in recovery material the account holder
    // never produced.
    recovery: RotationRecovery,
) -> Result<DualSigResult, CryptoError> {
    let wrap_bytes = wraps
        .iter()
        .map(|wrap| Ok((unb64(&wrap.hpke_enc)?, unb64(&wrap.wrapped_ck)?)))
        .collect::<Result<Vec<_>, CryptoError>>()?;
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
        .collect::<Result<Vec<_>, CryptoError>>()?;
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
        Some(parse_uuid(&revoked_device_id)?)
    };
    let transcript = key_rotation_transcript(
        parse_uuid(&collection_id)?,
        revoked,
        key_epoch,
        &key_wraps_digest(&wrap_entries),
        &rotated_objects_digest(&object_entries),
        &digest32(&manifest_digest_b64)?,
        &rotation_recovery_payload(
            &unb64(&recovery.kdf_salt)?,
            &unb64(&recovery.phrase_mldsa_pk)?,
            &unb64(&recovery.phrase_ed25519_pk)?,
            &unb64(&recovery.phrase_lookup_id)?,
            &recovery.phrase_scheme,
        ),
    );
    let secrets = DeviceSigningSecrets {
        mldsa_seed: unb64(&mldsa_seed_b64)?,
        ed25519_sk: unb64(&ed25519_sk_b64)?,
    };
    let sig = sign(&secrets, &transcript)?;
    Ok(DualSigResult {
        mldsa: b64(&sig.mldsa),
        ed25519: b64(&sig.ed25519),
    })
}

// ── Signed manifest ──
//
// Mirrors the WASM bindings exactly, so both clients compute the same digests and
// signatures from the same Rust.

fn digest32(b64_value: &str) -> Result<[u8; 32], CryptoError> {
    let bytes = unb64(b64_value)?;
    if bytes.len() != 32 {
        return Err(CryptoError::General {
            msg: "digest must be 32 bytes".into(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[derive(uniffi::Record)]
pub struct ManifestEntryIn {
    pub id: String,
    pub revision: u64,
    pub tombstone: bool,
    pub content_digest: String,
}

fn manifest_entries(entries: &[ManifestEntryIn]) -> Result<Vec<ManifestDigestEntry>, CryptoError> {
    entries
        .iter()
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
#[uniffi::export]
pub fn object_content_digest(
    nonce_b64: String,
    ciphertext_b64: String,
) -> Result<String, CryptoError> {
    Ok(b64(&content_digest(
        &unb64(&nonce_b64)?,
        &unb64(&ciphertext_b64)?,
    )))
}

/// Digest of a whole collection, for a manifest.
#[uniffi::export]
pub fn manifest_digest_of(entries: Vec<ManifestEntryIn>) -> Result<String, CryptoError> {
    Ok(b64(&manifest_digest(&manifest_entries(&entries)?)))
}

// ── Device roster ──

fn roster_err(e: impl std::fmt::Display) -> CryptoError {
    CryptoError::General { msg: e.to_string() }
}

fn devices_from(devices_json: &str) -> Result<Vec<DevicePublicKeys>, CryptoError> {
    serde_json::from_str(devices_json).map_err(roster_err)
}

/// Signs a device roster with this device's keys and MACs it under the
/// collection key. `devices_json` is the full device list in wire format; the
/// result is the roster JSON to send with a registration, approval or rotation.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn roster_seal_device(
    collection_id: String,
    roster_seq: u64,
    key_epoch: u64,
    devices_json: String,
    phrase_mldsa_pk_b64: String,
    phrase_ed25519_pk_b64: String,
    signer_device_id: String,
    mldsa_seed_b64: String,
    ed25519_sk_b64: String,
    ck_b64: String,
) -> Result<String, CryptoError> {
    let roster = RosterBody::seal(
        parse_uuid(&collection_id)?,
        roster_seq,
        key_epoch,
        devices_from(&devices_json)?,
        unb64(&phrase_mldsa_pk_b64)?,
        unb64(&phrase_ed25519_pk_b64)?,
        RosterSignerBody::Device {
            device_id: parse_uuid(&signer_device_id)?,
        },
        &DeviceSigningSecrets {
            mldsa_seed: unb64(&mldsa_seed_b64)?,
            ed25519_sk: unb64(&ed25519_sk_b64)?,
        },
        &ck_from_b64(&ck_b64)?,
    )?;
    serde_json::to_string(&roster).map_err(roster_err)
}

// ── HTTP transport ──
//
// Sealbook servers negotiate TLS 1.3 with X25519MLKEM768 and refuse every other
// key exchange. Android's platform TLS does not offer that group, so a request
// made through the platform stack is rejected at the ClientHello and the app
// cannot reach a server at all. Routing requests through rustls here means the
// app speaks the same TLS as every other client, built from the same Rust and
// the same policy, rather than depending on what a given device happens to
// support.
//
// Deliberately a transport and nothing more: status and body come back exactly
// as the server sent them, and the Kotlin above keeps its own idea of what an
// error means. Anything richer would be a second implementation of the protocol
// living alongside the one the app already has.

use std::sync::Arc;

use sealbook_client::{certificate_from_pem, pq_tls_config, TrustAnchors};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum HttpError {
    /// The request never completed: DNS, connection, timeout, or a handshake the
    /// server refused. A failed PQ handshake arrives here.
    #[error("{msg}")]
    Transport { msg: String },
    /// The client could not be built, so no request was attempted.
    #[error("{msg}")]
    Tls { msg: String },
}

/// What the server answered, whatever the status.
///
/// A 4xx or 5xx is a response, not an error: the caller parses the body for the
/// server's own message and decides what it means. Only a request that never got
/// an answer is an `Err`.
#[derive(uniffi::Record)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

#[derive(uniffi::Object)]
pub struct HttpClient {
    inner: reqwest::blocking::Client,
}

#[uniffi::export]
impl HttpClient {
    /// `extra_trust_pem` is a certificate trusted *in addition to* the public
    /// roots, for reaching a development server that no public CA has signed.
    /// It is additive on purpose: a debug build has to reach both that server
    /// and a normally-named one, and dropping the public roots would break the
    /// second. Release builds pass nothing.
    #[uniffi::constructor]
    pub fn new(
        extra_trust_pem: Option<String>,
        timeout_seconds: u32,
    ) -> Result<Arc<Self>, HttpError> {
        let trust = match extra_trust_pem {
            Some(pem) => TrustAnchors::WebPkiPlus(
                certificate_from_pem(&pem).map_err(|e| HttpError::Tls { msg: e.to_string() })?,
            ),
            None => TrustAnchors::WebPki,
        };
        let config = pq_tls_config(trust).map_err(|e| HttpError::Tls { msg: e.to_string() })?;
        let timeout = std::time::Duration::from_secs(timeout_seconds as u64);
        let inner = reqwest::blocking::Client::builder()
            .use_preconfigured_tls(config)
            // Cleartext would undo the point of the transport, and the app's
            // network security config refused it before this existed.
            .https_only(true)
            .connect_timeout(timeout)
            .timeout(timeout)
            .build()
            .map_err(|e| HttpError::Tls { msg: e.to_string() })?;
        Ok(Arc::new(Self { inner }))
    }

    /// One request, blocking. Callers are already on a background thread.
    pub fn request(
        &self,
        method: String,
        url: String,
        body: Option<String>,
        bearer: Option<String>,
    ) -> Result<HttpResponse, HttpError> {
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| HttpError::Transport { msg: e.to_string() })?;
        let mut req = self.inner.request(method, &url);
        if let Some(body) = body {
            req = req
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/json; charset=utf-8",
                )
                .body(body);
        }
        if let Some(token) = bearer {
            req = req.bearer_auth(token);
        }
        let response = req.send().map_err(|e| HttpError::Transport {
            msg: transport_message(&e),
        })?;
        let status = response.status().as_u16();
        let body = response
            .text()
            .map_err(|e| HttpError::Transport { msg: e.to_string() })?;
        Ok(HttpResponse { status, body })
    }
}

/// A message that names the cause rather than stopping at the outermost layer.
///
/// `reqwest`'s own `Display` for a failed handshake says only that a connection
/// failed, which is exactly the case where the reason — no shared key exchange —
/// is the whole diagnosis.
fn transport_message(err: &reqwest::Error) -> String {
    let mut parts = vec![err.to_string()];
    let mut source = std::error::Error::source(err);
    while let Some(cause) = source {
        parts.push(cause.to_string());
        source = cause.source();
    }
    parts.join(": ")
}
