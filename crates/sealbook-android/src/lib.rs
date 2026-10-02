use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sealbook_crypto::opaque::{
    client_login_finish, client_login_start, client_register_finish, client_register_start,
    ClientLogin, ClientRegistration, SealbookCipherSuite,
};
use sealbook_crypto::{
    account_op_transcript, content_digest, decrypt_object, delete_account_payload, encrypt_object,
    enrollment_transcript, entropy_from_phrase, generate_device_hpke, generate_device_signing,
    generate_kdf_salt, generate_phrase, key_rotation_transcript, key_wraps_digest,
    login_start_transcript, login_transcript, manifest_digest, manifest_transcript, object_aad,
    open_login_challenge, pair_grant_transcript, password_change_payload, phrase_lookup_id,
    phrase_recovery_public, phrase_recovery_transcript, rotated_objects_digest,
    rotation_recovery_payload, sign, sign_phrase_recovery, unwrap_collection_key,
    unwrap_for_device, unwrap_for_phrase, username_change_payload, verify, wrap_collection_key,
    wrap_for_device, wrap_for_phrase, CollectionKey, DeviceHpkePublic, DeviceHpkeSecret,
    DeviceHpkeWrap, DeviceSigningPublic, DeviceSigningSecrets, DualSignature, EncryptedObject,
    ManifestDigestEntry, ObjectDigestEntry, RecoveryWrap, WrapDigestEntry, PHRASE_CIPHERSUITE,
    PHRASE_SCHEME, RECOVERY_CIPHERSUITE, XWING_CIPHERSUITE,
};
use sealbook_crypto::{phrase_recovery_keys, RosterPin};
use sealbook_protocol::{DevicePublicKeys, RosterBody, RosterSignerBody};
use uuid::Uuid;

uniffi::setup_scaffolding!();

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

#[derive(uniffi::Record)]
pub struct OpaqueStartResult {
    pub request: String,
    pub state: String,
}

#[uniffi::export]
pub fn opaque_register_start(password: String) -> Result<OpaqueStartResult, CryptoError> {
    let (request, state) = client_register_start(password.as_bytes())
        .map_err(|e| CryptoError::General { msg: e.to_string() })?;
    Ok(OpaqueStartResult {
        request: b64(&request),
        state: b64(&state.serialize()),
    })
}

#[uniffi::export]
pub fn opaque_register_finish(
    state_b64: String,
    password: String,
    response_b64: String,
) -> Result<String, CryptoError> {
    let state = ClientRegistration::<SealbookCipherSuite>::deserialize(&unb64(&state_b64)?)
        .map_err(|e| CryptoError::General { msg: e.to_string() })?;
    let upload = client_register_finish(state, password.as_bytes(), &unb64(&response_b64)?)
        .map_err(|e| CryptoError::General { msg: e.to_string() })?;
    Ok(b64(&upload))
}

// ── Enrollment ──

#[derive(uniffi::Record)]
pub struct EnrollmentResult {
    pub device_id: String,
    pub hpke_sk: String,
    pub hpke_pk: String,
    pub mldsa_seed: String,
    pub mldsa_pk: String,
    pub ed25519_sk: String,
    pub ed25519_pk: String,
    pub kdf_salt: String,
    pub collection_key: String,
    pub enrollment_mldsa: String,
    pub enrollment_ed25519: String,
    pub device_enc: String,
    pub device_wrapped_ck: String,
    pub recovery_nonce: String,
    pub recovery_wrapped_ck: String,
    pub phrase: String,
    pub phrase_nonce: String,
    pub phrase_wrapped_ck: String,
    pub phrase_mldsa_pk: String,
    pub phrase_ed25519_pk: String,
    pub phrase_lookup_id: String,
    pub phrase_scheme: String,
    pub phrase_ciphersuite: String,
    pub xwing_ciphersuite: String,
    pub recovery_ciphersuite: String,
}

#[derive(uniffi::Record)]
pub struct PasswordWrapResult {
    pub kdf_salt: String,
    pub recovery_nonce: String,
    pub recovery_wrapped_ck: String,
    pub recovery_ciphersuite: String,
}

#[uniffi::export]
pub fn wrap_ck_for_password(
    collection_key_b64: String,
    password: String,
) -> Result<PasswordWrapResult, CryptoError> {
    let bytes = unb64(&collection_key_b64)?;
    if bytes.len() != 32 {
        return Err(CryptoError::General {
            msg: "collection key must be 32 bytes".into(),
        });
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    let salt = generate_kdf_salt();
    let wrap = wrap_collection_key(password.as_bytes(), &salt, &CollectionKey::from_bytes(key))?;
    Ok(PasswordWrapResult {
        kdf_salt: b64(&salt),
        recovery_nonce: b64(&wrap.nonce),
        recovery_wrapped_ck: b64(&wrap.ciphertext),
        recovery_ciphersuite: RECOVERY_CIPHERSUITE.to_string(),
    })
}

#[uniffi::export]
pub fn create_enrollment(password: String) -> Result<EnrollmentResult, CryptoError> {
    let (hpke_sk, hpke_pk) = generate_device_hpke()?;
    let (sign_sk, sign_pk) = generate_device_signing()?;
    let ck = CollectionKey::generate();
    let salt = generate_kdf_salt();
    let recovery = wrap_collection_key(password.as_bytes(), &salt, &ck)?;
    let (phrase, phrase_entropy) = generate_phrase()?;
    let phrase_wrap = wrap_for_phrase(&phrase_entropy, &ck)?;
    let device_wrap = wrap_for_device(&hpke_pk, &ck)?;
    let device_id = Uuid::new_v4();
    let transcript = enrollment_transcript(
        device_id,
        &sign_pk.mldsa_pk,
        &sign_pk.ed25519_pk,
        &hpke_pk.0,
    );
    let sig = sign(&sign_sk, &transcript)?;
    let phrase_recovery = phrase_recovery_public(&phrase_entropy)?;
    Ok(EnrollmentResult {
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
        phrase_lookup_id: b64(&phrase_lookup_id(&phrase_entropy)?),
        phrase_scheme: PHRASE_SCHEME.to_string(),
        phrase_ciphersuite: PHRASE_CIPHERSUITE.to_string(),
        xwing_ciphersuite: XWING_CIPHERSUITE.to_string(),
        recovery_ciphersuite: RECOVERY_CIPHERSUITE.to_string(),
    })
}

// ── OPAQUE Login ──

#[uniffi::export]
pub fn opaque_login_start(password: String) -> Result<OpaqueStartResult, CryptoError> {
    let (request, state) = client_login_start(password.as_bytes())
        .map_err(|e| CryptoError::General { msg: e.to_string() })?;
    Ok(OpaqueStartResult {
        request: b64(&request),
        state: b64(&state.serialize()),
    })
}

#[derive(uniffi::Record)]
pub struct LoginStartProofResult {
    pub challenge: String,
    pub mldsa: String,
    pub ed25519: String,
}

#[derive(uniffi::Record)]
pub struct LoginProofResult {
    pub finalization: String,
    pub mldsa: String,
    pub ed25519: String,
}

/// Step 2 of login: open the sealed challenge and sign it together with the
/// OPAQUE request. The server releases no credential response until this proof
/// verifies, which is what keeps the password out of reach of an attacker who
/// can break Ristretto255.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn login_start_proof(
    hpke_sk_b64: String,
    challenge_enc_b64: String,
    challenge_ct_b64: String,
    challenge_id: String,
    username: String,
    device_id: String,
    request_b64: String,
    mldsa_seed_b64: String,
    ed25519_sk_b64: String,
) -> Result<LoginStartProofResult, CryptoError> {
    let challenge = open_login_challenge(
        &DeviceHpkeSecret::from_bytes(unb64(&hpke_sk_b64)?),
        &DeviceHpkeWrap {
            enc: unb64(&challenge_enc_b64)?,
            ciphertext: unb64(&challenge_ct_b64)?,
            ciphersuite: XWING_CIPHERSUITE,
        },
    )?;
    let secrets = DeviceSigningSecrets {
        mldsa_seed: unb64(&mldsa_seed_b64)?,
        ed25519_sk: unb64(&ed25519_sk_b64)?,
    };
    let transcript = login_start_transcript(
        parse_uuid(&challenge_id)?,
        &username,
        parse_uuid(&device_id)?,
        &challenge,
        &unb64(&request_b64)?,
    );
    let sig = sign(&secrets, &transcript)?;
    Ok(LoginStartProofResult {
        challenge: b64(&challenge),
        mldsa: b64(&sig.mldsa),
        ed25519: b64(&sig.ed25519),
    })
}

/// Step 3 of login. `challenge_b64` is the value returned by
/// [`login_start_proof`], so the challenge is opened only once.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn opaque_login_finish(
    state_b64: String,
    password: String,
    response_b64: String,
    challenge_b64: String,
    login_id: String,
    username: String,
    device_id: String,
    mldsa_seed_b64: String,
    ed25519_sk_b64: String,
) -> Result<LoginProofResult, CryptoError> {
    let state = ClientLogin::<SealbookCipherSuite>::deserialize(&unb64(&state_b64)?)
        .map_err(|e| CryptoError::General { msg: e.to_string() })?;
    let finished = client_login_finish(state, password.as_bytes(), &unb64(&response_b64)?)
        .map_err(|e| CryptoError::General { msg: e.to_string() })?;
    let challenge_bytes = unb64(&challenge_b64)?;
    if challenge_bytes.len() != 32 {
        return Err(CryptoError::General {
            msg: "challenge must be 32 bytes".into(),
        });
    }
    let mut challenge = [0u8; 32];
    challenge.copy_from_slice(&challenge_bytes);
    let secrets = DeviceSigningSecrets {
        mldsa_seed: unb64(&mldsa_seed_b64)?,
        ed25519_sk: unb64(&ed25519_sk_b64)?,
    };
    let transcript = login_transcript(
        parse_uuid(&login_id)?,
        &username,
        parse_uuid(&device_id)?,
        &finished.message,
        &challenge,
    );
    let sig = sign(&secrets, &transcript)?;
    Ok(LoginProofResult {
        finalization: b64(&finished.message),
        mldsa: b64(&sig.mldsa),
        ed25519: b64(&sig.ed25519),
    })
}

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
    let oid = parse_uuid(&object_id)?;
    let cid = parse_uuid(&collection_id)?;
    let nonce_bytes = unb64(&nonce_b64)?;
    if nonce_bytes.len() != 24 {
        return Err(CryptoError::General {
            msg: "nonce must be 24 bytes".into(),
        });
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&nonce_bytes);
    let aad = object_aad(oid.as_bytes(), cid.as_bytes());
    let plain = decrypt_object(
        &ck_from_b64(&ck_b64)?,
        &EncryptedObject {
            nonce,
            ciphertext: unb64(&ciphertext_b64)?,
            padded_size: padded_size as usize,
        },
        &aad,
    )?;
    String::from_utf8(plain).map_err(|e| CryptoError::General { msg: e.to_string() })
}

// ── Device Creation ──

#[derive(uniffi::Record)]
pub struct DeviceResult {
    pub device_id: String,
    pub hpke_sk: String,
    pub hpke_pk: String,
    pub mldsa_seed: String,
    pub mldsa_pk: String,
    pub ed25519_sk: String,
    pub ed25519_pk: String,
    pub enrollment_mldsa: String,
    pub enrollment_ed25519: String,
}

#[uniffi::export]
pub fn create_device() -> Result<DeviceResult, CryptoError> {
    let (hpke_sk, hpke_pk) = generate_device_hpke()?;
    let (sign_sk, sign_pk) = generate_device_signing()?;
    let device_id = Uuid::new_v4();
    let transcript = enrollment_transcript(
        device_id,
        &sign_pk.mldsa_pk,
        &sign_pk.ed25519_pk,
        &hpke_pk.0,
    );
    let sig = sign(&sign_sk, &transcript)?;
    Ok(DeviceResult {
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
}

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

#[uniffi::export]
pub fn unwrap_phrase_ck(
    phrase: String,
    nonce_b64: String,
    wrapped_ck_b64: String,
) -> Result<String, CryptoError> {
    let entropy = entropy_from_phrase(&phrase)?;
    let nonce_bytes = unb64(&nonce_b64)?;
    if nonce_bytes.len() != 24 {
        return Err(CryptoError::General {
            msg: "nonce must be 24 bytes".into(),
        });
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&nonce_bytes);
    let key = unwrap_for_phrase(
        &entropy,
        &RecoveryWrap {
            nonce,
            ciphertext: unb64(&wrapped_ck_b64)?,
            ciphersuite: PHRASE_CIPHERSUITE.to_string(),
        },
    )?;
    Ok(b64(key.as_bytes()))
}

#[derive(uniffi::Record)]
pub struct PhraseRecoveryResult {
    pub mldsa_pk: String,
    pub ed25519_pk: String,
    pub lookup_id: String,
    pub scheme: String,
}

/// The opaque handle used to look up a phrase key wrap. Safe to send before a
/// recovery proof, unlike the verification keys.
#[uniffi::export]
pub fn phrase_lookup_id_b64(phrase: String) -> Result<String, CryptoError> {
    let entropy = entropy_from_phrase(&phrase)?;
    Ok(b64(&phrase_lookup_id(&entropy)?))
}

/// The hybrid recovery material to register for a phrase.
#[uniffi::export]
pub fn phrase_recovery_material(phrase: String) -> Result<PhraseRecoveryResult, CryptoError> {
    let entropy = entropy_from_phrase(&phrase)?;
    let public = phrase_recovery_public(&entropy)?;
    Ok(PhraseRecoveryResult {
        mldsa_pk: b64(&public.mldsa_pk),
        ed25519_pk: b64(&public.ed25519_pk),
        lookup_id: b64(&phrase_lookup_id(&entropy)?),
        scheme: PHRASE_SCHEME.to_string(),
    })
}

#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn phrase_recovery_proof(
    phrase: String,
    username: String,
    recovery_id: String,
    challenge_b64: String,
    device_id: String,
    mldsa_pk_b64: String,
    ed25519_pk_b64: String,
    hpke_pk_b64: String,
) -> Result<DualSigResult, CryptoError> {
    let entropy = entropy_from_phrase(&phrase)?;
    let transcript = phrase_recovery_transcript(
        &username,
        parse_uuid(&recovery_id)?,
        &unb64(&challenge_b64)?,
        parse_uuid(&device_id)?,
        &unb64(&mldsa_pk_b64)?,
        &unb64(&ed25519_pk_b64)?,
        &unb64(&hpke_pk_b64)?,
    );
    let proof = sign_phrase_recovery(&entropy, &transcript)?;
    Ok(DualSigResult {
        mldsa: b64(&proof.mldsa),
        ed25519: b64(&proof.ed25519),
    })
}

// ── Pair Grant Signing ──

#[derive(uniffi::Record)]
pub struct DualSigResult {
    pub mldsa: String,
    pub ed25519: String,
}

#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn pair_grant_sign(
    mldsa_seed_b64: String,
    ed25519_sk_b64: String,
    pair_id: String,
    approver_device_id: String,
    new_device_id: String,
    mldsa_pk_b64: String,
    ed25519_pk_b64: String,
    hpke_pk_b64: String,
    confirm: String,
) -> Result<DualSigResult, CryptoError> {
    let secrets = DeviceSigningSecrets {
        mldsa_seed: unb64(&mldsa_seed_b64)?,
        ed25519_sk: unb64(&ed25519_sk_b64)?,
    };
    let t = pair_grant_transcript(
        parse_uuid(&pair_id)?,
        parse_uuid(&approver_device_id)?,
        parse_uuid(&new_device_id)?,
        &unb64(&mldsa_pk_b64)?,
        &unb64(&ed25519_pk_b64)?,
        &unb64(&hpke_pk_b64)?,
        &confirm,
    );
    let sig = sign(&secrets, &t)?;
    Ok(DualSigResult {
        mldsa: b64(&sig.mldsa),
        ed25519: b64(&sig.ed25519),
    })
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

#[derive(uniffi::Record)]
pub struct NewPhraseResult {
    pub phrase: String,
    pub phrase_nonce: String,
    pub phrase_wrapped_ck: String,
    pub phrase_mldsa_pk: String,
    pub phrase_ed25519_pk: String,
    pub phrase_lookup_id: String,
    pub phrase_scheme: String,
    pub phrase_ciphersuite: String,
}

/// A fresh recovery phrase, with the given collection key wrapped under it.
///
/// Every rotation issues one: the new key cannot be re-wrapped for the old phrase,
/// because no client holds the phrase itself.
#[uniffi::export]
pub fn generate_new_phrase(ck_b64: String) -> Result<NewPhraseResult, CryptoError> {
    let ck = ck_from_b64(&ck_b64)?;
    let (phrase, entropy) = generate_phrase()?;
    let wrap = wrap_for_phrase(&entropy, &ck)?;
    let recovery = phrase_recovery_public(&entropy)?;
    Ok(NewPhraseResult {
        phrase,
        phrase_nonce: b64(&wrap.nonce),
        phrase_wrapped_ck: b64(&wrap.ciphertext),
        phrase_mldsa_pk: b64(&recovery.mldsa_pk),
        phrase_ed25519_pk: b64(&recovery.ed25519_pk),
        phrase_lookup_id: b64(&phrase_lookup_id(&entropy)?),
        phrase_scheme: PHRASE_SCHEME.to_string(),
        phrase_ciphersuite: PHRASE_CIPHERSUITE.to_string(),
    })
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

#[derive(uniffi::Record)]
pub struct SignedManifest {
    pub manifest_seq: u64,
    pub key_epoch: u64,
    pub latest_revision: u64,
    pub object_count: u64,
    pub digest: String,
    pub device_id: String,
    pub signature: DualSigResult,
}

/// Signs a manifest for the state a write produces.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn manifest_sign(
    mldsa_seed_b64: String,
    ed25519_sk_b64: String,
    collection_id: String,
    device_id: String,
    manifest_seq: u64,
    key_epoch: u64,
    latest_revision: u64,
    entries: Vec<ManifestEntryIn>,
) -> Result<SignedManifest, CryptoError> {
    let digest_entries = manifest_entries(&entries)?;
    let digest = manifest_digest(&digest_entries);
    let transcript = manifest_transcript(
        parse_uuid(&collection_id)?,
        manifest_seq,
        key_epoch,
        latest_revision,
        digest_entries.len() as u64,
        &digest,
    );
    let secrets = DeviceSigningSecrets {
        mldsa_seed: unb64(&mldsa_seed_b64)?,
        ed25519_sk: unb64(&ed25519_sk_b64)?,
    };
    let sig = sign(&secrets, &transcript)?;
    Ok(SignedManifest {
        manifest_seq,
        key_epoch,
        latest_revision,
        object_count: digest_entries.len() as u64,
        digest: b64(&digest),
        device_id,
        signature: DualSigResult {
            mldsa: b64(&sig.mldsa),
            ed25519: b64(&sig.ed25519),
        },
    })
}

/// Digest of a whole collection, for a manifest.
#[uniffi::export]
pub fn manifest_digest_of(entries: Vec<ManifestEntryIn>) -> Result<String, CryptoError> {
    Ok(b64(&manifest_digest(&manifest_entries(&entries)?)))
}

/// Checks a served manifest against the entries it is supposed to describe.
///
/// An error here means the server served something no device signed for.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn manifest_verify(
    signer_mldsa_pk_b64: String,
    signer_ed25519_pk_b64: String,
    collection_id: String,
    manifest_seq: u64,
    key_epoch: u64,
    latest_revision: u64,
    entries: Vec<ManifestEntryIn>,
    expected_digest_b64: String,
    signature: DualSigResult,
) -> Result<(), CryptoError> {
    let digest_entries = manifest_entries(&entries)?;
    let digest = manifest_digest(&digest_entries);
    if digest != digest32(&expected_digest_b64)? {
        return Err(CryptoError::General {
            msg: "the objects served do not match the signed manifest; an object may have been \
                  withheld, rolled back or substituted"
                .into(),
        });
    }
    let transcript = manifest_transcript(
        parse_uuid(&collection_id)?,
        manifest_seq,
        key_epoch,
        latest_revision,
        digest_entries.len() as u64,
        &digest,
    );
    verify(
        &DeviceSigningPublic {
            mldsa_pk: unb64(&signer_mldsa_pk_b64)?,
            ed25519_pk: unb64(&signer_ed25519_pk_b64)?,
        },
        &transcript,
        &DualSignature {
            mldsa: unb64(&signature.mldsa)?,
            ed25519: unb64(&signature.ed25519)?,
        },
    )
    .map_err(|_| CryptoError::General {
        msg: "manifest signature does not verify".into(),
    })
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

/// Signs a device roster with the recovery phrase's key, for a recovery.
#[uniffi::export]
pub fn roster_seal_phrase(
    collection_id: String,
    roster_seq: u64,
    key_epoch: u64,
    devices_json: String,
    phrase: String,
    ck_b64: String,
) -> Result<String, CryptoError> {
    let entropy = entropy_from_phrase(&phrase)?;
    let (secrets, public) = phrase_recovery_keys(&entropy)?;
    let roster = RosterBody::seal(
        parse_uuid(&collection_id)?,
        roster_seq,
        key_epoch,
        devices_from(&devices_json)?,
        public.mldsa_pk,
        public.ed25519_pk,
        RosterSignerBody::Phrase,
        &secrets,
        &ck_from_b64(&ck_b64)?,
    )?;
    serde_json::to_string(&roster).map_err(roster_err)
}

#[derive(uniffi::Record)]
pub struct VerifiedRoster {
    /// The verified roster in wire format. Its devices are the only ones to wrap
    /// the collection key for or accept manifest signatures from.
    pub roster_json: String,
    /// The pin to store in place of the old one.
    pub pin_seq: u64,
    pub pin_transcript: String,
}

/// Verifies a served roster history from this device's pin.
///
/// `pin_seq` 0 means nothing is pinned yet, in which case `ck_b64` and
/// `key_epoch` must be the current collection key and its epoch.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn roster_verify(
    collection_id: String,
    pin_seq: u64,
    pin_transcript_b64: String,
    rosters_json: String,
    ck_b64: Option<String>,
    key_epoch: u64,
    self_device_id: String,
) -> Result<VerifiedRoster, CryptoError> {
    let collection = parse_uuid(&collection_id)?;
    let pin = if pin_seq == 0 {
        None
    } else {
        Some(RosterPin {
            roster_seq: pin_seq,
            transcript: digest32(&pin_transcript_b64)?,
        })
    };
    let chain: Vec<RosterBody> = serde_json::from_str(&rosters_json).map_err(roster_err)?;
    let key = ck_b64.as_deref().map(ck_from_b64).transpose()?;
    let latest = RosterBody::verify_chain(
        collection,
        pin,
        chain,
        key.as_ref().map(|key| (key, key_epoch)),
        parse_uuid(&self_device_id)?,
    )?;
    let pin = latest.pin(collection);
    Ok(VerifiedRoster {
        roster_json: serde_json::to_string(&latest).map_err(roster_err)?,
        pin_seq: pin.roster_seq,
        pin_transcript: b64(&pin.transcript),
    })
}

#[derive(uniffi::Record)]
pub struct AccountOpPayload {
    pub new_username: Option<String>,
    pub upload: Option<String>,
    pub kdf_salt: Option<String>,
    pub recovery_nonce: Option<String>,
    pub recovery_wrapped_ck: Option<String>,
    pub recovery_ciphersuite: Option<String>,
}

/// Signs an account mutation: `"username"`, `"password"` or `"delete"`.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn account_op_sign(
    mldsa_seed_b64: String,
    ed25519_sk_b64: String,
    op: String,
    challenge_id: String,
    challenge_b64: String,
    account_id: String,
    device_id: String,
    payload: AccountOpPayload,
) -> Result<DualSigResult, CryptoError> {
    fn need(value: &Option<String>, field: &str) -> Result<String, CryptoError> {
        value.clone().ok_or_else(|| CryptoError::General {
            msg: format!("{field} is required for this operation"),
        })
    }
    let digest = match op.as_str() {
        "username" => username_change_payload(
            &need(&payload.new_username, "new_username")?,
            &unb64(&need(&payload.upload, "upload")?)?,
        ),
        "password" => password_change_payload(
            &unb64(&need(&payload.upload, "upload")?)?,
            &unb64(&need(&payload.kdf_salt, "kdf_salt")?)?,
            &unb64(&need(&payload.recovery_nonce, "recovery_nonce")?)?,
            &unb64(&need(&payload.recovery_wrapped_ck, "recovery_wrapped_ck")?)?,
            &need(&payload.recovery_ciphersuite, "recovery_ciphersuite")?,
        ),
        "delete" => delete_account_payload(),
        other => {
            return Err(CryptoError::General {
                msg: format!("unknown account operation {other}"),
            })
        }
    };
    let transcript = account_op_transcript(
        &op,
        parse_uuid(&challenge_id)?,
        &unb64(&challenge_b64)?,
        &account_id,
        parse_uuid(&device_id)?,
        &digest,
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
