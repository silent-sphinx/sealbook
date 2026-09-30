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
    open_login_challenge, pair_confirmation, pair_grant_transcript, password_change_payload,
    phrase_lookup_id, phrase_recovery_public, phrase_recovery_transcript, rotated_objects_digest,
    rotation_recovery_payload, sign, sign_phrase_recovery, unwrap_collection_key,
    unwrap_for_device, unwrap_for_phrase, username_change_payload, verify, wrap_collection_key,
    wrap_for_device, wrap_for_phrase, CollectionKey, DeviceHpkePublic, DeviceHpkeSecret,
    DeviceHpkeWrap, DeviceSigningPublic, DeviceSigningSecrets, DualSignature, EncryptedObject,
    ManifestDigestEntry, ObjectDigestEntry, RecoveryWrap, WrapDigestEntry, PHRASE_CIPHERSUITE,
    PHRASE_SCHEME, RECOVERY_CIPHERSUITE, XWING_CIPHERSUITE,
};
use serde::{Deserialize, Serialize};
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
struct B64Pair {
    request: String,
    state: String,
}

#[wasm_bindgen]
pub fn opaque_register_start(password: &str) -> Result<String, JsError> {
    let (request, state) = client_register_start(password.as_bytes()).map_err(js_err)?;
    serde_json::to_string(&B64Pair {
        request: b64(&request),
        state: b64(&state.serialize()),
    })
    .map_err(js_err)
}

#[wasm_bindgen]
pub fn opaque_register_finish(
    state_b64: &str,
    password: &str,
    response_b64: &str,
) -> Result<String, JsError> {
    let state = ClientRegistration::<SealbookCipherSuite>::deserialize(&unb64(state_b64)?)
        .map_err(|err| JsError::new(&err.to_string()))?;
    let upload = client_register_finish(state, password.as_bytes(), &unb64(response_b64)?)
        .map_err(js_err)?;
    Ok(b64(&upload))
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
pub fn opaque_login_start(password: &str) -> Result<String, JsError> {
    let (request, state) = client_login_start(password.as_bytes()).map_err(js_err)?;
    serde_json::to_string(&B64Pair {
        request: b64(&request),
        state: b64(&state.serialize()),
    })
    .map_err(js_err)
}

#[derive(Serialize)]
struct LoginProof {
    challenge: String,
    mldsa: String,
    ed25519: String,
}

#[derive(Serialize)]
struct LoginFinishProof {
    finalization: String,
    mldsa: String,
    ed25519: String,
}

/// Step 2 of login: open the sealed challenge and sign it together with the
/// OPAQUE request. The server releases no credential response until this proof
/// verifies, which is what keeps the password out of reach of an attacker who
/// can break Ristretto255.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn login_start_proof(
    hpke_sk_b64: &str,
    challenge_enc_b64: &str,
    challenge_ct_b64: &str,
    challenge_id: &str,
    username: &str,
    device_id: &str,
    request_b64: &str,
    mldsa_seed_b64: &str,
    ed25519_sk_b64: &str,
) -> Result<String, JsError> {
    let challenge = open_login_challenge(
        &DeviceHpkeSecret::from_bytes(unb64(hpke_sk_b64)?),
        &DeviceHpkeWrap {
            enc: unb64(challenge_enc_b64)?,
            ciphertext: unb64(challenge_ct_b64)?,
            ciphersuite: XWING_CIPHERSUITE,
        },
    )
    .map_err(js_err)?;
    let secrets = DeviceSigningSecrets {
        mldsa_seed: unb64(mldsa_seed_b64)?,
        ed25519_sk: unb64(ed25519_sk_b64)?,
    };
    let transcript = login_start_transcript(
        parse_uuid(challenge_id)?,
        username,
        parse_uuid(device_id)?,
        &challenge,
        &unb64(request_b64)?,
    );
    let sig = sign(&secrets, &transcript).map_err(js_err)?;
    serde_json::to_string(&LoginProof {
        challenge: b64(&challenge),
        mldsa: b64(&sig.mldsa),
        ed25519: b64(&sig.ed25519),
    })
    .map_err(js_err)
}

/// Step 3 of login. `challenge_b64` is the value returned by
/// [`login_start_proof`], so the challenge is opened only once.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn opaque_login_finish(
    state_b64: &str,
    password: &str,
    response_b64: &str,
    challenge_b64: &str,
    login_id: &str,
    username: &str,
    device_id: &str,
    mldsa_seed_b64: &str,
    ed25519_sk_b64: &str,
) -> Result<String, JsError> {
    let state = ClientLogin::<SealbookCipherSuite>::deserialize(&unb64(state_b64)?)
        .map_err(|err| JsError::new(&err.to_string()))?;
    let finished =
        client_login_finish(state, password.as_bytes(), &unb64(response_b64)?).map_err(js_err)?;
    let challenge_bytes = unb64(challenge_b64)?;
    if challenge_bytes.len() != 32 {
        return Err(JsError::new("challenge length"));
    }
    let mut challenge = [0u8; 32];
    challenge.copy_from_slice(&challenge_bytes);
    let secrets = DeviceSigningSecrets {
        mldsa_seed: unb64(mldsa_seed_b64)?,
        ed25519_sk: unb64(ed25519_sk_b64)?,
    };
    let transcript = login_transcript(
        parse_uuid(login_id)?,
        username,
        parse_uuid(device_id)?,
        &finished.message,
        &challenge,
    );
    let sig = sign(&secrets, &transcript).map_err(js_err)?;
    serde_json::to_string(&LoginFinishProof {
        finalization: b64(&finished.message),
        mldsa: b64(&sig.mldsa),
        ed25519: b64(&sig.ed25519),
    })
    .map_err(js_err)
}

#[derive(Deserialize)]
struct WrapIn {
    recipient_kind: String,
    recipient_id: String,
    hpke_enc: String,
    wrapped_ck: String,
    ciphersuite: String,
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
    String::from_utf8(plain).map_err(|err| JsError::new(&err.to_string()))
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

#[wasm_bindgen]
pub fn unwrap_phrase(
    phrase: &str,
    nonce_b64: &str,
    wrapped_ck_b64: &str,
) -> Result<String, JsError> {
    let entropy = entropy_from_phrase(phrase).map_err(js_err)?;
    let nonce_bytes = unb64(nonce_b64)?;
    if nonce_bytes.len() != 24 {
        return Err(JsError::new("nonce length"));
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&nonce_bytes);
    let key = unwrap_for_phrase(
        &entropy,
        &RecoveryWrap {
            nonce,
            ciphertext: unb64(wrapped_ck_b64)?,
            ciphersuite: PHRASE_CIPHERSUITE.to_string(),
        },
    )
    .map_err(js_err)?;
    Ok(b64(key.as_bytes()))
}

/// The opaque handle used to look up a phrase key wrap. Safe to send before a
/// recovery proof, unlike the verification keys.
#[wasm_bindgen]
pub fn phrase_lookup_id_b64(phrase: &str) -> Result<String, JsError> {
    let entropy = entropy_from_phrase(phrase).map_err(js_err)?;
    Ok(b64(&phrase_lookup_id(&entropy).map_err(js_err)?))
}

/// The hybrid recovery material to register for a phrase.
#[wasm_bindgen]
pub fn phrase_recovery_json(phrase: &str) -> Result<String, JsError> {
    let entropy = entropy_from_phrase(phrase).map_err(js_err)?;
    let public = phrase_recovery_public(&entropy).map_err(js_err)?;
    serde_json::to_string(&serde_json::json!({
        "mldsa_pk": b64(&public.mldsa_pk),
        "ed25519_pk": b64(&public.ed25519_pk),
        "lookup_id": b64(&phrase_lookup_id(&entropy).map_err(js_err)?),
        "scheme": PHRASE_SCHEME,
    }))
    .map_err(js_err)
}

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn phrase_recovery_proof_json(
    phrase: &str,
    username: &str,
    recovery_id: &str,
    challenge_b64: &str,
    device_id: &str,
    mldsa_pk_b64: &str,
    ed25519_pk_b64: &str,
    hpke_pk_b64: &str,
) -> Result<String, JsError> {
    let entropy = entropy_from_phrase(phrase).map_err(js_err)?;
    let challenge = unb64(challenge_b64)?;
    let transcript = phrase_recovery_transcript(
        username,
        parse_uuid(recovery_id)?,
        &challenge,
        parse_uuid(device_id)?,
        &unb64(mldsa_pk_b64)?,
        &unb64(ed25519_pk_b64)?,
        &unb64(hpke_pk_b64)?,
    );
    let proof = sign_phrase_recovery(&entropy, &transcript).map_err(js_err)?;
    serde_json::to_string(&serde_json::json!({
        "mldsa": b64(&proof.mldsa),
        "ed25519": b64(&proof.ed25519),
    }))
    .map_err(js_err)
}

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn pair_grant_sign(
    mldsa_seed_b64: &str,
    ed25519_sk_b64: &str,
    pair_id: &str,
    approver_device_id: &str,
    new_device_id: &str,
    mldsa_pk_b64: &str,
    ed25519_pk_b64: &str,
    hpke_pk_b64: &str,
    confirm: &str,
) -> Result<String, JsError> {
    let secrets = DeviceSigningSecrets {
        mldsa_seed: unb64(mldsa_seed_b64)?,
        ed25519_sk: unb64(ed25519_sk_b64)?,
    };
    let t = pair_grant_transcript(
        parse_uuid(pair_id)?,
        parse_uuid(approver_device_id)?,
        parse_uuid(new_device_id)?,
        &unb64(mldsa_pk_b64)?,
        &unb64(ed25519_pk_b64)?,
        &unb64(hpke_pk_b64)?,
        confirm,
    );
    let sig = sign(&secrets, &t).map_err(js_err)?;
    serde_json::to_string(&serde_json::json!({
        "mldsa": b64(&sig.mldsa),
        "ed25519": b64(&sig.ed25519),
    }))
    .map_err(js_err)
}

#[wasm_bindgen]
pub fn pair_confirmation_code(
    pair_id: &str,
    device_id: &str,
    mldsa_pk_b64: &str,
    ed25519_pk_b64: &str,
    hpke_pk_b64: &str,
) -> Result<String, JsError> {
    Ok(pair_confirmation(
        parse_uuid(pair_id)?,
        parse_uuid(device_id)?,
        &unb64(mldsa_pk_b64)?,
        &unb64(ed25519_pk_b64)?,
        &unb64(hpke_pk_b64)?,
    ))
}

#[wasm_bindgen]
pub fn wrap_ck_for_password(ck_b64: &str, password: &str) -> Result<String, JsError> {
    let ck = ck_from_b64(ck_b64)?;
    let salt = generate_kdf_salt();
    let wrap = wrap_collection_key(password.as_bytes(), &salt, &ck).map_err(js_err)?;
    serde_json::to_string(&serde_json::json!({
        "kdf_salt": b64(&salt),
        "recovery_nonce": b64(&wrap.nonce),
        "recovery_wrapped_ck": b64(&wrap.ciphertext),
        "recovery_ciphersuite": RECOVERY_CIPHERSUITE,
    }))
    .map_err(js_err)
}

#[wasm_bindgen]
pub fn generate_new_phrase(ck_b64: &str) -> Result<String, JsError> {
    let ck = ck_from_b64(ck_b64)?;
    let (phrase, entropy) = generate_phrase().map_err(js_err)?;
    let wrap = wrap_for_phrase(&entropy, &ck).map_err(js_err)?;
    let recovery = phrase_recovery_public(&entropy).map_err(js_err)?;
    serde_json::to_string(&serde_json::json!({
        "phrase": phrase,
        "phrase_nonce": b64(&wrap.nonce),
        "phrase_wrapped_ck": b64(&wrap.ciphertext),
        "phrase_mldsa_pk": b64(&recovery.mldsa_pk),
        "phrase_ed25519_pk": b64(&recovery.ed25519_pk),
        "phrase_lookup_id": b64(&phrase_lookup_id(&entropy).map_err(js_err)?),
        "phrase_scheme": PHRASE_SCHEME,
        "phrase_ciphersuite": PHRASE_CIPHERSUITE,
    }))
    .map_err(js_err)
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

/// Checks a served manifest against the entries it is supposed to describe.
///
/// Returns nothing on success and throws with a reason on failure. A failure here
/// means the server served something no device signed for: an object withheld,
/// rolled back or substituted. It is never transient.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn manifest_verify(
    signer_mldsa_pk_b64: &str,
    signer_ed25519_pk_b64: &str,
    collection_id: &str,
    manifest_seq: u64,
    key_epoch: u64,
    latest_revision: u64,
    entries_json: &str,
    expected_digest_b64: &str,
    mldsa_sig_b64: &str,
    ed25519_sig_b64: &str,
) -> Result<(), JsError> {
    let entries = manifest_entries(entries_json)?;
    let digest = manifest_digest(&entries);
    if digest != digest32(expected_digest_b64)? {
        return Err(JsError::new(
            "the objects served do not match the signed manifest; an object may have been \
             withheld, rolled back or substituted",
        ));
    }
    let transcript = manifest_transcript(
        parse_uuid(collection_id)?,
        manifest_seq,
        key_epoch,
        latest_revision,
        entries.len() as u64,
        &digest,
    );
    verify(
        &DeviceSigningPublic {
            mldsa_pk: unb64(signer_mldsa_pk_b64)?,
            ed25519_pk: unb64(signer_ed25519_pk_b64)?,
        },
        &transcript,
        &DualSignature {
            mldsa: unb64(mldsa_sig_b64)?,
            ed25519: unb64(ed25519_sig_b64)?,
        },
    )
    .map_err(|_| JsError::new("manifest signature does not verify"))
}

/// Signs an account mutation: `"username"`, `"password"` or `"delete"`.
///
/// The payload digest is computed here from the actual fields being sent, so a
/// signature always covers the change it accompanies.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn account_op_sign(
    mldsa_seed_b64: &str,
    ed25519_sk_b64: &str,
    op: &str,
    challenge_id: &str,
    challenge_b64: &str,
    account_id: &str,
    device_id: &str,
    payload_json: &str,
) -> Result<String, JsError> {
    #[derive(Deserialize)]
    struct UsernamePayload {
        new_username: String,
        upload: String,
    }
    #[derive(Deserialize)]
    struct PasswordPayload {
        upload: String,
        kdf_salt: String,
        recovery_nonce: String,
        recovery_wrapped_ck: String,
        recovery_ciphersuite: String,
    }
    let payload = match op {
        "username" => {
            let p: UsernamePayload = serde_json::from_str(payload_json).map_err(js_err)?;
            username_change_payload(&p.new_username, &unb64(&p.upload)?)
        }
        "password" => {
            let p: PasswordPayload = serde_json::from_str(payload_json).map_err(js_err)?;
            password_change_payload(
                &unb64(&p.upload)?,
                &unb64(&p.kdf_salt)?,
                &unb64(&p.recovery_nonce)?,
                &unb64(&p.recovery_wrapped_ck)?,
                &p.recovery_ciphersuite,
            )
        }
        "delete" => delete_account_payload(),
        other => return Err(JsError::new(&format!("unknown account operation {other}"))),
    };
    let transcript = account_op_transcript(
        op,
        parse_uuid(challenge_id)?,
        &unb64(challenge_b64)?,
        account_id,
        parse_uuid(device_id)?,
        &payload,
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
