//! Registering an account, signing in, recovering onto a fresh device, and the
//! account operations those make possible.
//!
//! All four flows are multi-round, and every round carries a decision the three
//! clients had each been making for themselves: which username to send, whether
//! a phrase typed in capitals counts, whether the collection the server echoes
//! is the one the genesis roster was signed over, and which key wrap to open.
//! Those are the decisions here.
//!
//! Each step returns an [`AuthRequest`]: a path and a JSON body for the host to
//! post. Core never sees the server URL or the bearer token, and nothing it
//! signs depends on either.
//!
//! The OPAQUE client state crosses back to the host as base64 between rounds.
//! It is password-equivalent for the length of one exchange, so a host keeps it
//! in memory and never writes it down.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sealbook_crypto::opaque::{
    client_login_finish, client_login_start, client_register_finish, client_register_start,
    ClientLogin, ClientRegistration, SealbookCipherSuite,
};
use sealbook_crypto::{
    account_op_transcript, delete_account_payload, enrollment_transcript, entropy_from_phrase,
    generate_device_hpke, generate_device_signing, generate_kdf_salt, generate_phrase,
    login_start_transcript, login_transcript, open_login_challenge, password_change_payload,
    phrase_lookup_id, phrase_recovery_keys, phrase_recovery_public, phrase_recovery_transcript,
    recovery_password_payload, sign, sign_phrase_recovery, unwrap_collection_key,
    unwrap_for_device, unwrap_for_phrase, username_change_payload, wrap_collection_key,
    wrap_for_device, wrap_for_phrase, CollectionKey, DeviceHpkePublic, DeviceHpkeSecret,
    DeviceHpkeWrap, DeviceSigningSecrets, RecoveryWrap, PHRASE_CIPHERSUITE, PHRASE_SCHEME,
    RECOVERY_CIPHERSUITE, XWING_CIPHERSUITE,
};
use sealbook_protocol::{
    valid_username, AccountChallengeResponse, ChangePasswordRequest, ChangePasswordStartRequest,
    ChangePasswordStartResponse, ChangeUsernameRequest, DeleteAccountRequest, DevicePublicKeys,
    DualSignatureBody, KeyWrapBody, LoginChallengeRequest, LoginChallengeResponse,
    LoginFinishRequest, LoginFinishResponse, LoginStartRequest, LoginStartResponse, ManifestBody,
    PhraseRecoveryBody, RecoverFinishRequest, RecoverFinishResponse, RecoverStartRequest,
    RecoverStartResponse, RegisterFinishRequest, RegisterFinishResponse, RegisterStartRequest,
    RegisterStartResponse, RosterBody, RosterSignerBody,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::manifest::{manifest_sign, ManifestContext, ManifestPlan};
use crate::roster::{roster_accept_sealed, CoreDevice, CoreRoster, CoreRosterPin, RosterContext};
use crate::{CoreDeviceState, CoreError, CoreSession};

/// Why an authentication flow cannot go on.
///
/// Typed rather than free text for the same reason pairing's refusals are: each
/// is something to tell the user, and each host words it its own way.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[serde(tag = "refusal")]
pub enum AuthRefusal {
    #[error(
        "a username is 3 to 64 characters of letters, digits, dot, dash or underscore, \
         and this one is not"
    )]
    Username,
    #[error("that is not a 24-word recovery phrase")]
    Phrase,
    /// The phrase did not open the account's wrap. A lookup that matched nothing
    /// is answered with a decoy, so this is the only thing a recovery can say
    /// about either a mistyped phrase or an account that does not exist, and it
    /// has to be the same answer for both.
    #[error("that recovery phrase does not open this account")]
    PhraseMismatch,
    #[error("the server sent no device roster to recover onto")]
    NoRoster,
    #[error("the server's recovery challenge is not the 32 bytes a proof is signed over")]
    Challenge,
    /// The server answered with a different collection than the one the genesis
    /// roster and the first manifest were signed over, so neither verifies
    /// against what it says it stored.
    #[error("this device asked for collection {chose} and the server answered with {served}")]
    CollectionMoved {
        #[cfg_attr(feature = "wasm", tsify(type = "string"))]
        chose: Uuid,
        #[cfg_attr(feature = "wasm", tsify(type = "string"))]
        served: Uuid,
    },
    /// Login returned no wrap this device can open. Its own wrap being gone is
    /// what a revocation looks like from here.
    #[error("this device has no collection key wrap in the account any more")]
    NoKeyWrap,
}

/// An OPAQUE round in flight: the message to send, and the client state to hand
/// back to core along with the server's answer.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct OpaqueStart {
    pub request: String,
    pub state: String,
}

/// A request core has decided on, for the host to post.
///
/// A JSON body rather than [`HttpRequest`](crate::HttpRequest)'s bytes, because
/// all three hosts post text here and two of them would otherwise copy a byte
/// array across the binding for every round.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AuthRequest {
    /// Server-relative, leading slash.
    pub path: String,
    pub body: String,
}

/// A device's keys, with the secrets base64 as every host stores them.
///
/// No `Debug`: it carries the signing and HPKE secrets.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreDeviceSecrets {
    pub device: CoreDevice,
    pub hpke_sk: String,
    pub mldsa_seed: String,
    pub ed25519_sk: String,
}

/// Everything a registration mints before it says anything to the server.
///
/// The collection id is chosen here, like the device id, so the genesis roster
/// and the first manifest can be signed over it before the account exists.
///
/// No `Debug`: it carries the collection key and the recovery phrase.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RegisterIdentity {
    pub device: CoreDeviceSecrets,
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub collection_id: Uuid,
    pub collection_key: String,
    pub kdf_salt: String,
    /// The 24 words to show the user once. Nothing can re-derive them.
    pub phrase: String,
}

/// The register finish request, and the anchor it leaves this device on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Registering {
    pub request: AuthRequest,
    /// The genesis roster, to pin before the first roster fetch. A device that
    /// registered and then trusted whatever roster it was served next would have
    /// no device history at all.
    pub pin: CoreRosterPin,
}

/// Login step 2, with the challenge this device opened.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct LoginStarting {
    pub request: AuthRequest,
    /// base64 of the opened challenge, which step 3 signs over as well. Carried
    /// so the sealed challenge is opened exactly once.
    pub challenge: String,
}

/// What a completed login hands the host.
///
/// No `Debug`: it carries the collection key and the session token.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct LoggedIn {
    /// The persisted state with the account, collection, salt and token the
    /// server just confirmed, for the host to store in place of its own.
    pub state: CoreDeviceState,
    pub collection_key: String,
    pub key_epoch: u64,
    /// True when a recovery enrolled a device and the key has still not been
    /// rotated, so the phrase used then, and any copy of it, still opens this
    /// vault. The server refuses writes until the rotation lands.
    pub recovery_pending: bool,
}

/// What the first round of a recovery established, checked against the phrase.
///
/// No `Debug`: it carries the collection key the phrase opened.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RecoverStarted {
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub recovery_id: Uuid,
    pub challenge: String,
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub collection_id: Uuid,
    pub collection_key: String,
    /// The roster the account is on, verified under the key the phrase opened.
    pub roster: CoreRoster,
    pub opaque_response: String,
    /// That roster in wire form, for the step that signs the next one.
    pub roster_json: String,
}

/// The recover finish request, and what it leaves this device holding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Recovering {
    pub request: AuthRequest,
    /// The roster step this device signed with the phrase, to pin: its first
    /// fetch then has to be a step from a roster it has already checked.
    pub pin: CoreRosterPin,
    pub kdf_salt: String,
}

/// What a password change start established.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PasswordChangeStarted {
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub password_change_id: Uuid,
    /// Doubles as the account-operation challenge, so a password change stays
    /// two round trips rather than three.
    pub challenge: String,
    pub opaque_response: String,
}

/// The password change request, and the salt it leaves the account on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PasswordChange {
    pub request: AuthRequest,
    pub kdf_salt: String,
}

// ── What the user typed ──

/// The username to send, which is the one the user typed without its
/// surrounding whitespace.
///
/// Trimmed because the server's `valid_username` rejects a space, so a trailing
/// one turned a plausible username into "invalid username" on two of the three
/// clients while the third quietly fixed it.
pub fn normalize_username(raw: &str) -> String {
    raw.trim().to_string()
}

/// The phrase to derive from: lowercase, single-spaced.
///
/// BIP-39 words are lowercase, so a phrase pasted with a capitalised first word
/// is one the word list cannot match. Two clients lowercased it and the third
/// told the user their own correct phrase was wrong.
pub fn normalize_phrase(raw: &str) -> String {
    raw.split_whitespace()
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .join(" ")
}

// ── OPAQUE rounds ──

/// Begins registering a password. Also the first round of a password change, a
/// username change and a recovery, each of which re-registers the verifier.
pub fn opaque_register_start(password: &str) -> Result<OpaqueStart, CoreError> {
    let (request, state) = client_register_start(password.as_bytes())?;
    Ok(OpaqueStart {
        request: encode(&request),
        state: encode(&state.serialize()),
    })
}

/// Finishes a registration, giving the verifier upload the server stores.
pub fn opaque_register_upload(
    state_b64: &str,
    password: &str,
    response_b64: &str,
) -> Result<String, CoreError> {
    let state =
        ClientRegistration::<SealbookCipherSuite>::deserialize(&decode(state_b64, "OPAQUE state")?)
            .map_err(|err| CoreError::malformed(format!("OPAQUE state is unreadable: {err}")))?;
    let upload = client_register_finish(
        state,
        password.as_bytes(),
        &decode(response_b64, "OPAQUE response")?,
    )?;
    Ok(encode(&upload))
}

/// Begins a login.
pub fn opaque_login_start(password: &str) -> Result<OpaqueStart, CoreError> {
    let (request, state) = client_login_start(password.as_bytes())?;
    Ok(OpaqueStart {
        request: encode(&request),
        state: encode(&state.serialize()),
    })
}

// ── Register ──

/// A new device's keys.
///
/// This and [`new_registration`] are the only places core draws randomness, and
/// each returns it for the host to persist. Both were a copy per binding crate
/// before, which is how two hosts came to generate the collection id and one did
/// not.
pub fn new_device() -> Result<CoreDeviceSecrets, CoreError> {
    let (hpke_sk, hpke_pk) = generate_device_hpke()?;
    let (sign_sk, sign_pk) = generate_device_signing()?;
    Ok(CoreDeviceSecrets {
        device: CoreDevice {
            device_id: Uuid::new_v4(),
            mldsa_pk: encode(&sign_pk.mldsa_pk),
            ed25519_pk: encode(&sign_pk.ed25519_pk),
            xwing_hpke_pk: encode(&hpke_pk.0),
        },
        hpke_sk: encode(hpke_sk.as_bytes()),
        mldsa_seed: encode(&sign_sk.mldsa_seed),
        ed25519_sk: encode(&sign_sk.ed25519_sk),
    })
}

/// Everything a registration mints: a device, a collection, a collection key, a
/// KDF salt and a recovery phrase.
pub fn new_registration() -> Result<RegisterIdentity, CoreError> {
    let (phrase, _entropy) = generate_phrase()?;
    Ok(RegisterIdentity {
        device: new_device()?,
        collection_id: Uuid::new_v4(),
        collection_key: encode(CollectionKey::generate().as_bytes()),
        kdf_salt: encode(&generate_kdf_salt()),
        phrase,
    })
}

/// The register start request.
pub fn register_start_request(
    username: &str,
    opaque_request_b64: &str,
) -> Result<AuthRequest, CoreError> {
    Ok(AuthRequest {
        path: "/v1/opaque/register/start".into(),
        body: serde_json::to_string(&RegisterStartRequest {
            username: checked_username(username)?,
            request: decode(opaque_request_b64, "OPAQUE request")?,
        })?,
    })
}

/// The OPAQUE response out of a register start, for the matching upload.
pub fn register_start_accept(body: &str) -> Result<String, CoreError> {
    let served: RegisterStartResponse = serde_json::from_str(body).map_err(|err| {
        CoreError::malformed(format!("the register start response is unreadable: {err}"))
    })?;
    Ok(encode(&served.response))
}

/// The register finish request: the genesis roster, the first manifest, and the
/// three wraps of the collection key.
///
/// The roster and the manifest are both signed before the account exists, so an
/// account has a device history and a signed manifest from the moment it does,
/// and no client is ever asked to accept an unsigned "your vault is empty".
///
/// The password gets a wrap of the collection key alongside the device's and the
/// phrase's, so the account can be opened on a device holding neither.
pub fn register_finish_request(
    username: &str,
    password: &str,
    upload_b64: &str,
    identity: &RegisterIdentity,
) -> Result<Registering, CoreError> {
    let username = checked_username(username)?;
    let key = CollectionKey::from_bytes(crate::roster::collection_key(&identity.collection_key)?);
    let keys = DevicePublicKeys::try_from(&identity.device.device)?;
    let secrets = identity.device.signing()?;
    let salt = decode(&identity.kdf_salt, "KDF salt")?;
    let entropy = phrase_entropy(&identity.phrase)?;

    let password_wrap = wrap_collection_key(password.as_bytes(), &salt, &key)?;
    let phrase_wrap = wrap_for_phrase(&entropy, &key)?;
    let device_wrap = wrap_for_device(&DeviceHpkePublic(keys.xwing_hpke_pk.clone()), &key)?;
    let phrase_public = phrase_recovery_public(&entropy)?;
    let phrase_recovery = PhraseRecoveryBody {
        mldsa_pk: phrase_public.mldsa_pk.clone(),
        ed25519_pk: phrase_public.ed25519_pk.clone(),
        lookup_id: phrase_lookup_id(&entropy)?.to_vec(),
        scheme: PHRASE_SCHEME.to_string(),
    };

    let roster = RosterBody::seal(
        identity.collection_id,
        1,
        1,
        vec![keys.clone()],
        phrase_public.mldsa_pk,
        phrase_public.ed25519_pk,
        RosterSignerBody::Device {
            device_id: keys.device_id,
        },
        &secrets,
        &key,
    )?;
    let roster_json = serde_json::to_string(&roster)?;
    let manifest = manifest_sign(
        &secrets,
        &ManifestContext {
            collection_id: identity.collection_id,
            device_id: keys.device_id,
            manifest_seq: 0,
        },
        &ManifestPlan {
            manifest_seq: 1,
            key_epoch: 1,
            latest_revision: 0,
        },
        &[],
    )?;
    let request = AuthRequest {
        path: "/v1/opaque/register/finish".into(),
        body: serde_json::to_string(&RegisterFinishRequest {
            username: username.clone(),
            upload: decode(upload_b64, "OPAQUE upload")?,
            kdf_salt: salt,
            device: keys.clone(),
            collection_id: identity.collection_id,
            enrollment_signature: enrollment_signature(&keys, &secrets)?,
            key_wraps: vec![
                device_key_wrap(keys.device_id, &device_wrap),
                KeyWrapBody {
                    recipient_kind: "recovery".into(),
                    recipient_id: username.clone(),
                    hpke_enc: password_wrap.nonce.to_vec(),
                    wrapped_ck: password_wrap.ciphertext,
                    ciphersuite: RECOVERY_CIPHERSUITE.into(),
                },
                KeyWrapBody {
                    recipient_kind: "phrase".into(),
                    recipient_id: username.clone(),
                    hpke_enc: phrase_wrap.nonce.to_vec(),
                    wrapped_ck: phrase_wrap.ciphertext,
                    ciphersuite: PHRASE_CIPHERSUITE.into(),
                },
            ],
            phrase_recovery,
            manifest: serde_json::from_str::<ManifestBody>(&manifest.manifest_json)?,
            roster,
        })?,
    };
    Ok(Registering {
        request,
        pin: sealed_pin(identity.collection_id, keys.device_id, &key, &roster_json)?,
    })
}

/// Reads the register finish response into the state this device persists.
///
/// Refuses a response naming a different collection: the genesis roster and the
/// first manifest are signed over the one this device chose, so an account built
/// on another id has nothing this device can verify.
pub fn register_accept(
    server: &str,
    username: &str,
    identity: &RegisterIdentity,
    pin: &CoreRosterPin,
    body: &str,
) -> Result<CoreDeviceState, CoreError> {
    let served: RegisterFinishResponse = serde_json::from_str(body).map_err(|err| {
        CoreError::malformed(format!("the register finish response is unreadable: {err}"))
    })?;
    if served.collection_id != identity.collection_id {
        return Err(refuse(AuthRefusal::CollectionMoved {
            chose: identity.collection_id,
            served: served.collection_id,
        }));
    }
    enrolled_state(
        server,
        username,
        served.account_id,
        served.collection_id,
        &identity.device,
        &identity.kdf_salt,
        // Registration posts a manifest at sequence 1, so the first one this
        // device is served has to be at least that.
        1,
        pin,
    )
}

// ── Login ──

/// Login step 1: ask for a challenge sealed to this device's X-Wing key.
pub fn login_challenge_request(username: &str, device_id: Uuid) -> Result<AuthRequest, CoreError> {
    Ok(AuthRequest {
        path: "/v1/opaque/login/challenge".into(),
        body: serde_json::to_string(&LoginChallengeRequest {
            username: checked_username(username)?,
            device_id,
        })?,
    })
}

/// Login step 2: open the sealed challenge and sign it together with the OPAQUE
/// request.
///
/// The server releases no credential response until this proof verifies, which
/// is what keeps the password out of reach of an attacker who can break
/// Ristretto255 and harvest an exchange for any username.
pub fn login_start_request(
    state: &CoreDeviceState,
    opaque_request_b64: &str,
    body: &str,
) -> Result<LoginStarting, CoreError> {
    let served: LoginChallengeResponse = serde_json::from_str(body)
        .map_err(|err| CoreError::malformed(format!("the login challenge is unreadable: {err}")))?;
    let challenge = open_login_challenge(
        &DeviceHpkeSecret::from_bytes(state.hpke_sk.clone()),
        &DeviceHpkeWrap {
            enc: served.challenge_enc,
            ciphertext: served.challenge_ct,
            ciphersuite: XWING_CIPHERSUITE,
        },
    )?;
    let request = decode(opaque_request_b64, "OPAQUE request")?;
    let username = checked_username(&state.username)?;
    let signature = sign(
        &signing(state)?,
        &login_start_transcript(
            served.challenge_id,
            &username,
            state.device_id,
            &challenge,
            &request,
        ),
    )?;
    Ok(LoginStarting {
        request: AuthRequest {
            path: "/v1/opaque/login/start".into(),
            body: serde_json::to_string(&LoginStartRequest {
                challenge_id: served.challenge_id,
                username,
                device_id: state.device_id,
                challenge: challenge.to_vec(),
                request,
                device_signature: dual(signature),
            })?,
        },
        challenge: encode(&challenge),
    })
}

/// Login step 3: complete OPAQUE and bind the finalization to this device.
pub fn login_finish_request(
    state: &CoreDeviceState,
    opaque_state_b64: &str,
    password: &str,
    challenge_b64: &str,
    body: &str,
) -> Result<AuthRequest, CoreError> {
    let served: LoginStartResponse = serde_json::from_str(body).map_err(|err| {
        CoreError::malformed(format!("the login start response is unreadable: {err}"))
    })?;
    let opaque =
        ClientLogin::<SealbookCipherSuite>::deserialize(&decode(opaque_state_b64, "OPAQUE state")?)
            .map_err(|err| CoreError::malformed(format!("OPAQUE state is unreadable: {err}")))?;
    let finished = client_login_finish(opaque, password.as_bytes(), &served.response)?;
    let challenge = challenge_bytes(&decode(challenge_b64, "login challenge")?)?;
    let username = checked_username(&state.username)?;
    let signature = sign(
        &signing(state)?,
        &login_transcript(
            served.login_id,
            &username,
            state.device_id,
            &finished.message,
            &challenge,
        ),
    )?;
    Ok(AuthRequest {
        path: "/v1/opaque/login/finish".into(),
        body: serde_json::to_string(&LoginFinishRequest {
            login_id: served.login_id,
            username,
            device_id: state.device_id,
            finalization: finished.message,
            device_signature: dual(signature),
        })?,
    })
}

/// Reads the login finish response: opens the collection key, and returns the
/// state to persist in place of the old one.
///
/// The device's own wrap is preferred and the password wrap is the fallback, so
/// a device whose wrap was never written can still sign in. No wrap at all is
/// [`AuthRefusal::NoKeyWrap`].
///
/// The roster is not fetched here, and the host must sync it before anything
/// reads or writes the vault: it is what every later device-set decision is made
/// from, and a device no longer in it has been revoked and should learn so here
/// rather than fail confusingly later.
pub fn login_accept(
    state: &CoreDeviceState,
    password: &str,
    body: &str,
) -> Result<LoggedIn, CoreError> {
    let served: LoginFinishResponse = serde_json::from_str(body).map_err(|err| {
        CoreError::malformed(format!("the login finish response is unreadable: {err}"))
    })?;
    let key = open_collection_key(
        password,
        &served.kdf_salt,
        &state.hpke_sk,
        state.device_id,
        &served.key_wraps,
    )?;
    let mut state = state.clone();
    state.account_id = served.account_id;
    state.collection_id = served.collection_id;
    state.kdf_salt = served.kdf_salt;
    state.session_token = Some(served.session_token);
    Ok(LoggedIn {
        state,
        collection_key: encode(key.as_bytes()),
        key_epoch: served.key_epoch,
        recovery_pending: served.recovery_pending,
    })
}

// ── Recovery ──

/// Recovery step 1: look the account up by a value derived from the phrase, and
/// begin registering the replacement password in the same round trip.
///
/// The lookup id reveals nothing on its own, which is why the server can answer
/// it before any proof. A lookup that matched nothing is answered with a decoy.
pub fn recover_start_request(
    username: &str,
    phrase: &str,
    opaque_request_b64: &str,
) -> Result<AuthRequest, CoreError> {
    let entropy = phrase_entropy(phrase)?;
    Ok(AuthRequest {
        path: "/v1/recover/start".into(),
        body: serde_json::to_string(&RecoverStartRequest {
            username: checked_username(username)?,
            lookup_id: phrase_lookup_id(&entropy)?.to_vec(),
            opaque_request: decode(opaque_request_b64, "OPAQUE request")?,
        })?,
    })
}

/// Opens the phrase wrap and checks the roster the account is on.
///
/// The server serves that roster with the phrase keys stripped, because handing
/// out the phrase verification keys before a proof would help anyone guessing
/// phrases. They are filled in from the phrase and then checked: the MAC is
/// keyed from the collection key the phrase wrap just opened, so a roster the
/// server made up cannot pass.
pub fn recover_start_accept(phrase: &str, body: &str) -> Result<RecoverStarted, CoreError> {
    let served: RecoverStartResponse = serde_json::from_str(body).map_err(|err| {
        CoreError::malformed(format!("the recovery start response is unreadable: {err}"))
    })?;
    let entropy = phrase_entropy(phrase)?;
    if served.challenge.len() != 32 {
        return Err(refuse(AuthRefusal::Challenge));
    }
    if served.wrap.hpke_enc.len() != 24 {
        return Err(CoreError::Nonce);
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&served.wrap.hpke_enc);
    // Named rather than passed on as a crypto failure: the wrap not opening is
    // what a wrong phrase looks like, and reporting it as a key or roster
    // problem sent users looking for a fault in the account.
    let key = unwrap_for_phrase(
        &entropy,
        &RecoveryWrap {
            nonce,
            ciphertext: served.wrap.wrapped_ck,
            ciphersuite: PHRASE_CIPHERSUITE.to_string(),
        },
    )
    .map_err(|_| refuse(AuthRefusal::PhraseMismatch))?;
    let (Some(mut roster), Some(collection_id)) = (served.roster, served.collection_id) else {
        return Err(refuse(AuthRefusal::NoRoster));
    };
    let phrase_public = phrase_recovery_public(&entropy)?;
    roster.phrase_mldsa_pk = phrase_public.mldsa_pk;
    roster.phrase_ed25519_pk = phrase_public.ed25519_pk;
    // The membership check core makes is "is this device listed", and a
    // recovering device is not listed yet by definition, so an enrolled member
    // stands in for it. What matters here is the signature and the MAC.
    let Some(stand_in) = roster.devices.first().map(|device| device.device_id) else {
        return Err(refuse(AuthRefusal::NoRoster));
    };
    let verified = roster_accept_sealed(
        &RosterContext {
            collection_id,
            device_id: stand_in,
            roster_seq: 0,
            roster_transcript: String::new(),
        },
        &session(&key),
        &serde_json::to_string(&roster)?,
    )?;
    Ok(RecoverStarted {
        recovery_id: served.recovery_id,
        challenge: encode(&served.challenge),
        collection_id,
        collection_key: encode(key.as_bytes()),
        roster: verified.roster,
        opaque_response: encode(&served.opaque_response),
        roster_json: verified.roster_json,
    })
}

/// Recovery step 2: enrol the recovering device, set the replacement password,
/// and sign the roster step that adds the device with the phrase.
///
/// The phrase is the only member of the current roster available to sign that
/// step, because the recovering device has no enrolled key yet. The phrase proof
/// covers the password upload and its wrap as well, so none of it can be
/// substituted in flight.
pub fn recover_finish_request(
    username: &str,
    phrase: &str,
    password: &str,
    started: &RecoverStarted,
    device: &CoreDeviceSecrets,
    upload_b64: &str,
) -> Result<Recovering, CoreError> {
    let username = checked_username(username)?;
    let entropy = phrase_entropy(phrase)?;
    let key = CollectionKey::from_bytes(crate::roster::collection_key(&started.collection_key)?);
    let keys = DevicePublicKeys::try_from(&device.device)?;
    let upload = decode(upload_b64, "OPAQUE upload")?;
    let challenge = challenge_bytes(&decode(&started.challenge, "recovery challenge")?)?;

    let salt = generate_kdf_salt();
    let password_wrap = wrap_collection_key(password.as_bytes(), &salt, &key)?;
    let device_wrap = wrap_for_device(&DeviceHpkePublic(keys.xwing_hpke_pk.clone()), &key)?;
    let payload = recovery_password_payload(
        &upload,
        &salt,
        &password_wrap.nonce,
        &password_wrap.ciphertext,
        &password_wrap.ciphersuite,
    );

    let (phrase_secrets, phrase_public) = phrase_recovery_keys(&entropy)?;
    let current = &started.roster;
    let mut devices = current
        .devices
        .iter()
        .map(DevicePublicKeys::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    devices.push(keys.clone());
    let roster = RosterBody::seal(
        started.collection_id,
        current.roster_seq + 1,
        current.key_epoch,
        devices,
        phrase_public.mldsa_pk.clone(),
        phrase_public.ed25519_pk.clone(),
        RosterSignerBody::Phrase,
        &phrase_secrets,
        &key,
    )?;
    let roster_json = serde_json::to_string(&roster)?;
    let proof = sign_phrase_recovery(
        &entropy,
        &phrase_recovery_transcript(
            &username,
            started.recovery_id,
            &challenge,
            keys.device_id,
            &keys.mldsa_pk,
            &keys.ed25519_pk,
            &keys.xwing_hpke_pk,
            &payload,
        ),
    )?;
    let request = AuthRequest {
        path: "/v1/recover/finish".into(),
        body: serde_json::to_string(&RecoverFinishRequest {
            username,
            recovery_id: started.recovery_id,
            challenge: challenge.to_vec(),
            phrase_proof: dual(proof),
            device: keys.clone(),
            enrollment_signature: enrollment_signature(&keys, &device.signing()?)?,
            wrap: device_key_wrap(keys.device_id, &device_wrap),
            roster,
            upload,
            kdf_salt: salt.to_vec(),
            recovery_nonce: password_wrap.nonce.to_vec(),
            recovery_wrapped_ck: password_wrap.ciphertext,
            recovery_ciphersuite: password_wrap.ciphersuite,
        })?,
    };
    Ok(Recovering {
        request,
        pin: sealed_pin(started.collection_id, keys.device_id, &key, &roster_json)?,
        kdf_salt: encode(&salt),
    })
}

/// Reads the recover finish response into the state this device persists.
///
/// The collection is checked against the one the phrase wrap opened, for the
/// same reason registration checks its own: the roster step this device signed
/// is over that collection and nothing else.
pub fn recover_accept(
    server: &str,
    username: &str,
    started: &RecoverStarted,
    device: &CoreDeviceSecrets,
    recovering: &Recovering,
    body: &str,
) -> Result<CoreDeviceState, CoreError> {
    let served: RecoverFinishResponse = serde_json::from_str(body).map_err(|err| {
        CoreError::malformed(format!("the recovery finish response is unreadable: {err}"))
    })?;
    if served.collection_id != started.collection_id {
        return Err(refuse(AuthRefusal::CollectionMoved {
            chose: started.collection_id,
            served: served.collection_id,
        }));
    }
    enrolled_state(
        server,
        username,
        served.account_id,
        served.collection_id,
        device,
        &recovering.kdf_salt,
        // Nothing is known about the collection's manifest yet; the first login
        // and sync establish it.
        0,
        &recovering.pin,
    )
}

// ── Account operations ──

/// The challenge a username change or an account deletion is signed over.
///
/// Account mutations are authorized by a device signature over a server-issued
/// challenge, not by the age of a session, so a stolen bearer token alone cannot
/// rename or destroy an account.
pub fn account_challenge_request() -> AuthRequest {
    AuthRequest {
        path: "/v1/account/challenge".into(),
        body: "{}".into(),
    }
}

/// Renames the account, re-registering the password under the new username.
///
/// The OPAQUE record is bound to the username, so the verifier has to be
/// registered again under the new one or the next sign-in would fail.
pub fn change_username_request(
    state: &CoreDeviceState,
    new_username: &str,
    upload_b64: &str,
    challenge_body: &str,
) -> Result<AuthRequest, CoreError> {
    let new_username = checked_username(new_username)?;
    let challenge = account_challenge(challenge_body)?;
    let upload = decode(upload_b64, "OPAQUE upload")?;
    let signature = account_signature(
        state,
        "username",
        challenge.challenge_id,
        &challenge.challenge,
        &username_change_payload(&new_username, &upload),
    )?;
    Ok(AuthRequest {
        path: "/v1/account/username".into(),
        body: serde_json::to_string(&ChangeUsernameRequest {
            new_username,
            upload,
            challenge_id: challenge.challenge_id,
            challenge: challenge.challenge,
            signature,
        })?,
    })
}

/// Password change step 1, which also issues the challenge step 2 signs over.
pub fn password_change_start_request(opaque_request_b64: &str) -> Result<AuthRequest, CoreError> {
    Ok(AuthRequest {
        path: "/v1/account/password/start".into(),
        body: serde_json::to_string(&ChangePasswordStartRequest {
            request: decode(opaque_request_b64, "OPAQUE request")?,
        })?,
    })
}

/// Reads a password change start.
pub fn password_change_start_accept(body: &str) -> Result<PasswordChangeStarted, CoreError> {
    let served: ChangePasswordStartResponse = serde_json::from_str(body).map_err(|err| {
        CoreError::malformed(format!(
            "the password change start response is unreadable: {err}"
        ))
    })?;
    Ok(PasswordChangeStarted {
        password_change_id: served.password_change_id,
        challenge: encode(&served.challenge),
        opaque_response: encode(&served.response),
    })
}

/// Password change step 2: the new verifier, and the collection key re-wrapped
/// under the new password.
///
/// The signature covers the replacement wrap as well as the verifier. Without
/// it, somebody holding only a token could substitute key material the account
/// holder never produced and quietly destroy password-based recovery.
pub fn change_password_request(
    state: &CoreDeviceState,
    session: &CoreSession,
    new_password: &str,
    upload_b64: &str,
    started: &PasswordChangeStarted,
) -> Result<PasswordChange, CoreError> {
    let key = CollectionKey::from_bytes(session.collection_key.ok_or(CoreError::NoCollectionKey)?);
    let upload = decode(upload_b64, "OPAQUE upload")?;
    let challenge = decode(&started.challenge, "password change challenge")?;
    let salt = generate_kdf_salt();
    let wrap = wrap_collection_key(new_password.as_bytes(), &salt, &key)?;
    let signature = account_signature(
        state,
        "password",
        started.password_change_id,
        &challenge,
        &password_change_payload(
            &upload,
            &salt,
            &wrap.nonce,
            &wrap.ciphertext,
            &wrap.ciphersuite,
        ),
    )?;
    Ok(PasswordChange {
        request: AuthRequest {
            path: "/v1/account/password".into(),
            body: serde_json::to_string(&ChangePasswordRequest {
                password_change_id: started.password_change_id,
                challenge,
                signature,
                upload,
                kdf_salt: salt.to_vec(),
                recovery_nonce: wrap.nonce.to_vec(),
                recovery_wrapped_ck: wrap.ciphertext,
                recovery_ciphersuite: wrap.ciphersuite,
            })?,
        },
        kdf_salt: encode(&salt),
    })
}

/// Deletes the account and everything in it.
pub fn delete_account_request(
    state: &CoreDeviceState,
    challenge_body: &str,
) -> Result<AuthRequest, CoreError> {
    let challenge = account_challenge(challenge_body)?;
    let signature = account_signature(
        state,
        "delete",
        challenge.challenge_id,
        &challenge.challenge,
        &delete_account_payload(),
    )?;
    Ok(AuthRequest {
        path: "/v1/account".into(),
        body: serde_json::to_string(&DeleteAccountRequest {
            challenge_id: challenge.challenge_id,
            challenge: challenge.challenge,
            signature,
        })?,
    })
}

// ── Shared ──

#[allow(clippy::too_many_arguments)]
fn enrolled_state(
    server: &str,
    username: &str,
    account_id: Uuid,
    collection_id: Uuid,
    device: &CoreDeviceSecrets,
    kdf_salt_b64: &str,
    manifest_seq: u64,
    pin: &CoreRosterPin,
) -> Result<CoreDeviceState, CoreError> {
    let transcript = decode(&pin.transcript, "roster pin transcript")?;
    if pin.roster_seq == 0 || transcript.len() != 32 {
        return Err(CoreError::roster(
            "a roster pin is a sequence and a 32-byte transcript",
        ));
    }
    Ok(CoreDeviceState {
        server: server.trim_end_matches('/').to_string(),
        username: checked_username(username)?,
        account_id,
        collection_id,
        device_id: device.device.device_id,
        session_token: None,
        kdf_salt: decode(kdf_salt_b64, "KDF salt")?,
        hpke_sk: decode(&device.hpke_sk, "HPKE secret key")?,
        mldsa_seed: decode(&device.mldsa_seed, "ML-DSA seed")?,
        ed25519_sk: decode(&device.ed25519_sk, "Ed25519 secret key")?,
        manifest_seq,
        roster_seq: pin.roster_seq,
        roster_transcript: transcript,
    })
}

/// The pin a device takes from a roster it sealed itself.
fn sealed_pin(
    collection_id: Uuid,
    device_id: Uuid,
    key: &CollectionKey,
    roster_json: &str,
) -> Result<CoreRosterPin, CoreError> {
    Ok(roster_accept_sealed(
        &RosterContext {
            collection_id,
            device_id,
            roster_seq: 0,
            roster_transcript: String::new(),
        },
        &session(key),
        roster_json,
    )?
    .pin)
}

fn session(key: &CollectionKey) -> CoreSession {
    CoreSession {
        collection_key: Some(*key.as_bytes()),
        key_epoch: 0,
        verified_roster: None,
    }
}

fn open_collection_key(
    password: &str,
    kdf_salt: &[u8],
    hpke_sk: &[u8],
    device_id: Uuid,
    wraps: &[KeyWrapBody],
) -> Result<CollectionKey, CoreError> {
    let device = device_id.to_string();
    if let Some(wrap) = wraps
        .iter()
        .find(|wrap| wrap.recipient_kind == "device" && wrap.recipient_id == device)
    {
        return Ok(unwrap_for_device(
            &DeviceHpkeSecret::from_bytes(hpke_sk.to_vec()),
            &DeviceHpkeWrap {
                enc: wrap.hpke_enc.clone(),
                ciphertext: wrap.wrapped_ck.clone(),
                ciphersuite: XWING_CIPHERSUITE,
            },
        )?);
    }
    if let Some(wrap) = wraps.iter().find(|wrap| wrap.recipient_kind == "recovery") {
        if wrap.hpke_enc.len() != 24 {
            return Err(CoreError::Nonce);
        }
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&wrap.hpke_enc);
        return Ok(unwrap_collection_key(
            password.as_bytes(),
            kdf_salt,
            &RecoveryWrap {
                nonce,
                ciphertext: wrap.wrapped_ck.clone(),
                ciphersuite: wrap.ciphersuite.clone(),
            },
        )?);
    }
    Err(refuse(AuthRefusal::NoKeyWrap))
}

fn account_challenge(body: &str) -> Result<AccountChallengeResponse, CoreError> {
    serde_json::from_str(body)
        .map_err(|err| CoreError::malformed(format!("the account challenge is unreadable: {err}")))
}

fn account_signature(
    state: &CoreDeviceState,
    op: &str,
    challenge_id: Uuid,
    challenge: &[u8],
    payload: &[u8; 32],
) -> Result<DualSignatureBody, CoreError> {
    Ok(dual(sign(
        &signing(state)?,
        &account_op_transcript(
            op,
            challenge_id,
            challenge,
            &state.account_id.to_string(),
            state.device_id,
            payload,
        ),
    )?))
}

fn enrollment_signature(
    keys: &DevicePublicKeys,
    secrets: &DeviceSigningSecrets,
) -> Result<DualSignatureBody, CoreError> {
    Ok(dual(sign(
        secrets,
        &enrollment_transcript(
            keys.device_id,
            &keys.mldsa_pk,
            &keys.ed25519_pk,
            &keys.xwing_hpke_pk,
        ),
    )?))
}

fn dual(signature: sealbook_crypto::DualSignature) -> DualSignatureBody {
    DualSignatureBody {
        mldsa: signature.mldsa,
        ed25519: signature.ed25519,
    }
}

fn device_key_wrap(device_id: Uuid, wrap: &DeviceHpkeWrap) -> KeyWrapBody {
    KeyWrapBody {
        recipient_kind: "device".into(),
        recipient_id: device_id.to_string(),
        hpke_enc: wrap.enc.clone(),
        wrapped_ck: wrap.ciphertext.clone(),
        ciphersuite: XWING_CIPHERSUITE.into(),
    }
}

fn signing(state: &CoreDeviceState) -> Result<DeviceSigningSecrets, CoreError> {
    Ok(DeviceSigningSecrets {
        mldsa_seed: state.mldsa_seed.clone(),
        ed25519_sk: state.ed25519_sk.clone(),
    })
}

fn phrase_entropy(phrase: &str) -> Result<[u8; 32], CoreError> {
    entropy_from_phrase(&normalize_phrase(phrase)).map_err(|_| refuse(AuthRefusal::Phrase))
}

fn challenge_bytes(bytes: &[u8]) -> Result<[u8; 32], CoreError> {
    if bytes.len() != 32 {
        return Err(refuse(AuthRefusal::Challenge));
    }
    let mut challenge = [0u8; 32];
    challenge.copy_from_slice(bytes);
    Ok(challenge)
}

fn checked_username(raw: &str) -> Result<String, CoreError> {
    let username = normalize_username(raw);
    if !valid_username(&username) {
        return Err(refuse(AuthRefusal::Username));
    }
    Ok(username)
}

fn refuse(refusal: AuthRefusal) -> CoreError {
    CoreError::Auth { refusal }
}

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode(text: &str, what: &str) -> Result<Vec<u8>, CoreError> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|err| CoreError::malformed(format!("{what} is not base64: {err}")))
}

impl CoreDeviceSecrets {
    fn signing(&self) -> Result<DeviceSigningSecrets, CoreError> {
        Ok(DeviceSigningSecrets {
            mldsa_seed: decode(&self.mldsa_seed, "ML-DSA seed")?,
            ed25519_sk: decode(&self.ed25519_sk, "Ed25519 secret key")?,
        })
    }
}

/// The uniffi surface for the decisions above.
///
/// Separate because uniffi lowers records by value rather than borrowing them,
/// and because Kotlin holds the session's collection key as base64.
#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{
        AuthRequest, CoreDeviceSecrets, CoreDeviceState, CoreError, LoggedIn, LoginStarting,
        OpaqueStart, PasswordChange, PasswordChangeStarted, RecoverStarted, Recovering,
        RegisterIdentity, Registering,
    };
    use crate::roster::CoreRosterPin;
    use crate::CoreSession;
    use uuid::Uuid;

    fn session(ck_b64: Option<String>) -> Result<CoreSession, CoreError> {
        let collection_key = match ck_b64 {
            Some(text) => Some(crate::roster::collection_key(&text)?),
            None => None,
        };
        Ok(CoreSession {
            collection_key,
            key_epoch: 0,
            verified_roster: None,
        })
    }

    #[uniffi::export]
    pub fn normalize_username(raw: String) -> String {
        super::normalize_username(&raw)
    }

    #[uniffi::export]
    pub fn normalize_phrase(raw: String) -> String {
        super::normalize_phrase(&raw)
    }

    #[uniffi::export]
    pub fn opaque_register_start(password: String) -> Result<OpaqueStart, CoreError> {
        super::opaque_register_start(&password)
    }

    #[uniffi::export]
    pub fn opaque_register_upload(
        state_b64: String,
        password: String,
        response_b64: String,
    ) -> Result<String, CoreError> {
        super::opaque_register_upload(&state_b64, &password, &response_b64)
    }

    #[uniffi::export]
    pub fn opaque_login_start(password: String) -> Result<OpaqueStart, CoreError> {
        super::opaque_login_start(&password)
    }

    #[uniffi::export]
    pub fn new_device() -> Result<CoreDeviceSecrets, CoreError> {
        super::new_device()
    }

    #[uniffi::export]
    pub fn new_registration() -> Result<RegisterIdentity, CoreError> {
        super::new_registration()
    }

    #[uniffi::export]
    pub fn register_start_request(
        username: String,
        opaque_request_b64: String,
    ) -> Result<AuthRequest, CoreError> {
        super::register_start_request(&username, &opaque_request_b64)
    }

    #[uniffi::export]
    pub fn register_start_accept(body: String) -> Result<String, CoreError> {
        super::register_start_accept(&body)
    }

    #[uniffi::export]
    pub fn register_finish_request(
        username: String,
        password: String,
        upload_b64: String,
        identity: RegisterIdentity,
    ) -> Result<Registering, CoreError> {
        super::register_finish_request(&username, &password, &upload_b64, &identity)
    }

    #[uniffi::export]
    pub fn register_accept(
        server: String,
        username: String,
        identity: RegisterIdentity,
        pin: CoreRosterPin,
        body: String,
    ) -> Result<CoreDeviceState, CoreError> {
        super::register_accept(&server, &username, &identity, &pin, &body)
    }

    #[uniffi::export]
    pub fn login_challenge_request(
        username: String,
        device_id: Uuid,
    ) -> Result<AuthRequest, CoreError> {
        super::login_challenge_request(&username, device_id)
    }

    #[uniffi::export]
    pub fn login_start_request(
        state: CoreDeviceState,
        opaque_request_b64: String,
        body: String,
    ) -> Result<LoginStarting, CoreError> {
        super::login_start_request(&state, &opaque_request_b64, &body)
    }

    #[uniffi::export]
    pub fn login_finish_request(
        state: CoreDeviceState,
        opaque_state_b64: String,
        password: String,
        challenge_b64: String,
        body: String,
    ) -> Result<AuthRequest, CoreError> {
        super::login_finish_request(&state, &opaque_state_b64, &password, &challenge_b64, &body)
    }

    #[uniffi::export]
    pub fn login_accept(
        state: CoreDeviceState,
        password: String,
        body: String,
    ) -> Result<LoggedIn, CoreError> {
        super::login_accept(&state, &password, &body)
    }

    #[uniffi::export]
    pub fn recover_start_request(
        username: String,
        phrase: String,
        opaque_request_b64: String,
    ) -> Result<AuthRequest, CoreError> {
        super::recover_start_request(&username, &phrase, &opaque_request_b64)
    }

    #[uniffi::export]
    pub fn recover_start_accept(phrase: String, body: String) -> Result<RecoverStarted, CoreError> {
        super::recover_start_accept(&phrase, &body)
    }

    #[uniffi::export]
    pub fn recover_finish_request(
        username: String,
        phrase: String,
        password: String,
        started: RecoverStarted,
        device: CoreDeviceSecrets,
        upload_b64: String,
    ) -> Result<Recovering, CoreError> {
        super::recover_finish_request(
            &username,
            &phrase,
            &password,
            &started,
            &device,
            &upload_b64,
        )
    }

    #[uniffi::export]
    pub fn recover_accept(
        server: String,
        username: String,
        started: RecoverStarted,
        device: CoreDeviceSecrets,
        recovering: Recovering,
        body: String,
    ) -> Result<CoreDeviceState, CoreError> {
        super::recover_accept(&server, &username, &started, &device, &recovering, &body)
    }

    #[uniffi::export]
    pub fn account_challenge_request() -> AuthRequest {
        super::account_challenge_request()
    }

    #[uniffi::export]
    pub fn change_username_request(
        state: CoreDeviceState,
        new_username: String,
        upload_b64: String,
        challenge_body: String,
    ) -> Result<AuthRequest, CoreError> {
        super::change_username_request(&state, &new_username, &upload_b64, &challenge_body)
    }

    #[uniffi::export]
    pub fn password_change_start_request(
        opaque_request_b64: String,
    ) -> Result<AuthRequest, CoreError> {
        super::password_change_start_request(&opaque_request_b64)
    }

    #[uniffi::export]
    pub fn password_change_start_accept(body: String) -> Result<PasswordChangeStarted, CoreError> {
        super::password_change_start_accept(&body)
    }

    #[uniffi::export]
    pub fn change_password_request(
        state: CoreDeviceState,
        ck_b64: Option<String>,
        new_password: String,
        upload_b64: String,
        started: PasswordChangeStarted,
    ) -> Result<PasswordChange, CoreError> {
        super::change_password_request(
            &state,
            &session(ck_b64)?,
            &new_password,
            &upload_b64,
            &started,
        )
    }

    #[uniffi::export]
    pub fn delete_account_request(
        state: CoreDeviceState,
        challenge_body: String,
    ) -> Result<AuthRequest, CoreError> {
        super::delete_account_request(&state, &challenge_body)
    }
}
