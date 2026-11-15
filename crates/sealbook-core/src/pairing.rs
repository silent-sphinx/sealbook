//! Enrolling a second device over a PAKE.
//!
//! The joining device shows an eight-word code; the user types or scans it into
//! a device that is already signed in. The first three words are a nameplate
//! the server uses to put the two in touch. The other five never leave the
//! devices: they are the password for a CPace run (`sealbook_crypto::pairing`)
//! whose associated data is the joining device's keys. So the keys the two runs
//! derive only agree if both devices hold the same code and the approving device
//! is looking at the keys the joining device actually has. Nothing is compared
//! by eye, and a server that swaps the keys has one guess at the secret words
//! per pairing.
//!
//! The steps, and which side runs each:
//!
//! 1. joining: [`pair_start`], post the body, [`pair_join_accept`];
//! 2. approving: [`pair_lookup_path`], fetch, [`pair_respond`], post the body;
//! 3. joining: [`pair_join_poll`] says `Confirm`, [`pair_confirm`], post it;
//! 4. approving: [`pair_approve_poll`] says `Preview`, [`pair_preview`]; the
//!    user is shown what is joining and agrees;
//! 5. approving: [`pair_approve`], post it;
//! 6. joining: [`pair_join_poll`] says `Ready`, [`pair_finish`] gives the roster
//!    pin to trust from, then the device signs in with the password.
//!
//! A failure at step 4 means the code was wrong or the keys were swapped. The
//! code is then spent: the approving device cancels, and the user starts again
//! on the joining device. The state each side keeps between steps is secret and
//! lives only in the host's memory.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::{CryptoRng, RngCore};
use sealbook_crypto::{
    enrollment_transcript, pair_grant_transcript, sign, wrap_for_device, CollectionKey,
    CryptoError, DeviceHpkePublic, DeviceSigningSecrets, PairCode, PairInitiator, PairKeys,
    WrapBinding, XWING_CIPHERSUITE,
};
use sealbook_protocol::{
    DevicePublicKeys, DualSignatureBody, KeyWrapBody, PairApproveRequest, PairConfirmRequest,
    PairJoinRequest, PairJoinResponse, PairRespondRequest, PairStatusResponse, RosterBody,
    RosterSignerBody,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::roster::{CoreDevice, CoreRosterPin, RosterContext, VerifiedRoster};
use crate::{CoreError, CoreSession};

/// The longest device description an approving device shows, in characters.
pub const PAIR_DESCRIPTION_MAX: usize = 64;

/// Why a pairing cannot go on.
///
/// Typed rather than free text because each of these is something to tell the
/// user about, and each host has its own wording for it.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[serde(tag = "refusal")]
pub enum PairRefusal {
    /// What was typed or scanned is not a pairing code. Nothing has been sent.
    #[error("{reason}")]
    Code { reason: String },
    #[error("this pairing request has expired")]
    Expired,
    #[error(
        "the collection key has moved to epoch {roster} and this device holds epoch {held}; \
         sign in again and approve the new device after that"
    )]
    KeyRotated { held: u64, roster: u64 },
    #[error("device {device} is already enrolled")]
    AlreadyEnrolled {
        #[cfg_attr(feature = "wasm", tsify(type = "string"))]
        device: Uuid,
    },
    /// The new device's answer did not open: the code entered is not the one it
    /// shows, or the keys on offer are not the ones it holds. The code is spent.
    #[error("that code does not match the new device")]
    CodeMismatch,
    /// The approving device's answer did not open, on the joining side.
    #[error("the approving device's answer could not be verified")]
    Unverified,
}

/// What the joining device holds once it has made its code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PairStarted {
    /// The words to show, lowercase and space-separated.
    pub code: String,
    /// What to draw as a QR code.
    pub qr_text: String,
    /// The join request body, ready to post.
    pub body: String,
    /// This device's half of the CPace run. Secret: kept in memory only, and
    /// handed back to [`pair_confirm`] and [`pair_finish`].
    pub state: String,
}

/// What the joining device learns from the server's answer to its join.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PairJoined {
    /// What the joining device polls by. The server never shows it to anyone
    /// but the joining device and a device on the account.
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub pair_id: Uuid,
}

/// What a joining device does after a poll.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum PairJoinPoll {
    /// The approving device has answered: run [`pair_confirm`] and post it,
    /// then keep polling.
    Confirm,
    /// The pairing was approved: stop polling and run [`pair_finish`].
    Ready,
    /// The code is gone: stop polling and tell the user to start again.
    Expired,
    /// Nothing to act on yet: ask again after this long.
    Wait { after_ms: u32 },
}

/// What an approving device does after a poll.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum PairApprovePoll {
    /// The joining device has answered: run [`pair_preview`] on this body.
    Preview,
    /// The code is gone: stop polling and tell the user to start again.
    Expired,
    /// Nothing to act on yet: ask again after this long.
    Wait { after_ms: u32 },
}

/// The approving device's half of a pairing, kept from [`pair_respond`] to
/// [`pair_approve`]. `keys` is secret: kept in memory only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CorePairResponse {
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub pair_id: Uuid,
    /// What the approving device looks the pairing up by.
    pub nameplate: String,
    /// The keys the run was bound to. The approval wraps for these and only
    /// these, whatever a later fetch is served.
    pub device: CoreDevice,
    pub sid: String,
    pub joiner_share: String,
    pub approver_share: String,
    pub keys: String,
}

/// The approving device's answer to a pairing: what to post, and what to keep.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PairResponded {
    pub response: CorePairResponse,
    /// The respond request body, ready to post.
    pub body: String,
}

/// A joining device, as the approving device shows it before the user agrees.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CorePairPreview {
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub pair_id: Uuid,
    pub device: CoreDevice,
    /// What the joining device says it is, such as "Firefox on macOS". Sealed
    /// under the run's keys, so the server cannot change it, but chosen by
    /// whoever holds the code.
    pub description: String,
    /// The sealed message this preview was opened from, which the approval
    /// opens again rather than trusting a preview a host hands back.
    pub hello: String,
}

/// What an approval sends, and what it leaves this device pinned on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PairApproval {
    /// The approve request body, ready to post.
    pub body: String,
    /// The roster step this device signed. The account is on it once the server
    /// accepts the approval, so the pin moves onto it rather than waiting to be
    /// served it back.
    pub roster_json: String,
}

#[derive(Serialize, Deserialize)]
struct Hello {
    description: String,
}

/// How long either device waits between polls.
pub const PAIR_POLL_INTERVAL_MS: u32 = 1000;

// ── The joining device ──

/// Makes the code and the join request, with the enrollment signature over the
/// new keys and this device's CPace share.
///
/// The device is generated by the host, which is the only randomness in a
/// pairing that core does not see: the keys are what the host has to persist.
pub fn pair_start(
    username: &str,
    device: &CoreDevice,
    secrets: &DeviceSigningSecrets,
) -> Result<PairStarted, CoreError> {
    pair_start_with_rng(&mut rand::thread_rng(), username, device, secrets)
}

/// [`pair_start`] with the randomness supplied, for the shared fixture.
#[doc(hidden)]
pub fn pair_start_with_rng<R: RngCore + CryptoRng>(
    rng: &mut R,
    username: &str,
    device: &CoreDevice,
    secrets: &DeviceSigningSecrets,
) -> Result<PairStarted, CoreError> {
    let keys = DevicePublicKeys::try_from(device)?;
    let signature = sign(secrets, &joiner_keys(&keys))?;
    let code = PairCode::generate(rng);
    let initiator = PairInitiator::start(rng, &code, username);
    let body = serde_json::to_string(&PairJoinRequest {
        username: username.to_string(),
        device: keys,
        enrollment_signature: DualSignatureBody {
            mldsa: signature.mldsa,
            ed25519: signature.ed25519,
        },
        nameplate: code.nameplate(),
        sid: initiator.sid.to_vec(),
        share: initiator.share.to_vec(),
    })?;
    Ok(PairStarted {
        code: code.display(),
        qr_text: code.qr_text(),
        body,
        state: URL_SAFE_NO_PAD.encode(initiator.to_bytes()),
    })
}

pub fn pair_join_accept(body: &str) -> Result<PairJoined, CoreError> {
    let joined: PairJoinResponse = serde_json::from_str(body)
        .map_err(|err| CoreError::malformed(format!("the join response is unreadable: {err}")))?;
    Ok(PairJoined {
        pair_id: joined.pair_id,
    })
}

/// The decision a joining device's poll leads to, so no host chooses its own.
///
/// `status` is `None` when the request never got an answer. Everything that is
/// not a step to take or an expiry is a wait: a dropped request, a server error
/// and an unreadable body say nothing about the pairing, and giving up on one
/// would abandon a pairing the user is still busy approving.
pub fn pair_join_poll(status: Option<u16>, body: &str) -> PairJoinPoll {
    match served_status(status, body).as_deref() {
        Some("responded") => PairJoinPoll::Confirm,
        Some("ready") => PairJoinPoll::Ready,
        Some("expired") => PairJoinPoll::Expired,
        _ => PairJoinPoll::Wait {
            after_ms: PAIR_POLL_INTERVAL_MS,
        },
    }
}

/// Finishes this device's CPace run with the approving device's share, and seals
/// `description` for it. The approving device can only open what this sends if
/// the user entered this device's code and is looking at this device's keys.
pub fn pair_confirm(
    state: &str,
    device: &CoreDevice,
    pair_id: Uuid,
    body: &str,
    description: &str,
) -> Result<String, CoreError> {
    pair_confirm_with_rng(
        &mut rand::thread_rng(),
        state,
        device,
        pair_id,
        body,
        description,
    )
}

/// [`pair_confirm`] with the randomness supplied, for the shared fixture.
#[doc(hidden)]
pub fn pair_confirm_with_rng<R: RngCore + CryptoRng>(
    rng: &mut R,
    state: &str,
    device: &CoreDevice,
    pair_id: Uuid,
    body: &str,
    description: &str,
) -> Result<String, CoreError> {
    let keys = joiner_run_keys(state, device, pair_id, body)?;
    let hello = serde_json::to_vec(&Hello {
        description: clean_description(description),
    })?;
    let hello = keys
        .seal_for_approver(rng, pair_id, &hello)
        .map_err(|_| refuse(PairRefusal::Unverified))?;
    Ok(serde_json::to_string(&PairConfirmRequest { hello })?)
}

/// Opens the roster pin the approving device sealed, once the pairing is ready.
///
/// This pin is the joining device's root of trust for the account's devices. It
/// reaches it under the run's keys, so the server cannot choose it.
pub fn pair_finish(
    state: &str,
    device: &CoreDevice,
    pair_id: Uuid,
    body: &str,
) -> Result<CoreRosterPin, CoreError> {
    let keys = joiner_run_keys(state, device, pair_id, body)?;
    let served = served(body)?;
    let pin = keys
        .open_from_approver(pair_id, &served.sealed_pin)
        .map_err(|_| refuse(PairRefusal::Unverified))?;
    if pin.len() != 8 + 32 {
        return Err(refuse(PairRefusal::Unverified));
    }
    let roster_seq = u64::from_be_bytes(pin[..8].try_into().expect("eight bytes"));
    if roster_seq == 0 {
        return Err(refuse(PairRefusal::Unverified));
    }
    Ok(CoreRosterPin {
        roster_seq,
        transcript: URL_SAFE_NO_PAD.encode(&pin[8..]),
    })
}

/// The run's keys from the joining side, given a body carrying the approving
/// device's share.
fn joiner_run_keys(
    state: &str,
    device: &CoreDevice,
    pair_id: Uuid,
    body: &str,
) -> Result<PairKeys, CoreError> {
    let served = served(body)?;
    if served.pair_id != pair_id {
        return Err(refuse(PairRefusal::Unverified));
    }
    let initiator = PairInitiator::from_bytes(&decode(state, "pairing state")?)
        .map_err(|_| CoreError::malformed("the pairing state is not this device's"))?;
    let keys = DevicePublicKeys::try_from(device)?;
    initiator
        .finish(&joiner_keys(&keys), &served.approver_share)
        .map_err(|_| refuse(PairRefusal::Unverified))
}

// ── The approving device ──

/// Reads a code as typed or scanned and gives the path that looks it up.
///
/// A code that is not eight list words is refused here, before anything is
/// sent, so a typo costs nothing. A typo that is still eight list words is only
/// found at [`pair_preview`], and spends the code.
pub fn pair_lookup_path(typed: &str) -> Result<String, CoreError> {
    Ok(pair_path(&parse_code(typed)?.nameplate()))
}

/// Answers a pairing with this device's CPace share.
///
/// `username` is this account's, which the run binds: a pairing started for
/// another account does not complete here even if the server shows it.
/// `typed` is the code as entered. The checks that do not need the joining
/// device's answer are made now, so a pairing that cannot be approved fails
/// before the code is spent.
pub fn pair_respond(
    session: &CoreSession,
    verified: &VerifiedRoster,
    username: &str,
    typed: &str,
    body: &str,
) -> Result<PairResponded, CoreError> {
    pair_respond_with_rng(
        &mut rand::thread_rng(),
        session,
        verified,
        username,
        typed,
        body,
    )
}

/// [`pair_respond`] with the randomness supplied, for the shared fixture.
#[doc(hidden)]
pub fn pair_respond_with_rng<R: RngCore + CryptoRng>(
    rng: &mut R,
    session: &CoreSession,
    verified: &VerifiedRoster,
    username: &str,
    typed: &str,
    body: &str,
) -> Result<PairResponded, CoreError> {
    let code = parse_code(typed)?;
    let served = served(body)?;
    // No device means the server will not show this pairing to this caller: it
    // has expired, or it belongs to another account. Any status past `pending`
    // means another device has already answered it.
    let Some(served_device) = served.device.as_ref() else {
        return Err(refuse(PairRefusal::Expired));
    };
    if served.status != "pending" {
        return Err(refuse(PairRefusal::Expired));
    }
    let device = CoreDevice::from(served_device);
    check_anchor(session, verified, &device)?;
    let (share, keys) = sealbook_crypto::pair_respond(
        rng,
        &code,
        username,
        &served.sid,
        &served.joiner_share,
        &joiner_keys(served_device),
    )
    .map_err(|err| match err {
        CryptoError::PairShare => refuse(PairRefusal::CodeMismatch),
        other => other.into(),
    })?;
    Ok(PairResponded {
        body: serde_json::to_string(&PairRespondRequest {
            share: share.to_vec(),
        })?,
        response: CorePairResponse {
            pair_id: served.pair_id,
            nameplate: code.nameplate(),
            device,
            sid: URL_SAFE_NO_PAD.encode(&served.sid),
            joiner_share: URL_SAFE_NO_PAD.encode(&served.joiner_share),
            approver_share: URL_SAFE_NO_PAD.encode(share),
            keys: URL_SAFE_NO_PAD.encode(keys.to_bytes()),
        },
    })
}

/// The decision an approving device's poll leads to, on the same terms as
/// [`pair_join_poll`].
pub fn pair_approve_poll(status: Option<u16>, body: &str) -> PairApprovePoll {
    match served_status(status, body).as_deref() {
        Some("confirmed") => PairApprovePoll::Preview,
        Some("expired") | Some("ready") => PairApprovePoll::Expired,
        _ => PairApprovePoll::Wait {
            after_ms: PAIR_POLL_INTERVAL_MS,
        },
    }
}

/// Opens the joining device's answer, which proves it holds the code typed here
/// and the keys this device answered for.
///
/// A refusal here spends the code: the host cancels the pairing, and the user
/// starts again on the joining device.
pub fn pair_preview(
    session: &CoreSession,
    verified: &VerifiedRoster,
    response: &CorePairResponse,
    body: &str,
) -> Result<CorePairPreview, CoreError> {
    let served = served(body)?;
    if served.pair_id != response.pair_id {
        return Err(refuse(PairRefusal::Expired));
    }
    let description = open_hello(response, &served.hello)?;
    check_anchor(session, verified, &response.device)?;
    Ok(CorePairPreview {
        pair_id: response.pair_id,
        device: response.device.clone(),
        description,
        hello: URL_SAFE_NO_PAD.encode(&served.hello),
    })
}

/// Approves a joining device: wraps the collection key for it, signs the grant,
/// signs the roster step that adds it, and seals that step's pin for it.
///
/// Re-checks against a roster verified now rather than the one the preview was
/// made from, because the user has been looking at a screen in between and a
/// rotation or another pairing may have landed.
pub fn pair_approve(
    secrets: &DeviceSigningSecrets,
    context: &RosterContext,
    session: &CoreSession,
    verified: &VerifiedRoster,
    response: &CorePairResponse,
    preview: &CorePairPreview,
) -> Result<PairApproval, CoreError> {
    if preview.pair_id != response.pair_id {
        return Err(refuse(PairRefusal::Expired));
    }
    open_hello(response, &decode(&preview.hello, "pairing hello")?)?;
    check_anchor(session, verified, &response.device)?;
    let key = CollectionKey::from_bytes(session.collection_key.ok_or(CoreError::NoCollectionKey)?);
    let joining = DevicePublicKeys::try_from(&response.device)?;
    let wrap = wrap_for_device(
        &DeviceHpkePublic(joining.xwing_hpke_pk.clone()),
        &key,
        &WrapBinding {
            collection_id: context.collection_id,
            key_epoch: session.key_epoch,
        },
    )?;
    let grant = sign(
        secrets,
        &pair_grant_transcript(
            response.pair_id,
            context.device_id,
            joining.device_id,
            &joining.mldsa_pk,
            &joining.ed25519_pk,
            &joining.xwing_hpke_pk,
            &decode(&response.sid, "pairing session id")?,
            &decode(&response.joiner_share, "joining device's share")?,
            &decode(&response.approver_share, "approving device's share")?,
        ),
    )?;
    let current = &verified.roster;
    let mut devices = current
        .devices
        .iter()
        .map(DevicePublicKeys::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    devices.push(joining.clone());
    let roster = RosterBody::seal(
        context.collection_id,
        current.roster_seq + 1,
        current.key_epoch,
        devices,
        decode(&current.phrase_mldsa_pk, "phrase ML-DSA key")?,
        decode(&current.phrase_ed25519_pk, "phrase Ed25519 key")?,
        RosterSignerBody::Device {
            device_id: context.device_id,
        },
        secrets,
        &key,
    )?;
    let pin = roster.pin(context.collection_id);
    let pin_bytes = [pin.roster_seq.to_be_bytes().as_slice(), &pin.transcript].concat();
    let sealed_pin = run_keys(response)?
        .seal_for_joiner(&mut rand::thread_rng(), response.pair_id, &pin_bytes)
        .map_err(CoreError::from)?;
    let roster_json = serde_json::to_string(&roster)?;
    let body = serde_json::to_string(&PairApproveRequest {
        wrap: KeyWrapBody {
            recipient_kind: "device".into(),
            recipient_id: joining.device_id.to_string(),
            hpke_enc: wrap.enc,
            wrapped_ck: wrap.ciphertext,
            ciphersuite: XWING_CIPHERSUITE.into(),
        },
        grant: DualSignatureBody {
            mldsa: grant.mldsa,
            ed25519: grant.ed25519,
        },
        roster,
        sealed_pin,
    })?;
    Ok(PairApproval { body, roster_json })
}

fn run_keys(response: &CorePairResponse) -> Result<PairKeys, CoreError> {
    PairKeys::from_bytes(&decode(&response.keys, "pairing keys")?)
        .map_err(|_| CoreError::malformed("the pairing keys are not this device's"))
}

fn open_hello(response: &CorePairResponse, sealed: &[u8]) -> Result<String, CoreError> {
    let opened = run_keys(response)?
        .open_from_joiner(response.pair_id, sealed)
        .map_err(|_| refuse(PairRefusal::CodeMismatch))?;
    let hello: Hello =
        serde_json::from_slice(&opened).map_err(|_| refuse(PairRefusal::CodeMismatch))?;
    Ok(clean_description(&hello.description))
}

// ── Paths ──

/// The path that reads a pairing: by nameplate for the approving device, by
/// pair id for the joining one.
pub fn pair_path(key: &str) -> String {
    format!("/v1/pair/{}", escape(key.trim()))
}

pub fn pair_respond_path(key: &str) -> String {
    format!("{}/respond", pair_path(key))
}

pub fn pair_confirm_path(key: &str) -> String {
    format!("{}/confirm", pair_path(key))
}

pub fn pair_approve_path(key: &str) -> String {
    format!("{}/approve", pair_path(key))
}

pub fn pair_cancel_path(key: &str) -> String {
    format!("{}/cancel", pair_path(key))
}

// ── Shared ──

/// The checks an approval makes that do not need the joining device's answer.
fn check_anchor(
    session: &CoreSession,
    verified: &VerifiedRoster,
    joining: &CoreDevice,
) -> Result<(), CoreError> {
    let roster = &verified.roster;
    // A revocation is always a rotation, so the epoch having moved is what a
    // device having been removed looks like from here. Wrapping the key this
    // session holds would hand the new device a key the account has retired.
    if roster.key_epoch != session.key_epoch {
        return Err(refuse(PairRefusal::KeyRotated {
            held: session.key_epoch,
            roster: roster.key_epoch,
        }));
    }
    if roster
        .devices
        .iter()
        .any(|device| device.device_id == joining.device_id)
    {
        return Err(refuse(PairRefusal::AlreadyEnrolled {
            device: joining.device_id,
        }));
    }
    Ok(())
}

/// The joining device's CPace associated data: its enrollment transcript.
fn joiner_keys(keys: &DevicePublicKeys) -> [u8; 32] {
    enrollment_transcript(
        keys.device_id,
        &keys.mldsa_pk,
        &keys.ed25519_pk,
        &keys.xwing_hpke_pk,
    )
}

fn parse_code(typed: &str) -> Result<PairCode, CoreError> {
    PairCode::parse(typed).map_err(|err| {
        refuse(PairRefusal::Code {
            reason: err.to_string(),
        })
    })
}

fn served(body: &str) -> Result<PairStatusResponse, CoreError> {
    serde_json::from_str(body).map_err(|err| {
        CoreError::malformed(format!("the pairing status response is unreadable: {err}"))
    })
}

/// The status a poll reports, with expiry folded in: the server says so with a
/// 404 rather than a status, so a host that only reads the body polls a dead
/// pairing for ever.
fn served_status(status: Option<u16>, body: &str) -> Option<String> {
    match status? {
        404 => Some("expired".into()),
        200 => served(body).ok().map(|served| served.status),
        _ => None,
    }
}

/// A description fit to show: no control characters, trimmed, and capped.
fn clean_description(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(PAIR_DESCRIPTION_MAX)
        .collect()
}

fn refuse(refusal: PairRefusal) -> CoreError {
    CoreError::Pair { refusal }
}

/// Percent-encodes a lookup key for a path segment. Nameplates are lowercase
/// words and hyphens and pair ids hex and hyphens, so in practice this changes
/// nothing; it is here so that nothing typed can reach the path unescaped.
fn escape(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    for byte in key.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

fn decode(text: &str, what: &str) -> Result<Vec<u8>, CoreError> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|err| CoreError::malformed(format!("{what} is not base64: {err}")))
}

#[cfg(test)]
mod poll_tests {
    use super::*;

    fn served(status: &str) -> String {
        format!(r#"{{"pair_id":"00000000-0000-0000-0000-000000000001","status":"{status}"}}"#)
    }

    #[test]
    fn each_side_acts_on_its_own_step() {
        assert_eq!(
            pair_join_poll(Some(200), &served("responded")),
            PairJoinPoll::Confirm
        );
        assert_eq!(
            pair_join_poll(Some(200), &served("ready")),
            PairJoinPoll::Ready
        );
        assert_eq!(
            pair_approve_poll(Some(200), &served("confirmed")),
            PairApprovePoll::Preview
        );
    }

    #[test]
    fn expiry_ends_both_polls() {
        assert_eq!(pair_join_poll(Some(404), ""), PairJoinPoll::Expired);
        assert_eq!(
            pair_join_poll(Some(200), &served("expired")),
            PairJoinPoll::Expired
        );
        assert_eq!(pair_approve_poll(Some(404), ""), PairApprovePoll::Expired);
        // Approved from elsewhere: nothing left for this device to approve.
        assert_eq!(
            pair_approve_poll(Some(200), &served("ready")),
            PairApprovePoll::Expired
        );
    }

    #[test]
    fn anything_else_waits_the_same_interval() {
        let join_wait = PairJoinPoll::Wait {
            after_ms: PAIR_POLL_INTERVAL_MS,
        };
        let approve_wait = PairApprovePoll::Wait {
            after_ms: PAIR_POLL_INTERVAL_MS,
        };
        for (status, body) in [
            (Some(200), served("pending")),
            (Some(200), served("confirmed")),
            (None, String::new()),
            (Some(500), "oops".into()),
            (Some(200), "not json".into()),
        ] {
            if body != served("confirmed") {
                assert_eq!(pair_approve_poll(status, &body), approve_wait, "{body}");
            }
            assert_eq!(pair_join_poll(status, &body), join_wait, "{body}");
        }
    }

    #[test]
    fn a_description_is_cleaned_before_it_is_shown() {
        assert_eq!(
            clean_description("  Firefox\n on\u{7} macOS "),
            "Firefox on macOS"
        );
        assert_eq!(
            clean_description(&"x".repeat(200)).len(),
            PAIR_DESCRIPTION_MAX
        );
    }
}

/// The uniffi surface for the steps above.
///
/// Separate because uniffi lowers records by value rather than borrowing them,
/// and takes the device's signing secrets as base64 because that is how Kotlin
/// holds them.
#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{
        CoreDevice, CoreError, CorePairPreview, CorePairResponse, CoreRosterPin, PairApproval,
        PairApprovePoll, PairJoinPoll, PairJoined, PairResponded, PairStarted, RosterContext,
        VerifiedRoster,
    };
    use crate::CoreSession;
    use sealbook_crypto::DeviceSigningSecrets;
    use uuid::Uuid;

    fn secrets(
        mldsa_seed_b64: &str,
        ed25519_sk_b64: &str,
    ) -> Result<DeviceSigningSecrets, CoreError> {
        Ok(DeviceSigningSecrets {
            mldsa_seed: super::decode(mldsa_seed_b64, "ML-DSA seed")?,
            ed25519_sk: super::decode(ed25519_sk_b64, "Ed25519 secret key")?,
        })
    }

    fn session(ck_b64: Option<String>, key_epoch: u64) -> Result<CoreSession, CoreError> {
        let collection_key = match ck_b64 {
            Some(text) => Some(crate::roster::collection_key(&text)?),
            None => None,
        };
        Ok(CoreSession {
            collection_key,
            key_epoch,
            verified_roster: None,
        })
    }

    #[uniffi::export]
    pub fn pair_start(
        username: String,
        device: CoreDevice,
        mldsa_seed_b64: String,
        ed25519_sk_b64: String,
    ) -> Result<PairStarted, CoreError> {
        super::pair_start(
            &username,
            &device,
            &secrets(&mldsa_seed_b64, &ed25519_sk_b64)?,
        )
    }

    #[uniffi::export]
    pub fn pair_join_accept(body: String) -> Result<PairJoined, CoreError> {
        super::pair_join_accept(&body)
    }

    #[uniffi::export]
    pub fn pair_join_poll(status: Option<u16>, body: String) -> PairJoinPoll {
        super::pair_join_poll(status, &body)
    }

    #[uniffi::export]
    pub fn pair_confirm(
        state: String,
        device: CoreDevice,
        pair_id: Uuid,
        body: String,
        description: String,
    ) -> Result<String, CoreError> {
        super::pair_confirm(&state, &device, pair_id, &body, &description)
    }

    #[uniffi::export]
    pub fn pair_finish(
        state: String,
        device: CoreDevice,
        pair_id: Uuid,
        body: String,
    ) -> Result<CoreRosterPin, CoreError> {
        super::pair_finish(&state, &device, pair_id, &body)
    }

    #[uniffi::export]
    pub fn pair_lookup_path(typed: String) -> Result<String, CoreError> {
        super::pair_lookup_path(&typed)
    }

    #[uniffi::export]
    pub fn pair_respond(
        ck_b64: Option<String>,
        key_epoch: u64,
        verified: VerifiedRoster,
        username: String,
        typed: String,
        body: String,
    ) -> Result<PairResponded, CoreError> {
        super::pair_respond(
            &session(ck_b64, key_epoch)?,
            &verified,
            &username,
            &typed,
            &body,
        )
    }

    #[uniffi::export]
    pub fn pair_approve_poll(status: Option<u16>, body: String) -> PairApprovePoll {
        super::pair_approve_poll(status, &body)
    }

    #[uniffi::export]
    pub fn pair_preview(
        ck_b64: Option<String>,
        key_epoch: u64,
        verified: VerifiedRoster,
        response: CorePairResponse,
        body: String,
    ) -> Result<CorePairPreview, CoreError> {
        super::pair_preview(&session(ck_b64, key_epoch)?, &verified, &response, &body)
    }

    #[uniffi::export]
    #[allow(clippy::too_many_arguments)]
    pub fn pair_approve(
        mldsa_seed_b64: String,
        ed25519_sk_b64: String,
        context: RosterContext,
        ck_b64: Option<String>,
        key_epoch: u64,
        verified: VerifiedRoster,
        response: CorePairResponse,
        preview: CorePairPreview,
    ) -> Result<PairApproval, CoreError> {
        super::pair_approve(
            &secrets(&mldsa_seed_b64, &ed25519_sk_b64)?,
            &context,
            &session(ck_b64, key_epoch)?,
            &verified,
            &response,
            &preview,
        )
    }

    #[uniffi::export]
    pub fn pair_path(key: String) -> String {
        super::pair_path(&key)
    }

    #[uniffi::export]
    pub fn pair_respond_path(key: String) -> String {
        super::pair_respond_path(&key)
    }

    #[uniffi::export]
    pub fn pair_confirm_path(key: String) -> String {
        super::pair_confirm_path(&key)
    }

    #[uniffi::export]
    pub fn pair_approve_path(key: String) -> String {
        super::pair_approve_path(&key)
    }

    #[uniffi::export]
    pub fn pair_cancel_path(key: String) -> String {
        super::pair_cancel_path(&key)
    }
}
