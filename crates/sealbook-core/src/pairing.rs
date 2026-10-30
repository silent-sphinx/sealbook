//! Enrolling a second device: what the joining side sends, what the approving
//! side checks, and the code the user compares on two screens.
//!
//! The confirmation code is the whole point of this module. It commits to the
//! joining device's keys *and* to the roster the account is on, so a user
//! comparing two codes confirms both. That only holds if each side computes the
//! code itself: a side that displays the code the server sent proves nothing
//! more than that a code reached the server unmodified, and a server that
//! substituted the keys could show the real code while keeping the ones it swapped
//! in. So core computes the code on both sides and the server's copy is only ever
//! compared against it.
//!
//! The approving side's roster comes from [`VerifiedRoster`], never from the
//! server's device list, for the same reason the roster exists at all.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sealbook_crypto::{
    enrollment_transcript, pair_confirmation, pair_grant_transcript, sign, wrap_for_device,
    CollectionKey, DeviceHpkePublic, DeviceSigningSecrets, XWING_CIPHERSUITE,
};
use sealbook_protocol::{
    DevicePublicKeys, DualSignatureBody, KeyWrapBody, PairApproveRequest, PairJoinRequest,
    PairJoinResponse, PairStatusResponse, RosterBody, RosterSignerBody,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::roster::{CoreDevice, CoreRosterPin, RosterContext, VerifiedRoster};
use crate::{CoreError, CoreSession};

/// Characters per display group. A v2 code is 26 base-32 characters, which has
/// to be grouped to stay comparable by eye.
const GROUP: usize = 4;

/// Why a pairing cannot go on.
///
/// Typed rather than free text because each of these is something to tell the
/// user about, and each host has its own wording for it.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[serde(tag = "refusal")]
pub enum PairRefusal {
    #[error("the server sent no device roster for this account to anchor on")]
    NoAnchor,
    /// The server's code is not the one computed here, so the two sides folded
    /// different things into it: either the roster moved under the pairing, or
    /// the keys on offer are not the ones the other device is holding.
    #[error("this device and the new one do not agree on the account's devices")]
    ServerCode,
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
    #[error(
        "the new device started pairing against roster {joined_at} but this account is now on \
         roster {now}; start the pairing again"
    )]
    RosterMoved { joined_at: u64, now: u64 },
    #[error("that confirmation code does not match the one for this pairing")]
    TypedCode,
}

/// What the joining device holds once the server has taken its join request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PairJoined {
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub pair_id: Uuid,
    /// The code the user carries to the approving device.
    pub pair_code: String,
    /// The code this device computed, which is the one to show. The server's
    /// copy has already been compared against it.
    pub confirm: String,
    /// The anchor the user is about to vouch for by comparing codes, to pin
    /// before the first roster fetch. Pinning it here is what makes that fetch
    /// a signed step from a roster the user confirmed, rather than one checked
    /// against a MAC keyed from a collection key the same server supplies.
    pub pin: CoreRosterPin,
}

/// Where a pairing has got to, from the joining side's poll.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum PairStatus {
    Pending,
    Ready,
    /// The code is gone: either it timed out or it was never valid. The server
    /// says so with a 404 rather than a status, so a host that only reads the
    /// body polls a dead pairing for ever.
    Expired,
}

/// A pairing request as the approving device sees it, checked against a roster
/// this device verified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CorePairPreview {
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub pair_id: Uuid,
    /// Computed here, not the server's copy. This is the code to display.
    pub confirm: String,
    pub device: CoreDevice,
    /// The roster the approval extends, which the code above commits to.
    pub roster_seq: u64,
}

/// What an approval sends, and what it leaves this device pinned on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PairApproval {
    /// The approve request body, ready to post.
    pub body: String,
    /// The canonical code that body carries.
    pub confirm: String,
    /// The roster step this device signed. The account is on it once the server
    /// accepts the approval, so the pin moves onto it rather than waiting to be
    /// served it back.
    pub roster_json: String,
}

/// The join request body, with the enrollment signature over the new keys.
///
/// The device is generated by the host, which is the only randomness in a
/// pairing that core does not see: the keys are what the host has to persist.
pub fn pair_join_body(
    username: &str,
    device: &CoreDevice,
    secrets: &DeviceSigningSecrets,
) -> Result<String, CoreError> {
    let keys = DevicePublicKeys::try_from(device)?;
    let transcript = enrollment_transcript(
        keys.device_id,
        &keys.mldsa_pk,
        &keys.ed25519_pk,
        &keys.xwing_hpke_pk,
    );
    let signature = sign(secrets, &transcript)?;
    Ok(serde_json::to_string(&PairJoinRequest {
        username: username.to_string(),
        device: keys,
        enrollment_signature: DualSignatureBody {
            mldsa: signature.mldsa,
            ed25519: signature.ed25519,
        },
    })?)
}

/// Checks the join response and computes the code the joining device shows.
///
/// Refuses an answer with no roster to anchor on: without one there is nothing
/// for the code to commit to, and the device would pin nothing and trust the
/// first roster it was served.
pub fn pair_join_accept(device: &CoreDevice, body: &str) -> Result<PairJoined, CoreError> {
    let joined: PairJoinResponse = serde_json::from_str(body)
        .map_err(|err| CoreError::malformed(format!("the join response is unreadable: {err}")))?;
    if joined.roster_seq == 0 || joined.roster_transcript.len() != 32 {
        return Err(refuse(PairRefusal::NoAnchor));
    }
    let keys = DevicePublicKeys::try_from(device)?;
    let confirm = pair_confirmation(
        joined.pair_id,
        keys.device_id,
        &keys.mldsa_pk,
        &keys.ed25519_pk,
        &keys.xwing_hpke_pk,
        joined.roster_seq,
        &joined.roster_transcript,
    );
    if joined.confirm != confirm {
        return Err(refuse(PairRefusal::ServerCode));
    }
    Ok(PairJoined {
        pair_id: joined.pair_id,
        pair_code: joined.pair_code,
        confirm,
        pin: CoreRosterPin {
            roster_seq: joined.roster_seq,
            transcript: URL_SAFE_NO_PAD.encode(&joined.roster_transcript),
        },
    })
}

/// Where a poll says the pairing has got to.
///
/// Takes the status code as well as the body, because expiry is a 404 and not a
/// status in the body.
pub fn pair_status(status: u16, body: &str) -> Result<PairStatus, CoreError> {
    if status == 404 {
        return Ok(PairStatus::Expired);
    }
    if status != 200 {
        return Err(CoreError::Server {
            detail: format!("the pairing status request returned HTTP {status}"),
        });
    }
    let served: PairStatusResponse = serde_json::from_str(body).map_err(|err| {
        CoreError::malformed(format!("the pairing status response is unreadable: {err}"))
    })?;
    Ok(match served.status.as_str() {
        "ready" => PairStatus::Ready,
        "expired" => PairStatus::Expired,
        _ => PairStatus::Pending,
    })
}

/// How long a joining device waits between polls.
pub const PAIR_POLL_INTERVAL_MS: u32 = 2000;

/// What a joining device does after a poll.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum PairPoll {
    /// The pairing was approved: stop polling and finish signing in.
    Ready,
    /// The code is gone: stop polling and tell the user to start again.
    Expired,
    /// Nothing to act on yet: ask again after this long.
    Wait { after_ms: u32 },
}

/// The decision a poll's outcome leads to, so no host chooses its own.
///
/// `status` is `None` when the request never got an answer. Everything that is
/// neither approval nor expiry is a wait: a dropped request, a server error and
/// an unreadable body say nothing about the pairing, and giving up on one would
/// abandon a pairing the user is still waiting to approve.
pub fn pair_poll(status: Option<u16>, body: &str) -> PairPoll {
    let wait = PairPoll::Wait {
        after_ms: PAIR_POLL_INTERVAL_MS,
    };
    match status.map(|status| pair_status(status, body)) {
        Some(Ok(PairStatus::Ready)) => PairPoll::Ready,
        Some(Ok(PairStatus::Expired)) => PairPoll::Expired,
        Some(Ok(PairStatus::Pending)) | Some(Err(_)) | None => wait,
    }
}

/// The path that looks a pairing up, from a code as the user typed it or from a
/// pair id.
///
/// The server matches a code on its whitespace-normalized form, so a code typed
/// with a double space has to be normalized here too rather than escaped as it
/// stands: escaping it verbatim turned a stray keystroke into "expired".
pub fn pair_path(pair_key: &str) -> String {
    format!("/v1/pair/{}", escape(&normalize_key(pair_key)))
}

/// The path an approval posts to, for the same key.
pub fn pair_approve_path(pair_key: &str) -> String {
    format!("{}/approve", pair_path(pair_key))
}

/// Reads a pairing request and checks everything about it that does not need the
/// typed code, so a preview that cannot lead to a valid approval fails before
/// the user is asked to compare anything.
///
/// `verified` is a roster this device checked from its own pin. The code is
/// computed over that roster's anchor and the keys in this preview, and the
/// server's copy is compared against it.
pub fn pair_preview(
    session: &CoreSession,
    verified: &VerifiedRoster,
    body: &str,
) -> Result<CorePairPreview, CoreError> {
    let served: PairStatusResponse = serde_json::from_str(body).map_err(|err| {
        CoreError::malformed(format!("the pairing status response is unreadable: {err}"))
    })?;
    // No device means the server is not willing to show this pairing to this
    // caller: it has expired, or it belongs to another account.
    let Some(device) = served.device.as_ref().map(CoreDevice::from) else {
        return Err(refuse(PairRefusal::Expired));
    };
    check_anchor(session, verified, &device, served.roster_seq)?;
    let confirm = confirmation_for(served.pair_id, &device, &verified.pin)?;
    if served.confirm != confirm {
        return Err(refuse(PairRefusal::ServerCode));
    }
    Ok(CorePairPreview {
        pair_id: served.pair_id,
        confirm,
        device,
        roster_seq: verified.pin.roster_seq,
    })
}

/// Approves a joining device: wraps the collection key for it, signs the grant,
/// and signs the roster step that adds it.
///
/// Re-checks the preview against a roster verified now rather than trusting the
/// one the preview was built from, because the user has been looking at a screen
/// in between and a rotation or another pairing may have landed. The typed code
/// is compared against the code recomputed here, never against anything the
/// server supplied.
///
/// The roster step is what lets the joining device, and every other device,
/// accept the new one without trusting the server's device list.
pub fn pair_approve(
    secrets: &DeviceSigningSecrets,
    context: &RosterContext,
    session: &CoreSession,
    verified: &VerifiedRoster,
    preview: &CorePairPreview,
    typed: &str,
) -> Result<PairApproval, CoreError> {
    check_anchor(session, verified, &preview.device, Some(preview.roster_seq))?;
    let confirm = confirmation_for(preview.pair_id, &preview.device, &verified.pin)?;
    // Codes are shown in groups, so compare on the normalized form but send the
    // canonical one.
    if normalize_confirmation(typed) != confirm {
        return Err(refuse(PairRefusal::TypedCode));
    }
    let key = CollectionKey::from_bytes(session.collection_key.ok_or(CoreError::NoCollectionKey)?);
    let joining = DevicePublicKeys::try_from(&preview.device)?;
    let wrap = wrap_for_device(&DeviceHpkePublic(joining.xwing_hpke_pk.clone()), &key)?;
    let grant = sign(
        secrets,
        &pair_grant_transcript(
            preview.pair_id,
            context.device_id,
            joining.device_id,
            &joining.mldsa_pk,
            &joining.ed25519_pk,
            &joining.xwing_hpke_pk,
            &confirm,
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
        confirmation: confirm.clone(),
        roster,
    })?;
    Ok(PairApproval {
        body,
        confirm,
        roster_json,
    })
}

/// Strips spacing and case differences from a typed code, so one shown in
/// groups can be entered as the user sees it.
pub fn normalize_confirmation(entered: &str) -> String {
    entered
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(char::to_uppercase)
        .collect()
}

/// A code split into display groups.
pub fn confirmation_groups(code: &str) -> Vec<String> {
    normalize_confirmation(code)
        .chars()
        .collect::<Vec<_>>()
        .chunks(GROUP)
        .map(|chunk| chunk.iter().collect())
        .collect()
}

/// A code grouped for display, so 26 characters stay scannable.
pub fn format_confirmation(code: &str) -> String {
    confirmation_groups(code).join(" ")
}

/// The checks an approval makes that do not need the typed code.
fn check_anchor(
    session: &CoreSession,
    verified: &VerifiedRoster,
    joining: &CoreDevice,
    joined_at: Option<u64>,
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
    // A rotation or another pairing landed while this one was waiting, so the
    // two sides would fold different anchors into the code. Said plainly here,
    // because the bare code mismatch it would otherwise surface as reads as
    // though something had been tampered with.
    if let Some(joined_at) = joined_at.filter(|seq| *seq != verified.pin.roster_seq) {
        return Err(refuse(PairRefusal::RosterMoved {
            joined_at,
            now: verified.pin.roster_seq,
        }));
    }
    Ok(())
}

fn confirmation_for(
    pair_id: Uuid,
    device: &CoreDevice,
    pin: &CoreRosterPin,
) -> Result<String, CoreError> {
    let keys = DevicePublicKeys::try_from(device)?;
    Ok(pair_confirmation(
        pair_id,
        keys.device_id,
        &keys.mldsa_pk,
        &keys.ed25519_pk,
        &keys.xwing_hpke_pk,
        pin.roster_seq,
        &decode(&pin.transcript, "roster pin transcript")?,
    ))
}

fn refuse(refusal: PairRefusal) -> CoreError {
    CoreError::Pair { refusal }
}

fn normalize_key(pair_key: &str) -> String {
    pair_key.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Percent-encodes a lookup key for a path segment. Codes are base-32 and
/// spaces, pair ids hex and hyphens, so in practice this escapes the spaces.
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

/// The uniffi surface for the decisions above.
///
/// Separate because uniffi lowers records by value rather than borrowing them,
/// and takes the device's signing secrets as base64 because that is how Kotlin
/// holds them.
#[cfg(test)]
mod poll_tests {
    use super::*;

    fn served(status: &str) -> String {
        format!(
            r#"{{"pair_id":"00000000-0000-0000-0000-000000000001","status":"{status}","confirm":"0000-0000"}}"#
        )
    }

    #[test]
    fn approval_and_expiry_end_the_poll() {
        assert_eq!(pair_poll(Some(200), &served("ready")), PairPoll::Ready);
        assert_eq!(pair_poll(Some(404), ""), PairPoll::Expired);
        assert_eq!(pair_poll(Some(200), &served("expired")), PairPoll::Expired);
    }

    #[test]
    fn anything_else_waits_the_same_interval() {
        let wait = PairPoll::Wait {
            after_ms: PAIR_POLL_INTERVAL_MS,
        };
        assert_eq!(pair_poll(Some(200), &served("pending")), wait);
        assert_eq!(pair_poll(None, ""), wait);
        assert_eq!(pair_poll(Some(500), "oops"), wait);
        assert_eq!(pair_poll(Some(200), "not json"), wait);
    }
}

#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{
        CoreDevice, CoreError, CorePairPreview, PairApproval, PairJoined, PairPoll, PairStatus,
        RosterContext, VerifiedRoster,
    };
    use crate::CoreSession;
    use sealbook_crypto::DeviceSigningSecrets;

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
    pub fn pair_join_body(
        username: String,
        device: CoreDevice,
        mldsa_seed_b64: String,
        ed25519_sk_b64: String,
    ) -> Result<String, CoreError> {
        super::pair_join_body(
            &username,
            &device,
            &secrets(&mldsa_seed_b64, &ed25519_sk_b64)?,
        )
    }

    #[uniffi::export]
    pub fn pair_join_accept(device: CoreDevice, body: String) -> Result<PairJoined, CoreError> {
        super::pair_join_accept(&device, &body)
    }

    #[uniffi::export]
    pub fn pair_poll(status: Option<u16>, body: String) -> PairPoll {
        super::pair_poll(status, &body)
    }

    #[uniffi::export]
    pub fn pair_status(status: u16, body: String) -> Result<PairStatus, CoreError> {
        super::pair_status(status, &body)
    }

    #[uniffi::export]
    pub fn pair_path(pair_key: String) -> String {
        super::pair_path(&pair_key)
    }

    #[uniffi::export]
    pub fn pair_approve_path(pair_key: String) -> String {
        super::pair_approve_path(&pair_key)
    }

    #[uniffi::export]
    pub fn pair_preview(
        ck_b64: Option<String>,
        key_epoch: u64,
        verified: VerifiedRoster,
        body: String,
    ) -> Result<CorePairPreview, CoreError> {
        super::pair_preview(&session(ck_b64, key_epoch)?, &verified, &body)
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
        preview: CorePairPreview,
        typed: String,
    ) -> Result<PairApproval, CoreError> {
        super::pair_approve(
            &secrets(&mldsa_seed_b64, &ed25519_sk_b64)?,
            &context,
            &session(ck_b64, key_epoch)?,
            &verified,
            &preview,
            &typed,
        )
    }

    #[uniffi::export]
    pub fn normalize_confirmation(entered: String) -> String {
        super::normalize_confirmation(&entered)
    }

    #[uniffi::export]
    pub fn confirmation_groups(code: String) -> Vec<String> {
        super::confirmation_groups(&code)
    }

    #[uniffi::export]
    pub fn format_confirmation(code: String) -> String {
        super::format_confirmation(&code)
    }
}
