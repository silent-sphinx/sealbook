//! Roster decisions: what to ask the server for, whether what came back can be
//! trusted, and when the pin moves.
//!
//! The bearer token stays with the host, which owns session refresh and the 401
//! path; nothing here is signed over it. Every host also raises a response that
//! is not a success before core sees it, so the status check in
//! [`roster_accept`] is a guard rather than the error path.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sealbook_crypto::{CollectionKey, RosterPin};
use sealbook_protocol::{DevicePublicKeys, RosterBody, RosterResponse, RosterSignerBody};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{CoreError, CoreSession, HttpRequest, HttpResponse, Method};

/// Just what a roster decision reads out of the persisted state.
///
/// Narrow on purpose: a host converts four fields rather than its whole stored
/// format, and the transcript is base64 as all three already hold it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RosterContext {
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub collection_id: Uuid,
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub device_id: Uuid,
    /// 0 means unpinned.
    pub roster_seq: u64,
    pub roster_transcript: String,
}

impl RosterContext {
    /// The pin to check a chain against, or `None` while unpinned.
    ///
    /// A nonzero sequence whose transcript is not a 32-byte digest is an error,
    /// not an unpinned device: returning `None` there would trust the next
    /// roster the server serves.
    pub fn pin(&self) -> Result<Option<RosterPin>, CoreError> {
        if self.roster_seq == 0 && self.roster_transcript.is_empty() {
            return Ok(None);
        }
        let transcript = decode(&self.roster_transcript, "stored roster transcript")?;
        if self.roster_seq == 0 || transcript.len() != 32 {
            return Err(CoreError::roster(
                "stored roster pin is incomplete; it must not be treated as unpinned",
            ));
        }
        let mut pinned = [0u8; 32];
        pinned.copy_from_slice(&transcript);
        Ok(Some(RosterPin {
            roster_seq: self.roster_seq,
            transcript: pinned,
        }))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreDevice {
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub device_id: Uuid,
    pub mldsa_pk: String,
    pub ed25519_pk: String,
    pub xwing_hpke_pk: String,
}

/// Who signed a roster step. A phrase signer is a recovery, which is why it
/// carries no device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum CoreRosterSigner {
    Device {
        #[cfg_attr(feature = "wasm", tsify(type = "string"))]
        device_id: Uuid,
    },
    Phrase,
}

/// A roster as a host reads it, with the binary fields base64 as all three
/// clients already hold them. The signature and MAC are not here: they are
/// spent by the time this exists, and a host has no use for them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreRoster {
    pub roster_seq: u64,
    pub key_epoch: u64,
    pub devices: Vec<CoreDevice>,
    pub phrase_mldsa_pk: String,
    pub phrase_ed25519_pk: String,
    pub signer: CoreRosterSigner,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreRosterPin {
    pub roster_seq: u64,
    /// base64 of the 32-byte transcript.
    pub transcript: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct VerifiedRoster {
    pub roster: CoreRoster,
    /// The pin to store in place of the old one. Storing it is a separate step:
    /// a read of the roster may not move the pin.
    pub pin: CoreRosterPin,
    /// The verified roster in wire form, for a host that must hand the same
    /// bytes on to a signature or cache them for the session.
    pub roster_json: String,
}

/// The request that fetches the roster history this device can check.
///
/// `from` is the pinned sequence, so the server serves the chain back to it. A
/// lagging pin costs a longer chain to check, never any trust. Unpinned, only
/// the newest roster is asked for, and it is then trusted on the collection key
/// alone.
pub fn roster_request(context: &RosterContext) -> Result<HttpRequest, CoreError> {
    let collection = context.collection_id;
    let path = match context.pin()? {
        Some(pin) => format!(
            "/v1/collections/{collection}/roster?from={}",
            pin.roster_seq
        ),
        None => format!("/v1/collections/{collection}/roster"),
    };
    Ok(HttpRequest {
        method: Method::Get,
        path,
        headers: Vec::new(),
        body: Vec::new(),
    })
}

/// Verifies a served roster history from this device's pin.
///
/// Does not move the pin; [`pin_roster`] does.
pub fn roster_accept(
    context: &RosterContext,
    session: &CoreSession,
    response: &HttpResponse,
) -> Result<VerifiedRoster, CoreError> {
    if response.status != 200 {
        return Err(CoreError::Server {
            detail: format!("the roster request returned HTTP {}", response.status),
        });
    }
    let served: RosterResponse = serde_json::from_slice(&response.body)
        .map_err(|err| CoreError::malformed(format!("the roster response is unreadable: {err}")))?;
    let pin = context.pin()?;
    if let Some(pin) = &pin {
        if served.floor > pin.roster_seq {
            return Err(CoreError::RosterTooOld);
        }
    }
    verify(
        context,
        session.collection_key,
        session.key_epoch,
        pin,
        served.rosters,
    )
}

/// Verifies a roster this device sealed itself, once the server has accepted it.
///
/// Checked from no pin rather than trusted directly, because that check is what
/// computes the pin and it is the one the server applies too: a step this device
/// could not verify is one it should not have sent. Verified at the roster's own
/// key epoch, so the MAC is never the arm `verify_roster_chain` skips. The host
/// holds the key it was MAC'd under by construction, having just sealed it.
pub fn roster_accept_sealed(
    context: &RosterContext,
    session: &CoreSession,
    roster_json: &str,
) -> Result<VerifiedRoster, CoreError> {
    let roster: RosterBody = serde_json::from_str(roster_json)
        .map_err(|err| CoreError::malformed(format!("the sealed roster is unreadable: {err}")))?;
    let epoch = roster.key_epoch;
    verify(context, session.collection_key, epoch, None, vec![roster])
}

/// Records the roster this device has accepted, returning the state to persist.
///
/// A pin never moves backwards: every roster accepted from here on has to be
/// reachable from this one along device-signed steps.
pub fn pin_roster(
    context: &RosterContext,
    pin: &CoreRosterPin,
) -> Result<RosterContext, CoreError> {
    if pin.roster_seq < context.roster_seq {
        return Err(CoreError::roster("refusing to pin an older device roster"));
    }
    if pin.roster_seq == 0 || decode(&pin.transcript, "roster pin transcript")?.len() != 32 {
        return Err(CoreError::roster(
            "a roster pin is a sequence and a 32-byte transcript",
        ));
    }
    Ok(RosterContext {
        roster_seq: pin.roster_seq,
        roster_transcript: pin.transcript.clone(),
        ..context.clone()
    })
}

/// The fields a host reads out of a wire roster.
///
/// Verifies nothing: for a roster that has already been through
/// [`roster_accept`] or that is about to be, so a host does not parse the wire
/// shape itself.
pub fn read_roster(roster_json: &str) -> Result<CoreRoster, CoreError> {
    let body: RosterBody = serde_json::from_str(roster_json)
        .map_err(|err| CoreError::malformed(format!("the roster is unreadable: {err}")))?;
    Ok(read(&body))
}

/// Whether a roster already in hand can answer the caller, or the chain has to
/// be walked again.
///
/// A constraint given is checked: the epoch has to match, because a revocation
/// is always a rotation and so the epoch moving is what a device having been
/// removed looks like from here, and a signer has to be listed, because one that
/// is not is a pairing elsewhere. A constraint left out is not checked, for the
/// caller that wants whatever roster this session has verified.
pub fn roster_answers_for(
    cached: Option<&CoreRoster>,
    key_epoch: Option<u64>,
    signer: Option<Uuid>,
) -> bool {
    cached.is_some_and(|roster| {
        key_epoch.is_none_or(|epoch| roster.key_epoch == epoch)
            && signer.is_none_or(|signer| {
                roster
                    .devices
                    .iter()
                    .any(|device| device.device_id == signer)
            })
    })
}

fn verify(
    context: &RosterContext,
    key: Option<[u8; 32]>,
    key_epoch: u64,
    pin: Option<RosterPin>,
    chain: Vec<RosterBody>,
) -> Result<VerifiedRoster, CoreError> {
    let collection = context.collection_id;
    let key = key.map(CollectionKey);
    let latest = RosterBody::verify_chain(
        collection,
        pin,
        chain,
        key.as_ref().map(|key| (key, key_epoch)),
        context.device_id,
    )?;
    let transcript = latest.pin(collection).transcript;
    Ok(VerifiedRoster {
        roster: read(&latest),
        pin: CoreRosterPin {
            roster_seq: latest.roster_seq,
            transcript: encode(&transcript),
        },
        roster_json: serde_json::to_string(&latest)?,
    })
}

fn read(body: &RosterBody) -> CoreRoster {
    CoreRoster {
        roster_seq: body.roster_seq,
        key_epoch: body.key_epoch,
        devices: body
            .devices
            .iter()
            .map(|device| CoreDevice {
                device_id: device.device_id,
                mldsa_pk: encode(&device.mldsa_pk),
                ed25519_pk: encode(&device.ed25519_pk),
                xwing_hpke_pk: encode(&device.xwing_hpke_pk),
            })
            .collect(),
        phrase_mldsa_pk: encode(&body.phrase_mldsa_pk),
        phrase_ed25519_pk: encode(&body.phrase_ed25519_pk),
        signer: match body.signer {
            RosterSignerBody::Device { device_id } => CoreRosterSigner::Device { device_id },
            RosterSignerBody::Phrase => CoreRosterSigner::Phrase,
        },
    }
}

impl From<&DevicePublicKeys> for CoreDevice {
    fn from(device: &DevicePublicKeys) -> Self {
        CoreDevice {
            device_id: device.device_id,
            mldsa_pk: encode(&device.mldsa_pk),
            ed25519_pk: encode(&device.ed25519_pk),
            xwing_hpke_pk: encode(&device.xwing_hpke_pk),
        }
    }
}

// Every base64 field in the protocol is URL-safe and unpadded, including the
// ones the hosts already have stored, so core has to agree with it.
fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(feature = "uniffi")]
fn collection_key(ck_b64: &str) -> Result<[u8; 32], CoreError> {
    let bytes = decode(ck_b64, "collection key")?;
    if bytes.len() != 32 {
        return Err(CoreError::malformed("a collection key is 32 bytes"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn decode(text: &str, what: &str) -> Result<Vec<u8>, CoreError> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|err| CoreError::malformed(format!("{what} is not base64: {err}")))
}

/// The uniffi surface for the decisions above.
///
/// Separate because uniffi lowers records by value rather than borrowing them,
/// and because a host's transport has already raised anything that is not a
/// success, so these take the response body alone.
#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{CoreError, CoreRoster, CoreRosterPin, HttpRequest, RosterContext, VerifiedRoster};
    use crate::{CoreSession, HttpResponse};
    use uuid::Uuid;

    fn session(ck_b64: Option<String>, key_epoch: u64) -> Result<CoreSession, CoreError> {
        let collection_key = match ck_b64 {
            Some(text) => Some(super::collection_key(&text)?),
            None => None,
        };
        Ok(CoreSession {
            collection_key,
            key_epoch,
            verified_roster: None,
        })
    }

    fn ok(body: String) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: body.into_bytes(),
        }
    }

    #[uniffi::export]
    pub fn roster_request(context: RosterContext) -> Result<HttpRequest, CoreError> {
        super::roster_request(&context)
    }

    #[uniffi::export]
    pub fn roster_accept(
        context: RosterContext,
        ck_b64: Option<String>,
        key_epoch: u64,
        body: String,
    ) -> Result<VerifiedRoster, CoreError> {
        super::roster_accept(&context, &session(ck_b64, key_epoch)?, &ok(body))
    }

    #[uniffi::export]
    pub fn roster_accept_sealed(
        context: RosterContext,
        ck_b64: Option<String>,
        roster_json: String,
    ) -> Result<VerifiedRoster, CoreError> {
        super::roster_accept_sealed(&context, &session(ck_b64, 0)?, &roster_json)
    }

    #[uniffi::export]
    pub fn pin_roster(
        context: RosterContext,
        pin: CoreRosterPin,
    ) -> Result<RosterContext, CoreError> {
        super::pin_roster(&context, &pin)
    }

    #[uniffi::export]
    pub fn read_roster(roster_json: String) -> Result<CoreRoster, CoreError> {
        super::read_roster(&roster_json)
    }

    #[uniffi::export]
    pub fn roster_answers_for(
        cached: CoreRoster,
        key_epoch: Option<u64>,
        signer: Option<Uuid>,
    ) -> bool {
        super::roster_answers_for(Some(&cached), key_epoch, signer)
    }
}
