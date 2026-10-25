//! The state a device keeps, split by whether it is persisted.

use crate::CoreError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

/// Exactly the field set all three clients already persist, so a host converts
/// to and from its own on-disk format in memory and no stored format changes.
///
/// Plain data, with no zeroizing `Drop`: the secrets are lowered across both
/// bindings and persisted by the host, so the copy that lives long enough to
/// matter is the host's. The CLI keeps that wiping in its own `LocalState`
/// wrapper rather than aliasing this type.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreDeviceState {
    pub server: String,
    pub username: String,
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub account_id: Uuid,
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub collection_id: Uuid,
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub device_id: Uuid,
    #[serde(default)]
    pub session_token: Option<String>,
    pub kdf_salt: Vec<u8>,
    pub hpke_sk: Vec<u8>,
    pub mldsa_seed: Vec<u8>,
    pub ed25519_sk: Vec<u8>,
    /// Highest manifest sequence accepted. The only freshness the client has:
    /// a server can still freeze a device at a real past state, not rewind it.
    #[serde(default)]
    pub manifest_seq: u64,
    /// The pinned roster, by sequence and transcript. Every later roster has to
    /// be reached from this one along device-signed steps. 0 means unpinned.
    #[serde(default)]
    pub roster_seq: u64,
    #[serde(default)]
    pub roster_transcript: Vec<u8>,
}

impl CoreDeviceState {
    /// The pin to check a roster chain against, or `None` while unpinned.
    ///
    /// A nonzero sequence whose transcript is not a 32-byte digest is an error,
    /// not an unpinned device: returning `None` there would trust the next
    /// roster the server serves.
    pub fn roster_pin(&self) -> Result<Option<sealbook_crypto::RosterPin>, CoreError> {
        if self.roster_seq == 0 && self.roster_transcript.is_empty() {
            return Ok(None);
        }
        if self.roster_seq == 0 || self.roster_transcript.len() != 32 {
            return Err(CoreError::roster(
                "stored roster pin is incomplete; it must not be treated as unpinned",
            ));
        }
        let mut transcript = [0u8; 32];
        transcript.copy_from_slice(&self.roster_transcript);
        Ok(Some(sealbook_crypto::RosterPin {
            roster_seq: self.roster_seq,
            transcript,
        }))
    }
}

/// Values a host holds for the life of a session and must never write down.
#[derive(Clone, Default)]
pub struct CoreSession {
    pub collection_key: Option<[u8; 32]>,
    pub key_epoch: u64,
    /// The roster this device last verified, kept so a second check in the same
    /// session does not have to re-walk the chain.
    pub verified_roster: Option<String>,
}

impl Drop for CoreSession {
    fn drop(&mut self) {
        if let Some(key) = &mut self.collection_key {
            key.zeroize();
        }
    }
}
