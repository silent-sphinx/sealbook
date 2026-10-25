//! The per-device state a caller persists between runs.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Clone, Serialize, Deserialize)]
pub struct LocalState {
    pub server: String,
    pub username: String,
    pub account_id: Uuid,
    pub collection_id: Uuid,
    pub device_id: Uuid,
    pub session_token: Option<String>,
    pub kdf_salt: Vec<u8>,
    pub hpke_sk: Vec<u8>,
    pub mldsa_seed: Vec<u8>,
    pub ed25519_sk: Vec<u8>,
    /// Highest manifest sequence this device has accepted.
    ///
    /// Remembered so that a server cannot serve an older manifest, or claim to
    /// have none at all, once this device has seen one. It is the only freshness
    /// the client has: the server is the only source of manifests, so it can still
    /// freeze a device at a real past state, just not rewind it.
    #[serde(default)]
    pub manifest_seq: u64,
    /// The last device roster this device accepted, by sequence and transcript.
    ///
    /// Every later roster has to be reached from this one along device-signed
    /// steps, so a server cannot slip a device of its own into the set. 0 means
    /// nothing is pinned yet.
    #[serde(default)]
    pub roster_seq: u64,
    #[serde(default)]
    pub roster_transcript: Vec<u8>,
}

impl LocalState {
    /// The same fields core names, for the decisions core makes.
    pub fn to_core(&self) -> sealbook_core::CoreDeviceState {
        sealbook_core::CoreDeviceState {
            server: self.server.clone(),
            username: self.username.clone(),
            account_id: self.account_id,
            collection_id: self.collection_id,
            device_id: self.device_id,
            session_token: self.session_token.clone(),
            kdf_salt: self.kdf_salt.clone(),
            hpke_sk: self.hpke_sk.clone(),
            mldsa_seed: self.mldsa_seed.clone(),
            ed25519_sk: self.ed25519_sk.clone(),
            manifest_seq: self.manifest_seq,
            roster_seq: self.roster_seq,
            roster_transcript: self.roster_transcript.clone(),
        }
    }
}

impl Drop for LocalState {
    fn drop(&mut self) {
        self.hpke_sk.zeroize();
        self.mldsa_seed.zeroize();
        self.ed25519_sk.zeroize();
        if let Some(token) = &mut self.session_token {
            token.zeroize();
        }
    }
}
