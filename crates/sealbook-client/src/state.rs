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
    /// A value that changes whenever anything persisted in this state does: the
    /// session token, the manifest sequence, the pinned roster.
    ///
    /// A host compares it before and after a round of work to know when to save
    /// the state again. It is a 64-bit non-cryptographic hash, for comparing within
    /// one process; it is not stable across builds and is never to be stored.
    pub fn fingerprint(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.server.hash(&mut hasher);
        self.username.hash(&mut hasher);
        self.account_id.hash(&mut hasher);
        self.collection_id.hash(&mut hasher);
        self.device_id.hash(&mut hasher);
        self.session_token.hash(&mut hasher);
        self.hpke_sk.hash(&mut hasher);
        self.mldsa_seed.hash(&mut hasher);
        self.ed25519_sk.hash(&mut hasher);
        self.manifest_seq.hash(&mut hasher);
        self.roster_seq.hash(&mut hasher);
        self.roster_transcript.hash(&mut hasher);
        hasher.finish()
    }

    /// The same fields core names, for the decisions core makes.
    pub fn to_core(&self) -> sealbook_core::CoreDeviceState {
        sealbook_core::CoreDeviceState {
            server: self.server.clone(),
            username: self.username.clone(),
            account_id: self.account_id,
            collection_id: self.collection_id,
            device_id: self.device_id,
            session_token: self.session_token.clone(),
            hpke_sk: self.hpke_sk.clone(),
            mldsa_seed: self.mldsa_seed.clone(),
            ed25519_sk: self.ed25519_sk.clone(),
            manifest_seq: self.manifest_seq,
            roster_seq: self.roster_seq,
            roster_transcript: self.roster_transcript.clone(),
        }
    }

    /// Back from core's shape, for the flows where core decides what this
    /// device persists.
    pub fn from_core(state: sealbook_core::CoreDeviceState) -> Self {
        LocalState {
            server: state.server,
            username: state.username,
            account_id: state.account_id,
            collection_id: state.collection_id,
            device_id: state.device_id,
            session_token: state.session_token,
            hpke_sk: state.hpke_sk,
            mldsa_seed: state.mldsa_seed,
            ed25519_sk: state.ed25519_sk,
            manifest_seq: state.manifest_seq,
            roster_seq: state.roster_seq,
            roster_transcript: state.roster_transcript,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> LocalState {
        LocalState {
            server: "https://sealbook.example".into(),
            username: "ada".into(),
            account_id: Uuid::from_u128(1),
            collection_id: Uuid::from_u128(2),
            device_id: Uuid::from_u128(3),
            session_token: Some("token".into()),
            hpke_sk: vec![1],
            mldsa_seed: vec![2],
            ed25519_sk: vec![3],
            manifest_seq: 4,
            roster_seq: 5,
            roster_transcript: vec![6],
        }
    }

    #[test]
    fn the_fingerprint_follows_what_is_persisted() {
        let before = state();
        assert_eq!(before.fingerprint(), before.clone().fingerprint());

        let mut changed = before.clone();
        changed.manifest_seq += 1;
        assert_ne!(changed.fingerprint(), before.fingerprint());

        let mut changed = before.clone();
        changed.roster_transcript = vec![7];
        assert_ne!(changed.fingerprint(), before.fingerprint());

        let mut changed = before.clone();
        changed.session_token = None;
        assert_ne!(changed.fingerprint(), before.fingerprint());
    }
}
