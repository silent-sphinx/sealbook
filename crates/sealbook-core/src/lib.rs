//! Sealbook's client decisions, with no I/O and nothing async.
//!
//! Everything that decides what goes to the server and what is accepted back
//! lives here, so that all four clients behaving the same is a property of the
//! build rather than of review. The hosts keep transport, persistence and UI:
//! `sealbook-client` wraps this in `reqwest` for the CLI, `sealbook-wasm` hands
//! it to the web and Firefox, `sealbook-android` to Kotlin over uniffi.
//!
//! Two rules hold for every function added here. It is a pure function of its
//! inputs, which means no clock, no randomness a caller did not pass, and no
//! network. And it is wire-identical to the implementation it replaces: the
//! protocol generation stays [`PROTOCOL_VERSION`].

mod error;
mod http;
mod manifest;
mod roster;
mod rotation;
mod state;
mod sync;

// uniffi's scaffolding and custom types have to sit in the crate root.
#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

#[cfg(feature = "uniffi")]
use uuid::Uuid;

#[cfg(feature = "uniffi")]
uniffi::custom_type!(Uuid, String, {
    remote,
    lower: |id| id.to_string(),
    try_lift: |s| Ok(s.parse::<Uuid>()?),
});

pub use error::CoreError;
pub use http::{Header, HttpRequest, HttpResponse, Method, Step};
pub use manifest::{
    accept_manifest_seq, core_entries, manifest_absence_ok, manifest_accept, manifest_apply,
    manifest_buckets_accept, manifest_buckets_from_whole, manifest_buckets_request,
    manifest_entry_for, manifest_request, manifest_sign, manifest_sign_root, manifest_signer,
    manifest_verify, wire_entries, AppliedManifest, BucketedManifest, BucketsOutcome,
    CoreManifestEntry, ManifestContext, ManifestOutcome, ManifestPlan, ManifestSigner,
    SignedManifest,
};
pub use roster::{
    pin_roster, read_roster, roster_accept, roster_accept_sealed, roster_answers_for,
    roster_request, CoreDevice, CoreRoster, CoreRosterPin, CoreRosterSigner, RosterContext,
    VerifiedRoster,
};
pub use rotation::{
    reseal_row, rotation_entries, rotation_plan, rotation_recipients, ResealRow, RotationPlan,
    RotationRefusal, RotationState,
};
pub use state::{CoreDeviceState, CoreSession};
pub use sync::{
    changes_request, latest_revisions, open_row, open_stored, require_key_epoch, walk_page,
    walk_start, ChangesPage, CoreSealedRow, RowOutcome, RowRef, StoredRow, UnreadableReason,
    WalkCursor, WalkOutcome, WalkStep, CHANGES_PAGE_LIMIT, SYNC_RESTART_LIMIT,
};

pub use sealbook_protocol::{PAYLOAD_SCHEMA_VERSION, PROTOCOL_VERSION};

/// This core build, for the pinning check each client's build runs.
///
/// Boundary types derive `Tsify` for their TypeScript declaration only. The
/// wasm ABI attributes are deliberately absent: they leak the whole wasm heap
/// when JavaScript passes a value serde cannot read, so `sealbook-wasm` takes
/// and returns `Ts<T>` and deserializes inside the function instead.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreBuild {
    pub core_version: String,
    pub protocol_version: String,
    pub payload_schema_version: String,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn core_build() -> CoreBuild {
    CoreBuild {
        core_version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        payload_schema_version: PAYLOAD_SCHEMA_VERSION.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn state() -> CoreDeviceState {
        CoreDeviceState {
            server: "https://vault.example".into(),
            username: "alice".into(),
            account_id: Uuid::from_u128(1),
            collection_id: Uuid::from_u128(2),
            device_id: Uuid::from_u128(3),
            session_token: None,
            kdf_salt: vec![0; 16],
            hpke_sk: vec![0; 32],
            mldsa_seed: vec![0; 32],
            ed25519_sk: vec![0; 32],
            manifest_seq: 0,
            roster_seq: 0,
            roster_transcript: Vec::new(),
        }
    }

    #[test]
    fn the_build_reports_the_generation_it_speaks() {
        assert_eq!(core_build().protocol_version, "sealbook-v1");
    }

    #[test]
    fn a_fresh_device_has_no_roster_pin() {
        assert!(state().roster_pin().unwrap().is_none());
    }

    #[test]
    fn a_corrupt_roster_pin_is_an_error_not_an_unpinned_device() {
        let mut state = state();
        state.roster_seq = 4;
        state.roster_transcript = vec![0; 7];
        assert!(matches!(state.roster_pin(), Err(CoreError::Roster { .. })));

        state.roster_seq = 0;
        state.roster_transcript = vec![0; 32];
        assert!(matches!(state.roster_pin(), Err(CoreError::Roster { .. })));
    }

    #[test]
    fn a_pinned_device_carries_its_transcript() {
        let mut state = state();
        state.roster_seq = 9;
        state.roster_transcript = vec![7; 32];
        let pin = state.roster_pin().unwrap().expect("pinned");
        assert_eq!(pin.roster_seq, 9);
        assert_eq!(pin.transcript, [7u8; 32]);
    }

    #[test]
    fn persisted_state_round_trips_through_the_fields_the_clients_store() {
        let json = serde_json::to_string(&state()).unwrap();
        let back: CoreDeviceState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.username, "alice");
        assert_eq!(back.manifest_seq, 0);
    }

    #[test]
    fn a_response_header_lookup_ignores_case() {
        let response = HttpResponse {
            status: 200,
            headers: vec![Header {
                name: "X-Sealbook-Nonce".into(),
                value: "abc".into(),
            }],
            body: Vec::new(),
        };
        assert_eq!(response.header("x-sealbook-nonce"), Some("abc"));
    }
}
