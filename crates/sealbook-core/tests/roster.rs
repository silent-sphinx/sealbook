//! The shared roster-chain fixture, and core's decisions over it.
//!
//! Run `REGENERATE_ROSTER_FIXTURE=1 cargo test -p sealbook-core -- --ignored
//! regenerate` to rewrite the fixture after a deliberate wire change.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sealbook_core::{
    pin_roster, roster_accept, roster_accept_sealed, roster_answers_for, roster_request,
    CoreDeviceState, CoreError, CoreRoster, CoreRosterPin, CoreRosterSigner, CoreSession, Header,
    HttpResponse, Method, RosterContext,
};
use sealbook_crypto::{signing_from_seeds, CollectionKey, DeviceSigningSecrets};
use sealbook_protocol::{DevicePublicKeys, RosterBody, RosterSignerBody};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../sealbook-protocol/fixtures/rosters/chain-with-revoke.json"
);

const COLLECTION: &str = "11111111-1111-1111-1111-111111111111";
const ALPHA: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const BETA: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

#[derive(Serialize, Deserialize)]
struct Fixture {
    collection_id: Uuid,
    collection_key: String,
    key_epoch: u64,
    alpha_device_id: Uuid,
    beta_device_id: Uuid,
    floor: u64,
    rosters: Vec<RosterBody>,
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(text: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(text).expect("fixture base64")
}

fn fixture() -> Fixture {
    serde_json::from_str(&std::fs::read_to_string(FIXTURE).expect("roster fixture")).unwrap()
}

impl Fixture {
    fn key(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        key.copy_from_slice(&unb64(&self.collection_key));
        key
    }

    fn session(&self) -> CoreSession {
        CoreSession {
            collection_key: Some(self.key()),
            key_epoch: self.key_epoch,
            verified_roster: None,
        }
    }

    /// What the roster module reads, derived from the persisted state so the
    /// bridge is covered too.
    fn context(&self, seq: u64) -> RosterContext {
        self.state(seq).roster_context()
    }

    /// `alpha` at the pin named, with no pin when `seq` is 0.
    fn state(&self, seq: u64) -> CoreDeviceState {
        let transcript = if seq == 0 {
            Vec::new()
        } else {
            let roster = self
                .rosters
                .iter()
                .find(|roster| roster.roster_seq == seq)
                .expect("a roster at that sequence");
            roster.pin(self.collection_id).transcript.to_vec()
        };
        CoreDeviceState {
            server: "https://vault.example".into(),
            username: "alpha".into(),
            account_id: Uuid::nil(),
            collection_id: self.collection_id,
            device_id: self.alpha_device_id,
            session_token: Some("t".into()),
            kdf_salt: Vec::new(),
            hpke_sk: Vec::new(),
            mldsa_seed: Vec::new(),
            ed25519_sk: Vec::new(),
            manifest_seq: 0,
            roster_seq: seq,
            roster_transcript: transcript,
        }
    }

    /// What the server answers `roster_request` with, serving from `from` on.
    fn served(&self, from: u64, floor: u64) -> HttpResponse {
        let rosters: Vec<&RosterBody> = self
            .rosters
            .iter()
            .filter(|roster| roster.roster_seq >= from)
            .collect();
        HttpResponse {
            status: 200,
            headers: vec![Header {
                name: "content-type".into(),
                value: "application/json".into(),
            }],
            body: serde_json::to_vec(&serde_json::json!({ "rosters": rosters, "floor": floor }))
                .unwrap(),
        }
    }
}

#[test]
fn the_request_asks_from_the_pin_so_the_chain_can_be_checked() {
    let fixture = fixture();

    let unpinned = roster_request(&fixture.context(0)).unwrap();
    assert_eq!(unpinned.method, Method::Get);
    assert_eq!(
        unpinned.path,
        format!("/v1/collections/{COLLECTION}/roster")
    );
    assert!(unpinned.headers.is_empty(), "the token is the host's");

    assert_eq!(
        roster_request(&fixture.context(2)).unwrap().path,
        format!("/v1/collections/{COLLECTION}/roster?from=2")
    );
}

#[test]
fn a_chain_from_the_pin_verifies_and_yields_the_newest_roster() {
    let fixture = fixture();
    let verified = roster_accept(
        &fixture.context(1),
        &fixture.session(),
        &fixture.served(1, 1),
    )
    .expect("the chain from the first roster verifies");

    assert_eq!(verified.roster.roster_seq, 3);
    assert_eq!(verified.pin.roster_seq, 3);
    // The revoke is the point of this fixture: beta is in roster 2 and gone by 3.
    assert_eq!(
        verified.roster.devices.len(),
        1,
        "the revoked device is not in the roster this device ends on"
    );
    assert_eq!(
        verified.roster.devices[0].device_id,
        fixture.alpha_device_id
    );
    assert_eq!(
        verified.roster.signer,
        CoreRosterSigner::Device {
            device_id: fixture.alpha_device_id
        }
    );
    // The wire form is the same roster, not a re-shaped one.
    let wire: RosterBody = serde_json::from_str(&verified.roster_json).unwrap();
    assert_eq!(wire.roster_seq, 3);
    assert_eq!(
        b64(&wire.devices[0].mldsa_pk),
        verified.roster.devices[0].mldsa_pk
    );
}

#[test]
fn an_unpinned_device_takes_the_newest_roster_on_the_collection_key_alone() {
    let fixture = fixture();
    let verified = roster_accept(
        &fixture.context(0),
        &fixture.session(),
        &fixture.served(3, 3),
    )
    .expect("an unpinned device trusts the newest roster under its key");
    assert_eq!(verified.pin.roster_seq, 3);
}

#[test]
fn an_unpinned_device_with_no_collection_key_refuses_the_roster() {
    let fixture = fixture();
    let session = CoreSession::default();
    let err = roster_accept(&fixture.context(0), &session, &fixture.served(3, 3)).unwrap_err();
    assert_eq!(err.kind(), "Roster", "{err:?}");
}

#[test]
fn a_history_that_no_longer_reaches_the_pin_is_roster_too_old_not_a_forgery() {
    let fixture = fixture();
    // The server has trimmed to roster 2; this device is pinned on 1.
    let err = roster_accept(
        &fixture.context(1),
        &fixture.session(),
        &fixture.served(2, 2),
    )
    .unwrap_err();
    assert_eq!(err, CoreError::RosterTooOld);
}

#[test]
fn a_chain_that_does_not_start_at_the_pin_is_refused() {
    let fixture = fixture();
    // Floor says the pin is still served, but the history handed over starts
    // past it, so there is no link back to what this device accepted.
    let err = roster_accept(
        &fixture.context(1),
        &fixture.session(),
        &fixture.served(2, 1),
    )
    .unwrap_err();
    assert_eq!(err.kind(), "Roster", "{err:?}");
}

#[test]
fn a_device_the_roster_does_not_list_is_refused_its_own_account() {
    let fixture = fixture();
    let mut state = fixture.context(1);
    state.device_id = fixture.beta_device_id;
    // Beta was revoked in roster 3, so the chain verifies and then rejects it.
    let err = roster_accept(&state, &fixture.session(), &fixture.served(1, 1)).unwrap_err();
    assert_eq!(err.kind(), "Roster", "{err:?}");
}

#[test]
fn a_tampered_roster_breaks_the_chain() {
    let fixture = fixture();
    let mut rosters = fixture.rosters.clone();
    rosters[2].devices.push(DevicePublicKeys {
        device_id: Uuid::new_v4(),
        mldsa_pk: vec![1; 8],
        ed25519_pk: vec![2; 8],
        xwing_hpke_pk: vec![3; 8],
    });
    let response = HttpResponse {
        status: 200,
        headers: Vec::new(),
        body: serde_json::to_vec(&serde_json::json!({ "rosters": rosters, "floor": 1 })).unwrap(),
    };
    let err = roster_accept(&fixture.context(1), &fixture.session(), &response).unwrap_err();
    assert_eq!(err.kind(), "Roster", "{err:?}");
}

#[test]
fn a_response_that_is_not_a_roster_history_is_malformed_not_a_roster_failure() {
    let fixture = fixture();
    let response = HttpResponse {
        status: 200,
        headers: Vec::new(),
        body: b"<html>".to_vec(),
    };
    assert_eq!(
        roster_accept(&fixture.context(1), &fixture.session(), &response)
            .unwrap_err()
            .kind(),
        "Malformed"
    );
    let failed = HttpResponse {
        status: 503,
        headers: Vec::new(),
        body: Vec::new(),
    };
    assert_eq!(
        roster_accept(&fixture.context(1), &fixture.session(), &failed)
            .unwrap_err()
            .kind(),
        "Server"
    );
}

#[test]
fn a_roster_this_device_sealed_is_checked_at_its_own_key_epoch() {
    let fixture = fixture();
    let latest = fixture.rosters.last().unwrap();
    let json = serde_json::to_string(latest).unwrap();

    let verified = roster_accept_sealed(&fixture.context(2), &fixture.session(), &json)
        .expect("the roster this device signed verifies from no pin");
    assert_eq!(verified.pin.roster_seq, 3);

    // A session whose epoch has drifted still verifies, because the MAC is
    // checked at the roster's epoch rather than the session's.
    let mut drifted = fixture.session();
    drifted.key_epoch = fixture.key_epoch + 7;
    assert!(roster_accept_sealed(&fixture.context(2), &drifted, &json).is_ok());
}

#[test]
fn the_pin_moves_forward_and_never_back() {
    let fixture = fixture();
    let state = fixture.context(1);
    let verified = roster_accept(&state, &fixture.session(), &fixture.served(1, 1)).unwrap();

    let next = pin_roster(&state, &verified.pin).unwrap();
    assert_eq!(next.roster_seq, 3);
    assert_eq!(next.roster_transcript, verified.pin.transcript);
    // Nothing else the context names moves with a pin.
    assert_eq!(next.collection_id, state.collection_id);
    assert_eq!(next.device_id, state.device_id);

    let older = CoreRosterPin {
        roster_seq: 2,
        transcript: verified.pin.transcript.clone(),
    };
    assert_eq!(
        pin_roster(&next, &older).unwrap_err().kind(),
        "Roster",
        "pinned a roster older than the one already pinned"
    );
    // Re-pinning the same roster is not a rewind.
    assert!(pin_roster(&next, &verified.pin).is_ok());
}

#[test]
fn a_pin_that_is_not_a_32_byte_transcript_is_refused() {
    let fixture = fixture();
    let state = fixture.context(0);
    for transcript in ["", "not base64!", &b64(&[0u8; 16])] {
        let pin = CoreRosterPin {
            roster_seq: 4,
            transcript: transcript.to_string(),
        };
        assert!(
            pin_roster(&state, &pin).is_err(),
            "accepted a pin transcript of {transcript:?}"
        );
    }
}

#[test]
fn a_cached_roster_answers_only_for_a_signer_of_its_own_epoch() {
    let fixture = fixture();
    let verified = roster_accept(
        &fixture.context(1),
        &fixture.session(),
        &fixture.served(1, 1),
    )
    .unwrap();
    let roster: &CoreRoster = &verified.roster;
    let alpha = fixture.alpha_device_id;

    let epoch = Some(roster.key_epoch);
    assert!(roster_answers_for(Some(roster), epoch, Some(alpha)));
    assert!(!roster_answers_for(
        Some(roster),
        Some(roster.key_epoch + 1),
        Some(alpha)
    ));
    assert!(!roster_answers_for(
        Some(roster),
        epoch,
        Some(fixture.beta_device_id)
    ));
    assert!(!roster_answers_for(None, epoch, Some(alpha)));
    // A constraint left out is not checked, for the caller that wants whatever
    // roster this session has verified.
    assert!(roster_answers_for(Some(roster), None, None));
    assert!(roster_answers_for(Some(roster), None, Some(alpha)));
    assert!(!roster_answers_for(None, None, None));
}

#[test]
fn the_pin_transcript_is_the_alphabet_the_hosts_already_store() {
    let fixture = fixture();
    let verified = roster_accept(
        &fixture.context(1),
        &fixture.session(),
        &fixture.served(1, 1),
    )
    .unwrap();
    let transcript = &verified.pin.transcript;
    // URL-safe and unpadded, like every other base64 field in the protocol: a
    // host that stored the standard alphabet instead would hand back a pin
    // core cannot read.
    assert!(
        !transcript.contains(['+', '/', '=']),
        "pin transcript is not URL-safe unpadded base64: {transcript}"
    );
    assert_eq!(unb64(transcript).len(), 32);
}

#[test]
#[ignore = "writes the shared fixture; run with REGENERATE_ROSTER_FIXTURE=1"]
fn regenerate_the_roster_chain_fixture() {
    assert!(
        std::env::var("REGENERATE_ROSTER_FIXTURE").is_ok(),
        "set REGENERATE_ROSTER_FIXTURE=1 to confirm overwriting the shared fixture"
    );
    std::fs::write(FIXTURE, built_fixture()).unwrap();
}

#[test]
fn the_checked_in_fixture_is_what_the_generator_builds() {
    let collection: Uuid = COLLECTION.parse().unwrap();
    let built: Fixture = serde_json::from_str(&built_fixture()).unwrap();
    let stored = fixture();
    assert_eq!(stored.collection_id, built.collection_id);
    assert_eq!(stored.collection_key, built.collection_key);
    assert_eq!(stored.alpha_device_id, built.alpha_device_id);
    assert_eq!(
        stored.rosters.len(),
        built.rosters.len(),
        "regenerate the fixture: REGENERATE_ROSTER_FIXTURE=1"
    );
    for (stored, built) in stored.rosters.iter().zip(&built.rosters) {
        // Transcripts, not signatures: ML-DSA signing need not be deterministic.
        assert_eq!(
            stored.to_roster().transcript(collection),
            built.to_roster().transcript(collection),
            "regenerate the fixture: REGENERATE_ROSTER_FIXTURE=1"
        );
    }
}

/// Alpha registers, pairs beta, then revokes it: three roster steps under one
/// collection key, each signed by a device the step before lists.
fn built_fixture() -> String {
    let collection_id: Uuid = COLLECTION.parse().unwrap();
    let alpha_device_id: Uuid = ALPHA.parse().unwrap();
    let beta_device_id: Uuid = BETA.parse().unwrap();
    let key = CollectionKey([7u8; 32]);
    let key_epoch = 1;

    let (alpha_secrets, alpha_public) = signing_from_seeds(&[1u8; 32], &[2u8; 32]);
    let (_, beta_public) = signing_from_seeds(&[3u8; 32], &[4u8; 32]);
    let (_, phrase_public) = signing_from_seeds(&[5u8; 32], &[6u8; 32]);

    let device =
        |id: Uuid, public: &sealbook_crypto::DeviceSigningPublic, hpke: u8| DevicePublicKeys {
            device_id: id,
            mldsa_pk: public.mldsa_pk.clone(),
            ed25519_pk: public.ed25519_pk.clone(),
            xwing_hpke_pk: vec![hpke; 32],
        };
    let alpha = device(alpha_device_id, &alpha_public, 8);
    let beta = device(beta_device_id, &beta_public, 9);

    let seal = |seq: u64, devices: Vec<DevicePublicKeys>, by: &DeviceSigningSecrets| {
        RosterBody::seal(
            collection_id,
            seq,
            key_epoch,
            devices,
            phrase_public.mldsa_pk.clone(),
            phrase_public.ed25519_pk.clone(),
            RosterSignerBody::Device {
                device_id: alpha_device_id,
            },
            by,
            &key,
        )
        .unwrap()
    };

    let rosters = vec![
        seal(1, vec![alpha.clone()], &alpha_secrets),
        seal(2, vec![alpha.clone(), beta], &alpha_secrets),
        seal(3, vec![alpha], &alpha_secrets),
    ];

    let fixture = Fixture {
        collection_id,
        collection_key: b64(&key.0),
        key_epoch,
        alpha_device_id,
        beta_device_id,
        floor: 1,
        rosters,
    };
    let mut json = serde_json::to_string_pretty(&fixture).unwrap();
    json.push('\n');
    json
}
