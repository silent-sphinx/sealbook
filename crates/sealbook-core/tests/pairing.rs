//! The shared pairing fixture, and what core makes of it.
//!
//! One account with two enrolled devices and a third asking to join, through
//! every step of the PAKE handshake as each side sees it: the code the joining
//! device makes, the approving device's answer to it, the joining device's
//! sealed reply, the preview, the approval, and the roster pin the joining
//! device ends up trusting. Then every refusal either side can raise.
//!
//! Held to the same document as `sealbook-web/src/lib/pairingParity.test.ts`
//! and Android's `DevicePairingTest`, so a pairing that differs here differs
//! from the other clients rather than from a copy of their output.
//!
//! Run `REGENERATE_PAIRING_FIXTURE=1 cargo test -p sealbook-core -- --ignored
//! regenerate` to rewrite the fixture after a deliberate change.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sealbook_core::{
    pair_approve, pair_approve_path, pair_approve_poll, pair_cancel_path, pair_confirm_path,
    pair_confirm_with_rng, pair_finish, pair_join_accept, pair_join_poll, pair_lookup_path,
    pair_path, pair_preview, pair_respond, pair_respond_path, pair_respond_with_rng,
    pair_start_with_rng, read_roster, roster_accept_sealed, CoreDevice, CoreError, CorePairPreview,
    CorePairResponse, CoreRosterPin, CoreSession, PairApprovePoll, PairJoinPoll, PairJoined,
    PairRefusal, PairResponded, PairStarted, RosterContext, VerifiedRoster, PAIR_POLL_INTERVAL_MS,
};
use sealbook_crypto::{
    pair_grant_transcript, signing_from_seeds, CollectionKey, DeviceSigningSecrets, RosterPin,
};
use sealbook_protocol::{
    DevicePublicKeys, PairApproveRequest, PairConfirmRequest, PairJoinRequest, PairJoinResponse,
    PairRespondRequest, PairStatusResponse, RosterBody, RosterSignerBody,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../sealbook-protocol/fixtures/pairing/handshake.json"
);

const COLLECTION: &str = "11111111-1111-1111-1111-111111111111";
const ALPHA: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const BETA: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const JOINING: &str = "dddddddd-dddd-dddd-dddd-dddddddddddd";
const INTRUDER: &str = "99999999-9999-9999-9999-999999999999";
const PAIR_ID: &str = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee";
const USERNAME: &str = "alice";
/// The manifest sequence the approver vouches for, sealed next to the roster pin.
const APPROVER_MANIFEST_SEQ: u64 = 9;
const DESCRIPTION: &str = "Firefox on macOS";
const WAIT_JOIN: PairJoinPoll = PairJoinPoll::Wait {
    after_ms: PAIR_POLL_INTERVAL_MS,
};
const WAIT_APPROVE: PairApprovePoll = PairApprovePoll::Wait {
    after_ms: PAIR_POLL_INTERVAL_MS,
};

#[derive(Serialize, Deserialize)]
struct Fixture {
    collection_id: Uuid,
    collection_key: String,
    /// The epoch the roster below is sealed at, and which an approving device
    /// has to be holding.
    key_epoch: u64,
    username: String,
    /// What the joining device says it is.
    description: String,
    /// The device doing the approving, with the secrets it signs with.
    approver: Device,
    /// The roster the approval extends, as the approver verified it from its
    /// own pin.
    verified: VerifiedRoster,
    /// The device asking to join, with the secrets it signs its enrollment
    /// with.
    joining: Device,
    pair_id: Uuid,
    /// Step 1, joining: the code, the join request, and this side's state.
    started: PairStarted,
    join_response: String,
    joined: PairJoined,
    /// Step 2, approving: the pairing as the approver is served it, the code as
    /// the user typed it, and the approver's answer.
    typed: String,
    pending_response: String,
    responded: PairResponded,
    /// Step 3, joining: the pairing with the approver's share, and the sealed
    /// reply.
    responded_response: String,
    confirm_body: String,
    /// Step 4, approving: the pairing with the reply, and what it opens to.
    confirmed_response: String,
    preview: CorePairPreview,
    /// Step 6, joining: the approved pairing, the roster the approval signed,
    /// and the pin the joining device opens from it.
    ready_response: String,
    approved_roster_json: String,
    finished: CoreRosterPin,
    respond_refusals: Vec<RespondRefusal>,
    preview_refusals: Vec<PreviewRefusal>,
    finish_refusals: Vec<FinishRefusal>,
    /// Codes as a user might enter them, and the lookup path or refusal.
    codes: Vec<CodeCase>,
    paths: Vec<PathCase>,
    join_polls: Vec<JoinPollCase>,
    approve_polls: Vec<ApprovePollCase>,
}

/// A device as its host holds it: the public keys the protocol carries and the
/// signing secrets behind them.
#[derive(Clone, Serialize, Deserialize)]
struct Device {
    device: CoreDevice,
    mldsa_seed: String,
    ed25519_sk: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RespondRefusal {
    what: String,
    typed: String,
    response: String,
    /// The epoch the approving device holds, which only the rotation case
    /// differs on.
    held_epoch: u64,
    refusal: PairRefusal,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PreviewRefusal {
    what: String,
    /// The approver's state from its own answer.
    response: CorePairResponse,
    /// The pairing as served once the joining device replied.
    body: String,
    refusal: PairRefusal,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FinishRefusal {
    what: String,
    body: String,
    refusal: PairRefusal,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct CodeCase {
    typed: String,
    path: Option<String>,
    refusal: Option<PairRefusal>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PathCase {
    /// A nameplate, or the pair id the joining device polls by.
    key: String,
    path: String,
    respond: String,
    confirm: String,
    approve: String,
    cancel: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct JoinPollCase {
    what: String,
    status: Option<u16>,
    body: String,
    decision: PairJoinPoll,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ApprovePollCase {
    what: String,
    status: Option<u16>,
    body: String,
    decision: PairApprovePoll,
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn fixture() -> Fixture {
    serde_json::from_str(&std::fs::read_to_string(FIXTURE).expect("pairing fixture")).unwrap()
}

fn pair_refusal(err: CoreError) -> PairRefusal {
    match err {
        CoreError::Pair { refusal } => refusal,
        other => panic!("expected a pairing refusal, got {other}"),
    }
}

impl Device {
    fn secrets(&self) -> DeviceSigningSecrets {
        DeviceSigningSecrets {
            mldsa_seed: URL_SAFE_NO_PAD.decode(&self.mldsa_seed).unwrap(),
            ed25519_sk: URL_SAFE_NO_PAD.decode(&self.ed25519_sk).unwrap(),
        }
    }
}

impl Fixture {
    fn context(&self) -> RosterContext {
        RosterContext {
            collection_id: self.collection_id,
            device_id: self.approver.device.device_id,
            roster_seq: self.verified.pin.roster_seq,
            roster_transcript: self.verified.pin.transcript.clone(),
        }
    }

    fn session(&self, key_epoch: u64) -> CoreSession {
        let mut key = [0u8; 32];
        key.copy_from_slice(&URL_SAFE_NO_PAD.decode(&self.collection_key).unwrap());
        CoreSession {
            collection_key: Some(key),
            key_epoch,
            verified_roster: None,
            legacy_wrap: false,
        }
    }

    fn approve(&self) -> sealbook_core::PairApproval {
        pair_approve(
            &self.approver.secrets(),
            &self.context(),
            &self.session(self.key_epoch),
            &self.verified,
            &self.responded.response,
            &self.preview,
            APPROVER_MANIFEST_SEQ,
        )
        .expect("the approval signs")
    }
}

// ── The handshake ──

/// The property the whole handshake rests on: given only what the server relays,
/// the two devices end up with the same keys, and the approving device opens the
/// joining device's reply to the description it sealed.
#[test]
fn each_step_gives_what_the_fixture_names() {
    let fixture = fixture();
    assert_eq!(
        pair_join_accept(&fixture.join_response).unwrap(),
        fixture.joined
    );
    let responded = pair_respond_with_rng(
        &mut StdRng::seed_from_u64(2),
        &fixture.session(fixture.key_epoch),
        &fixture.verified,
        &fixture.username,
        &fixture.typed,
        &fixture.pending_response,
    )
    .expect("the approver answers");
    assert_eq!(responded, fixture.responded);
    let confirm = pair_confirm_with_rng(
        &mut StdRng::seed_from_u64(3),
        &fixture.started.state,
        &fixture.joining.device,
        fixture.pair_id,
        &fixture.responded_response,
        &fixture.description,
    )
    .expect("the joining device replies");
    assert_eq!(confirm, fixture.confirm_body);
    let preview = pair_preview(
        &fixture.session(fixture.key_epoch),
        &fixture.verified,
        &fixture.responded.response,
        &fixture.confirmed_response,
    )
    .expect("the reply opens");
    assert_eq!(preview, fixture.preview);
    assert_eq!(preview.description, DESCRIPTION);
    assert_eq!(preview.device, fixture.joining.device);
}

/// The joining device's root of trust for the account's devices is the roster
/// the approver signed, reached under the run's keys rather than taken from the
/// server.
#[test]
fn the_joining_device_pins_the_roster_the_approval_signed() {
    let fixture = fixture();
    let pin = pair_finish(
        &fixture.started.state,
        &fixture.joining.device,
        fixture.pair_id,
        &fixture.ready_response,
    )
    .expect("the sealed pin opens");
    assert_eq!(pin, fixture.finished);
    let roster: RosterBody = serde_json::from_str(&fixture.approved_roster_json).unwrap();
    let expected = roster.pin(fixture.collection_id);
    assert_eq!(pin.roster_seq, expected.roster_seq);
    assert_eq!(pin.transcript, b64(&expected.transcript));
}

/// A fresh approval seals a pin the joining device opens, for the roster that
/// same approval signs.
#[test]
fn an_approval_seals_the_pin_of_its_own_roster_step() {
    let fixture = fixture();
    let approval = fixture.approve();
    let body: PairApproveRequest = serde_json::from_str(&approval.body).unwrap();
    let mut ready: PairStatusResponse = serde_json::from_str(&fixture.ready_response).unwrap();
    ready.sealed_pin = body.sealed_pin;
    let pin = pair_finish(
        &fixture.started.state,
        &fixture.joining.device,
        fixture.pair_id,
        &serde_json::to_string(&ready).unwrap(),
    )
    .unwrap();
    let expected = body.roster.pin(fixture.collection_id);
    assert_eq!(pin.roster_seq, expected.roster_seq);
    assert_eq!(pin.transcript, b64(&expected.transcript));
    assert_eq!(pin.manifest_seq, APPROVER_MANIFEST_SEQ);
}

/// An approver that has seen no manifest has nothing to vouch for, and a pin
/// carrying sequence 0 would leave the joining device exactly where it started.
#[test]
fn an_approver_with_no_manifest_cannot_approve() {
    let fixture = fixture();
    let refused = pair_approve(
        &fixture.approver.secrets(),
        &fixture.context(),
        &fixture.session(fixture.key_epoch),
        &fixture.verified,
        &fixture.responded.response,
        &fixture.preview,
        0,
    )
    .expect_err("sequence 0 is refused");
    assert!(matches!(refused, CoreError::Manifest { .. }), "{refused:?}");
}

// ── The refusals ──

#[test]
fn the_respond_refusals_are_what_the_fixture_names() {
    let fixture = fixture();
    for case in &fixture.respond_refusals {
        let refused = pair_respond(
            &fixture.session(case.held_epoch),
            &fixture.verified,
            &fixture.username,
            &case.typed,
            &case.response,
        )
        .expect_err(&format!("{} is refused", case.what));
        assert_eq!(pair_refusal(refused), case.refusal, "{}", case.what);
    }
}

/// A wrong secret word and keys the server swapped in look the same from here:
/// the reply does not open. That is the whole defence, so both are pinned.
#[test]
fn the_preview_refusals_are_what_the_fixture_names() {
    let fixture = fixture();
    assert!(!fixture.preview_refusals.is_empty());
    for case in &fixture.preview_refusals {
        let refused = pair_preview(
            &fixture.session(fixture.key_epoch),
            &fixture.verified,
            &case.response,
            &case.body,
        )
        .expect_err(&format!("{} is refused", case.what));
        assert_eq!(pair_refusal(refused), case.refusal, "{}", case.what);
    }
}

#[test]
fn the_finish_refusals_are_what_the_fixture_names() {
    let fixture = fixture();
    for case in &fixture.finish_refusals {
        let refused = pair_finish(
            &fixture.started.state,
            &fixture.joining.device,
            fixture.pair_id,
            &case.body,
        )
        .expect_err(&format!("{} is refused", case.what));
        assert_eq!(pair_refusal(refused), case.refusal, "{}", case.what);
    }
}

/// The approval opens the reply again rather than trusting the preview it is
/// handed, so a host cannot approve keys the run did not bind.
#[test]
fn an_approval_refuses_a_preview_the_run_did_not_open() {
    let fixture = fixture();
    let mut forged = fixture.preview.clone();
    forged.hello = b64(&[0u8; 64]);
    let refused = pair_approve(
        &fixture.approver.secrets(),
        &fixture.context(),
        &fixture.session(fixture.key_epoch),
        &fixture.verified,
        &fixture.responded.response,
        &forged,
        APPROVER_MANIFEST_SEQ,
    )
    .expect_err("a preview that does not open is refused");
    assert_eq!(pair_refusal(refused), PairRefusal::CodeMismatch);
}

// ── What each side sends ──

/// Core signs the enrollment the server checks, and the nameplate the server
/// sees is the code's first three words and nothing more.
#[test]
fn the_join_request_carries_the_enrollment_and_only_the_nameplate() {
    let fixture = fixture();
    let request: PairJoinRequest = serde_json::from_str(&fixture.started.body).unwrap();
    assert_eq!(request.username, USERNAME);
    let words: Vec<&str> = fixture.started.code.split(' ').collect();
    assert_eq!(words.len(), 8);
    assert_eq!(request.nameplate, words[..3].join("-"));
    for secret in &words[3..] {
        assert!(
            !fixture.started.body.contains(secret),
            "{secret} reached the server"
        );
    }
    assert_eq!(
        fixture.started.qr_text,
        format!("SEALBOOK-PAIR:{}", fixture.started.code.to_uppercase())
    );
    let keys = DevicePublicKeys::try_from(&fixture.joining.device).unwrap();
    sealbook_crypto::verify(
        &sealbook_crypto::DeviceSigningPublic {
            mldsa_pk: keys.mldsa_pk.clone(),
            ed25519_pk: keys.ed25519_pk.clone(),
        },
        &sealbook_crypto::enrollment_transcript(
            keys.device_id,
            &keys.mldsa_pk,
            &keys.ed25519_pk,
            &keys.xwing_hpke_pk,
        ),
        &sealbook_crypto::DualSignature {
            mldsa: request.enrollment_signature.mldsa,
            ed25519: request.enrollment_signature.ed25519,
        },
    )
    .expect("the server accepts the enrollment signature");
}

/// The roster step is what lets the joining device, and every other device,
/// accept the new one without trusting the server's device list. It extends the
/// roster this device verified by one sequence at the same epoch, and it has to
/// verify from the approver's own pin.
#[test]
fn an_approval_signs_the_roster_step_that_adds_the_device() {
    let fixture = fixture();
    let approval = fixture.approve();
    let next = read_roster(&approval.roster_json).unwrap();
    assert_eq!(next.roster_seq, fixture.verified.roster.roster_seq + 1);
    assert_eq!(next.key_epoch, fixture.verified.roster.key_epoch);
    assert_eq!(
        next.devices.iter().map(|d| d.device_id).collect::<Vec<_>>(),
        fixture
            .verified
            .roster
            .devices
            .iter()
            .map(|d| d.device_id)
            .chain([fixture.joining.device.device_id])
            .collect::<Vec<_>>()
    );
    let verified = roster_accept_sealed(
        &fixture.context(),
        &fixture.session(fixture.key_epoch),
        &approval.roster_json,
    )
    .expect("the step verifies from the approver's pin");
    assert_eq!(verified.pin.roster_seq, next.roster_seq);
}

/// The grant covers the CPace run, from fields the server holds, so the server
/// can check it and cannot lift it onto another pairing.
#[test]
fn an_approval_grants_over_the_run_the_server_relayed() {
    let fixture = fixture();
    let approval = fixture.approve();
    let body: PairApproveRequest = serde_json::from_str(&approval.body).unwrap();
    assert_eq!(body.wrap.recipient_id, JOINING);
    let join: PairJoinRequest = serde_json::from_str(&fixture.started.body).unwrap();
    let respond: PairRespondRequest = serde_json::from_str(&fixture.responded.body).unwrap();
    let keys = DevicePublicKeys::try_from(&fixture.joining.device).unwrap();
    let approver = DevicePublicKeys::try_from(&fixture.approver.device).unwrap();
    sealbook_crypto::verify(
        &sealbook_crypto::DeviceSigningPublic {
            mldsa_pk: approver.mldsa_pk,
            ed25519_pk: approver.ed25519_pk,
        },
        &pair_grant_transcript(
            fixture.pair_id,
            fixture.approver.device.device_id,
            keys.device_id,
            &keys.mldsa_pk,
            &keys.ed25519_pk,
            &keys.xwing_hpke_pk,
            &join.sid,
            &join.share,
            &respond.share,
        ),
        &sealbook_crypto::DualSignature {
            mldsa: body.grant.mldsa,
            ed25519: body.grant.ed25519,
        },
    )
    .expect("the server accepts the grant");
}

// ── Codes, paths and polls ──

#[test]
fn the_code_cases_are_what_the_fixture_names() {
    for case in &fixture().codes {
        match pair_lookup_path(&case.typed) {
            Ok(path) => assert_eq!(Some(path), case.path, "{}", case.typed),
            Err(err) => assert_eq!(Some(pair_refusal(err)), case.refusal, "{}", case.typed),
        }
    }
}

#[test]
fn the_paths_are_what_the_fixture_names() {
    for case in &fixture().paths {
        assert_eq!(pair_path(&case.key), case.path);
        assert_eq!(pair_respond_path(&case.key), case.respond);
        assert_eq!(pair_confirm_path(&case.key), case.confirm);
        assert_eq!(pair_approve_path(&case.key), case.approve);
        assert_eq!(pair_cancel_path(&case.key), case.cancel);
    }
}

#[test]
fn the_polls_decide_what_the_fixture_names() {
    let fixture = fixture();
    for case in &fixture.join_polls {
        assert_eq!(
            pair_join_poll(case.status, &case.body),
            case.decision,
            "{}",
            case.what
        );
    }
    for case in &fixture.approve_polls {
        assert_eq!(
            pair_approve_poll(case.status, &case.body),
            case.decision,
            "{}",
            case.what
        );
    }
}

// ── The fixture itself ──

#[test]
#[ignore = "writes the fixture; run deliberately"]
fn regenerate_the_pairing_fixture() {
    if std::env::var("REGENERATE_PAIRING_FIXTURE").as_deref() != Ok("1") {
        panic!("set REGENERATE_PAIRING_FIXTURE=1 to rewrite the fixture");
    }
    let fixture = build();
    let path = std::path::Path::new(FIXTURE);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();
}

/// Everything but the approval, whose signatures, key wrap and sealing nonce
/// are fresh each time, has to come out of the generator as it is checked in.
#[test]
fn the_checked_in_fixture_is_what_the_generator_builds() {
    let built = build();
    let have = fixture();
    assert_eq!(built.started, have.started);
    assert_eq!(built.join_response, have.join_response);
    assert_eq!(built.joined, have.joined);
    assert_eq!(built.typed, have.typed);
    assert_eq!(built.pending_response, have.pending_response);
    assert_eq!(built.responded, have.responded);
    assert_eq!(built.responded_response, have.responded_response);
    assert_eq!(built.confirm_body, have.confirm_body);
    assert_eq!(built.confirmed_response, have.confirmed_response);
    assert_eq!(built.preview, have.preview);
    assert_eq!(built.verified.pin, have.verified.pin);
    assert_eq!(built.verified.roster_json, have.verified.roster_json);
    assert_eq!(built.respond_refusals, have.respond_refusals);
    assert_eq!(built.codes, have.codes);
    assert_eq!(built.paths, have.paths);
    assert_eq!(built.join_polls, have.join_polls);
    assert_eq!(built.approve_polls, have.approve_polls);
}

fn device(id: &str, seed: u8) -> Device {
    let mldsa_seed = [seed; 32];
    let ed25519_sk = [seed + 10; 32];
    let (_, public) = signing_from_seeds(&mldsa_seed, &ed25519_sk);
    Device {
        device: CoreDevice {
            device_id: id.parse().unwrap(),
            mldsa_pk: b64(&public.mldsa_pk),
            ed25519_pk: b64(&public.ed25519_pk),
            // An approval wraps the collection key for the joining device, so
            // its X-Wing key has to be a real encoding rather than bytes of the
            // right length.
            xwing_hpke_pk: b64(
                sealbook_crypto::device_hpke_public_from_ikm(&[seed + 20; 32])
                    .0
                    .as_slice(),
            ),
        },
        mldsa_seed: b64(&mldsa_seed),
        ed25519_sk: b64(&ed25519_sk),
    }
}

/// The pairing as the server would serve it at each step.
struct Served {
    pair_id: Uuid,
    join: PairJoinRequest,
}

impl Served {
    /// The approving device's view: the joining device's half.
    fn to_approver(
        &self,
        status: &str,
        device: Option<DevicePublicKeys>,
        hello: Vec<u8>,
    ) -> String {
        serde_json::to_string(&PairStatusResponse {
            pair_id: self.pair_id,
            status: status.into(),
            username: device.as_ref().map(|_| USERNAME.to_string()),
            device,
            sid: self.join.sid.clone(),
            joiner_share: self.join.share.clone(),
            approver_share: Vec::new(),
            hello,
            sealed_pin: Vec::new(),
        })
        .unwrap()
    }

    /// The joining device's view: the approving device's half.
    fn to_joiner(&self, status: &str, approver_share: Vec<u8>, sealed_pin: Vec<u8>) -> String {
        serde_json::to_string(&PairStatusResponse {
            pair_id: self.pair_id,
            status: status.into(),
            username: None,
            device: None,
            sid: Vec::new(),
            joiner_share: Vec::new(),
            approver_share,
            hello: Vec::new(),
            sealed_pin,
        })
        .unwrap()
    }
}

/// The account mid-pairing, and what core makes of each side of it.
fn build() -> Fixture {
    let collection_id: Uuid = COLLECTION.parse().unwrap();
    let pair_id: Uuid = PAIR_ID.parse().unwrap();
    let key = CollectionKey::from_bytes([3u8; 32]);
    let key_epoch = 4;

    let approver = device(ALPHA, 1);
    let second = device(BETA, 2);
    let joining = device(JOINING, 4);
    let intruder = device(INTRUDER, 5);

    // The roster the approval extends: two devices at sequence 3, sealed by the
    // approver so that the step it signs below is reachable from this one.
    let enrolled: Vec<DevicePublicKeys> = [&approver.device, &second.device]
        .iter()
        .map(|device| DevicePublicKeys::try_from(*device).unwrap())
        .collect();
    let phrase = signing_from_seeds(&[9u8; 32], &[19u8; 32]).1;
    let roster = RosterBody::seal(
        collection_id,
        3,
        key_epoch,
        enrolled,
        phrase.mldsa_pk.clone(),
        phrase.ed25519_pk.clone(),
        RosterSignerBody::Device {
            device_id: approver.device.device_id,
        },
        &approver.secrets(),
        &key,
    )
    .unwrap();
    let anchor: RosterPin = roster.pin(collection_id);
    let roster_json = serde_json::to_string(&roster).unwrap();
    let verified = VerifiedRoster {
        roster: read_roster(&roster_json).unwrap(),
        pin: CoreRosterPin {
            roster_seq: roster.roster_seq,
            transcript: b64(&anchor.transcript),
            manifest_seq: 0,
        },
        roster_json: roster_json.clone(),
        key_committed: true,
        migrated: true,
    };
    let session = |held: u64| CoreSession {
        collection_key: Some(*key.as_bytes()),
        key_epoch: held,
        verified_roster: None,
        legacy_wrap: false,
    };
    let context = RosterContext {
        collection_id,
        device_id: approver.device.device_id,
        roster_seq: verified.pin.roster_seq,
        roster_transcript: verified.pin.transcript.clone(),
    };

    // Step 1: the joining device makes its code.
    let started = pair_start_with_rng(
        &mut StdRng::seed_from_u64(1),
        USERNAME,
        &joining.device,
        &joining.secrets(),
    )
    .unwrap();
    let join: PairJoinRequest = serde_json::from_str(&started.body).unwrap();
    let join_response = serde_json::to_string(&PairJoinResponse { pair_id }).unwrap();
    let joined = pair_join_accept(&join_response).unwrap();
    let served = Served {
        pair_id,
        join: join.clone(),
    };
    let joining_keys = DevicePublicKeys::try_from(&joining.device).unwrap();

    // Step 2: the user types the code on the approver, which answers. The words
    // are typed in capitals with a stray double space, as a user might.
    let typed = started.code.to_uppercase().replacen(' ', "  ", 1);
    let pending_response = served.to_approver("pending", Some(joining_keys.clone()), Vec::new());
    let respond = |seed: u64, typed: &str, body: &str| {
        pair_respond_with_rng(
            &mut StdRng::seed_from_u64(seed),
            &session(key_epoch),
            &verified,
            USERNAME,
            typed,
            body,
        )
        .unwrap()
    };
    let responded = respond(2, &typed, &pending_response);
    let approver_share = serde_json::from_str::<PairRespondRequest>(&responded.body)
        .unwrap()
        .share;

    // Step 3: the joining device replies under the run's keys.
    let reply = |seed: u64, approver_share: Vec<u8>| {
        let body = served.to_joiner("responded", approver_share, Vec::new());
        let confirm = pair_confirm_with_rng(
            &mut StdRng::seed_from_u64(seed),
            &started.state,
            &joining.device,
            pair_id,
            &body,
            DESCRIPTION,
        )
        .unwrap();
        (body, confirm)
    };
    let (responded_response, confirm_body) = reply(3, approver_share.clone());
    let hello = |confirm: &str| {
        serde_json::from_str::<PairConfirmRequest>(confirm)
            .unwrap()
            .hello
    };

    // Step 4: the approver opens the reply.
    let confirmed_response = served.to_approver(
        "confirmed",
        Some(joining_keys.clone()),
        hello(&confirm_body),
    );
    let preview = pair_preview(
        &session(key_epoch),
        &verified,
        &responded.response,
        &confirmed_response,
    )
    .unwrap();

    // Steps 5 and 6: the approval, and the joining device opening its pin.
    let approval = pair_approve(
        &approver.secrets(),
        &context,
        &session(key_epoch),
        &verified,
        &responded.response,
        &preview,
        APPROVER_MANIFEST_SEQ,
    )
    .unwrap();
    let approved: PairApproveRequest = serde_json::from_str(&approval.body).unwrap();
    let ready_response =
        served.to_joiner("ready", approver_share.clone(), approved.sealed_pin.clone());
    let finished = pair_finish(&started.state, &joining.device, pair_id, &ready_response).unwrap();

    // The refusals.
    let words: Vec<&str> = started.code.split(' ').collect();
    let mut wrong_words = words.clone();
    wrong_words[7] = if words[7] == "zoo" { "zone" } else { "zoo" };
    let wrong_code = wrong_words.join(" ");

    let respond_refusals = vec![
        RespondRefusal {
            what: "the pairing has expired, so there are no keys to answer for".into(),
            typed: typed.clone(),
            response: served.to_approver("pending", None, Vec::new()),
            held_epoch: key_epoch,
            refusal: PairRefusal::Expired,
        },
        RespondRefusal {
            what: "another device has already answered this pairing".into(),
            typed: typed.clone(),
            response: served.to_approver("responded", Some(joining_keys.clone()), Vec::new()),
            held_epoch: key_epoch,
            refusal: PairRefusal::Expired,
        },
        RespondRefusal {
            what: "the key was rotated after this session fetched it".into(),
            typed: typed.clone(),
            response: pending_response.clone(),
            held_epoch: key_epoch - 1,
            refusal: PairRefusal::KeyRotated {
                held: key_epoch - 1,
                roster: key_epoch,
            },
        },
        RespondRefusal {
            what: "the device is already enrolled".into(),
            typed: typed.clone(),
            response: served.to_approver(
                "pending",
                Some(DevicePublicKeys::try_from(&second.device).unwrap()),
                Vec::new(),
            ),
            held_epoch: key_epoch,
            refusal: PairRefusal::AlreadyEnrolled {
                device: second.device.device_id,
            },
        },
        RespondRefusal {
            what: "the code is short a word".into(),
            typed: words[..7].join(" "),
            response: pending_response.clone(),
            held_epoch: key_epoch,
            refusal: PairRefusal::Code {
                reason: "a pairing code has 8 words, and this has 7".into(),
            },
        },
    ];

    // A wrong secret word: the approver answers, the joining device replies to
    // that answer, and the reply does not open.
    let wrong = respond(4, &wrong_code, &pending_response);
    let wrong_share = serde_json::from_str::<PairRespondRequest>(&wrong.body)
        .unwrap()
        .share;
    let (_, wrong_confirm) = reply(5, wrong_share);
    // Swapped keys: the server shows the approver its own device in place of
    // the joining one, and relays everything else as it is.
    let intruder_keys = DevicePublicKeys::try_from(&intruder.device).unwrap();
    let swapped = respond(
        6,
        &typed,
        &served.to_approver("pending", Some(intruder_keys.clone()), Vec::new()),
    );
    let swapped_share = serde_json::from_str::<PairRespondRequest>(&swapped.body)
        .unwrap()
        .share;
    let (_, swapped_confirm) = reply(7, swapped_share);
    let preview_refusals = vec![
        PreviewRefusal {
            what: "the code typed differs from the joining device's in its last word".into(),
            response: wrong.response,
            body: served.to_approver(
                "confirmed",
                Some(joining_keys.clone()),
                hello(&wrong_confirm),
            ),
            refusal: PairRefusal::CodeMismatch,
        },
        PreviewRefusal {
            what: "the server showed this device other keys than the joining device holds".into(),
            response: swapped.response,
            body: served.to_approver("confirmed", Some(intruder_keys), hello(&swapped_confirm)),
            refusal: PairRefusal::CodeMismatch,
        },
    ];

    let mut tampered_pin = approved.sealed_pin.clone();
    let last = tampered_pin.len() - 1;
    tampered_pin[last] ^= 1;
    let other_share = serde_json::from_str::<PairRespondRequest>(&wrong.body)
        .unwrap()
        .share;
    // Sealed under the run's own keys, so the only thing wrong with them is
    // their shape.
    let run_keys = sealbook_crypto::PairKeys::from_bytes(
        &URL_SAFE_NO_PAD.decode(&responded.response.keys).unwrap(),
    )
    .unwrap();
    let pin_of = |manifest_seq: Option<u64>| {
        let mut bytes = finished.roster_seq.to_be_bytes().to_vec();
        if let Some(manifest_seq) = manifest_seq {
            bytes.extend_from_slice(&manifest_seq.to_be_bytes());
        }
        bytes.extend_from_slice(&URL_SAFE_NO_PAD.decode(&finished.transcript).unwrap());
        run_keys
            .seal_for_joiner(&mut StdRng::seed_from_u64(9), pair_id, &bytes)
            .unwrap()
    };
    let finish_refusals = vec![
        FinishRefusal {
            what: "the pin is the old 40-byte form with no manifest sequence".into(),
            body: served.to_joiner("ready", approver_share.clone(), pin_of(None)),
            refusal: PairRefusal::Unverified,
        },
        FinishRefusal {
            what: "the approving device vouched for manifest sequence 0".into(),
            body: served.to_joiner("ready", approver_share.clone(), pin_of(Some(0))),
            refusal: PairRefusal::Unverified,
        },
        FinishRefusal {
            what: "the sealed pin was altered on the way".into(),
            body: served.to_joiner("ready", approver_share.clone(), tampered_pin),
            refusal: PairRefusal::Unverified,
        },
        FinishRefusal {
            what: "the share served now is not the one this device replied to".into(),
            body: served.to_joiner("ready", other_share, approved.sealed_pin.clone()),
            refusal: PairRefusal::Unverified,
        },
        FinishRefusal {
            what: "the pairing is not ready, so there is no pin".into(),
            body: served.to_joiner("responded", approver_share.clone(), Vec::new()),
            refusal: PairRefusal::Unverified,
        },
    ];

    let prefixes: Vec<String> = words
        .iter()
        .map(|word| word.chars().take(4).collect())
        .collect();
    let mut misspelt = words.clone();
    misspelt[3] = "qqqq";
    let codes = [
        started.code.clone(),
        typed.clone(),
        started.qr_text.clone(),
        words.join("-"),
        prefixes.join(" "),
        misspelt.join(" "),
        words[..7].join(" "),
        String::new(),
    ]
    .into_iter()
    .map(|typed| match pair_lookup_path(&typed) {
        Ok(path) => CodeCase {
            typed,
            path: Some(path),
            refusal: None,
        },
        Err(err) => CodeCase {
            typed,
            path: None,
            refusal: Some(pair_refusal(err)),
        },
    })
    .collect();

    let paths = [join.nameplate.clone(), PAIR_ID.to_string()]
        .into_iter()
        .map(|key| PathCase {
            path: pair_path(&key),
            respond: pair_respond_path(&key),
            confirm: pair_confirm_path(&key),
            approve: pair_approve_path(&key),
            cancel: pair_cancel_path(&key),
            key,
        })
        .collect();

    let expired = r#"{"error":"expired"}"#.to_string();
    let join_polls = vec![
        JoinPollCase {
            what: "waiting for an approving device".into(),
            status: Some(200),
            body: served.to_joiner("pending", Vec::new(), Vec::new()),
            decision: WAIT_JOIN,
        },
        JoinPollCase {
            what: "an approving device has answered".into(),
            status: Some(200),
            body: responded_response.clone(),
            decision: PairJoinPoll::Confirm,
        },
        JoinPollCase {
            what: "replied, and waiting for the user to approve".into(),
            status: Some(200),
            body: served.to_joiner("confirmed", approver_share.clone(), Vec::new()),
            decision: WAIT_JOIN,
        },
        JoinPollCase {
            what: "approved".into(),
            status: Some(200),
            body: served.to_joiner("ready", approver_share.clone(), Vec::new()),
            decision: PairJoinPoll::Ready,
        },
        JoinPollCase {
            what: "the code has timed out, which the server answers with a 404".into(),
            status: Some(404),
            body: expired.clone(),
            decision: PairJoinPoll::Expired,
        },
        JoinPollCase {
            what: "the request never got an answer".into(),
            status: None,
            body: String::new(),
            decision: WAIT_JOIN,
        },
    ];
    let approve_polls = vec![
        ApprovePollCase {
            what: "waiting for the joining device to reply".into(),
            status: Some(200),
            body: served.to_approver("responded", Some(joining_keys.clone()), Vec::new()),
            decision: WAIT_APPROVE,
        },
        ApprovePollCase {
            what: "the joining device has replied".into(),
            status: Some(200),
            body: confirmed_response.clone(),
            decision: PairApprovePoll::Preview,
        },
        ApprovePollCase {
            what: "the code has timed out".into(),
            status: Some(404),
            body: expired,
            decision: PairApprovePoll::Expired,
        },
    ];

    Fixture {
        collection_id,
        collection_key: b64(key.as_bytes()),
        key_epoch,
        username: USERNAME.into(),
        description: DESCRIPTION.into(),
        approver,
        verified,
        joining,
        pair_id,
        started,
        join_response,
        joined,
        typed,
        pending_response,
        responded,
        responded_response,
        confirm_body,
        confirmed_response,
        preview,
        ready_response,
        approved_roster_json: approval.roster_json,
        finished,
        respond_refusals,
        preview_refusals,
        finish_refusals,
        codes,
        paths,
        join_polls,
        approve_polls,
    }
}
