//! The shared pairing fixture, and what core makes of it.
//!
//! One account with two enrolled devices and a third asking to join, as both
//! sides of a pairing see it: the join response the new device checks, the
//! status response the approver previews, the code both sides have to compute
//! from those, and every refusal either side can raise.
//!
//! Held to the same document as `sealbook-web/src/lib/pairingParity.test.ts`
//! and Android's `DevicePairingTest`, so a pairing that differs here differs
//! from the other clients rather than from a copy of their output.
//!
//! Run `REGENERATE_PAIRING_FIXTURE=1 cargo test -p sealbook-core -- --ignored
//! regenerate` to rewrite the fixture after a deliberate change.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sealbook_core::{
    confirmation_groups, format_confirmation, normalize_confirmation, pair_approve,
    pair_approve_path, pair_join_accept, pair_join_body, pair_path, pair_preview, pair_status,
    read_roster, roster_accept_sealed, CoreDevice, CoreError, CorePairPreview, CoreSession,
    PairJoined, PairRefusal, PairStatus, RosterContext, VerifiedRoster,
};
use sealbook_crypto::{
    pair_confirmation, signing_from_seeds, CollectionKey, DeviceSigningSecrets, RosterPin,
};
use sealbook_protocol::{
    DevicePublicKeys, PairApproveRequest, PairJoinRequest, PairJoinResponse, PairStatusResponse,
    RosterBody, RosterSignerBody,
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
const PAIR_ID: &str = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee";
const PAIR_CODE: &str = "KQ4R 7T2M 9XJB";

#[derive(Serialize, Deserialize)]
struct Fixture {
    collection_id: Uuid,
    collection_key: String,
    /// The epoch the roster below is sealed at, and which an approving device
    /// has to be holding.
    key_epoch: u64,
    /// The device doing the approving, with the secrets it signs with.
    approver: Device,
    /// The roster the approval extends, as the approver verified it from its
    /// own pin.
    verified: VerifiedRoster,
    /// The device asking to join, with the secrets it signs its enrollment
    /// with.
    joining: Device,
    pair_id: Uuid,
    pair_code: String,
    /// The code both sides compute, over the joining device's keys and the
    /// roster anchor. Neither side displays the server's copy.
    confirm: String,
    /// The join response, as the server answers the joining device.
    join_response: String,
    joined: PairJoined,
    /// The status response, as the server answers the approving device.
    preview_response: String,
    preview: CorePairPreview,
    /// Join responses the joining device refuses, and why.
    join_refusals: Vec<JoinRefusal>,
    /// Status responses an approval refuses, and why.
    approve_refusals: Vec<ApproveRefusal>,
    /// Codes as the user might type them, and what they normalize to.
    codes: Vec<CodeCase>,
    /// Lookup keys and the path that resolves them.
    paths: Vec<PathCase>,
    /// Poll answers and the state they report.
    polls: Vec<PollCase>,
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
struct JoinRefusal {
    what: String,
    response: String,
    refusal: PairRefusal,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ApproveRefusal {
    what: String,
    response: String,
    /// The epoch the approving device holds, which only the rotation case
    /// differs on.
    held_epoch: u64,
    refusal: PairRefusal,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct CodeCase {
    typed: String,
    normalized: String,
    formatted: String,
    groups: Vec<String>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PathCase {
    /// What the user typed, or the pair id a host held on to.
    key: String,
    path: String,
    approve_path: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PollCase {
    what: String,
    status: u16,
    body: String,
    state: PairStatus,
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn fixture() -> Fixture {
    serde_json::from_str(&std::fs::read_to_string(FIXTURE).expect("pairing fixture")).unwrap()
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
        }
    }

    fn approve(&self, typed: &str) -> Result<sealbook_core::PairApproval, CoreError> {
        pair_approve(
            &self.approver.secrets(),
            &self.context(),
            &self.session(self.key_epoch),
            &self.verified,
            &self.preview,
            typed,
        )
    }
}

// ── The code both sides compute ──

/// The one property the whole handshake rests on: the joining device and the
/// approving device, given what the server tells each of them, arrive at the
/// same code without either taking the server's word for it.
#[test]
fn both_sides_compute_the_same_code_from_what_they_are_served() {
    let fixture = fixture();
    let joined = pair_join_accept(&fixture.joining.device, &fixture.join_response)
        .expect("the join response anchors");
    let preview = pair_preview(
        &fixture.session(fixture.key_epoch),
        &fixture.verified,
        &fixture.preview_response,
    )
    .expect("the preview is approvable");
    assert_eq!(joined.confirm, fixture.confirm);
    assert_eq!(preview.confirm, fixture.confirm);
    assert_eq!(joined, fixture.joined);
    assert_eq!(preview, fixture.preview);
}

/// The anchor the joining device pins is the one the code committed to, so its
/// first roster fetch is checked against a roster the user vouched for rather
/// than against a MAC keyed from a collection key the same server supplies.
#[test]
fn the_joining_device_pins_the_anchor_the_code_commits_to() {
    let fixture = fixture();
    let joined = pair_join_accept(&fixture.joining.device, &fixture.join_response).unwrap();
    assert_eq!(joined.pin, fixture.verified.pin);
    assert_eq!(
        joined.confirm,
        pair_confirmation(
            joined.pair_id,
            fixture.joining.device.device_id,
            &URL_SAFE_NO_PAD
                .decode(&fixture.joining.device.mldsa_pk)
                .unwrap(),
            &URL_SAFE_NO_PAD
                .decode(&fixture.joining.device.ed25519_pk)
                .unwrap(),
            &URL_SAFE_NO_PAD
                .decode(&fixture.joining.device.xwing_hpke_pk)
                .unwrap(),
            joined.pin.roster_seq,
            &URL_SAFE_NO_PAD.decode(&joined.pin.transcript).unwrap(),
        )
    );
}

/// A code that differs from the one computed here is a refusal, not something
/// to display: a server that substituted the joining device's keys could show
/// the real code and keep the ones it swapped in.
#[test]
fn the_servers_copy_of_the_code_is_only_ever_compared_against_ours() {
    let fixture = fixture();
    let mut served: PairStatusResponse = serde_json::from_str(&fixture.preview_response).unwrap();
    served.confirm = "AAAABBBBCCCCDDDDEEEEFFFFGG".into();
    let refused = pair_preview(
        &fixture.session(fixture.key_epoch),
        &fixture.verified,
        &serde_json::to_string(&served).unwrap(),
    )
    .expect_err("a code that is not ours is refused");
    assert_eq!(
        refused,
        CoreError::Pair {
            refusal: PairRefusal::ServerCode
        }
    );
}

// ── The refusals ──

#[test]
fn the_join_refusals_are_what_the_fixture_names() {
    let fixture = fixture();
    for case in &fixture.join_refusals {
        let refused = pair_join_accept(&fixture.joining.device, &case.response)
            .expect_err(&format!("{} is refused", case.what));
        assert_eq!(
            refused,
            CoreError::Pair {
                refusal: case.refusal.clone()
            },
            "{}",
            case.what
        );
    }
}

#[test]
fn the_approve_refusals_are_what_the_fixture_names() {
    let fixture = fixture();
    for case in &fixture.approve_refusals {
        let refused = pair_preview(
            &fixture.session(case.held_epoch),
            &fixture.verified,
            &case.response,
        )
        .expect_err(&format!("{} is refused", case.what));
        assert_eq!(
            refused,
            CoreError::Pair {
                refusal: case.refusal.clone()
            },
            "{}",
            case.what
        );
    }
}

/// The typed code is compared against the one recomputed at approval time, not
/// against the one the preview was built from: the user has been looking at a
/// screen in between.
#[test]
fn a_typed_code_that_does_not_match_refuses_the_approval() {
    let fixture = fixture();
    let refused = fixture
        .approve("AAAA BBBB CCCC DDDD EEEE FFFF GG")
        .expect_err("a code that is not this pairing's is refused");
    assert_eq!(
        refused,
        CoreError::Pair {
            refusal: PairRefusal::TypedCode
        }
    );
}

/// Shown in groups of four, so the form the user can retype has to be accepted.
#[test]
fn the_code_is_accepted_as_it_is_displayed() {
    let fixture = fixture();
    for typed in [
        fixture.confirm.clone(),
        format_confirmation(&fixture.confirm),
        format_confirmation(&fixture.confirm).to_lowercase(),
        confirmation_groups(&fixture.confirm).join("-"),
    ] {
        fixture
            .approve(&typed)
            .unwrap_or_else(|err| panic!("{typed:?} should be accepted: {err}"));
    }
}

// ── What an approval sends ──

/// The roster step is what lets the joining device, and every other device,
/// accept the new one without trusting the server's device list. It extends the
/// roster this device verified by one sequence at the same epoch, and it has to
/// verify from the approver's own pin: a step this device could not check is one
/// it should not have sent.
#[test]
fn an_approval_signs_the_roster_step_that_adds_the_device() {
    let fixture = fixture();
    let approval = fixture
        .approve(&fixture.confirm)
        .expect("the approval signs");
    let next = read_roster(&approval.roster_json).unwrap();
    assert_eq!(next.roster_seq, fixture.verified.roster.roster_seq + 1);
    assert_eq!(next.key_epoch, fixture.verified.roster.key_epoch);
    assert_eq!(
        next.signer,
        sealbook_core::CoreRosterSigner::Device {
            device_id: fixture.approver.device.device_id
        }
    );
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

/// The body carries the canonical code, the wrap addressed to the joining
/// device, and the same roster the approval pins itself on.
#[test]
fn an_approval_sends_the_canonical_code_and_a_wrap_for_the_joining_device() {
    let fixture = fixture();
    let approval = fixture
        .approve(&format_confirmation(&fixture.confirm))
        .expect("the approval signs");
    assert_eq!(approval.confirm, fixture.confirm);
    let body: PairApproveRequest = serde_json::from_str(&approval.body).unwrap();
    assert_eq!(body.confirmation, fixture.confirm);
    assert_eq!(body.wrap.recipient_kind, "device");
    assert_eq!(
        body.wrap.recipient_id,
        fixture.joining.device.device_id.to_string()
    );
    assert!(!body.wrap.wrapped_ck.is_empty() && !body.wrap.hpke_enc.is_empty());
    assert_eq!(
        serde_json::to_string(&body.roster).unwrap(),
        approval.roster_json
    );
}

/// Core signs the enrollment the server checks, so a host never assembles the
/// transcript itself.
#[test]
fn the_join_request_carries_an_enrollment_signature_over_the_new_keys() {
    let fixture = fixture();
    let body = pair_join_body("alice", &fixture.joining.device, &fixture.joining.secrets())
        .expect("the join request signs");
    let request: PairJoinRequest = serde_json::from_str(&body).unwrap();
    assert_eq!(request.username, "alice");
    assert_eq!(request.device.device_id, fixture.joining.device.device_id);
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

// ── Codes, paths and polls ──

#[test]
fn the_code_cases_normalize_and_group_as_the_fixture_names() {
    for case in &fixture().codes {
        assert_eq!(normalize_confirmation(&case.typed), case.normalized);
        assert_eq!(format_confirmation(&case.typed), case.formatted);
        assert_eq!(confirmation_groups(&case.typed), case.groups);
    }
}

/// The server matches a code on its whitespace-normalized form, so a code typed
/// with a stray double space has to resolve to the same path rather than to a
/// 404 the host reports as "expired".
#[test]
fn the_lookup_path_is_what_the_fixture_names() {
    for case in &fixture().paths {
        assert_eq!(pair_path(&case.key), case.path);
        assert_eq!(pair_approve_path(&case.key), case.approve_path);
    }
}

/// Expiry is a 404 and not a status in the body, so a host that reads only the
/// body polls a dead pairing for ever.
#[test]
fn the_poll_cases_report_what_the_fixture_names() {
    for case in &fixture().polls {
        assert_eq!(
            pair_status(case.status, &case.body).expect(&case.what),
            case.state,
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

#[test]
fn the_checked_in_fixture_is_what_the_generator_builds() {
    let built = build();
    let have = fixture();
    assert_eq!(built.confirm, have.confirm);
    assert_eq!(built.joined, have.joined);
    assert_eq!(built.preview, have.preview);
    assert_eq!(built.join_response, have.join_response);
    assert_eq!(built.preview_response, have.preview_response);
    assert_eq!(built.verified.pin, have.verified.pin);
    assert_eq!(built.verified.roster_json, have.verified.roster_json);
    assert_eq!(built.join_refusals, have.join_refusals);
    assert_eq!(built.approve_refusals, have.approve_refusals);
    assert_eq!(built.codes, have.codes);
    assert_eq!(built.paths, have.paths);
    assert_eq!(built.polls, have.polls);
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

/// The account mid-pairing, and what core makes of each side of it.
fn build() -> Fixture {
    let collection_id: Uuid = COLLECTION.parse().unwrap();
    let pair_id: Uuid = PAIR_ID.parse().unwrap();
    let key = CollectionKey::from_bytes([3u8; 32]);
    let key_epoch = 4;

    let approver = device(ALPHA, 1);
    let second = device(BETA, 2);
    let joining = device(JOINING, 4);

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
        pin: sealbook_core::CoreRosterPin {
            roster_seq: roster.roster_seq,
            transcript: b64(&anchor.transcript),
        },
        roster_json: roster_json.clone(),
    };

    let joining_keys = DevicePublicKeys::try_from(&joining.device).unwrap();
    let confirm = pair_confirmation(
        pair_id,
        joining_keys.device_id,
        &joining_keys.mldsa_pk,
        &joining_keys.ed25519_pk,
        &joining_keys.xwing_hpke_pk,
        anchor.roster_seq,
        &anchor.transcript,
    );

    let join_response = |roster_seq: u64, transcript: Vec<u8>, confirm: &str| {
        serde_json::to_string(&PairJoinResponse {
            pair_id,
            pair_code: PAIR_CODE.into(),
            confirm: confirm.to_string(),
            roster_seq,
            roster_transcript: transcript,
        })
        .unwrap()
    };
    let served_join = join_response(anchor.roster_seq, anchor.transcript.to_vec(), &confirm);

    let status_response = |device: Option<DevicePublicKeys>, roster_seq, confirm: &str| {
        serde_json::to_string(&PairStatusResponse {
            pair_id,
            status: "pending".into(),
            confirm: confirm.to_string(),
            username: Some("alice".into()),
            device,
            roster_seq,
        })
        .unwrap()
    };
    let served_preview = status_response(
        Some(joining_keys.clone()),
        Some(anchor.roster_seq),
        &confirm,
    );

    let other_code = "AAAABBBBCCCCDDDDEEEEFFFFGG";
    let join_refusals = vec![
        JoinRefusal {
            what: "the account has no roster to anchor on".into(),
            response: join_response(0, Vec::new(), &confirm),
            refusal: PairRefusal::NoAnchor,
        },
        JoinRefusal {
            // A sequence with a transcript that is not a digest is not an
            // unpinned device: pinning it would trust the next roster served.
            what: "the anchor's transcript is not a digest".into(),
            response: join_response(anchor.roster_seq, vec![0; 7], &confirm),
            refusal: PairRefusal::NoAnchor,
        },
        JoinRefusal {
            what: "the server's code is not the one computed here".into(),
            response: join_response(anchor.roster_seq, anchor.transcript.to_vec(), other_code),
            refusal: PairRefusal::ServerCode,
        },
    ];

    let approve_refusals = vec![
        ApproveRefusal {
            what: "the pairing has expired, so there are no keys to approve".into(),
            response: status_response(None, None, &confirm),
            held_epoch: key_epoch,
            refusal: PairRefusal::Expired,
        },
        ApproveRefusal {
            what: "the key was rotated after this session fetched it".into(),
            response: served_preview.clone(),
            held_epoch: key_epoch - 1,
            refusal: PairRefusal::KeyRotated {
                held: key_epoch - 1,
                roster: key_epoch,
            },
        },
        ApproveRefusal {
            what: "the device is already enrolled".into(),
            response: status_response(
                Some(DevicePublicKeys::try_from(&second.device).unwrap()),
                Some(anchor.roster_seq),
                &confirm,
            ),
            held_epoch: key_epoch,
            refusal: PairRefusal::AlreadyEnrolled {
                device: second.device.device_id,
            },
        },
        ApproveRefusal {
            what: "a rotation or another pairing landed while this one waited".into(),
            response: status_response(Some(joining_keys.clone()), Some(2), &confirm),
            held_epoch: key_epoch,
            refusal: PairRefusal::RosterMoved {
                joined_at: 2,
                now: anchor.roster_seq,
            },
        },
        ApproveRefusal {
            what: "the server's code is not the one computed here".into(),
            response: status_response(
                Some(joining_keys.clone()),
                Some(anchor.roster_seq),
                other_code,
            ),
            held_epoch: key_epoch,
            refusal: PairRefusal::ServerCode,
        },
    ];

    let codes = ["ABCD EFGH", "abcd-efgh", " ABCDEFGH ", &confirm]
        .iter()
        .map(|typed| CodeCase {
            typed: (*typed).to_string(),
            normalized: normalize_confirmation(typed),
            formatted: format_confirmation(typed),
            groups: confirmation_groups(typed),
        })
        .collect();

    let paths = [PAIR_CODE, "kq4r 7t2m 9xjb", "KQ4R  7T2M  9XJB", PAIR_ID]
        .iter()
        .map(|key| PathCase {
            key: (*key).to_string(),
            path: pair_path(key),
            approve_path: pair_approve_path(key),
        })
        .collect();

    let polls = vec![
        PollCase {
            what: "waiting for the other device".into(),
            status: 200,
            body: served_preview.clone(),
            state: PairStatus::Pending,
        },
        PollCase {
            what: "approved".into(),
            status: 200,
            body: status_response(None, None, &confirm).replace("pending", "ready"),
            state: PairStatus::Ready,
        },
        PollCase {
            what: "the code has timed out, which the server answers with a 404".into(),
            status: 404,
            body: r#"{"error":"expired"}"#.into(),
            state: PairStatus::Expired,
        },
    ];

    let session = CoreSession {
        collection_key: Some(*key.as_bytes()),
        key_epoch,
        verified_roster: None,
    };
    let joined = pair_join_accept(&joining.device, &served_join).unwrap();
    let preview = pair_preview(&session, &verified, &served_preview).unwrap();

    Fixture {
        collection_id,
        collection_key: b64(key.as_bytes()),
        key_epoch,
        approver,
        verified,
        joining,
        pair_id,
        pair_code: PAIR_CODE.into(),
        confirm,
        join_response: served_join,
        joined,
        preview_response: served_preview,
        preview,
        join_refusals,
        approve_refusals,
        codes,
        paths,
        polls,
    }
}
