//! The shared rotation fixture, and core's plan for it.
//!
//! One collection as a verified read leaves it, holding every row a rotation
//! has to tell apart: live rows, a sealed tombstone that is re-sealed like any
//! other row, a tombstone above the floor that the manifest still commits to,
//! and one below it whose row the rotation retires. Alongside it the row a
//! rotation refuses on, and the roster cases that decide who keeps a wrap of
//! the new key.
//!
//! Held to the same document as `sealbook-web/src/lib/rotationParity.test.ts`
//! and Android's `VaultRotationTest`, so a rotation that differs here differs
//! from the other clients rather than from a copy of their output.
//!
//! Run `REGENERATE_ROTATION_FIXTURE=1 cargo test -p sealbook-core -- --ignored
//! regenerate` to rewrite the fixture after a deliberate change.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sealbook_core::{
    manifest_entry_for, open_row, reseal_row, rotation_entries, rotation_plan, rotation_recipients,
    CoreDevice, CoreError, CoreManifestEntry, CoreSealedRow, ManifestPlan, RotationPlan,
    RotationRefusal, RotationState, RowOutcome, UnreadableReason,
};
use sealbook_crypto::{encrypt_object, object_aad, signing_from_seeds, CollectionKey};
use sealbook_protocol::envelope::{seal_envelope, seal_tombstone_envelope};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../sealbook-protocol/fixtures/rotation/plan.json"
);

const COLLECTION: &str = "11111111-1111-1111-1111-111111111111";
const ALPHA: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const BETA: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const GAMMA: &str = "cccccccc-cccc-cccc-cccc-cccccccccccc";
const DELTA: &str = "dddddddd-dddd-dddd-dddd-dddddddddddd";
const NOTE: &str = "application/sealbook.note+json";
const CONTACT: &str = "application/jscontact+json";

#[derive(Serialize, Deserialize)]
struct Fixture {
    collection_id: Uuid,
    /// The device the rotation runs on.
    device_id: Uuid,
    /// The key the rows below are sealed under, except the one that
    /// deliberately is not.
    collection_key: String,
    /// The key the rotation moves the collection to.
    new_collection_key: String,
    state: RotationState,
    /// The collection as a verified read leaves it: the newest revision of
    /// every row, in walk order.
    rows: Vec<CoreSealedRow>,
    plan: ExpectedPlan,
    /// A live row sealed under an epoch this device has not caught up to. Every
    /// other read counts one of these; a rotation refuses on it.
    unreadable: CoreSealedRow,
    refusal: RotationRefusal,
    devices: Vec<CoreDevice>,
    recipients: Vec<RecipientCase>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ExpectedPlan {
    reseal: Vec<PlannedRow>,
    carried: Vec<CoreManifestEntry>,
    retired: Vec<Uuid>,
    manifest: ManifestPlan,
}

/// A row to re-seal, as the plan names it: the revision is the one after the
/// rotation, not the one the row was served at.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PlannedRow {
    id: Uuid,
    revision: u64,
}

/// One roster a rotation could be asked to run against, and what it answers.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RecipientCase {
    /// Which of the fixture's devices the roster lists for this case.
    roster: Vec<Uuid>,
    revoke: Option<Uuid>,
    /// The devices that keep a wrap of the new key, or `None` with a refusal.
    keep: Option<Vec<Uuid>>,
    refusal: Option<RotationRefusal>,
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn fixture() -> Fixture {
    serde_json::from_str(&std::fs::read_to_string(FIXTURE).expect("rotation fixture")).unwrap()
}

impl Fixture {
    fn plan(&self) -> Result<RotationPlan, CoreError> {
        rotation_plan(
            &self.collection_key,
            self.collection_id,
            &self.state,
            &self.rows,
        )
    }

    fn planned(&self, plan: &RotationPlan) -> ExpectedPlan {
        ExpectedPlan {
            reseal: plan
                .reseal
                .iter()
                .map(|row| PlannedRow {
                    id: row.id,
                    revision: row.revision,
                })
                .collect(),
            carried: plan.carried.clone(),
            retired: plan.retired.clone(),
            manifest: plan.manifest,
        }
    }

    fn device(&self, id: Uuid) -> CoreDevice {
        self.devices
            .iter()
            .find(|device| device.device_id == id)
            .expect("the case names a device the fixture holds")
            .clone()
    }

    fn roster(&self, case: &RecipientCase) -> Vec<CoreDevice> {
        case.roster.iter().map(|id| self.device(*id)).collect()
    }
}

// ── The plan ──

#[test]
fn the_plan_is_what_the_fixture_names() {
    let fixture = fixture();
    let plan = fixture.plan().expect("the fixture's rows all open");
    assert_eq!(fixture.planned(&plan), fixture.plan);
}

/// A sealed tombstone has a row-level flag of false, so it is a row with bytes
/// like any other and the rotation re-seals it. Classifying by the envelope
/// would leave it out of the request and short in the manifest.
#[test]
fn a_sealed_tombstone_is_re_sealed_and_a_row_level_one_is_not() {
    let fixture = fixture();
    let plan = fixture.plan().unwrap();
    let resealed: Vec<Uuid> = plan.reseal.iter().map(|row| row.id).collect();
    let sealed_delete = Uuid::from_bytes([0xa4; 16]);
    assert!(resealed.contains(&sealed_delete));
    for row in &fixture.rows {
        if row.tombstone {
            assert!(!resealed.contains(&row.id), "{} was re-sealed", row.id);
        }
    }
}

/// The revisions a rotation assigns run consecutively from the collection's
/// next one, whatever it is carrying or retiring: the server refuses a rotation
/// whose revisions have a gap in them.
#[test]
fn the_revisions_run_consecutively_from_the_collections_next_one() {
    let fixture = fixture();
    let plan = fixture.plan().unwrap();
    let first = fixture.state.latest_revision + 1;
    for (offset, row) in plan.reseal.iter().enumerate() {
        assert_eq!(row.revision, first + offset as u64);
    }
    assert_eq!(
        plan.manifest.latest_revision,
        first + plan.reseal.len() as u64 - 1
    );
}

/// The manifest commits to the re-sealed rows at their new digests and to the
/// carried tombstones at the digests they were stored with, and to nothing
/// else: the retired rows are left out, which is what authorises the server to
/// drop them.
#[test]
fn the_manifest_commits_to_the_resealed_rows_and_the_carried_tombstones() {
    let fixture = fixture();
    let plan = fixture.plan().unwrap();
    let resealed = reseal_all(&fixture, &plan);
    let entries = rotation_entries(&plan, &resealed).unwrap();
    let mut ids: Vec<Uuid> = entries.iter().map(|entry| entry.id).collect();
    ids.sort();
    let mut expected: Vec<Uuid> = plan
        .reseal
        .iter()
        .map(|row| row.id)
        .chain(plan.carried.iter().map(|entry| entry.id))
        .collect();
    expected.sort();
    assert_eq!(ids, expected);
    for retired in &plan.retired {
        assert!(!ids.contains(retired), "{retired} is still in the manifest");
    }
    for (entry, sealed) in entries.iter().zip(&resealed) {
        assert_eq!(
            entry.content_digest,
            manifest_entry_for(
                sealed.id,
                sealed.revision,
                false,
                &sealed.nonce,
                &sealed.ciphertext
            )
            .unwrap()
            .content_digest,
            "the entry commits to bytes other than the ones re-sealed"
        );
    }
}

#[test]
fn every_resealed_row_opens_under_the_new_key_and_no_longer_under_the_old_one() {
    let fixture = fixture();
    let plan = fixture.plan().unwrap();
    for sealed in reseal_all(&fixture, &plan) {
        let under_new = open_row(&fixture.new_collection_key, fixture.collection_id, &sealed)
            .expect("the new key is usable");
        assert!(
            !matches!(under_new, RowOutcome::Unreadable { .. }),
            "{} does not open under the new key",
            sealed.id
        );
        let under_old = open_row(&fixture.collection_key, fixture.collection_id, &sealed).unwrap();
        assert!(
            matches!(under_old, RowOutcome::Unreadable { .. }),
            "{} still opens under the retired key",
            sealed.id
        );
    }
}

/// The 2026-10-20 bug: a read counts a row it cannot open and carries on, which
/// for a rotation would leave the row sealed under the retired key and drop the
/// object from the collection for good.
#[test]
fn a_row_this_device_cannot_open_refuses_the_whole_rotation() {
    let fixture = fixture();
    let mut rows = fixture.rows.clone();
    rows.push(fixture.unreadable.clone());
    let refused = rotation_plan(
        &fixture.collection_key,
        fixture.collection_id,
        &fixture.state,
        &rows,
    )
    .expect_err("a rotation cannot re-seal a row it cannot read");
    assert_eq!(
        refused,
        CoreError::Rotation {
            refusal: fixture.refusal.clone()
        }
    );
    // The same row through the read path is counted rather than raised.
    assert_eq!(
        open_row(
            &fixture.collection_key,
            fixture.collection_id,
            &fixture.unreadable
        )
        .unwrap(),
        RowOutcome::Unreadable {
            reason: UnreadableReason::Key
        }
    );
}

// ── Who keeps a wrap ──

#[test]
fn the_roster_cases_answer_what_the_fixture_names() {
    let fixture = fixture();
    for case in &fixture.recipients {
        let answer = rotation_recipients(fixture.device_id, case.revoke, &fixture.roster(case));
        match (&case.keep, &case.refusal) {
            (Some(keep), None) => assert_eq!(
                answer
                    .as_ref()
                    .expect("the case keeps devices")
                    .iter()
                    .map(|device| device.device_id)
                    .collect::<Vec<_>>(),
                *keep,
                "case revoking {:?}",
                case.revoke
            ),
            (None, Some(refusal)) => assert_eq!(
                answer.expect_err("the case is a refusal"),
                CoreError::Rotation {
                    refusal: refusal.clone()
                },
                "case revoking {:?}",
                case.revoke
            ),
            _ => panic!("a case keeps devices or refuses, not both"),
        }
    }
}

fn reseal_all(fixture: &Fixture, plan: &RotationPlan) -> Vec<CoreSealedRow> {
    plan.reseal
        .iter()
        .map(|row| {
            reseal_row(
                &fixture.collection_key,
                &fixture.new_collection_key,
                fixture.collection_id,
                row,
            )
            .expect("every planned row re-seals")
        })
        .collect()
}

// ── The fixture itself ──

#[test]
#[ignore = "writes the fixture; run deliberately"]
fn regenerate_the_rotation_fixture() {
    if std::env::var("REGENERATE_ROTATION_FIXTURE").as_deref() != Ok("1") {
        panic!("set REGENERATE_ROTATION_FIXTURE=1 to rewrite the fixture");
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
    // Not the bytes: the AEAD nonce is random, so each run seals the same rows
    // to different ciphertext and a carried tombstone's digest is of the bytes
    // it was stored with. The plan and the verdicts are what must match.
    assert_eq!(built.state, have.state);
    assert_eq!(built.plan.reseal, have.plan.reseal);
    assert_eq!(built.plan.retired, have.plan.retired);
    assert_eq!(built.plan.manifest, have.plan.manifest);
    assert_eq!(
        carried_rows(&built.plan.carried),
        carried_rows(&have.plan.carried)
    );
    assert_eq!(built.refusal, have.refusal);
    assert_eq!(built.recipients, have.recipients);
    assert_eq!(
        built.rows.iter().map(|row| row.id).collect::<Vec<_>>(),
        have.rows.iter().map(|row| row.id).collect::<Vec<_>>()
    );
}

fn carried_rows(entries: &[CoreManifestEntry]) -> Vec<(Uuid, u64, bool)> {
    entries
        .iter()
        .map(|entry| (entry.id, entry.revision, entry.tombstone))
        .collect()
}

/// The fixture collection, and the plan core makes for it.
fn build() -> Fixture {
    let collection_id: Uuid = COLLECTION.parse().unwrap();
    let device_id: Uuid = ALPHA.parse().unwrap();
    let key = CollectionKey::from_bytes([3u8; 32]);
    let new_key = CollectionKey::from_bytes([5u8; 32]);
    // The epoch this device has not caught up to.
    let other = CollectionKey::from_bytes([4u8; 32]);

    let devices = [ALPHA, BETA, GAMMA]
        .iter()
        .enumerate()
        .map(|(index, id)| {
            let seed = index as u8 + 1;
            let (_, public) = signing_from_seeds(&[seed; 32], &[seed + 10; 32]);
            CoreDevice {
                device_id: id.parse().unwrap(),
                mldsa_pk: b64(&public.mldsa_pk),
                ed25519_pk: b64(&public.ed25519_pk),
                // A rotation wraps the new key for this, so unlike the read
                // fixture it has to be a real key: the roster fixture is where
                // the wrap itself is checked.
                xwing_hpke_pk: b64(&[seed + 20; 1216]),
            }
        })
        .collect::<Vec<_>>();

    let id = |tail: u8| Uuid::from_bytes([tail; 16]);
    let note = id(0xa1);
    let contact = id(0xa2);
    let carried = id(0xa3);
    let sealed_delete = id(0xa4);
    let stranger = id(0xa5);
    let retired = id(0xa6);

    let seal = |key: &CollectionKey, object: Uuid, plain: Vec<u8>, revision, tombstone| {
        let aad = object_aad(object.as_bytes(), collection_id.as_bytes());
        let enc = encrypt_object(key, &plain, &aad).unwrap();
        CoreSealedRow {
            id: object,
            revision,
            tombstone,
            nonce: b64(&enc.nonce),
            ciphertext: b64(&enc.ciphertext),
            padded_size: enc.padded_size as u64,
        }
    };

    let state = RotationState {
        manifest_seq: 6,
        key_epoch: 4,
        latest_revision: 7,
        // Exactly the revision of the carried tombstone, which is still
        // reachable by an incremental answer and so is not retired.
        tombstone_floor: 4,
    };
    let rows = vec![
        seal(
            &key,
            note,
            seal_envelope(NOTE, br#"{"@type":"Note","version":"1","title":"rotated"}"#),
            7,
            false,
        ),
        seal(
            &key,
            contact,
            seal_envelope(CONTACT, br#"{"@type":"Card","version":"1.0"}"#),
            3,
            false,
        ),
        // A row-level tombstone keeps whatever body it had: the flag is what
        // the manifest vouches for, and a rotation never re-seals it.
        seal(&key, carried, seal_envelope(NOTE, b"gone"), 4, true),
        seal(&key, sealed_delete, seal_tombstone_envelope(NOTE), 5, false),
        seal(&key, retired, seal_envelope(NOTE, b"older"), 2, true),
    ];
    let unreadable = seal(
        &other,
        stranger,
        seal_envelope(NOTE, br#"{"@type":"Note"}"#),
        6,
        false,
    );

    let alpha: Uuid = ALPHA.parse().unwrap();
    let beta: Uuid = BETA.parse().unwrap();
    let gamma: Uuid = GAMMA.parse().unwrap();
    let recipients = vec![
        RecipientCase {
            roster: vec![alpha, beta, gamma],
            revoke: None,
            keep: Some(vec![alpha, beta, gamma]),
            refusal: None,
        },
        RecipientCase {
            roster: vec![alpha, beta, gamma],
            revoke: Some(beta),
            keep: Some(vec![alpha, gamma]),
            refusal: None,
        },
        RecipientCase {
            roster: vec![alpha, beta, gamma],
            revoke: Some(alpha),
            keep: None,
            refusal: Some(RotationRefusal::RevokingSelf),
        },
        RecipientCase {
            roster: vec![alpha, beta, gamma],
            revoke: Some(DELTA.parse().unwrap()),
            keep: None,
            refusal: Some(RotationRefusal::NotInRoster),
        },
        RecipientCase {
            roster: vec![beta],
            revoke: Some(beta),
            keep: None,
            refusal: Some(RotationRefusal::LastDevice),
        },
        // Signed in on a device the roster does not list: the rotation would
        // wrap the new key for everyone except the device doing it.
        RecipientCase {
            roster: vec![beta, gamma],
            revoke: None,
            keep: None,
            refusal: Some(RotationRefusal::NotEnrolled),
        },
    ];

    let collection_key = b64(key.as_bytes());
    let plan = rotation_plan(&collection_key, collection_id, &state, &rows).unwrap();
    let mut fixture = Fixture {
        collection_id,
        device_id,
        collection_key,
        new_collection_key: b64(new_key.as_bytes()),
        state,
        rows,
        plan: ExpectedPlan {
            reseal: Vec::new(),
            carried: Vec::new(),
            retired: Vec::new(),
            manifest: plan.manifest,
        },
        unreadable,
        refusal: RotationRefusal::Unreadable {
            object: stranger,
            reason: UnreadableReason::Key,
        },
        devices,
        recipients,
    };
    fixture.plan = fixture.planned(&plan);
    fixture
}
