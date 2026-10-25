//! The shared change-feed fixture, and core's read of it.
//!
//! One collection served as two pages, signed by the same alpha device as the
//! roster and manifest fixtures and under the same collection, so all three
//! describe one account. Holds every row kind a read has to tell apart: a
//! superseded revision, a row-level tombstone, a sealed tombstone, and a row
//! sealed under a key this device does not hold.
//!
//! Run `REGENERATE_SYNC_FIXTURE=1 cargo test -p sealbook-core -- --ignored
//! regenerate` to rewrite the fixture after a deliberate wire change.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sealbook_core::{
    changes_request, latest_revisions, manifest_sign, manifest_verify, open_row, walk_page,
    walk_start, ChangesPage, CoreDevice, CoreManifestEntry, CoreSealedRow, ManifestContext,
    ManifestPlan, Method, RowOutcome, RowRef, UnreadableReason, WalkOutcome, WalkStep,
};
use sealbook_crypto::{encrypt_object, object_aad, signing_from_seeds, CollectionKey};
use sealbook_protocol::envelope::{seal_envelope, seal_tombstone_envelope};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../sealbook-protocol/fixtures/changes/paged-walk.json"
);

const COLLECTION: &str = "11111111-1111-1111-1111-111111111111";
const ALPHA: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const NOTE: &str = "application/sealbook.note+json";
const CONTACT: &str = "application/jscontact+json";

#[derive(Serialize, Deserialize)]
struct Fixture {
    collection_id: Uuid,
    device_id: Uuid,
    key_epoch: u64,
    /// The collection key the rows below are sealed under, except the one that
    /// deliberately is not.
    collection_key: String,
    devices: Vec<CoreDevice>,
    /// The walk, in the order the server serves it.
    pages: Vec<Value>,
    /// What the read must yield, in walk order.
    objects: Vec<ReadObject>,
    /// Rows that are deletes, by id.
    deleted: Vec<Uuid>,
    unreadable: Vec<UnreadableRow>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ReadObject {
    id: Uuid,
    content_type: String,
    payload: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct UnreadableRow {
    id: Uuid,
    reason: UnreadableReason,
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn fixture() -> Fixture {
    serde_json::from_str(&std::fs::read_to_string(FIXTURE).expect("changes fixture")).unwrap()
}

impl Fixture {
    fn context(&self) -> ManifestContext {
        ManifestContext {
            collection_id: self.collection_id,
            device_id: self.device_id,
            manifest_seq: 0,
        }
    }

    /// What a walk decision reads out of one page.
    fn facts(&self, page: &Value) -> ChangesPage {
        ChangesPage {
            manifest_json: page
                .get("manifest")
                .filter(|manifest| !manifest.is_null())
                .map(|manifest| serde_json::to_string(manifest).unwrap()),
            key_epoch: page["key_epoch"].as_u64().unwrap(),
            latest_revision: page["latest_revision"].as_u64().unwrap(),
            tombstone_floor: page["tombstone_floor"].as_u64().unwrap_or(0),
            has_more: page["has_more"].as_bool().unwrap(),
            resync: page["resync"].as_bool().unwrap_or(false),
            highest_revision: rows(page)
                .iter()
                .map(|row| row.revision)
                .max()
                .unwrap_or(0),
        }
    }

    /// The whole walk, driven as a host drives it.
    fn walk(&self) -> (Vec<CoreSealedRow>, WalkOutcome) {
        let mut cursor = walk_start(0);
        let mut page_index = 0;
        let mut held: Vec<CoreSealedRow> = Vec::new();
        loop {
            let page = &self.pages[page_index];
            // The path core asks for is part of the walk being one read.
            assert_eq!(
                changes_request(self.collection_id, &cursor).path,
                page["request_path"].as_str().unwrap(),
                "page {page_index} was served for a different request"
            );
            let served = rows(page);
            match walk_page(&cursor, &self.facts(page)).expect("the fixture walk completes") {
                WalkStep::Next { cursor: next } => {
                    held.extend(served);
                    cursor = next;
                    page_index += 1;
                }
                WalkStep::Restart { cursor: next } => {
                    held.clear();
                    cursor = next;
                    page_index += 1;
                }
                WalkStep::Done { walk } => {
                    held.extend(served);
                    return (held, walk);
                }
            }
        }
    }

    /// The walk collapsed to the newest revision of each object.
    fn current(&self) -> Vec<CoreSealedRow> {
        let (walked, _) = self.walk();
        let refs: Vec<RowRef> = walked
            .iter()
            .map(|row| RowRef {
                id: row.id,
                revision: row.revision,
            })
            .collect();
        latest_revisions(&refs)
            .iter()
            .map(|index| walked[*index as usize].clone())
            .collect()
    }
}

fn rows(page: &Value) -> Vec<CoreSealedRow> {
    page["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| CoreSealedRow {
            id: row["id"].as_str().unwrap().parse().unwrap(),
            revision: row["revision"].as_u64().unwrap(),
            tombstone: row["tombstone"].as_bool().unwrap(),
            nonce: row["nonce"].as_str().unwrap().to_owned(),
            ciphertext: row["ciphertext"].as_str().unwrap().to_owned(),
            padded_size: row["padded_size"].as_u64().unwrap(),
        })
        .collect()
}

// ── The walk ──

#[test]
fn a_read_asks_for_the_live_rows_from_the_start() {
    let fixture = fixture();
    let request = changes_request(fixture.collection_id, &walk_start(0));
    assert_eq!(request.method, Method::Get);
    assert_eq!(
        request.path,
        format!("/v1/collections/{COLLECTION}/changes?after=0&limit=500&snapshot=true")
    );
}

#[test]
fn the_walk_pages_to_the_end_and_keeps_what_it_was_served() {
    let fixture = fixture();
    let (walked, walk) = fixture.walk();
    assert_eq!(walked.len(), 6, "every row of both pages is carried out");
    assert_eq!(walk.key_epoch, fixture.key_epoch);
    assert_eq!(walk.latest_revision, 7);
    assert!(walk.full, "a walk from nothing is the whole collection");
    assert!(walk.manifest_json.is_some());
}

/// The collection is served with a superseded revision still in the log, so a
/// read that kept both would commit to an object twice and the digest would
/// disagree with the manifest.
#[test]
fn only_the_newest_revision_of_each_object_survives_the_walk() {
    let fixture = fixture();
    let current = fixture.current();
    assert_eq!(current.len(), 5);
    let mut seen: Vec<(Uuid, u64)> = current
        .iter()
        .map(|row| (row.id, row.revision))
        .collect();
    seen.sort();
    let superseded = seen.iter().any(|(_, revision)| *revision == 2);
    assert!(!superseded, "the superseded revision was kept: {seen:?}");
}

/// The manifest commits to the collection rather than to any page of it, so it
/// is the assembled set that has to satisfy it.
#[test]
fn the_assembled_set_satisfies_the_manifest_the_pages_carried() {
    let fixture = fixture();
    let (_, walk) = fixture.walk();
    let entries: Vec<CoreManifestEntry> = fixture
        .current()
        .iter()
        .map(|row| {
            sealbook_core::manifest_entry_for(
                row.id,
                row.revision,
                row.tombstone,
                &row.nonce,
                &row.ciphertext,
            )
            .unwrap()
        })
        .collect();
    let plan = manifest_verify(
        &fixture.context(),
        &walk.manifest_json.expect("the fixture is manifested"),
        &entries,
        &fixture.devices,
    )
    .expect("the fixture's manifest describes its rows");
    assert_eq!(plan.key_epoch, fixture.key_epoch);
    assert_eq!(plan.latest_revision, 7);
}

// ── The rows ──

#[test]
fn the_read_yields_the_objects_the_fixture_names() {
    let fixture = fixture();
    let read: Vec<ReadObject> = fixture
        .current()
        .iter()
        .filter_map(|row| {
            match open_row(&fixture.collection_key, fixture.collection_id, row).unwrap() {
                RowOutcome::Object {
                    content_type,
                    payload,
                } => Some(ReadObject {
                    id: row.id,
                    content_type,
                    payload,
                }),
                _ => None,
            }
        })
        .collect();
    assert_eq!(read, fixture.objects);
}

/// A row-level tombstone and a sealed one are the same verdict: a delete with
/// nothing to read, and not a row this device has lost access to.
#[test]
fn both_kinds_of_tombstone_are_deletes() {
    let fixture = fixture();
    let deleted: Vec<Uuid> = fixture
        .current()
        .iter()
        .filter(|row| {
            open_row(&fixture.collection_key, fixture.collection_id, row).unwrap()
                == RowOutcome::Deleted
        })
        .map(|row| row.id)
        .collect();
    assert_eq!(deleted, fixture.deleted);
    assert_eq!(deleted.len(), 2, "one row-level and one sealed tombstone");
}

#[test]
fn a_row_this_key_does_not_open_is_reported_with_its_reason() {
    let fixture = fixture();
    let unreadable: Vec<UnreadableRow> = fixture
        .current()
        .iter()
        .filter_map(|row| {
            match open_row(&fixture.collection_key, fixture.collection_id, row).unwrap() {
                RowOutcome::Unreadable { reason } => Some(UnreadableRow { id: row.id, reason }),
                _ => None,
            }
        })
        .collect();
    assert_eq!(unreadable, fixture.unreadable);
}

// ── The fixture itself ──

#[test]
#[ignore = "writes the fixture; run deliberately"]
fn regenerate_the_sync_fixture() {
    if std::env::var("REGENERATE_SYNC_FIXTURE").as_deref() != Ok("1") {
        panic!("set REGENERATE_SYNC_FIXTURE=1 to rewrite the fixture");
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
    // Not the bytes: ML-DSA signing need not be deterministic, and the AEAD
    // nonce is random, so the commitments and the verdicts are what must match.
    assert_eq!(built.objects, have.objects);
    assert_eq!(built.deleted, have.deleted);
    assert_eq!(built.unreadable, have.unreadable);
    assert_eq!(built.pages.len(), have.pages.len());
    for (built, have) in built.pages.iter().zip(&have.pages) {
        assert_eq!(built["request_path"], have["request_path"]);
        assert_eq!(built["manifest"]["object_count"], have["manifest"]["object_count"]);
        assert_eq!(built["has_more"], have["has_more"]);
    }
}

/// The fixture collection, in the order the server's two pages serve it.
fn build() -> Fixture {
    let collection_id: Uuid = COLLECTION.parse().unwrap();
    let device_id: Uuid = ALPHA.parse().unwrap();
    let key_epoch = 4;
    let (secrets, public) = signing_from_seeds(&[1u8; 32], &[2u8; 32]);
    let devices = vec![CoreDevice {
        device_id,
        mldsa_pk: b64(&public.mldsa_pk),
        ed25519_pk: b64(&public.ed25519_pk),
        // A read never checks an HPKE key; the roster fixture is where that
        // field is real.
        xwing_hpke_pk: String::new(),
    }];
    let key = CollectionKey::from_bytes([3u8; 32]);
    // The epoch this device has not caught up to, for the one row it must
    // report rather than lose the collection over.
    let other = CollectionKey::from_bytes([4u8; 32]);

    let id = |tail: u8| Uuid::from_bytes([tail; 16]);
    let note = id(0xa1);
    let contact = id(0xa2);
    let dropped = id(0xa3);
    let sealed_delete = id(0xa4);
    let stranger = id(0xa5);

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

    let note_payload = r#"{"@type":"Note","version":"1","title":"walked"}"#;
    let contact_payload = r#"{"@type":"Card","version":"1.0","name":{"full":"Alpha"}}"#;
    // Revision 2 is superseded by revision 7 in the second page.
    let stale = seal(
        &key,
        note,
        seal_envelope(NOTE, b"{\"@type\":\"Note\",\"version\":\"1\"}"),
        2,
        false,
    );
    let current = seal(
        &key,
        note,
        seal_envelope(NOTE, note_payload.as_bytes()),
        7,
        false,
    );
    let contact_row = seal(
        &key,
        contact,
        seal_envelope(CONTACT, contact_payload.as_bytes()),
        3,
        false,
    );
    // A row-level tombstone keeps whatever body it had: the flag is what the
    // manifest vouches for, and a rotation never re-seals it.
    let row_delete = seal(&key, dropped, seal_envelope(NOTE, b"gone"), 4, true);
    let envelope_delete = seal(&key, sealed_delete, seal_tombstone_envelope(NOTE), 5, false);
    let unreachable = seal(
        &other,
        stranger,
        seal_envelope(NOTE, b"{\"@type\":\"Note\"}"),
        6,
        false,
    );

    let first = vec![stale, contact_row.clone(), row_delete.clone()];
    let second = vec![
        envelope_delete.clone(),
        unreachable.clone(),
        current.clone(),
    ];

    // The manifest commits to the collection after the walk, which is the
    // newest revision of each object.
    let entries: Vec<CoreManifestEntry> = [
        &contact_row,
        &row_delete,
        &envelope_delete,
        &unreachable,
        &current,
    ]
    .iter()
    .map(|row| {
        sealbook_core::manifest_entry_for(
            row.id,
            row.revision,
            row.tombstone,
            &row.nonce,
            &row.ciphertext,
        )
        .unwrap()
    })
    .collect();
    let manifest = manifest_sign(
        &secrets,
        &ManifestContext {
            collection_id,
            device_id,
            manifest_seq: 0,
        },
        &ManifestPlan {
            manifest_seq: 6,
            key_epoch,
            latest_revision: 7,
        },
        &entries,
    )
    .unwrap();
    let manifest_body: Value = serde_json::from_str(&manifest.manifest_json).unwrap();

    let page = |rows: &[CoreSealedRow], after: u64, has_more: bool| {
        json!({
            // The request this page is the answer to, so a reader checks the
            // walk's cursor rather than only its result.
            "request_path": format!(
                "/v1/collections/{COLLECTION}/changes?after={after}&limit=500&snapshot=true"
            ),
            "latest_revision": 7,
            "key_epoch": key_epoch,
            "objects": rows.iter().map(|row| json!({
                "id": row.id,
                "revision": row.revision,
                "tombstone": row.tombstone,
                "nonce": row.nonce,
                "ciphertext": row.ciphertext,
                "padded_size": row.padded_size,
                "content_type": "application/sealbook.sealed",
            })).collect::<Vec<_>>(),
            "has_more": has_more,
            "manifest": manifest_body,
            // The server marks every snapshot answer a resync, because a
            // snapshot walk is itself one.
            "resync": true,
            "tombstone_floor": 1,
        })
    };

    Fixture {
        collection_id,
        device_id,
        key_epoch,
        collection_key: b64(key.as_bytes()),
        devices,
        pages: vec![page(&first, 0, true), page(&second, 4, false)],
        // In walk order, which is first appearance in revision order: the
        // note's superseded revision 2 is what puts it ahead of the contact,
        // not the revision 7 the read keeps.
        objects: vec![
            ReadObject {
                id: note,
                content_type: NOTE.into(),
                payload: note_payload.into(),
            },
            ReadObject {
                id: contact,
                content_type: CONTACT.into(),
                payload: contact_payload.into(),
            },
        ],
        deleted: vec![dropped, sealed_delete],
        unreadable: vec![UnreadableRow {
            id: stranger,
            reason: UnreadableReason::Key,
        }],
    }
}
