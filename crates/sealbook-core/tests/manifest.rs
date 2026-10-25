//! The shared manifest fixture, and core's decisions over it.
//!
//! Signed by the same alpha device as the roster fixture, under the same
//! collection, so the two describe one account.
//!
//! Run `REGENERATE_MANIFEST_FIXTURE=1 cargo test -p sealbook-core -- --ignored
//! regenerate` to rewrite the fixture after a deliberate wire change.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sealbook_core::{
    accept_manifest_seq, manifest_accept, manifest_apply, manifest_buckets_accept,
    manifest_absence_ok, manifest_buckets_from_whole, manifest_buckets_request, manifest_entry_for,
    manifest_request, manifest_sign, manifest_sign_root, manifest_signer, manifest_verify,
    BucketsOutcome, CoreDevice, CoreError,
    CoreManifestEntry, HttpResponse, ManifestContext, ManifestOutcome, ManifestPlan, Method,
};
use sealbook_crypto::{signing_from_seeds, DeviceSigningSecrets};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../sealbook-protocol/fixtures/manifests/one-write.json"
);

const COLLECTION: &str = "11111111-1111-1111-1111-111111111111";
const ALPHA: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

#[derive(Serialize, Deserialize)]
struct Fixture {
    collection_id: Uuid,
    device_id: Uuid,
    key_epoch: u64,
    /// Alpha's signing seeds, the same pair the roster fixture enrols.
    mldsa_seed: String,
    ed25519_sk: String,
    devices: Vec<CoreDevice>,
    manifest_response: Value,
    /// The buckets the write below touches.
    wanted: Vec<u8>,
    buckets_response: Value,
    write: Vec<CoreManifestEntry>,
    next_object_count: u64,
    next_root: String,
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(text: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(text).expect("fixture base64")
}

fn fixture() -> Fixture {
    serde_json::from_str(&std::fs::read_to_string(FIXTURE).expect("manifest fixture")).unwrap()
}

fn ok(body: &Value) -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: Vec::new(),
        body: serde_json::to_vec(body).unwrap(),
    }
}

impl Fixture {
    fn context(&self) -> ManifestContext {
        ManifestContext {
            collection_id: self.collection_id,
            device_id: self.device_id,
            manifest_seq: 0,
        }
    }

    fn secrets(&self) -> DeviceSigningSecrets {
        DeviceSigningSecrets {
            mldsa_seed: unb64(&self.mldsa_seed),
            ed25519_sk: unb64(&self.ed25519_sk),
        }
    }

    fn ids(&self) -> Vec<Uuid> {
        self.write.iter().map(|entry| entry.id).collect()
    }
}

// ── Requests ──

#[test]
fn the_whole_manifest_is_asked_for_by_collection() {
    let fixture = fixture();
    let request = manifest_request(&fixture.context());
    assert_eq!(request.method, Method::Get);
    assert_eq!(
        request.path,
        format!("/v1/collections/{COLLECTION}/manifest")
    );
}

#[test]
fn a_write_asks_only_for_the_buckets_its_objects_fall_in() {
    let fixture = fixture();
    let request = manifest_buckets_request(&fixture.context(), &fixture.ids());
    let query: String = fixture
        .wanted
        .iter()
        .map(|bucket| format!("{bucket:02x}"))
        .collect();
    assert_eq!(
        request.path,
        format!("/v1/collections/{COLLECTION}/manifest/buckets?buckets={query}")
    );
}

#[test]
fn the_bucket_list_is_sorted_and_deduplicated() {
    let fixture = fixture();
    let id = |byte: u8| Uuid::from_bytes([byte; 16]);
    let request = manifest_buckets_request(&fixture.context(), &[id(0x1f), id(0x03), id(0x1f)]);
    assert!(request.path.ends_with("buckets=031f"));
}

// ── Accepting what came back ──

#[test]
fn the_signer_is_read_before_the_roster_is_fetched() {
    let fixture = fixture();
    let signer = manifest_signer(&serde_json::to_vec(&fixture.manifest_response).unwrap())
        .unwrap()
        .expect("a signed manifest");
    assert_eq!(signer.device_id.to_string(), ALPHA);
    assert_eq!(signer.key_epoch, fixture.key_epoch);
}

#[test]
fn a_collection_with_no_manifest_names_no_signer() {
    let body = serde_json::json!({ "manifest": null, "entries": [] });
    assert!(manifest_signer(&serde_json::to_vec(&body).unwrap())
        .unwrap()
        .is_none());
}

#[test]
fn the_checked_in_whole_manifest_verifies() {
    let fixture = fixture();
    let outcome = manifest_accept(
        &fixture.context(),
        &ok(&fixture.manifest_response),
        &fixture.devices,
    )
    .unwrap();
    let ManifestOutcome::Signed { plan, entries } = outcome else {
        panic!("the fixture carries a signed manifest");
    };
    assert_eq!(plan.key_epoch, fixture.key_epoch);
    assert_eq!(plan.manifest_seq, 7);
    assert_eq!(entries.len(), 5);
}

#[test]
fn an_object_withheld_from_the_served_set_is_refused() {
    let fixture = fixture();
    let mut body = fixture.manifest_response.clone();
    body["entries"].as_array_mut().unwrap().pop();
    // The count check fires first, so drop the count to the served length to
    // reach the digest check that is the real guard.
    body["manifest"]["object_count"] = serde_json::json!(4);
    let err = manifest_accept(&fixture.context(), &ok(&body), &fixture.devices).unwrap_err();
    assert!(
        matches!(&err, CoreError::Manifest { detail } if detail.contains("withheld")),
        "{err:?}"
    );
}

#[test]
fn a_manifest_signed_by_a_device_outside_the_roster_is_refused() {
    let fixture = fixture();
    let err = manifest_accept(&fixture.context(), &ok(&fixture.manifest_response), &[]).unwrap_err();
    assert!(
        matches!(&err, CoreError::Manifest { detail } if detail.contains("does not have")),
        "{err:?}"
    );
}

#[test]
fn a_manifest_older_than_the_one_this_device_saw_is_refused() {
    let fixture = fixture();
    let context = ManifestContext {
        manifest_seq: 99,
        ..fixture.context()
    };
    let err = manifest_accept(&context, &ok(&fixture.manifest_response), &fixture.devices)
        .unwrap_err();
    assert!(
        matches!(&err, CoreError::Manifest { detail } if detail.contains("went backwards")),
        "{err:?}"
    );
}

#[test]
fn a_vault_with_no_manifest_is_accepted_only_by_a_device_that_has_seen_none() {
    let fixture = fixture();
    let mut body = fixture.manifest_response.clone();
    body["manifest"] = Value::Null;
    let outcome = manifest_accept(&fixture.context(), &ok(&body), &fixture.devices).unwrap();
    let ManifestOutcome::Unmanifested {
        latest_revision,
        entries,
    } = outcome
    else {
        panic!("no manifest was served");
    };
    assert_eq!(entries.len(), 5);
    assert_eq!(latest_revision, 12);

    let context = ManifestContext {
        manifest_seq: 7,
        ..fixture.context()
    };
    let err = manifest_accept(&context, &ok(&body), &fixture.devices).unwrap_err();
    assert!(
        matches!(&err, CoreError::Manifest { detail } if detail.contains("has seen sequence")),
        "{err:?}"
    );
}

#[test]
fn the_checked_in_bucket_answer_verifies_and_holds_what_a_write_needs() {
    let fixture = fixture();
    let held = signed_buckets(&fixture);
    assert_eq!(held.plan.manifest_seq, 7);
    assert_eq!(held.object_count, 5);
    assert_eq!(held.held, fixture.wanted);
    // Only the asked-for buckets' entries, not the whole collection.
    assert!(held.entries.len() < 5);
}

#[test]
fn a_bucket_answer_for_other_buckets_than_were_asked_for_is_refused() {
    let fixture = fixture();
    let mut body = fixture.buckets_response.clone();
    body["served"] = serde_json::json!([0x03]);
    let err = manifest_buckets_accept(
        &fixture.context(),
        &fixture.ids(),
        &ok(&body),
        &fixture.devices,
    )
    .unwrap_err();
    assert!(
        matches!(&err, CoreError::Manifest { detail } if detail.contains("other buckets")),
        "{err:?}"
    );
}

#[test]
fn an_object_withheld_from_a_served_bucket_is_refused() {
    let fixture = fixture();
    let mut body = fixture.buckets_response.clone();
    body["entries"].as_array_mut().unwrap().pop();
    let err = manifest_buckets_accept(
        &fixture.context(),
        &fixture.ids(),
        &ok(&body),
        &fixture.devices,
    )
    .unwrap_err();
    assert!(
        matches!(&err, CoreError::Manifest { detail } if detail.contains("do not match its digest")),
        "{err:?}"
    );
}

#[test]
fn an_edited_bucket_digest_fails_the_root_rather_than_the_bucket_check() {
    let fixture = fixture();
    let mut body = fixture.buckets_response.clone();
    let mut blob = unb64(body["buckets"].as_str().unwrap());
    // Bucket 0x81 carries no served entries, so only the root binds it.
    blob[0x81 * 32] ^= 1;
    body["buckets"] = serde_json::json!(b64(&blob));
    let err = manifest_buckets_accept(
        &fixture.context(),
        &fixture.ids(),
        &ok(&body),
        &fixture.devices,
    )
    .unwrap_err();
    assert!(
        matches!(&err, CoreError::Manifest { detail } if detail.contains("bucket digests served")),
        "{err:?}"
    );
}

#[test]
fn a_bucket_answer_with_no_manifest_sends_the_host_to_the_whole_read() {
    let fixture = fixture();
    let mut body = fixture.buckets_response.clone();
    body["manifest"] = Value::Null;
    let outcome = manifest_buckets_accept(
        &fixture.context(),
        &fixture.ids(),
        &ok(&body),
        &fixture.devices,
    )
    .unwrap();
    assert!(matches!(outcome, BucketsOutcome::Unmanifested));

    // The rule still applies: a device that has seen a manifest may not be told
    // there is none.
    let context = ManifestContext {
        manifest_seq: 7,
        ..fixture.context()
    };
    assert!(
        manifest_buckets_accept(&context, &fixture.ids(), &ok(&body), &fixture.devices).is_err()
    );
}

#[test]
fn a_walk_is_checked_against_the_manifest_it_was_served_with() {
    let fixture = fixture();
    let manifest = fixture.manifest_response["manifest"].to_string();
    let entries: Vec<CoreManifestEntry> =
        serde_json::from_value(fixture.manifest_response["entries"].clone()).unwrap();
    let plan = manifest_verify(&fixture.context(), &manifest, &entries, &fixture.devices).unwrap();
    assert_eq!(plan.manifest_seq, 7);

    // One object dropped from the walk is the rollback this check exists for.
    let short = &entries[..4];
    let err =
        manifest_verify(&fixture.context(), &manifest, short, &fixture.devices).unwrap_err();
    assert!(
        matches!(&err, CoreError::Manifest { detail } if detail.contains("commits to")),
        "{err:?}"
    );
}

#[test]
fn objects_served_with_no_manifest_are_refused_once_this_device_has_seen_one() {
    let fixture = fixture();
    assert!(manifest_absence_ok(&fixture.context()).is_ok());
    let context = ManifestContext {
        manifest_seq: 1,
        ..fixture.context()
    };
    assert!(manifest_absence_ok(&context).is_err());
}

// ── The next manifest ──

#[test]
fn the_write_folded_in_produces_the_root_the_server_will_recompute() {
    let fixture = fixture();
    let applied = manifest_apply(&signed_buckets(&fixture), &fixture.write).unwrap();
    assert_eq!(applied.object_count, fixture.next_object_count);
    assert_eq!(applied.root, fixture.next_root);
}

#[test]
fn the_bucket_path_and_the_whole_path_agree_on_the_root() {
    let fixture = fixture();
    let ManifestOutcome::Signed { plan, entries } = manifest_accept(
        &fixture.context(),
        &ok(&fixture.manifest_response),
        &fixture.devices,
    )
    .unwrap()
    else {
        panic!("signed");
    };
    let whole = manifest_buckets_from_whole(&plan, &entries).unwrap();
    assert_eq!(
        manifest_apply(&whole, &fixture.write).unwrap().root,
        fixture.next_root
    );
}

#[test]
fn a_write_into_a_bucket_this_device_did_not_fetch_is_refused() {
    let fixture = fixture();
    let stray = CoreManifestEntry {
        id: Uuid::from_bytes([0x7e; 16]),
        ..fixture.write[0].clone()
    };
    let err = manifest_apply(&signed_buckets(&fixture), &[stray]).unwrap_err();
    assert!(
        matches!(&err, CoreError::Manifest { detail } if detail.contains("did not fetch")),
        "{err:?}"
    );
}

#[test]
fn a_signed_manifest_is_the_one_a_reader_verifies() {
    let fixture = fixture();
    let plan = ManifestPlan {
        manifest_seq: 8,
        key_epoch: fixture.key_epoch,
        latest_revision: 13,
    };
    let applied = manifest_apply(&signed_buckets(&fixture), &fixture.write).unwrap();
    let signed =
        manifest_sign_root(&fixture.secrets(), &fixture.context(), &plan, &applied).unwrap();
    assert_eq!(signed.digest, fixture.next_root);
    assert_eq!(signed.object_count, fixture.next_object_count);

    // What the host puts on the wire has to verify against the same entry set,
    // which is what the server checks before it stores the manifest.
    let body: Value = serde_json::from_str(&signed.manifest_json).unwrap();
    assert_eq!(body["manifest_seq"], 8);
    assert_eq!(body["digest"].as_str().unwrap(), fixture.next_root);
    assert_eq!(body["device_id"].as_str().unwrap(), ALPHA);
}

#[test]
fn signing_over_the_entries_and_over_the_root_cover_the_same_value() {
    let fixture = fixture();
    let ManifestOutcome::Signed { plan, mut entries } = manifest_accept(
        &fixture.context(),
        &ok(&fixture.manifest_response),
        &fixture.devices,
    )
    .unwrap()
    else {
        panic!("signed");
    };
    let whole = manifest_sign(&fixture.secrets(), &fixture.context(), &plan, &entries).unwrap();
    let applied = manifest_apply(
        &manifest_buckets_from_whole(&plan, &entries).unwrap(),
        &[],
    )
    .unwrap();
    assert_eq!(whole.digest, applied.root);
    assert_eq!(whole.object_count, applied.object_count);

    // And the fixture's own manifest is that same value, which is what makes
    // this a check of the checked-in bytes rather than of core alone.
    assert_eq!(
        fixture.manifest_response["manifest"]["digest"]
            .as_str()
            .unwrap(),
        whole.digest
    );
    entries.clear();
}

#[test]
fn the_pin_moves_forward_and_never_back() {
    assert_eq!(accept_manifest_seq(7, 9), 9);
    assert_eq!(accept_manifest_seq(9, 7), 9);
}

#[test]
fn an_entry_commits_to_the_bytes_that_were_sealed() {
    let id = Uuid::from_bytes([0x03; 16]);
    let entry = manifest_entry_for(id, 4, false, &b64(&[1, 2, 3]), &b64(&[4, 5, 6])).unwrap();
    assert_eq!(
        entry.content_digest,
        b64(&sealbook_crypto::content_digest(&[1, 2, 3], &[4, 5, 6]))
    );
    // The digest is over the ciphertext, so the same object sealed again under a
    // fresh nonce commits to something else.
    let other = manifest_entry_for(id, 4, false, &b64(&[9, 9, 9]), &b64(&[4, 5, 6])).unwrap();
    assert_ne!(entry.content_digest, other.content_digest);
}

fn signed_buckets(fixture: &Fixture) -> sealbook_core::BucketedManifest {
    let outcome = manifest_buckets_accept(
        &fixture.context(),
        &fixture.ids(),
        &ok(&fixture.buckets_response),
        &fixture.devices,
    )
    .unwrap();
    match outcome {
        BucketsOutcome::Signed { held } => held,
        BucketsOutcome::Unmanifested => panic!("the fixture carries a signed manifest"),
    }
}

// ── The generator ──

#[test]
#[ignore = "writes the checked-in fixture; run with REGENERATE_MANIFEST_FIXTURE=1"]
fn regenerate_the_manifest_fixture() {
    if std::env::var("REGENERATE_MANIFEST_FIXTURE").as_deref() != Ok("1") {
        panic!("set REGENERATE_MANIFEST_FIXTURE=1 to rewrite the fixture");
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
    // Not the bytes: ML-DSA signing need not be deterministic, so the
    // commitments are what must match.
    assert_eq!(
        built.manifest_response["manifest"]["digest"],
        have.manifest_response["manifest"]["digest"]
    );
    assert_eq!(
        built.buckets_response["buckets"],
        have.buckets_response["buckets"]
    );
    assert_eq!(built.next_root, have.next_root);
    assert_eq!(built.next_object_count, have.next_object_count);
    assert_eq!(built.wanted, have.wanted);
}

/// The fixture collection: five objects spread over four buckets, one write
/// that updates an object in a served bucket and one that adds to another.
fn build() -> Fixture {
    let collection_id: Uuid = COLLECTION.parse().unwrap();
    let device_id: Uuid = ALPHA.parse().unwrap();
    let key_epoch = 4;
    let (secrets, public) = signing_from_seeds(&[1u8; 32], &[2u8; 32]);
    let devices = vec![CoreDevice {
        device_id,
        mldsa_pk: b64(&public.mldsa_pk),
        ed25519_pk: b64(&public.ed25519_pk),
        // A manifest check never reads an HPKE key; the roster fixture is where
        // that field is real.
        xwing_hpke_pk: String::new(),
    }];

    let object = |bucket: u8, tail: u8| {
        let mut bytes = [tail; 16];
        bytes[0] = bucket;
        Uuid::from_bytes(bytes)
    };
    let entry = |id: Uuid, revision: u64, tombstone: bool, seed: u8| CoreManifestEntry {
        id,
        revision,
        tombstone,
        content_digest: b64(&sealbook_crypto::content_digest(&[seed], &[seed; 48])),
    };
    let updated = object(0x1f, 0x22);
    let entries = vec![
        entry(object(0x03, 0x11), 3, false, 1),
        entry(updated, 9, false, 2),
        entry(object(0x1f, 0x33), 10, false, 3),
        entry(object(0x80, 0x44), 12, true, 4),
        entry(object(0xff, 0x55), 5, false, 5),
    ];
    let write = vec![
        entry(updated, 13, false, 6),
        entry(object(0x03, 0x66), 14, false, 7),
    ];
    let wanted = vec![0x03u8, 0x1f];

    let context = ManifestContext {
        collection_id,
        device_id,
        manifest_seq: 0,
    };
    let plan = ManifestPlan {
        manifest_seq: 7,
        key_epoch,
        latest_revision: 12,
    };
    let signed = manifest_sign(&secrets, &context, &plan, &entries).unwrap();
    let manifest: Value = serde_json::from_str(&signed.manifest_json).unwrap();
    let whole = manifest_buckets_from_whole(&plan, &entries).unwrap();
    let applied = manifest_apply(&whole, &write).unwrap();

    let wire = |entry: &CoreManifestEntry| {
        serde_json::json!({
            "id": entry.id,
            "revision": entry.revision,
            "tombstone": entry.tombstone,
            "content_digest": entry.content_digest,
        })
    };
    let served: Vec<Value> = entries
        .iter()
        .filter(|entry| wanted.contains(&entry.id.as_bytes()[0]))
        .map(wire)
        .collect();

    Fixture {
        collection_id,
        device_id,
        key_epoch,
        mldsa_seed: b64(&secrets.mldsa_seed),
        ed25519_sk: b64(&secrets.ed25519_sk),
        devices,
        manifest_response: serde_json::json!({
            "manifest": manifest,
            "entries": entries.iter().map(wire).collect::<Vec<Value>>(),
        }),
        buckets_response: serde_json::json!({
            "manifest": manifest,
            "buckets": whole.buckets,
            "object_count": entries.len(),
            "served": wanted,
            "entries": served,
        }),
        wanted,
        write,
        next_object_count: applied.object_count,
        next_root: applied.root,
    }
}
