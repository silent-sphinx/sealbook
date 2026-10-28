//! Attachment decisions, against the fixture the three clients share.
//!
//! What is pinned here is what the clients disagreed about: how a size becomes a
//! chunk count, which paths the rounds use, what each refusal is called, the
//! content hash a download is checked against, and which listed attachments a
//! sweep is allowed to delete.
//!
//! The sealed chunk is the generator's output once, because `encrypt_chunk`
//! draws a fresh nonce. Every language opens that same chunk, which is what
//! proves the three agree on the AAD rather than only on the key.
//!
//! Regenerate with:
//! `REGENERATE_ATTACHMENT_FIXTURE=1 cargo test -p sealbook-core --test attachments -- --ignored regenerate`

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sealbook_core::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const FIXTURE: &str = "../sealbook-protocol/fixtures/attachments/attachments.json";

const COLLECTION: &str = "11111111-1111-4111-8111-111111111111";
const ATTACHMENT: &str = "22222222-2222-4222-8222-222222222222";
const OTHER: &str = "33333333-3333-4333-8333-333333333333";
/// A fixed key, so the sealed chunk below is openable in every language.
const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

#[derive(Serialize, Deserialize)]
struct Fixture {
    collection_id: String,
    attachment_id: String,
    key: String,
    limits: Limits,
    plans: Vec<Plan>,
    paths: Paths,
    digests: Vec<Digest>,
    content_hashes: Vec<ContentHash>,
    sealed_chunk: SealedChunk,
    refusals: Vec<Refusal>,
    sweep: Sweep,
}

#[derive(Serialize, Deserialize)]
struct Limits {
    max_size: u64,
    chunk_size: u32,
    nonce_header: String,
    nonce_len: u32,
    orphan_grace_secs: i64,
}

#[derive(Serialize, Deserialize)]
struct Plan {
    size: u64,
    chunk_count: u32,
    /// Omitted for the sizes whose range list would be dozens of entries; the
    /// count is the decision those pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ranges: Option<Vec<(u64, u64)>>,
}

#[derive(Serialize, Deserialize)]
struct Paths {
    create: String,
    chunk: String,
    commit: String,
    meta: String,
    delete: String,
    list: String,
    list_after: String,
}

#[derive(Serialize, Deserialize)]
struct Digest {
    plaintext_b64: String,
    digest: String,
}

#[derive(Serialize, Deserialize)]
struct ContentHash {
    digests: Vec<String>,
    hash: String,
}

#[derive(Serialize, Deserialize)]
struct SealedChunk {
    index: u32,
    chunk_count: u32,
    plaintext_b64: String,
    nonce: String,
    ciphertext_b64: String,
}

#[derive(Serialize, Deserialize)]
struct Refusal {
    case: String,
    refusal: String,
}

#[derive(Serialize, Deserialize)]
struct Sweep {
    rows: Vec<Row>,
    referenced: Vec<String>,
    now_secs: i64,
    orphans: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Row {
    attachment_id: String,
    state: String,
    created_at: i64,
}

fn fixture() -> Fixture {
    let text = std::fs::read_to_string(FIXTURE).expect("fixture");
    serde_json::from_str(&text).expect("fixture parses")
}

fn collection() -> Uuid {
    COLLECTION.parse().unwrap()
}

fn attachment() -> Uuid {
    ATTACHMENT.parse().unwrap()
}

fn plan_of(size: u64) -> AttachmentPlan {
    AttachmentPlan {
        attachment_id: attachment(),
        key: KEY.to_string(),
        chunk_size: attachment_limits().chunk_size,
        chunk_count: size.div_ceil(attachment_limits().chunk_size as u64) as u32,
        total_plaintext_size: size,
    }
}

/// The refusal's variant name, which is what the fixture pins rather than the
/// sentence each host words for itself.
fn refusal_name(error: &CoreError) -> String {
    match error {
        CoreError::Attachment { refusal } => match refusal {
            AttachmentRefusal::Empty => "Empty",
            AttachmentRefusal::TooLarge { .. } => "TooLarge",
            AttachmentRefusal::ChunkCount { .. } => "ChunkCount",
            AttachmentRefusal::State { .. } => "State",
            AttachmentRefusal::MissingNonce => "MissingNonce",
            AttachmentRefusal::Key => "Key",
        }
        .to_string(),
        CoreError::AttachmentIntegrity { .. } => "Integrity".to_string(),
        other => other.kind().to_string(),
    }
}

fn refused(result: Result<(), CoreError>) -> String {
    refusal_name(&result.expect_err("refused"))
}

#[test]
fn the_limits_are_the_protocols() {
    let fixture = fixture();
    let limits = attachment_limits();
    assert_eq!(limits.max_size, fixture.limits.max_size);
    assert_eq!(limits.chunk_size, fixture.limits.chunk_size);
    assert_eq!(limits.nonce_header, fixture.limits.nonce_header);
    assert_eq!(limits.nonce_len, fixture.limits.nonce_len);
    assert_eq!(limits.orphan_grace_secs, fixture.limits.orphan_grace_secs);
    assert_eq!(limits.nonce_header, NONCE_HEADER);
}

#[test]
fn a_size_becomes_the_chunk_count_the_server_derives() {
    for entry in fixture().plans {
        if entry.size == 0 || entry.size > attachment_limits().max_size {
            continue;
        }
        let plan = attachment_plan(entry.size).expect("planned");
        assert_eq!(plan.chunk_count, entry.chunk_count, "size {}", entry.size);
        assert_eq!(plan.total_plaintext_size, entry.size);
    }
}

/// The server recomputes the count the same way and refuses one that disagrees,
/// so a client's arithmetic has to match it exactly.
#[test]
fn the_chunk_count_is_the_rounded_up_division_with_no_floor() {
    let chunk = attachment_limits().chunk_size as u64;
    assert_eq!(attachment_plan(1).unwrap().chunk_count, 1);
    assert_eq!(attachment_plan(chunk - 1).unwrap().chunk_count, 1);
    assert_eq!(attachment_plan(chunk).unwrap().chunk_count, 1);
    assert_eq!(attachment_plan(chunk + 1).unwrap().chunk_count, 2);
    assert_eq!(attachment_plan(chunk * 3).unwrap().chunk_count, 3);
}

#[test]
fn the_ranges_cover_the_plaintext_once_and_in_order() {
    for entry in fixture().plans {
        let Some(expected) = entry.ranges else {
            continue;
        };
        let ranges = attachment_ranges(&plan_of(entry.size));
        let actual: Vec<(u64, u64)> = ranges.iter().map(|r| (r.start, r.end)).collect();
        assert_eq!(actual, expected, "size {}", entry.size);
        assert_eq!(ranges.last().unwrap().end, entry.size);
        for (index, range) in ranges.iter().enumerate() {
            assert_eq!(range.index as usize, index);
        }
    }
}

#[test]
fn an_empty_attachment_is_refused_rather_than_sent() {
    assert_eq!(refused(attachment_plan(0).map(|_| ())), "Empty");
}

#[test]
fn an_attachment_over_the_protocol_ceiling_is_refused() {
    let over = attachment_limits().max_size + 1;
    assert_eq!(refused(attachment_plan(over).map(|_| ())), "TooLarge");
}

#[test]
fn the_rounds_use_the_paths_the_fixture_pins() {
    let fixture = fixture();
    let plan = plan_of(1);
    assert_eq!(
        attachment_create_request(collection(), &plan).path,
        fixture.paths.create
    );
    assert_eq!(
        attachment_chunk_path(collection(), attachment(), 0),
        fixture.paths.chunk
    );
    assert_eq!(
        attachment_commit_request(collection(), attachment()).path,
        fixture.paths.commit
    );
    assert_eq!(
        attachment_meta_request(collection(), attachment()).path,
        fixture.paths.meta
    );
    assert_eq!(
        attachment_delete_request(collection(), attachment()).path,
        fixture.paths.delete
    );
    assert_eq!(
        sweep_request(collection(), &sweep_start()).path,
        fixture.paths.list
    );
    let cursor = SweepCursor {
        after: Some(attachment()),
        seen: vec![attachment()],
    };
    assert_eq!(
        sweep_request(collection(), &cursor).path,
        fixture.paths.list_after
    );
}

#[test]
fn the_create_body_is_what_the_server_validates_against() {
    let plan = plan_of(attachment_limits().chunk_size as u64 + 1);
    let request = attachment_create_request(collection(), &plan);
    let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body["attachment_id"], ATTACHMENT);
    assert_eq!(body["total_plaintext_size"], plan.total_plaintext_size);
    assert_eq!(body["chunk_size"], plan.chunk_size);
    assert_eq!(body["chunk_count"], 2);
}

#[test]
fn a_reservation_for_another_attachment_is_not_accepted() {
    let plan = plan_of(1);
    let body = format!(r#"{{"attachment_id":"{OTHER}","state":"pending"}}"#);
    assert_eq!(refused(attachment_create_accept(&plan, &body)), "Malformed");
}

#[test]
fn a_reservation_the_server_already_calls_committed_is_refused() {
    let plan = plan_of(1);
    let body = format!(r#"{{"attachment_id":"{ATTACHMENT}","state":"committed"}}"#);
    assert_eq!(refused(attachment_create_accept(&plan, &body)), "State");
}

#[test]
fn a_commit_the_server_left_pending_is_not_reported_as_done() {
    let pending = format!(r#"{{"attachment_id":"{ATTACHMENT}","state":"pending"}}"#);
    assert_eq!(
        refused(attachment_commit_accept(attachment(), &pending)),
        "State"
    );
    let done = format!(r#"{{"attachment_id":"{ATTACHMENT}","state":"committed"}}"#);
    assert!(attachment_commit_accept(attachment(), &done).is_ok());
}

/// The record's count is the one every chunk's AAD was built over, so a server
/// offering a different number of chunks is offering a different attachment.
#[test]
fn a_server_that_names_another_chunk_count_is_refused_before_any_bytes() {
    let body = meta_body(ATTACHMENT, "committed", 7);
    assert_eq!(
        refused(attachment_meta_accept(attachment(), 3, &body).map(|_| ())),
        "ChunkCount"
    );
    assert!(attachment_meta_accept(attachment(), 7, &body).is_ok());
}

#[test]
fn an_uncommitted_attachment_is_not_downloaded() {
    let body = meta_body(ATTACHMENT, "pending", 1);
    assert_eq!(
        refused(attachment_meta_accept(attachment(), 1, &body).map(|_| ())),
        "State"
    );
}

#[test]
fn a_chunk_served_without_its_nonce_header_is_refused() {
    assert_eq!(
        refused(attachment_chunk_nonce(None).map(|_| ())),
        "MissingNonce"
    );
    assert_eq!(
        refused(attachment_chunk_nonce(Some(String::new())).map(|_| ())),
        "MissingNonce"
    );
    assert_eq!(attachment_chunk_nonce(Some("abc".into())).unwrap(), "abc");
}

#[test]
fn a_chunk_digest_is_the_value_the_fixture_pins() {
    for entry in fixture().digests {
        let plaintext = URL_SAFE_NO_PAD.decode(&entry.plaintext_b64).unwrap();
        assert_eq!(attachment_chunk_digest(&plaintext), entry.digest);
    }
}

#[test]
fn the_content_hash_is_the_value_the_fixture_pins() {
    for entry in fixture().content_hashes {
        assert_eq!(attachment_content_hash(&entry.digests).unwrap(), entry.hash);
    }
}

/// The count is folded in last for exactly this: a prefix of the chunks must
/// not roll up to the same value as the whole set.
#[test]
fn a_truncated_chunk_set_does_not_reach_the_whole_hash() {
    let digests: Vec<String> = (0u8..4)
        .map(|byte| attachment_chunk_digest(&[byte; 16]))
        .collect();
    let whole = attachment_content_hash(&digests).unwrap();
    assert_ne!(attachment_content_hash(&digests[..3]).unwrap(), whole);

    let mut reordered = digests.clone();
    reordered.swap(0, 1);
    assert_ne!(attachment_content_hash(&reordered).unwrap(), whole);
}

#[test]
fn a_download_that_does_not_reproduce_the_hash_is_an_integrity_failure() {
    let digests = vec![attachment_chunk_digest(b"one")];
    let hash = attachment_content_hash(&digests).unwrap();
    assert!(attachment_verify(attachment(), &hash, &digests).is_ok());

    let wrong = vec![attachment_chunk_digest(b"two")];
    assert_eq!(
        refused(attachment_verify(attachment(), &hash, &wrong)),
        "Integrity"
    );
}

#[test]
fn a_chunk_core_sealed_opens_again_under_the_same_aad() {
    let fixture = fixture();
    let sealed = fixture.sealed_chunk;
    let plaintext = URL_SAFE_NO_PAD.decode(&sealed.plaintext_b64).unwrap();
    let ciphertext = URL_SAFE_NO_PAD.decode(&sealed.ciphertext_b64).unwrap();
    let opened = open_attachment_chunk(
        KEY,
        attachment(),
        collection(),
        sealed.index,
        sealed.chunk_count,
        &sealed.nonce,
        &ciphertext,
    )
    .expect("opens");
    assert_eq!(opened, plaintext);
}

/// Each of these is what a replayed, reordered or substituted chunk looks like,
/// and the AAD is what makes all four fail rather than decrypt to the wrong
/// thing.
#[test]
fn a_chunk_does_not_open_in_another_position_or_under_another_attachment() {
    let fixture = fixture();
    let sealed = fixture.sealed_chunk;
    let ciphertext = URL_SAFE_NO_PAD.decode(&sealed.ciphertext_b64).unwrap();
    let open = |attachment_id: Uuid, collection_id: Uuid, index: u32, count: u32| {
        open_attachment_chunk(
            KEY,
            attachment_id,
            collection_id,
            index,
            count,
            &sealed.nonce,
            &ciphertext,
        )
        .map(|_| ())
    };
    let other: Uuid = OTHER.parse().unwrap();
    assert_eq!(
        refused(open(
            attachment(),
            collection(),
            sealed.index + 1,
            sealed.chunk_count
        )),
        "Integrity"
    );
    assert_eq!(
        refused(open(
            attachment(),
            collection(),
            sealed.index,
            sealed.chunk_count + 1
        )),
        "Integrity"
    );
    assert_eq!(
        refused(open(other, collection(), sealed.index, sealed.chunk_count)),
        "Integrity"
    );
    assert_eq!(
        refused(open(attachment(), other, sealed.index, sealed.chunk_count)),
        "Integrity"
    );
}

#[test]
fn a_seal_and_open_round_trips_every_chunk_of_a_plan() {
    let chunk = attachment_limits().chunk_size as u64;
    let data: Vec<u8> = (0..(chunk + 100)).map(|i| (i % 251) as u8).collect();
    let plan = plan_of(data.len() as u64);
    let mut digests = Vec::new();
    let mut out = Vec::new();
    for range in attachment_ranges(&plan) {
        let slice = &data[range.start as usize..range.end as usize];
        digests.push(attachment_chunk_digest(slice));
        let sealed = seal_attachment_chunk(
            &plan.key,
            plan.attachment_id,
            collection(),
            range.index,
            plan.chunk_count,
            slice,
        )
        .unwrap();
        let nonce_len = attachment_limits().nonce_len as usize;
        let opened = open_attachment_chunk(
            &plan.key,
            plan.attachment_id,
            collection(),
            range.index,
            plan.chunk_count,
            &URL_SAFE_NO_PAD.encode(&sealed[..nonce_len]),
            &sealed[nonce_len..],
        )
        .unwrap();
        out.extend_from_slice(&opened);
    }
    assert_eq!(out, data);
    let hash = attachment_content_hash(&digests).unwrap();
    assert!(attachment_verify(plan.attachment_id, &hash, &digests).is_ok());
}

#[test]
fn an_unreadable_key_is_named_rather_than_reported_as_a_crypto_failure() {
    assert_eq!(
        refused(
            seal_attachment_chunk("not base64!", attachment(), collection(), 0, 1, b"x")
                .map(|_| ())
        ),
        "Key"
    );
    assert_eq!(
        refused(seal_attachment_chunk("AAAA", attachment(), collection(), 0, 1, b"x").map(|_| ())),
        "Key"
    );
}

#[test]
fn every_refusal_the_fixture_names_is_one_core_raises() {
    let names: Vec<String> = fixture()
        .refusals
        .into_iter()
        .map(|entry| entry.refusal)
        .collect();
    for expected in [
        "Empty",
        "TooLarge",
        "ChunkCount",
        "State",
        "MissingNonce",
        "Key",
        "Integrity",
    ] {
        assert!(names.contains(&expected.to_string()), "{expected}");
    }
}

#[test]
fn a_sweep_pages_the_listing_and_stops_when_it_is_exhausted() {
    let first = format!(
        r#"{{"attachments":[{{"attachment_id":"{ATTACHMENT}","state":"committed","created_at":10}}],"next_after":"{OTHER}"}}"#
    );
    let cursor = sweep_start();
    let page = sweep_page(&cursor, &first).unwrap();
    assert_eq!(page.rows.len(), 1);
    let next = page.next.expect("another page");
    assert_eq!(next.after, Some(OTHER.parse().unwrap()));

    let last = r#"{"attachments":[],"next_after":null}"#;
    assert!(sweep_page(&next, last).unwrap().next.is_none());
}

/// The CLI had no such guard and would page forever.
#[test]
fn a_cursor_that_does_not_advance_ends_the_sweep() {
    let cursor = SweepCursor {
        after: Some(OTHER.parse().unwrap()),
        seen: vec![OTHER.parse().unwrap()],
    };
    let body = format!(r#"{{"attachments":[],"next_after":"{OTHER}"}}"#);
    assert!(sweep_page(&cursor, &body).unwrap().next.is_none());
}

#[test]
fn a_sweep_deletes_only_unreferenced_attachments_past_the_grace_period() {
    let fixture = fixture();
    let rows: Vec<AttachmentRow> = fixture
        .sweep
        .rows
        .iter()
        .map(|row| AttachmentRow {
            attachment_id: row.attachment_id.parse().unwrap(),
            state: row.state.clone(),
            created_at: row.created_at,
        })
        .collect();
    let referenced: Vec<Uuid> = fixture
        .sweep
        .referenced
        .iter()
        .map(|id| id.parse().unwrap())
        .collect();
    let orphans: Vec<String> = sweep_orphans(&rows, &referenced, fixture.sweep.now_secs)
        .iter()
        .map(|id| id.to_string())
        .collect();
    assert_eq!(orphans, fixture.sweep.orphans);
}

/// An upload creates the row before the record that references it is written,
/// so a sweep inside the grace period would delete a live attachment.
#[test]
fn an_attachment_inside_the_grace_period_is_left_alone() {
    let now = 1_000_000;
    let rows = vec![
        AttachmentRow {
            attachment_id: attachment(),
            state: "pending".into(),
            created_at: now - ORPHAN_GRACE_SECS + 1,
        },
        AttachmentRow {
            attachment_id: OTHER.parse().unwrap(),
            state: "committed".into(),
            created_at: now - ORPHAN_GRACE_SECS - 1,
        },
    ];
    assert_eq!(
        sweep_orphans(&rows, &[], now),
        vec![OTHER.parse::<Uuid>().unwrap()]
    );
}

fn meta_body(id: &str, state: &str, chunk_count: u32) -> String {
    format!(
        r#"{{"attachment_id":"{id}","state":"{state}","chunk_size":4194304,"chunk_count":{chunk_count},"total_ciphertext_size":64,"created_at":10}}"#
    )
}

#[test]
#[ignore = "writes the shared fixture"]
fn regenerate() {
    if std::env::var("REGENERATE_ATTACHMENT_FIXTURE").is_err() {
        return;
    }
    let limits = attachment_limits();
    let chunk = limits.chunk_size as u64;

    let sizes = [
        1u64,
        chunk - 1,
        chunk,
        chunk + 1,
        chunk * 3,
        limits.max_size,
    ];
    let plans: Vec<Plan> = sizes
        .iter()
        .map(|&size| {
            let plan = plan_of(size);
            let ranges = (plan.chunk_count <= 4).then(|| {
                attachment_ranges(&plan)
                    .iter()
                    .map(|r| (r.start, r.end))
                    .collect()
            });
            Plan {
                size,
                chunk_count: plan.chunk_count,
                ranges,
            }
        })
        .collect();

    let plaintexts: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"one".to_vec(),
        (0..=255u8).collect(),
        vec![7u8; 4096],
    ];
    let digests: Vec<Digest> = plaintexts
        .iter()
        .map(|plaintext| Digest {
            plaintext_b64: URL_SAFE_NO_PAD.encode(plaintext),
            digest: attachment_chunk_digest(plaintext),
        })
        .collect();

    let content_hashes: Vec<ContentHash> = (1..=plaintexts.len())
        .map(|take| {
            let list: Vec<String> = digests[..take].iter().map(|d| d.digest.clone()).collect();
            ContentHash {
                hash: attachment_content_hash(&list).unwrap(),
                digests: list,
            }
        })
        .collect();

    let plaintext = b"a chunk every client must be able to open".to_vec();
    let sealed = seal_attachment_chunk(KEY, attachment(), collection(), 1, 3, &plaintext).unwrap();
    let nonce_len = limits.nonce_len as usize;
    let sealed_chunk = SealedChunk {
        index: 1,
        chunk_count: 3,
        plaintext_b64: URL_SAFE_NO_PAD.encode(&plaintext),
        nonce: URL_SAFE_NO_PAD.encode(&sealed[..nonce_len]),
        ciphertext_b64: URL_SAFE_NO_PAD.encode(&sealed[nonce_len..]),
    };

    let now = 1_700_000_000i64;
    let rows = vec![
        Row {
            attachment_id: ATTACHMENT.into(),
            state: "committed".into(),
            created_at: now - ORPHAN_GRACE_SECS - 60,
        },
        Row {
            attachment_id: OTHER.into(),
            state: "committed".into(),
            created_at: now - ORPHAN_GRACE_SECS - 60,
        },
        Row {
            attachment_id: "44444444-4444-4444-8444-444444444444".into(),
            state: "pending".into(),
            created_at: now - 60,
        },
    ];
    let referenced = vec![OTHER.to_string()];
    let orphans: Vec<String> = sweep_orphans(
        &rows
            .iter()
            .map(|row| AttachmentRow {
                attachment_id: row.attachment_id.parse().unwrap(),
                state: row.state.clone(),
                created_at: row.created_at,
            })
            .collect::<Vec<_>>(),
        &referenced
            .iter()
            .map(|id| id.parse().unwrap())
            .collect::<Vec<Uuid>>(),
        now,
    )
    .iter()
    .map(|id| id.to_string())
    .collect();

    let plan = plan_of(1);
    let fixture = Fixture {
        collection_id: COLLECTION.into(),
        attachment_id: ATTACHMENT.into(),
        key: KEY.into(),
        limits: Limits {
            max_size: limits.max_size,
            chunk_size: limits.chunk_size,
            nonce_header: limits.nonce_header.clone(),
            nonce_len: limits.nonce_len,
            orphan_grace_secs: limits.orphan_grace_secs,
        },
        plans,
        paths: Paths {
            create: attachment_create_request(collection(), &plan).path,
            chunk: attachment_chunk_path(collection(), attachment(), 0),
            commit: attachment_commit_request(collection(), attachment()).path,
            meta: attachment_meta_request(collection(), attachment()).path,
            delete: attachment_delete_request(collection(), attachment()).path,
            list: sweep_request(collection(), &sweep_start()).path,
            list_after: sweep_request(
                collection(),
                &SweepCursor {
                    after: Some(attachment()),
                    seen: vec![attachment()],
                },
            )
            .path,
        },
        digests,
        content_hashes,
        sealed_chunk,
        refusals: [
            ("an attachment with no bytes", "Empty"),
            ("a file over the protocol ceiling", "TooLarge"),
            ("the server names another chunk count", "ChunkCount"),
            ("the attachment is not in the expected state", "State"),
            ("a chunk response carried no nonce header", "MissingNonce"),
            ("the attachment key is unreadable", "Key"),
            ("the chunks did not reproduce the content hash", "Integrity"),
        ]
        .iter()
        .map(|(case, refusal)| Refusal {
            case: (*case).to_string(),
            refusal: (*refusal).to_string(),
        })
        .collect(),
        sweep: Sweep {
            rows,
            referenced,
            now_secs: now,
            orphans,
        },
    };

    std::fs::create_dir_all("../sealbook-protocol/fixtures/attachments").unwrap();
    std::fs::write(
        FIXTURE,
        format!("{}\n", serde_json::to_string_pretty(&fixture).unwrap()),
    )
    .unwrap();
}
