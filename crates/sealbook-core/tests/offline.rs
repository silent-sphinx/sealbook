//! The outbox, the three-way merge and the flush plan, against the fixture the
//! clients share.
//!
//! Each case holds its inputs and the exact output core gives for them, so a
//! host checks itself by calling its binding on the inputs and comparing.
//!
//! Regenerate with:
//! `REGENERATE_OFFLINE_FIXTURE=1 cargo test -p sealbook-core --test offline -- --ignored regenerate`

use sealbook_core::*;
use sealbook_crypto::CollectionKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const FIXTURE: &str = "../sealbook-protocol/fixtures/offline/offline.json";

const DATE: &str = "2026-11-03";
/// The collection key conflict-copy ids are derived under: 32 bytes of 9.
const COLLECTION_KEY: &str = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk";
const QUEUED_AT: &str = "2026-11-03T09:00:00.000Z";

const NOTE_A: &str = "0a6f4c1e-1b2c-4d3e-8f40-000000000001";
const NOTE_B: &str = "0a6f4c1e-1b2c-4d3e-8f40-000000000002";
const NOTE_C: &str = "0a6f4c1e-1b2c-4d3e-8f40-000000000003";
const NOTEBOOK: &str = "0a6f4c1e-1b2c-4d3e-8f40-000000000010";

#[derive(Serialize, Deserialize)]
struct Fixture {
    date: String,
    collection_key: String,
    outbox: Vec<OutboxCase>,
    merge: Vec<MergeCase>,
    flush: Vec<FlushCase>,
    settle: Vec<SettleCase>,
    batch: Vec<BatchCase>,
}

#[derive(Serialize, Deserialize)]
struct OutboxCase {
    case: String,
    vault: LocalVault,
    pushes: Vec<PendingWrite>,
    outbox: Outbox,
    view: Vec<LocalObject>,
}

#[derive(Serialize, Deserialize)]
struct MergeCase {
    case: String,
    content_type: String,
    base: Option<String>,
    local: String,
    remote: String,
    outcome: MergeOutcome,
}

#[derive(Serialize, Deserialize)]
struct FlushCase {
    case: String,
    vault: LocalVault,
    outbox: Outbox,
    plan: FlushPlan,
}

/// A flush that planned `planned`, sent the writes for `ids`, and found the outbox
/// as `current` by the time they were taken.
#[derive(Serialize, Deserialize)]
struct SettleCase {
    case: String,
    current: Outbox,
    planned: Outbox,
    vault: LocalVault,
    ids: Vec<String>,
    outbox: Outbox,
}

#[derive(Serialize, Deserialize)]
struct BatchCase {
    case: String,
    writes: Vec<FlushWrite>,
    len: u32,
}

fn object(id: &str, content_type: &str, revision: u64, payload: &Value) -> LocalObject {
    LocalObject {
        id: id.into(),
        content_type: content_type.into(),
        revision,
        tombstone: false,
        payload: payload.to_string(),
    }
}

fn deleted(id: &str, content_type: &str, revision: u64) -> LocalObject {
    LocalObject {
        id: id.into(),
        content_type: content_type.into(),
        revision,
        tombstone: true,
        payload: String::new(),
    }
}

fn edit(base: Option<LocalObject>, id: &str, content_type: &str, payload: &Value) -> PendingWrite {
    PendingWrite {
        id: id.into(),
        content_type: content_type.into(),
        tombstone: false,
        payload: payload.to_string(),
        base,
        queued_at: QUEUED_AT.into(),
    }
}

fn delete(base: Option<LocalObject>, id: &str, content_type: &str) -> PendingWrite {
    PendingWrite {
        tombstone: true,
        payload: String::new(),
        ..edit(base, id, content_type, &Value::Null)
    }
}

fn vault(revision: u64, objects: Vec<LocalObject>) -> LocalVault {
    LocalVault {
        version: LOCAL_VAULT_VERSION,
        latest_revision: revision,
        key_epoch: 1,
        objects,
    }
}

fn note(title: &str, body: &str) -> Value {
    json!({
        "@type": "Note",
        "version": "1.0",
        "title": title,
        "body": body,
        "notebookId": NOTEBOOK,
        "createdAt": "2026-11-01T08:00:00.000Z",
        "updatedAt": "2026-11-01T08:00:00.000Z",
    })
}

fn with(mut value: Value, key: &str, field: Value) -> Value {
    value[key] = field;
    value
}

fn photo(id: &str) -> Value {
    json!({
        "id": id, "filename": format!("{id}.jpg"), "mimeType": "image/jpeg", "byteSize": 10,
        "adk": "k", "contentHash": "h", "chunkSize": 10, "chunkCount": 1,
    })
}

fn outbox_inputs() -> Vec<(String, LocalVault, Vec<PendingWrite>)> {
    let base = object(NOTE_A, NOTE_CONTENT_TYPE, 4, &note("Plan", "a"));
    let other = object(NOTE_B, NOTE_CONTENT_TYPE, 5, &note("Other", "b"));
    let stored = vault(5, vec![base.clone(), other.clone()]);
    let first = edit(
        Some(base.clone()),
        NOTE_A,
        NOTE_CONTENT_TYPE,
        &note("Plan v2", "a"),
    );
    let second = edit(
        Some(object(NOTE_A, NOTE_CONTENT_TYPE, 4, &note("Plan v2", "a"))),
        NOTE_A,
        NOTE_CONTENT_TYPE,
        &note("Plan v3", "a"),
    );
    let created = edit(None, NOTE_C, NOTE_CONTENT_TYPE, &note("New", ""));
    vec![
        (
            "a second edit keeps the first base and the first place".into(),
            stored.clone(),
            vec![first, created.clone(), second],
        ),
        (
            "deleting an unsent create leaves nothing queued".into(),
            stored.clone(),
            vec![created, delete(None, NOTE_C, NOTE_CONTENT_TYPE)],
        ),
        (
            "a queued delete hides the object".into(),
            stored,
            vec![delete(Some(other), NOTE_B, NOTE_CONTENT_TYPE)],
        ),
    ]
}

fn merge_inputs() -> Vec<(String, &'static str, Option<Value>, Value, Value)> {
    let base = note("Plan", "one\ntwo\nthree\nfour");
    let edited = |value: Value, at: &str| with(value, "updatedAt", json!(at));
    let local_at = "2026-11-02T10:00:00.000Z";
    let remote_at = "2026-11-02T11:00:00.000Z";
    let contact = json!({"@type": "Card", "version": "1.0", "name": {"full": "Ada Lovelace"}});
    let settings = json!({
        "@type": "Settings", "version": "1.0", "accent": "blue", "contactMode": "basic",
        "features": ["contacts", "notes"],
    });
    let notebook = json!({"@type": "Notebook", "version": "1.0", "name": "Work"});
    vec![
        (
            "different fields changed on each side both land".into(),
            NOTE_CONTENT_TYPE,
            Some(base.clone()),
            edited(with(base.clone(), "title", json!("Plan A")), local_at),
            edited(
                with(base.clone(), "notebookId", json!("elsewhere")),
                remote_at,
            ),
        ),
        (
            "body edits on different lines merge".into(),
            NOTE_CONTENT_TYPE,
            Some(base.clone()),
            edited(
                with(base.clone(), "body", json!("ONE\ntwo\nthree\nfour")),
                local_at,
            ),
            edited(
                with(base.clone(), "body", json!("one\ntwo\nthree\nFOUR")),
                remote_at,
            ),
        ),
        (
            "the same line changed two ways is a conflicted copy".into(),
            NOTE_CONTENT_TYPE,
            Some(base.clone()),
            edited(
                with(base.clone(), "body", json!("one\nTWO\nthree\nfour")),
                local_at,
            ),
            edited(
                with(base.clone(), "body", json!("one\n2\nthree\nfour")),
                remote_at,
            ),
        ),
        (
            "a title conflict makes a copy even when the body merges".into(),
            NOTE_CONTENT_TYPE,
            Some(base.clone()),
            with(
                with(base.clone(), "title", json!("Plan A")),
                "body",
                json!("ONE\ntwo\nthree\nfour"),
            ),
            with(
                with(base.clone(), "title", json!("Plan B")),
                "body",
                json!("one\ntwo\nthree\nFOUR"),
            ),
        ),
        (
            "the same edit on both sides needs nothing".into(),
            NOTE_CONTENT_TYPE,
            Some(base.clone()),
            with(base.clone(), "title", json!("Same")),
            with(base.clone(), "title", json!("Same")),
        ),
        (
            "a key this build does not know survives".into(),
            NOTE_CONTENT_TYPE,
            Some(base.clone()),
            with(base.clone(), "x-future", json!({"kept": true})),
            with(base.clone(), "title", json!("Renamed")),
        ),
        (
            "a photo removed on either side stays removed, an added one is kept".into(),
            NOTE_CONTENT_TYPE,
            Some(with(
                base.clone(),
                "attachments",
                json!([photo("p1"), photo("p2")]),
            )),
            with(
                base.clone(),
                "attachments",
                json!([photo("p1"), photo("p2"), photo("p3")]),
            ),
            with(base.clone(), "attachments", json!([photo("p2")])),
        ),
        (
            "a contact's conflicted copy is renamed in name.full".into(),
            JSCONTACT_CONTENT_TYPE,
            Some(contact.clone()),
            with(contact.clone(), "name", json!({"full": "Ada King"})),
            with(contact.clone(), "name", json!({"full": "Augusta Ada"})),
        ),
        (
            "a container conflict keeps this device's value".into(),
            NOTEBOOK_CONTENT_TYPE,
            Some(notebook.clone()),
            with(notebook.clone(), "name", json!("Work (old)")),
            with(notebook.clone(), "name", json!("Office")),
        ),
        (
            "settings created on two devices merge per key, this device winning".into(),
            ACCOUNT_SETTINGS_CONTENT_TYPE,
            None,
            with(settings.clone(), "accent", json!("rose")),
            with(
                with(settings.clone(), "accent", json!("green")),
                "contactMode",
                json!("detailed"),
            ),
        ),
        (
            "an edit that removes a key keeps it removed".into(),
            TASK_CONTENT_TYPE,
            Some(json!({"@type": "Task", "title": "Call", "notes": "x", "dueDate": "2026-11-05"})),
            json!({"@type": "Task", "title": "Call", "notes": "x"}),
            json!({"@type": "Task", "title": "Call", "notes": "x\ny", "dueDate": "2026-11-05"}),
        ),
        (
            "the later updatedAt wins without a conflict".into(),
            BOOKMARK_CONTENT_TYPE,
            Some(
                json!({"@type": "Bookmark", "url": "https://a.example", "updatedAt": "2026-11-01T00:00:00.000Z"}),
            ),
            json!({"@type": "Bookmark", "url": "https://a.example", "updatedAt": "2026-11-03T00:00:00.000Z"}),
            json!({"@type": "Bookmark", "url": "https://a.example", "title": "A", "updatedAt": "2026-11-02T00:00:00.000Z"}),
        ),
    ]
}

fn flush_inputs() -> Vec<(String, LocalVault, Vec<PendingWrite>)> {
    let base = object(NOTE_A, NOTE_CONTENT_TYPE, 4, &note("Plan", "one\ntwo"));
    let local = note("Plan", "one\nTWO");
    let ahead = |payload: &Value| object(NOTE_A, NOTE_CONTENT_TYPE, 9, payload);
    let notebook = json!({"@type": "Notebook", "version": "1.0", "name": "Trip"});
    vec![
        (
            "an unchanged object is written over its revision".into(),
            vault(9, vec![base.clone()]),
            (vec![edit(Some(base.clone()), NOTE_A, NOTE_CONTENT_TYPE, &local)]),
        ),
        (
            "a create expects nothing there".into(),
            vault(9, vec![]),
            (vec![edit(None, NOTE_C, NOTE_CONTENT_TYPE, &note("New", ""))]),
        ),
        (
            "a remote change to another field is merged in".into(),
            vault(9, vec![ahead(&note("Plan (renamed)", "one\ntwo"))]),
            (vec![edit(Some(base.clone()), NOTE_A, NOTE_CONTENT_TYPE, &local)]),
        ),
        (
            "a remote change to the same line writes a copy".into(),
            vault(9, vec![ahead(&note("Plan", "one\n2"))]),
            (vec![edit(Some(base.clone()), NOTE_A, NOTE_CONTENT_TYPE, &local)]),
        ),
        (
            "an edit to an object deleted elsewhere brings it back".into(),
            vault(9, vec![deleted(NOTE_A, NOTE_CONTENT_TYPE, 9)]),
            (vec![edit(Some(base.clone()), NOTE_A, NOTE_CONTENT_TYPE, &local)]),
        ),
        (
            "a delete of an object changed elsewhere is dropped".into(),
            vault(9, vec![ahead(&note("Plan", "one\n2"))]),
            (vec![delete(Some(base.clone()), NOTE_A, NOTE_CONTENT_TYPE)]),
        ),
        (
            "a delete of an object deleted elsewhere needs nothing".into(),
            vault(9, vec![deleted(NOTE_A, NOTE_CONTENT_TYPE, 9)]),
            (vec![delete(Some(base.clone()), NOTE_A, NOTE_CONTENT_TYPE)]),
        ),
        (
            "an edit already on the server is dropped".into(),
            vault(9, vec![ahead(&local)]),
            (vec![edit(Some(base.clone()), NOTE_A, NOTE_CONTENT_TYPE, &local)]),
        ),
        (
            "a renamed notebook deleted elsewhere comes back before the note created in it".into(),
            vault(
                9,
                vec![deleted(NOTEBOOK, NOTEBOOK_CONTENT_TYPE, 9), base.clone()],
            ),
            (vec![
                edit(
                    Some(object(NOTEBOOK, NOTEBOOK_CONTENT_TYPE, 3, &notebook)),
                    NOTEBOOK,
                    NOTEBOOK_CONTENT_TYPE,
                    &with(notebook.clone(), "name", json!("Trip 2026")),
                ),
                edit(None, NOTE_B, NOTE_CONTENT_TYPE, &note("Packing", "")),
            ]),
        ),
    ]
}

fn outbox_of(writes: Vec<PendingWrite>) -> Outbox {
    Outbox {
        version: OUTBOX_VERSION,
        writes,
        failed: Vec::new(),
    }
}

fn settle_inputs() -> Vec<(String, Outbox, Outbox, LocalVault, Vec<String>)> {
    let base = object(NOTE_A, NOTE_CONTENT_TYPE, 4, &note("Plan", "a"));
    let sent = object(NOTE_A, NOTE_CONTENT_TYPE, 9, &note("Plan v2", "a"));
    let planned = outbox_of(vec![
        edit(
            Some(base.clone()),
            NOTE_A,
            NOTE_CONTENT_TYPE,
            &note("Plan v2", "a"),
        ),
        edit(None, NOTE_C, NOTE_CONTENT_TYPE, &note("New", "")),
    ]);
    let after_send = vault(9, vec![sent.clone()]);
    let ids = |ids: &[&str]| ids.iter().map(|id| id.to_string()).collect::<Vec<_>>();
    // A refused version of a note that was edited and queued again, then sent.
    let mut with_failed = planned.clone();
    with_failed.failed.push(FailedWrite {
        write: edit(None, NOTE_A, NOTE_CONTENT_TYPE, &note("Refused", "")),
        reason: "too large".into(),
    });
    vec![
        (
            "writes that were not edited again are taken out".into(),
            planned.clone(),
            planned.clone(),
            after_send.clone(),
            ids(&[NOTE_A, NOTE_C]),
        ),
        (
            "a write edited again in flight stays, rebased on what the server now holds".into(),
            outbox_of(vec![
                edit(
                    Some(base.clone()),
                    NOTE_A,
                    NOTE_CONTENT_TYPE,
                    &note("Plan v3", "a"),
                ),
                planned.writes[1].clone(),
            ]),
            planned.clone(),
            after_send.clone(),
            ids(&[NOTE_A, NOTE_C]),
        ),
        (
            "a write edited again in flight has no base when the server holds none".into(),
            outbox_of(vec![
                planned.writes[0].clone(),
                edit(None, NOTE_C, NOTE_CONTENT_TYPE, &note("New, renamed", "")),
            ]),
            planned.clone(),
            vault(9, vec![deleted(NOTE_C, NOTE_CONTENT_TYPE, 9), sent.clone()]),
            ids(&[NOTE_A, NOTE_C]),
        ),
        (
            "a delete queued over a sent edit stays".into(),
            outbox_of(vec![delete(Some(base.clone()), NOTE_A, NOTE_CONTENT_TYPE)]),
            outbox_of(vec![planned.writes[0].clone()]),
            after_send.clone(),
            ids(&[NOTE_A]),
        ),
        (
            "a write outside the settled ids stays, edited or not".into(),
            planned.clone(),
            planned.clone(),
            after_send.clone(),
            ids(&[NOTE_A]),
        ),
        (
            "a write queued after the plan is left alone".into(),
            outbox_of(vec![
                planned.writes[0].clone(),
                edit(None, NOTE_B, NOTE_CONTENT_TYPE, &note("Later", "")),
            ]),
            outbox_of(vec![planned.writes[0].clone()]),
            after_send.clone(),
            ids(&[NOTE_A, NOTE_B]),
        ),
        (
            "a failed entry for a settled id goes with it, one for another id stays".into(),
            {
                let mut other = with_failed.clone();
                other.failed.push(FailedWrite {
                    write: edit(None, NOTE_B, NOTE_CONTENT_TYPE, &note("Refused too", "")),
                    reason: "too large".into(),
                });
                other
            },
            planned,
            after_send,
            ids(&[NOTE_A, NOTE_C]),
        ),
    ]
}

fn flush_write(settles: &str, id: &str, payload: &str) -> FlushWrite {
    FlushWrite {
        id: id.into(),
        content_type: NOTE_CONTENT_TYPE.into(),
        tombstone: false,
        payload: payload.into(),
        expect_revision: None,
        settles: settles.into(),
        copy: false,
        notice: None,
    }
}

fn batch_inputs() -> Vec<(String, Vec<FlushWrite>)> {
    let pair = vec![
        flush_write(NOTE_A, NOTE_A, "merged"),
        FlushWrite {
            copy: true,
            ..flush_write(NOTE_A, NOTE_B, "copy")
        },
    ];
    vec![
        ("nothing queued is an empty batch".into(), vec![]),
        (
            "small writes go together".into(),
            vec![
                flush_write(NOTE_A, NOTE_A, "a"),
                flush_write(NOTE_B, NOTE_B, "b"),
                flush_write(NOTE_C, NOTE_C, "c"),
            ],
        ),
        (
            "a conflict's merged write and copy stay together".into(),
            pair,
        ),
    ]
}

fn key() -> CollectionKey {
    CollectionKey::from_bytes([9; 32])
}

fn build() -> Fixture {
    Fixture {
        date: DATE.into(),
        collection_key: COLLECTION_KEY.into(),
        outbox: outbox_inputs()
            .into_iter()
            .map(|(case, vault, pushes)| {
                let outbox = pushes.iter().fold(Outbox::default(), |outbox, write| {
                    outbox_push(&outbox, write.clone())
                });
                let view = local_view(&vault, &outbox);
                OutboxCase {
                    case,
                    vault,
                    pushes,
                    outbox,
                    view,
                }
            })
            .collect(),
        merge: merge_inputs()
            .into_iter()
            .map(|(case, content_type, base, local, remote)| {
                let base = base.map(|base| base.to_string());
                let (local, remote) = (local.to_string(), remote.to_string());
                let outcome = merge_payload(content_type, base.as_deref(), &local, &remote, DATE);
                MergeCase {
                    case,
                    content_type: content_type.into(),
                    base,
                    local,
                    remote,
                    outcome,
                }
            })
            .collect(),
        flush: flush_inputs()
            .into_iter()
            .map(|(case, vault, writes)| {
                let outbox = Outbox {
                    version: OUTBOX_VERSION,
                    writes,
                    failed: Vec::new(),
                };
                let plan = flush_plan(&outbox, &vault, DATE, &key());
                FlushCase {
                    case,
                    vault,
                    outbox,
                    plan,
                }
            })
            .collect(),
        settle: settle_inputs()
            .into_iter()
            .map(|(case, current, planned, vault, ids)| {
                let outbox = outbox_settle_sent(&current, &planned, &vault, &ids);
                SettleCase {
                    case,
                    current,
                    planned,
                    vault,
                    ids,
                    outbox,
                }
            })
            .collect(),
        batch: batch_inputs()
            .into_iter()
            .map(|(case, writes)| {
                let len = flush_batch_len(&writes);
                BatchCase { case, writes, len }
            })
            .collect(),
    }
}

fn fixture() -> Fixture {
    let text = std::fs::read_to_string(FIXTURE).expect("fixture");
    serde_json::from_str(&text).expect("fixture parses")
}

#[test]
fn the_outbox_combines_and_overlays_as_the_fixture_holds() {
    for case in fixture().outbox {
        let outbox = case.pushes.iter().fold(Outbox::default(), |outbox, write| {
            outbox_push(&outbox, write.clone())
        });
        assert_eq!(outbox, case.outbox, "{}", case.case);
        assert_eq!(local_view(&case.vault, &outbox), case.view, "{}", case.case);
        assert_eq!(outbox_read(&outbox_write(&outbox)).unwrap(), outbox);
        assert_eq!(
            local_vault_read(&local_vault_write(&case.vault)).unwrap(),
            case.vault
        );
    }
}

#[test]
fn every_merge_gives_what_the_fixture_holds() {
    let fixture = fixture();
    for case in fixture.merge {
        let outcome = merge_payload(
            &case.content_type,
            case.base.as_deref(),
            &case.local,
            &case.remote,
            &fixture.date,
        );
        assert_eq!(outcome, case.outcome, "{}", case.case);
    }
}

#[test]
fn every_flush_plans_what_the_fixture_holds() {
    let fixture = fixture();
    for case in fixture.flush {
        let plan = flush_plan(&case.outbox, &case.vault, &fixture.date, &key());
        assert_eq!(plan, case.plan, "{}", case.case);
    }
}

#[test]
fn every_settle_leaves_what_the_fixture_holds() {
    for case in fixture().settle {
        let outbox = outbox_settle_sent(&case.current, &case.planned, &case.vault, &case.ids);
        assert_eq!(outbox, case.outbox, "{}", case.case);
    }
}

#[test]
fn every_batch_takes_what_the_fixture_holds() {
    for case in fixture().batch {
        assert_eq!(flush_batch_len(&case.writes), case.len, "{}", case.case);
    }
}

/// Spelled out rather than read from the fixture, so a wrong fixture cannot
/// make a wrong rule pass.
#[test]
fn the_settle_rules_hold_independent_of_the_fixture() {
    let cases = settle_inputs();
    let result = |at: usize| {
        let (_, current, planned, vault, ids) = &cases[at];
        outbox_settle_sent(current, planned, vault, ids)
    };
    assert!(result(0).writes.is_empty());

    let rebased = result(1);
    assert_eq!(rebased.writes.len(), 1);
    assert_eq!(rebased.writes[0].id, NOTE_A);
    assert_eq!(rebased.writes[0].base.as_ref().unwrap().revision, 9);

    let none_held = result(2);
    assert_eq!(none_held.writes.len(), 1);
    assert_eq!(none_held.writes[0].id, NOTE_C);
    assert_eq!(none_held.writes[0].base, None);

    assert_eq!(result(3).writes.len(), 1);
    assert!(result(3).writes[0].tombstone);
    assert_eq!(result(4).writes.len(), 1);
    assert_eq!(result(4).writes[0].id, NOTE_C);
    assert_eq!(result(5).writes.len(), 1);
    assert_eq!(result(5).writes[0].id, NOTE_B);
    let last = result(6);
    assert!(last.writes.is_empty());
    assert_eq!(last.failed.len(), 1);
    assert_eq!(last.failed[0].write.id, NOTE_B);
}

#[test]
fn the_fixture_is_what_core_gives_today() {
    let fixture = fixture();
    let built = build();
    assert_eq!(
        serde_json::to_value(&built).unwrap(),
        serde_json::to_value(&fixture).unwrap(),
        "regenerate the offline fixture"
    );
}

#[test]
fn a_merged_payload_is_what_the_next_merge_reads_as_the_same() {
    for case in fixture().merge {
        let written = match &case.outcome {
            MergeOutcome::Merged { payload, .. } => payload.clone(),
            MergeOutcome::Conflict {
                payload: Some(payload),
                ..
            } => payload.clone(),
            _ => continue,
        };
        let again = merge_payload(
            &case.content_type,
            case.base.as_deref(),
            &case.local,
            &written,
            DATE,
        );
        assert!(
            !matches!(
                again,
                MergeOutcome::Merged {
                    overwrote: false,
                    ..
                }
            ),
            "{}: merging onto the merged payload changed it again",
            case.case
        );
    }
}

#[test]
#[ignore]
fn regenerate() {
    if std::env::var("REGENERATE_OFFLINE_FIXTURE").is_err() {
        return;
    }
    std::fs::create_dir_all("../sealbook-protocol/fixtures/offline").unwrap();
    std::fs::write(
        FIXTURE,
        format!("{}\n", serde_json::to_string_pretty(&build()).unwrap()),
    )
    .unwrap();
}
