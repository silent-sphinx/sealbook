//! Note and notebook payloads, against the fixture the three clients share.
//!
//! What is pinned here is the plaintext itself, byte for byte. Every other
//! phase has a server check behind it; this one has none, because objects are
//! sealed before they leave and the content type string is all the server ever
//! sees. The bytes are reproducible because core now writes them for all three
//! hosts: `serde_json::Map` is ordered, so one payload has one spelling.
//!
//! The cases are the ones the clients disagreed about: whether a title is
//! trimmed, what an untitled or unparsable note is listed as, whether an edit
//! keeps a field the editing host cannot show, which name an unnamed notebook
//! takes, and what happens to a payload from a newer schema major.
//!
//! Regenerate with:
//! `REGENERATE_NOTE_FIXTURE=1 cargo test -p sealbook-core --test notes -- --ignored regenerate`

use sealbook_core::*;
use serde::{Deserialize, Serialize};

const FIXTURE: &str = "../sealbook-protocol/fixtures/payloads/notes.json";

/// Fixed so the written payloads are reproducible: core takes the clock from its
/// caller and has none of its own.
const NOW: &str = "2026-10-28T12:00:00Z";

const NOTE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OTHER_NOTEBOOK: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

#[derive(Serialize, Deserialize)]
struct Fixture {
    now: String,
    constants: Constants,
    writes: Vec<WriteCase>,
    parses: Vec<ParseCase>,
    notebook_writes: Vec<NotebookWriteCase>,
    notebook_parses: Vec<NotebookParseCase>,
    refusals: Vec<RefusalCase>,
}

#[derive(Serialize, Deserialize)]
struct Constants {
    note_content_type: String,
    notebook_content_type: String,
    note_keys: Vec<String>,
    notebook_keys: Vec<String>,
    default_notebook_id: String,
    default_notebook_name: String,
    untitled_note_title: String,
    unreadable_note_title: String,
    untitled_notebook_name: String,
}

/// A draft, and the one spelling of the payload it writes.
#[derive(Serialize, Deserialize)]
struct WriteCase {
    case: String,
    draft: CoreNoteDraft,
    payload: String,
}

#[derive(Serialize, Deserialize)]
struct ParseCase {
    case: String,
    id: String,
    raw: String,
    note: CoreNote,
}

#[derive(Serialize, Deserialize)]
struct NotebookWriteCase {
    case: String,
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous: Option<String>,
    payload: String,
}

#[derive(Serialize, Deserialize)]
struct NotebookParseCase {
    case: String,
    id: String,
    raw: String,
    notebook: CoreNotebook,
}

/// The variant name, which is what the fixture pins rather than the sentence
/// each host words for itself.
#[derive(Serialize, Deserialize)]
struct RefusalCase {
    case: String,
    error: String,
}

fn fixture() -> Fixture {
    let text = std::fs::read_to_string(FIXTURE).expect("fixture");
    serde_json::from_str(&text).expect("fixture parses")
}

fn blank() -> CoreNoteDraft {
    CoreNoteDraft {
        title: String::new(),
        body: String::new(),
        notebook_id: default_notebook_id(),
        parent_id: None,
        attachments: Vec::new(),
        created_at: None,
        pinned: None,
        raw: None,
    }
}

/// A note as the web client stores one with a photo, which is the richest
/// payload any client writes.
fn stored_with_everything() -> String {
    serde_json::json!({
        "@type": "Note",
        "version": "1.0",
        "title": "Trip",
        "body": "![photo](attachment:a1)\n",
        "notebookId": OTHER_NOTEBOOK,
        "parentId": NOTE,
        "createdAt": "2026-01-01T00:00:00Z",
        "updatedAt": "2026-02-02T00:00:00Z",
        "pinned": true,
        "somethingNewer": { "from": "a later build" },
        "attachments": [{
            "id": "a1",
            "filename": "photo.jpg",
            "mimeType": "image/jpeg",
            "byteSize": 2_097_152,
            "width": 4032,
            "height": 3024,
            "adk": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            "contentHash": "ZGlnZXN0",
            "chunkSize": 4_194_304,
            "chunkCount": 1,
            "displayWidth": 480,
            "thumbnail": "data:image/jpeg;base64,/9j/",
            "caption": "also from a later build"
        }]
    })
    .to_string()
}

fn write_cases() -> Vec<(String, CoreNoteDraft)> {
    let stored = stored_with_everything();
    let parsed = note_parse(NOTE, &stored);
    vec![
        (
            "a note written from scratch".into(),
            CoreNoteDraft {
                title: "Plan".into(),
                body: "first line\nsecond line\n".into(),
                ..blank()
            },
        ),
        (
            "a title with surrounding space, and a body whose space is the user's".into(),
            CoreNoteDraft {
                title: "  Plan  ".into(),
                body: "  kept as typed  ".into(),
                ..blank()
            },
        ),
        (
            "a blank notebook resolves to the one every account has".into(),
            CoreNoteDraft {
                title: "Loose".into(),
                notebook_id: "   ".into(),
                ..blank()
            },
        ),
        (
            "a note under another note, in a notebook of its own".into(),
            CoreNoteDraft {
                title: "Child".into(),
                notebook_id: OTHER_NOTEBOOK.into(),
                parent_id: Some(NOTE.into()),
                created_at: Some("2026-01-01T00:00:00Z".into()),
                ..blank()
            },
        ),
        (
            "a host that manages pinning says so".into(),
            CoreNoteDraft {
                title: "Pinned".into(),
                pinned: Some(true),
                ..blank()
            },
        ),
        (
            "a host that does not manage pinning leaves the stored value alone".into(),
            CoreNoteDraft {
                title: parsed.title.clone(),
                body: parsed.body.clone(),
                notebook_id: parsed.notebook_id.clone(),
                parent_id: parsed.parent_id.clone(),
                attachments: parsed.attachments.clone(),
                created_at: parsed.created_at.clone(),
                pinned: None,
                raw: Some(stored.clone()),
            },
        ),
        (
            "an edit that clears the parent and the photos".into(),
            CoreNoteDraft {
                title: "Trip".into(),
                body: "no photo now\n".into(),
                notebook_id: parsed.notebook_id.clone(),
                created_at: parsed.created_at.clone(),
                raw: Some(stored),
                ..blank()
            },
        ),
    ]
}

fn parse_cases() -> Vec<(String, String, String)> {
    vec![
        (
            "the richest payload any client writes".into(),
            NOTE.into(),
            stored_with_everything(),
        ),
        ("an empty object".into(), NOTE.into(), "{}".into()),
        (
            "a title that is only space".into(),
            NOTE.into(),
            r#"{"title":"   "}"#.into(),
        ),
        (
            "a payload that is not JSON at all".into(),
            NOTE.into(),
            "this was never a note".into(),
        ),
        (
            "a payload that is JSON but not an object".into(),
            NOTE.into(),
            "[1,2,3]".into(),
        ),
        (
            "a body that is not a string".into(),
            NOTE.into(),
            r#"{"title":"t","body":42}"#.into(),
        ),
        (
            "an attachment entry that cannot name its own bytes".into(),
            NOTE.into(),
            serde_json::json!({
                "title": "t",
                "attachments": [
                    { "id": "a1", "filename": "half.jpg" },
                    {
                        "id": "a2",
                        "filename": "whole.jpg",
                        "mimeType": "image/jpeg",
                        "byteSize": 10,
                        "adk": "QUJD",
                        "contentHash": "REVG",
                        "chunkSize": 4_194_304,
                        "chunkCount": 1
                    }
                ]
            })
            .to_string(),
        ),
        (
            "a payload from a newer schema major".into(),
            NOTE.into(),
            r#"{"@type":"Note","version":"2.0","title":"future"}"#.into(),
        ),
    ]
}

fn notebook_write_cases() -> Vec<(String, String, Option<String>)> {
    vec![
        (
            "a notebook created from scratch".into(),
            "Work".into(),
            None,
        ),
        (
            "a name with surrounding space".into(),
            "  Work  ".into(),
            None,
        ),
        (
            "a rename that keeps what this build does not own".into(),
            "Renamed".into(),
            Some(r#"{"@type":"Notebook","version":"1.0","name":"Work","colour":"amber"}"#.into()),
        ),
    ]
}

fn notebook_parse_cases() -> Vec<(String, String, String)> {
    vec![
        (
            "a named notebook".into(),
            OTHER_NOTEBOOK.into(),
            r#"{"@type":"Notebook","version":"1.0","name":"  Work  "}"#.into(),
        ),
        (
            "the default notebook, unnamed".into(),
            default_notebook_id(),
            "{}".into(),
        ),
        (
            "any other notebook, unnamed".into(),
            OTHER_NOTEBOOK.into(),
            "not json".into(),
        ),
    ]
}

fn error_name(error: &CoreError) -> String {
    error.kind().to_string()
}

#[test]
fn every_written_payload_is_the_one_spelling_the_fixture_holds() {
    let fixture = fixture();
    assert_eq!(
        fixture.now, NOW,
        "the fixture was built under another clock"
    );
    assert_eq!(fixture.writes.len(), write_cases().len());
    for (expected, (case, draft)) in fixture.writes.iter().zip(write_cases()) {
        assert_eq!(expected.case, case);
        assert_eq!(expected.draft, draft, "{case}: the draft drifted");
        assert_eq!(
            note_write(&draft, NOW).expect("writes"),
            expected.payload,
            "{case}"
        );
    }
}

#[test]
fn every_payload_reads_back_as_the_record_the_fixture_holds() {
    for (expected, (case, id, raw)) in fixture().parses.iter().zip(parse_cases()) {
        assert_eq!(expected.case, case);
        assert_eq!(expected.raw, raw, "{case}: the input drifted");
        assert_eq!(note_parse(&id, &raw), expected.note, "{case}");
    }
}

#[test]
fn every_notebook_payload_is_the_one_spelling_the_fixture_holds() {
    for (expected, (case, name, previous)) in
        fixture().notebook_writes.iter().zip(notebook_write_cases())
    {
        assert_eq!(expected.case, case);
        assert_eq!(
            notebook_write(&name, previous.as_deref()).expect("writes"),
            expected.payload,
            "{case}"
        );
    }
}

#[test]
fn every_notebook_reads_back_as_the_record_the_fixture_holds() {
    for (expected, (case, id, raw)) in fixture().notebook_parses.iter().zip(notebook_parse_cases())
    {
        assert_eq!(expected.case, case);
        assert_eq!(notebook_parse(&id, &raw), expected.notebook, "{case}");
    }
}

#[test]
fn the_fixture_states_the_constants_the_three_hosts_mirror() {
    let constants = fixture().constants;
    assert_eq!(constants.note_content_type, NOTE_CONTENT_TYPE);
    assert_eq!(constants.notebook_content_type, NOTEBOOK_CONTENT_TYPE);
    assert_eq!(constants.note_keys, NOTE_KEYS);
    assert_eq!(constants.notebook_keys, NOTEBOOK_KEYS);
    assert_eq!(constants.default_notebook_id, default_notebook_id());
    assert_eq!(constants.default_notebook_name, DEFAULT_NOTEBOOK_NAME);
    assert_eq!(constants.untitled_note_title, UNTITLED_NOTE_TITLE);
    assert_eq!(constants.unreadable_note_title, UNREADABLE_NOTE_TITLE);
    assert_eq!(constants.untitled_notebook_name, UNTITLED_NOTEBOOK_NAME);
}

/// The one refusal this layer has, and the reason the version check now has a
/// caller: three clients each carried a copy of it and none of them ran it.
#[test]
fn a_payload_from_a_newer_schema_major_is_read_but_never_written_over() {
    let refusals = fixture().refusals;
    let future = r#"{"@type":"Note","version":"2.0","title":"future"}"#;

    let note = note_parse(NOTE, future);
    assert_eq!(note.title, "future");
    assert!(!note.readable);

    let refused = note_write(
        &CoreNoteDraft {
            title: "edited".into(),
            raw: Some(future.into()),
            ..blank()
        },
        NOW,
    )
    .expect_err("refuses");
    assert_eq!(error_name(&refused), refusals[0].error);

    let notebook = r#"{"@type":"Notebook","version":"3.1","name":"future"}"#;
    assert!(!notebook_parse(&default_notebook_id(), notebook).readable);
    let refused = notebook_write("edited", Some(notebook)).expect_err("refuses");
    assert_eq!(error_name(&refused), refusals[1].error);
}

/// A notebook id a note points at that is not in the list, which is what a
/// deleted notebook leaves behind.
#[test]
fn a_note_whose_notebook_is_gone_is_shown_under_the_default_notebooks_name() {
    let notebooks = vec![notebook_parse(&default_notebook_id(), r#"{"name":"Mine"}"#)];
    assert_eq!(notebook_name_by_id(&notebooks, None), "Mine");
    assert_eq!(
        notebook_name_by_id(&notebooks, Some(default_notebook_id())),
        "Mine"
    );
    assert_eq!(
        notebook_name_by_id(&notebooks, Some(OTHER_NOTEBOOK.into())),
        DEFAULT_NOTEBOOK_NAME
    );
}

#[test]
#[ignore = "writes the shared fixture"]
fn regenerate() {
    if std::env::var("REGENERATE_NOTE_FIXTURE").is_err() {
        return;
    }
    let fixture = Fixture {
        now: NOW.into(),
        constants: Constants {
            note_content_type: NOTE_CONTENT_TYPE.into(),
            notebook_content_type: NOTEBOOK_CONTENT_TYPE.into(),
            note_keys: NOTE_KEYS.iter().map(|key| key.to_string()).collect(),
            notebook_keys: NOTEBOOK_KEYS.iter().map(|key| key.to_string()).collect(),
            default_notebook_id: default_notebook_id(),
            default_notebook_name: DEFAULT_NOTEBOOK_NAME.into(),
            untitled_note_title: UNTITLED_NOTE_TITLE.into(),
            unreadable_note_title: UNREADABLE_NOTE_TITLE.into(),
            untitled_notebook_name: UNTITLED_NOTEBOOK_NAME.into(),
        },
        writes: write_cases()
            .into_iter()
            .map(|(case, draft)| WriteCase {
                case,
                payload: note_write(&draft, NOW).expect("writes"),
                draft,
            })
            .collect(),
        parses: parse_cases()
            .into_iter()
            .map(|(case, id, raw)| ParseCase {
                case,
                note: note_parse(&id, &raw),
                id,
                raw,
            })
            .collect(),
        notebook_writes: notebook_write_cases()
            .into_iter()
            .map(|(case, name, previous)| NotebookWriteCase {
                case,
                payload: notebook_write(&name, previous.as_deref()).expect("writes"),
                name,
                previous,
            })
            .collect(),
        notebook_parses: notebook_parse_cases()
            .into_iter()
            .map(|(case, id, raw)| NotebookParseCase {
                case,
                notebook: notebook_parse(&id, &raw),
                id,
                raw,
            })
            .collect(),
        refusals: vec![
            RefusalCase {
                case: "editing a note from a newer schema major".into(),
                error: "PayloadSchema".into(),
            },
            RefusalCase {
                case: "renaming a notebook from a newer schema major".into(),
                error: "PayloadSchema".into(),
            },
        ],
    };

    std::fs::create_dir_all("../sealbook-protocol/fixtures/payloads").unwrap();
    std::fs::write(
        FIXTURE,
        format!("{}\n", serde_json::to_string_pretty(&fixture).unwrap()),
    )
    .unwrap();
}
