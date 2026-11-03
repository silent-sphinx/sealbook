//! The export file schema against what the writers produce: the account export
//! fixtures, the notes JSON backup and the task export.
//!
//! Run `REGENERATE_SCHEMA=1 cargo test -p sealbook-core -- --ignored
//! regenerate` to rewrite it after a deliberate format change.

use sealbook_core::schema::file_schema;
use sealbook_core::*;
use serde_json::Value;

const SCHEMA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../sealbook-protocol/schema/files.json"
);
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../sealbook-protocol/fixtures");

fn built() -> String {
    serde_json::to_string_pretty(&file_schema()).unwrap() + "\n"
}

#[test]
#[ignore = "writes the checked-in schema; run with REGENERATE_SCHEMA=1"]
fn regenerate_the_file_schema() {
    assert!(
        std::env::var("REGENERATE_SCHEMA").is_ok(),
        "set REGENERATE_SCHEMA=1 to confirm overwriting the checked-in schema"
    );
    std::fs::write(SCHEMA, built()).unwrap();
}

#[test]
fn the_checked_in_file_schema_is_what_core_builds() {
    let stored = std::fs::read_to_string(SCHEMA).unwrap_or_default();
    assert!(
        stored == built(),
        "schema/files.json is stale; regenerate it: REGENERATE_SCHEMA=1"
    );
}

fn validator(type_name: &str) -> jsonschema::Validator {
    let mut schema = file_schema();
    assert!(schema["$defs"].get(type_name).is_some(), "no {type_name}");
    schema["$ref"] = format!("#/$defs/{type_name}").into();
    jsonschema::validator_for(&schema).expect("the file schema compiles")
}

fn errors(type_name: &str, document: &Value) -> Vec<String> {
    validator(type_name)
        .iter_errors(document)
        .map(|error| format!("{error} at {}", error.instance_path()))
        .collect()
}

fn read(name: &str) -> Value {
    let path = format!("{FIXTURES}/{name}");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    serde_json::from_str(&text).expect("a fixture must be JSON")
}

#[test]
fn every_written_account_export_meets_the_schema() {
    let fixture = read("payloads/account_export.json");
    let writes = fixture["writes"].as_array().expect("a writes table");
    assert!(writes.len() >= 8, "{} writes", writes.len());
    let mut documents: Vec<(String, Value)> = writes
        .iter()
        .map(|row| {
            let document = row["document"].as_str().expect("a written document");
            (
                row["name"].as_str().unwrap_or_default().to_string(),
                serde_json::from_str(document).expect("a written document is JSON"),
            )
        })
        .collect();
    documents.push((
        "v1.0.0-account-export.json".into(),
        read("v1.0.0-account-export.json"),
    ));
    let failures: Vec<String> = documents
        .iter()
        .filter_map(|(name, document)| {
            let errors = errors("AccountExport", document);
            (!errors.is_empty()).then(|| format!("{name}: {errors:?}"))
        })
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_notes_backup_meets_the_schema() {
    let notebooks = vec![CoreNotebook {
        id: default_notebook_id(),
        name: "Journal".into(),
        readable: true,
        raw: String::new(),
    }];
    let plain = CoreNoteFileEntry {
        title: "Plain".into(),
        body: "text".into(),
        notebook_id: default_notebook_id(),
        ..CoreNoteFileEntry::default()
    };
    let full = CoreNoteFileEntry {
        title: "Full".into(),
        pinned: Some(true),
        created_at: Some("2026-10-01T09:00:00.000Z".into()),
        updated_at: Some("2026-10-02T09:00:00.000Z".into()),
        ..plain.clone()
    };
    let unfiled = CoreNoteFileEntry {
        notebook_id: "00000000-0000-4000-8000-0000000000ff".into(),
        pinned: Some(false),
        ..plain.clone()
    };
    for notes in [vec![], vec![plain, full, unfiled]] {
        let text = notes_write_json(&notes, &notebooks, "2026-10-30T00:00:00Z");
        let document: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(errors("NotesExport", &document), Vec::<String>::new());
    }
}

#[test]
fn a_task_export_meets_the_schema() {
    let lists = vec![task_list_parse(
        &default_task_list_id(),
        r#"{"name":"Inbox","color":"blue"}"#,
    )];
    let tasks = vec![
        task_parse("p", r#"{"title":"Plain"}"#),
        task_parse(
            "c",
            r#"{"title":"Full","parentId":"p","dueDate":"2026-11-02","priority":2,
                "tags":["home"],"recurrence":{"frequency":"weekly"},"done":true}"#,
        ),
    ];
    for tasks in [vec![], tasks] {
        let document: Value =
            serde_json::from_str(&task_export(&tasks, &lists, "2026-11-02T00:00:00Z")).unwrap();
        assert_eq!(errors("TasksExport", &document), Vec::<String>::new());
    }
}

#[test]
fn the_schema_refuses_what_no_writer_produces() {
    let document = |object: Value| {
        serde_json::json!({
            "@type": "SealbookAccountExport",
            "version": "1.0",
            "exportedAt": "2026-10-28T12:00:00Z",
            "account": {
                "server": "https://sealbook.example",
                "username": "Ada",
                "accountId": "11111111-1111-4111-8111-111111111111",
                "collectionId": "22222222-2222-4222-8222-222222222222",
                "deviceId": "33333333-3333-4333-8333-333333333333",
            },
            "objectCount": 1,
            "objects": [object],
        })
    };
    let id = "00000000-0000-4000-8000-000000000001";
    let note = "application/sealbook.note+json";
    assert!(validator("AccountExport").is_valid(&document(
        serde_json::json!({ "id": id, "contentType": note, "text": "x" })
    )));
    for (why, object) in [
        (
            "both payload and text",
            serde_json::json!({ "id": id, "contentType": note, "payload": {}, "text": "x" }),
        ),
        (
            "a null payload",
            serde_json::json!({ "id": id, "contentType": note, "payload": null }),
        ),
        (
            "no content type",
            serde_json::json!({ "id": id, "contentType": "", "text": "x" }),
        ),
    ] {
        assert!(
            !validator("AccountExport").is_valid(&document(object)),
            "{why}"
        );
    }
}
