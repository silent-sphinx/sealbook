//! The stored-payload schema against the owned key lists, and every payload a
//! writer produced in the shared fixtures against the schema.
//!
//! Run `REGENERATE_SCHEMA=1 cargo test -p sealbook-core -- --ignored
//! regenerate` to rewrite it after a deliberate payload change.

use std::collections::BTreeSet;

use sealbook_core::schema::{payload_schema, PAYLOAD_TYPES};
use serde_json::Value;

const SCHEMA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../sealbook-protocol/schema/payloads.json"
);
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../sealbook-protocol/fixtures");

fn built() -> String {
    serde_json::to_string_pretty(&payload_schema()).unwrap() + "\n"
}

#[test]
#[ignore = "writes the checked-in schema; run with REGENERATE_SCHEMA=1"]
fn regenerate_the_payload_schema() {
    assert!(
        std::env::var("REGENERATE_SCHEMA").is_ok(),
        "set REGENERATE_SCHEMA=1 to confirm overwriting the checked-in schema"
    );
    std::fs::write(SCHEMA, built()).unwrap();
}

#[test]
fn the_checked_in_payload_schema_is_what_core_builds() {
    let stored = std::fs::read_to_string(SCHEMA).unwrap_or_default();
    assert!(
        stored == built(),
        "schema/payloads.json is stale; regenerate it: REGENERATE_SCHEMA=1"
    );
}

#[test]
fn each_payload_describes_exactly_the_keys_its_writer_owns() {
    let schema = payload_schema();
    for (name, content_type, owned) in PAYLOAD_TYPES {
        let def = &schema["$defs"][*name];
        assert_eq!(def["x-sealbook-content-type"], *content_type, "{name}");
        let described: BTreeSet<&str> = def["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{name} has properties"))
            .keys()
            .map(String::as_str)
            .collect();
        let conditional: BTreeSet<&str> = def["x-sealbook-conditionally-owned"]
            .as_array()
            .map(|keys| keys.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let expected: BTreeSet<&str> = owned.iter().copied().chain(conditional).collect();
        assert_eq!(described, expected, "{name}");
    }
}

fn validator(type_name: &str) -> jsonschema::Validator {
    let mut schema = payload_schema();
    assert!(schema["$defs"].get(type_name).is_some(), "no {type_name}");
    schema["$ref"] = format!("#/$defs/{type_name}").into();
    jsonschema::validator_for(&schema).expect("the payload schema compiles")
}

fn read(name: &str) -> Value {
    let path = format!("{FIXTURES}/{name}");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    serde_json::from_str(&text).expect("a fixture must be JSON")
}

/// Every payload a writer produced: each `*writes` table's `payload`, and the
/// three files that are the literal output of the writers before core.
fn written() -> Vec<(String, Value)> {
    let mut out = Vec::new();
    for name in [
        "payloads/notes.json",
        "payloads/bookmarks.json",
        "payloads/tasks.json",
        "payloads/calendars.json",
        "payloads/contacts.json",
        "payloads/settings.json",
        "payloads/fuzz.json",
    ] {
        let fixture = read(name);
        for (table, rows) in fixture.as_object().expect("an object") {
            if !table.ends_with("writes") {
                continue;
            }
            for (index, row) in rows.as_array().expect("a table").iter().enumerate() {
                let payload = row["payload"].as_str().expect("a write has a payload");
                let payload = serde_json::from_str(payload).expect("a written payload is JSON");
                out.push((format!("{name} {table}[{index}]"), payload));
            }
        }
    }
    for name in [
        "payloads/calendar.json",
        "payloads/calendar-archived.json",
        "payloads/calendar-event.json",
    ] {
        out.push((name.to_string(), read(name)));
    }
    out
}

#[test]
fn every_written_payload_in_the_shared_fixtures_meets_the_schema() {
    let written = written();
    assert!(written.len() >= 290, "{} written payloads", written.len());
    let mut failures = Vec::new();
    for (whence, payload) in &written {
        let type_name = payload["@type"].as_str().unwrap_or_default();
        let errors: Vec<String> = validator(type_name)
            .iter_errors(payload)
            .map(|error| format!("{error} at {}", error.instance_path()))
            .collect();
        if !errors.is_empty() {
            failures.push(format!("{whence} ({type_name}): {errors:?}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn the_schema_refuses_what_no_writer_produces() {
    let note = serde_json::json!({
        "@type": "Note",
        "version": "1.0",
        "body": "",
        "notebookId": "00000000-0000-0000-0000-000000000002",
        "createdAt": "2026-10-28T12:00:00Z",
        "updatedAt": "2026-10-28T12:00:00Z",
    });
    assert!(!validator("Note").is_valid(&note), "a note with no title");

    let settings = serde_json::json!({
        "@type": "AccountSettings",
        "version": "1.0",
        "features": {
            "contacts": false, "calendar": false, "notes": false, "bookmarks": false, "tasks": false,
        },
        "contactMode": "basic",
        "accent": "blue",
    });
    assert!(
        !validator("AccountSettings").is_valid(&settings),
        "settings with every feature off"
    );
}
