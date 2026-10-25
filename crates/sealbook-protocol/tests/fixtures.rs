//! The shared payload fixtures, read here as well as by the TypeScript and
//! Kotlin suites.
//!
//! What Rust can be held to without a client: that each fixture declares the
//! content type's `@type` and a schema version this build speaks, that every
//! key in it is one of that type's owned keys, and that `merge_payload` carries
//! an unknown key through an edit rather than dropping it.

use sealbook_protocol::{merge_payload, PAYLOAD_SCHEMA_VERSION};
use serde_json::{json, Value};

fn fixture(name: &str) -> String {
    let path = format!("{}/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"))
}

fn body(name: &str) -> Value {
    serde_json::from_str(&fixture(name)).expect("a fixture must be JSON")
}

/// Mirrors `CALENDAR_EVENT_KEYS` in `sealbook-web/src/lib/calendarApi.ts`.
const CALENDAR_EVENT_KEYS: &[&str] = &[
    "@type",
    "version",
    "title",
    "start",
    "end",
    "notes",
    "location",
    "participants",
    "timezone",
    "calendarId",
    "recurrence",
];

/// Mirrors `CALENDAR_KEYS` in `sealbook-web/src/lib/calendar.ts`.
const CALENDAR_KEYS: &[&str] = &["@type", "version", "name", "color", "favorite", "archived"];

#[test]
fn every_payload_fixture_declares_its_type_and_a_version_this_build_speaks() {
    for (name, declared) in [
        ("payloads/calendar-event.json", "CalendarEvent"),
        ("payloads/calendar.json", "Calendar"),
        ("payloads/calendar-archived.json", "Calendar"),
    ] {
        let body = body(name);
        assert_eq!(body["@type"], declared, "{name}");
        assert_eq!(body["version"], PAYLOAD_SCHEMA_VERSION, "{name}");
    }
}

#[test]
fn no_payload_fixture_carries_a_key_outside_its_owned_set() {
    for (name, owned) in [
        ("payloads/calendar-event.json", CALENDAR_EVENT_KEYS),
        ("payloads/calendar.json", CALENDAR_KEYS),
        ("payloads/calendar-archived.json", CALENDAR_KEYS),
    ] {
        let unknown: Vec<String> = body(name)
            .as_object()
            .expect("an object")
            .keys()
            .filter(|key| !owned.contains(&key.as_str()))
            .cloned()
            .collect();
        assert!(unknown.is_empty(), "{name} carries {unknown:?}");
    }
}

#[test]
fn an_edit_through_merge_payload_keeps_a_field_this_build_does_not_own() {
    let mut body = body("payloads/calendar-event.json");
    body["futureField"] = json!("kept");
    let previous = serde_json::to_string(&body).unwrap();

    let edited = merge_payload(
        Some(&previous),
        json!({
            "@type": "CalendarEvent",
            "version": PAYLOAD_SCHEMA_VERSION,
            "title": "Renamed",
        }),
        CALENDAR_EVENT_KEYS,
    );

    assert_eq!(edited["title"], "Renamed");
    assert_eq!(
        edited["futureField"], "kept",
        "an unowned field must survive an edit"
    );
}

#[test]
fn the_v1_release_export_is_still_readable_json() {
    let body = body("v1.0.0-account-export.json");
    assert_eq!(body["@type"], "SealbookAccountExport");
    assert_eq!(
        body["objects"].as_array().expect("objects").len(),
        body["objectCount"].as_u64().expect("objectCount") as usize
    );
}
