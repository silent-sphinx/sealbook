//! The export files: one spelling written, every old one still read.
//!
//! A file exported before payload 1.1 carries the old `@type` (or none) and a
//! numeric `version`. It has to import, because the person who made it may have
//! kept it for years.

use sealbook_core::schema::file_schema;
use sealbook_core::*;
use serde_json::{json, Value};

const NOW: &str = "2026-11-20T09:00:00Z";

fn valid(type_name: &str, document: &str) {
    let mut schema = file_schema();
    schema["$ref"] = format!("#/$defs/{type_name}").into();
    let validator = jsonschema::validator_for(&schema).expect("the file schema compiles");
    let document: Value = serde_json::from_str(document).expect("a JSON file");
    let errors: Vec<String> = validator
        .iter_errors(&document)
        .map(|error| format!("{error} at {}", error.instance_path()))
        .collect();
    assert!(errors.is_empty(), "{type_name}: {errors:?}");
}

fn task(title: &str) -> CoreTask {
    task_parse(
        "t1",
        &json!({"@type":"Task","version":"1.1","title":title,"taskListId":default_task_list_id()})
            .to_string(),
    )
}

#[test]
fn the_tasks_export_writes_the_new_tag_and_a_string_version() {
    let lists = vec![task_list_parse(&default_task_list_id(), "{}")];
    let text = task_export(&[task("Call")], &lists, NOW);
    let file: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(file["@type"], "SealbookTasksExport");
    assert_eq!(file["version"], "1.1");
    valid("TasksExport", &text);
}

#[test]
fn a_tasks_file_exported_before_the_rename_still_imports() {
    let old = r#"{"@type":"sealbook-task-export","version":1,"exportedAt":"2025-01-01T00:00:00Z",
        "lists":[],"tasks":[{"id":"a","title":"Call","listName":"Default"}]}"#;
    let new = old
        .replace("sealbook-task-export", "SealbookTasksExport")
        .replace("\"version\":1", "\"version\":\"1.1\"");
    let from_old = task_import(old).expect("the old form imports");
    let from_new = task_import(&new).expect("the new form imports");
    assert_eq!(from_old.tasks.len(), 1);
    assert_eq!(from_old.tasks[0].draft.title, "Call");
    assert_eq!(from_old.tasks, from_new.tasks);
}

#[test]
fn the_bookmarks_export_writes_the_new_tag_and_a_string_version() {
    let text = bookmark_export(&[], &[], NOW);
    let file: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(file["@type"], "SealbookBookmarksExport");
    assert_eq!(file["version"], "1.1");
    valid("BookmarksExport", &text);
}

#[test]
fn a_bookmarks_file_exported_before_the_rename_still_imports() {
    let old = r#"{"@type":"sealbook-bookmark-export","version":1,"exportedAt":"2025-01-01T00:00:00Z",
        "bookmarks":[{"url":"https://a.example","title":"A","collectionId":"c","collectionName":"C"}],
        "collections":[]}"#;
    let new = old
        .replace("sealbook-bookmark-export", "SealbookBookmarksExport")
        .replace("\"version\":1", "\"version\":\"1.1\"");
    let from_old = bookmark_import(old).expect("the old form imports");
    let from_new = bookmark_import(&new).expect("the new form imports");
    assert_eq!(from_old.bookmarks.len(), 1);
    assert_eq!(from_old.bookmarks, from_new.bookmarks);
}

#[test]
fn the_notes_export_writes_a_tag_and_a_string_version() {
    let text = notes_write_json(&[], &[], NOW);
    let file: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(file["@type"], "SealbookNotesExport");
    assert_eq!(file["version"], "1.1");
    valid("NotesExport", &text);
}

#[test]
fn a_notes_file_with_no_tag_and_version_1_0_still_imports() {
    let old = r#"{"version":"1.0","exportedAt":"2025-01-01T00:00:00Z",
        "notebooks":[{"id":"n","name":"Journal"}],
        "notes":[{"title":"Day one","body":"text","notebookId":"n","notebook":"Journal"}]}"#;
    let file = notes_import("notes.json", old, &default_notebook_id()).expect("imports");
    assert_eq!(file.notes.len(), 1);
    assert_eq!(file.notes[0].title, "Day one");
    let new = old.replace(
        "{\"version\":\"1.0\"",
        "{\"@type\":\"SealbookNotesExport\",\"version\":\"1.1\"",
    );
    let again = notes_import("notes.json", &new, &default_notebook_id()).expect("imports");
    assert_eq!(file.notes, again.notes);
}

#[test]
fn an_account_export_is_written_as_1_1_and_a_1_0_file_still_restores() {
    let fixture = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../sealbook-protocol/fixtures/v1.0.0-account-export.json"
    ))
    .unwrap();
    let restored = account_export_parse(&fixture).expect("a 1.0 file restores");
    assert!(!restored.objects.is_empty());
    assert_eq!(sealbook_protocol::ACCOUNT_EXPORT_VERSION, "1.1");
}

#[test]
fn an_account_import_upgrades_each_object_as_it_reads_it() {
    let document = json!({
        "@type": "SealbookAccountExport",
        "version": "1.0",
        "exportedAt": "2025-01-01T00:00:00Z",
        "account": {},
        "objectCount": 3,
        "objects": [
            {"id":"11111111-1111-4111-8111-111111111111",
             "contentType":"application/sealbook.calendar-event+json",
             "payload":{"@type":"CalendarEvent","version":"1.0","title":"E","start":"2026-10-01"}},
            {"id":"22222222-2222-4222-8222-222222222222",
             "contentType":"application/sealbook.note+json",
             "payload":{"@type":"Note","version":"1.0","title":"N","body":"b","notebookId":"n"}},
            {"id":"33333333-3333-4333-8333-333333333333",
             "contentType":"application/sealbook.note+json",
             "text":"not json at all"},
        ],
    })
    .to_string();
    let restored = account_export_parse(&document).unwrap();
    let payload =
        |index: usize| -> Value { serde_json::from_str(&restored.objects[index].payload).unwrap() };
    assert_eq!(payload(0)["version"], "1.1");
    assert_eq!(payload(0)["calendarId"], default_calendar_id());
    assert_eq!(payload(1)["version"], "1.1");
    assert_eq!(restored.objects[2].payload, "not json at all");
}
