//! Notes as a file: the bundle both clients write, and what an import reads.

use sealbook_core::*;

fn entry(title: &str, body: &str) -> CoreNoteFileEntry {
    CoreNoteFileEntry {
        title: title.into(),
        body: body.into(),
        notebook_id: default_notebook_id(),
        ..CoreNoteFileEntry::default()
    }
}

fn notebooks() -> Vec<CoreNotebook> {
    vec![CoreNotebook {
        id: default_notebook_id(),
        name: "Journal".into(),
        readable: true,
        raw: String::new(),
    }]
}

#[test]
fn a_bundle_round_trips() {
    let mut first = entry("Plan: \"v2\"", "Line one\n\n---\n\nafter a rule");
    first.created_at = Some("2026-10-01T09:00:00.000Z".into());
    first.updated_at = Some("2026-10-02T09:00:00.000Z".into());
    first.pinned = Some(true);
    let second = entry("Second", "text");
    let text = notes_write_markdown(&[second.clone(), first.clone()], &notebooks());

    let read = notes_import("bundle.md", &text, &default_notebook_id()).unwrap();
    assert_eq!(read.format, "Markdown");
    assert_eq!(read.notes, vec![first, second]);
}

#[test]
fn pinned_is_written_only_when_set() {
    let plain = notes_write_markdown(&[entry("a", "b")], &notebooks());
    assert!(!plain.contains("pinned"));
    let mut pinned = entry("a", "b");
    pinned.pinned = Some(false);
    assert!(notes_write_markdown(&[pinned], &notebooks()).contains("pinned: false"));
}

#[test]
fn pinned_first_then_latest_edit_then_title() {
    let at = |title: &str, stamp: &str, pinned: Option<bool>| CoreNoteFileEntry {
        updated_at: Some(stamp.into()),
        pinned,
        ..entry(title, "")
    };
    let text = notes_write_markdown(
        &[
            at("old", "2026-01-01T00:00:00Z", None),
            at("new", "2026-06-01T00:00:00Z", None),
            at("pin", "2025-01-01T00:00:00Z", Some(true)),
        ],
        &notebooks(),
    );
    let titles: Vec<String> = notes_import("a.md", &text, "")
        .unwrap()
        .notes
        .into_iter()
        .map(|n| n.title)
        .collect();
    assert_eq!(titles, ["pin", "new", "old"]);
}

#[test]
fn json_round_trips_and_keeps_pinned() {
    let mut note = entry("Title", "Body");
    note.pinned = Some(true);
    note.created_at = Some("2026-10-01T09:00:00.000Z".into());
    let text = notes_write_json(&[note.clone()], &notebooks(), "2026-10-30T00:00:00Z");
    let read = notes_import("backup.json", &text, &default_notebook_id()).unwrap();
    assert_eq!(read.format, "JSON");
    assert_eq!(read.notes, vec![note]);
}

#[test]
fn a_plain_markdown_file_is_one_note_titled_by_its_heading() {
    let read = notes_import("Trip.md", "\n# Packing\n\nsocks", "").unwrap();
    assert_eq!(read.notes.len(), 1);
    assert_eq!(read.notes[0].title, "Packing");
    assert_eq!(read.notes[0].body, "socks");
    let read = notes_import("Trip.md", "just words", "").unwrap();
    assert_eq!(read.notes[0].title, "Trip");
}

#[test]
fn imported_tables_are_repaired() {
    let read = notes_import("t.md", "x\n\n| a | b |\n| --- |  |\n| 1 | 2 |", "").unwrap();
    assert!(read.notes[0].body.contains("| --- | --- |"));
}

#[test]
fn text_that_is_not_a_note_list_falls_back_to_markdown() {
    let read = notes_import("x.json", "{\"other\": 1}", "").unwrap();
    assert_eq!(read.format, "Markdown");
    let read = notes_import(
        "a.json",
        "[{\"title\":\" \",\"body\":\"\"},3,{\"title\":\"ok\"}]",
        "",
    )
    .unwrap();
    assert_eq!(read.notes.len(), 1);
}

#[test]
fn limits_are_errors_and_big_notes_are_skipped() {
    let many = vec![r#"{"title":"n"}"#; 501].join(",");
    assert!(notes_import("a.json", &format!("[{many}]"), "").is_err());

    let big = "x".repeat(9 * 1024 * 1024);
    let text = notes_write_markdown(&[entry("big", &big), entry("small", "ok")], &notebooks());
    let read = notes_import("a.md", &text, "").unwrap();
    assert_eq!(read.notes.len(), 1);
    assert_eq!(read.skipped[0].title, "big");
    assert!(notes_import("a.md", "  ", "").unwrap().notes.is_empty());
}
