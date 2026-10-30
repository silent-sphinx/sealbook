//! Notes as a file, and a file back as notes.
//!
//! The markdown bundle is the format both clients write and read, so its
//! boundary markers and front-matter keys are not for one client to change.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::markdown::{heading_text, repair_pipe_tables};
use crate::notes::{
    note_write, notebook_name_by_id, resolve_notebook_id, CoreNoteDraft, CoreNotebook,
    UNTITLED_NOTE_TITLE,
};
use crate::recurrence::days_from_civil;
use crate::CoreError;

/// A bundle holds many notes in one file, so each needs a boundary a note body
/// cannot produce by accident. A bare `---` is a thematic break in markdown; the
/// marker is the `sealbook: note` line immediately after it.
const MARKER: &str = "sealbook: note";

/// Matches the per-account byte quota, because the largest file anyone can
/// reasonably import is a full export of their own vault.
pub const MAX_NOTE_IMPORT_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_IMPORTED_NOTES: usize = 500;

/// The envelope's other keys: version, contentType, tombstone, revision.
const ENVELOPE_OVERHEAD: usize = 256;

/// One note as the file carries it.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreNoteFileEntry {
    pub title: String,
    pub body: String,
    pub notebook_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Written, and read back, only when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned: Option<bool>,
}

/// A note left out of an import.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreNoteSkipped {
    pub title: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreNoteFile {
    /// `Markdown` or `JSON`.
    pub format: String,
    pub notes: Vec<CoreNoteFileEntry>,
    pub skipped: Vec<CoreNoteSkipped>,
}

fn quote(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// Accepts the quoted form this writes, and a bare value a person typed.
fn unquote(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.starts_with('"') {
        if let Ok(Value::String(parsed)) = serde_json::from_str::<Value>(trimmed) {
            return parsed;
        }
    }
    trimmed.to_string()
}

/// Milliseconds since the epoch of an RFC 3339 stamp, 0 when it is not one.
fn edited_millis(stamp: Option<&str>) -> i64 {
    let parse = |stamp: &str| -> Option<i64> {
        let (date, time) = stamp.split_once(['T', 't'])?;
        let mut day = date.split('-');
        let (y, m, d) = (
            day.next()?.parse().ok()?,
            day.next()?.parse().ok()?,
            day.next()?.parse().ok()?,
        );
        let split = time.find(['Z', 'z', '+', '-']).unwrap_or(time.len());
        let (clock, zone) = time.split_at(split);
        let mut parts = clock.split(':');
        let hours: i64 = parts.next()?.parse().ok()?;
        let minutes: i64 = parts.next()?.parse().ok()?;
        let seconds: f64 = parts.next()?.parse().ok()?;
        let offset = match zone.as_bytes().first() {
            Some(b'+' | b'-') => {
                let (h, m) = zone[1..].split_once(':')?;
                let minutes = h.parse::<i64>().ok()? * 60 + m.parse::<i64>().ok()?;
                if zone.starts_with('-') {
                    -minutes
                } else {
                    minutes
                }
            }
            _ => 0,
        };
        let days = days_from_civil(y, m, d);
        Some(((days * 24 + hours) * 60 + minutes - offset) * 60_000 + (seconds * 1000.0) as i64)
    };
    stamp.and_then(parse).unwrap_or(0)
}

/// Pinned first, then most recently edited, then by title so the order is total.
fn sorted(notes: &[CoreNoteFileEntry]) -> Vec<&CoreNoteFileEntry> {
    let mut list: Vec<&CoreNoteFileEntry> = notes.iter().collect();
    list.sort_by(|a, b| {
        let key = |n: &CoreNoteFileEntry| {
            (
                n.pinned != Some(true),
                std::cmp::Reverse(edited_millis(
                    n.updated_at.as_deref().or(n.created_at.as_deref()),
                )),
                n.title.to_lowercase(),
            )
        };
        key(a).cmp(&key(b))
    });
    list
}

fn notebook_name(notebooks: &[CoreNotebook], note: &CoreNoteFileEntry) -> String {
    notebook_name_by_id(notebooks, Some(note.notebook_id.clone()))
}

/// Every note in one markdown file.
pub fn notes_write_markdown(notes: &[CoreNoteFileEntry], notebooks: &[CoreNotebook]) -> String {
    sorted(notes)
        .into_iter()
        .map(|note| {
            let mut front = vec![
                "---".to_string(),
                MARKER.to_string(),
                format!("title: {}", quote(&note.title)),
                format!("notebook: {}", quote(&notebook_name(notebooks, note))),
            ];
            if let Some(pinned) = note.pinned {
                front.push(format!("pinned: {pinned}"));
            }
            if let Some(created) = &note.created_at {
                front.push(format!("created: {}", quote(created)));
            }
            if let Some(updated) = &note.updated_at {
                front.push(format!("updated: {}", quote(updated)));
            }
            front.push("---".to_string());
            format!("{}\n\n{}\n", front.join("\n"), note.body.trim_end())
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every note, and the notebooks, as a JSON backup.
pub fn notes_write_json(
    notes: &[CoreNoteFileEntry],
    notebooks: &[CoreNotebook],
    exported_at: &str,
) -> String {
    let entries: Vec<Value> = sorted(notes)
        .into_iter()
        .map(|note| {
            let mut entry = Map::new();
            entry.insert("title".into(), json!(note.title));
            entry.insert("body".into(), json!(note.body));
            entry.insert("notebookId".into(), json!(note.notebook_id));
            entry.insert("notebook".into(), json!(notebook_name(notebooks, note)));
            if let Some(pinned) = note.pinned {
                entry.insert("pinned".into(), json!(pinned));
            }
            if let Some(created) = &note.created_at {
                entry.insert("createdAt".into(), json!(created));
            }
            if let Some(updated) = &note.updated_at {
                entry.insert("updatedAt".into(), json!(updated));
            }
            Value::Object(entry)
        })
        .collect();
    let document = json!({
        "version": "1.0",
        "exportedAt": exported_at,
        "notebooks": notebooks
            .iter()
            .map(|n| json!({ "id": n.id, "name": n.name }))
            .collect::<Vec<_>>(),
        "notes": entries,
    });
    serde_json::to_string_pretty(&document).unwrap_or_default()
}

fn title_from_body(body: &str, fallback: &str) -> (String, String) {
    let lines: Vec<&str> = body.split('\n').collect();
    if let Some(first) = lines.iter().position(|l| !l.trim().is_empty()) {
        if let Some(title) = heading_text(lines[first]).filter(|t| !t.is_empty()) {
            // The heading becomes the title rather than being repeated in the body.
            return (
                title.to_string(),
                lines[first + 1..].join("\n").trim().to_string(),
            );
        }
    }
    (fallback.to_string(), body.trim().to_string())
}

fn entry_from(
    title: &str,
    body: &str,
    notebook_id: &str,
    pinned: Option<bool>,
    created_at: Option<String>,
    updated_at: Option<String>,
) -> CoreNoteFileEntry {
    let title = title.trim();
    CoreNoteFileEntry {
        title: if title.is_empty() {
            UNTITLED_NOTE_TITLE
        } else {
            title
        }
        .to_string(),
        // Imported text comes from exporters that spell a table loosely, and an
        // editor would otherwise flatten what it cannot read into a paragraph.
        body: repair_pipe_tables(body),
        notebook_id: resolve_notebook_id(Some(notebook_id.to_string())),
        created_at,
        updated_at,
        pinned,
    }
}

fn parse_markdown(content: &str, filename: &str, notebook_id: &str) -> Vec<CoreNoteFileEntry> {
    let normalized = content.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<&str> = normalized.split('\n').collect();
    let starts: Vec<usize> = (0..lines.len().saturating_sub(1))
        .filter(|i| lines[*i].trim() == "---" && lines[*i + 1].trim() == MARKER)
        .collect();

    // No marker: a markdown file from somewhere else, which is one note.
    if starts.is_empty() {
        let stem = match filename.rfind('.') {
            Some(dot) => &filename[..dot],
            None => filename,
        };
        let fallback = if stem.is_empty() {
            "Imported note"
        } else {
            stem
        };
        let (title, body) = title_from_body(content, fallback);
        return if body.is_empty() && title.is_empty() {
            Vec::new()
        } else {
            vec![entry_from(&title, &body, notebook_id, None, None, None)]
        };
    }

    let mut entries = Vec::new();
    for (index, start) in starts.iter().enumerate() {
        let end = starts.get(index + 1).copied().unwrap_or(lines.len());
        let mut cursor = start + 2;
        let mut fields: Vec<(String, &str)> = Vec::new();
        while cursor < end && lines[cursor].trim() != "---" {
            if let Some(split) = lines[cursor].find(':').filter(|s| *s > 0) {
                fields.push((
                    lines[cursor][..split].trim().to_lowercase(),
                    &lines[cursor][split + 1..],
                ));
            }
            cursor += 1;
        }
        let field = |key: &str| fields.iter().rev().find(|(k, _)| k == key).map(|(_, v)| *v);
        let body = lines[(cursor + 1).min(end)..end]
            .join("\n")
            .trim()
            .to_string();
        let title = field("title").map(unquote).unwrap_or_default();
        let (title, body) = if title.is_empty() {
            title_from_body(&body, UNTITLED_NOTE_TITLE)
        } else {
            (title, body)
        };
        let pinned = match field("pinned").map(str::trim) {
            Some("true") => Some(true),
            Some("false") => Some(false),
            _ => None,
        };
        entries.push(entry_from(
            &title,
            &body,
            notebook_id,
            pinned,
            field("created").map(unquote),
            field("updated").map(unquote),
        ));
    }
    entries
}

fn parse_json(content: &str, notebook_id: &str) -> Option<Vec<CoreNoteFileEntry>> {
    let parsed: Value = serde_json::from_str(content).ok()?;
    let list = match &parsed {
        Value::Array(items) => items,
        Value::Object(object) => object.get("notes")?.as_array()?,
        _ => return None,
    };
    let text = |entry: &Map<String, Value>, key: &str| {
        entry
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let stamp = |entry: &Map<String, Value>, key: &str| {
        Some(text(entry, key).trim().to_string()).filter(|s| !s.is_empty())
    };
    let mut entries = Vec::new();
    for item in list {
        let Some(entry) = item.as_object() else {
            continue;
        };
        let (title, body) = (text(entry, "title"), text(entry, "body"));
        if title.trim().is_empty() && body.trim().is_empty() {
            continue;
        }
        entries.push(entry_from(
            &title,
            &body,
            notebook_id,
            entry.get("pinned").and_then(Value::as_bool),
            stamp(entry, "createdAt"),
            stamp(entry, "updatedAt"),
        ));
    }
    Some(entries)
}

/// Whether the note, once written and sealed, fits one vault object.
fn fits_object_limit(entry: &CoreNoteFileEntry) -> bool {
    let draft = CoreNoteDraft {
        title: entry.title.clone(),
        body: entry.body.clone(),
        notebook_id: entry.notebook_id.clone(),
        created_at: entry.created_at.clone(),
        pinned: entry.pinned,
        ..CoreNoteDraft::default()
    };
    let now = entry
        .updated_at
        .as_deref()
        .unwrap_or("2026-01-01T00:00:00.000Z");
    let Ok(payload) = note_write(&draft, now) else {
        return true;
    };
    // The payload is escaped again inside the sealed envelope that carries it.
    let sealed = quote(&payload).len() + ENVELOPE_OVERHEAD;
    sealed + 4 <= sealbook_protocol::MAX_PADDED_OBJECT_SIZE
}

/// Reads a notes file: JSON when the name says so or the text opens with a
/// bracket and holds a note list, otherwise a markdown bundle or a single
/// markdown document. Notes too large for one vault object are reported rather
/// than left to fail partway through an upload.
pub fn notes_import(
    filename: &str,
    text: &str,
    notebook_id: &str,
) -> Result<CoreNoteFile, CoreError> {
    if text.len() > MAX_NOTE_IMPORT_BYTES {
        return Err(CoreError::malformed(
            "Import file is too large (maximum 128 MB).",
        ));
    }
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(CoreNoteFile {
            format: "Markdown".into(),
            notes: Vec::new(),
            skipped: Vec::new(),
        });
    }

    let mut format = "Markdown";
    let mut entries = None;
    if filename.to_lowercase().ends_with(".json")
        || trimmed.starts_with('{')
        || trimmed.starts_with('[')
    {
        entries = parse_json(trimmed, notebook_id);
        if entries.is_some() {
            format = "JSON";
        }
    }
    let entries = entries.unwrap_or_else(|| parse_markdown(text, filename, notebook_id));

    if entries.len() > MAX_IMPORTED_NOTES {
        return Err(CoreError::malformed(format!(
            "Import contains too many notes (maximum {MAX_IMPORTED_NOTES})."
        )));
    }

    let mut notes = Vec::new();
    let mut skipped = Vec::new();
    for entry in entries {
        if fits_object_limit(&entry) {
            notes.push(entry);
        } else {
            skipped.push(CoreNoteSkipped {
                title: entry.title,
                reason: "larger than the 8 MB limit for one note".into(),
            });
        }
    }
    Ok(CoreNoteFile {
        format: format.into(),
        notes,
        skipped,
    })
}

/// Everything above, in the shapes the bindings can carry.
#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{CoreNoteFile, CoreNoteFileEntry};
    use crate::{CoreError, CoreNotebook};

    #[uniffi::export(name = "notes_write_markdown")]
    pub fn notes_write_markdown(
        notes: Vec<CoreNoteFileEntry>,
        notebooks: Vec<CoreNotebook>,
    ) -> String {
        super::notes_write_markdown(&notes, &notebooks)
    }

    #[uniffi::export(name = "notes_write_json")]
    pub fn notes_write_json(
        notes: Vec<CoreNoteFileEntry>,
        notebooks: Vec<CoreNotebook>,
        exported_at: String,
    ) -> String {
        super::notes_write_json(&notes, &notebooks, &exported_at)
    }

    #[uniffi::export(name = "notes_import")]
    pub fn notes_import(
        filename: String,
        text: String,
        notebook_id: String,
    ) -> Result<CoreNoteFile, CoreError> {
        super::notes_import(&filename, &text, &notebook_id)
    }
}
