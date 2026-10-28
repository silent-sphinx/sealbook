//! The note and notebook payloads: which keys a writer owns, how one is
//! written, and how one is read back.
//!
//! Notes are the first content type to move here, because they are the one with
//! the widest spread of writers: the CLI, the web client, Firefox through the
//! web's lib, and Android all write them, and three of the four had their own
//! key list. The CLI's was the last writer in the codebase that rebuilt a record
//! rather than merging onto it, so a note edited from the CLI came back without
//! its place in the tree or its photos.
//!
//! Three rules decide everything below.
//!
//! **One owned set.** [`NOTE_KEYS`] is the union of every key any client writes,
//! not the subset a given host's UI can express. A host that cannot show a field
//! still carries it, because it reads the stored note into [`CoreNote`] first and
//! writes that record back. That is what replaces the per-host short lists, and
//! what makes a new note field reach every client by being added here once.
//!
//! **Absent is omitted, never null.** A note at the top level carries no
//! `parentId` and a note with no photos carries no `attachments`, so a reader
//! predating either field sees exactly the shape it expects.
//!
//! **A newer major is not edited.** [`note_write`] refuses to write over a
//! payload whose `version` declares a schema major this build does not read.
//! Carrying unknown keys through is enough for an added field; it is not enough
//! for a field whose meaning changed, and that is the case the version check is
//! for. Before this, all three clients had a copy of the check and none of them
//! called it.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::payload::{as_object, text, trimmed, write_payload};
use crate::CoreError;
use sealbook_protocol::{payload_schema_readable, PAYLOAD_SCHEMA_VERSION};

pub use sealbook_protocol::{DEFAULT_NOTEBOOK_NAME, NOTE_CONTENT_TYPE, NOTEBOOK_CONTENT_TYPE};

/// What a note with no readable title is listed as.
pub const UNTITLED_NOTE_TITLE: &str = "Untitled note";

/// What a note whose payload will not parse at all is listed as. It still has to
/// render as something the user can find and delete rather than taking the whole
/// list down, which is why this is a title and not an error.
pub const UNREADABLE_NOTE_TITLE: &str = "Unreadable note";

pub const UNTITLED_NOTEBOOK_NAME: &str = "Untitled";

/// The default notebook's id, as a string, since that is how every host holds a
/// note's `notebookId`: the field is read leniently and a value that is not a
/// UUID is carried rather than rewritten.
pub fn default_notebook_id() -> String {
    sealbook_protocol::DEFAULT_NOTEBOOK_ID.to_string()
}

/// Every key a note writer owns.
///
/// `pinned` is deliberately absent and is handled by [`pinned_keys`]: see
/// [`CoreNoteDraft::pinned`].
pub const NOTE_KEYS: &[&str] = &[
    "@type",
    "version",
    "title",
    "body",
    "notebookId",
    "parentId",
    "createdAt",
    "updatedAt",
    "attachments",
];

pub const NOTEBOOK_KEYS: &[&str] = &["@type", "version", "name"];

/// The owned set for a write that has an opinion about `pinned`.
///
/// Held as a function rather than a second constant so there is one list to add
/// a key to.
fn pinned_keys() -> Vec<&'static str> {
    let mut keys = NOTE_KEYS.to_vec();
    keys.push("pinned");
    keys
}

/// A photo or other binary attached to a note.
///
/// The bytes live outside the sealed-object set, chunked and sealed under `adk`,
/// so this reference is all the note payload carries. See
/// `sealbook_core::attachments`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreNoteAttachment {
    pub id: String,
    pub filename: String,
    pub mime_type: String,
    /// Original plaintext size, for display.
    pub byte_size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    /// Base64url attachment data key, sealed with the rest of the note.
    pub adk: String,
    /// Base64url rolled-up content hash, checked on download.
    pub content_hash: String,
    pub chunk_size: u32,
    pub chunk_count: u32,
    /// Displayed width in CSS pixels, as the user dragged it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_width: Option<u32>,
    /// Small inline preview that rides inside the sealed note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<String>,
    /// Whatever else the stored entry carried, as a JSON object, `{}` when it
    /// carried nothing else.
    ///
    /// The degrade-invisibly rule holds inside an entry as well as inside the
    /// note: `displayWidth` was added after `thumbnail`, and a client that
    /// rewrote the array from its own view of each entry dropped it. No host
    /// reads this field; it exists so a writer can put back what it could not
    /// understand.
    pub extra: String,
}

/// One note as it is drafted, before it is written.
///
/// A host that edits an existing note builds this from [`note_parse`] and
/// changes the fields its UI owns, rather than assembling it from its own view
/// model. That is what carries a field the host cannot show.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreNoteDraft {
    pub title: String,
    /// Markdown source, as typed. Whitespace is the user's, so it is written
    /// through untouched.
    pub body: String,
    pub notebook_id: String,
    /// The note this one sits under. `None` is a note at the notebook's top
    /// level, which is every note written before the field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    /// Empty writes no `attachments` key at all, which is the shape a reader
    /// predating photos expects.
    pub attachments: Vec<CoreNoteAttachment>,
    /// Client-generated: the server keeps no user timestamps, so an edit that
    /// does not carry `created_at` forward loses it. `None` on a new note, which
    /// takes the `now` passed to [`note_write`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// The one note key with three states, because one client manages it and
    /// another has deliberately dropped it.
    ///
    /// `Some` writes the value and owns the key. `None` leaves whatever is
    /// stored alone, which is what the web client needs: it removed favouriting
    /// in 2026-10 and must neither write `pinned` nor strip the values Android
    /// wrote. Every other key is owned unconditionally, because every client
    /// either manages it or round-trips it through [`CoreNote`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned: Option<bool>,
    /// The payload this draft came from, when it came from one. The write merges
    /// onto it. `None` for a note written from scratch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

/// One note as it was read back.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreNote {
    pub id: String,
    pub title: String,
    pub body: String,
    pub notebook_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    pub attachments: Vec<CoreNoteAttachment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned: Option<bool>,
    /// Whether this build reads the schema major the payload declares.
    ///
    /// False means the fields above were still read, because every one of them
    /// is optional and a lenient parse is better than a blank row, but a field
    /// this build understands may have changed meaning. [`note_write`] refuses
    /// such a payload, so a host that offers an editor should show it read-only.
    pub readable: bool,
    pub raw: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreNotebook {
    pub id: String,
    pub name: String,
    pub readable: bool,
    pub raw: String,
}

/// A note's `notebookId`, with a blank or missing one resolved to the default
/// notebook every account has.
pub fn resolve_notebook_id(notebook_id: Option<String>) -> String {
    notebook_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(default_notebook_id)
}

/// Reads a stored note payload.
///
/// Lenient throughout: a payload that is not JSON, or that is JSON but not an
/// object, comes back under [`UNREADABLE_NOTE_TITLE`] with the stored text as
/// its body, because a note the user cannot see is a note the user cannot
/// delete.
pub fn note_parse(id: &str, raw: &str) -> CoreNote {
    let Some(object) = as_object(raw) else {
        return CoreNote {
            id: id.to_string(),
            title: UNREADABLE_NOTE_TITLE.to_string(),
            body: raw.to_string(),
            notebook_id: default_notebook_id(),
            parent_id: None,
            attachments: Vec::new(),
            created_at: None,
            updated_at: None,
            pinned: None,
            readable: true,
            raw: raw.to_string(),
        };
    };
    CoreNote {
        id: id.to_string(),
        title: trimmed(&object, "title").unwrap_or_else(|| UNTITLED_NOTE_TITLE.to_string()),
        body: text(&object, "body"),
        notebook_id: resolve_notebook_id(trimmed(&object, "notebookId")),
        parent_id: trimmed(&object, "parentId"),
        attachments: parse_attachments(object.get("attachments")),
        created_at: trimmed(&object, "createdAt"),
        updated_at: trimmed(&object, "updatedAt"),
        pinned: object.get("pinned").and_then(Value::as_bool),
        readable: declared_readable(&object),
        raw: raw.to_string(),
    }
}

/// Serialises a note, merging onto whatever `draft.raw` carried.
///
/// `now` is the caller's clock: core has none. It becomes `updatedAt`, and
/// `createdAt` too on a note that has none.
pub fn note_write(draft: &CoreNoteDraft, now: &str) -> Result<String, CoreError> {
    refuse_newer_major(draft.raw.as_deref())?;

    let mut fields = Map::new();
    fields.insert("@type".into(), json!("Note"));
    fields.insert("version".into(), json!(PAYLOAD_SCHEMA_VERSION));
    fields.insert("title".into(), json!(draft.title.trim()));
    fields.insert("body".into(), json!(draft.body));
    fields.insert(
        "notebookId".into(),
        json!(resolve_notebook_id(Some(draft.notebook_id.clone()))),
    );
    if let Some(parent) = draft
        .parent_id
        .as_deref()
        .map(str::trim)
        .filter(|parent| !parent.is_empty())
    {
        fields.insert("parentId".into(), json!(parent));
    }
    if !draft.attachments.is_empty() {
        fields.insert(
            "attachments".into(),
            Value::Array(draft.attachments.iter().map(attachment_json).collect()),
        );
    }
    fields.insert(
        "createdAt".into(),
        json!(draft.created_at.as_deref().unwrap_or(now)),
    );
    fields.insert("updatedAt".into(), json!(now));

    let owned = match draft.pinned {
        Some(pinned) => {
            fields.insert("pinned".into(), json!(pinned));
            pinned_keys()
        }
        None => NOTE_KEYS.to_vec(),
    };
    Ok(write_payload(
        draft.raw.as_deref(),
        Value::Object(fields),
        &owned,
    ))
}

pub fn notebook_parse(id: &str, raw: &str) -> CoreNotebook {
    let object = as_object(raw);
    let stored = object.as_ref().and_then(|object| trimmed(object, "name"));
    CoreNotebook {
        id: id.to_string(),
        name: stored.unwrap_or_else(|| fallback_notebook_name(id)),
        readable: object.as_ref().map(declared_readable).unwrap_or(true),
        raw: raw.to_string(),
    }
}

pub fn notebook_write(name: &str, previous_raw: Option<&str>) -> Result<String, CoreError> {
    refuse_newer_major(previous_raw)?;
    Ok(write_payload(
        previous_raw,
        json!({
            "@type": "Notebook",
            "version": PAYLOAD_SCHEMA_VERSION,
            "name": name.trim(),
        }),
        NOTEBOOK_KEYS,
    ))
}

/// The name to show for a note's notebook, when the notebook itself is in hand.
///
/// A note pointing at a notebook that is not in the list shows the default
/// notebook's name rather than nothing, since a missing notebook and a blank
/// one look the same to the user.
pub fn notebook_name_by_id(notebooks: &[CoreNotebook], notebook_id: Option<String>) -> String {
    let id = resolve_notebook_id(notebook_id);
    notebooks
        .iter()
        .find(|notebook| notebook.id == id)
        .map(|notebook| notebook.name.clone())
        .unwrap_or_else(|| DEFAULT_NOTEBOOK_NAME.to_string())
}

/// The default notebook is the one container every client creates for itself, so
/// an unnamed one is that name rather than `Untitled`: two clients that disagreed
/// here showed the same notebook under two names.
fn fallback_notebook_name(id: &str) -> String {
    if id == default_notebook_id() {
        DEFAULT_NOTEBOOK_NAME.to_string()
    } else {
        UNTITLED_NOTEBOOK_NAME.to_string()
    }
}

fn declared_readable(object: &Map<String, Value>) -> bool {
    match object.get("version").and_then(Value::as_str) {
        Some(declared) => payload_schema_readable(declared),
        None => true,
    }
}

fn refuse_newer_major(previous: Option<&str>) -> Result<(), CoreError> {
    let Some(object) = previous.and_then(as_object) else {
        return Ok(());
    };
    if declared_readable(&object) {
        return Ok(());
    }
    Err(CoreError::PayloadSchema {
        declared: object
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    })
}

/// One `attachments` entry.
///
/// An entry missing any field needed to fetch and verify the bytes is dropped
/// rather than taken half-built: a malformed entry would otherwise surface as a
/// broken photo with no way to tell which. Dropping it is also a write, since the
/// array is rewritten from what was parsed, and that is the honest outcome for an
/// entry that cannot name its own bytes.
fn parse_attachment(value: &Value) -> Option<CoreNoteAttachment> {
    let object = value.as_object()?;
    let string = |key: &str| object.get(key).and_then(Value::as_str).map(ToOwned::to_owned);
    let number = |key: &str| object.get(key).and_then(Value::as_u64);

    let known = [
        "id",
        "filename",
        "mimeType",
        "byteSize",
        "width",
        "height",
        "adk",
        "contentHash",
        "chunkSize",
        "chunkCount",
        "displayWidth",
        "thumbnail",
    ];
    let extra: Map<String, Value> = object
        .iter()
        .filter(|(key, _)| !known.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    Some(CoreNoteAttachment {
        id: string("id")?,
        filename: string("filename").unwrap_or_else(|| "attachment".to_string()),
        mime_type: string("mimeType").unwrap_or_else(|| "application/octet-stream".to_string()),
        byte_size: number("byteSize").unwrap_or(0),
        width: number("width").map(|width| width as u32),
        height: number("height").map(|height| height as u32),
        adk: string("adk")?,
        content_hash: string("contentHash")?,
        chunk_size: number("chunkSize")? as u32,
        chunk_count: number("chunkCount")? as u32,
        display_width: number("displayWidth").map(|width| width as u32),
        thumbnail: string("thumbnail"),
        extra: Value::Object(extra).to_string(),
    })
}

fn parse_attachments(value: Option<&Value>) -> Vec<CoreNoteAttachment> {
    value
        .and_then(Value::as_array)
        .map(|entries| entries.iter().filter_map(parse_attachment).collect())
        .unwrap_or_default()
}

fn attachment_json(attachment: &CoreNoteAttachment) -> Value {
    let mut entry = match as_object(&attachment.extra) {
        Some(extra) => extra,
        None => Map::new(),
    };
    entry.insert("id".into(), json!(attachment.id));
    entry.insert("filename".into(), json!(attachment.filename));
    entry.insert("mimeType".into(), json!(attachment.mime_type));
    entry.insert("byteSize".into(), json!(attachment.byte_size));
    if let Some(width) = attachment.width {
        entry.insert("width".into(), json!(width));
    }
    if let Some(height) = attachment.height {
        entry.insert("height".into(), json!(height));
    }
    entry.insert("adk".into(), json!(attachment.adk));
    entry.insert("contentHash".into(), json!(attachment.content_hash));
    entry.insert("chunkSize".into(), json!(attachment.chunk_size));
    entry.insert("chunkCount".into(), json!(attachment.chunk_count));
    if let Some(width) = attachment.display_width {
        entry.insert("displayWidth".into(), json!(width));
    }
    if let Some(thumbnail) = &attachment.thumbnail {
        entry.insert("thumbnail".into(), json!(thumbnail));
    }
    Value::Object(entry)
}

/// Everything above, in the shapes the bindings can carry.
#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{CoreError, CoreNote, CoreNoteDraft, CoreNotebook};

    #[uniffi::export(name = "note_keys")]
    pub fn note_keys() -> Vec<String> {
        super::NOTE_KEYS.iter().map(|key| key.to_string()).collect()
    }

    #[uniffi::export(name = "notebook_keys")]
    pub fn notebook_keys() -> Vec<String> {
        super::NOTEBOOK_KEYS
            .iter()
            .map(|key| key.to_string())
            .collect()
    }

    #[uniffi::export(name = "default_notebook_id")]
    pub fn default_notebook_id() -> String {
        super::default_notebook_id()
    }

    #[uniffi::export(name = "resolve_notebook_id")]
    pub fn resolve_notebook_id(notebook_id: Option<String>) -> String {
        super::resolve_notebook_id(notebook_id)
    }

    #[uniffi::export(name = "note_parse")]
    pub fn note_parse(id: String, raw: String) -> CoreNote {
        super::note_parse(&id, &raw)
    }

    #[uniffi::export(name = "note_write")]
    pub fn note_write(draft: CoreNoteDraft, now: String) -> Result<String, CoreError> {
        super::note_write(&draft, &now)
    }

    #[uniffi::export(name = "notebook_parse")]
    pub fn notebook_parse(id: String, raw: String) -> CoreNotebook {
        super::notebook_parse(&id, &raw)
    }

    #[uniffi::export(name = "notebook_write")]
    pub fn notebook_write(
        name: String,
        previous_raw: Option<String>,
    ) -> Result<String, CoreError> {
        super::notebook_write(&name, previous_raw.as_deref())
    }

    #[uniffi::export(name = "notebook_name_by_id")]
    pub fn notebook_name_by_id(
        notebooks: Vec<CoreNotebook>,
        notebook_id: Option<String>,
    ) -> String {
        super::notebook_name_by_id(&notebooks, notebook_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: &str = "2026-10-28T12:00:00Z";

    fn draft() -> CoreNoteDraft {
        CoreNoteDraft {
            title: "Plan".into(),
            body: "line one\n".into(),
            notebook_id: default_notebook_id(),
            ..Default::default()
        }
    }

    fn written(draft: &CoreNoteDraft) -> Map<String, Value> {
        as_object(&note_write(draft, NOW).unwrap()).expect("an object")
    }

    #[test]
    fn a_new_note_takes_the_callers_clock_for_both_stamps() {
        let note = written(&draft());
        assert_eq!(note["createdAt"], NOW);
        assert_eq!(note["updatedAt"], NOW);
    }

    #[test]
    fn a_title_is_trimmed_and_a_body_is_not() {
        let note = written(&CoreNoteDraft {
            title: "  Plan  ".into(),
            body: "  kept  ".into(),
            ..draft()
        });
        assert_eq!(note["title"], "Plan");
        assert_eq!(note["body"], "  kept  ");
    }

    #[test]
    fn a_blank_notebook_resolves_to_the_default_every_account_has() {
        let note = written(&CoreNoteDraft {
            notebook_id: "   ".into(),
            ..draft()
        });
        assert_eq!(note["notebookId"], default_notebook_id());
    }

    #[test]
    fn a_top_level_note_carries_no_parent_key_at_all() {
        assert!(!written(&draft()).contains_key("parentId"));
        let note = written(&CoreNoteDraft {
            parent_id: Some("  ".into()),
            ..draft()
        });
        assert!(!note.contains_key("parentId"));
    }

    #[test]
    fn a_note_with_no_photos_carries_no_attachments_key_at_all() {
        assert!(!written(&draft()).contains_key("attachments"));
    }

    /// The divergence this phase exists for: the CLI's writer rebuilt the record
    /// from the three fields its command line takes, so every other field went.
    #[test]
    fn an_edit_carries_the_fields_the_editing_host_cannot_show() {
        let stored = r#"{"@type":"Note","version":"1.0","title":"old","body":"b",
            "notebookId":"00000000-0000-0000-0000-000000000002","parentId":"p1",
            "pinned":true,"somethingNewer":42}"#;
        let note = note_parse("n1", stored);
        let edited = written(&CoreNoteDraft {
            title: "new".into(),
            body: note.body.clone(),
            notebook_id: note.notebook_id.clone(),
            parent_id: note.parent_id.clone(),
            attachments: note.attachments.clone(),
            created_at: note.created_at.clone(),
            pinned: None,
            raw: Some(stored.to_string()),
        });
        assert_eq!(edited["title"], "new");
        assert_eq!(edited["parentId"], "p1");
        assert_eq!(edited["pinned"], true);
        assert_eq!(edited["somethingNewer"], 42);
    }

    #[test]
    fn a_host_with_an_opinion_about_pinned_writes_it_and_one_without_leaves_it() {
        let stored = r#"{"@type":"Note","pinned":true}"#;
        let unopinionated = written(&CoreNoteDraft {
            raw: Some(stored.into()),
            ..draft()
        });
        assert_eq!(unopinionated["pinned"], true);

        let unpinned = written(&CoreNoteDraft {
            pinned: Some(false),
            raw: Some(stored.into()),
            ..draft()
        });
        assert_eq!(unpinned["pinned"], false);
    }

    #[test]
    fn a_payload_that_will_not_parse_is_still_a_row_the_user_can_delete() {
        let note = note_parse("n1", "not json at all");
        assert_eq!(note.title, UNREADABLE_NOTE_TITLE);
        assert_eq!(note.body, "not json at all");
        assert_eq!(note.notebook_id, default_notebook_id());
    }

    #[test]
    fn a_note_with_no_title_is_listed_under_one() {
        assert_eq!(note_parse("n1", "{}").title, UNTITLED_NOTE_TITLE);
        assert_eq!(
            note_parse("n1", r#"{"title":"  "}"#).title,
            UNTITLED_NOTE_TITLE
        );
    }

    /// Android's `optString` coerced a non-string body to its own rendering of
    /// it, where the web read an empty string. Only a JSON string is a body.
    #[test]
    fn a_body_that_is_not_a_string_reads_as_empty() {
        assert_eq!(note_parse("n1", r#"{"body":42}"#).body, "");
        assert_eq!(note_parse("n1", r#"{"body":null}"#).body, "");
    }

    #[test]
    fn a_newer_schema_major_is_read_but_not_written_over() {
        let stored = r#"{"@type":"Note","version":"2.0","title":"future"}"#;
        let note = note_parse("n1", stored);
        assert_eq!(note.title, "future");
        assert!(!note.readable);

        let refused = note_write(
            &CoreNoteDraft {
                raw: Some(stored.into()),
                ..draft()
            },
            NOW,
        );
        assert!(matches!(
            refused,
            Err(CoreError::PayloadSchema { ref declared }) if declared == "2.0"
        ));
    }

    #[test]
    fn a_minor_within_this_major_is_both_read_and_written() {
        let stored = r#"{"@type":"Note","version":"1.9","title":"t"}"#;
        assert!(note_parse("n1", stored).readable);
        assert!(note_write(
            &CoreNoteDraft {
                raw: Some(stored.into()),
                ..draft()
            },
            NOW
        )
        .is_ok());
    }

    fn attachment() -> Value {
        json!({
            "id": "a1",
            "filename": "photo.jpg",
            "mimeType": "image/jpeg",
            "byteSize": 1234,
            "adk": "QUJD",
            "contentHash": "REVG",
            "chunkSize": 4194304,
            "chunkCount": 1,
        })
    }

    #[test]
    fn an_attachment_round_trips_through_the_record() {
        let stored = json!({ "@type": "Note", "attachments": [attachment()] }).to_string();
        let note = note_parse("n1", &stored);
        assert_eq!(note.attachments.len(), 1);
        assert_eq!(note.attachments[0].filename, "photo.jpg");

        let again = written(&CoreNoteDraft {
            attachments: note.attachments.clone(),
            raw: Some(stored),
            ..draft()
        });
        assert_eq!(again["attachments"][0], attachment());
    }

    /// The degrade-invisibly rule, one level in: a key inside an entry that this
    /// build does not know is put back, not dropped on the next edit.
    #[test]
    fn a_key_inside_an_attachment_entry_survives_a_rewrite() {
        let mut entry = attachment();
        entry["caption"] = json!("from a newer build");
        let stored = json!({ "@type": "Note", "attachments": [entry] }).to_string();
        let note = note_parse("n1", &stored);
        let again = written(&CoreNoteDraft {
            attachments: note.attachments.clone(),
            raw: Some(stored),
            ..draft()
        });
        assert_eq!(again["attachments"][0]["caption"], "from a newer build");
    }

    #[test]
    fn an_attachment_that_cannot_name_its_own_bytes_is_dropped() {
        let mut entry = attachment();
        entry.as_object_mut().unwrap().remove("adk");
        let stored = json!({ "@type": "Note", "attachments": [entry, attachment()] }).to_string();
        assert_eq!(note_parse("n1", &stored).attachments.len(), 1);
    }

    #[test]
    fn a_notebook_rename_carries_what_it_does_not_own() {
        let stored = r#"{"@type":"Notebook","version":"1.0","name":"old","colour":"blue"}"#;
        let renamed = as_object(&notebook_write("  new  ", Some(stored)).unwrap()).unwrap();
        assert_eq!(renamed["name"], "new");
        assert_eq!(renamed["colour"], "blue");
    }

    /// Two clients disagreed here, so one notebook listed under two names.
    #[test]
    fn an_unnamed_default_notebook_is_the_default_name_and_any_other_is_untitled() {
        assert_eq!(
            notebook_parse(&default_notebook_id(), "{}").name,
            DEFAULT_NOTEBOOK_NAME
        );
        assert_eq!(
            notebook_parse("77777777-7777-4777-8777-777777777777", "not json").name,
            UNTITLED_NOTEBOOK_NAME
        );
    }

    #[test]
    fn a_note_in_a_notebook_that_is_gone_shows_the_default_notebooks_name() {
        let notebooks = vec![notebook_parse(
            &default_notebook_id(),
            r#"{"name":"Mine"}"#,
        )];
        assert_eq!(notebook_name_by_id(&notebooks, None), "Mine");
        assert_eq!(
            notebook_name_by_id(&notebooks, Some("missing".into())),
            DEFAULT_NOTEBOOK_NAME
        );
    }
}
