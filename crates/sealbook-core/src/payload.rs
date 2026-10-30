//! Writing a content payload, and reading one leniently.
//!
//! This is the layer the server never sees. Objects are sealed before they
//! leave, so the content type string is all it knows and no server check
//! catches a client that writes a key the others do not read. Every other phase
//! has a wire check behind it; this one has only the fixtures.
//!
//! Two rules hold for every type that moves here. A payload is written through
//! [`write_payload`], so a field this build does not own survives an edit. And
//! an optional value that is absent is omitted rather than written null, so a
//! reader predating the field sees the shape it expects.
//!
//! [`write_payload`] differs from `sealbook_protocol::merge_payload` in one
//! way, and it is the reason it exists: it filters the fields it is handed down
//! to the owned keys first. `owned` governs only which of the *previous*
//! payload's keys are dropped, so a caller that passes an extra field writes it
//! into the plaintext under the old function. A writer in core takes its fields
//! from a typed record, and the filter is what makes "the owned keys are the
//! keys this type writes" true of the output rather than of the caller.

use serde_json::{Map, Value};

use crate::CoreError;
use sealbook_protocol::payload_schema_readable;

/// Serialises a payload: the owned fields this write names, over whatever of
/// `previous` this build does not own.
pub fn write_payload(previous: Option<&str>, fields: Value, owned: &[&str]) -> String {
    let mut merged = carried(previous, owned);
    if let Some(fields) = fields.as_object() {
        for (key, value) in fields {
            if owned.contains(&key.as_str()) {
                merged.insert(key.clone(), value.clone());
            }
        }
    }
    if let Some(previous) = higher_version(previous, &merged) {
        merged.insert("version".into(), Value::String(previous));
    }
    Value::Object(merged).to_string()
}

/// The version `previous` declares, when it is a later minor of the major this
/// write stamps: a save must not claim an older schema than the keys it carries.
fn higher_version(previous: Option<&str>, merged: &Map<String, Value>) -> Option<String> {
    let declared = as_object(previous?)?.get("version")?.as_str()?.to_string();
    let stamped = merged.get("version")?.as_str()?;
    let pair = |text: &str| -> Option<(u32, u32)> {
        let (major, minor) = text.split_once('.')?;
        Some((major.parse().ok()?, minor.parse().ok()?))
    };
    let (declared_pair, stamped_pair) = (pair(&declared)?, pair(stamped)?);
    (declared_pair.0 == stamped_pair.0 && declared_pair.1 > stamped_pair.1).then_some(declared)
}

fn carried(previous: Option<&str>, owned: &[&str]) -> Map<String, Value> {
    let Some(previous) = previous else {
        return Map::new();
    };
    let Ok(Value::Object(object)) = serde_json::from_str::<Value>(previous) else {
        return Map::new();
    };
    object
        .into_iter()
        .filter(|(key, _)| !owned.contains(&key.as_str()))
        .collect()
}

/// A string field, trimmed, or `None` where it is absent, not a string, or
/// empty once trimmed.
///
/// Every reader here is lenient by design: a payload from a newer build, or one
/// that is not JSON at all, has to render as something the user can find and
/// delete rather than taking a whole list down with it.
pub(crate) fn trimmed(object: &Map<String, Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|found| !found.is_empty())
        .map(ToOwned::to_owned)
}

/// A string field as stored, with no trimming and no emptiness check. For a
/// field whose whitespace is the user's, such as a note body.
pub(crate) fn text(object: &Map<String, Value>, key: &str) -> String {
    object
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// The entry's keys outside `known`, as a JSON object, or `None` when there are none.
pub(crate) fn extra_of(entry: &Map<String, Value>, known: &[&str]) -> Option<String> {
    let extra: Map<String, Value> = entry
        .iter()
        .filter(|(key, _)| !known.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    (!extra.is_empty()).then(|| Value::Object(extra).to_string())
}

/// A new entry seeded with the keys `extra` carried, for the writer to set its own over.
pub(crate) fn entry_with(extra: &Option<String>) -> Map<String, Value> {
    extra.as_deref().and_then(as_object).unwrap_or_default()
}

pub(crate) fn as_object(raw: &str) -> Option<Map<String, Value>> {
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Object(object)) => Some(object),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum CorePayloadKind {
    Contact,
    AddressBook,
    CalendarEvent,
    Calendar,
    Note,
    Notebook,
    Bookmark,
    BookmarkCollection,
    Task,
    TaskList,
    AccountSettings,
    Unknown,
}

/// Which payload type an opened object is.
///
/// The content type wins when it names a type, then the `@type` tag. An untagged
/// payload with an object `name` is a legacy contact; anything else is
/// `Unknown`, so a future type is skipped rather than rendered and overwritten
/// as a contact.
pub fn payload_kind(content_type: &str, raw: &str) -> CorePayloadKind {
    use sealbook_protocol::{
        ADDRESS_BOOK_CONTENT_TYPE, BOOKMARK_COLLECTION_CONTENT_TYPE, BOOKMARK_CONTENT_TYPE,
        CALENDAR_CONTENT_TYPE, CALENDAR_EVENT_CONTENT_TYPE, JSCONTACT_CONTENT_TYPE,
        NOTEBOOK_CONTENT_TYPE, NOTE_CONTENT_TYPE, TASK_CONTENT_TYPE, TASK_LIST_CONTENT_TYPE,
    };
    use CorePayloadKind::*;
    let by_content_type = [
        (JSCONTACT_CONTENT_TYPE, Contact),
        (CALENDAR_EVENT_CONTENT_TYPE, CalendarEvent),
        (CALENDAR_CONTENT_TYPE, Calendar),
        (ADDRESS_BOOK_CONTENT_TYPE, AddressBook),
        (NOTE_CONTENT_TYPE, Note),
        (NOTEBOOK_CONTENT_TYPE, Notebook),
        (BOOKMARK_CONTENT_TYPE, Bookmark),
        (BOOKMARK_COLLECTION_CONTENT_TYPE, BookmarkCollection),
        (TASK_CONTENT_TYPE, Task),
        (TASK_LIST_CONTENT_TYPE, TaskList),
        (
            crate::settings::ACCOUNT_SETTINGS_CONTENT_TYPE,
            AccountSettings,
        ),
    ];
    if let Some((_, kind)) = by_content_type
        .iter()
        .find(|(name, _)| *name == content_type)
    {
        return *kind;
    }
    let object = as_object(raw);
    match object
        .as_ref()
        .and_then(|o| o.get("@type"))
        .and_then(Value::as_str)
    {
        Some("CalendarEvent") => CalendarEvent,
        Some("Calendar") => Calendar,
        Some("AddressBook") => AddressBook,
        Some("Note") => Note,
        Some("Notebook") => Notebook,
        Some("Bookmark") => Bookmark,
        Some("BookmarkCollection") => BookmarkCollection,
        Some("Task") => Task,
        Some("TaskList") => TaskList,
        Some("AccountSettings") => AccountSettings,
        Some("Card") => Contact,
        Some(_) => Unknown,
        None if object
            .as_ref()
            .is_some_and(|o| o.get("name").is_some_and(Value::is_object)) =>
        {
            Contact
        }
        None => Unknown,
    }
}

/// Whether this build reads the schema major a payload declares.
///
/// A payload with no `version` at all is read: the field was added after the
/// first release, and absence means the generation this build speaks.
pub(crate) fn declared_readable(object: &Map<String, Value>) -> bool {
    match object.get("version").and_then(Value::as_str) {
        Some(declared) => payload_schema_readable(declared),
        None => true,
    }
}

/// Refuses a write over a payload from a schema major this build does not read.
///
/// Carrying unknown keys through is enough for a field that was added; it is not
/// enough for one whose meaning changed, which is the case this check exists
/// for. Every payload type in core calls it before it writes, which is what
/// gave the check a caller: all three clients carried a copy and none of them
/// ran it.
pub(crate) fn refuse_newer_major(previous: Option<&str>) -> Result<(), CoreError> {
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

#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::CorePayloadKind;

    #[uniffi::export(name = "payload_kind")]
    pub fn payload_kind(content_type: String, raw: String) -> CorePayloadKind {
        super::payload_kind(&content_type, &raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_content_type_then_the_tag_then_the_legacy_shape_names_the_kind() {
        use CorePayloadKind::*;
        let kind = |content_type: &str, raw: &str| payload_kind(content_type, raw);
        assert_eq!(kind("application/sealbook.note+json", "{}"), Note);
        assert_eq!(kind("application/jscontact+json", "{}"), Contact);
        assert_eq!(kind("", r#"{"@type":"TaskList"}"#), TaskList);
        assert_eq!(kind("", r#"{"@type":"Card"}"#), Contact);
        assert_eq!(kind("", r#"{"name":{"full":"Ada"}}"#), Contact);
        assert_eq!(kind("", r#"{"name":"Ada"}"#), Unknown);
        assert_eq!(kind("", r#"{"@type":"Hologram","name":{}}"#), Unknown);
        assert_eq!(kind("", "not json"), Unknown);
    }

    const OWNED: &[&str] = &["@type", "title"];

    fn parsed(json: &str) -> Map<String, Value> {
        match serde_json::from_str::<Value>(json).unwrap() {
            Value::Object(object) => object,
            other => panic!("not an object: {other}"),
        }
    }

    #[test]
    fn a_field_this_build_does_not_own_survives_a_write() {
        let previous = r#"{"@type":"Note","title":"old","pinned":true}"#;
        let written = parsed(&write_payload(
            Some(previous),
            serde_json::json!({ "@type": "Note", "title": "new" }),
            OWNED,
        ));
        assert_eq!(written["title"], "new");
        assert_eq!(written["pinned"], true);
    }

    #[test]
    fn a_save_keeps_a_later_minor_and_never_lowers_a_version() {
        let fields = |version: &str| serde_json::json!({ "@type": "Note", "version": version });
        let written = |previous: &str, stamped: &str| {
            parsed(&write_payload(
                Some(previous),
                fields(stamped),
                &["@type", "version"],
            ))["version"]
                .clone()
        };
        assert_eq!(written(r#"{"version":"1.7"}"#, "1.0"), "1.7");
        assert_eq!(written(r#"{"version":"1.0"}"#, "1.2"), "1.2");
        assert_eq!(written(r#"{"version":"0.9"}"#, "1.0"), "1.0");
        assert_eq!(written(r#"{"version":"junk"}"#, "1.0"), "1.0");
        assert_eq!(written(r#"{}"#, "1.0"), "1.0");
    }

    #[test]
    fn an_owned_field_this_write_omits_is_cleared_rather_than_carried() {
        let previous = r#"{"@type":"Note","title":"old"}"#;
        let written = parsed(&write_payload(
            Some(previous),
            serde_json::json!({ "@type": "Note" }),
            OWNED,
        ));
        assert!(!written.contains_key("title"));
    }

    /// The whole reason this is not `merge_payload`: a caller handing the writer
    /// a field outside the owned set used to have it written into the plaintext,
    /// where no other client would ever read it and the next edit from a build
    /// with a different caller would drop it.
    #[test]
    fn a_field_outside_the_owned_set_is_not_written_even_when_it_is_handed_over() {
        let written = parsed(&write_payload(
            None,
            serde_json::json!({ "@type": "Note", "title": "t", "id": "leaked" }),
            OWNED,
        ));
        assert!(!written.contains_key("id"));
    }

    #[test]
    fn a_previous_payload_that_is_not_an_object_carries_nothing() {
        for previous in ["", "not json", "[1,2]", "null", "\"text\""] {
            let written = parsed(&write_payload(
                Some(previous),
                serde_json::json!({ "@type": "Note" }),
                OWNED,
            ));
            assert_eq!(written.len(), 1, "carried something from {previous:?}");
        }
    }
}
