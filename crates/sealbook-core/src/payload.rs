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
    let upgraded = upgraded_previous(previous, &fields);
    let mut merged = carried(upgraded.as_deref().or(previous), owned);
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
    natural_json(&Value::Object(merged))
}

/// `previous` upgraded to the schema this write stamps, so a key the writer no
/// longer owns is not carried through and the old shape does not survive every
/// save. A Card is left alone: its writer owns the legacy keys and clears them.
fn upgraded_previous(previous: Option<&str>, fields: &Value) -> Option<String> {
    let tag = fields
        .get("@type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let kind = payload_kind("", &serde_json::json!({ "@type": tag }).to_string());
    if kind == CorePayloadKind::Contact {
        return None;
    }
    let mut object = as_object(previous?)?;
    upgrade_object(kind, &mut object).then(|| Value::Object(object).to_string())
}

/// Compact JSON with each object's keys in natural order, so `e2` precedes
/// `e10`. Clients that predate core read numbered entries in file order, and
/// for keys without digits this is the sorted order `to_string` gives.
pub(crate) fn natural_json(value: &Value) -> String {
    match value {
        Value::Object(object) => {
            let mut entries: Vec<_> = object.iter().collect();
            entries.sort_by(|(a, _), (b, _)| natural_cmp(a, b));
            let body: Vec<String> = entries
                .into_iter()
                .map(|(key, value)| {
                    format!("{}:{}", Value::from(key.as_str()), natural_json(value))
                })
                .collect();
            format!("{{{}}}", body.join(","))
        }
        Value::Array(items) => {
            let body: Vec<String> = items.iter().map(natural_json).collect();
            format!("[{}]", body.join(","))
        }
        scalar => scalar.to_string(),
    }
}

fn natural_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let (a_bytes, b_bytes) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    while i < a_bytes.len() && j < b_bytes.len() {
        if a_bytes[i].is_ascii_digit() && b_bytes[j].is_ascii_digit() {
            let run = |bytes: &[u8], start: usize| {
                start
                    + bytes[start..]
                        .iter()
                        .take_while(|b| b.is_ascii_digit())
                        .count()
            };
            let (a_end, b_end) = (run(a_bytes, i), run(b_bytes, j));
            let trim = |digits: &[u8]| {
                let zeros = digits.iter().take_while(|&&d| d == b'0').count();
                digits[zeros..].to_vec()
            };
            let (x, y) = (trim(&a_bytes[i..a_end]), trim(&b_bytes[j..b_end]));
            let order = x.len().cmp(&y.len()).then_with(|| x.cmp(&y));
            if order.is_ne() {
                return order;
            }
            (i, j) = (a_end, b_end);
        } else {
            let order = a_bytes[i].cmp(&b_bytes[j]);
            if order.is_ne() {
                return order;
            }
            (i, j) = (i + 1, j + 1);
        }
    }
    (a_bytes.len() - i)
        .cmp(&(b_bytes.len() - j))
        .then_with(|| a.cmp(b))
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

/// Sets `createdAt` and `updatedAt` on a write: `createdAt` is what the stored
/// payload holds, else `now`, and `updatedAt` is always `now`. Core has no clock,
/// so the caller's is the only one there is.
pub(crate) fn stamp(fields: &mut Map<String, Value>, previous: Option<&str>, now: &str) {
    let created = previous
        .and_then(as_object)
        .and_then(|stored| trimmed(&stored, "createdAt"))
        .unwrap_or_else(|| now.to_string());
    fields.insert("createdAt".into(), Value::String(created));
    fields.insert("updatedAt".into(), Value::String(now.to_string()));
}

/// A parsed payload read as the current schema, so a record looks the same
/// whichever shape is stored: an event with no calendar is in the default one.
/// The stored text is untouched; only the read is.
pub(crate) fn upgraded(
    kind: CorePayloadKind,
    object: Option<Map<String, Value>>,
) -> Option<Map<String, Value>> {
    let mut object = object?;
    upgrade_object(kind, &mut object);
    Some(object)
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
    DeviceLabel,
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
        (crate::devices::DEVICE_LABEL_CONTENT_TYPE, DeviceLabel),
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
        Some("DeviceLabel") => DeviceLabel,
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

/// The Card property that holds Sealbook's schema version. A Card's own
/// `version` is RFC 9553's JSContact version and stays `"1.0"`.
pub const CARD_SCHEMA_PROP: &str = "sealbook:version";

/// The schema version a payload declares: a Card's `sealbook:version`, falling
/// back to its `version` for a Card written before that property existed, and
/// `version` for every other type.
pub(crate) fn declared_version(object: &Map<String, Value>) -> Option<&str> {
    if object.get("@type").and_then(Value::as_str) == Some("Card") {
        if let Some(declared) = object.get(CARD_SCHEMA_PROP).and_then(Value::as_str) {
            return Some(declared);
        }
    }
    object.get("version").and_then(Value::as_str)
}

/// Whether this build reads the schema major a payload declares.
///
/// A payload with no version at all is read: the field was added after the
/// first release, and absence means the generation this build speaks.
pub(crate) fn declared_readable(object: &Map<String, Value>) -> bool {
    match declared_version(object) {
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
        declared: declared_version(&object)
            .map(ToOwned::to_owned)
            .unwrap_or_default(),
    })
}

/// The key a payload of this kind names its container under, for the kinds that
/// live in one. The names stay per type; this is the one place that says so.
pub(crate) fn container_key_of(kind: CorePayloadKind) -> Option<&'static str> {
    use CorePayloadKind::*;
    match kind {
        Contact => Some(sealbook_protocol::ADDRESS_BOOK_ID_PROP),
        CalendarEvent => Some("calendarId"),
        Note => Some("notebookId"),
        Task => Some("taskListId"),
        Bookmark => Some("collectionId"),
        _ => None,
    }
}

/// [`container_key_of`] for a stored content type.
pub fn container_key(content_type: &str) -> Option<&'static str> {
    container_key_of(payload_kind(content_type, ""))
}

/// Whether a payload declares the generation [`upgrade`] moves forward: `1.0`,
/// or nothing at all.
pub(crate) fn declares_legacy(object: &Map<String, Value>) -> bool {
    match declared_version(object) {
        None => true,
        Some(declared) => declared
            .split_once('.')
            .is_some_and(|(major, minor)| major == "1" && minor == "0"),
    }
}

/// Moves a `1.0` payload to `1.1` in place, for every kind but a Card.
///
/// Pure and idempotent: a payload already at `1.1`, from a later major, or of a
/// kind core does not know comes back untouched. Three things change. An event
/// with no calendar goes into the default one. A stored `favorite: false` goes,
/// since a flag is written only when true. And the version moves.
///
/// A Card is not handled here: its legacy keys are converted by a round trip
/// through the card parser and writer, in [`upgrade`].
pub(crate) fn upgrade_object(kind: CorePayloadKind, object: &mut Map<String, Value>) -> bool {
    use CorePayloadKind::*;
    if matches!(kind, Contact | Unknown) || !declares_legacy(object) {
        return false;
    }
    if kind == CalendarEvent && trimmed(object, "calendarId").is_none() {
        object.insert(
            "calendarId".into(),
            Value::String(sealbook_protocol::DEFAULT_CALENDAR_ID.to_string()),
        );
    }
    if object.get("favorite") == Some(&Value::Bool(false)) {
        object.remove("favorite");
    }
    object.insert(
        "version".into(),
        Value::String(sealbook_protocol::PAYLOAD_SCHEMA_VERSION.into()),
    );
    true
}

/// A stored payload moved to the current schema, or `None` when there is
/// nothing to move: not an object, a content type core does not know, already current,
/// or from a major this build does not read.
///
/// Pure and idempotent. Keys core does not model survive.
pub fn upgrade(content_type: &str, raw: &str) -> Option<String> {
    let mut object = as_object(raw)?;
    // By the content type alone: it is the authenticated one, and a payload's own
    // `@type` must not pick how an object of some other type is rewritten.
    let kind = payload_kind(content_type, "");
    if kind == CorePayloadKind::Contact {
        return crate::contacts::contact_upgrade(&object, raw);
    }
    upgrade_object(kind, &mut object).then(|| natural_json(&Value::Object(object)))
}

#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::CorePayloadKind;

    #[uniffi::export(name = "payload_kind")]
    pub fn payload_kind(content_type: String, raw: String) -> CorePayloadKind {
        super::payload_kind(&content_type, &raw)
    }

    /// A payload moved to the current schema, or `None` when it already is one or
    /// is not one core knows how to move.
    #[uniffi::export(name = "payload_upgrade")]
    pub fn payload_upgrade(content_type: String, raw: String) -> Option<String> {
        super::upgrade(&content_type, &raw)
    }

    /// The payload key that names an object's container, for a content type that
    /// has one.
    #[uniffi::export(name = "container_key")]
    pub fn container_key(content_type: String) -> Option<String> {
        super::container_key(&content_type).map(str::to_string)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbered_keys_are_written_in_number_order() {
        let written = write_payload(
            None,
            serde_json::json!({ "emails": { "e10": 10, "e2": 2, "e1": 1 }, "@type": "Card", "a": [{ "x11": 0, "x9": 0 }] }),
            &["emails", "@type", "a"],
        );
        assert_eq!(
            written,
            r#"{"@type":"Card","a":[{"x9":0,"x11":0}],"emails":{"e1":1,"e2":2,"e10":10}}"#
        );
    }

    #[test]
    fn keys_without_differing_numbers_keep_sorted_order() {
        let keys = [
            "", "a", "a1", "a1b", "ab", "B", "b2", "e01", "e1", "@type", "é", "zz",
        ];
        for a in keys {
            for b in keys {
                if a.bytes().filter(u8::is_ascii_digit).count() < 2
                    && b.bytes().filter(u8::is_ascii_digit).count() < 2
                {
                    assert_eq!(natural_cmp(a, b), a.cmp(b), "{a} vs {b}");
                }
            }
        }
        assert_eq!(natural_cmp("e1", "e01"), std::cmp::Ordering::Greater);
    }

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
