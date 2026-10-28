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
    Value::Object(merged).to_string()
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

pub(crate) fn as_object(raw: &str) -> Option<Map<String, Value>> {
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Object(object)) => Some(object),
        _ => None,
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

#[cfg(test)]
mod tests {
    use super::*;

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
