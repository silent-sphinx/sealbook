//! The account export document: the whole vault as one JSON file, and the rules
//! for reading one back.
//!
//! The CLI, the web and Android each wrote this document and only the CLI and
//! the web read it. They agreed on the envelope and differed inside it.
//!
//! **A payload is JSON or it is text.** Any value that parses goes out as
//! `payload`, a scalar included; the Android writer carried only objects and
//! arrays, so a bare number came out as `text` there and `payload` elsewhere. A
//! payload that is the JSON `null` goes out as `text`, because a reader treats
//! a null `payload` as absent and refused the file.
//!
//! **Ids are canonical.** An id is read in its hyphenated form, either case, and
//! written lowercase.
//!
//! **Order is fixed.** Objects are sorted by content type then id, byte for
//! byte, and keys are sorted by the serialiser, so two exports of an unchanged
//! vault are the same bytes whichever client wrote them.
//!
//! **A short backup says so.** `unreadable` is written when a device could not
//! open some objects and read back so an import can report that it is not a
//! complete restore.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::CoreError;
use sealbook_protocol::{ACCOUNT_EXPORT_TYPE, ACCOUNT_EXPORT_VERSION};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreExportAccount {
    pub server: String,
    pub username: String,
    pub account_id: String,
    pub collection_id: String,
    pub device_id: String,
}

/// One object as a vault holds it: `payload` is the plaintext as stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreExportObject {
    pub id: String,
    pub content_type: String,
    pub payload: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreAccountImport {
    /// In file order, ids lowercased, each payload the text that goes back.
    pub objects: Vec<CoreExportObject>,
    /// The account the file was written from, for the line an import reports.
    pub source: String,
    /// Objects the exporting device could not open.
    pub unreadable: u32,
}

/// The document, pretty-printed with two spaces.
pub fn account_export_write(
    account: &CoreExportAccount,
    objects: &[CoreExportObject],
    unreadable: u32,
    exported_at: &str,
) -> String {
    let mut sorted: Vec<(String, &CoreExportObject)> = objects
        .iter()
        .map(|object| (canonical_id(&object.id), object))
        .collect();
    sorted.sort_by(|(a_id, a), (b_id, b)| {
        a.content_type
            .cmp(&b.content_type)
            .then_with(|| a_id.cmp(b_id))
    });

    let entries: Vec<Value> = sorted
        .into_iter()
        .map(|(id, object)| {
            let mut entry = Map::new();
            entry.insert("id".into(), id.into());
            entry.insert("contentType".into(), object.content_type.clone().into());
            match serde_json::from_str::<Value>(&object.payload) {
                Ok(payload) if !payload.is_null() => entry.insert("payload".into(), payload),
                _ => entry.insert("text".into(), object.payload.clone().into()),
            };
            Value::Object(entry)
        })
        .collect();

    let mut document = json!({
        "@type": ACCOUNT_EXPORT_TYPE,
        "version": ACCOUNT_EXPORT_VERSION,
        "exportedAt": exported_at,
        "account": {
            "server": account.server,
            "username": account.username,
            "accountId": account.account_id,
            "collectionId": account.collection_id,
            "deviceId": account.device_id,
        },
        "objectCount": entries.len(),
        "objects": entries,
    });
    if unreadable > 0 {
        document["unreadable"] = unreadable.into();
    }
    serde_json::to_string_pretty(&document).expect("a JSON value always serialises")
}

/// Reads an export document, refusing one that cannot be restored faithfully.
///
/// A payload is carried as the file writes it, so a field this build does not
/// know survives the round trip, and `text` comes back as those same bytes. A
/// newer minor version is accepted, since the format only gains fields and
/// objects go back untouched either way; a newer major is refused, because the
/// meaning of what is already there may have changed.
pub fn account_export_parse(document: &str) -> Result<CoreAccountImport, CoreError> {
    let Ok(Value::Object(document)) = serde_json::from_str::<Value>(document) else {
        return Err(CoreError::malformed("This is not a JSON document."));
    };
    if document.get("@type").and_then(Value::as_str) != Some(ACCOUNT_EXPORT_TYPE) {
        return Err(CoreError::malformed(
            "This is not a Sealbook account export file.",
        ));
    }
    let Some(version) = document.get("version").and_then(Value::as_str) else {
        return Err(CoreError::malformed("The file has no version."));
    };
    let major = |value: &str| value.split('.').next().unwrap_or_default().to_string();
    if major(version) != major(ACCOUNT_EXPORT_VERSION) {
        return Err(CoreError::malformed(format!(
            "The file is version {version} and this app reads {ACCOUNT_EXPORT_VERSION}. \
             Update whichever is older."
        )));
    }
    let Some(entries) = document.get("objects").and_then(Value::as_array) else {
        return Err(CoreError::malformed("The file has no objects."));
    };

    let mut objects = Vec::with_capacity(entries.len());
    let mut seen = std::collections::HashSet::new();
    for (index, entry) in entries.iter().enumerate() {
        let position = index + 1;
        let Value::Object(entry) = entry else {
            return Err(CoreError::malformed(format!(
                "Object {position} is not an object."
            )));
        };
        let id = entry
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| id.len() == 36)
            .and_then(|id| Uuid::parse_str(id).ok())
            .ok_or_else(|| {
                CoreError::malformed(format!("Object {position} has an id that is not a UUID."))
            })?;
        if !seen.insert(id) {
            return Err(CoreError::malformed(format!(
                "Object {position} repeats id {id}."
            )));
        }
        let content_type = match entry.get("contentType").and_then(Value::as_str) {
            Some(content_type) if !content_type.is_empty() => content_type.to_string(),
            _ => {
                return Err(CoreError::malformed(format!(
                    "Object {id} has no contentType."
                )))
            }
        };
        let payload = match entry.get("payload") {
            None | Some(Value::Null) => match entry.get("text").and_then(Value::as_str) {
                Some(text) => text.to_string(),
                None => {
                    return Err(CoreError::malformed(format!(
                        "Object {id} has neither a payload nor text."
                    )))
                }
            },
            Some(payload) => payload.to_string(),
        };
        objects.push(CoreExportObject {
            id: id.to_string(),
            content_type,
            payload,
        });
    }

    let account = document.get("account").and_then(Value::as_object);
    let field = |key: &str| account.and_then(|account| account.get(key)?.as_str());
    let source = match (field("username"), field("server")) {
        (Some(username), Some(server)) => format!("{username} at {server}"),
        _ => "an export with no account block".to_string(),
    };
    let unreadable = document
        .get("unreadable")
        .and_then(Value::as_u64)
        .map_or(0, |count| count.min(u64::from(u32::MAX)) as u32);
    Ok(CoreAccountImport {
        objects,
        source,
        unreadable,
    })
}

/// A filename carrying the account and the day, safe on every filesystem. The
/// day is the host's, since core has no clock.
pub fn account_export_filename(username: &str, day: &str) -> String {
    let mut slug = String::new();
    for c in username.to_lowercase().chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            slug.push(c);
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug = slug.trim_matches('-');
    let slug = if slug.is_empty() { "export" } else { slug };
    format!("sealbook-account-{slug}-{day}.json")
}

#[cfg(feature = "uniffi")]
pub mod ffi {
    use crate::{CoreAccountImport, CoreError, CoreExportAccount, CoreExportObject};

    #[uniffi::export(name = "account_export_write")]
    pub fn account_export_write(
        account: CoreExportAccount,
        objects: Vec<CoreExportObject>,
        unreadable: u32,
        exported_at: String,
    ) -> String {
        super::account_export_write(&account, &objects, unreadable, &exported_at)
    }

    #[uniffi::export(name = "account_export_parse")]
    pub fn account_export_parse(document: String) -> Result<CoreAccountImport, CoreError> {
        super::account_export_parse(&document)
    }

    #[uniffi::export(name = "account_export_filename")]
    pub fn account_export_filename(username: String, day: String) -> String {
        super::account_export_filename(&username, &day)
    }
}

/// The id as written: lowercase hyphenated when it parses, otherwise as given,
/// so a vault object with an odd id is still in the backup.
fn canonical_id(id: &str) -> String {
    Uuid::parse_str(id).map_or_else(|_| id.to_string(), |id| id.to_string())
}
