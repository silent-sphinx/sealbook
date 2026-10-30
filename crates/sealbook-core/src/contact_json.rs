//! Import of contacts from a JSON file: one card, a list of cards, or a
//! `{"contacts": [...]}` backup.

use serde_json::{Map, Value};

use crate::contacts::{resolve_address_book_id, CoreContactDraft};
use crate::csv::csv_import;
use crate::csv::{address_of, channel_of, date_of, social_of, text, work_of};
use crate::vcard::{vcard_import, CoreContactImport, CoreContactSkipped, NO_NAME};
use crate::CoreError;
use serde::{Deserialize, Serialize};

/// Most cards one import may carry.
pub const MAX_IMPORTED_CONTACTS: usize = 1_000;
/// Most entries kept from any one list on a card.
pub const MAX_CONTACT_LIST_ITEMS: usize = 100;
const MAX_FIELD_CHARS: usize = 100_000;
/// Largest file an import will read, in bytes.
pub const MAX_IMPORT_BYTES: usize = 5 * 1024 * 1024;

/// The cards in a contacts file, and which format the file was read as.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreContactFile {
    /// `JSON`, `vCard` or `CSV`.
    pub format: String,
    pub contacts: Vec<crate::contacts::CoreContactDraft>,
    pub skipped: Vec<CoreContactSkipped>,
}

/// Reads a contacts file in whichever of JSON, vCard or CSV it holds: JSON when
/// the name ends in `.json` or the text opens with a bracket and yields cards,
/// then vCard on a `.vcf` name or a card in the text, otherwise CSV.
pub fn contacts_import(
    filename: &str,
    text: &str,
    address_book_id: &str,
) -> Result<CoreContactFile, CoreError> {
    if text.len() > MAX_IMPORT_BYTES {
        return Err(CoreError::malformed(
            "Import file is too large (maximum 5 MB).",
        ));
    }
    let text = text.trim();
    let name = filename.to_lowercase();
    let file = |format: &str, read: CoreContactImport| -> Result<CoreContactFile, CoreError> {
        if read.contacts.len() > MAX_IMPORTED_CONTACTS {
            return Err(CoreError::malformed(
                "Import contains too many contacts (maximum 1,000).",
            ));
        }
        Ok(CoreContactFile {
            format: format.to_string(),
            contacts: read.contacts,
            skipped: read.skipped,
        })
    };

    if name.ends_with(".json") || text.starts_with('[') || text.starts_with('{') {
        let read = json_import(text, address_book_id)?;
        if !read.contacts.is_empty() {
            return file("JSON", read);
        }
    }
    if name.ends_with(".vcf") || text.to_uppercase().contains("BEGIN:VCARD") {
        let read = vcard_import(text, address_book_id);
        if !read.contacts.is_empty() {
            return file("vCard", read);
        }
    }
    file("CSV", csv_import(text, address_book_id))
}

/// The cards in a JSON document, and the entries that had no name.
///
/// Text that is not a JSON object or array reads as no cards, so a caller can go
/// on to the other formats. More than [`MAX_IMPORTED_CONTACTS`] entries is an
/// error rather than a silent cut.
pub fn json_import(text: &str, address_book_id: &str) -> Result<CoreContactImport, CoreError> {
    let nothing = CoreContactImport {
        contacts: Vec::new(),
        skipped: Vec::new(),
    };
    let Ok(parsed) = serde_json::from_str::<Value>(text.trim()) else {
        return Ok(nothing);
    };
    let list: Vec<&Value> = match &parsed {
        Value::Array(items) => items.iter().collect(),
        Value::Object(object) => match object.get("contacts").and_then(Value::as_array) {
            Some(items) => items.iter().collect(),
            None => vec![&parsed],
        },
        _ => return Ok(nothing),
    };
    if list.len() > MAX_IMPORTED_CONTACTS {
        return Err(CoreError::malformed(
            "Import contains too many contacts (maximum 1,000).",
        ));
    }

    let mut contacts = Vec::new();
    let mut skipped = Vec::new();
    for (index, item) in list.into_iter().enumerate() {
        match item.as_object().and_then(|o| card(o, address_book_id)) {
            Some(contact) => contacts.push(contact),
            None => skipped.push(CoreContactSkipped {
                label: format!("Card {}", index + 1),
                reason: NO_NAME.to_string(),
            }),
        }
    }
    Ok(CoreContactImport { contacts, skipped })
}

fn field(entry: &Map<String, Value>, key: &str) -> Option<String> {
    text(entry, key).filter(|v| v.chars().count() <= MAX_FIELD_CHARS)
}

fn list<T>(
    entry: &Map<String, Value>,
    key: &str,
    read: fn(&Map<String, Value>) -> Option<T>,
) -> Vec<T> {
    entry
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .take(MAX_CONTACT_LIST_ITEMS)
                .filter_map(Value::as_object)
                .filter_map(read)
                .collect()
        })
        .unwrap_or_default()
}

fn card(entry: &Map<String, Value>, default_book: &str) -> Option<CoreContactDraft> {
    let name = field(entry, "name")?;
    let book = field(entry, "addressBookId").unwrap_or_else(|| default_book.to_string());
    Some(CoreContactDraft {
        name,
        nickname: field(entry, "nickname"),
        pronouns: field(entry, "pronouns"),
        emails: list(entry, "emails", channel_of),
        phones: list(entry, "phones", channel_of),
        address: entry
            .get("address")
            .and_then(|a| address_of(&a.to_string())),
        work: list(entry, "work", work_of),
        dates: list(entry, "dates", date_of),
        socials: list(entry, "socials", social_of),
        notes: field(entry, "notes"),
        avatar: field(entry, "avatar"),
        address_book_id: resolve_address_book_id(Some(book)),
        created_at: field(entry, "createdAt"),
        ..CoreContactDraft::default()
    })
}

/// Everything above, in the shapes the bindings can carry.
#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{CoreContactFile, CoreContactImport};
    use crate::CoreError;

    #[uniffi::export(name = "json_import")]
    pub fn json_import(
        text: String,
        address_book_id: String,
    ) -> Result<CoreContactImport, CoreError> {
        super::json_import(&text, &address_book_id)
    }

    #[uniffi::export(name = "contacts_import")]
    pub fn contacts_import(
        filename: String,
        text: String,
        address_book_id: String,
    ) -> Result<CoreContactFile, CoreError> {
        super::contacts_import(&filename, &text, &address_book_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(text: &str) -> Vec<String> {
        json_import(text, "book")
            .unwrap()
            .contacts
            .into_iter()
            .map(|c| c.name)
            .collect()
    }

    #[test]
    fn reads_a_list_a_backup_and_a_single_card() {
        assert_eq!(
            names(r#"[{"name":" Ada "},{"name":"Bob"}]"#),
            ["Ada", "Bob"]
        );
        assert_eq!(names(r#"{"contacts":[{"name":"Ada"}]}"#), ["Ada"]);
        assert_eq!(names(r#"{"name":"Ada"}"#), ["Ada"]);
    }

    #[test]
    fn text_that_is_not_json_reads_as_nothing() {
        let read = json_import("Name,Notes\nAda,x", "book").unwrap();
        assert!(read.contacts.is_empty() && read.skipped.is_empty());
    }

    #[test]
    fn nameless_entries_are_reported() {
        let read = json_import(r#"[{"name":"Ada"},{"name":" "},3]"#, "book").unwrap();
        assert_eq!(read.contacts.len(), 1);
        assert_eq!(read.skipped.len(), 2);
        assert_eq!(read.skipped[1].label, "Card 3");
    }

    #[test]
    fn lists_are_capped_and_a_card_without_a_book_takes_the_target() {
        let emails: Vec<String> = (0..150)
            .map(|i| format!(r#"{{"value":"a{i}@x"}}"#))
            .collect();
        let text = format!(r#"[{{"name":"Ada","emails":[{}]}}]"#, emails.join(","));
        let read = json_import(&text, "book").unwrap();
        assert_eq!(read.contacts[0].emails.len(), MAX_CONTACT_LIST_ITEMS);
        assert_eq!(read.contacts[0].address_book_id, "book");
    }

    #[test]
    fn a_file_is_read_as_the_first_format_that_yields_cards() {
        let read = |name: &str, text: &str| contacts_import(name, text, "book").unwrap();
        assert_eq!(read("a.json", r#"[{"name":"Ada"}]"#).format, "JSON");
        assert_eq!(
            read("a.txt", "BEGIN:VCARD\nFN:Ada\nEND:VCARD").format,
            "vCard"
        );
        assert_eq!(read("a.csv", "Name\nAda").format, "CSV");
        assert_eq!(read("a.json", "Name\nAda").format, "CSV");
        let big = "x".repeat(MAX_IMPORT_BYTES + 1);
        assert!(contacts_import("a.csv", &big, "book").is_err());
    }

    #[test]
    fn too_many_cards_is_an_error() {
        let cards = vec![r#"{"name":"a"}"#; MAX_IMPORTED_CONTACTS + 1].join(",");
        assert!(json_import(&format!("[{cards}]"), "book").is_err());
    }
}
