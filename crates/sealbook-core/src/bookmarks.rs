//! The bookmark and bookmark collection payloads: which keys a writer owns, how
//! one is written, and how one is read back.
//!
//! Four clients write bookmarks and they disagreed in small ways: the CLI wrote
//! a title it had invented from the URL and never normalised the address, the
//! web wrote a collection's colour and Android neither read nor wrote it, and
//! three different fallbacks named a collection that had no name.
//!
//! Three rules decide everything below.
//!
//! **One owned set.** [`BOOKMARK_KEYS`] and [`BOOKMARK_COLLECTION_KEYS`] are the
//! union of what any client writes. A host reads the stored record into
//! [`CoreBookmark`] first and writes it back through [`CoreBookmark::draft`], so
//! a field its UI cannot show still travels.
//!
//! **Absent is omitted, never null.** A bookmark with no notes and no tags
//! carries neither key, and a top-level collection carries no `parentId`.
//!
//! **A bookmark is not titled by being saved.** A bookmark with no title lists
//! as its address, but that is the reader's fallback. [`CoreBookmark::title`]
//! carries it for display and [`CoreBookmark::derived_title`] says it was not
//! stored, so [`CoreBookmark::draft`] hands the writer an empty title and the
//! address is not written onto the record.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::payload::{
    as_object, declared_readable, refuse_newer_major, text, trimmed, write_payload,
};
use crate::CoreError;
use sealbook_protocol::PAYLOAD_SCHEMA_VERSION;

pub use sealbook_protocol::{
    BOOKMARK_COLLECTION_CONTENT_TYPE, BOOKMARK_CONTENT_TYPE, DEFAULT_BOOKMARK_COLLECTION_NAME,
};

/// What a bookmark with neither a title nor an address is listed as.
pub const UNTITLED_BOOKMARK_TITLE: &str = "Untitled bookmark";

/// What a bookmark whose payload will not parse is listed as.
pub const UNREADABLE_BOOKMARK_TITLE: &str = "Unreadable bookmark";

pub const UNTITLED_COLLECTION_NAME: &str = "Untitled";

/// Tags kept on one bookmark. A write past it drops the rest.
pub const MAX_BOOKMARK_TAGS: usize = 32;

pub const BOOKMARK_KEYS: &[&str] = &[
    "@type",
    "version",
    "url",
    "title",
    "notes",
    "tags",
    "collectionId",
    "createdAt",
    "updatedAt",
];

pub const BOOKMARK_COLLECTION_KEYS: &[&str] = &["@type", "version", "name", "parentId", "color"];

/// Tones for a collection that has never been given a colour.
const COLLECTION_TONES: &[&str] = &[
    "#7aa2f7", "#9ece6a", "#bb9af7", "#e0af68", "#7dcfff", "#f7768e", "#ff9e64", "#73daca",
];

/// The default collection's id, as a string, since that is how every host holds
/// a bookmark's `collectionId`.
pub fn default_bookmark_collection_id() -> String {
    sealbook_protocol::DEFAULT_BOOKMARK_COLLECTION_ID.to_string()
}

/// A bookmark's `collectionId`, with a blank or missing one resolved to the
/// default collection every account has.
pub fn resolve_collection_id(collection_id: Option<String>) -> String {
    collection_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(default_bookmark_collection_id)
}

/// The address as it should be stored: trimmed, and given an `https://` scheme
/// when it was typed as a bare host.
///
/// Deliberately not a fetch or a lookup. Nothing in Sealbook resolves a saved
/// address, because doing so would tell the site in it that this account holds
/// it.
pub fn normalize_url(url: &str) -> String {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if has_scheme(trimmed) {
        return trimmed.to_string();
    }
    format!("https://{trimmed}")
}

fn has_scheme(url: &str) -> bool {
    let mut chars = url.chars();
    if !chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
    {
        return false;
    }
    for char in chars {
        match char {
            ':' => return true,
            c if c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-') => {}
            _ => return false,
        }
    }
    false
}

/// Trimmed, de-duplicated case-insensitively, and capped at
/// [`MAX_BOOKMARK_TAGS`].
pub fn normalize_tags(tags: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for entry in tags {
        let tag = entry.trim();
        if tag.is_empty() || !seen.insert(tag.to_lowercase()) {
            continue;
        }
        out.push(tag.to_string());
        if out.len() == MAX_BOOKMARK_TAGS {
            break;
        }
    }
    out
}

/// One bookmark as it is drafted, before it is written.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreBookmarkDraft {
    pub url: String,
    /// May be empty: the reader lists such a bookmark by its address.
    pub title: String,
    /// Empty writes no `notes` key.
    pub notes: String,
    /// Empty writes no `tags` key.
    pub tags: Vec<String>,
    pub collection_id: String,
    /// Client-generated: the server keeps no user timestamps. `None` on a new
    /// bookmark, which takes the `now` passed to [`bookmark_write`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// The payload this draft came from, when it came from one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

/// One bookmark as it was read back.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreBookmark {
    pub id: String,
    pub url: String,
    /// The title to list: the stored one, else the address, else
    /// [`UNTITLED_BOOKMARK_TITLE`].
    pub title: String,
    /// True when [`CoreBookmark::title`] is a fallback and the payload stores no
    /// title, so a save must not write it back.
    pub derived_title: bool,
    pub notes: String,
    pub tags: Vec<String>,
    pub collection_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Whether this build reads the schema major the payload declares. False
    /// means the fields above were still read, but [`bookmark_write`] refuses.
    pub readable: bool,
    pub raw: String,
}

impl CoreBookmark {
    /// The draft that writes this bookmark back unchanged, for a host to edit
    /// the fields it names.
    pub fn draft(&self) -> CoreBookmarkDraft {
        CoreBookmarkDraft {
            url: self.url.clone(),
            title: if self.derived_title {
                String::new()
            } else {
                self.title.clone()
            },
            notes: self.notes.clone(),
            tags: self.tags.clone(),
            collection_id: self.collection_id.clone(),
            created_at: self.created_at.clone(),
            raw: Some(self.raw.clone()),
        }
    }
}

/// A collection as it is drafted.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreBookmarkCollectionDraft {
    pub name: String,
    /// `None` is a collection at the top level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    /// Only a top-level collection carries one; see [`collection_tone`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreBookmarkCollection {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    pub readable: bool,
    pub raw: String,
}

impl CoreBookmarkCollection {
    pub fn draft(&self) -> CoreBookmarkCollectionDraft {
        CoreBookmarkCollectionDraft {
            name: self.name.clone(),
            parent_id: self.parent_id.clone(),
            color: self.color.clone(),
            raw: Some(self.raw.clone()),
        }
    }
}

/// Reads a stored bookmark payload.
///
/// Lenient throughout: a payload that is not a JSON object comes back under
/// [`UNREADABLE_BOOKMARK_TITLE`], because a bookmark the user cannot see is one
/// the user cannot delete.
pub fn bookmark_parse(id: &str, raw: &str) -> CoreBookmark {
    let Some(object) = as_object(raw) else {
        return CoreBookmark {
            id: id.to_string(),
            url: String::new(),
            title: UNREADABLE_BOOKMARK_TITLE.to_string(),
            derived_title: true,
            notes: String::new(),
            tags: Vec::new(),
            collection_id: default_bookmark_collection_id(),
            created_at: None,
            updated_at: None,
            readable: true,
            raw: raw.to_string(),
        };
    };
    let url = trimmed(&object, "url").unwrap_or_default();
    let stored_title = trimmed(&object, "title");
    let derived_title = stored_title.is_none();
    let title = stored_title.unwrap_or_else(|| {
        if url.is_empty() {
            UNTITLED_BOOKMARK_TITLE.to_string()
        } else {
            url.clone()
        }
    });
    CoreBookmark {
        id: id.to_string(),
        url,
        title,
        derived_title,
        notes: text(&object, "notes").trim().to_string(),
        tags: normalize_tags(&string_entries(object.get("tags"))),
        collection_id: resolve_collection_id(trimmed(&object, "collectionId")),
        created_at: trimmed(&object, "createdAt"),
        updated_at: trimmed(&object, "updatedAt"),
        readable: declared_readable(&object),
        raw: raw.to_string(),
    }
}

/// Only genuine strings: a nested object reaching the renderer as a tag is the
/// one thing this field can carry that a UI cannot draw.
fn string_entries(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Serialises a bookmark, merging onto whatever `draft.raw` carried.
///
/// `now` is the caller's clock: core has none. It becomes `updatedAt`, and
/// `createdAt` too on a bookmark that has none.
pub fn bookmark_write(draft: &CoreBookmarkDraft, now: &str) -> Result<String, CoreError> {
    refuse_newer_major(draft.raw.as_deref())?;

    let notes = draft.notes.trim();
    let tags = normalize_tags(&draft.tags);
    let mut fields = Map::new();
    fields.insert("@type".into(), json!("Bookmark"));
    fields.insert("version".into(), json!(PAYLOAD_SCHEMA_VERSION));
    fields.insert("url".into(), json!(normalize_url(&draft.url)));
    fields.insert("title".into(), json!(draft.title.trim()));
    if !notes.is_empty() {
        fields.insert("notes".into(), json!(notes));
    }
    if !tags.is_empty() {
        fields.insert("tags".into(), json!(tags));
    }
    fields.insert(
        "collectionId".into(),
        json!(resolve_collection_id(Some(draft.collection_id.clone()))),
    );
    fields.insert(
        "createdAt".into(),
        json!(draft.created_at.as_deref().unwrap_or(now)),
    );
    fields.insert("updatedAt".into(), json!(now));
    Ok(write_payload(
        draft.raw.as_deref(),
        Value::Object(fields),
        BOOKMARK_KEYS,
    ))
}

pub fn bookmark_collection_parse(id: &str, raw: &str) -> CoreBookmarkCollection {
    let object = as_object(raw);
    let read = |key: &str| object.as_ref().and_then(|object| trimmed(object, key));
    CoreBookmarkCollection {
        id: id.to_string(),
        name: read("name").unwrap_or_else(|| fallback_collection_name(id)),
        parent_id: read("parentId"),
        color: read("color"),
        readable: object.as_ref().map(declared_readable).unwrap_or(true),
        raw: raw.to_string(),
    }
}

pub fn bookmark_collection_write(draft: &CoreBookmarkCollectionDraft) -> Result<String, CoreError> {
    refuse_newer_major(draft.raw.as_deref())?;

    let present = |value: &Option<String>| {
        value
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    };
    let mut fields = Map::new();
    fields.insert("@type".into(), json!("BookmarkCollection"));
    fields.insert("version".into(), json!(PAYLOAD_SCHEMA_VERSION));
    fields.insert("name".into(), json!(draft.name.trim()));
    if let Some(parent) = present(&draft.parent_id) {
        fields.insert("parentId".into(), json!(parent));
    }
    if let Some(color) = present(&draft.color) {
        fields.insert("color".into(), json!(color));
    }
    Ok(write_payload(
        draft.raw.as_deref(),
        Value::Object(fields),
        BOOKMARK_COLLECTION_KEYS,
    ))
}

/// The default collection is the one every client creates for itself, so an
/// unnamed one is that name rather than `Untitled`.
fn fallback_collection_name(id: &str) -> String {
    if id == default_bookmark_collection_id() {
        DEFAULT_BOOKMARK_COLLECTION_NAME.to_string()
    } else {
        UNTITLED_COLLECTION_NAME.to_string()
    }
}

/// The name to show for a bookmark's collection. A collection that is gone shows
/// the default one's name rather than nothing.
pub fn bookmark_collection_name_by_id(
    collections: &[CoreBookmarkCollection],
    collection_id: Option<String>,
) -> String {
    let id = resolve_collection_id(collection_id);
    collections
        .iter()
        .find(|collection| collection.id == id)
        .map(|collection| collection.name.clone())
        .unwrap_or_else(|| DEFAULT_BOOKMARK_COLLECTION_NAME.to_string())
}

/// A collection's colour: its root's explicit colour, or one hashed from the
/// root's id when it has none.
///
/// Only a top-level collection carries an explicit colour, so everything nested
/// under it resolves to the same value. The hash is over UTF-16 units, so every
/// client lands an uncoloured collection on the same tone.
pub fn bookmark_collection_tone(collections: &[CoreBookmarkCollection], id: &str) -> String {
    let root = collection_root_id(collections, id);
    if let Some(explicit) = collections
        .iter()
        .find(|collection| collection.id == root)
        .and_then(|collection| collection.color.clone())
    {
        return explicit;
    }
    let hash = root.encode_utf16().fold(0u32, |hash, unit| {
        hash.wrapping_mul(31).wrapping_add(u32::from(unit))
    });
    COLLECTION_TONES[hash as usize % COLLECTION_TONES.len()].to_string()
}

/// The top-level collection `id` sits under: itself, if it is already one. A
/// parent that is missing, or a loop, ends the walk where it stands.
fn collection_root_id(collections: &[CoreBookmarkCollection], id: &str) -> String {
    let mut seen = vec![id.to_string()];
    let mut cursor = id.to_string();
    loop {
        let parent = collections
            .iter()
            .find(|collection| collection.id == cursor)
            .and_then(|collection| collection.parent_id.clone())
            .filter(|parent| {
                !seen.contains(parent) && collections.iter().any(|other| other.id == *parent)
            });
        match parent {
            Some(parent) => {
                seen.push(parent.clone());
                cursor = parent;
            }
            None => return cursor,
        }
    }
}

/// Everything above, in the shapes the bindings can carry.
#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{
        CoreBookmark, CoreBookmarkCollection, CoreBookmarkCollectionDraft, CoreBookmarkDraft,
        CoreError,
    };

    fn keys(keys: &[&str]) -> Vec<String> {
        keys.iter().map(|key| key.to_string()).collect()
    }

    #[uniffi::export(name = "bookmark_keys")]
    pub fn bookmark_keys() -> Vec<String> {
        keys(super::BOOKMARK_KEYS)
    }

    #[uniffi::export(name = "bookmark_collection_keys")]
    pub fn bookmark_collection_keys() -> Vec<String> {
        keys(super::BOOKMARK_COLLECTION_KEYS)
    }

    #[uniffi::export(name = "default_bookmark_collection_id")]
    pub fn default_bookmark_collection_id() -> String {
        super::default_bookmark_collection_id()
    }

    #[uniffi::export(name = "resolve_collection_id")]
    pub fn resolve_collection_id(collection_id: Option<String>) -> String {
        super::resolve_collection_id(collection_id)
    }

    #[uniffi::export(name = "normalize_url")]
    pub fn normalize_url(url: String) -> String {
        super::normalize_url(&url)
    }

    #[uniffi::export(name = "normalize_tags")]
    pub fn normalize_tags(tags: Vec<String>) -> Vec<String> {
        super::normalize_tags(&tags)
    }

    #[uniffi::export(name = "bookmark_parse")]
    pub fn bookmark_parse(id: String, raw: String) -> CoreBookmark {
        super::bookmark_parse(&id, &raw)
    }

    #[uniffi::export(name = "bookmark_write")]
    pub fn bookmark_write(draft: CoreBookmarkDraft, now: String) -> Result<String, CoreError> {
        super::bookmark_write(&draft, &now)
    }

    #[uniffi::export(name = "bookmark_collection_parse")]
    pub fn bookmark_collection_parse(id: String, raw: String) -> CoreBookmarkCollection {
        super::bookmark_collection_parse(&id, &raw)
    }

    #[uniffi::export(name = "bookmark_collection_write")]
    pub fn bookmark_collection_write(
        draft: CoreBookmarkCollectionDraft,
    ) -> Result<String, CoreError> {
        super::bookmark_collection_write(&draft)
    }

    #[uniffi::export(name = "bookmark_collection_name_by_id")]
    pub fn bookmark_collection_name_by_id(
        collections: Vec<CoreBookmarkCollection>,
        collection_id: Option<String>,
    ) -> String {
        super::bookmark_collection_name_by_id(&collections, collection_id)
    }

    #[uniffi::export(name = "bookmark_collection_tone")]
    pub fn bookmark_collection_tone(
        collections: Vec<CoreBookmarkCollection>,
        id: String,
    ) -> String {
        super::bookmark_collection_tone(&collections, &id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: &str = "2026-10-28T12:00:00Z";

    fn draft() -> CoreBookmarkDraft {
        CoreBookmarkDraft {
            url: "example.com/a".into(),
            title: "Example".into(),
            collection_id: default_bookmark_collection_id(),
            ..Default::default()
        }
    }

    fn written(draft: &CoreBookmarkDraft) -> Map<String, Value> {
        as_object(&bookmark_write(draft, NOW).unwrap()).expect("an object")
    }

    #[test]
    fn a_bare_host_is_given_a_scheme_and_a_scheme_is_left_alone() {
        assert_eq!(normalize_url("  example.com  "), "https://example.com");
        assert_eq!(normalize_url("http://example.com"), "http://example.com");
        assert_eq!(normalize_url("mailto:a@b.c"), "mailto:a@b.c");
        assert_eq!(normalize_url("1abc:x"), "https://1abc:x");
        assert_eq!(normalize_url("   "), "");
    }

    #[test]
    fn a_bookmark_without_notes_or_tags_carries_neither_key() {
        let bookmark = written(&draft());
        assert!(!bookmark.contains_key("notes"));
        assert!(!bookmark.contains_key("tags"));
        assert_eq!(bookmark["url"], "https://example.com/a");
    }

    #[test]
    fn tags_are_trimmed_deduplicated_without_regard_to_case_and_capped() {
        let tags: Vec<String> = ["  a ", "A", "", "b"]
            .iter()
            .map(|t| t.to_string())
            .collect();
        assert_eq!(normalize_tags(&tags), ["a", "b"]);
        let many: Vec<String> = (0..40).map(|n| format!("t{n}")).collect();
        assert_eq!(normalize_tags(&many).len(), MAX_BOOKMARK_TAGS);
    }

    #[test]
    fn a_bookmark_with_no_stored_title_is_not_titled_by_a_save() {
        let stored = r#"{"@type":"Bookmark","url":"https://example.com","title":"  "}"#;
        let bookmark = bookmark_parse("b", stored);
        assert_eq!(bookmark.title, "https://example.com");
        assert!(bookmark.derived_title);
        let rewritten = as_object(&bookmark_write(&bookmark.draft(), NOW).unwrap()).unwrap();
        assert_eq!(rewritten["title"], "");
    }

    #[test]
    fn a_nested_collection_takes_its_roots_colour() {
        let parse = |id: &str, raw: &str| bookmark_collection_parse(id, raw);
        let collections = vec![
            parse("root", r##"{"name":"R","color":"#123456"}"##),
            parse("child", r#"{"name":"C","parentId":"root"}"#),
            parse("loop-a", r#"{"name":"A","parentId":"loop-b"}"#),
            parse("loop-b", r#"{"name":"B","parentId":"loop-a"}"#),
        ];
        assert_eq!(bookmark_collection_tone(&collections, "child"), "#123456");
        let looped = bookmark_collection_tone(&collections, "loop-a");
        assert!(COLLECTION_TONES.contains(&looped.as_str()));
    }

    #[test]
    fn an_unnamed_collection_is_named_for_whether_it_is_the_default() {
        let default = bookmark_collection_parse(&default_bookmark_collection_id(), "{}");
        assert_eq!(default.name, DEFAULT_BOOKMARK_COLLECTION_NAME);
        assert_eq!(bookmark_collection_parse("x", "nope").name, "Untitled");
    }
}
