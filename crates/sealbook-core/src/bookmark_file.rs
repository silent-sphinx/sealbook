//! Bookmark import and export files.
//!
//! Two formats, written once here so every client reads and writes the same
//! file. The web used to keep the first in `lib/bookmarkExport.ts`, which broke
//! the rule that a format has one author.
//!
//! **Sealbook JSON** (`sealbook-bookmark-export`, version 1): the format the web
//! has always written. A bare JSON array of bookmark-like objects is read too.
//!
//! **Netscape HTML**: the `<!DOCTYPE NETSCAPE-Bookmark-file-1>` file Firefox,
//! Chrome, Safari and Edge all export and import. Folders become the nesting
//! of `<DL>` lists, `ADD_DATE` is seconds since the epoch, and `TAGS` is a comma
//! list. A page that is not a web address (`place:` queries, `javascript:`
//! bookmarklets) is skipped and counted.
//!
//! An import hands back drafts and the folder each came from. Where they go is
//! the host's: the web puts them all in the collection the person picked.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::bookmarks::{
    bookmark_collection_name_by_id, default_bookmark_collection_id, CoreBookmark,
    CoreBookmarkCollection, CoreBookmarkCollectionDraft, CoreBookmarkDraft,
};
use crate::CoreError;

pub const BOOKMARK_EXPORT_TYPE: &str = "sealbook-bookmark-export";

/// Shown for a file that is not JSON at all.
pub const BOOKMARK_NOT_JSON: &str = "Not a valid JSON file.";

/// Shown for JSON that is neither an export nor an array.
pub const BOOKMARK_UNRECOGNISED: &str =
    "Unrecognised format. Expected a Sealbook bookmark export or a JSON array of bookmarks.";

/// One bookmark from a file, and the folder it was in.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreImportedBookmark {
    /// `collection_id` is empty: the host chooses where it goes.
    pub draft: CoreBookmarkDraft,
    /// Outermost folder first. Empty for a bookmark at the top of the file. A
    /// Sealbook export has one level, the collection's name.
    pub folder: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreBookmarkImport {
    pub bookmarks: Vec<CoreImportedBookmark>,
    /// Entries with neither a URL nor a title, or that are not web pages.
    pub skipped: u32,
}

/// A collection an import has to make, with the id it will be written under.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreNewBookmarkCollection {
    pub id: String,
    pub draft: CoreBookmarkCollectionDraft,
}

/// What happens to one folder of an imported file.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CoreFolderAction {
    /// The folder becomes a collection, named `name` or else as in the file.
    /// One that already exists under the same parent is reused.
    Collection { name: Option<String> },
    /// The folder's bookmarks go where its parent's go.
    Merge,
    /// The folder's bookmarks, and its subfolders', are not imported.
    Skip,
    /// The folder's bookmarks go in a collection that already exists.
    Existing { collection_id: String },
}

/// What to do with the folder at `path`, outermost first, matched ignoring case.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreFolderRule {
    pub path: Vec<String>,
    pub action: CoreFolderAction,
}

/// How an import treats the folders of a file.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreBookmarkImportOptions {
    /// Folders this many levels down or fewer become collections unless a rule
    /// says otherwise, and deeper ones merge into the folder above. 0 imports
    /// everything flat; [`u32::MAX`] keeps every folder.
    pub depth: u32,
    pub rules: Vec<CoreFolderRule>,
}

/// One folder of an imported file, as the options would treat it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreImportFolder {
    /// Outermost first. A parent is listed before the folders in it.
    pub path: Vec<String>,
    /// Bookmarks filed directly in the folder.
    pub direct: u32,
    /// Bookmarks in the folder and every folder below it.
    pub total: u32,
    /// The rule for this folder, or the default for its depth.
    pub action: CoreFolderAction,
    /// This folder or one above it is skipped, so nothing in it is imported.
    pub excluded: bool,
}

/// Where an import's bookmarks go.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreBookmarkImportPlan {
    /// Parents before the collections nested in them.
    pub collections: Vec<CoreNewBookmarkCollection>,
    /// In file order, each with its `collection_id` set.
    pub bookmarks: Vec<CoreBookmarkDraft>,
    /// Bookmarks left out because their folder is skipped.
    pub excluded: u32,
}

fn folder_key(path: &[String]) -> Vec<String> {
    path.iter().map(|name| name.trim().to_lowercase()).collect()
}

/// What a folder `level` deep gets when no rule names it.
fn default_action(depth: u32, level: usize) -> CoreFolderAction {
    if level as u64 <= u64::from(depth) {
        CoreFolderAction::Collection { name: None }
    } else {
        CoreFolderAction::Merge
    }
}

fn folder_action(options: &CoreBookmarkImportOptions, path: &[String]) -> CoreFolderAction {
    let key = folder_key(path);
    options
        .rules
        .iter()
        .rev()
        .find(|rule| folder_key(&rule.path) == key)
        .map(|rule| rule.action.clone())
        .unwrap_or_else(|| default_action(options.depth, path.len()))
}

/// The options with the folder at `path` set to `action`. A rule that only
/// restates what the depth already does is dropped, so the options stay
/// recognisable as a preset until a folder really differs.
pub fn bookmark_import_with_folder(
    options: &CoreBookmarkImportOptions,
    path: &[String],
    action: CoreFolderAction,
) -> CoreBookmarkImportOptions {
    let key = folder_key(path);
    let mut rules: Vec<CoreFolderRule> = options
        .rules
        .iter()
        .filter(|rule| folder_key(&rule.path) != key)
        .cloned()
        .collect();
    let unnamed = |action: &CoreFolderAction| match action {
        CoreFolderAction::Collection { name } => CoreFolderAction::Collection {
            name: name
                .as_deref()
                .map(str::trim)
                .filter(|n| !n.is_empty())
                .map(str::to_owned),
        },
        other => other.clone(),
    };
    if unnamed(&action) != default_action(options.depth, path.len()) {
        rules.push(CoreFolderRule {
            path: path.to_vec(),
            action,
        });
    }
    CoreBookmarkImportOptions {
        depth: options.depth,
        rules,
    }
}

/// The folders of a file with their sizes and what `options` does with each,
/// for an editor to show before anything is written.
pub fn bookmark_import_folders(
    import: &CoreBookmarkImport,
    options: &CoreBookmarkImportOptions,
) -> Vec<CoreImportFolder> {
    let mut folders: Vec<CoreImportFolder> = Vec::new();
    let mut at: std::collections::HashMap<Vec<String>, usize> = std::collections::HashMap::new();
    for item in &import.bookmarks {
        for depth in 1..=item.folder.len() {
            let path = &item.folder[..depth];
            let index = *at.entry(folder_key(path)).or_insert_with(|| {
                let excluded = (1..=depth).any(|n| {
                    matches!(
                        folder_action(options, &item.folder[..n]),
                        CoreFolderAction::Skip
                    )
                });
                folders.push(CoreImportFolder {
                    path: path.to_vec(),
                    direct: 0,
                    total: 0,
                    action: folder_action(options, path),
                    excluded,
                });
                folders.len() - 1
            });
            folders[index].total += 1;
            if depth == item.folder.len() {
                folders[index].direct += 1;
            }
        }
    }
    folders
}

/// Decides where an import's bookmarks go.
///
/// `target` is the collection everything goes in (the default collection when
/// `None`), or the one the file's folders nest under. A folder made a collection
/// is matched to an existing collection of the same name under the same parent,
/// ignoring case, so importing twice does not double the tree. A target that is
/// the default collection, which is not a real parent, nests folders at the top
/// level.
pub fn bookmark_import_plan(
    import: &CoreBookmarkImport,
    existing: &[CoreBookmarkCollection],
    target: Option<&str>,
    options: &CoreBookmarkImportOptions,
) -> CoreBookmarkImportPlan {
    let default_id = default_bookmark_collection_id();
    let home = target.unwrap_or(&default_id).to_owned();
    let root = target.filter(|id| *id != default_id).map(str::to_owned);
    // (parent, lowercase name, id), for what exists and what this plan adds.
    let mut folders: Vec<(Option<String>, String, String)> = existing
        .iter()
        .map(|c| (c.parent_id.clone(), c.name.to_lowercase(), c.id.clone()))
        .collect();
    let mut made = Vec::new();
    let mut bookmarks = Vec::with_capacity(import.bookmarks.len());
    let mut excluded = 0;
    'bookmarks: for item in &import.bookmarks {
        let mut parent = root.clone();
        let mut collection = home.clone();
        for depth in 1..=item.folder.len() {
            match folder_action(options, &item.folder[..depth]) {
                CoreFolderAction::Skip => {
                    excluded += 1;
                    continue 'bookmarks;
                }
                CoreFolderAction::Merge => {}
                CoreFolderAction::Existing { collection_id } => {
                    parent = Some(collection_id.clone());
                    collection = collection_id;
                }
                CoreFolderAction::Collection { name } => {
                    let name = name
                        .as_deref()
                        .map(str::trim)
                        .filter(|name| !name.is_empty())
                        .unwrap_or_else(|| item.folder[depth - 1].trim());
                    let key = name.to_lowercase();
                    let found = folders
                        .iter()
                        .find(|(p, n, _)| *p == parent && *n == key)
                        .map(|(_, _, id)| id.clone());
                    let id = found.unwrap_or_else(|| {
                        let id = uuid::Uuid::new_v4().to_string();
                        made.push(CoreNewBookmarkCollection {
                            id: id.clone(),
                            draft: CoreBookmarkCollectionDraft {
                                name: name.to_owned(),
                                parent_id: parent.clone(),
                                ..Default::default()
                            },
                        });
                        folders.push((parent.clone(), key, id.clone()));
                        id
                    });
                    parent = Some(id.clone());
                    collection = id;
                }
            }
        }
        bookmarks.push(CoreBookmarkDraft {
            collection_id: collection,
            ..item.draft.clone()
        });
    }
    CoreBookmarkImportPlan {
        collections: made,
        bookmarks,
        excluded,
    }
}

/// The Sealbook JSON export.
pub fn bookmark_export(
    bookmarks: &[CoreBookmark],
    collections: &[CoreBookmarkCollection],
    now: &str,
) -> String {
    let entries: Vec<Value> = bookmarks
        .iter()
        .map(|bookmark| {
            let mut entry = Map::new();
            entry.insert("url".into(), json!(bookmark.url));
            entry.insert("title".into(), json!(bookmark.title));
            if !bookmark.notes.is_empty() {
                entry.insert("notes".into(), json!(bookmark.notes));
            }
            if !bookmark.tags.is_empty() {
                entry.insert("tags".into(), json!(bookmark.tags));
            }
            entry.insert("collectionId".into(), json!(bookmark.collection_id));
            entry.insert(
                "collectionName".into(),
                json!(bookmark_collection_name_by_id(
                    collections,
                    Some(bookmark.collection_id.clone())
                )),
            );
            if let Some(created) = &bookmark.created_at {
                entry.insert("createdAt".into(), json!(created));
            }
            if let Some(updated) = &bookmark.updated_at {
                entry.insert("updatedAt".into(), json!(updated));
            }
            Value::Object(entry)
        })
        .collect();
    let folders: Vec<Value> = collections
        .iter()
        .map(|collection| {
            let mut entry = Map::new();
            entry.insert("id".into(), json!(collection.id));
            entry.insert("name".into(), json!(collection.name));
            if let Some(parent) = &collection.parent_id {
                entry.insert("parentId".into(), json!(parent));
            }
            if let Some(color) = &collection.color {
                entry.insert("color".into(), json!(color));
            }
            Value::Object(entry)
        })
        .collect();
    serde_json::to_string_pretty(&json!({
        "@type": BOOKMARK_EXPORT_TYPE,
        "version": 1,
        "exportedAt": now,
        "bookmarks": entries,
        "collections": folders,
    }))
    .unwrap_or_default()
}

/// Largest bookmark file an import will read, in bytes.
pub const MAX_BOOKMARK_IMPORT_BYTES: usize = 16 * 1024 * 1024;
/// Most bookmarks one import may carry.
pub const MAX_IMPORTED_BOOKMARKS: usize = 20_000;

/// Reads a bookmark file: Netscape HTML when it starts with a tag, else a
/// Sealbook export or a JSON array.
pub fn bookmark_import(text: &str) -> Result<CoreBookmarkImport, CoreError> {
    if text.len() > MAX_BOOKMARK_IMPORT_BYTES {
        return Err(CoreError::malformed(
            "Import file is too large (maximum 16 MB).",
        ));
    }
    let read = if text.trim_start().starts_with('<') {
        import_html(text)
    } else {
        import_json(text)?
    };
    if read.bookmarks.len() > MAX_IMPORTED_BOOKMARKS {
        return Err(CoreError::malformed(
            "Import contains too many bookmarks (maximum 20,000).",
        ));
    }
    Ok(read)
}

fn import_json(text: &str) -> Result<CoreBookmarkImport, CoreError> {
    let parsed: Value =
        serde_json::from_str(text).map_err(|_| CoreError::malformed(BOOKMARK_NOT_JSON))?;
    if !parsed.is_array() && !parsed.is_object() {
        return Err(CoreError::malformed(BOOKMARK_NOT_JSON));
    }
    let tree = export_collections(&parsed);
    let entries = match &parsed {
        Value::Array(entries) => entries,
        Value::Object(body) if body.get("@type") == Some(&json!(BOOKMARK_EXPORT_TYPE)) => body
            .get("bookmarks")
            .and_then(Value::as_array)
            .ok_or_else(|| CoreError::malformed(BOOKMARK_UNRECOGNISED))?,
        _ => return Err(CoreError::malformed(BOOKMARK_UNRECOGNISED)),
    };
    let mut bookmarks = Vec::new();
    let mut skipped = 0;
    for entry in entries {
        let Some(fields) = entry.as_object() else {
            skipped += 1;
            continue;
        };
        let string = |key: &str| {
            fields
                .get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or_default()
        };
        let (url, title) = (string("url"), string("title"));
        if (url.is_empty() && title.is_empty()) || (!url.is_empty() && !is_page(url)) {
            skipped += 1;
            continue;
        }
        let tags = fields
            .get("tags")
            .and_then(Value::as_array)
            .map(|tags| {
                tags.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let name = fields
            .get("collectionName")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty());
        let by_id = fields
            .get("collectionId")
            .and_then(Value::as_str)
            .and_then(|id| collection_path(&tree, id));
        bookmarks.push(CoreImportedBookmark {
            draft: CoreBookmarkDraft {
                url: url.to_owned(),
                title: if title.is_empty() { url } else { title }.to_owned(),
                notes: fields
                    .get("notes")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                tags,
                collection_id: String::new(),
                created_at: fields
                    .get("createdAt")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                raw: None,
            },
            folder: by_id
                .or_else(|| name.map(|name| vec![name.to_owned()]))
                .unwrap_or_default(),
        });
    }
    Ok(CoreBookmarkImport { bookmarks, skipped })
}

type CollectionTree = std::collections::HashMap<String, (String, Option<String>)>;

/// The `collections` of a Sealbook export as id to (name, parent id). Empty for
/// a bare array and for an export from before collections were listed.
fn export_collections(parsed: &Value) -> CollectionTree {
    let mut tree = CollectionTree::new();
    let listed = parsed.get("collections").and_then(Value::as_array);
    for entry in listed.into_iter().flatten() {
        let text = |key: &str| entry.get(key).and_then(Value::as_str);
        let (Some(id), Some(name)) = (text("id"), text("name")) else {
            continue;
        };
        let name = name.trim();
        if !name.is_empty() {
            tree.insert(
                id.to_owned(),
                (name.to_owned(), text("parentId").map(str::to_owned)),
            );
        }
    }
    tree
}

/// The folder path of collection `id`, outermost first, or `None` when the
/// export does not list it. A parent that is missing ends the path there, and a
/// cycle is cut rather than followed.
fn collection_path(tree: &CollectionTree, id: &str) -> Option<Vec<String>> {
    let (name, mut parent) = tree.get(id)?.clone();
    let mut path = vec![name];
    let mut seen = vec![id.to_owned()];
    while let Some(next) = parent {
        let Some((name, above)) = tree.get(&next) else {
            break;
        };
        if seen.contains(&next) {
            break;
        }
        seen.push(next);
        path.push(name.clone());
        parent = above.clone();
    }
    path.reverse();
    Some(path)
}

// ---- Netscape HTML ----------------------------------------------------------

struct Tag {
    name: String,
    closing: bool,
    attrs: Vec<(String, String)>,
}

impl Tag {
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

enum Piece {
    Tag(Tag),
    Text(String),
}

fn tokens(html: &str) -> Vec<Piece> {
    let mut out = Vec::new();
    let mut rest = html;
    while !rest.is_empty() {
        match rest.find('<') {
            None => {
                out.push(Piece::Text(rest.to_owned()));
                break;
            }
            Some(0) => {
                if let Some(after) = rest.strip_prefix("<!--") {
                    rest = after.find("-->").map_or("", |end| &after[end + 3..]);
                    continue;
                }
                let Some(end) = tag_end(rest) else {
                    out.push(Piece::Text(rest.to_owned()));
                    break;
                };
                if let Some(tag) = parse_tag(&rest[1..end]) {
                    out.push(Piece::Tag(tag));
                }
                rest = &rest[end + 1..];
            }
            Some(at) => {
                out.push(Piece::Text(rest[..at].to_owned()));
                rest = &rest[at..];
            }
        }
    }
    out
}

/// The index of the `>` that closes the tag at the start of `text`, skipping any
/// inside a quoted attribute.
fn tag_end(text: &str) -> Option<usize> {
    let mut quote: Option<char> = None;
    for (index, c) in text.char_indices().skip(1) {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (None, '"' | '\'') => quote = Some(c),
            (None, '>') => return Some(index),
            _ => {}
        }
    }
    None
}

fn parse_tag(inner: &str) -> Option<Tag> {
    let inner = inner.trim();
    let (closing, inner) = match inner.strip_prefix('/') {
        Some(rest) => (true, rest),
        None => (false, inner),
    };
    let name_end = inner
        .find(|c: char| c.is_whitespace() || c == '/')
        .unwrap_or(inner.len());
    let name = inner[..name_end].to_ascii_lowercase();
    if name.is_empty() || name.starts_with('!') {
        return None;
    }
    let mut attrs = Vec::new();
    let mut rest = inner[name_end..].trim_start();
    while !rest.is_empty() {
        let key_end = rest
            .find(|c: char| c.is_whitespace() || c == '=')
            .unwrap_or(rest.len());
        let key = rest[..key_end].trim_matches('/').to_ascii_lowercase();
        rest = rest[key_end..].trim_start();
        let mut value = String::new();
        if let Some(after) = rest.strip_prefix('=') {
            let after = after.trim_start();
            if let Some(quote) = after.chars().next().filter(|c| matches!(c, '"' | '\'')) {
                let body = &after[1..];
                let end = body.find(quote).unwrap_or(body.len());
                value = decode(&body[..end]);
                rest = body.get(end + 1..).unwrap_or("");
            } else {
                let end = after.find(char::is_whitespace).unwrap_or(after.len());
                value = decode(&after[..end]);
                rest = &after[end..];
            }
        }
        if !key.is_empty() {
            attrs.push((key, value));
        }
        rest = rest.trim_start();
    }
    Some(Tag {
        name,
        closing,
        attrs,
    })
}

fn decode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let decoded = rest.find(';').filter(|end| *end <= 10).and_then(|end| {
            let name = &rest[1..end];
            let c = match name {
                "amp" => '&',
                "lt" => '<',
                "gt" => '>',
                "quot" => '"',
                "apos" => '\'',
                "nbsp" => ' ',
                _ => {
                    let number = name.strip_prefix('#')?;
                    let code = match number.strip_prefix(['x', 'X']) {
                        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                        None => number.parse().ok()?,
                    };
                    char::from_u32(code)?
                }
            };
            Some((c, end))
        });
        match decoded {
            Some((c, end)) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn is_page(url: &str) -> bool {
    crate::bookmarks::is_web_url(url)
}

fn import_html(html: &str) -> CoreBookmarkImport {
    let pieces = tokens(html);
    // One entry per open `<DL>`: the folder it belongs to, if it has a name.
    let mut lists: Vec<Option<String>> = Vec::new();
    let mut pending_folder: Option<String> = None;
    let mut bookmarks: Vec<CoreImportedBookmark> = Vec::new();
    let mut skipped = 0;
    let mut last: Option<usize> = None;
    let mut index = 0;
    let text_after = |from: usize, stop: &dyn Fn(&Tag) -> bool| {
        let mut text = String::new();
        let mut at = from;
        while let Some(piece) = pieces.get(at) {
            match piece {
                Piece::Text(chunk) => text.push_str(chunk),
                Piece::Tag(tag) if stop(tag) => break,
                Piece::Tag(tag) if tag.name == "br" => text.push('\n'),
                Piece::Tag(_) => {}
            }
            at += 1;
        }
        (text, at)
    };
    while index < pieces.len() {
        match &pieces[index] {
            Piece::Tag(tag) if tag.name == "h3" && !tag.closing => {
                let (name, end) = text_after(index + 1, &|t| t.name == "h3" && t.closing);
                pending_folder = Some(decode(&name).trim().to_owned());
                index = end;
                last = None;
            }
            Piece::Tag(tag) if tag.name == "dl" && !tag.closing => {
                lists.push(pending_folder.take());
            }
            Piece::Tag(tag) if tag.name == "dl" && tag.closing => {
                lists.pop();
                last = None;
            }
            Piece::Tag(tag) if tag.name == "a" && !tag.closing => {
                let (title, end) = text_after(index + 1, &|t| t.name == "a" && t.closing);
                index = end;
                let url = tag.attr("href").unwrap_or_default().trim();
                let title = decode(&title).trim().to_owned();
                if (url.is_empty() && title.is_empty()) || (!url.is_empty() && !is_page(url)) {
                    skipped += 1;
                    last = None;
                } else {
                    let tags = tag
                        .attr("tags")
                        .unwrap_or_default()
                        .split(',')
                        .map(str::trim)
                        .filter(|t| !t.is_empty())
                        .map(str::to_owned)
                        .collect();
                    bookmarks.push(CoreImportedBookmark {
                        draft: CoreBookmarkDraft {
                            url: url.to_owned(),
                            title: if title.is_empty() {
                                url.to_owned()
                            } else {
                                title
                            },
                            notes: String::new(),
                            tags,
                            collection_id: String::new(),
                            created_at: tag
                                .attr("add_date")
                                .and_then(|d| d.trim().parse::<i64>().ok())
                                .and_then(rfc3339_from_epoch),
                            raw: None,
                        },
                        folder: lists
                            .iter()
                            .flatten()
                            .filter(|name| !name.is_empty())
                            .cloned()
                            .collect(),
                    });
                    last = Some(bookmarks.len() - 1);
                }
            }
            Piece::Tag(tag) if tag.name == "dd" && !tag.closing => {
                let (text, end) = text_after(index + 1, &|t| {
                    !t.closing && matches!(t.name.as_str(), "dt" | "dd" | "dl" | "h3")
                        || t.closing && t.name == "dl"
                });
                index = end;
                let note = decode(&text).trim().to_owned();
                if let (Some(at), false) = (last, note.is_empty()) {
                    bookmarks[at].draft.notes = note;
                }
                continue;
            }
            _ => {}
        }
        index += 1;
    }
    CoreBookmarkImport { bookmarks, skipped }
}

/// Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let mp = i64::from(if month > 2 { month - 3 } else { month + 9 });
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn rfc3339_from_epoch(seconds: i64) -> Option<String> {
    if !(0..=253_402_300_799).contains(&seconds) {
        return None;
    }
    let (year, month, day) = civil_from_days(seconds.div_euclid(86_400));
    let rest = seconds.rem_euclid(86_400);
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    ))
}

/// Seconds since the epoch for an RFC 3339 stamp, or None for anything else.
fn epoch_from_rfc3339(stamp: &str) -> Option<i64> {
    let (date, time) = stamp.split_once(['T', 't'])?;
    let mut date = date.splitn(3, '-');
    let (year, month, day) = (
        date.next()?.parse::<i64>().ok()?,
        date.next()?.parse::<u32>().ok()?,
        date.next()?.parse::<u32>().ok()?,
    );
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let split = time.find(['Z', 'z', '+', '-']).unwrap_or(time.len());
    let (clock, zone) = time.split_at(split);
    let mut parts = clock.splitn(3, ':');
    let hour = parts.next()?.parse::<i64>().ok()?;
    let minute = parts.next()?.parse::<i64>().ok()?;
    let second = parts
        .next()
        .and_then(|s| s.split('.').next())
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    let offset = match zone.as_bytes().first() {
        Some(b'+' | b'-') => {
            let sign = if zone.starts_with('-') { -1 } else { 1 };
            let mut z = zone[1..].splitn(2, ':');
            let h = z.next()?.parse::<i64>().ok()?;
            let m = z.next().map_or(Some(0), |m| m.parse::<i64>().ok())?;
            sign * (h * 3600 + m * 60)
        }
        _ => 0,
    };
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The Netscape bookmark file: collections as nested folders, tags as `TAGS`.
pub fn bookmark_export_html(
    bookmarks: &[CoreBookmark],
    collections: &[CoreBookmarkCollection],
) -> String {
    let mut out = String::from(
        "<!DOCTYPE NETSCAPE-Bookmark-file-1>\n\
         <!-- This is an automatically generated file. -->\n\
         <META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=UTF-8\">\n\
         <TITLE>Bookmarks</TITLE>\n<H1>Bookmarks</H1>\n<DL><p>\n",
    );
    let known = |id: &str| collections.iter().any(|c| c.id == id);
    let mut shown = std::collections::HashSet::new();
    let mut roots: Vec<&CoreBookmarkCollection> = collections
        .iter()
        .filter(|c| {
            c.parent_id
                .as_deref()
                .is_none_or(|p| !known(p) || p == c.id)
        })
        .collect();
    roots.sort_by_key(|c| c.name.to_lowercase());
    // A collection on a parent cycle has no root above it; put it at the top so
    // no bookmark is left out of the file.
    for root in &roots {
        write_folder(&mut out, root, collections, bookmarks, 1, &mut shown);
    }
    let mut stranded: Vec<&CoreBookmarkCollection> = collections
        .iter()
        .filter(|c| !shown.contains(&c.id))
        .collect();
    stranded.sort_by_key(|c| c.name.to_lowercase());
    for collection in stranded {
        if !shown.contains(&collection.id) {
            write_folder(&mut out, collection, collections, bookmarks, 1, &mut shown);
        }
    }
    // Bookmarks whose collection is gone sit at the top, as the app lists them.
    for bookmark in bookmarks.iter().filter(|b| !known(&b.collection_id)) {
        write_entry(&mut out, bookmark, 1);
    }
    out.push_str("</DL><p>\n");
    out
}

fn write_folder(
    out: &mut String,
    collection: &CoreBookmarkCollection,
    collections: &[CoreBookmarkCollection],
    bookmarks: &[CoreBookmark],
    depth: usize,
    shown: &mut std::collections::HashSet<String>,
) {
    if !shown.insert(collection.id.clone()) {
        return;
    }
    let pad = "    ".repeat(depth);
    out.push_str(&format!(
        "{pad}<DT><H3>{}</H3>\n{pad}<DL><p>\n",
        escape(&collection.name)
    ));
    let mut children: Vec<&CoreBookmarkCollection> = collections
        .iter()
        .filter(|c| c.parent_id.as_deref() == Some(collection.id.as_str()) && c.id != collection.id)
        .collect();
    children.sort_by_key(|c| c.name.to_lowercase());
    for child in children {
        write_folder(out, child, collections, bookmarks, depth + 1, shown);
    }
    for bookmark in bookmarks
        .iter()
        .filter(|b| b.collection_id == collection.id)
    {
        write_entry(out, bookmark, depth + 1);
    }
    out.push_str(&format!("{pad}</DL><p>\n"));
}

fn write_entry(out: &mut String, bookmark: &CoreBookmark, depth: usize) {
    let pad = "    ".repeat(depth);
    let mut attrs = format!("HREF=\"{}\"", escape(&bookmark.url));
    if let Some(seconds) = bookmark.created_at.as_deref().and_then(epoch_from_rfc3339) {
        attrs.push_str(&format!(" ADD_DATE=\"{seconds}\""));
    }
    if !bookmark.tags.is_empty() {
        attrs.push_str(&format!(" TAGS=\"{}\"", escape(&bookmark.tags.join(","))));
    }
    out.push_str(&format!(
        "{pad}<DT><A {attrs}>{}</A>\n",
        escape(&bookmark.title)
    ));
    if !bookmark.notes.is_empty() {
        out.push_str(&format!(
            "{pad}<DD>{}\n",
            escape(&bookmark.notes).replace('\n', "<br>")
        ));
    }
}

/// Everything above, in the shapes the bindings can carry.
#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{
        CoreBookmark, CoreBookmarkCollection, CoreBookmarkImport, CoreBookmarkImportOptions,
        CoreBookmarkImportPlan, CoreError, CoreFolderAction, CoreImportFolder,
    };

    #[uniffi::export(name = "bookmark_import_plan")]
    pub fn bookmark_import_plan(
        import: CoreBookmarkImport,
        existing: Vec<CoreBookmarkCollection>,
        target: Option<String>,
        options: CoreBookmarkImportOptions,
    ) -> CoreBookmarkImportPlan {
        super::bookmark_import_plan(&import, &existing, target.as_deref(), &options)
    }

    #[uniffi::export(name = "bookmark_import_with_folder")]
    pub fn bookmark_import_with_folder(
        options: CoreBookmarkImportOptions,
        path: Vec<String>,
        action: CoreFolderAction,
    ) -> CoreBookmarkImportOptions {
        super::bookmark_import_with_folder(&options, &path, action)
    }

    #[uniffi::export(name = "bookmark_import_folders")]
    pub fn bookmark_import_folders(
        import: CoreBookmarkImport,
        options: CoreBookmarkImportOptions,
    ) -> Vec<CoreImportFolder> {
        super::bookmark_import_folders(&import, &options)
    }

    #[uniffi::export(name = "bookmark_export")]
    pub fn bookmark_export(
        bookmarks: Vec<CoreBookmark>,
        collections: Vec<CoreBookmarkCollection>,
        now: String,
    ) -> String {
        super::bookmark_export(&bookmarks, &collections, &now)
    }

    #[uniffi::export(name = "bookmark_export_html")]
    pub fn bookmark_export_html(
        bookmarks: Vec<CoreBookmark>,
        collections: Vec<CoreBookmarkCollection>,
    ) -> String {
        super::bookmark_export_html(&bookmarks, &collections)
    }

    #[uniffi::export(name = "bookmark_import")]
    pub fn bookmark_import(text: String) -> Result<CoreBookmarkImport, CoreError> {
        super::bookmark_import(&text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bookmarks::{bookmark_collection_parse, bookmark_parse};

    fn imported(url: &str, folder: &[&str]) -> CoreImportedBookmark {
        CoreImportedBookmark {
            draft: CoreBookmarkDraft {
                url: url.into(),
                title: url.into(),
                ..Default::default()
            },
            folder: folder.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn file(items: Vec<CoreImportedBookmark>) -> CoreBookmarkImport {
        CoreBookmarkImport {
            bookmarks: items,
            skipped: 0,
        }
    }

    fn stored(id: &str, name: &str, parent: Option<&str>) -> CoreBookmarkCollection {
        let mut payload = json!({"@type":"BookmarkCollection","name":name});
        if let Some(parent) = parent {
            payload["parentId"] = json!(parent);
        }
        bookmark_collection_parse(id, &payload.to_string())
    }

    fn depth(depth: u32) -> CoreBookmarkImportOptions {
        CoreBookmarkImportOptions {
            depth,
            rules: Vec::new(),
        }
    }

    fn rule(path: &[&str], action: CoreFolderAction) -> CoreFolderRule {
        CoreFolderRule {
            path: path.iter().map(|s| s.to_string()).collect(),
            action,
        }
    }

    fn homes(plan: &CoreBookmarkImportPlan) -> Vec<&str> {
        plan.bookmarks
            .iter()
            .map(|b| b.collection_id.as_str())
            .collect()
    }

    #[test]
    fn at_depth_zero_everything_goes_in_one_collection() {
        let plan = bookmark_import_plan(
            &file(vec![imported("a", &["F"]), imported("b", &[])]),
            &[],
            Some("target"),
            &depth(0),
        );
        assert!(plan.collections.is_empty());
        assert_eq!(homes(&plan), ["target", "target"]);
        let plan = bookmark_import_plan(&file(vec![imported("a", &["F"])]), &[], None, &depth(0));
        assert_eq!(
            plan.bookmarks[0].collection_id,
            default_bookmark_collection_id()
        );
    }

    #[test]
    fn every_folder_is_kept_once_and_nested_at_full_depth() {
        let plan = bookmark_import_plan(
            &file(vec![
                imported("a", &["Reading", "Deep"]),
                imported("b", &["Reading"]),
                imported("c", &["reading", "deep"]),
                imported("d", &[]),
            ]),
            &[],
            None,
            &depth(u32::MAX),
        );
        assert_eq!(plan.collections.len(), 2);
        let (reading, deep) = (&plan.collections[0], &plan.collections[1]);
        assert_eq!(reading.draft.name, "Reading");
        assert_eq!(reading.draft.parent_id, None);
        assert_eq!(deep.draft.parent_id.as_deref(), Some(reading.id.as_str()));
        assert_eq!(
            homes(&plan),
            [
                deep.id.as_str(),
                reading.id.as_str(),
                deep.id.as_str(),
                &default_bookmark_collection_id()
            ]
        );
    }

    #[test]
    fn depth_one_makes_the_top_folders_and_merges_what_is_below() {
        let plan = bookmark_import_plan(
            &file(vec![
                imported("a", &["Reading", "Deep"]),
                imported("b", &["Work"]),
                imported("c", &[]),
            ]),
            &[],
            None,
            &depth(1),
        );
        let names: Vec<&str> = plan
            .collections
            .iter()
            .map(|c| c.draft.name.as_str())
            .collect();
        assert_eq!(names, ["Reading", "Work"]);
        assert_eq!(
            homes(&plan),
            [
                plan.collections[0].id.as_str(),
                plan.collections[1].id.as_str(),
                &default_bookmark_collection_id()
            ]
        );
    }

    #[test]
    fn a_rule_overrides_the_depth_for_its_folder() {
        let import = file(vec![
            imported("a", &["Bar", "News"]),
            imported("b", &["Bar", "Old"]),
            imported("c", &["Other"]),
        ]);
        let options = CoreBookmarkImportOptions {
            depth: 1,
            rules: vec![
                rule(&["bar"], CoreFolderAction::Merge),
                rule(
                    &["Bar", "News"],
                    CoreFolderAction::Collection {
                        name: Some(" Headlines ".into()),
                    },
                ),
                rule(&["Bar", "Old"], CoreFolderAction::Skip),
                rule(
                    &["Other"],
                    CoreFolderAction::Existing {
                        collection_id: "mine".into(),
                    },
                ),
            ],
        };
        let plan = bookmark_import_plan(&import, &[], Some("target"), &options);
        assert_eq!(plan.excluded, 1);
        assert_eq!(plan.collections.len(), 1);
        assert_eq!(plan.collections[0].draft.name, "Headlines");
        assert_eq!(
            plan.collections[0].draft.parent_id.as_deref(),
            Some("target")
        );
        assert_eq!(homes(&plan), [plan.collections[0].id.as_str(), "mine"]);
    }

    #[test]
    fn setting_a_folder_keeps_a_rule_only_when_it_differs_from_the_depth() {
        let path = ["Reading".to_string(), "Deep".to_string()];
        let base = depth(1);
        let own =
            bookmark_import_with_folder(&base, &path, CoreFolderAction::Collection { name: None });
        assert_eq!(own.rules.len(), 1);
        let renamed = bookmark_import_with_folder(
            &own,
            &["reading".to_string(), "DEEP".to_string()],
            CoreFolderAction::Collection {
                name: Some("Later".into()),
            },
        );
        assert_eq!(renamed.rules.len(), 1);
        let blank = bookmark_import_with_folder(
            &renamed,
            &path,
            CoreFolderAction::Collection {
                name: Some("  ".into()),
            },
        );
        assert_eq!(
            blank.rules.len(),
            1,
            "a collection at depth 2 is not the default of depth 1"
        );
        let merged = bookmark_import_with_folder(&blank, &path, CoreFolderAction::Merge);
        assert_eq!(merged, base);
    }

    #[test]
    fn a_skipped_folder_skips_everything_below_it() {
        let options = CoreBookmarkImportOptions {
            depth: u32::MAX,
            rules: vec![rule(&["A"], CoreFolderAction::Skip)],
        };
        let import = file(vec![imported("a", &["A", "B"]), imported("b", &["C"])]);
        let plan = bookmark_import_plan(&import, &[], None, &options);
        assert_eq!(
            (plan.excluded, plan.bookmarks.len(), plan.collections.len()),
            (1, 1, 1)
        );
        let folders = bookmark_import_folders(&import, &options);
        let excluded: Vec<(Vec<String>, bool)> = folders
            .iter()
            .map(|f| (f.path.clone(), f.excluded))
            .collect();
        assert_eq!(
            excluded,
            [
                (vec!["A".to_string()], true),
                (vec!["A".to_string(), "B".to_string()], true),
                (vec!["C".to_string()], false),
            ]
        );
    }

    #[test]
    fn the_folder_list_counts_and_shows_the_effective_action() {
        let import = file(vec![
            imported("a", &["Reading", "Deep"]),
            imported("b", &["Reading"]),
            imported("c", &[]),
        ]);
        let folders = bookmark_import_folders(&import, &depth(1));
        assert_eq!(folders.len(), 2);
        assert_eq!(folders[0].path, ["Reading"]);
        assert_eq!((folders[0].direct, folders[0].total), (1, 2));
        assert_eq!(
            folders[0].action,
            CoreFolderAction::Collection { name: None }
        );
        assert_eq!(folders[1].path, ["Reading", "Deep"]);
        assert_eq!((folders[1].direct, folders[1].total), (1, 1));
        assert_eq!(folders[1].action, CoreFolderAction::Merge);
    }

    #[test]
    fn a_folder_that_already_exists_is_reused_not_doubled() {
        let existing = [stored("r", "Reading", None), stored("d", "Deep", Some("r"))];
        let plan = bookmark_import_plan(
            &file(vec![imported("a", &["READING", "Deep", "New"])]),
            &existing,
            None,
            &depth(u32::MAX),
        );
        assert_eq!(plan.collections.len(), 1);
        assert_eq!(plan.collections[0].draft.name, "New");
        assert_eq!(plan.collections[0].draft.parent_id.as_deref(), Some("d"));
    }

    #[test]
    fn folders_nest_under_the_chosen_collection_but_not_under_the_default_one() {
        let under = bookmark_import_plan(
            &file(vec![imported("a", &["F"])]),
            &[],
            Some("t"),
            &depth(1),
        );
        assert_eq!(under.collections[0].draft.parent_id.as_deref(), Some("t"));
        let default_id = default_bookmark_collection_id();
        let top = bookmark_import_plan(
            &file(vec![imported("a", &["F"])]),
            &[],
            Some(&default_id),
            &depth(1),
        );
        assert_eq!(top.collections[0].draft.parent_id, None);
    }

    #[test]
    fn oversized_imports_are_refused() {
        let big = format!("[{}]", " ".repeat(MAX_BOOKMARK_IMPORT_BYTES));
        assert!(bookmark_import(&big).is_err());
        let entry = r#"{"url":"https://a.example/","title":"a"},"#;
        let many = format!(
            "[{}{{\"url\":\"https://b.example/\"}}]",
            entry.repeat(MAX_IMPORTED_BOOKMARKS)
        );
        assert!(bookmark_import(&many).is_err());
    }

    fn bookmark(id: &str, payload: Value) -> CoreBookmark {
        bookmark_parse(id, &payload.to_string())
    }

    fn collection(id: &str, name: &str, parent: Option<&str>) -> CoreBookmarkCollection {
        let mut payload = json!({"@type": "BookmarkCollection", "name": name});
        if let Some(parent) = parent {
            payload["parentId"] = json!(parent);
        }
        bookmark_collection_parse(id, &payload.to_string())
    }

    fn folders_of(text: &str) -> Vec<Vec<String>> {
        bookmark_import(text)
            .unwrap()
            .bookmarks
            .into_iter()
            .map(|item| item.folder)
            .collect()
    }

    #[test]
    fn an_export_reads_back_into_the_tree_it_was_written_from() {
        let collections = vec![
            collection("a", "Work", None),
            collection("b", "Reading", Some("a")),
            collection("c", "Home", None),
            collection("d", "Reading", Some("c")),
        ];
        let in_collection = |id: &str, url: &str| {
            bookmark(
                id,
                json!({"@type":"Bookmark","url":url,"title":"t","collectionId":id}),
            )
        };
        let bookmarks = vec![
            in_collection("b", "https://one.example"),
            in_collection("d", "https://two.example"),
        ];
        let text = bookmark_export(&bookmarks, &collections, "2026-11-11T00:00:00Z");
        assert_eq!(
            folders_of(&text),
            [vec!["Work", "Reading"], vec!["Home", "Reading"]]
        );
    }

    #[test]
    fn an_export_without_ids_is_read_by_collection_name() {
        let text = r#"{"@type":"sealbook-bookmark-export","version":1,"bookmarks":[
            {"url":"https://a.example","title":"a","collectionName":"Reading"},
            {"url":"https://b.example","title":"b","collectionId":"gone","collectionName":"Later"}],
            "collections":[{"id":"c1","name":"Reading"}]}"#;
        assert_eq!(folders_of(text), [vec!["Reading"], vec!["Later"]]);
    }

    #[test]
    fn a_loop_in_an_exports_collections_ends_the_path() {
        let text = r#"{"@type":"sealbook-bookmark-export","version":1,"bookmarks":[
            {"url":"https://a.example","title":"a","collectionId":"x"}],
            "collections":[{"id":"x","name":"X","parentId":"y"},{"id":"y","name":"Y","parentId":"x"}]}"#;
        assert_eq!(folders_of(text), [vec!["Y", "X"]]);
    }

    #[test]
    fn json_import_skips_non_web_addresses() {
        let text = r#"[{"url":"javascript:alert(1)","title":"x"},{"url":"data:text/html,x","title":"y"},{"url":"https://ok.example","title":"z"}]"#;
        let read = bookmark_import(text).unwrap();
        assert_eq!(read.bookmarks.len(), 1);
        assert_eq!(read.skipped, 2);
    }

    #[test]
    fn an_export_has_the_shape_the_web_has_always_written() {
        let collections = vec![collection("c1", "Reading", None)];
        let bookmarks = vec![
            bookmark(
                "b1",
                json!({"@type":"Bookmark","url":"https://a.example","title":"A","notes":"n",
                       "tags":["x"],"collectionId":"c1","createdAt":"2026-01-01T00:00:00Z"}),
            ),
            bookmark("b2", json!({"@type":"Bookmark","url":"https://b.example"})),
        ];
        let out: Value = serde_json::from_str(&bookmark_export(
            &bookmarks,
            &collections,
            "2026-11-11T00:00:00Z",
        ))
        .unwrap();
        assert_eq!(out["@type"], "sealbook-bookmark-export");
        assert_eq!(out["version"], 1);
        assert_eq!(out["exportedAt"], "2026-11-11T00:00:00Z");
        assert_eq!(
            out["bookmarks"][0],
            json!({"url":"https://a.example","title":"A","notes":"n","tags":["x"],
                   "collectionId":"c1","collectionName":"Reading","createdAt":"2026-01-01T00:00:00Z"})
        );
        // No notes, tags or dates: none of those keys. An untitled bookmark
        // exports under its address, and a missing collection under the default.
        assert_eq!(
            out["bookmarks"][1],
            json!({"url":"https://b.example","title":"https://b.example",
                   "collectionId":"00000000-0000-0000-0000-000000000005","collectionName":"Default Collection"})
        );
        assert_eq!(out["collections"], json!([{"id":"c1","name":"Reading"}]));
    }

    #[test]
    fn an_export_reads_back_as_the_bookmarks_it_was_written_from() {
        let bookmarks = vec![bookmark(
            "b1",
            json!({"@type":"Bookmark","url":"https://a.example","title":"A","notes":"n","tags":["x","y"]}),
        )];
        let text = bookmark_export(&bookmarks, &[], "2026-11-11T00:00:00Z");
        let read = bookmark_import(&text).unwrap();
        assert_eq!(read.skipped, 0);
        assert_eq!(read.bookmarks.len(), 1);
        let draft = &read.bookmarks[0].draft;
        assert_eq!(
            (
                draft.url.as_str(),
                draft.title.as_str(),
                draft.notes.as_str()
            ),
            ("https://a.example", "A", "n")
        );
        assert_eq!(draft.tags, ["x", "y"]);
        assert_eq!(read.bookmarks[0].folder, ["Default Collection"]);
    }

    #[test]
    fn json_entries_are_read_as_the_web_read_them() {
        let text = r#"[
            {"url":"  https://a.example ","title":"  "},
            {"title":"No address"},
            {"url":"","title":""},
            "text",
            {"url":"https://c.example","tags":["ok",3,null],"notes":"","createdAt":"2025-05-05T00:00:00Z"}
        ]"#;
        let read = bookmark_import(text).unwrap();
        assert_eq!(read.skipped, 2);
        let titles: Vec<&str> = read
            .bookmarks
            .iter()
            .map(|b| b.draft.title.as_str())
            .collect();
        assert_eq!(
            titles,
            ["https://a.example", "No address", "https://c.example"]
        );
        assert_eq!(read.bookmarks[2].draft.tags, ["ok"]);
        assert_eq!(
            read.bookmarks[2].draft.created_at.as_deref(),
            Some("2025-05-05T00:00:00Z")
        );
        assert!(read.bookmarks[0].draft.collection_id.is_empty());
    }

    #[test]
    fn a_file_that_is_not_bookmarks_is_refused_with_a_sentence() {
        for text in ["not json", "5", "null", "\"x\""] {
            let err = bookmark_import(text).unwrap_err().to_string();
            assert!(err.contains(BOOKMARK_NOT_JSON), "{text}: {err}");
        }
        for text in [
            "{}",
            r#"{"@type":"other"}"#,
            r#"{"@type":"sealbook-bookmark-export"}"#,
        ] {
            let err = bookmark_import(text).unwrap_err().to_string();
            assert!(err.contains(BOOKMARK_UNRECOGNISED), "{text}: {err}");
        }
    }

    const FIREFOX: &str = r#"<!DOCTYPE NETSCAPE-Bookmark-file-1>
<!-- comment <A HREF="https://hidden.example">hidden</A> -->
<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">
<TITLE>Bookmarks</TITLE>
<H1>Bookmarks Menu</H1>
<DL><p>
    <DT><A HREF="https://top.example/?a=1&amp;b=2" ADD_DATE="1700000000" TAGS="one, two">Top &amp; <b>bold</b></A>
    <DT><H3 ADD_DATE="1">Reading</H3>
    <DL><p>
        <DT><A HREF="https://r.example" ADD_DATE="0">R</A>
        <DD>A note<br>on two lines
        <DT><H3>Deep</H3>
        <DL><p>
            <DT><A HREF='https://d.example'>Deep one</A>
        </DL><p>
        <DT><A HREF="place:sort=8">A query</A>
        <DT><A HREF="javascript:alert(1)">Bookmarklet</A>
    </DL><p>
    <DT><A HREF="https://after.example">After</A>
</DL><p>"#;

    #[test]
    fn a_browser_file_keeps_folders_tags_notes_and_dates() {
        let read = bookmark_import(FIREFOX).unwrap();
        assert_eq!(read.skipped, 2);
        let summary: Vec<(String, String, Vec<String>)> = read
            .bookmarks
            .iter()
            .map(|b| (b.draft.url.clone(), b.draft.title.clone(), b.folder.clone()))
            .collect();
        assert_eq!(
            summary,
            vec![
                (
                    "https://top.example/?a=1&b=2".into(),
                    "Top & bold".into(),
                    vec![]
                ),
                (
                    "https://r.example".into(),
                    "R".into(),
                    vec!["Reading".into()]
                ),
                (
                    "https://d.example".into(),
                    "Deep one".into(),
                    vec!["Reading".into(), "Deep".into()]
                ),
                ("https://after.example".into(), "After".into(), vec![]),
            ]
        );
        let top = &read.bookmarks[0].draft;
        assert_eq!(top.tags, ["one", "two"]);
        assert_eq!(top.created_at.as_deref(), Some("2023-11-14T22:13:20Z"));
        assert_eq!(read.bookmarks[1].draft.notes, "A note\non two lines");
        assert_eq!(
            read.bookmarks[1].draft.created_at.as_deref(),
            Some("1970-01-01T00:00:00Z")
        );
    }

    #[test]
    fn html_export_reads_back_with_the_same_folders() {
        let collections = vec![
            collection("c1", "Reading", None),
            collection("c2", "Deep & more", Some("c1")),
        ];
        let bookmarks = vec![
            bookmark(
                "b1",
                json!({"@type":"Bookmark","url":"https://a.example/?x=1&y=2","title":"A <b>","notes":"line1\nline2",
                       "tags":["t1","t2"],"collectionId":"c1","createdAt":"2023-11-14T22:13:20Z"}),
            ),
            bookmark(
                "b2",
                json!({"@type":"Bookmark","url":"https://b.example","title":"B","collectionId":"c2"}),
            ),
            bookmark(
                "b3",
                json!({"@type":"Bookmark","url":"https://c.example","title":"C","collectionId":"gone"}),
            ),
        ];
        let html = bookmark_export_html(&bookmarks, &collections);
        assert!(html.starts_with("<!DOCTYPE NETSCAPE-Bookmark-file-1>"));
        assert!(html.contains("ADD_DATE=\"1700000000\""), "{html}");
        let read = bookmark_import(&html).unwrap();
        assert_eq!(read.bookmarks.len(), 3, "{html}");
        let by_url = |url: &str| read.bookmarks.iter().find(|b| b.draft.url == url).unwrap();
        let a = by_url("https://a.example/?x=1&y=2");
        assert_eq!(a.draft.title, "A <b>");
        assert_eq!(a.draft.notes, "line1\nline2");
        assert_eq!(a.draft.tags, ["t1", "t2"]);
        assert_eq!(a.draft.created_at.as_deref(), Some("2023-11-14T22:13:20Z"));
        assert_eq!(a.folder, ["Reading"]);
        assert_eq!(
            by_url("https://b.example").folder,
            ["Reading", "Deep & more"]
        );
        assert!(by_url("https://c.example").folder.is_empty());
    }

    #[test]
    fn a_collection_cycle_does_not_lose_bookmarks_or_loop() {
        let collections = vec![
            collection("a", "A", Some("b")),
            collection("b", "B", Some("a")),
        ];
        let bookmarks = vec![
            bookmark(
                "1",
                json!({"@type":"Bookmark","url":"https://1.example","collectionId":"a"}),
            ),
            bookmark(
                "2",
                json!({"@type":"Bookmark","url":"https://2.example","collectionId":"b"}),
            ),
        ];
        let read = bookmark_import(&bookmark_export_html(&bookmarks, &collections)).unwrap();
        assert_eq!(read.bookmarks.len(), 2);
    }

    #[test]
    fn dates_round_trip_through_epoch_seconds() {
        for stamp in [
            "1970-01-01T00:00:00Z",
            "2000-02-29T12:34:56Z",
            "2038-01-19T03:14:08Z",
        ] {
            let seconds = epoch_from_rfc3339(stamp).unwrap();
            assert_eq!(rfc3339_from_epoch(seconds).unwrap(), stamp);
        }
        assert_eq!(
            epoch_from_rfc3339("2026-11-11T10:00:00+02:00"),
            epoch_from_rfc3339("2026-11-11T08:00:00Z")
        );
        assert_eq!(epoch_from_rfc3339("garbage"), None);
        assert_eq!(rfc3339_from_epoch(-1), None);
    }

    #[test]
    fn an_empty_or_unfinished_html_file_reads_as_nothing_rather_than_failing() {
        assert_eq!(bookmark_import("<html></html>").unwrap().bookmarks.len(), 0);
        assert_eq!(
            bookmark_import("<DL><DT><A HREF=\"https://x.example\"")
                .unwrap()
                .bookmarks
                .len(),
            0
        );
    }
}
