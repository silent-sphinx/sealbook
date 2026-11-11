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
    bookmark_collection_name_by_id, CoreBookmark, CoreBookmarkCollection, CoreBookmarkDraft,
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

/// Reads a bookmark file: Netscape HTML when it starts with a tag, else a
/// Sealbook export or a JSON array.
pub fn bookmark_import(text: &str) -> Result<CoreBookmarkImport, CoreError> {
    if text.trim_start().starts_with('<') {
        Ok(import_html(text))
    } else {
        import_json(text)
    }
}

fn import_json(text: &str) -> Result<CoreBookmarkImport, CoreError> {
    let parsed: Value =
        serde_json::from_str(text).map_err(|_| CoreError::malformed(BOOKMARK_NOT_JSON))?;
    if !parsed.is_array() && !parsed.is_object() {
        return Err(CoreError::malformed(BOOKMARK_NOT_JSON));
    }
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
            folder: name.map(|name| vec![name.to_owned()]).unwrap_or_default(),
        });
    }
    Ok(CoreBookmarkImport { bookmarks, skipped })
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
    use super::{CoreBookmark, CoreBookmarkCollection, CoreBookmarkImport, CoreError};

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
                   "collectionName":"Reading","createdAt":"2026-01-01T00:00:00Z"})
        );
        // No notes, tags or dates: none of those keys. An untitled bookmark
        // exports under its address, and a missing collection under the default.
        assert_eq!(
            out["bookmarks"][1],
            json!({"url":"https://b.example","title":"https://b.example",
                   "collectionName":"Default Collection"})
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
