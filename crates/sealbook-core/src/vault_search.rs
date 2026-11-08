//! Search across the whole vault: one index a client builds when its search
//! opens and asks per keystroke.
//!
//! Contacts are ranked by [`ContactIndex`], unchanged. Notes, tasks, bookmarks
//! and events are read from their stored payloads, and each whitespace-separated
//! word of the query has to be found somewhere on the item. A hit in the title
//! ranks before one in a tag, address or place, which ranks before one in the
//! body, which ranks before the container's name. Case and accents are folded.
//!
//! The index searches everything it is given. What to leave out, such as an
//! archived contact, a finished task or a hidden calendar, is the host's to
//! decide by not passing it in.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::contact_search::{ContactIndex, CoreBookName, CoreContactSource};
use crate::order::{name_key, stamp_millis};
use crate::{bookmark_parse, contact_parse, event_parse, note_parse, task_parse};

/// What a search result is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum CoreSearchKind {
    Contact,
    Event,
    Note,
    Bookmark,
    Task,
}

/// A stored note, task, bookmark or event, as a host holds it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreSearchSource {
    pub kind: CoreSearchKind,
    pub id: String,
    pub raw: String,
}

/// A notebook, task list, collection or calendar name, shown beside a result
/// and searched last.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreSearchContainer {
    pub kind: CoreSearchKind,
    pub id: String,
    pub name: String,
}

/// One result. `context` is the container's name, or a contact's employer.
/// `snippet` is the text around the first hit, when the hit was in a body.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreSearchHit {
    pub kind: CoreSearchKind,
    pub id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
}

/// Characters of body shown around a hit.
const SNIPPET_CHARS: usize = 90;
/// Of those, how many come before the hit.
const SNIPPET_LEAD: usize = 30;

struct Item {
    kind: CoreSearchKind,
    id: String,
    title: String,
    context: Option<String>,
    stamp: i64,
    folded_title: String,
    title_words: Vec<String>,
    fields: Vec<String>,
    body: String,
    folded_body: String,
    container: String,
}

struct Label {
    title: String,
    context: Option<String>,
}

pub struct VaultIndex {
    contacts: ContactIndex,
    contact_labels: HashMap<String, Label>,
    items: Vec<Item>,
}

fn words_of(folded: &str) -> Vec<String> {
    folded
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect()
}

fn item(source: &CoreSearchSource, containers: &HashMap<(CoreSearchKind, &str), &str>) -> Item {
    let (title, container_id, fields, body, stamp) = match source.kind {
        CoreSearchKind::Note => {
            let note = note_parse(&source.id, &source.raw);
            let stamp = note.updated_at.or(note.created_at);
            (note.title, note.notebook_id, Vec::new(), note.body, stamp)
        }
        CoreSearchKind::Task => {
            let task = task_parse(&source.id, &source.raw);
            let stamp = task.updated_at.or(task.created_at);
            (task.title, task.task_list_id, task.tags, task.notes, stamp)
        }
        CoreSearchKind::Bookmark => {
            let bookmark = bookmark_parse(&source.id, &source.raw);
            let mut fields = bookmark.tags;
            fields.push(bookmark.url);
            let stamp = bookmark.updated_at.or(bookmark.created_at);
            (
                bookmark.title,
                bookmark.collection_id,
                fields,
                bookmark.notes,
                stamp,
            )
        }
        CoreSearchKind::Event => {
            let event = event_parse(&source.id, &source.raw);
            let mut fields = event.participants;
            fields.extend(event.location);
            (
                event.title,
                event.calendar_id.unwrap_or_default(),
                fields,
                event.notes.unwrap_or_default(),
                Some(event.start),
            )
        }
        CoreSearchKind::Contact => unreachable!("contacts are indexed by ContactIndex"),
    };
    let context = containers
        .get(&(source.kind, container_id.as_str()))
        .map(|name| (*name).to_owned());
    let folded_title = name_key(&title);
    Item {
        kind: source.kind,
        id: source.id.clone(),
        title_words: words_of(&folded_title),
        folded_title,
        fields: fields
            .iter()
            .filter(|text| !text.is_empty())
            .map(|text| name_key(text))
            .collect(),
        folded_body: name_key(&body),
        body,
        container: context.as_deref().map(name_key).unwrap_or_default(),
        context,
        stamp: stamp_millis(stamp.as_deref()),
        title,
    }
}

impl Item {
    /// Where a word was found, lowest first, or None if it was not.
    fn score(&self, word: &str) -> Option<u8> {
        if self.folded_title.starts_with(word) {
            Some(0)
        } else if self.title_words.iter().any(|w| w.starts_with(word)) {
            Some(1)
        } else if self.folded_title.contains(word) {
            Some(2)
        } else if self.fields.iter().any(|text| text.contains(word)) {
            Some(3)
        } else if self.folded_body.contains(word) {
            Some(4)
        } else if self.container.contains(word) {
            Some(5)
        } else {
            None
        }
    }

    /// The body around the first word found in it, on one line.
    fn snippet(&self, words: &[&str]) -> Option<String> {
        let first = words
            .iter()
            .filter_map(|word| fold_find(&self.body, word))
            .min()?;
        Some(excerpt(&self.body, first))
    }
}

/// The char index in `text` where the folded `word` first starts. Folding can
/// change a text's length, so it is done char by char to keep the mapping.
fn fold_find(text: &str, word: &str) -> Option<usize> {
    let mut folded = String::new();
    let mut origin: Vec<usize> = Vec::new();
    for (index, c) in text.chars().enumerate() {
        let piece = name_key(c.encode_utf8(&mut [0; 4]));
        origin.extend(std::iter::repeat_n(index, piece.len()));
        folded.push_str(&piece);
    }
    let at = folded.find(word)?;
    origin.get(at).copied()
}

/// About [`SNIPPET_CHARS`] of `text` around char `at`, whitespace collapsed,
/// cut at word boundaries where one is near, with an ellipsis where cut.
fn excerpt(text: &str, at: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut start = at.saturating_sub(SNIPPET_LEAD);
    if start > 0 {
        if let Some(space) = chars[start..at].iter().position(|c| c.is_whitespace()) {
            start += space + 1;
        }
    }
    let mut end = (start + SNIPPET_CHARS).min(chars.len());
    if end < chars.len() {
        if let Some(space) = chars[at..end].iter().rposition(|c| c.is_whitespace()) {
            end = at + space;
        }
    }
    let middle: String = chars[start..end].iter().collect();
    let middle = middle.split_whitespace().collect::<Vec<_>>().join(" ");
    let lead = if start > 0 { "\u{2026}" } else { "" };
    let tail = if end < chars.len() { "\u{2026}" } else { "" };
    format!("{lead}{middle}{tail}")
}

impl VaultIndex {
    pub fn new(
        contacts: &[CoreContactSource],
        books: &[CoreBookName],
        sources: &[CoreSearchSource],
        containers: &[CoreSearchContainer],
    ) -> Self {
        let contact_labels = contacts
            .iter()
            .map(|source| {
                let contact = contact_parse(&source.id, &source.raw);
                let context = contact
                    .work
                    .iter()
                    .map(|work| work.organization.as_str())
                    .find(|name| !name.trim().is_empty())
                    .or_else(|| contact.emails.first().map(|email| email.value.as_str()))
                    .map(str::to_owned);
                let label = Label {
                    title: contact.display_name,
                    context,
                };
                (source.id.clone(), label)
            })
            .collect();
        let names: HashMap<(CoreSearchKind, &str), &str> = containers
            .iter()
            .map(|c| ((c.kind, c.id.as_str()), c.name.as_str()))
            .collect();
        let items = sources
            .iter()
            .filter(|source| source.kind != CoreSearchKind::Contact)
            .map(|source| item(source, &names))
            .collect();
        Self {
            contacts: ContactIndex::new(contacts, books),
            contact_labels,
            items,
        }
    }

    /// The best `per_kind` matches of each kind, contacts first, then events,
    /// notes, bookmarks and tasks, each best first. An empty query finds
    /// nothing.
    pub fn search(&self, query: &str, per_kind: u32) -> Vec<CoreSearchHit> {
        let folded = name_key(query.trim());
        let words: Vec<&str> = folded.split_whitespace().collect();
        if words.is_empty() || per_kind == 0 {
            return Vec::new();
        }
        let per_kind = per_kind as usize;

        let mut hits: Vec<CoreSearchHit> = self
            .contacts
            .search(query)
            .into_iter()
            .take(per_kind)
            .filter_map(|id| {
                let label = self.contact_labels.get(&id)?;
                Some(CoreSearchHit {
                    kind: CoreSearchKind::Contact,
                    title: label.title.clone(),
                    context: label.context.clone(),
                    snippet: None,
                    id,
                })
            })
            .collect();

        let mut found: Vec<(u8, &Item)> = self
            .items
            .iter()
            .filter_map(|item| {
                let mut worst = 0;
                for word in &words {
                    worst = worst.max(item.score(word)?);
                }
                Some((worst, item))
            })
            .collect();
        found.sort_by(|(a_score, a), (b_score, b)| {
            (a.kind as u8)
                .cmp(&(b.kind as u8))
                .then(a_score.cmp(b_score))
                .then(b.stamp.cmp(&a.stamp))
                .then_with(|| a.folded_title.cmp(&b.folded_title))
                .then_with(|| a.id.cmp(&b.id))
        });

        let mut taken: HashMap<CoreSearchKind, usize> = HashMap::new();
        for (score, item) in found {
            let count = taken.entry(item.kind).or_default();
            if *count == per_kind {
                continue;
            }
            *count += 1;
            hits.push(CoreSearchHit {
                kind: item.kind,
                id: item.id.clone(),
                title: item.title.clone(),
                context: item.context.clone(),
                snippet: if score == 4 {
                    item.snippet(&words)
                } else {
                    None
                },
            });
        }
        hits
    }
}

#[cfg(feature = "uniffi")]
pub mod ffi {
    use std::sync::Arc;

    use super::{CoreSearchContainer, CoreSearchHit, CoreSearchSource, VaultIndex};
    use crate::contact_search::{CoreBookName, CoreContactSource};

    #[derive(uniffi::Object)]
    pub struct VaultSearchIndex {
        inner: VaultIndex,
    }

    #[uniffi::export]
    impl VaultSearchIndex {
        #[uniffi::constructor]
        pub fn new(
            contacts: Vec<CoreContactSource>,
            books: Vec<CoreBookName>,
            sources: Vec<CoreSearchSource>,
            containers: Vec<CoreSearchContainer>,
        ) -> Arc<Self> {
            Arc::new(Self {
                inner: VaultIndex::new(&contacts, &books, &sources, &containers),
            })
        }

        pub fn search(&self, query: String, per_kind: u32) -> Vec<CoreSearchHit> {
            self.inner.search(&query, per_kind)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(kind: CoreSearchKind, id: &str, raw: serde_json::Value) -> CoreSearchSource {
        CoreSearchSource {
            kind,
            id: id.into(),
            raw: raw.to_string(),
        }
    }

    fn ids(hits: &[CoreSearchHit]) -> Vec<&str> {
        hits.iter().map(|hit| hit.id.as_str()).collect()
    }

    fn found(sources: &[CoreSearchSource], query: &str) -> Vec<CoreSearchHit> {
        VaultIndex::new(&[], &[], sources, &[]).search(query, 10)
    }

    #[test]
    fn a_title_ranks_before_a_body() {
        let sources = [
            source(
                CoreSearchKind::Note,
                "body",
                serde_json::json!({"title": "Shopping", "body": "garlic and basil"}),
            ),
            source(
                CoreSearchKind::Note,
                "title",
                serde_json::json!({"title": "Basil pesto", "body": ""}),
            ),
        ];
        assert_eq!(ids(&found(&sources, "basil")), ["title", "body"]);
    }

    #[test]
    fn accents_fold_and_every_word_must_match() {
        let sources = [source(
            CoreSearchKind::Task,
            "a",
            serde_json::json!({"title": "Call Ren\u{e9}e", "tags": ["home"]}),
        )];
        assert_eq!(ids(&found(&sources, "renee home")), ["a"]);
        assert!(found(&sources, "renee work").is_empty());
    }

    #[test]
    fn a_body_hit_carries_its_snippet_in_the_original_text() {
        let body = format!("{} Caf\u{e9} at noon {}", "x ".repeat(40), "y ".repeat(60));
        let sources = [source(
            CoreSearchKind::Note,
            "a",
            serde_json::json!({"title": "Plans", "body": body}),
        )];
        let snippet = found(&sources, "cafe")[0].snippet.clone().unwrap();
        assert!(snippet.starts_with('\u{2026}'), "{snippet}");
        assert!(snippet.ends_with('\u{2026}'), "{snippet}");
        assert!(snippet.contains("Caf\u{e9} at noon"), "{snippet}");
    }

    #[test]
    fn a_title_hit_has_no_snippet() {
        let sources = [source(
            CoreSearchKind::Note,
            "a",
            serde_json::json!({"title": "Cafe", "body": "Cafe"}),
        )];
        assert_eq!(found(&sources, "cafe")[0].snippet, None);
    }

    #[test]
    fn results_are_grouped_by_kind_and_capped_per_kind() {
        let sources = [
            source(
                CoreSearchKind::Task,
                "t1",
                serde_json::json!({"title": "Lunch"}),
            ),
            source(
                CoreSearchKind::Task,
                "t2",
                serde_json::json!({"title": "Lunch"}),
            ),
            source(
                CoreSearchKind::Event,
                "e",
                serde_json::json!({"title": "Lunch", "start": "2026-11-08T12:00:00Z"}),
            ),
        ];
        let hits = VaultIndex::new(&[], &[], &sources, &[]).search("lunch", 1);
        assert_eq!(ids(&hits), ["e", "t1"]);
    }

    #[test]
    fn the_container_name_is_context_and_searched_last() {
        let sources = [source(
            CoreSearchKind::Bookmark,
            "a",
            serde_json::json!({"url": "https://example.com", "title": "Example", "collectionId": "c"}),
        )];
        let containers = [CoreSearchContainer {
            kind: CoreSearchKind::Bookmark,
            id: "c".into(),
            name: "Reading".into(),
        }];
        let hits = VaultIndex::new(&[], &[], &sources, &containers).search("reading", 5);
        assert_eq!(ids(&hits), ["a"]);
        assert_eq!(hits[0].context.as_deref(), Some("Reading"));
    }

    #[test]
    fn an_empty_query_finds_nothing() {
        let sources = [source(
            CoreSearchKind::Task,
            "a",
            serde_json::json!({"title": "x"}),
        )];
        assert!(found(&sources, "   ").is_empty());
    }
}
