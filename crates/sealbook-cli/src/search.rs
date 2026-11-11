//! `search`: one query across everything the vault holds.
//!
//! Ranking, folding, snippets and the per-kind cap are core's `VaultIndex`.
//! What this file decides is what is put into it, which is what the web's
//! search palette puts in: what each tab lists by default. Archived contacts
//! and books, finished tasks, bookmarks in a collection kept out of "All",
//! events in an archived calendar and any feature switched off are left out.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use clap::ValueEnum;
use sealbook_client::{
    address_book_parse, bookmark_collection_parse, bookmark_parse, calendar_parse, contact_parse,
    event_parse, notebook_parse, resolve_address_book_id, resolve_collection_id, task_list_parse,
    task_parse, CoreAccountSettings, CoreBookName, CoreContactSource, CoreSearchContainer,
    CoreSearchHit, CoreSearchKind, CoreSearchSource, SealbookClient, VaultIndex,
};
use uuid::Uuid;

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Kind {
    Contact,
    Event,
    Note,
    Bookmark,
    Task,
}

impl Kind {
    fn core(self) -> CoreSearchKind {
        match self {
            Kind::Contact => CoreSearchKind::Contact,
            Kind::Event => CoreSearchKind::Event,
            Kind::Note => CoreSearchKind::Note,
            Kind::Bookmark => CoreSearchKind::Bookmark,
            Kind::Task => CoreSearchKind::Task,
        }
    }
}

fn kind_name(kind: CoreSearchKind) -> &'static str {
    match kind {
        CoreSearchKind::Contact => "contact",
        CoreSearchKind::Event => "event",
        CoreSearchKind::Note => "note",
        CoreSearchKind::Bookmark => "bookmark",
        CoreSearchKind::Task => "task",
    }
}

/// Everything stored, as the listings return it.
#[derive(Default)]
pub struct Stored {
    pub contacts: Vec<(Uuid, String)>,
    pub books: Vec<(Uuid, String)>,
    pub events: Vec<(Uuid, String)>,
    pub calendars: Vec<(Uuid, String)>,
    pub notes: Vec<(Uuid, String)>,
    pub notebooks: Vec<(Uuid, String)>,
    pub bookmarks: Vec<(Uuid, String)>,
    pub collections: Vec<(Uuid, String)>,
    pub tasks: Vec<(Uuid, String)>,
    pub task_lists: Vec<(Uuid, String)>,
}

pub async fn load(client: &mut SealbookClient) -> Result<Stored> {
    Ok(Stored {
        contacts: client.list_contacts().await.context("contacts")?,
        books: client.list_address_book_payloads().await.context("books")?,
        events: client.list_calendar_events().await.context("events")?,
        calendars: client.list_calendar_payloads().await.context("calendars")?,
        notes: client.list_notes().await.context("notes")?,
        notebooks: client.list_notebook_payloads().await.context("notebooks")?,
        bookmarks: client.list_bookmarks().await.context("bookmarks")?,
        collections: client
            .list_bookmark_collection_payloads()
            .await
            .context("collections")?,
        tasks: client.list_tasks().await.context("tasks")?,
        task_lists: client
            .list_task_list_payloads()
            .await
            .context("task lists")?,
    })
}

type Inputs = (
    Vec<CoreContactSource>,
    Vec<CoreBookName>,
    Vec<CoreSearchSource>,
    Vec<CoreSearchContainer>,
);

/// What the index is built from.
pub fn inputs(stored: &Stored, settings: &CoreAccountSettings) -> Inputs {
    let mut sources = Vec::new();
    let mut containers = Vec::new();
    let mut contacts = Vec::new();
    let mut books = Vec::new();
    let source = |kind, (id, raw): &(Uuid, String)| CoreSearchSource {
        kind,
        id: id.to_string(),
        raw: raw.clone(),
    };

    if settings.is_enabled("contacts") {
        let parsed: Vec<_> = stored
            .books
            .iter()
            .map(|(id, raw)| address_book_parse(&id.to_string(), raw))
            .collect();
        let archived: HashSet<&str> = parsed
            .iter()
            .filter(|book| book.archived)
            .map(|book| book.id.as_str())
            .collect();
        for (id, raw) in &stored.contacts {
            let contact = contact_parse(&id.to_string(), raw);
            let book = resolve_address_book_id(Some(contact.address_book_id.clone()));
            if !contact.archived && !archived.contains(book.as_str()) {
                contacts.push(CoreContactSource {
                    id: id.to_string(),
                    raw: raw.clone(),
                });
            }
        }
        books = parsed
            .iter()
            .map(|book| CoreBookName {
                id: book.id.clone(),
                name: book.name.clone(),
            })
            .collect();
    }

    if settings.is_enabled("calendar") {
        let parsed: Vec<_> = stored
            .calendars
            .iter()
            .map(|(id, raw)| calendar_parse(&id.to_string(), raw))
            .collect();
        let archived: HashSet<&str> = parsed
            .iter()
            .filter(|calendar| calendar.archived)
            .map(|calendar| calendar.id.as_str())
            .collect();
        for entry in &stored.events {
            let event = event_parse(&entry.0.to_string(), &entry.1);
            let hidden = event
                .calendar_id
                .as_deref()
                .is_some_and(|calendar| archived.contains(calendar));
            if !hidden {
                sources.push(source(CoreSearchKind::Event, entry));
            }
        }
        containers.extend(parsed.iter().map(|calendar| CoreSearchContainer {
            kind: CoreSearchKind::Event,
            id: calendar.id.clone(),
            name: calendar.name.clone(),
        }));
    }

    if settings.is_enabled("notes") {
        sources.extend(stored.notes.iter().map(|n| source(CoreSearchKind::Note, n)));
        containers.extend(
            stored
                .notebooks
                .iter()
                .map(|(id, raw)| CoreSearchContainer {
                    kind: CoreSearchKind::Note,
                    id: id.to_string(),
                    name: notebook_parse(&id.to_string(), raw).name,
                }),
        );
    }

    if settings.is_enabled("bookmarks") {
        let parsed: Vec<_> = stored
            .collections
            .iter()
            .map(|(id, raw)| bookmark_collection_parse(&id.to_string(), raw))
            .collect();
        let hidden = hidden_from_all(&parsed);
        for entry in &stored.bookmarks {
            let bookmark = bookmark_parse(&entry.0.to_string(), &entry.1);
            let holder = resolve_collection_id(Some(bookmark.collection_id));
            if !hidden.contains(holder.as_str()) {
                sources.push(source(CoreSearchKind::Bookmark, entry));
            }
        }
        containers.extend(parsed.iter().map(|collection| CoreSearchContainer {
            kind: CoreSearchKind::Bookmark,
            id: collection.id.clone(),
            name: collection.name.clone(),
        }));
    }

    if settings.is_enabled("tasks") {
        for entry in &stored.tasks {
            if !task_parse(&entry.0.to_string(), &entry.1).done {
                sources.push(source(CoreSearchKind::Task, entry));
            }
        }
        containers.extend(
            stored
                .task_lists
                .iter()
                .map(|(id, raw)| CoreSearchContainer {
                    kind: CoreSearchKind::Task,
                    id: id.to_string(),
                    name: task_list_parse(&id.to_string(), raw).name,
                }),
        );
    }

    (contacts, books, sources, containers)
}

/// Collections marked "hide from All", and every one nested under one. A cycle
/// in stored parents ends the walk instead of looping.
fn hidden_from_all(collections: &[sealbook_client::CoreBookmarkCollection]) -> HashSet<String> {
    let by_id: HashMap<&str, &sealbook_client::CoreBookmarkCollection> =
        collections.iter().map(|c| (c.id.as_str(), c)).collect();
    let mut hidden = HashSet::new();
    for collection in collections {
        let mut seen = HashSet::new();
        let mut at = Some(collection);
        while let Some(current) = at {
            if !seen.insert(current.id.as_str()) {
                break;
            }
            if current.hide_from_all {
                hidden.insert(collection.id.clone());
                break;
            }
            at = current
                .parent_id
                .as_deref()
                .and_then(|parent| by_id.get(parent).copied());
        }
    }
    hidden
}

pub fn search(
    stored: &Stored,
    settings: &CoreAccountSettings,
    query: &str,
    kinds: &[Kind],
    limit: u32,
) -> Vec<CoreSearchHit> {
    let (contacts, books, sources, containers) = inputs(stored, settings);
    let index = VaultIndex::new(&contacts, &books, &sources, &containers);
    let wanted: Vec<CoreSearchKind> = kinds.iter().map(|kind| kind.core()).collect();
    index
        .search(query, limit)
        .into_iter()
        .filter(|hit| wanted.is_empty() || wanted.contains(&hit.kind))
        .collect()
}

pub fn hit_lines(hits: &[CoreSearchHit]) -> Vec<String> {
    let mut lines = Vec::new();
    for hit in hits {
        let context = hit
            .context
            .as_deref()
            .map(|context| format!(" [{context}]"))
            .unwrap_or_default();
        lines.push(format!(
            "{:<8} {} {}{}",
            kind_name(hit.kind),
            hit.id,
            hit.title,
            context
        ));
        if let Some(snippet) = &hit.snippet {
            lines.push(format!("         {snippet}"));
        }
    }
    lines
}

pub async fn run(
    client: &mut SealbookClient,
    query: &str,
    kinds: &[Kind],
    limit: u32,
) -> Result<()> {
    let settings = client.account_settings().await.context("settings")?;
    let stored = load(client).await?;
    let hits = search(&stored, &settings, query, kinds, limit);
    if hits.is_empty() {
        println!("(nothing found)");
    }
    for line in hit_lines(&hits) {
        println!("{line}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealbook_client::default_account_settings;
    use serde_json::json;

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn stored() -> Stored {
        Stored {
            notes: vec![(
                id(1),
                json!({"@type":"Note","title":"Basil pesto","body":"garlic"}).to_string(),
            )],
            tasks: vec![
                (id(2), json!({"@type":"Task","title":"Buy basil"}).to_string()),
                (
                    id(3),
                    json!({"@type":"Task","title":"Basil done","done":true}).to_string(),
                ),
            ],
            calendars: vec![(
                id(4),
                json!({"@type":"Calendar","name":"Old","archived":true}).to_string(),
            )],
            events: vec![(
                id(5),
                json!({"@type":"CalendarEvent","title":"Basil lunch","start":"2026-11-08T12:00:00Z","calendarId":id(4).to_string()})
                    .to_string(),
            )],
            collections: vec![(
                id(6),
                json!({"@type":"BookmarkCollection","name":"Later","hideFromAll":true}).to_string(),
            )],
            bookmarks: vec![(
                id(7),
                json!({"@type":"Bookmark","title":"Basil site","url":"https://b.example","collectionId":id(6).to_string()})
                    .to_string(),
            )],
            ..Stored::default()
        }
    }

    fn found(settings: &CoreAccountSettings, kinds: &[Kind]) -> Vec<String> {
        search(&stored(), settings, "basil", kinds, 10)
            .into_iter()
            .map(|hit| hit.id)
            .collect()
    }

    #[test]
    fn finished_tasks_hidden_bookmarks_and_archived_calendars_are_left_out() {
        let hits = found(&default_account_settings(), &[]);
        assert_eq!(hits.len(), 2, "{hits:?}");
        assert!(hits.contains(&id(1).to_string()));
        assert!(hits.contains(&id(2).to_string()));
    }

    #[test]
    fn a_feature_that_is_off_is_not_searched() {
        let off = sealbook_client::settings_parse(
            r#"{"@type":"AccountSettings","version":"1.0","features":{"tasks":false}}"#,
        );
        assert_eq!(found(&off, &[]), vec![id(1).to_string()]);
    }

    #[test]
    fn kind_narrows_the_hits() {
        let hits = found(&default_account_settings(), &[Kind::Task]);
        assert_eq!(hits, vec![id(2).to_string()]);
    }

    #[test]
    fn a_hit_prints_its_kind_id_title_and_container() {
        let mut data = stored();
        data.task_lists = vec![(id(8), json!({"@type":"TaskList","name":"Home"}).to_string())];
        data.tasks = vec![(
            id(2),
            json!({"@type":"Task","title":"Buy basil","taskListId":id(8).to_string()}).to_string(),
        )];
        let hits = search(
            &data,
            &default_account_settings(),
            "basil",
            &[Kind::Task],
            5,
        );
        assert_eq!(
            hit_lines(&hits),
            vec![format!("task     {} Buy basil [Home]", id(2))]
        );
    }
}
