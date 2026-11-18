//! `search`: one query across everything the vault holds.
//!
//! Ranking, folding, snippets and the per-kind cap are core's `VaultIndex`.
//! What this file decides is what is put into it, which is what the web's
//! search palette puts in: what each tab lists by default. Archived contacts
//! and books, finished tasks, events in an archived calendar, notes, tasks and
//! bookmarks in an archived notebook, list or collection, and any feature
//! switched off are left out. Hiding a container from the overviews does not
//! leave its contents out: hidden content stays searchable.

use std::collections::HashSet;

use anyhow::{Context, Result};
use clap::ValueEnum;
use sealbook_client::{
    address_book_parse, bookmark_collection_parse, bookmark_parse, calendar_parse, contact_parse,
    event_parse, note_parse, notebook_parse, resolve_address_book_id, resolve_collection_id,
    task_list_parse, task_parse, trash_hidden, trash_node, CoreAccountSettings, CoreBookName,
    CoreContactSource, CorePayloadKind, CoreSearchContainer, CoreSearchHit, CoreSearchKind,
    CoreSearchSource, SealbookClient, VaultIndex,
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
    Ok(without_trash(Stored {
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
    }))
}

/// Leaves out whatever is in the trash, or inside something that is.
fn without_trash(mut stored: Stored) -> Stored {
    use CorePayloadKind::*;
    let mut nodes = Vec::new();
    for (kind, rows) in [
        (Contact, &stored.contacts),
        (AddressBook, &stored.books),
        (CalendarEvent, &stored.events),
        (Calendar, &stored.calendars),
        (Note, &stored.notes),
        (Notebook, &stored.notebooks),
        (Bookmark, &stored.bookmarks),
        (BookmarkCollection, &stored.collections),
        (Task, &stored.tasks),
        (TaskList, &stored.task_lists),
    ] {
        nodes.extend(
            rows.iter()
                .filter_map(|(id, raw)| trash_node(&id.to_string(), kind, raw)),
        );
    }
    let hidden = trash_hidden(&nodes);
    for rows in [
        &mut stored.contacts,
        &mut stored.books,
        &mut stored.events,
        &mut stored.calendars,
        &mut stored.notes,
        &mut stored.notebooks,
        &mut stored.bookmarks,
        &mut stored.collections,
        &mut stored.tasks,
        &mut stored.task_lists,
    ] {
        rows.retain(|(id, _)| !hidden.contains(&id.to_string()));
    }
    stored
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
        let parsed: Vec<_> = stored
            .notebooks
            .iter()
            .map(|(id, raw)| notebook_parse(&id.to_string(), raw))
            .collect();
        let archived: HashSet<&str> = parsed
            .iter()
            .filter(|notebook| notebook.archived)
            .map(|notebook| notebook.id.as_str())
            .collect();
        for entry in &stored.notes {
            if !archived.contains(
                note_parse(&entry.0.to_string(), &entry.1)
                    .notebook_id
                    .as_str(),
            ) {
                sources.push(source(CoreSearchKind::Note, entry));
            }
        }
        containers.extend(
            parsed
                .iter()
                .filter(|notebook| !notebook.archived)
                .map(|notebook| CoreSearchContainer {
                    kind: CoreSearchKind::Note,
                    id: notebook.id.clone(),
                    name: notebook.name.clone(),
                }),
        );
    }

    if settings.is_enabled("bookmarks") {
        let parsed: Vec<_> = stored
            .collections
            .iter()
            .map(|(id, raw)| bookmark_collection_parse(&id.to_string(), raw))
            .collect();
        let archived = flagged(
            parsed
                .iter()
                .map(|c| (&c.id, c.parent_id.as_ref(), c.archived)),
        );
        for entry in &stored.bookmarks {
            let bookmark = bookmark_parse(&entry.0.to_string(), &entry.1);
            let holder = resolve_collection_id(Some(bookmark.collection_id));
            if !archived.contains(holder.as_str()) {
                sources.push(source(CoreSearchKind::Bookmark, entry));
            }
        }
        containers.extend(
            parsed
                .iter()
                .filter(|c| !archived.contains(&c.id))
                .map(|collection| CoreSearchContainer {
                    kind: CoreSearchKind::Bookmark,
                    id: collection.id.clone(),
                    name: collection.name.clone(),
                }),
        );
    }

    if settings.is_enabled("tasks") {
        let parsed: Vec<_> = stored
            .task_lists
            .iter()
            .map(|(id, raw)| task_list_parse(&id.to_string(), raw))
            .collect();
        let archived = flagged(
            parsed
                .iter()
                .map(|l| (&l.id, l.parent_id.as_ref(), l.archived)),
        );
        for entry in &stored.tasks {
            let task = task_parse(&entry.0.to_string(), &entry.1);
            if !task.done && !archived.contains(&task.task_list_id) {
                sources.push(source(CoreSearchKind::Task, entry));
            }
        }
        containers.extend(
            parsed
                .iter()
                .filter(|list| !archived.contains(&list.id))
                .map(|list| CoreSearchContainer {
                    kind: CoreSearchKind::Task,
                    id: list.id.clone(),
                    name: list.name.clone(),
                }),
        );
    }

    (contacts, books, sources, containers)
}

/// The flagged items, and everything nested under one, from `(id, parent, flag)`.
fn flagged<'a>(
    items: impl Iterator<Item = (&'a String, Option<&'a String>, bool)>,
) -> HashSet<String> {
    let owned: Vec<_> = items
        .map(|(id, parent, flag)| (id.clone(), parent.cloned(), flag))
        .collect();
    sealbook_client::flagged_with_descendants(&owned)
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
            notes: vec![
                (
                    id(1),
                    json!({"@type":"Note","title":"Basil pesto","body":"garlic"}).to_string(),
                ),
                (
                    id(16),
                    json!({"@type":"Note","title":"Basil shelved","notebookId":id(11).to_string()})
                        .to_string(),
                ),
            ],
            tasks: vec![
                (id(2), json!({"@type":"Task","title":"Buy basil"}).to_string()),
                (
                    id(15),
                    json!({"@type":"Task","title":"Basil shelved","taskListId":id(13).to_string()})
                        .to_string(),
                ),
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
            ),
            (
                id(10),
                json!({"@type":"BookmarkCollection","name":"Put away","archived":true}).to_string(),
            )],
            notebooks: vec![(
                id(11),
                json!({"@type":"Notebook","name":"Shelved","archived":true}).to_string(),
            )],
            task_lists: vec![
                (
                    id(12),
                    json!({"@type":"TaskList","name":"Shelved","archived":true}).to_string(),
                ),
                (
                    id(13),
                    json!({"@type":"TaskList","name":"Inside","parentId":id(12).to_string()})
                        .to_string(),
                ),
            ],
            bookmarks: vec![
                (
                    id(7),
                    json!({"@type":"Bookmark","title":"Basil site","url":"https://b.example","collectionId":id(6).to_string()})
                        .to_string(),
                ),
                (
                    id(14),
                    json!({"@type":"Bookmark","title":"Basil shelf","url":"https://c.example","collectionId":id(10).to_string()})
                        .to_string(),
                ),
            ],
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
    fn finished_tasks_and_archived_content_are_left_out_but_hidden_content_is_not() {
        let hits = found(&default_account_settings(), &[]);
        assert_eq!(hits.len(), 3, "{hits:?}");
        assert!(hits.contains(&id(1).to_string()));
        assert!(hits.contains(&id(2).to_string()));
        assert!(
            hits.contains(&id(7).to_string()),
            "a hidden collection's bookmark"
        );
    }

    #[test]
    fn a_feature_that_is_off_is_not_searched() {
        let off = sealbook_client::settings_parse(
            r#"{"@type":"AccountSettings","version":"1.0","features":{"tasks":false}}"#,
        );
        let hits = found(&off, &[]);
        assert_eq!(hits.len(), 2, "{hits:?}");
        assert!(hits.contains(&id(1).to_string()));
        assert!(hits.contains(&id(7).to_string()));
        assert!(!hits.contains(&id(2).to_string()), "tasks are off");
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
