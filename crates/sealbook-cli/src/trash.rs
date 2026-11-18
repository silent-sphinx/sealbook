//! `sealbook trash`, and the remove step every `delete` command shares.

use anyhow::{Context, Result};
use clap::Subcommand;
use sealbook_client::{
    trash_expired, trash_nodes, trash_roots, CorePayloadKind, SealbookClient, TrashObject,
    TrashRoot,
};
use uuid::Uuid;

#[derive(Subcommand)]
pub enum TrashCommand {
    /// What is in the trash, newest first.
    List {},
    /// Take an item out of the trash, with everything that went in with it.
    Restore {
        #[arg(long)]
        id: Uuid,
    },
    /// Delete an item in the trash, and everything inside it, for good.
    Purge {
        #[arg(long)]
        id: Uuid,
    },
    /// Delete everything in the trash for good.
    Empty {
        /// Confirm: this cannot be undone.
        #[arg(long)]
        yes: bool,
    },
    /// Delete for good whatever has been in the trash longer than the
    /// retention period, as every client does once a day.
    Expire {},
}

const DEFAULT_CONTAINERS: [Uuid; 5] = [
    sealbook_client::DEFAULT_ADDRESS_BOOK_ID,
    sealbook_client::DEFAULT_NOTEBOOK_ID,
    sealbook_client::DEFAULT_CALENDAR_ID,
    sealbook_client::DEFAULT_BOOKMARK_COLLECTION_ID,
    sealbook_client::DEFAULT_TASK_LIST_ID,
];

/// Moves `id` to the trash, taking everything inside it along, or with
/// `forever` deletes it and everything inside it for good. Returns what to
/// print.
pub async fn remove(client: &mut SealbookClient, id: Uuid, forever: bool) -> Result<String> {
    if DEFAULT_CONTAINERS.contains(&id) {
        anyhow::bail!("a default container cannot be deleted");
    }
    let objects = client.trashable_objects().await.context("read vault")?;
    let object = objects
        .iter()
        .find(|object| object.id == id)
        .with_context(|| format!("nothing with id {id}"))?;
    if forever {
        let count = client.purge_objects(&objects, &[id]).await?;
        return Ok(format!(
            "deleted {} for good{}",
            describe(object),
            with_more(count)
        ));
    }
    if object.node.trashed_at.is_some() {
        return Ok(format!("{} is already in the trash", describe(object)));
    }
    client
        .trash_object(object, &crate::now_rfc3339())
        .await
        .context("move to trash")?;
    Ok(format!(
        "moved {} to the trash; `sealbook trash restore --id {id}` brings it back",
        describe(object)
    ))
}

pub async fn run(client: &mut SealbookClient, command: TrashCommand) -> Result<()> {
    let objects = client.trashable_objects().await.context("read vault")?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let roots = trash_roots(&trash_nodes(&objects), now);
    match command {
        TrashCommand::List {} => {
            if roots.is_empty() {
                println!("the trash is empty");
            }
            for root in &roots {
                println!("{}", root_line(&objects, root));
            }
        }
        TrashCommand::Restore { id } => {
            let object = objects
                .iter()
                .find(|object| object.id == id && object.node.trashed_at.is_some())
                .with_context(|| format!("{id} is not in the trash: see `trash list`"))?;
            client.restore_object(&objects, object).await?;
            println!("restored {}", describe(object));
        }
        TrashCommand::Purge { id } => {
            if !roots.iter().any(|root| root.id == id.to_string()) {
                anyhow::bail!("{id} is not in the trash: see `trash list`");
            }
            let count = client.purge_objects(&objects, &[id]).await?;
            println!("deleted {id} for good{}", with_more(count));
        }
        TrashCommand::Empty { yes } => {
            if !yes {
                anyhow::bail!(
                    "this deletes {} item(s) and everything inside them from every device; \
                     run again with --yes to confirm",
                    roots.len()
                );
            }
            let ids = root_ids(roots.iter().map(|root| root.id.as_str()));
            let count = client.purge_objects(&objects, &ids).await?;
            println!("emptied the trash: {count} object(s) deleted for good");
        }
        TrashCommand::Expire {} => {
            let expired = trash_expired(&trash_nodes(&objects), now);
            let ids = root_ids(expired.iter().map(String::as_str));
            let count = client.purge_objects(&objects, &ids).await?;
            println!("{count} object(s) deleted for good");
        }
    }
    Ok(())
}

fn root_ids<'a>(ids: impl Iterator<Item = &'a str>) -> Vec<Uuid> {
    ids.filter_map(|id| Uuid::parse_str(id).ok()).collect()
}

fn with_more(count: usize) -> String {
    match count.saturating_sub(1) {
        0 => String::new(),
        more => format!(" with {more} item(s) inside it"),
    }
}

fn root_line(objects: &[TrashObject], root: &TrashRoot) -> String {
    let what = objects
        .iter()
        .find(|object| object.id.to_string() == root.id)
        .map(describe)
        .unwrap_or_else(|| root.id.clone());
    let inside = match root.contained {
        0 => String::new(),
        n => format!(", {n} inside"),
    };
    let left = match root.days_left {
        Some(days) => format!("{days} day(s) left"),
        None => "kept until emptied".into(),
    };
    format!("{}  {what}{inside}  ({left})", root.id)
}

fn describe(object: &TrashObject) -> String {
    use CorePayloadKind::*;
    let id = object.id.to_string();
    let raw = &object.raw;
    let (kind, title) = match object.kind {
        Contact => (
            "contact",
            sealbook_client::contact_parse(&id, raw).display_name,
        ),
        AddressBook => (
            "address book",
            sealbook_client::address_book_parse(&id, raw).name,
        ),
        Calendar => ("calendar", sealbook_client::calendar_parse(&id, raw).name),
        CalendarEvent => ("event", sealbook_client::event_parse(&id, raw).title),
        Notebook => ("notebook", sealbook_client::notebook_parse(&id, raw).name),
        Note => ("note", sealbook_client::note_parse(&id, raw).title),
        TaskList => ("task list", sealbook_client::task_list_parse(&id, raw).name),
        Task => ("task", sealbook_client::task_parse(&id, raw).title),
        BookmarkCollection => (
            "collection",
            sealbook_client::bookmark_collection_parse(&id, raw).name,
        ),
        Bookmark => ("bookmark", sealbook_client::bookmark_parse(&id, raw).title),
        AccountSettings | DeviceLabel | Unknown => ("object", id.clone()),
    };
    format!("{kind} \"{title}\"")
}
