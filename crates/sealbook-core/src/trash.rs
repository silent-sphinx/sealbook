//! The trash: what is in it, what it hides, and how an item comes back out.
//!
//! An item in the trash is an ordinary object carrying a `trashedAt` stamp
//! (`sealbook:trashedAt` on a card, as with every Sealbook key on JSContact).
//! The server sees one more sealed write, so nothing here changes the wire.
//! Deleting forever is the tombstone write every client already makes.
//!
//! No type writer owns the stamp. An edit made while an item sits in the trash,
//! say from a client that was offline when it was trashed, carries the stamp
//! through rather than quietly bringing the item back. Only [`trash_write`] and
//! [`trash_restore_write`] set or clear it.
//!
//! The rules take [`TrashNode`]s rather than parsed types, so every client and
//! the CLI apply the same ones whatever they hold. A node is hidden when it, a
//! parent it sits under, or the container it is filed in is trashed, so a
//! notebook goes into the trash with its notes in one write and comes back
//! the same way.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::bookmark_file::epoch_from_rfc3339;
use crate::payload::{as_object, natural_json, refuse_newer_major};
use crate::{CoreError, CorePayloadKind};

/// How long an item stays in the trash before a client deletes it for good.
pub const TRASH_RETENTION_DAYS: i64 = 30;

pub const TRASHED_AT_KEY: &str = "trashedAt";
pub const CONTACT_TRASHED_AT_PROP: &str = "sealbook:trashedAt";

const DAY_SECS: i64 = 86_400;

/// One item, as the trash rules need to see it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct TrashNode {
    pub id: String,
    pub kind: CorePayloadKind,
    /// The item of the same kind this one sits under: a note's parent note, a
    /// task's parent task, a nested list or collection's parent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    /// The container an item is filed in. `None` on an item reads as the
    /// kind's default container, and is ignored on a container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trashed_at: Option<String>,
}

/// An item the trash lists: trashed itself, and not inside anything trashed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct TrashRoot {
    pub id: String,
    pub kind: CorePayloadKind,
    pub trashed_at: String,
    /// Whole days until a client deletes it for good, never below zero. `None`
    /// when the stamp cannot be read, which no client purges.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days_left: Option<i64>,
    /// How many items went into the trash with it.
    pub contained: u32,
}

/// What restoring one item writes, besides clearing its stamp.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct TrashRehome {
    /// The parent is still in the trash, so the item comes back at the top
    /// level instead.
    pub clear_parent: bool,
    /// The container is still in the trash, so the item comes back in this one,
    /// the kind's default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
}

fn trash_key(kind: CorePayloadKind) -> &'static str {
    match kind {
        CorePayloadKind::Contact => CONTACT_TRASHED_AT_PROP,
        _ => TRASHED_AT_KEY,
    }
}

fn container_key(kind: CorePayloadKind) -> Option<&'static str> {
    use CorePayloadKind::*;
    match kind {
        Contact => Some(sealbook_protocol::ADDRESS_BOOK_ID_PROP),
        CalendarEvent => Some("calendarId"),
        Note => Some("notebookId"),
        Task => Some("taskListId"),
        Bookmark => Some("collectionId"),
        _ => None,
    }
}

fn default_container(kind: CorePayloadKind) -> Option<String> {
    use sealbook_protocol::*;
    use CorePayloadKind::*;
    let id = match kind {
        Contact => DEFAULT_ADDRESS_BOOK_ID,
        CalendarEvent => DEFAULT_CALENDAR_ID,
        Note => DEFAULT_NOTEBOOK_ID,
        Task => DEFAULT_TASK_LIST_ID,
        Bookmark => DEFAULT_BOOKMARK_COLLECTION_ID,
        _ => return None,
    };
    Some(id.to_string())
}

/// The stamp a parsed payload carries, for the type parsers.
pub(crate) fn stored_trashed_at(
    kind: CorePayloadKind,
    object: &Map<String, Value>,
) -> Option<String> {
    object
        .get(trash_key(kind))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|stamp| !stamp.is_empty())
        .map(ToOwned::to_owned)
}

/// Puts a payload in the trash, stamped `now`, leaving every other key alone.
pub fn trash_write(kind: CorePayloadKind, raw: &str, now: &str) -> Result<String, CoreError> {
    let mut object = writable(raw)?;
    object.insert(trash_key(kind).into(), json!(now));
    Ok(natural_json(&Value::Object(object)))
}

/// Takes a payload out of the trash, moving it as `rehome` says.
pub fn trash_restore_write(
    kind: CorePayloadKind,
    raw: &str,
    rehome: Option<&TrashRehome>,
) -> Result<String, CoreError> {
    let mut object = writable(raw)?;
    object.remove(trash_key(kind));
    if let Some(rehome) = rehome {
        if rehome.clear_parent {
            object.remove("parentId");
        }
        if let (Some(key), Some(container)) = (container_key(kind), &rehome.container_id) {
            object.insert(key.into(), json!(container));
        }
    }
    Ok(natural_json(&Value::Object(object)))
}

fn writable(raw: &str) -> Result<Map<String, Value>, CoreError> {
    refuse_newer_major(Some(raw))?;
    as_object(raw).ok_or_else(|| CoreError::Malformed {
        detail: "payload is not a JSON object".into(),
    })
}

/// The node for a stored payload, for a host that holds payloads rather than
/// parsed records. `None` for a kind the trash does not hold.
pub fn trash_node(id: &str, kind: CorePayloadKind, raw: &str) -> Option<TrashNode> {
    use CorePayloadKind::*;
    let (parent_id, container_id, trashed_at) = match kind {
        Contact => {
            let contact = crate::contact_parse(id, raw);
            (None, Some(contact.address_book_id), contact.trashed_at)
        }
        AddressBook => (None, None, crate::address_book_parse(id, raw).trashed_at),
        Calendar => (None, None, crate::calendar_parse(id, raw).trashed_at),
        CalendarEvent => {
            let event = crate::event_parse(id, raw);
            (None, event.calendar_id, event.trashed_at)
        }
        Notebook => (None, None, crate::notebook_parse(id, raw).trashed_at),
        Note => {
            let note = crate::note_parse(id, raw);
            (note.parent_id, Some(note.notebook_id), note.trashed_at)
        }
        TaskList => {
            let list = crate::task_list_parse(id, raw);
            (list.parent_id, None, list.trashed_at)
        }
        Task => {
            let task = crate::task_parse(id, raw);
            (task.parent_id, Some(task.task_list_id), task.trashed_at)
        }
        BookmarkCollection => {
            let collection = crate::bookmark_collection_parse(id, raw);
            (collection.parent_id, None, collection.trashed_at)
        }
        Bookmark => {
            let bookmark = crate::bookmark_parse(id, raw);
            (None, Some(bookmark.collection_id), bookmark.trashed_at)
        }
        AccountSettings | DeviceLabel | Unknown => return None,
    };
    Some(TrashNode {
        id: id.to_string(),
        kind,
        parent_id,
        container_id,
        trashed_at,
    })
}

/// The links a node is hidden through: its parent, then its container.
struct Graph<'a> {
    nodes: HashMap<&'a str, &'a TrashNode>,
    ups: HashMap<&'a str, Vec<&'a str>>,
}

impl<'a> Graph<'a> {
    fn new(nodes: &'a [TrashNode]) -> Self {
        let by_id: HashMap<&str, &TrashNode> =
            nodes.iter().map(|node| (node.id.as_str(), node)).collect();
        let mut ups = HashMap::new();
        for node in nodes {
            let mut links = Vec::new();
            if let Some(parent) = node.parent_id.as_deref() {
                if parent != node.id && by_id.contains_key(parent) {
                    links.push(parent);
                }
            }
            if let Some(container) = node.container_id.as_deref() {
                if container_key(node.kind).is_some() && by_id.contains_key(container) {
                    links.push(container);
                }
            }
            ups.insert(node.id.as_str(), links);
        }
        Graph { nodes: by_id, ups }
    }

    fn trashed(&self, id: &str) -> bool {
        self.nodes
            .get(id)
            .is_some_and(|node| node.trashed_at.is_some())
    }

    /// Everything a node sits under, nearest first, not including itself. A
    /// cycle stops at the first repeat.
    fn ancestors(&self, id: &'a str) -> Vec<&'a str> {
        let mut seen = HashSet::from([id]);
        let mut found = Vec::new();
        let mut queue = vec![id];
        while let Some(current) = queue.pop() {
            for &up in self.ups.get(current).into_iter().flatten() {
                if seen.insert(up) {
                    found.push(up);
                    queue.push(up);
                }
            }
        }
        found
    }

    fn hidden(&self, id: &'a str) -> bool {
        self.trashed(id) || self.ancestors(id).iter().any(|up| self.trashed(up))
    }

    fn is_root(&self, id: &'a str) -> bool {
        self.trashed(id) && !self.ancestors(id).iter().any(|up| self.trashed(up))
    }
}

/// Every id to leave out of a live view.
pub fn trash_hidden(nodes: &[TrashNode]) -> HashSet<String> {
    let graph = Graph::new(nodes);
    nodes
        .iter()
        .filter(|node| graph.hidden(&node.id))
        .map(|node| node.id.clone())
        .collect()
}

/// What the trash lists, newest first, with what each took with it.
pub fn trash_roots(nodes: &[TrashNode], now_secs: i64) -> Vec<TrashRoot> {
    let graph = Graph::new(nodes);
    let mut contained: HashMap<&str, u32> = HashMap::new();
    for node in nodes {
        for up in graph.ancestors(&node.id) {
            if graph.is_root(up) {
                *contained.entry(up).or_default() += 1;
            }
        }
    }
    let mut roots: Vec<TrashRoot> = nodes
        .iter()
        .filter(|node| graph.is_root(&node.id))
        .map(|node| {
            let trashed_at = node.trashed_at.clone().unwrap_or_default();
            TrashRoot {
                id: node.id.clone(),
                kind: node.kind,
                days_left: epoch_from_rfc3339(&trashed_at).map(|stamp| {
                    let left = stamp + TRASH_RETENTION_DAYS * DAY_SECS - now_secs;
                    (left + DAY_SECS - 1).div_euclid(DAY_SECS).max(0)
                }),
                contained: contained.get(node.id.as_str()).copied().unwrap_or(0),
                trashed_at,
            }
        })
        .collect();
    roots.sort_by(|a, b| {
        let stamp = |root: &TrashRoot| epoch_from_rfc3339(&root.trashed_at).unwrap_or(i64::MIN);
        stamp(b).cmp(&stamp(a)).then_with(|| a.id.cmp(&b.id))
    });
    roots
}

/// How restoring `id` lands: `None` when it comes back where it was.
///
/// Restoring never brings back a parent or container the user did not pick, so
/// an item whose parent is still trashed comes back at the top level, and one
/// whose container is still trashed comes back in the default one.
pub fn trash_restore_plan(nodes: &[TrashNode], id: &str) -> Option<TrashRehome> {
    let graph = Graph::new(nodes);
    let node = graph.nodes.get(id)?;
    let clear_parent = node
        .parent_id
        .as_deref()
        .is_some_and(|parent| graph.nodes.contains_key(parent) && graph.hidden(parent));
    let container_hidden = container_key(node.kind).is_some()
        && node.container_id.as_deref().is_some_and(|container| {
            graph.nodes.contains_key(container) && graph.hidden(container)
        });
    let rehome = TrashRehome {
        clear_parent,
        container_id: if container_hidden {
            default_container(node.kind)
        } else {
            None
        },
    };
    (rehome != TrashRehome::default()).then_some(rehome)
}

/// Every id to tombstone to delete `ids` for good: each one and everything
/// inside it, innermost first, so a run cut short leaves the outer item to
/// retry from.
pub fn trash_purge_plan(nodes: &[TrashNode], ids: &[String]) -> Vec<String> {
    let graph = Graph::new(nodes);
    let wanted: HashSet<&str> = ids.iter().map(String::as_str).collect();
    let mut plan: Vec<(usize, &str)> = nodes
        .iter()
        .filter_map(|node| {
            let ancestors = graph.ancestors(&node.id);
            let inside =
                wanted.contains(node.id.as_str()) || ancestors.iter().any(|up| wanted.contains(up));
            inside.then_some((ancestors.len(), node.id.as_str()))
        })
        .collect();
    plan.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1)));
    let mut ids: Vec<String> = plan.into_iter().map(|(_, id)| id.to_string()).collect();
    for id in wanted {
        if !graph.nodes.contains_key(id) {
            ids.push(id.to_string());
        }
    }
    ids
}

/// The roots that have been in the trash longer than [`TRASH_RETENTION_DAYS`].
/// Pass them to [`trash_purge_plan`].
pub fn trash_expired(nodes: &[TrashNode], now_secs: i64) -> Vec<String> {
    let cutoff = now_secs - TRASH_RETENTION_DAYS * DAY_SECS;
    let graph = Graph::new(nodes);
    nodes
        .iter()
        .filter(|node| graph.is_root(&node.id))
        .filter(|node| {
            node.trashed_at
                .as_deref()
                .and_then(epoch_from_rfc3339)
                .is_some_and(|stamp| stamp <= cutoff)
        })
        .map(|node| node.id.clone())
        .collect()
}

#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{TrashNode, TrashRehome, TrashRoot};
    use crate::{CoreError, CorePayloadKind};

    #[uniffi::export(name = "trash_write")]
    pub fn trash_write(
        kind: CorePayloadKind,
        raw: String,
        now: String,
    ) -> Result<String, CoreError> {
        super::trash_write(kind, &raw, &now)
    }

    #[uniffi::export(name = "trash_restore_write")]
    pub fn trash_restore_write(
        kind: CorePayloadKind,
        raw: String,
        rehome: Option<TrashRehome>,
    ) -> Result<String, CoreError> {
        super::trash_restore_write(kind, &raw, rehome.as_ref())
    }

    #[uniffi::export(name = "trash_node")]
    pub fn trash_node(id: String, kind: CorePayloadKind, raw: String) -> Option<TrashNode> {
        super::trash_node(&id, kind, &raw)
    }

    #[uniffi::export(name = "trash_hidden")]
    pub fn trash_hidden(nodes: Vec<TrashNode>) -> Vec<String> {
        let mut ids: Vec<String> = super::trash_hidden(&nodes).into_iter().collect();
        ids.sort();
        ids
    }

    #[uniffi::export(name = "trash_roots")]
    pub fn trash_roots(nodes: Vec<TrashNode>, now_secs: i64) -> Vec<TrashRoot> {
        super::trash_roots(&nodes, now_secs)
    }

    #[uniffi::export(name = "trash_restore_plan")]
    pub fn trash_restore_plan(nodes: Vec<TrashNode>, id: String) -> Option<TrashRehome> {
        super::trash_restore_plan(&nodes, &id)
    }

    #[uniffi::export(name = "trash_purge_plan")]
    pub fn trash_purge_plan(nodes: Vec<TrashNode>, ids: Vec<String>) -> Vec<String> {
        super::trash_purge_plan(&nodes, &ids)
    }

    #[uniffi::export(name = "trash_expired")]
    pub fn trash_expired(nodes: Vec<TrashNode>, now_secs: i64) -> Vec<String> {
        super::trash_expired(&nodes, now_secs)
    }

    #[uniffi::export(name = "trash_retention_days")]
    pub fn trash_retention_days() -> i64 {
        super::TRASH_RETENTION_DAYS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use CorePayloadKind::*;

    fn node(
        id: &str,
        kind: CorePayloadKind,
        parent: Option<&str>,
        container: Option<&str>,
        trashed: Option<&str>,
    ) -> TrashNode {
        TrashNode {
            id: id.into(),
            kind,
            parent_id: parent.map(Into::into),
            container_id: container.map(Into::into),
            trashed_at: trashed.map(Into::into),
        }
    }

    const T: &str = "2026-11-01T00:00:00Z";
    const T_SECS: i64 = 1_793_491_200;

    fn notebook_with_notes(
        notebook_trashed: Option<&str>,
        child_trashed: Option<&str>,
    ) -> Vec<TrashNode> {
        vec![
            node("book", Notebook, None, None, notebook_trashed),
            node("a", Note, None, Some("book"), None),
            node("b", Note, Some("a"), Some("book"), child_trashed),
            node("other", Note, None, Some("elsewhere"), None),
            node("elsewhere", Notebook, None, None, None),
        ]
    }

    #[test]
    fn a_trashed_container_hides_its_contents() {
        let nodes = notebook_with_notes(Some(T), None);
        let hidden = trash_hidden(&nodes);
        assert_eq!(
            hidden,
            HashSet::from(["book".into(), "a".into(), "b".into()])
        );
        let roots = trash_roots(&nodes, T_SECS);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].id, "book");
        assert_eq!(roots[0].contained, 2);
        assert_eq!(roots[0].days_left, Some(30));
    }

    #[test]
    fn a_trashed_note_hides_the_notes_under_it() {
        let mut nodes = notebook_with_notes(None, None);
        nodes[1].trashed_at = Some(T.into());
        assert_eq!(
            trash_hidden(&nodes),
            HashSet::from(["a".into(), "b".into()])
        );
    }

    #[test]
    fn an_item_trashed_before_its_container_is_listed_again_once_the_container_is_back() {
        let nodes = notebook_with_notes(Some(T), Some("2026-10-30T00:00:00Z"));
        assert_eq!(trash_roots(&nodes, T_SECS).len(), 1);
        let mut restored = nodes.clone();
        restored[0].trashed_at = None;
        let roots = trash_roots(&restored, T_SECS);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].id, "b");
    }

    #[test]
    fn restoring_into_a_trashed_parent_moves_the_item_out() {
        let mut nodes = notebook_with_notes(Some(T), Some(T));
        nodes[1].trashed_at = Some(T.into());
        let rehome = trash_restore_plan(&nodes, "b").unwrap();
        assert!(rehome.clear_parent);
        assert_eq!(
            rehome.container_id.as_deref(),
            Some(sealbook_protocol::DEFAULT_NOTEBOOK_ID.to_string().as_str())
        );
        assert_eq!(trash_restore_plan(&nodes, "book"), None);
    }

    #[test]
    fn a_purge_takes_everything_inside_innermost_first() {
        let nodes = notebook_with_notes(Some(T), None);
        assert_eq!(
            trash_purge_plan(&nodes, &["book".into()]),
            vec!["b", "a", "book"]
        );
        assert_eq!(trash_purge_plan(&nodes, &["gone".into()]), vec!["gone"]);
    }

    #[test]
    fn expiry_falls_on_the_retention_boundary() {
        let nodes = notebook_with_notes(Some(T), None);
        let boundary = T_SECS + TRASH_RETENTION_DAYS * DAY_SECS;
        assert!(trash_expired(&nodes, boundary - 1).is_empty());
        assert_eq!(trash_expired(&nodes, boundary), vec!["book"]);
        assert_eq!(
            trash_roots(&nodes, boundary + DAY_SECS)[0].days_left,
            Some(0)
        );
    }

    #[test]
    fn an_unreadable_stamp_still_hides_but_never_expires() {
        let nodes = vec![node("x", Bookmark, None, None, Some("yesterday"))];
        assert_eq!(trash_hidden(&nodes).len(), 1);
        assert!(trash_expired(&nodes, i64::MAX / 2).is_empty());
        assert_eq!(trash_roots(&nodes, 0)[0].days_left, None);
    }

    #[test]
    fn a_cycle_does_not_hang() {
        let nodes = vec![
            node("x", TaskList, Some("y"), None, Some(T)),
            node("y", TaskList, Some("x"), None, None),
        ];
        assert_eq!(trash_hidden(&nodes).len(), 2);
    }

    #[test]
    fn a_contact_is_stamped_under_its_own_key_and_restored_to_the_default_book() {
        let raw = r#"{"@type":"Card","version":"1.0","sealbook:addressBookId":"gone","name":{"full":"A"}}"#;
        let trashed = trash_write(Contact, raw, T).unwrap();
        assert!(trashed.contains(r#""sealbook:trashedAt":"2026-11-01T00:00:00Z""#));
        let rehome = TrashRehome {
            clear_parent: false,
            container_id: Some("book-1".into()),
        };
        let restored = trash_restore_write(Contact, &trashed, Some(&rehome)).unwrap();
        assert!(!restored.contains("trashedAt"));
        assert!(restored.contains(r#""sealbook:addressBookId":"book-1""#));
    }

    #[test]
    fn a_newer_major_is_not_rewritten() {
        let raw = r#"{"@type":"Note","version":"99.0","title":"x"}"#;
        assert!(trash_write(Note, raw, T).is_err());
    }
}
