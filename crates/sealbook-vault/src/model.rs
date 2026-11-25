//! The typed view of the vault: every object parsed once, and kept up to date by
//! re-parsing only the ids that changed.
//!
//! The model is a function of the local copy of the vault and the outbox laid
//! over it. [`VaultModel::update`] and [`VaultModel::rebuild`] must agree, which
//! the tests check.

use std::collections::{BTreeMap, HashMap};

use sealbook_core::{
    address_book_parse, bookmark_collection_parse, bookmark_parse, calendar_parse, contact_parse,
    device_label_parse, event_parse, note_parse, notebook_parse, payload_kind, settings_parse,
    task_list_parse, task_parse, CoreAccountSettings, CoreAddressBook, CoreBookmark,
    CoreBookmarkCollection, CoreCalendar, CoreCalendarEvent, CoreContact, CoreDeviceLabel,
    CoreNote, CoreNotebook, CorePayloadKind, CoreTask, CoreTaskList, LocalObject, LocalVault,
    Outbox,
};

#[derive(Clone, Debug, PartialEq)]
pub enum Item {
    Contact(Box<CoreContact>),
    AddressBook(Box<CoreAddressBook>),
    Note(Box<CoreNote>),
    Notebook(Box<CoreNotebook>),
    Task(Box<CoreTask>),
    TaskList(Box<CoreTaskList>),
    Bookmark(Box<CoreBookmark>),
    BookmarkCollection(Box<CoreBookmarkCollection>),
    Calendar(Box<CoreCalendar>),
    Event(Box<CoreCalendarEvent>),
    Settings(Box<CoreAccountSettings>),
    DeviceLabel(Box<CoreDeviceLabel>),
}

/// One object: what it parsed to, and the stored payload it came from, which an
/// edit writes back so keys this build does not know survive.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub id: String,
    pub kind: CorePayloadKind,
    pub content_type: String,
    /// 0 for an object only the outbox holds.
    pub revision: u64,
    pub raw: String,
    pub item: Item,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Updated,
    Removed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub id: String,
    pub kind: CorePayloadKind,
    pub change: ChangeKind,
}

/// What an update touched, so a view redraws only the rows it shows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChangeSet {
    pub changes: Vec<Change>,
    /// The model was rebuilt from nothing (an unlock, a full read): every view
    /// should read it again.
    pub everything: bool,
}

impl ChangeSet {
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty() && !self.everything
    }

    pub fn touches(&self, kind: CorePayloadKind) -> bool {
        self.everything || self.changes.iter().any(|change| change.kind == kind)
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct VaultModel {
    entries: BTreeMap<String, Entry>,
}

fn parse_entry(object: &LocalObject) -> Option<Entry> {
    let raw = &object.payload;
    let id = &object.id;
    let kind = payload_kind(&object.content_type, raw);
    let item = match kind {
        CorePayloadKind::Contact => Item::Contact(Box::new(contact_parse(id, raw))),
        CorePayloadKind::AddressBook => Item::AddressBook(Box::new(address_book_parse(id, raw))),
        CorePayloadKind::Note => Item::Note(Box::new(note_parse(id, raw))),
        CorePayloadKind::Notebook => Item::Notebook(Box::new(notebook_parse(id, raw))),
        CorePayloadKind::Task => Item::Task(Box::new(task_parse(id, raw))),
        CorePayloadKind::TaskList => Item::TaskList(Box::new(task_list_parse(id, raw))),
        CorePayloadKind::Bookmark => Item::Bookmark(Box::new(bookmark_parse(id, raw))),
        CorePayloadKind::BookmarkCollection => {
            Item::BookmarkCollection(Box::new(bookmark_collection_parse(id, raw)))
        }
        CorePayloadKind::Calendar => Item::Calendar(Box::new(calendar_parse(id, raw))),
        CorePayloadKind::CalendarEvent => Item::Event(Box::new(event_parse(id, raw))),
        CorePayloadKind::AccountSettings => Item::Settings(Box::new(settings_parse(raw))),
        CorePayloadKind::DeviceLabel => Item::DeviceLabel(Box::new(device_label_parse(raw)?)),
        CorePayloadKind::Unknown => return None,
    };
    Some(Entry {
        id: id.clone(),
        kind,
        content_type: object.content_type.clone(),
        revision: object.revision,
        raw: raw.clone(),
        item,
    })
}

/// The object `id` as the device shows it: the queued write if there is one, else
/// what the server last held. `None` when it is absent or deleted.
fn shown(
    id: &str,
    vault: &HashMap<&str, &LocalObject>,
    pending: &HashMap<&str, &sealbook_core::PendingWrite>,
) -> Option<LocalObject> {
    match pending.get(id) {
        Some(write) if write.tombstone => None,
        Some(write) => Some(LocalObject {
            id: write.id.clone(),
            content_type: write.content_type.clone(),
            revision: vault.get(id).map_or(0, |object| object.revision),
            tombstone: false,
            payload: write.payload.clone(),
        }),
        None => vault
            .get(id)
            .filter(|object| !object.tombstone)
            .map(|object| (*object).clone()),
    }
}

impl VaultModel {
    pub fn rebuild(vault: &LocalVault, outbox: &Outbox) -> Self {
        let mut model = Self::default();
        model.update(vault, outbox, &[], true);
        model
    }

    /// Brings the model in line with `vault` and `outbox` for `ids`, or for
    /// every object when `all` is set, and says what changed.
    pub fn update(
        &mut self,
        vault: &LocalVault,
        outbox: &Outbox,
        ids: &[String],
        all: bool,
    ) -> ChangeSet {
        let in_vault: HashMap<&str, &LocalObject> = vault
            .objects
            .iter()
            .map(|object| (object.id.as_str(), object))
            .collect();
        let pending: HashMap<&str, &sealbook_core::PendingWrite> = outbox
            .writes
            .iter()
            .map(|write| (write.id.as_str(), write))
            .collect();
        let wanted: Vec<String> = if all {
            in_vault
                .keys()
                .chain(pending.keys())
                .copied()
                .chain(self.entries.keys().map(String::as_str))
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .map(str::to_string)
                .collect()
        } else {
            ids.to_vec()
        };
        let mut set = ChangeSet {
            everything: all,
            ..ChangeSet::default()
        };
        for id in wanted.iter().map(String::as_str) {
            let next = shown(id, &in_vault, &pending).and_then(|object| parse_entry(&object));
            let change = match (self.entries.get(id), &next) {
                (None, None) => None,
                (Some(old), None) => Some((old.kind, ChangeKind::Removed)),
                (None, Some(entry)) => Some((entry.kind, ChangeKind::Added)),
                (Some(old), Some(entry)) if old == entry => None,
                (Some(_), Some(entry)) => Some((entry.kind, ChangeKind::Updated)),
            };
            let Some((kind, change)) = change else {
                continue;
            };
            match next {
                Some(entry) => self.entries.insert(id.to_string(), entry),
                None => self.entries.remove(id),
            };
            set.changes.push(Change {
                id: id.to_string(),
                kind,
                change,
            });
        }
        set
    }

    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.entries.get(id)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }

    pub fn of_kind(&self, kind: CorePayloadKind) -> impl Iterator<Item = &Entry> {
        self.entries
            .values()
            .filter(move |entry| entry.kind == kind)
    }
}

macro_rules! typed_getters {
    ($($name:ident, $variant:ident, $ty:ty;)*) => {
        impl VaultModel {
            $(
                pub fn $name(&self) -> impl Iterator<Item = &$ty> {
                    self.entries.values().filter_map(|entry| match &entry.item {
                        Item::$variant(item) => Some(&**item),
                        _ => None,
                    })
                }
            )*
        }
    };
}

typed_getters! {
    contacts, Contact, CoreContact;
    address_books, AddressBook, CoreAddressBook;
    notes, Note, CoreNote;
    notebooks, Notebook, CoreNotebook;
    tasks, Task, CoreTask;
    task_lists, TaskList, CoreTaskList;
    bookmarks, Bookmark, CoreBookmark;
    bookmark_collections, BookmarkCollection, CoreBookmarkCollection;
    calendars, Calendar, CoreCalendar;
    events, Event, CoreCalendarEvent;
    device_labels, DeviceLabel, CoreDeviceLabel;
}

impl VaultModel {
    /// The account settings, which are the defaults until one is written.
    pub fn settings(&self) -> CoreAccountSettings {
        self.entries
            .values()
            .find_map(|entry| match &entry.item {
                Item::Settings(settings) => Some((**settings).clone()),
                _ => None,
            })
            .unwrap_or_else(sealbook_core::default_account_settings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealbook_core::PendingWrite;
    use sealbook_protocol::{JSCONTACT_CONTENT_TYPE, NOTE_CONTENT_TYPE};

    fn contact_payload(name: &str) -> String {
        serde_json::json!({
            "@type": "Card",
            "version": "1.0",
            "name": {"full": name},
        })
        .to_string()
    }

    fn note_payload(title: &str) -> String {
        serde_json::json!({"@type": "Note", "version": 1, "title": title, "body": "text"})
            .to_string()
    }

    fn object(id: &str, content_type: &str, revision: u64, payload: String) -> LocalObject {
        LocalObject {
            id: id.into(),
            content_type: content_type.into(),
            revision,
            tombstone: false,
            payload,
        }
    }

    fn write(
        id: &str,
        content_type: &str,
        payload: String,
        base: Option<LocalObject>,
    ) -> PendingWrite {
        PendingWrite {
            id: id.into(),
            content_type: content_type.into(),
            tombstone: false,
            payload,
            base,
            queued_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    const A: &str = "00000000-0000-4000-8000-00000000000a";
    const B: &str = "00000000-0000-4000-8000-00000000000b";
    const C: &str = "00000000-0000-4000-8000-00000000000c";

    fn vault() -> LocalVault {
        LocalVault {
            version: 1,
            latest_revision: 3,
            key_epoch: 1,
            objects: vec![
                object(A, JSCONTACT_CONTENT_TYPE, 1, contact_payload("Ada")),
                object(B, NOTE_CONTENT_TYPE, 2, note_payload("Plan")),
                LocalObject {
                    id: C.into(),
                    content_type: NOTE_CONTENT_TYPE.into(),
                    revision: 3,
                    tombstone: true,
                    payload: String::new(),
                },
            ],
        }
    }

    #[test]
    fn a_rebuild_parses_live_objects_and_skips_tombstones_and_unknown_kinds() {
        let mut v = vault();
        v.objects.push(object(
            "00000000-0000-4000-8000-00000000000d",
            "application/x-future",
            4,
            "{}".into(),
        ));
        let model = VaultModel::rebuild(&v, &Outbox::default());
        assert_eq!(model.contacts().count(), 1);
        assert_eq!(model.notes().count(), 1);
        assert_eq!(model.len(), 2);
        assert!(model.get(C).is_none());
    }

    #[test]
    fn a_queued_edit_shows_over_the_stored_object_and_a_queued_delete_hides_it() {
        let v = vault();
        let mut outbox = Outbox::default();
        outbox
            .writes
            .push(write(B, NOTE_CONTENT_TYPE, note_payload("Edited"), None));
        let model = VaultModel::rebuild(&v, &outbox);
        assert_eq!(model.notes().next().unwrap().title, "Edited");
        assert_eq!(model.get(B).unwrap().revision, 2);

        outbox.writes[0].tombstone = true;
        let model = VaultModel::rebuild(&v, &outbox);
        assert_eq!(model.notes().count(), 0);
    }

    #[test]
    fn updating_only_the_changed_ids_gives_the_same_model_as_a_rebuild() {
        let mut v = vault();
        let mut outbox = Outbox::default();
        let mut model = VaultModel::rebuild(&v, &outbox);

        // A queued edit, a queued create, a server-side delete and a server-side add.
        outbox.writes.push(write(
            A,
            JSCONTACT_CONTENT_TYPE,
            contact_payload("Ada L"),
            None,
        ));
        outbox.writes.push(write(
            "00000000-0000-4000-8000-0000000000e0",
            NOTE_CONTENT_TYPE,
            note_payload("New"),
            None,
        ));
        v.objects[1].tombstone = true;
        v.objects[1].payload.clear();
        v.objects.push(object(
            "00000000-0000-4000-8000-0000000000f0",
            JSCONTACT_CONTENT_TYPE,
            5,
            contact_payload("Grace"),
        ));
        let ids: Vec<String> = [
            A,
            B,
            "00000000-0000-4000-8000-0000000000e0",
            "00000000-0000-4000-8000-0000000000f0",
        ]
        .iter()
        .map(|id| id.to_string())
        .collect();
        let set = model.update(&v, &outbox, &ids, false);

        assert_eq!(model, VaultModel::rebuild(&v, &outbox));
        assert_eq!(set.changes.len(), 4);
        assert!(!set.everything);
        let kinds: Vec<_> = set.changes.iter().map(|c| c.change).collect();
        assert!(kinds.contains(&ChangeKind::Removed));
        assert!(kinds.contains(&ChangeKind::Added));
        assert!(kinds.contains(&ChangeKind::Updated));
    }

    #[test]
    fn an_update_that_changes_nothing_reports_nothing() {
        let v = vault();
        let outbox = Outbox::default();
        let mut model = VaultModel::rebuild(&v, &outbox);
        let set = model.update(&v, &outbox, &[A.to_string(), B.to_string()], false);
        assert!(set.is_empty());
    }

    #[test]
    fn a_full_update_notices_what_left_the_vault() {
        let mut v = vault();
        let outbox = Outbox::default();
        let mut model = VaultModel::rebuild(&v, &outbox);
        v.objects.retain(|object| object.id != A);
        let set = model.update(&v, &outbox, &[], true);
        assert!(set.everything);
        assert!(set
            .changes
            .iter()
            .any(|c| c.id == A && c.change == ChangeKind::Removed));
        assert_eq!(model, VaultModel::rebuild(&v, &outbox));
    }

    #[test]
    fn settings_are_the_defaults_until_one_is_stored() {
        let model = VaultModel::default();
        assert_eq!(model.settings(), sealbook_core::default_account_settings());
    }
}
