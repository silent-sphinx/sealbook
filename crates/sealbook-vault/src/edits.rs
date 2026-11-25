//! Typed edit builders: each turns a draft into the one [`PendingWrite`] the
//! outbox queues, through core's `*_write` so the payload rules stay in core.
//!
//! The write's `base` is the object as the server last held it, which the
//! three-way merge needs when another device changed the same object first.

use sealbook_core::{
    address_book_write, bookmark_collection_write, bookmark_write, calendar_write, contact_write,
    event_write, note_write, notebook_write, settings_write, task_list_write, task_write,
    CoreAccountSettingsDraft, CoreAddressBookDraft, CoreBookmarkCollectionDraft, CoreBookmarkDraft,
    CoreCalendarDraft, CoreCalendarEventDraft, CoreContactDraft, CoreError, CoreNoteDraft,
    CoreTaskDraft, CoreTaskListDraft, LocalObject, LocalVault, PendingWrite,
    ACCOUNT_SETTINGS_CONTENT_TYPE,
};
use sealbook_protocol::{
    ACCOUNT_SETTINGS_ID, ADDRESS_BOOK_CONTENT_TYPE, BOOKMARK_COLLECTION_CONTENT_TYPE,
    BOOKMARK_CONTENT_TYPE, CALENDAR_CONTENT_TYPE, CALENDAR_EVENT_CONTENT_TYPE,
    JSCONTACT_CONTENT_TYPE, NOTEBOOK_CONTENT_TYPE, NOTE_CONTENT_TYPE, TASK_CONTENT_TYPE,
    TASK_LIST_CONTENT_TYPE,
};
use uuid::Uuid;

/// The host's clock as an RFC 3339 UTC timestamp, the `now` core's writers take.
pub fn now_rfc3339() -> String {
    jiff::Timestamp::now()
        .strftime("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

pub fn new_id() -> String {
    Uuid::new_v4().to_string()
}

/// The id of the one account-settings object.
pub fn settings_id() -> String {
    ACCOUNT_SETTINGS_ID.to_string()
}

/// What a notebook write carries. `previous_raw` is the stored payload when this
/// edits a notebook, so keys this build does not know survive.
#[derive(Clone, Copy, Debug, Default)]
pub struct NotebookEdit<'a> {
    pub name: &'a str,
    pub parent_id: Option<&'a str>,
    pub color: Option<&'a str>,
    pub archived: bool,
    pub hide_from_all: bool,
    pub previous_raw: Option<&'a str>,
}

impl<'a> NotebookEdit<'a> {
    pub fn named(name: &'a str) -> Self {
        Self {
            name,
            ..Self::default()
        }
    }
}

/// Builds writes against the copy of the vault the device last read.
pub struct Editor<'a> {
    vault: &'a LocalVault,
    now: &'a str,
}

impl<'a> Editor<'a> {
    pub fn new(vault: &'a LocalVault, now: &'a str) -> Self {
        Self { vault, now }
    }

    fn base(&self, id: &str) -> Option<LocalObject> {
        self.vault
            .objects
            .iter()
            .find(|object| object.id == id && !object.tombstone)
            .cloned()
    }

    /// A write of an already-built payload, the form trash and import use.
    pub fn put(&self, id: &str, content_type: &str, payload: String) -> PendingWrite {
        PendingWrite {
            id: id.to_string(),
            content_type: content_type.to_string(),
            tombstone: false,
            payload,
            base: self.base(id),
            queued_at: self.now.to_string(),
        }
    }

    /// A delete. Queued over a create the server never saw, the outbox drops both.
    pub fn delete(&self, id: &str, content_type: &str) -> PendingWrite {
        PendingWrite {
            id: id.to_string(),
            content_type: content_type.to_string(),
            tombstone: true,
            payload: String::new(),
            base: self.base(id),
            queued_at: self.now.to_string(),
        }
    }

    pub fn contact(&self, id: &str, draft: &CoreContactDraft) -> Result<PendingWrite, CoreError> {
        Ok(self.put(id, JSCONTACT_CONTENT_TYPE, contact_write(draft, self.now)?))
    }

    pub fn address_book(
        &self,
        id: &str,
        draft: &CoreAddressBookDraft,
    ) -> Result<PendingWrite, CoreError> {
        Ok(self.put(
            id,
            ADDRESS_BOOK_CONTENT_TYPE,
            address_book_write(draft, self.now)?,
        ))
    }

    pub fn note(&self, id: &str, draft: &CoreNoteDraft) -> Result<PendingWrite, CoreError> {
        Ok(self.put(id, NOTE_CONTENT_TYPE, note_write(draft, self.now)?))
    }

    pub fn notebook(&self, id: &str, edit: &NotebookEdit<'_>) -> Result<PendingWrite, CoreError> {
        Ok(self.put(
            id,
            NOTEBOOK_CONTENT_TYPE,
            notebook_write(
                edit.name,
                edit.parent_id,
                edit.color,
                edit.archived,
                edit.hide_from_all,
                edit.previous_raw,
                self.now,
            )?,
        ))
    }

    pub fn task(&self, id: &str, draft: &CoreTaskDraft) -> Result<PendingWrite, CoreError> {
        Ok(self.put(id, TASK_CONTENT_TYPE, task_write(draft, self.now)?))
    }

    pub fn task_list(
        &self,
        id: &str,
        draft: &CoreTaskListDraft,
    ) -> Result<PendingWrite, CoreError> {
        Ok(self.put(
            id,
            TASK_LIST_CONTENT_TYPE,
            task_list_write(draft, self.now)?,
        ))
    }

    pub fn bookmark(&self, id: &str, draft: &CoreBookmarkDraft) -> Result<PendingWrite, CoreError> {
        Ok(self.put(id, BOOKMARK_CONTENT_TYPE, bookmark_write(draft, self.now)?))
    }

    pub fn bookmark_collection(
        &self,
        id: &str,
        draft: &CoreBookmarkCollectionDraft,
    ) -> Result<PendingWrite, CoreError> {
        Ok(self.put(
            id,
            BOOKMARK_COLLECTION_CONTENT_TYPE,
            bookmark_collection_write(draft, self.now)?,
        ))
    }

    pub fn calendar(&self, id: &str, draft: &CoreCalendarDraft) -> Result<PendingWrite, CoreError> {
        Ok(self.put(id, CALENDAR_CONTENT_TYPE, calendar_write(draft, self.now)?))
    }

    pub fn event(
        &self,
        id: &str,
        draft: &CoreCalendarEventDraft,
    ) -> Result<PendingWrite, CoreError> {
        Ok(self.put(
            id,
            CALENDAR_EVENT_CONTENT_TYPE,
            event_write(draft, self.now)?,
        ))
    }

    pub fn settings(&self, draft: &CoreAccountSettingsDraft) -> Result<PendingWrite, CoreError> {
        Ok(self.put(
            &settings_id(),
            ACCOUNT_SETTINGS_CONTENT_TYPE,
            settings_write(draft)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealbook_core::{address_book_parse, outbox_push, Outbox};

    const NOW: &str = "2026-11-25T10:00:00Z";

    fn address_book_draft(name: &str) -> CoreAddressBookDraft {
        CoreAddressBookDraft {
            name: name.into(),
            ..CoreAddressBookDraft::default()
        }
    }

    #[test]
    fn a_create_has_no_base_and_an_edit_has_the_stored_object_as_its_base() {
        let id = new_id();
        let vault = LocalVault::default();
        let create = Editor::new(&vault, NOW)
            .address_book(&id, &address_book_draft("Work"))
            .unwrap();
        assert!(create.base.is_none());
        assert_eq!(address_book_parse(&id, &create.payload).name, "Work");

        let stored = LocalObject {
            id: id.clone(),
            content_type: ADDRESS_BOOK_CONTENT_TYPE.into(),
            revision: 4,
            tombstone: false,
            payload: create.payload.clone(),
        };
        let vault = LocalVault {
            objects: vec![stored.clone()],
            ..LocalVault::default()
        };
        let edit = Editor::new(&vault, NOW)
            .address_book(&id, &address_book_draft("Home"))
            .unwrap();
        assert_eq!(edit.base, Some(stored));
    }

    #[test]
    fn a_delete_over_a_queued_create_leaves_nothing_to_send() {
        let id = new_id();
        let vault = LocalVault::default();
        let editor = Editor::new(&vault, NOW);
        let outbox = outbox_push(
            &Outbox::default(),
            editor
                .address_book(&id, &address_book_draft("Work"))
                .unwrap(),
        );
        let outbox = outbox_push(&outbox, editor.delete(&id, ADDRESS_BOOK_CONTENT_TYPE));
        assert!(outbox.writes.is_empty());
    }

    #[test]
    fn a_refused_draft_is_an_error_not_a_write() {
        let vault = LocalVault::default();
        let draft = CoreAddressBookDraft {
            raw: Some(r#"{"version":"999.0"}"#.into()),
            ..address_book_draft("x")
        };
        assert!(Editor::new(&vault, NOW)
            .address_book(&new_id(), &draft)
            .is_err());
    }

    #[test]
    fn the_clock_is_an_rfc3339_utc_timestamp() {
        let now = now_rfc3339();
        assert_eq!(now.len(), 20);
        assert!(now.ends_with('Z'));
    }
}
