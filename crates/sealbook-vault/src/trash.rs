//! Putting items in the trash, restoring them, and deleting them for good.
//!
//! Core owns the rules (what a trashed parent hides, what comes back with an
//! item, what a purge takes with it); this reads them off the model and returns
//! the writes the outbox queues.

use std::collections::HashSet;

use sealbook_core::{
    trash_expired, trash_hidden, trash_node, trash_purge_plan, trash_restore_plan,
    trash_restore_write, trash_roots, trash_write, CoreContactDraft, CoreError, CorePayloadKind,
    PendingWrite, TrashNode, TrashRoot,
};

use crate::edits::Editor;
use crate::model::VaultModel;

/// The nodes for every item of a kind the trash holds.
pub fn nodes(model: &VaultModel) -> Vec<TrashNode> {
    model
        .entries()
        .filter_map(|entry| trash_node(&entry.id, entry.kind, &entry.raw))
        .collect()
}

/// What the trash lists: the items trashed on their own, newest rules from core.
pub fn roots(model: &VaultModel, now_secs: i64) -> Vec<TrashRoot> {
    trash_roots(&nodes(model), now_secs)
}

/// Ids of everything hidden from the normal views, because it or something above
/// it is in the trash.
pub fn hidden(model: &VaultModel) -> std::collections::HashSet<String> {
    trash_hidden(&nodes(model))
}

/// Ids a client should delete for good: in the trash longer than the retention.
pub fn expired(model: &VaultModel, now_secs: i64) -> Vec<String> {
    trash_expired(&nodes(model), now_secs)
}

/// The write that puts `id` in the trash.
pub fn trash(
    editor: &Editor<'_>,
    model: &VaultModel,
    id: &str,
    now: &str,
) -> Result<Option<PendingWrite>, CoreError> {
    let Some(entry) = trash_target(model, id) else {
        return Ok(None);
    };
    let raw = trash_write(entry.kind, &entry.raw, now)?;
    Ok(Some(editor.put(id, &entry.content_type, raw)))
}

/// The write that takes `id` out of the trash, moving it out of a parent or
/// container that is still in there.
pub fn restore(
    editor: &Editor<'_>,
    model: &VaultModel,
    id: &str,
) -> Result<Option<PendingWrite>, CoreError> {
    let Some(entry) = trash_target(model, id) else {
        return Ok(None);
    };
    let rehome = trash_restore_plan(&nodes(model), id);
    let raw = trash_restore_write(entry.kind, &entry.raw, rehome.as_ref())?;
    Ok(Some(editor.put(id, &entry.content_type, raw)))
}

/// The deletes for `ids` and everything inside them.
pub fn purge(editor: &Editor<'_>, model: &VaultModel, ids: &[String]) -> Vec<PendingWrite> {
    trash_purge_plan(&nodes(model), ids)
        .into_iter()
        .filter_map(|id| {
            let entry = model.get(&id)?;
            Some(editor.delete(&id, &entry.content_type))
        })
        .collect()
}

/// The deletes for everything in the trash past the retention period, and the
/// edits that unlink the live contacts from any contact going with it.
///
/// `model` must be a complete, current read: an item this device is missing
/// could be inside something about to go. [`crate::VaultHandle::sweep_trash`]
/// makes that read first.
pub(crate) fn expired_writes(
    editor: &Editor<'_>,
    model: &VaultModel,
    now_secs: i64,
) -> Result<Vec<PendingWrite>, CoreError> {
    let due = expired(model, now_secs);
    if due.is_empty() {
        return Ok(Vec::new());
    }
    let mut writes = purge(editor, model, &due);
    let gone: HashSet<&str> = writes.iter().map(|write| write.id.as_str()).collect();
    let hidden = hidden(model);
    let mut unlinks = Vec::new();
    for card in model.contacts() {
        // A card from a newer build cannot be rewritten, and must not hold up the rest.
        if !card.readable || gone.contains(card.id.as_str()) || hidden.contains(&card.id) {
            continue;
        }
        if let Some(draft) = without_links_to(card.draft(), &gone) {
            unlinks.push(editor.contact(&card.id, &draft)?);
        }
    }
    writes.extend(unlinks);
    Ok(writes)
}

/// `draft` without its links to any of `gone`, or `None` when it has none.
fn without_links_to(mut draft: CoreContactDraft, gone: &HashSet<&str>) -> Option<CoreContactDraft> {
    let profile = draft.profile.as_mut()?;
    let mut changed = false;
    for links in [
        &mut profile.family,
        &mut profile.friends,
        &mut profile.colleagues,
    ] {
        let before = links.len();
        links.retain(|link| {
            link.contact_id
                .as_deref()
                .is_none_or(|id| !gone.contains(id))
        });
        changed |= links.len() != before;
    }
    changed.then_some(draft)
}

fn trash_target<'a>(model: &'a VaultModel, id: &str) -> Option<&'a crate::model::Entry> {
    model
        .get(id)
        .filter(|entry| trash_node(id, entry.kind, &entry.raw).is_some())
        .filter(|entry| entry.kind != CorePayloadKind::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edits::new_id;
    use sealbook_core::{local_vault_apply, outbox_push, LocalVault, Outbox};
    use sealbook_protocol::NOTE_CONTENT_TYPE;

    const NOW: &str = "2026-11-25T10:00:00Z";
    const LATER: &str = "2026-11-26T10:00:00Z";

    fn note(title: &str) -> String {
        serde_json::json!({"@type": "Note", "version": 1, "title": title, "body": ""}).to_string()
    }

    fn model_with(notes: &[(&str, &str)]) -> (VaultModel, LocalVault) {
        let rows: Vec<_> = notes
            .iter()
            .map(|(id, title)| sealbook_core::LocalObject {
                id: (*id).into(),
                content_type: NOTE_CONTENT_TYPE.into(),
                revision: 1,
                tombstone: false,
                payload: note(title),
            })
            .collect();
        let vault = local_vault_apply(&LocalVault::default(), &rows, 1, 1);
        (VaultModel::rebuild(&vault, &Outbox::default()), vault)
    }

    #[test]
    fn a_trashed_note_is_hidden_listed_and_restored() {
        let id = new_id();
        let (mut model, vault) = model_with(&[(&id, "Plan")]);
        let editor = Editor::new(&vault, LATER);
        let write = trash(&editor, &model, &id, LATER).unwrap().unwrap();
        let outbox = outbox_push(&Outbox::default(), write);
        model.update(&vault, &outbox, std::slice::from_ref(&id), false);

        assert!(hidden(&model).contains(&id));
        let listed = roots(&model, 1_795_000_000);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, id);

        let write = restore(&editor, &model, &id).unwrap().unwrap();
        let outbox = outbox_push(&outbox, write);
        model.update(&vault, &outbox, std::slice::from_ref(&id), false);
        assert!(hidden(&model).is_empty());
        assert!(roots(&model, 1_795_000_000).is_empty());
    }

    #[test]
    fn purging_deletes_the_item_and_unknown_ids_are_ignored() {
        let id = new_id();
        let (model, vault) = model_with(&[(&id, "Plan")]);
        let editor = Editor::new(&vault, NOW);
        let writes = purge(&editor, &model, &[id.clone(), new_id()]);
        assert_eq!(writes.len(), 1);
        assert!(writes[0].tombstone);
        assert_eq!(writes[0].id, id);
    }

    #[test]
    fn something_that_is_not_in_the_model_cannot_be_trashed() {
        let (model, vault) = model_with(&[]);
        let editor = Editor::new(&vault, NOW);
        assert!(trash(&editor, &model, &new_id(), NOW).unwrap().is_none());
        assert!(restore(&editor, &model, &new_id()).unwrap().is_none());
    }
}
