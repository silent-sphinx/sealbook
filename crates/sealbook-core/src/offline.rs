//! What a device keeps of the vault between sessions, and the writes waiting to
//! reach the server.
//!
//! Both are plaintext. The host encrypts the bytes [`local_vault_write`] and
//! [`outbox_write`] return with its own platform storage, as it does with
//! everything else it keeps, and seals each write only when it is sent: a
//! sealed object binds its revision, which is not known until then.
//!
//! Every write goes through the outbox, online or not, so that one set of rules
//! decides what happens when another device changed the same object first. Those
//! rules are [`crate::merge`] and [`crate::flush`].

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::CoreError;

/// The format [`local_vault_write`] writes. A higher one is refused on read.
pub const LOCAL_VAULT_VERSION: u32 = 1;

/// The format [`outbox_write`] writes. A higher one is refused on read.
pub const OUTBOX_VERSION: u32 = 1;

/// One object as the device last read it. A delete keeps its revision with an
/// empty payload, which is what tells "deleted elsewhere" from "never seen".
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct LocalObject {
    pub id: String,
    pub content_type: String,
    pub revision: u64,
    pub tombstone: bool,
    pub payload: String,
}

/// The vault as the device last read it, with the revision that read reached.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct LocalVault {
    pub version: u32,
    pub latest_revision: u64,
    pub key_epoch: u64,
    pub objects: Vec<LocalObject>,
}

/// One write the server has not taken yet.
///
/// `base` is the object as it was when the edit started, `None` for a create.
/// Repeated edits keep the first base, so the merge sees everything this device
/// changed since it last agreed with the server.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PendingWrite {
    pub id: String,
    pub content_type: String,
    pub tombstone: bool,
    pub payload: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<LocalObject>,
    /// The host's clock at the latest edit, for display.
    pub queued_at: String,
}

/// A write the server refused, kept for the person to export or discard.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct FailedWrite {
    pub write: PendingWrite,
    pub reason: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Outbox {
    pub version: u32,
    /// In the order they were first queued, which is the order they are sent.
    pub writes: Vec<PendingWrite>,
    pub failed: Vec<FailedWrite>,
}

pub fn local_vault_write(vault: &LocalVault) -> String {
    let mut vault = vault.clone();
    vault.version = LOCAL_VAULT_VERSION;
    serde_json::to_string(&vault).expect("a local vault serialises")
}

pub fn local_vault_read(raw: &str) -> Result<LocalVault, CoreError> {
    read_versioned(raw, LOCAL_VAULT_VERSION, "local vault")
}

pub fn outbox_write(outbox: &Outbox) -> String {
    let mut outbox = outbox.clone();
    outbox.version = OUTBOX_VERSION;
    serde_json::to_string(&outbox).expect("an outbox serialises")
}

pub fn outbox_read(raw: &str) -> Result<Outbox, CoreError> {
    read_versioned(raw, OUTBOX_VERSION, "outbox")
}

fn read_versioned<T: serde::de::DeserializeOwned>(
    raw: &str,
    supported: u32,
    what: &str,
) -> Result<T, CoreError> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|err| CoreError::Malformed {
            detail: format!("{what}: {err}"),
        })?;
    let version = value.get("version").and_then(serde_json::Value::as_u64);
    if version.is_none_or(|version| version > u64::from(supported)) {
        return Err(CoreError::Malformed {
            detail: format!("{what}: version {version:?} is not one this build reads"),
        });
    }
    serde_json::from_value(value).map_err(|err| CoreError::Malformed {
        detail: format!("{what}: {err}"),
    })
}

/// Folds `rows` from a read into the vault, newest revision winning, and moves
/// it to the revision and key epoch that read reached.
pub fn local_vault_apply(
    vault: &LocalVault,
    rows: &[LocalObject],
    latest_revision: u64,
    key_epoch: u64,
) -> LocalVault {
    let mut next = vault.clone();
    let mut at: HashMap<String, usize> = next
        .objects
        .iter()
        .enumerate()
        .map(|(index, object)| (object.id.clone(), index))
        .collect();
    for row in rows {
        match at.get(&row.id) {
            Some(&index) if next.objects[index].revision > row.revision => {}
            Some(&index) => next.objects[index] = row.clone(),
            None => {
                at.insert(row.id.clone(), next.objects.len());
                next.objects.push(row.clone());
            }
        }
    }
    next.latest_revision = next.latest_revision.max(latest_revision);
    next.key_epoch = next.key_epoch.max(key_epoch);
    next.version = LOCAL_VAULT_VERSION;
    next
}

/// Queues a write. A second write to the same id replaces the first in its
/// place and keeps the first base. A delete of an object created since the
/// last sync takes both out, since the server never saw it.
pub fn outbox_push(outbox: &Outbox, write: PendingWrite) -> Outbox {
    let mut next = outbox.clone();
    next.version = OUTBOX_VERSION;
    match next.writes.iter().position(|queued| queued.id == write.id) {
        Some(index) => {
            let queued = &next.writes[index];
            if write.tombstone && queued.base.is_none() {
                next.writes.remove(index);
            } else {
                let base = queued.base.clone();
                next.writes[index] = PendingWrite { base, ..write };
            }
        }
        None => next.writes.push(write),
    }
    next
}

/// Takes the writes for `ids` out of the outbox, sent or discarded, from either
/// list.
pub fn outbox_settle(outbox: &Outbox, ids: &[String]) -> Outbox {
    let mut next = outbox.clone();
    next.writes.retain(|write| !ids.contains(&write.id));
    next.failed.retain(|failed| !ids.contains(&failed.write.id));
    next
}

/// Moves the writes for `ids` to the failed list, where they wait for the
/// person rather than being retried.
pub fn outbox_fail(outbox: &Outbox, ids: &[String], reason: &str) -> Outbox {
    let mut next = outbox.clone();
    let (failed, kept): (Vec<_>, Vec<_>) = next
        .writes
        .into_iter()
        .partition(|write| ids.contains(&write.id));
    next.writes = kept;
    next.failed
        .extend(failed.into_iter().map(|write| FailedWrite {
            write,
            reason: reason.to_string(),
        }));
    next
}

/// The live objects the device shows: the vault with the pending writes laid
/// over it. A queued create has revision 0.
pub fn local_view(vault: &LocalVault, outbox: &Outbox) -> Vec<LocalObject> {
    let pending: HashMap<&str, &PendingWrite> = outbox
        .writes
        .iter()
        .map(|write| (write.id.as_str(), write))
        .collect();
    let mut view: Vec<LocalObject> = vault
        .objects
        .iter()
        .filter(|object| !pending.contains_key(object.id.as_str()))
        .filter(|object| !object.tombstone)
        .cloned()
        .collect();
    let stored: HashMap<&str, u64> = vault
        .objects
        .iter()
        .map(|object| (object.id.as_str(), object.revision))
        .collect();
    for write in outbox.writes.iter().filter(|write| !write.tombstone) {
        view.push(LocalObject {
            id: write.id.clone(),
            content_type: write.content_type.clone(),
            revision: stored.get(write.id.as_str()).copied().unwrap_or(0),
            tombstone: false,
            payload: write.payload.clone(),
        });
    }
    view
}

#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{CoreError, LocalObject, LocalVault, Outbox, PendingWrite};

    #[uniffi::export(name = "local_vault_write")]
    pub fn local_vault_write(vault: LocalVault) -> String {
        super::local_vault_write(&vault)
    }

    #[uniffi::export(name = "local_vault_read")]
    pub fn local_vault_read(raw: String) -> Result<LocalVault, CoreError> {
        super::local_vault_read(&raw)
    }

    #[uniffi::export(name = "local_vault_apply")]
    pub fn local_vault_apply(
        vault: LocalVault,
        rows: Vec<LocalObject>,
        latest_revision: u64,
        key_epoch: u64,
    ) -> LocalVault {
        super::local_vault_apply(&vault, &rows, latest_revision, key_epoch)
    }

    #[uniffi::export(name = "outbox_write")]
    pub fn outbox_write(outbox: Outbox) -> String {
        super::outbox_write(&outbox)
    }

    #[uniffi::export(name = "outbox_read")]
    pub fn outbox_read(raw: String) -> Result<Outbox, CoreError> {
        super::outbox_read(&raw)
    }

    #[uniffi::export(name = "outbox_push")]
    pub fn outbox_push(outbox: Outbox, write: PendingWrite) -> Outbox {
        super::outbox_push(&outbox, write)
    }

    #[uniffi::export(name = "outbox_settle")]
    pub fn outbox_settle(outbox: Outbox, ids: Vec<String>) -> Outbox {
        super::outbox_settle(&outbox, &ids)
    }

    #[uniffi::export(name = "outbox_fail")]
    pub fn outbox_fail(outbox: Outbox, ids: Vec<String>, reason: String) -> Outbox {
        super::outbox_fail(&outbox, &ids, &reason)
    }

    #[uniffi::export(name = "local_view")]
    pub fn local_view(vault: LocalVault, outbox: Outbox) -> Vec<LocalObject> {
        super::local_view(&vault, &outbox)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(id: &str, revision: u64, payload: &str) -> LocalObject {
        LocalObject {
            id: id.into(),
            content_type: "application/sealbook.note+json".into(),
            revision,
            tombstone: false,
            payload: payload.into(),
        }
    }

    fn write(id: &str, payload: &str, base: Option<LocalObject>) -> PendingWrite {
        PendingWrite {
            id: id.into(),
            content_type: "application/sealbook.note+json".into(),
            tombstone: false,
            payload: payload.into(),
            base,
            queued_at: "2026-11-03T10:00:00Z".into(),
        }
    }

    #[test]
    fn a_second_edit_keeps_the_first_base_and_place() {
        let first = write("a", "1", Some(object("a", 3, "0")));
        let outbox = outbox_push(&Outbox::default(), first);
        let outbox = outbox_push(&outbox, write("b", "x", None));
        let outbox = outbox_push(&outbox, write("a", "2", Some(object("a", 3, "1"))));
        assert_eq!(outbox.writes[0].payload, "2");
        assert_eq!(outbox.writes[0].base.as_ref().unwrap().payload, "0");
        assert_eq!(outbox.writes[1].id, "b");
    }

    #[test]
    fn deleting_an_unsent_create_queues_nothing() {
        let outbox = outbox_push(&Outbox::default(), write("a", "1", None));
        let mut delete = write("a", "", None);
        delete.tombstone = true;
        assert!(outbox_push(&outbox, delete).writes.is_empty());
    }

    #[test]
    fn a_newer_format_is_refused() {
        assert!(outbox_read(r#"{"version":2,"writes":[],"failed":[]}"#).is_err());
        assert!(local_vault_read("{}").is_err());
        let vault = local_vault_read(&local_vault_write(&LocalVault::default())).unwrap();
        assert_eq!(vault.version, LOCAL_VAULT_VERSION);
    }

    #[test]
    fn an_older_row_does_not_replace_a_newer_one() {
        let vault = LocalVault {
            objects: vec![object("a", 5, "new")],
            ..Default::default()
        };
        let applied = local_vault_apply(&vault, &[object("a", 4, "old")], 4, 0);
        assert_eq!(applied.objects[0].payload, "new");
        assert_eq!(applied.latest_revision, 4);
    }
}
