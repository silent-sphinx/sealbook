//! Sending the outbox: what each queued write becomes once the server's copy
//! is known, and the check that nothing moved before the write is signed.
//!
//! The host first brings its [`LocalVault`] up to date with an incremental walk,
//! which is the only way to read another device's version of an object. Then
//! [`flush_plan`] decides each write against it. Just before signing a batch,
//! the host reads the manifest buckets of the batch's ids and asks
//! [`write_guard`] whether any of them moved since; a moved one is walked and
//! planned again rather than written blind. Signing at the next manifest
//! sequence makes that check and the write one step: anything written in
//! between makes the write a `409`, and the host starts again from the walk.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::merge::{conflict_copy_id, item_title, merge_payload, MergeOutcome};
use crate::messages::{
    offline_conflict_message, offline_delete_kept_message, offline_overwrote_message,
    offline_restored_message,
};
use crate::offline::{LocalObject, LocalVault, Outbox, PendingWrite};
use crate::{CoreError, CoreManifestEntry, SYNC_RESTART_LIMIT};

/// One object to seal and send.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct FlushWrite {
    pub id: String,
    pub content_type: String,
    pub tombstone: bool,
    pub payload: String,
    /// The revision the server must still hold for `id`. `None` is "absent or
    /// deleted".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect_revision: Option<u64>,
    /// The outbox write this settles once its batch is taken.
    pub settles: String,
    /// A conflicted copy, under an id derived from its content.
    pub copy: bool,
    /// What to tell the person once this is written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice: Option<String>,
}

/// A queued write with nothing to send, taken out of the outbox at once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct FlushDrop {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice: Option<String>,
}

/// In queued order, so a container is written before the items in it. A
/// conflict's two writes are adjacent.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct FlushPlan {
    pub writes: Vec<FlushWrite>,
    pub dropped: Vec<FlushDrop>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct FlushGuard {
    /// Outbox writes whose object moved since the plan: walk and plan again.
    pub moved: Vec<String>,
    /// Copies already on the server from an earlier attempt: leave them out.
    pub present: Vec<String>,
}

/// What a failed write request means for the writes in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum FlushFailure {
    /// Keep them and try again: the network, the server, or a write that lost
    /// a race and is planned again.
    Retry,
    /// Keep them, sign in again, then try again.
    SignIn,
    /// Move them to the failed list. Retrying would only be refused again.
    Refused,
}

/// Decides every queued write against `vault`, which the host has just
/// brought up to date. `date` is the host's local `YYYY-MM-DD`, for the title
/// of a conflicted copy.
pub fn flush_plan(outbox: &Outbox, vault: &LocalVault, date: &str) -> FlushPlan {
    let mut plan = FlushPlan::default();
    for write in &outbox.writes {
        let remote = vault.objects.iter().find(|object| object.id == write.id);
        plan_one(&mut plan, write, remote, date);
    }
    plan
}

fn plan_one(plan: &mut FlushPlan, write: &PendingWrite, remote: Option<&LocalObject>, date: &str) {
    let base_revision = write.base.as_ref().map_or(0, |base| base.revision);
    let title = || {
        let payload = match &write.base {
            Some(base) if write.tombstone => &base.payload,
            _ => &write.payload,
        };
        item_title(&write.content_type, payload)
    };
    let send = |payload: &str, expect_revision: Option<u64>, notice: Option<String>| FlushWrite {
        id: write.id.clone(),
        content_type: write.content_type.clone(),
        tombstone: write.tombstone,
        payload: payload.to_string(),
        expect_revision,
        settles: write.id.clone(),
        copy: false,
        notice,
    };
    let drop = |notice: Option<String>| FlushDrop {
        id: write.id.clone(),
        notice,
    };

    let live = remote.filter(|remote| !remote.tombstone);
    let Some(remote_live) = live else {
        if write.tombstone {
            plan.dropped.push(drop(None));
            return;
        }
        let notice = write
            .base
            .is_some()
            .then(|| offline_restored_message(&title()));
        plan.writes.push(send(&write.payload, None, notice));
        return;
    };
    if remote_live.revision == base_revision {
        plan.writes
            .push(send(&write.payload, Some(remote_live.revision), None));
        return;
    }
    if write.tombstone {
        plan.dropped
            .push(drop(Some(offline_delete_kept_message(&title()))));
        return;
    }
    let base = write.base.as_ref().map(|base| base.payload.as_str());
    match merge_payload(
        &write.content_type,
        base,
        &write.payload,
        &remote_live.payload,
        date,
    ) {
        MergeOutcome::Same => plan.dropped.push(drop(None)),
        MergeOutcome::Merged { payload, overwrote } => {
            let notice = overwrote.then(|| offline_overwrote_message(&title()));
            plan.writes
                .push(send(&payload, Some(remote_live.revision), notice));
        }
        MergeOutcome::Conflict { payload, copy } => {
            if let Some(payload) = payload {
                plan.writes
                    .push(send(&payload, Some(remote_live.revision), None));
            }
            let remote_title = item_title(&write.content_type, &remote_live.payload);
            let copy_title = item_title(&write.content_type, &copy);
            plan.writes.push(FlushWrite {
                id: conflict_copy_id(&write.id, &copy),
                content_type: write.content_type.clone(),
                tombstone: false,
                payload: copy,
                expect_revision: None,
                settles: write.id.clone(),
                copy: true,
                notice: Some(offline_conflict_message(&remote_title, &copy_title)),
            });
        }
    }
}

/// Checks a batch's writes against the manifest entries served for their
/// buckets, just before the batch is signed. `attempt` counts the plans
/// already made for this flush; past [`SYNC_RESTART_LIMIT`] a collection that
/// keeps moving is [`CoreError::CollectionBusy`].
pub fn write_guard(
    writes: &[FlushWrite],
    entries: &[CoreManifestEntry],
    attempt: u32,
) -> Result<FlushGuard, CoreError> {
    let mut guard = FlushGuard::default();
    for write in writes {
        let entry = Uuid::parse_str(&write.id)
            .ok()
            .and_then(|id| entries.iter().find(|entry| entry.id == id));
        let live = entry.filter(|entry| !entry.tombstone);
        let holds = match write.expect_revision {
            Some(revision) => live.is_some_and(|entry| entry.revision == revision),
            None => live.is_none(),
        };
        if holds {
            continue;
        }
        if write.copy {
            guard.present.push(write.id.clone());
        } else if !guard.moved.contains(&write.settles) {
            guard.moved.push(write.settles.clone());
        }
    }
    if !guard.moved.is_empty() && attempt >= SYNC_RESTART_LIMIT {
        return Err(CoreError::CollectionBusy);
    }
    Ok(guard)
}

/// What a write request's HTTP status means, with 0 for no response at all.
pub fn flush_failure(status: u16) -> FlushFailure {
    match status {
        401 => FlushFailure::SignIn,
        0 | 408 | 409 | 429 => FlushFailure::Retry,
        status if status >= 500 => FlushFailure::Retry,
        _ => FlushFailure::Refused,
    }
}

#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{CoreError, CoreManifestEntry, FlushFailure, FlushGuard, FlushPlan, FlushWrite};
    use crate::offline::{LocalVault, Outbox};

    #[uniffi::export(name = "flush_plan")]
    pub fn flush_plan(outbox: Outbox, vault: LocalVault, date: String) -> FlushPlan {
        super::flush_plan(&outbox, &vault, &date)
    }

    #[uniffi::export(name = "write_guard")]
    pub fn write_guard(
        writes: Vec<FlushWrite>,
        entries: Vec<CoreManifestEntry>,
        attempt: u32,
    ) -> Result<FlushGuard, CoreError> {
        super::write_guard(&writes, &entries, attempt)
    }

    #[uniffi::export(name = "flush_failure")]
    pub fn flush_failure(status: u16) -> FlushFailure {
        super::flush_failure(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_sorts_into_retry_sign_in_or_refused() {
        assert_eq!(flush_failure(0), FlushFailure::Retry);
        assert_eq!(flush_failure(409), FlushFailure::Retry);
        assert_eq!(flush_failure(503), FlushFailure::Retry);
        assert_eq!(flush_failure(401), FlushFailure::SignIn);
        assert_eq!(flush_failure(413), FlushFailure::Refused);
        assert_eq!(flush_failure(403), FlushFailure::Refused);
    }

    #[test]
    fn a_copy_already_written_is_left_out_not_replanned() {
        let id = Uuid::from_u128(7);
        let write = FlushWrite {
            id: id.to_string(),
            content_type: String::new(),
            tombstone: false,
            payload: String::new(),
            expect_revision: None,
            settles: "a".into(),
            copy: true,
            notice: None,
        };
        let entry = CoreManifestEntry {
            id,
            revision: 9,
            tombstone: false,
            content_digest: String::new(),
        };
        let guard = write_guard(&[write], &[entry], SYNC_RESTART_LIMIT).unwrap();
        assert_eq!(guard.present, vec![id.to_string()]);
        assert!(guard.moved.is_empty());
    }
}
