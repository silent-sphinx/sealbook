//! The collection read as the CLI fetches it.
//!
//! Every decision here is `sealbook_core::sync`; this module is the reqwest
//! shell around it. Core says what to ask for and what each page means, this
//! moves the bytes and keeps the rows.

use sealbook_core::{
    changes_page_read, changes_request, check_rows_against_entries, latest_revisions,
    local_vault_apply, open_stored, require_key_epoch, unreadable_rows, walk_page, LocalObject,
    LocalVault, RowOutcome, RowRef, RowsCheck, StoredRow, WalkOutcome, WalkStep,
};
use sealbook_protocol::{ChangesResponse, ObjectChange};
use uuid::Uuid;

use crate::{ClientError, SealbookClient};

/// Attempts at an incremental read that a concurrent write kept overtaking.
const MAX_CATCH_UP_READS: u32 = 3;

/// One verified read of the collection: the latest revision of every row, and
/// the floor that says which of its tombstones a rotation may retire.
pub(crate) struct VerifiedObjects {
    pub(crate) objects: Vec<ObjectChange>,
    pub(crate) tombstone_floor: u64,
}

/// A walk of the change feed: the newest row of each object, and what core made
/// of the pages.
struct Walked {
    rows: Vec<ObjectChange>,
    outcome: WalkOutcome,
}

/// What a catch-up read, opened and ready to fold into the device's copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatchUp {
    /// The rows are the whole collection rather than what changed since the
    /// mark. The copy is replaced by them instead of added to.
    pub full: bool,
    /// Opened rows, a delete as a tombstone with no payload. A row this device
    /// could not open is left out and counted in `unreadable`.
    pub rows: Vec<LocalObject>,
    pub latest_revision: u64,
    pub key_epoch: u64,
    pub unreadable: u64,
}

impl CatchUp {
    /// The copy after this read: replaced by a full one, added to by an
    /// incremental one.
    pub fn apply(&self, vault: &LocalVault) -> LocalVault {
        let from = if self.full {
            LocalVault::default()
        } else {
            vault.clone()
        };
        local_vault_apply(&from, &self.rows, self.latest_revision, self.key_epoch)
    }
}

impl SealbookClient {
    /// Every object in the collection, checked against the signed manifest.
    ///
    /// Walks the change feed to the end, then verifies the whole set at once: a
    /// page on its own cannot be checked, since the manifest commits to the
    /// collection rather than to any page of it.
    pub(crate) async fn fetch_verified_objects(&mut self) -> Result<VerifiedObjects, ClientError> {
        let walked = self.walk_changes(0).await?;
        self.verify_full_walk(&walked).await?;
        Ok(VerifiedObjects {
            objects: walked.rows,
            tombstone_floor: walked.outcome.tombstone_floor,
        })
    }

    /// Brings a device's copy of the vault up to date: what changed after
    /// `after`, or the whole collection when `after` is 0 or the feed no longer
    /// reaches it.
    ///
    /// A whole read is checked against the signed manifest. An incremental one
    /// is checked row by row against the signed entries for those objects,
    /// under the key epoch just aligned, and read again up to three times when
    /// a concurrent write moved the manifest past a row; if it keeps moving that
    /// is [`ClientError::CollectionBusy`], which is a race and not tampering.
    pub async fn catch_up(&mut self, after: u64) -> Result<CatchUp, ClientError> {
        let collection_id = self
            .state
            .as_ref()
            .ok_or(ClientError::NoState)?
            .collection_id;
        let mut walked = self.walk_changes(after).await?;
        let mut read = 1;
        loop {
            if walked.outcome.key_epoch != self.key_epoch {
                require_key_epoch(
                    walked.outcome.key_epoch,
                    self.refresh_collection_key().await?,
                )?;
            }
            if walked.outcome.full
                || self.verify_walked_rows(&walked.rows).await? == RowsCheck::Verified
            {
                break;
            }
            if read == MAX_CATCH_UP_READS {
                return Err(ClientError::CollectionBusy);
            }
            read += 1;
            walked = self.walk_changes(after).await?;
        }
        if walked.outcome.full {
            self.verify_full_walk(&walked).await?;
        }

        let key = self
            .collection_key
            .as_ref()
            .ok_or(ClientError::NoCollectionKey)?;
        let outcomes: Vec<(&ObjectChange, RowOutcome)> = walked
            .rows
            .iter()
            .map(|row| {
                let outcome = open_stored(
                    key,
                    collection_id,
                    &StoredRow {
                        id: row.id,
                        tombstone: row.tombstone,
                        nonce: &row.nonce,
                        ciphertext: &row.ciphertext,
                        padded_size: row.padded_size,
                    },
                );
                (row, outcome)
            })
            .collect();
        // A key that opens none of a whole read is raised rather than shown as an
        // emptied vault; an incremental read of a few rows says nothing about the key.
        let unreadable = if walked.outcome.full {
            unreadable_rows(outcomes.iter().map(|(_, outcome)| outcome))?
        } else {
            outcomes
                .iter()
                .filter(|(_, outcome)| matches!(outcome, RowOutcome::Unreadable { .. }))
                .count() as u64
        };
        let rows = outcomes
            .into_iter()
            .filter_map(|(row, outcome)| local_object(row, outcome))
            .collect();
        if walked.outcome.full {
            self.last_unreadable = unreadable;
        }
        Ok(CatchUp {
            full: walked.outcome.full,
            rows,
            latest_revision: walked.outcome.latest_revision,
            key_epoch: walked.outcome.key_epoch,
            unreadable,
        })
    }

    /// Reads the change feed after `after` to its end, restarting when the
    /// collection moves under the walk, as core decides.
    async fn walk_changes(&mut self, after: u64) -> Result<Walked, ClientError> {
        let collection_id = self
            .state
            .as_ref()
            .ok_or(ClientError::NoState)?
            .collection_id;
        let mut cursor = sealbook_core::walk_start(after);
        let mut rows: Vec<ObjectChange> = Vec::new();
        let outcome = loop {
            let response = self.fetch(&changes_request(collection_id, &cursor)).await?;
            let body = std::str::from_utf8(&response.body)
                .map_err(|err| ClientError::Server(format!("unreadable change page: {err}")))?;
            let mut page: ChangesResponse = serde_json::from_str(body)
                .map_err(|err| ClientError::Server(format!("unreadable change page: {err}")))?;
            match walk_page(&cursor, &changes_page_read(body)?)? {
                WalkStep::Next { cursor: next } => {
                    rows.append(&mut page.objects);
                    cursor = next;
                }
                WalkStep::Restart { cursor: next } => {
                    rows.clear();
                    cursor = next;
                }
                WalkStep::Done { walk } => {
                    rows.append(&mut page.objects);
                    break walk;
                }
            }
        };
        Ok(Walked {
            rows: newest(rows),
            outcome,
        })
    }

    /// Checks a whole read against the signed manifest.
    ///
    /// A missing manifest is a refusal: a device just paired, recovered or
    /// reinstalled has seen none, so accepting the absence would let a server
    /// serve any subset of the vault.
    async fn verify_full_walk(&mut self, walked: &Walked) -> Result<(), ClientError> {
        let manifest = walked.outcome.manifest_json.as_deref().ok_or_else(|| {
            ClientError::Manifest(crate::ManifestError(
                "the server served no signed manifest for this collection".into(),
            ))
        })?;
        self.verify_manifest(manifest, &entries(&walked.rows)).await
    }

    /// Checks what an incremental read returned, which no whole-collection
    /// manifest check covers, against the signed entries for just those objects.
    async fn verify_walked_rows(
        &mut self,
        rows: &[ObjectChange],
    ) -> Result<RowsCheck, ClientError> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        if rows.is_empty() {
            return Ok(RowsCheck::Verified);
        }
        let ids: Vec<Uuid> = rows.iter().map(|row| row.id).collect();
        let held = self.manifest_bucket_state(&ids).await?;
        // A collection no device has signed yet has nothing to check against, and
        // the buckets call has already applied the rule for one that should have.
        if held.plan.manifest_seq == 0 {
            return Ok(RowsCheck::Verified);
        }
        let sealed: Vec<sealbook_core::CoreSealedRow> = rows
            .iter()
            .map(|row| sealbook_core::CoreSealedRow {
                id: row.id,
                revision: row.revision,
                tombstone: row.tombstone,
                nonce: URL_SAFE_NO_PAD.encode(&row.nonce),
                ciphertext: URL_SAFE_NO_PAD.encode(&row.ciphertext),
                padded_size: row.padded_size as u64,
            })
            .collect();
        Ok(check_rows_against_entries(&sealed, &held.entries)?)
    }
}

/// A walked row as the device's copy holds it, or `None` when it will not open.
fn local_object(row: &ObjectChange, outcome: RowOutcome) -> Option<LocalObject> {
    match outcome {
        RowOutcome::Deleted => Some(LocalObject {
            id: row.id.to_string(),
            content_type: String::new(),
            revision: row.revision,
            tombstone: true,
            payload: String::new(),
        }),
        RowOutcome::Object {
            content_type,
            payload,
        } => Some(LocalObject {
            id: row.id.to_string(),
            content_type,
            revision: row.revision,
            tombstone: false,
            payload,
        }),
        RowOutcome::Unreadable { .. } => None,
    }
}

/// The newest revision of each object, in the order they were first walked.
fn newest(rows: Vec<ObjectChange>) -> Vec<ObjectChange> {
    let refs: Vec<RowRef> = rows
        .iter()
        .map(|row| RowRef {
            id: row.id,
            revision: row.revision,
        })
        .collect();
    let keep = latest_revisions(&refs);
    // Moved out by index rather than cloned: a full read holds the whole
    // collection's ciphertexts, and core names each index once.
    let mut held: Vec<Option<ObjectChange>> = rows.into_iter().map(Some).collect();
    keep.iter()
        .filter_map(|index| held[*index as usize].take())
        .collect()
}

fn entries(objects: &[ObjectChange]) -> Vec<sealbook_protocol::ManifestEntry> {
    objects
        .iter()
        .map(|object| sealbook_protocol::ManifestEntry {
            id: object.id,
            revision: object.revision,
            tombstone: object.tombstone,
            content_digest: sealbook_crypto::content_digest(&object.nonce, &object.ciphertext)
                .to_vec(),
        })
        .collect()
}
