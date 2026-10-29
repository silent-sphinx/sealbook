//! The collection read as the CLI fetches it.
//!
//! Every decision here is `sealbook_core::sync`; this module is the reqwest
//! shell around it. Core says what to ask for and what each page means, this
//! moves the bytes and keeps the rows.

use sealbook_core::{
    changes_page_read, changes_request, latest_revisions, walk_page, RowRef, WalkStep,
};
use sealbook_protocol::{ChangesResponse, ObjectChange};

use crate::{ClientError, SealbookClient};

/// One verified read of the collection: the latest revision of every row, and
/// the floor that says which of its tombstones a rotation may retire.
pub(crate) struct VerifiedObjects {
    pub(crate) objects: Vec<ObjectChange>,
    pub(crate) tombstone_floor: u64,
}

impl SealbookClient {
    /// Every object in the collection, checked against the signed manifest.
    ///
    /// Walks the change feed to the end, then verifies the whole set at once: a
    /// page on its own cannot be checked, since the manifest commits to the
    /// collection rather than to any page of it.
    pub(crate) async fn fetch_verified_objects(&mut self) -> Result<VerifiedObjects, ClientError> {
        let collection_id = self
            .state
            .as_ref()
            .ok_or(ClientError::NoState)?
            .collection_id;
        let mut cursor = sealbook_core::walk_start(0);
        let mut rows: Vec<ObjectChange> = Vec::new();
        let walk = loop {
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

        let objects = newest(rows);
        match &walk.manifest_json {
            Some(manifest) => self.verify_manifest(manifest, &entries(&objects)).await?,
            None => self.manifest_absence_ok()?,
        }
        Ok(VerifiedObjects {
            objects,
            tombstone_floor: walk.tombstone_floor,
        })
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
