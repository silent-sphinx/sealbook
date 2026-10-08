//! Reading and writing the collection's contents: the typed helpers callers
//! use, and the sealed object I/O underneath them.

use uuid::Uuid;

use std::collections::HashMap;

use sealbook_crypto::{
    content_digest, decrypt_object, encrypt_object, object_aad, EncryptedObject,
};
use sealbook_protocol::envelope::{open_envelope, seal_envelope, Unsealed};
use sealbook_protocol::{
    BatchObject, ChangesResponse, ManifestEntry, PutObjectRequest, PutObjectsRequest,
    PutObjectsResponse, MAX_BATCH_OBJECTS,
};
use sealbook_protocol::{
    ADDRESS_BOOK_CONTENT_TYPE, CALENDAR_CONTENT_TYPE, CALENDAR_EVENT_CONTENT_TYPE,
    DEFAULT_ADDRESS_BOOK_ID, DEFAULT_ADDRESS_BOOK_NAME, DEFAULT_CALENDAR_COLOR,
    DEFAULT_CALENDAR_ID, DEFAULT_CALENDAR_NAME, DEFAULT_NOTEBOOK_ID, DEFAULT_NOTEBOOK_NAME,
    JSCONTACT_CONTENT_TYPE, NOTEBOOK_CONTENT_TYPE, NOTE_CONTENT_TYPE, SEALED_CONTENT_TYPE,
};

use crate::manifest::BucketedManifest;
use crate::{ClientError, ManifestError, SealbookClient};

/// An object as stored, still wrapped in its envelope.
pub(crate) struct StoredObject {
    pub(crate) id: Uuid,
    pub(crate) stored: Vec<u8>,
}

/// A collection as a rotation needs to see it: what can be re-encrypted, the
/// tombstones that cannot but still belong in the manifest, and the ones the
/// rotation can retire.
#[derive(Default)]
pub(crate) struct VaultContents {
    pub(crate) live: Vec<StoredObject>,
    pub(crate) tombstones: Vec<ManifestEntry>,
    /// Tombstones below the collection's floor, which this rotation drops
    /// instead of carrying. Nothing else compacts them: each is a row and a
    /// manifest entry, and only a device can sign the manifest that leaves one
    /// out, so a rotation is the only place they can go.
    pub(crate) retired: Vec<Uuid>,
}

/// One object's encrypted bytes, waiting to be written.
///
/// What a batch is made of: the sealing is done per object, but the revision each
/// one takes and the manifest they are all written under are decided once, for
/// the batch.
pub(crate) struct PendingWrite {
    id: Uuid,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    padded_size: usize,
    tombstone: bool,
}

struct PlainObject {
    id: Uuid,
    content_type: String,
    plaintext: Vec<u8>,
}

/// The distinct, sorted ids of a batch, refusing one the manifest could not
/// describe: it holds one entry per id, and it is signed once for the whole
/// batch.
fn batch_ids(mut ids: Vec<Uuid>) -> Result<Vec<Uuid>, ClientError> {
    if ids.len() > MAX_BATCH_OBJECTS {
        return Err(ClientError::BatchTooLarge(ids.len()));
    }
    let distinct = ids.len();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() != distinct {
        return Err(ClientError::DuplicateInBatch);
    }
    Ok(ids)
}

impl PlainObject {
    fn into_text(self) -> Result<String, ClientError> {
        let id = self.id;
        String::from_utf8(self.plaintext).map_err(|_| ClientError::NonUtf8Object(id))
    }
}

impl SealbookClient {
    pub async fn put_contact(
        &mut self,
        object_id: Uuid,
        jscontact: &str,
    ) -> Result<u64, ClientError> {
        self.put_sealed(object_id, jscontact.as_bytes(), JSCONTACT_CONTENT_TYPE)
            .await
    }

    /// Writes up to `MAX_BATCH_OBJECTS` contacts in one request.
    ///
    /// What an import should use: one round trip and one manifest signature for
    /// the whole batch instead of one of each per contact, and the per-minute
    /// write cap then bounds objects rather than requests. Larger imports are
    /// sent in several calls.
    ///
    /// Returns the revision the last contact took, or 0 if the batch was empty.
    pub async fn put_contacts(&mut self, contacts: &[(Uuid, &str)]) -> Result<u64, ClientError> {
        self.put_sealed_batch(contacts, JSCONTACT_CONTENT_TYPE)
            .await
    }

    pub async fn delete_contact(&mut self, object_id: Uuid) -> Result<u64, ClientError> {
        self.write_object(object_id, Vec::new(), Vec::new(), 0, true)
            .await
    }

    pub async fn put_address_book(
        &mut self,
        object_id: Uuid,
        name: &str,
    ) -> Result<u64, ClientError> {
        let plaintext = serde_json::json!({
            "@type": "AddressBook",
            "version": "1.0",
            "name": name,
        })
        .to_string();
        self.put_sealed(object_id, plaintext.as_bytes(), ADDRESS_BOOK_CONTENT_TYPE)
            .await
    }

    pub async fn ensure_default_address_book(&mut self) -> Result<Uuid, ClientError> {
        let books = self.list_address_books().await?;
        if books.iter().any(|(id, _)| *id == DEFAULT_ADDRESS_BOOK_ID) {
            return Ok(DEFAULT_ADDRESS_BOOK_ID);
        }
        self.put_address_book(DEFAULT_ADDRESS_BOOK_ID, DEFAULT_ADDRESS_BOOK_NAME)
            .await?;
        Ok(DEFAULT_ADDRESS_BOOK_ID)
    }

    pub async fn list_address_books(&mut self) -> Result<Vec<(Uuid, String)>, ClientError> {
        let mut out = Vec::new();
        for obj in self.list_objects().await? {
            if obj.content_type != ADDRESS_BOOK_CONTENT_TYPE {
                continue;
            }
            out.push((obj.id, container_name(&obj.into_text()?)));
        }
        out.sort_by(|a, b| {
            if a.0 == DEFAULT_ADDRESS_BOOK_ID {
                return std::cmp::Ordering::Less;
            }
            if b.0 == DEFAULT_ADDRESS_BOOK_ID {
                return std::cmp::Ordering::Greater;
            }
            a.1.to_lowercase().cmp(&b.1.to_lowercase())
        });
        Ok(out)
    }

    pub async fn list_contacts(&mut self) -> Result<Vec<(Uuid, String)>, ClientError> {
        let mut out = Vec::new();
        for obj in self.list_objects().await? {
            if obj.content_type != JSCONTACT_CONTENT_TYPE {
                continue;
            }
            out.push((obj.id, obj.into_text()?));
        }
        Ok(out)
    }

    pub async fn put_calendar_event(
        &mut self,
        object_id: Uuid,
        event: &str,
    ) -> Result<u64, ClientError> {
        self.put_sealed(object_id, event.as_bytes(), CALENDAR_EVENT_CONTENT_TYPE)
            .await
    }

    pub async fn put_calendar(
        &mut self,
        object_id: Uuid,
        name: &str,
        color: &str,
    ) -> Result<u64, ClientError> {
        let calendar = serde_json::json!({
            "@type": "Calendar",
            "version": "1.0",
            "name": name,
            "color": color,
        });
        self.put_sealed(
            object_id,
            calendar.to_string().as_bytes(),
            CALENDAR_CONTENT_TYPE,
        )
        .await
    }

    /// Creates the reserved default calendar if the collection has none.
    ///
    /// The identity check is by id rather than by name, so a renamed default is
    /// still the default and a second one is never written.
    pub async fn ensure_default_calendar(&mut self) -> Result<Uuid, ClientError> {
        let calendars = self.list_calendars().await?;
        if calendars.iter().any(|(id, _)| *id == DEFAULT_CALENDAR_ID) {
            return Ok(DEFAULT_CALENDAR_ID);
        }
        self.put_calendar(
            DEFAULT_CALENDAR_ID,
            DEFAULT_CALENDAR_NAME,
            DEFAULT_CALENDAR_COLOR,
        )
        .await?;
        Ok(DEFAULT_CALENDAR_ID)
    }

    pub async fn list_calendars(&mut self) -> Result<Vec<(Uuid, String)>, ClientError> {
        let mut out = Vec::new();
        for obj in self.list_objects().await? {
            if obj.content_type == CALENDAR_CONTENT_TYPE {
                out.push((obj.id, obj.into_text()?));
            }
        }
        Ok(out)
    }

    pub async fn list_calendar_events(&mut self) -> Result<Vec<(Uuid, String)>, ClientError> {
        let mut out = Vec::new();
        for obj in self.list_objects().await? {
            if obj.content_type == CALENDAR_EVENT_CONTENT_TYPE {
                out.push((obj.id, obj.into_text()?));
            }
        }
        Ok(out)
    }

    pub async fn delete_calendar(&mut self, object_id: Uuid) -> Result<u64, ClientError> {
        self.write_object(object_id, Vec::new(), Vec::new(), 0, true)
            .await
    }

    pub async fn delete_calendar_event(&mut self, object_id: Uuid) -> Result<u64, ClientError> {
        self.write_object(object_id, Vec::new(), Vec::new(), 0, true)
            .await
    }

    pub async fn put_note(&mut self, object_id: Uuid, note: &str) -> Result<u64, ClientError> {
        self.put_sealed(object_id, note.as_bytes(), NOTE_CONTENT_TYPE)
            .await
    }

    /// Writes up to `MAX_BATCH_OBJECTS` notes in one request, as `put_contacts`
    /// does for contacts. Notes are the largest objects a vault holds, so a batch
    /// of them is bounded by the server's body limit well before the object
    /// count.
    pub async fn put_notes(&mut self, notes: &[(Uuid, &str)]) -> Result<u64, ClientError> {
        self.put_sealed_batch(notes, NOTE_CONTENT_TYPE).await
    }

    pub async fn delete_note(&mut self, object_id: Uuid) -> Result<u64, ClientError> {
        self.write_object(object_id, Vec::new(), Vec::new(), 0, true)
            .await
    }

    pub async fn put_notebook(&mut self, object_id: Uuid, name: &str) -> Result<u64, ClientError> {
        let plaintext = serde_json::json!({
            "@type": "Notebook",
            "version": "1.0",
            "name": name,
        })
        .to_string();
        self.put_sealed(object_id, plaintext.as_bytes(), NOTEBOOK_CONTENT_TYPE)
            .await
    }

    pub async fn delete_notebook(&mut self, object_id: Uuid) -> Result<u64, ClientError> {
        self.write_object(object_id, Vec::new(), Vec::new(), 0, true)
            .await
    }

    pub async fn ensure_default_notebook(&mut self) -> Result<Uuid, ClientError> {
        let notebooks = self.list_notebooks().await?;
        if notebooks.iter().any(|(id, _)| *id == DEFAULT_NOTEBOOK_ID) {
            return Ok(DEFAULT_NOTEBOOK_ID);
        }
        self.put_notebook(DEFAULT_NOTEBOOK_ID, DEFAULT_NOTEBOOK_NAME)
            .await?;
        Ok(DEFAULT_NOTEBOOK_ID)
    }

    pub async fn list_notebooks(&mut self) -> Result<Vec<(Uuid, String)>, ClientError> {
        let mut out = Vec::new();
        for obj in self.list_objects().await? {
            if obj.content_type != NOTEBOOK_CONTENT_TYPE {
                continue;
            }
            out.push((obj.id, container_name(&obj.into_text()?)));
        }
        out.sort_by(|a, b| {
            if a.0 == DEFAULT_NOTEBOOK_ID {
                return std::cmp::Ordering::Less;
            }
            if b.0 == DEFAULT_NOTEBOOK_ID {
                return std::cmp::Ordering::Greater;
            }
            a.1.to_lowercase().cmp(&b.1.to_lowercase())
        });
        Ok(out)
    }

    pub async fn list_notes(&mut self) -> Result<Vec<(Uuid, String)>, ClientError> {
        let mut out = Vec::new();
        for obj in self.list_objects().await? {
            if obj.content_type == NOTE_CONTENT_TYPE {
                out.push((obj.id, obj.into_text()?));
            }
        }
        Ok(out)
    }

    async fn put_sealed(
        &mut self,
        object_id: Uuid,
        plaintext: &[u8],
        content_type: &str,
    ) -> Result<u64, ClientError> {
        // Read before sealing: `prepare_write` fixes the epoch to seal under.
        let state = self.prepare_write(&[object_id]).await?;
        let write = self.seal_write(object_id, plaintext, content_type)?;
        self.write_prepared(state, write).await
    }

    /// The bucket state a write folds into, with the cached collection key
    /// aligned to that state's epoch.
    ///
    /// Callers must seal after this, not before: the epoch a write signs comes
    /// from the manifest read here, and sealing under an older key stores a row
    /// nothing can decrypt or rotate.
    async fn prepare_write(&mut self, ids: &[Uuid]) -> Result<BucketedManifest, ClientError> {
        let state = self.manifest_bucket_state(ids).await?;
        self.align_key_epoch(state.key_epoch).await?;
        Ok(state)
    }

    /// Brings the cached collection key up to `key_epoch`, or refuses the write.
    ///
    /// Refreshing needs only this device's X-Wing secret, so it happens here
    /// rather than sending the caller back for the password. A device that still
    /// cannot reach the epoch has been revoked or raced a second rotation.
    async fn align_key_epoch(&mut self, key_epoch: u64) -> Result<(), ClientError> {
        if self.key_epoch == key_epoch {
            return Ok(());
        }
        let refreshed = self.refresh_collection_key().await?;
        if refreshed != key_epoch {
            return Err(ClientError::StaleCollectionKey {
                expected: key_epoch,
                held: refreshed,
            });
        }
        Ok(())
    }

    /// Seals one object for a write, without sending it.
    fn seal_write(
        &self,
        object_id: Uuid,
        plaintext: &[u8],
        content_type: &str,
    ) -> Result<PendingWrite, ClientError> {
        let collection_id = self
            .state
            .as_ref()
            .ok_or(ClientError::NoState)?
            .collection_id;
        let key = self
            .collection_key
            .as_ref()
            .ok_or(ClientError::NoCollectionKey)?;
        let aad = object_aad(object_id.as_bytes(), collection_id.as_bytes());
        let enc = encrypt_object(key, &seal_envelope(content_type, plaintext), &aad)?;
        Ok(PendingWrite {
            id: object_id,
            nonce: enc.nonce.to_vec(),
            ciphertext: enc.ciphertext,
            padded_size: enc.padded_size,
            tombstone: false,
        })
    }

    /// Seals and writes several objects of one kind in a single request.
    async fn put_sealed_batch(
        &mut self,
        objects: &[(Uuid, &str)],
        content_type: &str,
    ) -> Result<u64, ClientError> {
        if objects.is_empty() {
            return Ok(0);
        }
        let ids = batch_ids(objects.iter().map(|(id, _)| *id).collect())?;
        let state = self.prepare_write(&ids).await?;
        let mut writes = Vec::with_capacity(objects.len());
        for (object_id, plaintext) in objects {
            writes.push(self.seal_write(*object_id, plaintext.as_bytes(), content_type)?);
        }
        self.write_batch_prepared(state, writes).await
    }

    /// Objects as stored, without opening the envelope, so they can be
    /// re-encrypted under a new key with their contents untouched. The one
    /// exception is an object with no envelope, which gets one here.
    ///
    /// Tombstones come back alongside the live objects rather than being dropped.
    /// A rotation does not re-encrypt them, since there is no plaintext left to
    /// re-encrypt, but they are still rows in the collection and the manifest
    /// commits to every row. Leaving them out made the manifest disagree with the
    /// server's view, and a rotation over a vault with any deletion in it was
    /// refused.
    pub(crate) async fn list_stored_objects(&mut self) -> Result<VaultContents, ClientError> {
        let collection_id = self
            .state
            .as_ref()
            .ok_or(ClientError::NoState)?
            .collection_id;
        let verified = self.fetch_verified_objects().await?;
        let key = self
            .collection_key
            .as_ref()
            .ok_or(ClientError::NoCollectionKey)?;
        let mut contents = VaultContents::default();
        for obj in verified.objects {
            if obj.tombstone {
                // Below the floor no incremental answer can still carry this
                // delete, so the row has done its job and this rotation retires
                // it rather than signing for it again.
                if obj.revision < verified.tombstone_floor {
                    contents.retired.push(obj.id);
                    continue;
                }
                contents.tombstones.push(ManifestEntry {
                    id: obj.id,
                    revision: obj.revision,
                    tombstone: true,
                    content_digest: content_digest(&obj.nonce, &obj.ciphertext).to_vec(),
                });
                continue;
            }
            if obj.nonce.len() != 24 {
                return Err(ClientError::Nonce);
            }
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(&obj.nonce);
            let encrypted = EncryptedObject {
                nonce,
                ciphertext: obj.ciphertext,
                padded_size: obj.padded_size,
            };
            let aad = object_aad(obj.id.as_bytes(), collection_id.as_bytes());
            let plain = decrypt_object(key, &encrypted, &aad)?;
            // A rotation is where a vault stops depending on the server's label.
            // An object written before the envelope existed is wrapped in one
            // here, from the only type on offer for it, so what goes back under
            // the new key carries its own type. After one rotation nothing in
            // the collection needs the label, and the server is told none.
            let unsealed = open_envelope(&plain);
            let stored = match unsealed {
                Unsealed::Envelope { .. } => plain,
                Unsealed::Legacy => seal_envelope(&obj.content_type, &plain),
                Unsealed::Unreadable => return Err(ClientError::Envelope(obj.id)),
            };
            contents.live.push(StoredObject { id: obj.id, stored });
        }
        Ok(contents)
    }

    async fn list_objects(&mut self) -> Result<Vec<PlainObject>, ClientError> {
        let collection_id = self
            .state
            .as_ref()
            .ok_or(ClientError::NoState)?
            .collection_id;
        let objects = self.fetch_verified_objects().await?.objects;
        let key = self
            .collection_key
            .as_ref()
            .ok_or(ClientError::NoCollectionKey)?;
        let mut out = Vec::new();
        for obj in objects {
            if obj.tombstone {
                continue;
            }
            if obj.nonce.len() != 24 {
                return Err(ClientError::Nonce);
            }
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(&obj.nonce);
            let encrypted = EncryptedObject {
                nonce,
                ciphertext: obj.ciphertext,
                padded_size: obj.padded_size,
            };
            let aad = object_aad(obj.id.as_bytes(), collection_id.as_bytes());
            let plain = decrypt_object(key, &encrypted, &aad)?;
            let unsealed = open_envelope(&plain);
            let (content_type, plaintext) = match unsealed {
                // A sealed tombstone, which `sealbook-web` writes: a row with a
                // body but nothing to read.
                Unsealed::Envelope {
                    tombstone: true, ..
                } => continue,
                Unsealed::Envelope {
                    content_type,
                    payload,
                    ..
                } => (content_type, payload),
                // Written before the envelope existed, so the server's label is
                // the only type on offer and nothing authenticates it. The next
                // rotation seals it in and this stops being reachable.
                Unsealed::Legacy => (obj.content_type, plain),
                Unsealed::Unreadable => return Err(ClientError::Envelope(obj.id)),
            };
            out.push(PlainObject {
                id: obj.id,
                content_type,
                plaintext,
            });
        }
        Ok(out)
    }

    /// Writes one object, signing a manifest for the state the write produces.
    ///
    /// Only the bucket the object falls in is read, not the whole collection.
    /// Reading every entry per write is what made importing n objects cost O(n^2)
    /// bytes.
    async fn write_object(
        &mut self,
        object_id: Uuid,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        padded_size: usize,
        tombstone: bool,
    ) -> Result<u64, ClientError> {
        let state = self.prepare_write(&[object_id]).await?;
        self.write_prepared(
            state,
            PendingWrite {
                id: object_id,
                nonce,
                ciphertext,
                padded_size,
                tombstone,
            },
        )
        .await
    }

    /// Sends one write against a bucket state already read and a key already
    /// aligned to its epoch.
    async fn write_prepared(
        &mut self,
        state: BucketedManifest,
        write: PendingWrite,
    ) -> Result<u64, ClientError> {
        let (server, collection_id, token) = {
            let local = self.state.as_ref().ok_or(ClientError::NoState)?;
            (
                local.server.clone(),
                local.collection_id,
                local.session_token.clone().ok_or(ClientError::NoState)?,
            )
        };
        let PendingWrite {
            id: object_id,
            nonce,
            ciphertext,
            padded_size,
            tombstone,
        } = write;
        let (seq, key_epoch, revision) = (state.seq, state.key_epoch, state.latest_revision + 1);
        let (object_count, root) = state.apply(&[ManifestEntry {
            id: object_id,
            revision,
            tombstone,
            content_digest: content_digest(&nonce, &ciphertext).to_vec(),
        }])?;
        let manifest =
            self.sign_manifest_root(seq + 1, key_epoch, revision, object_count, &root)?;
        let written_seq = seq + 1;

        let resp: sealbook_protocol::PutObjectResponse = self
            .put_json(
                &format!("{server}/v1/collections/{collection_id}/objects"),
                &PutObjectRequest {
                    id: object_id,
                    revision,
                    nonce,
                    ciphertext,
                    padded_size,
                    content_type: SEALED_CONTENT_TYPE.into(),
                    tombstone,
                    manifest,
                },
                Some(&token),
            )
            .await?;
        // The server stored the manifest this device signed, so that sequence is
        // now the floor: anything older served back is a rollback.
        self.accept_manifest_seq(written_seq)?;
        Ok(resp.revision)
    }

    /// Writes several objects under one manifest and one request.
    ///
    /// One `write_object` per object costs a round trip and a manifest signature
    /// each, and the per-minute write cap is reached at one object per request, so
    /// an import of any size was slow for reasons that had nothing to do with its
    /// bytes. This signs one manifest for the state the whole batch produces.
    ///
    /// Revisions run consecutively from the collection's next one, in the order
    /// given, because that is what the server assigns and the manifest commits to
    /// each of them. Sent against a bucket state already read and a key already
    /// aligned to that state's epoch.
    async fn write_batch_prepared(
        &mut self,
        state: BucketedManifest,
        writes: Vec<PendingWrite>,
    ) -> Result<u64, ClientError> {
        let (server, collection_id, token) = {
            let local = self.state.as_ref().ok_or(ClientError::NoState)?;
            (
                local.server.clone(),
                local.collection_id,
                local.session_token.clone().ok_or(ClientError::NoState)?,
            )
        };
        let (seq, key_epoch) = (state.seq, state.key_epoch);
        let first_revision = state.latest_revision + 1;

        let entries: Vec<ManifestEntry> = writes
            .iter()
            .enumerate()
            .map(|(index, write)| ManifestEntry {
                id: write.id,
                revision: first_revision + index as u64,
                tombstone: write.tombstone,
                content_digest: content_digest(&write.nonce, &write.ciphertext).to_vec(),
            })
            .collect();
        let latest_revision = first_revision + writes.len() as u64 - 1;
        let (object_count, root) = state.apply(&entries)?;
        let manifest =
            self.sign_manifest_root(seq + 1, key_epoch, latest_revision, object_count, &root)?;
        let written_seq = seq + 1;

        let objects: Vec<BatchObject> = writes
            .into_iter()
            .zip(&entries)
            .map(|(write, entry)| BatchObject {
                id: write.id,
                revision: entry.revision,
                nonce: write.nonce,
                ciphertext: write.ciphertext,
                padded_size: write.padded_size,
                content_type: SEALED_CONTENT_TYPE.into(),
                tombstone: write.tombstone,
            })
            .collect();
        let resp: PutObjectsResponse = self
            .put_json(
                &format!("{server}/v1/collections/{collection_id}/objects/batch"),
                &PutObjectsRequest { objects, manifest },
                Some(&token),
            )
            .await?;
        self.accept_manifest_seq(written_seq)?;
        Ok(resp.latest_revision)
    }

    /// Every object in the collection, checked against the signed manifest.
    ///
    /// Walks the paginated change feed to the end, then verifies the whole set at
    /// once — a page on its own cannot be checked, since the manifest commits to
    /// the collection rather than to any page of it. Restarts the walk if a write
    /// lands during it, because the accumulated set and the final manifest would
    /// then describe different states.
    async fn fetch_verified_objects(&mut self) -> Result<VerifiedObjects, ClientError> {
        for _ in 0..SYNC_ATTEMPTS {
            let Some(walk) = self.walk_collection().await? else {
                continue;
            };
            return self.verify_walk(walk).await;
        }
        Err(ClientError::CollectionBusy)
    }

    /// One pass over the change feed, or `None` if the collection moved during it.
    ///
    /// Every page carries the current manifest, so a page whose manifest sequence
    /// differs from the first page's is proof that a write committed between the
    /// two and that this pass cannot be verified as a whole.
    async fn walk_collection(&self) -> Result<Option<Walk>, ClientError> {
        let (server, collection_id, token) = {
            let state = self.state.as_ref().ok_or(ClientError::NoState)?;
            (
                state.server.clone(),
                state.collection_id,
                state.session_token.clone().ok_or(ClientError::NoState)?,
            )
        };
        let mut objects: Vec<sealbook_protocol::ObjectChange> = Vec::new();
        let mut after = 0u64;
        let mut manifest;
        let mut tombstone_floor;
        let mut expected_seq = None;
        let mut first_page = true;
        loop {
            let page: ChangesResponse = self
                .get_json(
                    // `snapshot=1`: this client rebuilds its whole view every
                    // time, so it walks live objects rather than the revision log.
                    // That cannot be interrupted by a retention sweep part way
                    // through the walk.
                    &format!(
                        "{server}/v1/collections/{collection_id}/changes\
                         ?after={after}&limit={}&snapshot=true",
                        sealbook_protocol::DEFAULT_CHANGES_LIMIT
                    ),
                    Some(&token),
                )
                .await?;
            // Compared as `Option`, so a collection that gains its first manifest
            // part way through a walk restarts as well.
            let page_seq = page.manifest.as_ref().map(|current| current.manifest_seq);
            if first_page {
                expected_seq = page_seq;
                first_page = false;
            } else if page_seq != expected_seq {
                return Ok(None);
            }
            manifest = page.manifest.clone();
            tombstone_floor = page.tombstone_floor;
            let page_high = page.objects.iter().map(|object| object.revision).max();
            objects.extend(page.objects);
            match (page.has_more, page_high) {
                (true, Some(high)) if high > after => after = high,
                _ => break,
            }
        }
        Ok(Some(Walk {
            objects,
            manifest,
            tombstone_floor,
        }))
    }

    /// Checks a completed walk against the manifest it was served with.
    async fn verify_walk(&mut self, walk: Walk) -> Result<VerifiedObjects, ClientError> {
        let Walk {
            objects,
            manifest,
            tombstone_floor,
        } = walk;
        let latest = latest_revisions(objects);

        match manifest {
            Some(manifest) => {
                let entries: Vec<ManifestEntry> = latest
                    .iter()
                    .map(|object| ManifestEntry {
                        id: object.id,
                        revision: object.revision,
                        tombstone: object.tombstone,
                        content_digest: content_digest(&object.nonce, &object.ciphertext).to_vec(),
                    })
                    .collect();
                let devices = self.list_devices().await?;
                self.verify_manifest(&manifest, &entries, &devices)?;
            }
            None => {
                let state = self.state.as_ref().ok_or(ClientError::NoState)?;
                if state.manifest_seq > 0 {
                    return Err(ManifestError(
                        "server served objects with no manifest, but this device has seen one"
                            .into(),
                    )
                    .into());
                }
            }
        }
        Ok(VerifiedObjects {
            objects: latest,
            tombstone_floor,
        })
    }
}

/// How many times a full sync restarts when the collection moves during it.
///
/// A write between two pages used to produce the tamper error, which is the
/// loudest thing this client says and the one failure that must never be
/// retried away. Telling the two apart is the point: a bounded restart answers
/// the race, and `ClientError::CollectionBusy` answers a collection that is
/// being written to continuously.
const SYNC_ATTEMPTS: usize = 4;

/// One pass over the change feed, before it has been verified.
struct Walk {
    objects: Vec<sealbook_protocol::ObjectChange>,
    manifest: Option<sealbook_protocol::ManifestBody>,
    tombstone_floor: u64,
}

/// The newest revision of each object, in the order they were first walked.
///
/// Indexed by id rather than scanned for: a linear search per object made a full
/// sync quadratic, which at the object quota is over a billion comparisons. The
/// manifest digest sorts within its buckets, so only the returned order matters
/// here, and first-walked order keeps it stable for callers.
fn latest_revisions(
    mut objects: Vec<sealbook_protocol::ObjectChange>,
) -> Vec<sealbook_protocol::ObjectChange> {
    // A later revision of the same object supersedes an earlier one.
    objects.sort_by_key(|object| object.revision);
    let mut position: HashMap<Uuid, usize> = HashMap::with_capacity(objects.len());
    let mut latest: Vec<sealbook_protocol::ObjectChange> = Vec::with_capacity(objects.len());
    for object in objects {
        match position.get(&object.id) {
            Some(&index) => latest[index] = object,
            None => {
                position.insert(object.id, latest.len());
                latest.push(object);
            }
        }
    }
    latest
}

/// One verified walk of the collection: the latest revision of every row, and
/// the floor that says which of its tombstones a rotation may retire.
struct VerifiedObjects {
    objects: Vec<sealbook_protocol::ObjectChange>,
    tombstone_floor: u64,
}

/// The `name` of any container object: address book or notebook.
pub(crate) fn container_name(plaintext: &str) -> String {
    serde_json::from_str::<serde_json::Value>(plaintext)
        .ok()
        .and_then(|value| {
            value
                .get("name")
                .and_then(|name| name.as_str())
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "Untitled".to_string())
}

#[cfg(test)]
mod tests {
    use super::{latest_revisions, PlainObject};
    use uuid::Uuid;

    fn change(id: Uuid, revision: u64) -> sealbook_protocol::ObjectChange {
        sealbook_protocol::ObjectChange {
            id,
            revision,
            tombstone: false,
            nonce: vec![0u8; 24],
            ciphertext: Vec::new(),
            padded_size: 256,
            content_type: "application/sealbook.sealed".to_string(),
        }
    }

    /// The dedupe used to be a linear scan per object, so a full sync at the
    /// object quota was over a billion comparisons. It has to keep both of the
    /// properties the scan had: the newest revision wins, and the order is the
    /// one the objects were first walked in, so a listing does not reshuffle
    /// between syncs.
    #[test]
    fn latest_revisions_keeps_the_newest_of_each_object_in_walk_order() {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let third = Uuid::new_v4();
        // Deliberately out of revision order, as two pages of a walk arrive.
        let walked = vec![
            change(first, 1),
            change(second, 2),
            change(first, 7),
            change(third, 3),
            change(second, 5),
        ];

        let latest = latest_revisions(walked);
        assert_eq!(
            latest
                .iter()
                .map(|object| (object.id, object.revision))
                .collect::<Vec<_>>(),
            // First appearance in revision order decides the position, which is
            // what the scan it replaced did too.
            vec![(first, 7), (second, 5), (third, 3)],
            "each id appears once, at its newest revision, in walk order"
        );
    }

    #[test]
    fn latest_revisions_handles_an_empty_walk() {
        assert!(latest_revisions(Vec::new()).is_empty());
    }

    // The envelope format itself is covered in `sealbook_protocol::envelope`,
    // which is where all three clients read it from.

    #[test]
    fn into_text_refuses_bytes_that_are_not_utf8() {
        let obj = PlainObject {
            id: Uuid::nil(),
            content_type: "application/jscontact+json".to_string(),
            plaintext: vec![0xff, 0xfe],
        };
        assert!(obj.into_text().is_err());
    }
}
