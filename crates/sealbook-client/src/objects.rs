//! Reading and writing the collection's contents: the typed helpers callers
//! use, and the sealed object I/O underneath them.

use uuid::Uuid;

use sealbook_crypto::{content_digest, encrypt_object, object_aad, padded_len};
use sealbook_protocol::envelope::seal_envelope;
use sealbook_protocol::{
    BatchObject, ManifestEntry, PutObjectRequest, PutObjectsRequest, PutObjectsResponse,
    MAX_BATCH_BYTES, MAX_BATCH_OBJECTS,
};
use sealbook_protocol::{
    ADDRESS_BOOK_CONTENT_TYPE, BOOKMARK_COLLECTION_CONTENT_TYPE, BOOKMARK_CONTENT_TYPE,
    CALENDAR_CONTENT_TYPE, CALENDAR_EVENT_CONTENT_TYPE, DEFAULT_ADDRESS_BOOK_ID,
    DEFAULT_ADDRESS_BOOK_NAME, DEFAULT_BOOKMARK_COLLECTION_ID, DEFAULT_BOOKMARK_COLLECTION_NAME,
    DEFAULT_CALENDAR_COLOR, DEFAULT_CALENDAR_ID, DEFAULT_CALENDAR_NAME, DEFAULT_NOTEBOOK_ID,
    DEFAULT_NOTEBOOK_NAME, JSCONTACT_CONTENT_TYPE, NOTEBOOK_CONTENT_TYPE, NOTE_CONTENT_TYPE,
    SEALED_CONTENT_TYPE,
};

use crate::{ClientError, SealbookClient};
use sealbook_core::{
    manifest_apply, open_stored, BucketedManifest, CoreAddressBookDraft, CoreCalendarDraft,
    CoreCalendarEventDraft, ManifestPlan, RowOutcome, StoredRow,
};

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
    plaintext: String,
}

/// Every object in the collection, with the rows this device could not read
/// counted rather than left out silently.
///
/// An export that quietly drops them is a backup missing objects the account
/// still holds, so the count travels with the objects and the caller says so.
pub struct ExportedVault {
    pub objects: Vec<ExportedObject>,
    pub unreadable: u64,
}

/// One object as an export sees it: its id, the content type its envelope
/// carries, and its plaintext payload.
#[derive(Clone)]
pub struct ExportedObject {
    pub id: Uuid,
    pub content_type: String,
    pub payload: String,
}

/// Splits objects into batches that fit a single request.
///
/// Bounded by object count and by padded bytes: `MAX_BATCH_OBJECTS` alone lets a
/// batch of large objects exceed the server's body limit, which fails the write
/// rather than splitting it. Sizes come from `padded_len` rather than from
/// sealing, so a batch is sized before any of it is encrypted.
///
/// An object larger than the whole budget still goes, alone: it is within the
/// body limit as a single write, and refusing it here would mean an object that
/// can be exported but never imported.
fn import_chunks(objects: &[ExportedObject]) -> Vec<&[ExportedObject]> {
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut bytes = 0;
    for (index, object) in objects.iter().enumerate() {
        let size = padded_len(object.payload.len());
        let full = index - start == MAX_BATCH_OBJECTS;
        let over = bytes + size > MAX_BATCH_BYTES;
        // `index > start` keeps a single oversized object from closing an empty
        // chunk, which would loop forever on it.
        if full || (over && index > start) {
            chunks.push(&objects[start..index]);
            start = index;
            bytes = 0;
        }
        bytes += size;
    }
    if start < objects.len() {
        chunks.push(&objects[start..]);
    }
    chunks
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

    /// Writes an address book, merging onto `draft.raw`. This used to rebuild the
    /// record from the name alone, so a write dropped any key another client had
    /// put there.
    pub async fn put_address_book(
        &mut self,
        object_id: Uuid,
        draft: &CoreAddressBookDraft,
    ) -> Result<u64, ClientError> {
        let plaintext = sealbook_core::address_book_write(draft)?;
        self.put_sealed(object_id, plaintext.as_bytes(), ADDRESS_BOOK_CONTENT_TYPE)
            .await
    }

    pub async fn ensure_default_address_book(&mut self) -> Result<Uuid, ClientError> {
        let books = self.list_address_books().await?;
        if books.iter().any(|(id, _)| *id == DEFAULT_ADDRESS_BOOK_ID) {
            return Ok(DEFAULT_ADDRESS_BOOK_ID);
        }
        self.put_address_book(
            DEFAULT_ADDRESS_BOOK_ID,
            &CoreAddressBookDraft {
                name: DEFAULT_ADDRESS_BOOK_NAME.to_string(),
                raw: None,
            },
        )
        .await?;
        Ok(DEFAULT_ADDRESS_BOOK_ID)
    }

    pub async fn list_address_books(&mut self) -> Result<Vec<(Uuid, String)>, ClientError> {
        let mut out = Vec::new();
        for obj in self.listed_objects().await? {
            if obj.content_type != ADDRESS_BOOK_CONTENT_TYPE {
                continue;
            }
            out.push((
                obj.id,
                sealbook_core::address_book_parse(&obj.id.to_string(), &obj.plaintext).name,
            ));
        }
        out.sort_by(|a, b| {
            sealbook_core::container_order(
                &DEFAULT_ADDRESS_BOOK_ID.to_string(),
                (&a.0.to_string(), &a.1),
                (&b.0.to_string(), &b.1),
            )
        });
        Ok(out)
    }

    pub async fn list_contacts(&mut self) -> Result<Vec<(Uuid, String)>, ClientError> {
        let mut out = Vec::new();
        for obj in self.listed_objects().await? {
            if obj.content_type != JSCONTACT_CONTENT_TYPE {
                continue;
            }
            out.push((obj.id, obj.plaintext));
        }
        Ok(out)
    }

    pub async fn put_calendar_event(
        &mut self,
        object_id: Uuid,
        draft: &CoreCalendarEventDraft,
    ) -> Result<u64, ClientError> {
        let plaintext = sealbook_core::event_write(draft)?;
        self.put_sealed(object_id, plaintext.as_bytes(), CALENDAR_EVENT_CONTENT_TYPE)
            .await
    }

    /// Writes a calendar, merging onto `draft.raw`.
    ///
    /// The `previous` payload matters here as it does for a notebook: this used
    /// to rebuild the record from the name and the colour, so a write dropped
    /// the favourite and archived flags the other clients had set, and declared
    /// `"1.0"` as a literal rather than the schema version this build speaks.
    pub async fn put_calendar(
        &mut self,
        object_id: Uuid,
        draft: &CoreCalendarDraft,
    ) -> Result<u64, ClientError> {
        let plaintext = sealbook_core::calendar_write(draft)?;
        self.put_sealed(object_id, plaintext.as_bytes(), CALENDAR_CONTENT_TYPE)
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
            &CoreCalendarDraft {
                name: DEFAULT_CALENDAR_NAME.to_string(),
                color: DEFAULT_CALENDAR_COLOR.to_string(),
                ..Default::default()
            },
        )
        .await?;
        Ok(DEFAULT_CALENDAR_ID)
    }

    /// Every calendar, by name, with the default one first as the other clients
    /// list it.
    pub async fn list_calendars(&mut self) -> Result<Vec<(Uuid, String)>, ClientError> {
        let mut out = Vec::new();
        for obj in self.listed_objects().await? {
            if obj.content_type != CALENDAR_CONTENT_TYPE {
                continue;
            }
            out.push((
                obj.id,
                sealbook_core::calendar_parse(&obj.id.to_string(), &obj.plaintext).name,
            ));
        }
        out.sort_by(|a, b| {
            sealbook_core::container_order(
                &DEFAULT_CALENDAR_ID.to_string(),
                (&a.0.to_string(), &a.1),
                (&b.0.to_string(), &b.1),
            )
        });
        Ok(out)
    }

    pub async fn list_calendar_events(&mut self) -> Result<Vec<(Uuid, String)>, ClientError> {
        let mut out = Vec::new();
        for obj in self.listed_objects().await? {
            if obj.content_type == CALENDAR_EVENT_CONTENT_TYPE {
                out.push((obj.id, obj.plaintext));
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

    /// `previous` is the stored payload when this is a rename, so a key a
    /// notebook carries that this build does not own survives it. Before core
    /// owned the writer this rebuilt the record and dropped every such key.
    pub async fn put_notebook(
        &mut self,
        object_id: Uuid,
        name: &str,
        previous: Option<&str>,
    ) -> Result<u64, ClientError> {
        let plaintext = sealbook_core::notebook_write(name, previous)?;
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
        self.put_notebook(DEFAULT_NOTEBOOK_ID, DEFAULT_NOTEBOOK_NAME, None)
            .await?;
        Ok(DEFAULT_NOTEBOOK_ID)
    }

    pub async fn list_notebooks(&mut self) -> Result<Vec<(Uuid, String)>, ClientError> {
        let mut out = Vec::new();
        for obj in self.listed_objects().await? {
            if obj.content_type != NOTEBOOK_CONTENT_TYPE {
                continue;
            }
            out.push((
                obj.id,
                sealbook_core::notebook_parse(&obj.id.to_string(), &obj.plaintext).name,
            ));
        }
        out.sort_by(|a, b| {
            sealbook_core::container_order(
                &DEFAULT_NOTEBOOK_ID.to_string(),
                (&a.0.to_string(), &a.1),
                (&b.0.to_string(), &b.1),
            )
        });
        Ok(out)
    }

    pub async fn list_notes(&mut self) -> Result<Vec<(Uuid, String)>, ClientError> {
        let mut out = Vec::new();
        for obj in self.listed_objects().await? {
            if obj.content_type == NOTE_CONTENT_TYPE {
                out.push((obj.id, obj.plaintext));
            }
        }
        Ok(out)
    }

    // Tasks and task lists are written only by sealbook-web, and there is no
    // writer for them here. A CLI task command must go through `merge_payload`
    // with a short owned-key set, as `jscontact` does, and must not rebuild the
    // payload as `note_json` does: that drops every field it does not name.
    pub async fn put_bookmark(
        &mut self,
        object_id: Uuid,
        bookmark: &str,
    ) -> Result<u64, ClientError> {
        self.put_sealed(object_id, bookmark.as_bytes(), BOOKMARK_CONTENT_TYPE)
            .await
    }

    /// Writes up to `MAX_BATCH_OBJECTS` bookmarks in one request, as
    /// `put_contacts` does for contacts. What an import of a browser's exported
    /// bookmarks should use.
    pub async fn put_bookmarks(&mut self, bookmarks: &[(Uuid, &str)]) -> Result<u64, ClientError> {
        self.put_sealed_batch(bookmarks, BOOKMARK_CONTENT_TYPE)
            .await
    }

    pub async fn delete_bookmark(&mut self, object_id: Uuid) -> Result<u64, ClientError> {
        self.write_object(object_id, Vec::new(), Vec::new(), 0, true)
            .await
    }

    pub async fn list_bookmarks(&mut self) -> Result<Vec<(Uuid, String)>, ClientError> {
        let mut out = Vec::new();
        for obj in self.listed_objects().await? {
            if obj.content_type == BOOKMARK_CONTENT_TYPE {
                out.push((obj.id, obj.plaintext));
            }
        }
        Ok(out)
    }

    /// Writes a collection. `previous` is the stored payload when this is a
    /// rename, so `parentId`, `color` and any key a later build added survive it.
    pub async fn put_bookmark_collection(
        &mut self,
        object_id: Uuid,
        name: &str,
        previous: Option<&str>,
    ) -> Result<u64, ClientError> {
        let mut draft = previous
            .map(|raw| {
                sealbook_core::bookmark_collection_parse(&object_id.to_string(), raw).draft()
            })
            .unwrap_or_default();
        draft.name = name.to_string();
        let plaintext = sealbook_core::bookmark_collection_write(&draft)?;
        self.put_sealed(
            object_id,
            plaintext.as_bytes(),
            BOOKMARK_COLLECTION_CONTENT_TYPE,
        )
        .await
    }

    pub async fn delete_bookmark_collection(
        &mut self,
        object_id: Uuid,
    ) -> Result<u64, ClientError> {
        self.write_object(object_id, Vec::new(), Vec::new(), 0, true)
            .await
    }

    pub async fn ensure_default_bookmark_collection(&mut self) -> Result<Uuid, ClientError> {
        let collections = self.list_bookmark_collections().await?;
        if collections
            .iter()
            .any(|(id, _)| *id == DEFAULT_BOOKMARK_COLLECTION_ID)
        {
            return Ok(DEFAULT_BOOKMARK_COLLECTION_ID);
        }
        self.put_bookmark_collection(
            DEFAULT_BOOKMARK_COLLECTION_ID,
            DEFAULT_BOOKMARK_COLLECTION_NAME,
            None,
        )
        .await?;
        Ok(DEFAULT_BOOKMARK_COLLECTION_ID)
    }

    pub async fn list_bookmark_collections(&mut self) -> Result<Vec<(Uuid, String)>, ClientError> {
        let mut out = Vec::new();
        for obj in self.listed_objects().await? {
            if obj.content_type != BOOKMARK_COLLECTION_CONTENT_TYPE {
                continue;
            }
            out.push((
                obj.id,
                sealbook_core::bookmark_collection_parse(&obj.id.to_string(), &obj.plaintext).name,
            ));
        }
        out.sort_by(|a, b| {
            sealbook_core::container_order(
                &DEFAULT_BOOKMARK_COLLECTION_ID.to_string(),
                (&a.0.to_string(), &a.1),
                (&b.0.to_string(), &b.1),
            )
        });
        Ok(out)
    }

    /// Every live object in the collection, whatever its content type.
    ///
    /// The typed `list_*` helpers each filter to one content type and so cannot
    /// answer "all of it": an object written by a newer client, or by a feature
    /// this build does not have, belongs in an export of the account even though
    /// nothing here can read it. Sorted by content type then id, so an export
    /// written twice from the same vault is the same bytes.
    pub async fn export_objects(&mut self) -> Result<ExportedVault, ClientError> {
        let (objects, unreadable) = self.list_objects().await?;
        let mut out: Vec<ExportedObject> = objects
            .into_iter()
            .map(|obj| ExportedObject {
                id: obj.id,
                content_type: obj.content_type,
                payload: obj.plaintext,
            })
            .collect();
        out.sort_by(|a, b| a.content_type.cmp(&b.content_type).then(a.id.cmp(&b.id)));
        Ok(ExportedVault {
            objects: out,
            unreadable,
        })
    }

    /// Writes objects of any mix of content types back into the collection.
    ///
    /// The counterpart of `export_objects`: an import carries whatever the file
    /// holds, including a content type this build cannot read, so it cannot go
    /// through the typed `put_*` helpers or `put_sealed_batch`, which each seal a
    /// batch under one type. Ids are taken from the file rather than minted, so
    /// an object that is already in the collection takes a new revision.
    ///
    /// Sent in chunks bounded by both `MAX_BATCH_OBJECTS` and `MAX_BATCH_BYTES`,
    /// each its own request and manifest signature. A chunk that fails leaves the
    /// chunks before it written: there is no transaction spanning them, and a
    /// rerun is harmless because the ids are fixed.
    ///
    /// Returns the revision the last object took, or 0 if there was nothing to
    /// write.
    pub async fn import_objects(&mut self, objects: &[ExportedObject]) -> Result<u64, ClientError> {
        let mut revision = 0;
        for chunk in import_chunks(objects) {
            let ids = batch_ids(chunk.iter().map(|object| object.id).collect())?;
            let state = self.prepare_write(&ids).await?;
            let mut writes = Vec::with_capacity(chunk.len());
            for object in chunk {
                writes.push(self.seal_write(
                    object.id,
                    object.payload.as_bytes(),
                    &object.content_type,
                )?);
            }
            revision = self.write_batch_prepared(state, writes).await?;
        }
        Ok(revision)
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
        self.align_key_epoch(state.plan.key_epoch).await?;
        Ok(state)
    }

    /// Brings the cached collection key up to `key_epoch`, or refuses the write.
    ///
    /// Refreshing needs only this device's X-Wing secret, so it happens here
    /// rather than sending the caller back for the password. A device that still
    /// cannot reach the epoch has been revoked or raced a second rotation.
    pub(crate) async fn align_key_epoch(&mut self, key_epoch: u64) -> Result<(), ClientError> {
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

    /// Every live object in the collection, opened.
    ///
    /// Returns the objects and the number of rows this device could not read.
    /// A row the manifest vouched for that will not open is a local failure, a
    /// key epoch this device has not caught up to or a payload a newer build
    /// wrote, so it is counted rather than raised: raising it would lose every
    /// readable object behind one unreadable one.
    async fn list_objects(&mut self) -> Result<(Vec<PlainObject>, u64), ClientError> {
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
        let mut unreadable = 0;
        for obj in objects {
            match open_stored(
                key,
                collection_id,
                &StoredRow {
                    id: obj.id,
                    tombstone: obj.tombstone,
                    nonce: &obj.nonce,
                    ciphertext: &obj.ciphertext,
                    padded_size: obj.padded_size,
                },
            ) {
                RowOutcome::Object {
                    content_type,
                    payload,
                } => out.push(PlainObject {
                    id: obj.id,
                    content_type,
                    plaintext: payload,
                }),
                RowOutcome::Deleted => {}
                RowOutcome::Unreadable { .. } => unreadable += 1,
            }
        }
        Ok((out, unreadable))
    }

    /// [`Self::list_objects`] for a caller that filters to one content type.
    ///
    /// The unreadable count is dropped deliberately: a typed listing already
    /// leaves out every object of another type, so it is not where a row this
    /// device could not read is reported. An export is.
    async fn listed_objects(&mut self) -> Result<Vec<PlainObject>, ClientError> {
        Ok(self.list_objects().await?.0)
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
        let revision = state.plan.latest_revision + 1;
        let written_seq = state.plan.manifest_seq + 1;
        let plan = ManifestPlan {
            manifest_seq: written_seq,
            key_epoch: state.plan.key_epoch,
            latest_revision: revision,
        };
        let applied = manifest_apply(
            &state,
            &sealbook_core::core_entries(&[ManifestEntry {
                id: object_id,
                revision,
                tombstone,
                content_digest: content_digest(&nonce, &ciphertext).to_vec(),
            }]),
        )?;
        let manifest = self.sign_manifest_root(&plan, &applied)?;

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
        let written_seq = state.plan.manifest_seq + 1;
        let first_revision = state.plan.latest_revision + 1;

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
        let plan = ManifestPlan {
            manifest_seq: written_seq,
            key_epoch: state.plan.key_epoch,
            latest_revision: first_revision + writes.len() as u64 - 1,
        };
        let applied = manifest_apply(&state, &sealbook_core::core_entries(&entries))?;
        let manifest = self.sign_manifest_root(&plan, &applied)?;

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
}

#[cfg(test)]
mod tests {
    use super::{import_chunks, ExportedObject};
    use sealbook_protocol::{MAX_BATCH_BYTES, MAX_BATCH_OBJECTS};
    use uuid::Uuid;

    fn sized(bytes: usize) -> ExportedObject {
        ExportedObject {
            id: Uuid::new_v4(),
            content_type: "application/sealbook.note+json".to_string(),
            payload: "x".repeat(bytes),
        }
    }

    #[test]
    fn a_batch_of_small_objects_is_bounded_by_the_count() {
        let objects: Vec<ExportedObject> =
            (0..MAX_BATCH_OBJECTS * 2 + 5).map(|_| sized(8)).collect();
        let chunks = import_chunks(&objects);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), MAX_BATCH_OBJECTS);
        assert_eq!(chunks[1].len(), MAX_BATCH_OBJECTS);
        assert_eq!(chunks[2].len(), 5);
        assert_eq!(
            chunks.iter().map(|chunk| chunk.len()).sum::<usize>(),
            objects.len()
        );
    }

    /// The bug this guards: batching on count alone sent a request past the
    /// server's body limit, and a vault of large notes could not be imported at
    /// all.
    #[test]
    fn a_batch_of_large_objects_is_bounded_by_the_bytes() {
        let megabyte = 1024 * 1024;
        let objects: Vec<ExportedObject> = (0..20).map(|_| sized(megabyte)).collect();
        let chunks = import_chunks(&objects);
        assert!(chunks.len() > 1, "20 MiB went out as one request");
        for chunk in &chunks {
            let bytes: usize = chunk
                .iter()
                .map(|object| sealbook_crypto::padded_len(object.payload.len()))
                .sum();
            assert!(
                bytes <= MAX_BATCH_BYTES,
                "a chunk carries {bytes} padded bytes, over the {MAX_BATCH_BYTES} budget"
            );
        }
        assert_eq!(
            chunks.iter().map(|chunk| chunk.len()).sum::<usize>(),
            objects.len()
        );
    }

    /// An object past the whole budget has to go out on its own rather than
    /// close an empty chunk, which would loop forever, or be dropped.
    #[test]
    fn an_object_larger_than_the_budget_goes_out_alone() {
        let objects = vec![sized(8), sized(MAX_BATCH_BYTES + 1), sized(8)];
        let chunks = import_chunks(&objects);
        assert_eq!(
            chunks.iter().map(|chunk| chunk.len()).collect::<Vec<_>>(),
            vec![1, 1, 1]
        );
    }

    #[test]
    fn nothing_to_import_is_no_requests() {
        assert!(import_chunks(&[]).is_empty());
    }

    // The envelope format itself is covered in `sealbook_protocol::envelope`,
    // which is where all three clients read it from. The walk and the row
    // classification are covered in `sealbook_core::sync`.
}
