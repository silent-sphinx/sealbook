//! Reading and writing the collection's contents: the typed helpers callers
//! use, and the sealed object I/O underneath them.

use serde::Deserialize;
use uuid::Uuid;

use sealbook_crypto::{
    content_digest, decrypt_object, encrypt_object, object_aad, EncryptedObject,
};
use sealbook_protocol::{ChangesResponse, ManifestEntry, PutObjectRequest};
use sealbook_protocol::{
    ADDRESS_BOOK_CONTENT_TYPE, CALENDAR_CONTENT_TYPE, CALENDAR_EVENT_CONTENT_TYPE,
    DEFAULT_ADDRESS_BOOK_ID, DEFAULT_ADDRESS_BOOK_NAME, JSCONTACT_CONTENT_TYPE,
};

use crate::{ClientError, ManifestError, SealbookClient};

/// An object as stored, still wrapped in its envelope.
pub(crate) struct StoredObject {
    pub(crate) id: Uuid,
    pub(crate) content_type: String,
    pub(crate) stored: String,
}

struct PlainObject {
    id: Uuid,
    content_type: String,
    plaintext: String,
}

#[derive(Deserialize)]
struct StoredEnvelope {
    version: u8,
    #[serde(rename = "contentType")]
    content_type: String,
    tombstone: bool,
    payload: String,
}

impl SealbookClient {
    pub async fn put_contact(&self, object_id: Uuid, jscontact: &str) -> Result<u64, ClientError> {
        self.put_sealed(object_id, jscontact.as_bytes(), JSCONTACT_CONTENT_TYPE)
            .await
    }

    pub async fn delete_contact(&self, object_id: Uuid) -> Result<u64, ClientError> {
        self.write_object(
            object_id,
            Vec::new(),
            Vec::new(),
            0,
            JSCONTACT_CONTENT_TYPE,
            true,
        )
        .await
    }

    pub async fn put_address_book(&self, object_id: Uuid, name: &str) -> Result<u64, ClientError> {
        let plaintext = serde_json::json!({
            "@type": "AddressBook",
            "version": "1.0",
            "name": name,
        })
        .to_string();
        self.put_sealed(object_id, plaintext.as_bytes(), ADDRESS_BOOK_CONTENT_TYPE)
            .await
    }

    pub async fn ensure_default_address_book(&self) -> Result<Uuid, ClientError> {
        let books = self.list_address_books().await?;
        if books.iter().any(|(id, _)| *id == DEFAULT_ADDRESS_BOOK_ID) {
            return Ok(DEFAULT_ADDRESS_BOOK_ID);
        }
        self.put_address_book(DEFAULT_ADDRESS_BOOK_ID, DEFAULT_ADDRESS_BOOK_NAME)
            .await?;
        Ok(DEFAULT_ADDRESS_BOOK_ID)
    }

    pub async fn list_address_books(&self) -> Result<Vec<(Uuid, String)>, ClientError> {
        let mut out = Vec::new();
        for obj in self.list_objects().await? {
            if obj.content_type != ADDRESS_BOOK_CONTENT_TYPE {
                continue;
            }
            out.push((obj.id, address_book_name(&obj.plaintext)));
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

    pub async fn list_contacts(&self) -> Result<Vec<(Uuid, String)>, ClientError> {
        let mut out = Vec::new();
        for obj in self.list_objects().await? {
            if obj.content_type != JSCONTACT_CONTENT_TYPE {
                continue;
            }
            out.push((obj.id, obj.plaintext));
        }
        Ok(out)
    }

    pub async fn put_calendar_event(
        &self,
        object_id: Uuid,
        event: &str,
    ) -> Result<u64, ClientError> {
        self.put_sealed(object_id, event.as_bytes(), CALENDAR_EVENT_CONTENT_TYPE)
            .await
    }

    pub async fn put_calendar(
        &self,
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

    pub async fn list_calendars(&self) -> Result<Vec<(Uuid, String)>, ClientError> {
        let mut out = Vec::new();
        for obj in self.list_objects().await? {
            if obj.content_type == CALENDAR_CONTENT_TYPE {
                out.push((obj.id, obj.plaintext));
            }
        }
        Ok(out)
    }

    pub async fn list_calendar_events(&self) -> Result<Vec<(Uuid, String)>, ClientError> {
        let mut out = Vec::new();
        for obj in self.list_objects().await? {
            if obj.content_type == CALENDAR_EVENT_CONTENT_TYPE {
                out.push((obj.id, obj.plaintext));
            }
        }
        Ok(out)
    }

    async fn put_sealed(
        &self,
        object_id: Uuid,
        plaintext: &[u8],
        content_type: &str,
    ) -> Result<u64, ClientError> {
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
        let enc = encrypt_object(key, plaintext, &aad)?;
        self.write_object(
            object_id,
            enc.nonce.to_vec(),
            enc.ciphertext,
            enc.padded_size,
            content_type,
            false,
        )
        .await
    }

    /// Objects exactly as stored, without unwrapping the envelope, so they can
    /// be re-encrypted verbatim under a new key.
    pub(crate) async fn list_stored_objects(&self) -> Result<Vec<StoredObject>, ClientError> {
        let collection_id = self
            .state
            .as_ref()
            .ok_or(ClientError::NoState)?
            .collection_id;
        let key = self
            .collection_key
            .as_ref()
            .ok_or(ClientError::NoCollectionKey)?;
        let mut out = Vec::new();
        for obj in self.fetch_verified_objects().await? {
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
            out.push(StoredObject {
                id: obj.id,
                content_type: obj.content_type,
                stored: String::from_utf8_lossy(&plain).into_owned(),
            });
        }
        Ok(out)
    }

    async fn list_objects(&self) -> Result<Vec<PlainObject>, ClientError> {
        let collection_id = self
            .state
            .as_ref()
            .ok_or(ClientError::NoState)?
            .collection_id;
        let key = self
            .collection_key
            .as_ref()
            .ok_or(ClientError::NoCollectionKey)?;
        let mut out = Vec::new();
        for obj in self.fetch_verified_objects().await? {
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
            let decrypted = String::from_utf8_lossy(&plain);
            let (content_type, plaintext) = match serde_json::from_str::<StoredEnvelope>(&decrypted)
            {
                Ok(envelope) if envelope.version == 1 => {
                    if envelope.tombstone {
                        continue;
                    }
                    (envelope.content_type, envelope.payload)
                }
                _ => (obj.content_type, decrypted.into_owned()),
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
    async fn write_object(
        &self,
        object_id: Uuid,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        padded_size: usize,
        content_type: &str,
        tombstone: bool,
    ) -> Result<u64, ClientError> {
        let (server, collection_id, token) = {
            let state = self.state.as_ref().ok_or(ClientError::NoState)?;
            (
                state.server.clone(),
                state.collection_id,
                state.session_token.clone().ok_or(ClientError::NoState)?,
            )
        };
        let (seq, key_epoch, latest_revision, mut entries) = self.manifest_state().await?;
        let revision = latest_revision + 1;
        let entry = ManifestEntry {
            id: object_id,
            revision,
            tombstone,
            content_digest: content_digest(&nonce, &ciphertext).to_vec(),
        };
        match entries.iter_mut().find(|existing| existing.id == object_id) {
            Some(existing) => *existing = entry,
            None => entries.push(entry),
        }
        let manifest = self.sign_manifest(seq + 1, key_epoch, revision, &entries)?;

        let resp: sealbook_protocol::PutObjectResponse = self
            .put_json(
                &format!("{server}/v1/collections/{collection_id}/objects"),
                &PutObjectRequest {
                    id: object_id,
                    revision,
                    nonce,
                    ciphertext,
                    padded_size,
                    content_type: content_type.into(),
                    tombstone,
                    manifest,
                },
                Some(&token),
            )
            .await?;
        Ok(resp.revision)
    }

    /// Every object in the collection, checked against the signed manifest.
    ///
    /// Walks the paginated change feed to the end, then verifies the whole set at
    /// once — a page on its own cannot be checked, since the manifest commits to
    /// the collection rather than to any page of it.
    async fn fetch_verified_objects(
        &self,
    ) -> Result<Vec<sealbook_protocol::ObjectChange>, ClientError> {
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
            manifest = page.manifest.clone();
            let page_high = page.objects.iter().map(|object| object.revision).max();
            objects.extend(page.objects);
            match (page.has_more, page_high) {
                (true, Some(high)) if high > after => after = high,
                _ => break,
            }
        }
        // A later revision of the same object supersedes an earlier one.
        objects.sort_by_key(|object| object.revision);
        let mut latest: Vec<sealbook_protocol::ObjectChange> = Vec::new();
        for object in objects {
            match latest.iter_mut().find(|existing| existing.id == object.id) {
                Some(existing) => *existing = object,
                None => latest.push(object),
            }
        }

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
        Ok(latest)
    }
}

fn address_book_name(plaintext: &str) -> String {
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
