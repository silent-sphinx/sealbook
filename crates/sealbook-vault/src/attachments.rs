//! Attachments: an encrypted on-disk cache with a size budget, and the worker
//! that fetches and uploads them over a client of its own, so a download never
//! waits behind a sync.
//!
//! Cached files are sealed under the account's key with the attachment id as
//! their record name, so a file renamed to another id does not open. The cache is
//! only ever a copy: a file that is missing, damaged or sealed under an old key
//! is a miss and is removed, and the attachment is fetched again.

use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;

use sealbook_client::{LocalState, SealbookClient, UploadedAttachment};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use crate::store::BlobSealer;
use crate::VaultError;

/// The default cache budget.
pub const DEFAULT_BUDGET: u64 = 64 * 1024 * 1024;

pub struct AttachmentCache {
    dir: PathBuf,
    sealer: BlobSealer,
    budget: u64,
}

impl AttachmentCache {
    pub fn new(dir: PathBuf, sealer: BlobSealer, budget: u64) -> Self {
        Self {
            dir,
            sealer,
            budget,
        }
    }

    fn path(&self, id: Uuid) -> PathBuf {
        self.dir.join(format!("{id}.sbx"))
    }

    /// The attachment's bytes if cached, marking it as just used.
    pub fn get(&self, id: Uuid) -> Option<Vec<u8>> {
        let path = self.path(id);
        let sealed = fs::read(&path).ok()?;
        match self.sealer.open(&id.to_string(), &sealed) {
            Ok(bytes) => {
                if let Ok(file) = fs::File::options().write(true).open(&path) {
                    let _ = file.set_modified(SystemTime::now());
                }
                Some(bytes)
            }
            Err(_) => {
                let _ = fs::remove_file(path);
                None
            }
        }
    }

    /// Caches `bytes`, then drops the least recently used files until the cache
    /// fits its budget. Anything larger than the whole budget is not cached.
    pub fn put(&self, id: Uuid, bytes: &[u8]) {
        if bytes.len() as u64 > self.budget {
            return;
        }
        let Ok(sealed) = self.sealer.seal(&id.to_string(), bytes) else {
            return;
        };
        if fs::create_dir_all(&self.dir).is_err() {
            return;
        }
        let temp = self.dir.join(format!("{id}.sbx.tmp"));
        if fs::write(&temp, &sealed).is_err() || fs::rename(&temp, self.path(id)).is_err() {
            let _ = fs::remove_file(&temp);
            return;
        }
        self.evict(id);
    }

    fn evict(&self, keep: Uuid) {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return;
        };
        let mut files: Vec<(SystemTime, u64, PathBuf)> = entries
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".sbx"))
            .filter_map(|entry| {
                let meta = entry.metadata().ok()?;
                Some((meta.modified().ok()?, meta.len(), entry.path()))
            })
            .collect();
        let mut total: u64 = files.iter().map(|(_, len, _)| len).sum();
        files.sort_by_key(|(used, _, _)| *used);
        let keep = self.path(keep);
        for (_, len, path) in files {
            if total <= self.budget {
                break;
            }
            if path != keep && fs::remove_file(&path).is_ok() {
                total -= len;
            }
        }
    }

    pub fn remove(&self, id: Uuid) {
        let _ = fs::remove_file(self.path(id));
    }

    pub fn clear(&self) {
        let _ = fs::remove_dir_all(&self.dir);
    }

    /// Bytes on disk, sealing overhead included.
    pub fn size(&self) -> u64 {
        fs::read_dir(&self.dir)
            .map(|entries| {
                entries
                    .flatten()
                    .filter_map(|entry| entry.metadata().ok())
                    .map(|meta| meta.len())
                    .sum()
            })
            .unwrap_or(0)
    }
}

pub(crate) enum AttachmentCommand {
    /// A signed-in device: the worker builds its own client from this.
    Session {
        state: Box<LocalState>,
        cache: AttachmentCache,
        pinned: Option<rustls_pki_types::CertificateDer<'static>>,
    },
    End,
    Fetch {
        reference: Box<UploadedAttachment>,
        reply: oneshot::Sender<Result<Vec<u8>, VaultError>>,
    },
    Upload {
        data: Vec<u8>,
        reply: oneshot::Sender<Result<UploadedAttachment, VaultError>>,
    },
    Delete {
        id: Uuid,
        reply: oneshot::Sender<Result<(), VaultError>>,
    },
}

struct Live {
    client: Option<SealbookClient>,
    fingerprint: u64,
    cache: AttachmentCache,
    state: LocalState,
    pinned: Option<rustls_pki_types::CertificateDer<'static>>,
}

impl Live {
    /// A client holding the collection key, built from the device record: the
    /// session token and device keys are enough, so no password is needed.
    async fn client(&mut self) -> Result<&mut SealbookClient, VaultError> {
        if self.client.is_none() {
            let mut client =
                SealbookClient::with_state_and_tls(self.state.clone(), self.pinned.clone())?;
            client.refresh_collection_key().await?;
            self.client = Some(client);
        }
        Ok(self.client.as_mut().expect("just built"))
    }
}

pub(crate) async fn run(mut commands: mpsc::UnboundedReceiver<AttachmentCommand>) {
    let mut live: Option<Live> = None;
    while let Some(command) = commands.recv().await {
        match command {
            AttachmentCommand::Session {
                state,
                cache,
                pinned,
            } => {
                let fingerprint = state.fingerprint();
                match &mut live {
                    Some(current) if current.fingerprint == fingerprint => {}
                    _ => {
                        live = Some(Live {
                            client: None,
                            fingerprint,
                            cache,
                            state: *state,
                            pinned,
                        })
                    }
                }
            }
            AttachmentCommand::End => live = None,
            AttachmentCommand::Fetch { reference, reply } => {
                let result = match live.as_mut() {
                    Some(live) => fetch(live, &reference).await,
                    None => Err(VaultError::NotUnlocked),
                };
                let _ = reply.send(result);
            }
            AttachmentCommand::Upload { data, reply } => {
                let result = match live.as_mut() {
                    Some(live) => upload(live, &data).await,
                    None => Err(VaultError::NotUnlocked),
                };
                let _ = reply.send(result);
            }
            AttachmentCommand::Delete { id, reply } => {
                let result = match live.as_mut() {
                    Some(live) => delete(live, id).await,
                    None => Err(VaultError::NotUnlocked),
                };
                let _ = reply.send(result);
            }
        }
    }
}

async fn fetch(live: &mut Live, reference: &UploadedAttachment) -> Result<Vec<u8>, VaultError> {
    if let Some(bytes) = live.cache.get(reference.attachment_id) {
        return Ok(bytes);
    }
    let bytes = live.client().await?.download_attachment(reference).await?;
    live.cache.put(reference.attachment_id, &bytes);
    Ok(bytes)
}

async fn upload(live: &mut Live, data: &[u8]) -> Result<UploadedAttachment, VaultError> {
    let uploaded = live.client().await?.upload_attachment(data).await?;
    live.cache.put(uploaded.attachment_id, data);
    Ok(uploaded)
}

async fn delete(live: &mut Live, id: Uuid) -> Result<(), VaultError> {
    live.cache.remove(id);
    live.client().await?.delete_attachment(id).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{Identity, Store};

    fn cache(budget: u64) -> (tempfile::TempDir, AttachmentCache, Store) {
        let root = tempfile::tempdir().unwrap();
        let identity = Identity {
            server: "http://localhost".into(),
            username: "ada".into(),
            account_id: Uuid::from_u128(1),
            collection_id: Uuid::from_u128(2),
            device_id: Uuid::from_u128(3),
        };
        let store = Store::create(root.path(), identity, "pw", b"device").unwrap();
        let cache = AttachmentCache::new(
            store.path().join("attachments"),
            store.blob_sealer(),
            budget,
        );
        (root, cache, store)
    }

    #[test]
    fn a_cached_attachment_comes_back_and_is_not_stored_in_the_clear() {
        let (_root, cache, _store) = cache(1 << 20);
        let id = Uuid::new_v4();
        let secret = b"the attachment's own bytes, long enough to spot".to_vec();
        cache.put(id, &secret);
        assert_eq!(cache.get(id).unwrap(), secret);
        let on_disk = fs::read(cache.path(id)).unwrap();
        assert!(!on_disk
            .windows(secret.len())
            .any(|window| window == secret.as_slice()));
    }

    #[test]
    fn the_least_recently_used_files_go_first_when_the_budget_is_exceeded() {
        let (_root, cache, _store) = cache(1000);
        let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        cache.put(a, &[1; 300]);
        std::thread::sleep(std::time::Duration::from_millis(30));
        cache.put(b, &[2; 300]);
        std::thread::sleep(std::time::Duration::from_millis(30));
        // Using `a` makes `b` the oldest.
        assert!(cache.get(a).is_some());
        std::thread::sleep(std::time::Duration::from_millis(30));
        cache.put(c, &[3; 300]);
        assert!(cache.get(a).is_some());
        assert!(cache.get(b).is_none(), "the oldest file was dropped");
        assert!(cache.get(c).is_some());
        assert!(cache.size() <= 1000);
    }

    #[test]
    fn something_larger_than_the_whole_budget_is_not_cached() {
        let (_root, cache, _store) = cache(100);
        let id = Uuid::new_v4();
        cache.put(id, &[0; 500]);
        assert!(cache.get(id).is_none());
        assert_eq!(cache.size(), 0);
    }

    #[test]
    fn a_file_moved_to_another_id_or_damaged_is_a_miss_and_is_removed() {
        let (_root, cache, _store) = cache(1 << 20);
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        cache.put(a, b"alpha");
        fs::copy(cache.path(a), cache.path(b)).unwrap();
        assert!(cache.get(b).is_none());
        assert!(!cache.path(b).exists());
        fs::write(cache.path(a), b"junk").unwrap();
        assert!(cache.get(a).is_none());
    }

    #[test]
    fn a_rekey_turns_the_cache_into_misses() {
        let (_root, cache, mut store) = cache(1 << 20);
        let id = Uuid::new_v4();
        cache.put(id, b"alpha");
        store.rekey("new password", &[]).unwrap();
        assert!(
            cache.get(id).is_some(),
            "the old sealer still has the old key"
        );
        let fresh = AttachmentCache::new(
            store.path().join("attachments"),
            store.blob_sealer(),
            1 << 20,
        );
        assert!(fresh.get(id).is_none());
    }
}
