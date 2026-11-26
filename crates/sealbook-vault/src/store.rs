//! The on-disk store: one folder per account holding sealed records.
//!
//! Every `.sbx` record starts with a plaintext header (the key-stretching suite,
//! a salt and the identity it belongs to) followed by what
//! [`sealbook_crypto::local_seal`] made of the contents. The identity is also
//! the record's additional data, so a file copied from another account, another
//! device or another record name does not open.
//!
//! A write goes to a temporary file in the same folder, is synced, and is renamed
//! over the old one, so a crash leaves the old record or the new one, never half
//! of either. Leftover temporary files are ignored and swept on open.
//!
//! The records sit in a generation folder (`g0`, `g1`, ...) that the plaintext
//! `current` file names. Changing the password writes every record again into the
//! next generation and then swaps `current` in one rename, so a crash leaves the
//! old password working on the old records or the new one on the new, never a mix.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fd_lock::{RwLock, RwLockWriteGuard};
use sealbook_crypto::{
    local_open, local_seal, local_storage_key, CryptoError, LOCAL_STORAGE_KDF,
    LOCAL_STORAGE_KEY_LEN,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"SBX1";
const SALT_LEN: usize = 16;
const TEMP_SUFFIX: &str = ".tmp";
const CURRENT_FILE: &str = "current";

pub const DEVICE_RECORD: &str = "device.sbx";
pub const VAULT_RECORD: &str = "vault.sbx";
pub const OUTBOX_RECORD: &str = "outbox.sbx";
/// Edits made while a rotation, revoke or phrase change holds the outbox back.
pub const OUTBOX_LOCKED_RECORD: &str = "outbox-locked.sbx";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("{what}: {source}")]
    Io {
        what: String,
        #[source]
        source: std::io::Error,
    },
    #[error("another Sealbook window already has this account open")]
    Locked,
    #[error("the password does not open this account's saved data")]
    WrongPassword,
    #[error("{0} is damaged or belongs to another account")]
    Corrupt(String),
    #[error("{0}")]
    Crypto(#[from] CryptoError),
}

impl StoreError {
    fn io(what: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            what: what.into(),
            source,
        }
    }
}

/// What a record is bound to. Stored in the clear in each header and
/// authenticated as additional data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub server: String,
    pub username: String,
    pub account_id: Uuid,
    pub collection_id: Uuid,
    pub device_id: Uuid,
}

impl Identity {
    fn context(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("an identity serialises")
    }
}

/// A line of `accounts.json`, which prefills the sign-in form. It holds nothing
/// secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountEntry {
    pub account_id: Uuid,
    pub server: String,
    pub username: String,
}

/// Where accounts live: the platform's per-user data directory for Sealbook.
pub fn default_data_root() -> Option<PathBuf> {
    directories::ProjectDirs::from("app", "sealbook", "Sealbook")
        .map(|dirs| dirs.data_dir().to_path_buf())
}

pub fn read_accounts(root: &Path) -> Vec<AccountEntry> {
    fs::read(root.join("accounts.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

pub fn remember_account(root: &Path, entry: AccountEntry) -> Result<(), StoreError> {
    let mut accounts = read_accounts(root);
    accounts.retain(|known| known.account_id != entry.account_id);
    accounts.insert(0, entry);
    fs::create_dir_all(root).map_err(|e| StoreError::io("create the data folder", e))?;
    write_atomic(
        &root.join("accounts.json"),
        &serde_json::to_vec_pretty(&accounts).expect("accounts serialise"),
    )
}

pub fn forget_account(root: &Path, account_id: Uuid) -> Result<(), StoreError> {
    let mut accounts = read_accounts(root);
    accounts.retain(|known| known.account_id != account_id);
    write_atomic(
        &root.join("accounts.json"),
        &serde_json::to_vec_pretty(&accounts).expect("accounts serialise"),
    )
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temp = path.with_file_name(format!(
        "{name}.{}.{}{TEMP_SUFFIX}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let written = (|| {
        let mut file = File::create(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)
    })();
    if let Err(error) = written {
        let _ = fs::remove_file(&temp);
        return Err(StoreError::io(format!("write {name}"), error));
    }
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// The account folder's lock, held for as long as the store is open: one
/// process per account.
struct ProcessLock {
    // Declared before the lock so the guard drops first. The guard borrows the
    // heap allocation `lock` points at, which does not move while the box lives.
    guard: Option<RwLockWriteGuard<'static, File>>,
    lock: *mut RwLock<File>,
}

// SAFETY: the raw pointer is only dereferenced in `new` and `drop`, and the lock
// it points to is `Send` (`File`).
unsafe impl Send for ProcessLock {}

impl ProcessLock {
    /// A lock that holds nothing, for the staged copy a rekey builds while the
    /// real one is still held.
    fn none() -> Self {
        Self {
            guard: None,
            lock: std::ptr::null_mut(),
        }
    }

    fn new(path: &Path) -> Result<Self, StoreError> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .map_err(|e| StoreError::io("open the account lock", e))?;
        let lock = Box::into_raw(Box::new(RwLock::new(file)));
        // SAFETY: `lock` was just allocated and is freed only in `drop`, after the
        // guard taken here has been dropped.
        match unsafe { &mut *lock }.try_write() {
            Ok(guard) => Ok(Self {
                guard: Some(guard),
                lock,
            }),
            Err(error) => {
                // SAFETY: no guard exists, so nothing borrows the allocation.
                drop(unsafe { Box::from_raw(lock) });
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    Err(StoreError::Locked)
                } else {
                    Err(StoreError::io("lock the account", error))
                }
            }
        }
    }
}

impl Drop for ProcessLock {
    fn drop(&mut self) {
        self.guard.take();
        if !self.lock.is_null() {
            // SAFETY: allocated in `new`, and the guard that borrowed it is gone.
            drop(unsafe { Box::from_raw(self.lock) });
        }
    }
}

type Key = Zeroizing<[u8; LOCAL_STORAGE_KEY_LEN]>;

/// A record file's plaintext header and the sealed bytes after it.
struct Parsed<'a> {
    suite: &'a str,
    salt: [u8; SALT_LEN],
    identity: Identity,
    sealed: &'a [u8],
}

fn encode(suite: &str, salt: &[u8; SALT_LEN], identity: &Identity, sealed: &[u8]) -> Vec<u8> {
    let identity = serde_json::to_vec(identity).expect("an identity serialises");
    let mut out = Vec::with_capacity(sealed.len() + identity.len() + 32);
    out.extend_from_slice(MAGIC);
    out.push(suite.len() as u8);
    out.extend_from_slice(suite.as_bytes());
    out.extend_from_slice(salt);
    out.extend_from_slice(&(identity.len() as u32).to_be_bytes());
    out.extend_from_slice(&identity);
    out.extend_from_slice(sealed);
    out
}

fn parse<'a>(name: &str, bytes: &'a [u8]) -> Result<Parsed<'a>, StoreError> {
    let corrupt = || StoreError::Corrupt(name.to_string());
    let rest = bytes.strip_prefix(MAGIC).ok_or_else(corrupt)?;
    let (&suite_len, rest) = rest.split_first().ok_or_else(corrupt)?;
    let suite_len = usize::from(suite_len);
    if rest.len() < suite_len + SALT_LEN + 4 {
        return Err(corrupt());
    }
    let suite = std::str::from_utf8(&rest[..suite_len]).map_err(|_| corrupt())?;
    let salt: [u8; SALT_LEN] = rest[suite_len..suite_len + SALT_LEN]
        .try_into()
        .map_err(|_| corrupt())?;
    let rest = &rest[suite_len + SALT_LEN..];
    let identity_len = u32::from_be_bytes(rest[..4].try_into().map_err(|_| corrupt())?) as usize;
    let rest = &rest[4..];
    if rest.len() < identity_len {
        return Err(corrupt());
    }
    let identity = serde_json::from_slice(&rest[..identity_len]).map_err(|_| corrupt())?;
    Ok(Parsed {
        suite,
        salt,
        identity,
        sealed: &rest[identity_len..],
    })
}

fn random_salt() -> [u8; SALT_LEN] {
    *Uuid::new_v4().as_bytes()
}

/// Seals and opens loose files under the account's key.
#[derive(Clone)]
pub struct BlobSealer {
    key: Key,
    context: Vec<u8>,
}

impl BlobSealer {
    pub fn seal(&self, name: &str, bytes: &[u8]) -> Result<Vec<u8>, StoreError> {
        Ok(local_seal(&self.key, name, &self.context, bytes)?)
    }

    pub fn open(&self, name: &str, sealed: &[u8]) -> Result<Vec<u8>, StoreError> {
        Ok(local_open(&self.key, name, &self.context, sealed)?)
    }
}

/// One account's folder, open and locked.
pub struct Store {
    dir: PathBuf,
    generation: u64,
    identity: Identity,
    password_key: Key,
    suite: String,
    salt: [u8; SALT_LEN],
    _lock: ProcessLock,
}

impl Store {
    /// The account's folder under `root`.
    pub fn account_dir(root: &Path, account_id: Uuid) -> PathBuf {
        root.join(account_id.to_string())
    }

    fn generation_dir(&self) -> PathBuf {
        self.dir.join(format!("g{}", self.generation))
    }

    /// Creates the account's folder, takes its lock and seals a first
    /// `device.sbx` holding `device` under `password`.
    pub fn create(
        root: &Path,
        identity: Identity,
        password: &str,
        device: &[u8],
    ) -> Result<Self, StoreError> {
        let dir = Self::account_dir(root, identity.account_id);
        fs::create_dir_all(&dir).map_err(|e| StoreError::io("create the account folder", e))?;
        let lock = ProcessLock::new(&dir.join("lock"))?;
        let salt = random_salt();
        let key = Zeroizing::new(local_storage_key(
            password.as_bytes(),
            &salt,
            LOCAL_STORAGE_KDF,
        )?);
        let store = Self {
            dir,
            generation: 0,
            identity,
            password_key: key,
            suite: LOCAL_STORAGE_KDF.to_string(),
            salt,
            _lock: lock,
        };
        fs::create_dir_all(store.generation_dir())
            .map_err(|e| StoreError::io("create the record folder", e))?;
        store.write(DEVICE_RECORD, device)?;
        write_atomic(&store.dir.join(CURRENT_FILE), b"0")?;
        Ok(store)
    }

    /// Opens an existing account folder and returns it with the device record.
    ///
    /// `expected` names the account the caller means: a `device.sbx` made for
    /// another server, user or account is refused before any key is derived.
    pub fn open(
        root: &Path,
        expected: &AccountEntry,
        password: &str,
    ) -> Result<(Self, Vec<u8>), StoreError> {
        let dir = Self::account_dir(root, expected.account_id);
        let lock = ProcessLock::new(&dir.join("lock"))?;
        let generation = fs::read_to_string(dir.join(CURRENT_FILE))
            .map_err(|e| StoreError::io(format!("read {CURRENT_FILE}"), e))?
            .trim()
            .parse::<u64>()
            .map_err(|_| StoreError::Corrupt(CURRENT_FILE.to_string()))?;
        sweep_leftovers(&dir, generation);
        let bytes = fs::read(dir.join(format!("g{generation}")).join(DEVICE_RECORD))
            .map_err(|e| StoreError::io(format!("read {DEVICE_RECORD}"), e))?;
        let parsed = parse(DEVICE_RECORD, &bytes)?;
        let identity = parsed.identity.clone();
        if identity.account_id != expected.account_id
            || identity.server != expected.server
            || identity.username != expected.username
        {
            return Err(StoreError::Corrupt(DEVICE_RECORD.to_string()));
        }
        let key = Zeroizing::new(local_storage_key(
            password.as_bytes(),
            &parsed.salt,
            parsed.suite,
        )?);
        let device = local_open(&key, DEVICE_RECORD, &identity.context(), parsed.sealed)
            .map_err(|_| StoreError::WrongPassword)?;
        let store = Self {
            dir,
            generation,
            identity,
            password_key: key,
            suite: parsed.suite.to_string(),
            salt: parsed.salt,
            _lock: lock,
        };
        Ok((store, device))
    }

    /// A check of a typed password against the one this store is sealed under,
    /// with no server round trip. It stretches the password, so run it off the
    /// async runtime's threads.
    pub fn password_check(&self) -> impl FnOnce(&str) -> bool + Send + 'static {
        let key = self.password_key.clone();
        let salt = self.salt;
        let suite = self.suite.clone();
        move |password| {
            local_storage_key(password.as_bytes(), &salt, &suite)
                .map(Zeroizing::new)
                .is_ok_and(|typed| *typed == *key)
        }
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The account's folder, for what the store does not hold itself (the
    /// attachment cache, `prefs.json`).
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// Seals `bytes` as record `name` under the current key and writes it
    /// atomically.
    pub fn write(&self, name: &str, bytes: &[u8]) -> Result<(), StoreError> {
        let sealed = local_seal(&self.password_key, name, &self.identity.context(), bytes)?;
        write_atomic(
            &self.generation_dir().join(name),
            &encode(&self.suite, &self.salt, &self.identity, &sealed),
        )
    }

    /// The record's contents, or `None` when it has not been written.
    pub fn read(&self, name: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let bytes = match fs::read(self.generation_dir().join(name)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(StoreError::io(format!("read {name}"), error)),
        };
        let parsed = parse(name, &bytes)?;
        if parsed.identity != self.identity
            || parsed.salt != self.salt
            || parsed.suite != self.suite
        {
            return Err(StoreError::Corrupt(name.to_string()));
        }
        local_open(
            &self.password_key,
            name,
            &self.identity.context(),
            parsed.sealed,
        )
        .map(Some)
        .map_err(|_| StoreError::Corrupt(name.to_string()))
    }

    /// Seals the device record and every record in `names` that exists under
    /// `password` with a fresh salt.
    ///
    /// Everything goes into the next generation folder first, and the swap of
    /// `current` is the one step that commits, so a crash at any point leaves
    /// one whole generation that opens with one password.
    pub fn rekey(&mut self, password: &str, names: &[&str]) -> Result<(), StoreError> {
        let mut records = Vec::new();
        for name in std::iter::once(&DEVICE_RECORD).chain(names) {
            if let Some(contents) = self.read(name)? {
                records.push((*name, Zeroizing::new(contents)));
            }
        }
        let salt = random_salt();
        let key = Zeroizing::new(local_storage_key(
            password.as_bytes(),
            &salt,
            LOCAL_STORAGE_KDF,
        )?);
        let next = Self {
            dir: self.dir.clone(),
            generation: self.generation + 1,
            identity: self.identity.clone(),
            password_key: key.clone(),
            suite: LOCAL_STORAGE_KDF.to_string(),
            salt,
            _lock: ProcessLock::none(),
        };
        let folder = next.generation_dir();
        let _ = fs::remove_dir_all(&folder);
        fs::create_dir_all(&folder).map_err(|e| StoreError::io("create the record folder", e))?;
        for (name, contents) in &records {
            next.write(name, contents)?;
        }
        write_atomic(
            &self.dir.join(CURRENT_FILE),
            next.generation.to_string().as_bytes(),
        )?;
        let old = self.generation_dir();
        self.generation = next.generation;
        self.password_key = key;
        self.suite = LOCAL_STORAGE_KDF.to_string();
        self.salt = salt;
        let _ = fs::remove_dir_all(old);
        Ok(())
    }

    /// A sealer for files that live outside the generation folder, such as the
    /// attachment cache. It holds a copy of the current key, so it stops opening
    /// anything after [`Store::rekey`], which for a cache is a miss and not a loss.
    pub fn blob_sealer(&self) -> BlobSealer {
        BlobSealer {
            key: self.password_key.clone(),
            context: self.identity.context(),
        }
    }

    /// Removes the account's folder and its line in `accounts.json`.
    pub fn delete(self, root: &Path) -> Result<(), StoreError> {
        let account_id = self.identity.account_id;
        let dir = self.dir.clone();
        drop(self);
        fs::remove_dir_all(&dir).map_err(|e| StoreError::io("delete the account folder", e))?;
        forget_account(root, account_id)
    }
}

/// Clears what a crash can leave: temporary files, and generation folders other
/// than the current one.
fn sweep_leftovers(dir: &Path, current: u64) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let keep = format!("g{current}");
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        if name.ends_with(TEMP_SUFFIX) {
            let _ = fs::remove_file(&path);
        } else if name.starts_with('g') && name != keep && path.is_dir() {
            let _ = fs::remove_dir_all(&path);
        }
    }
    let Ok(entries) = fs::read_dir(dir.join(keep)) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy().ends_with(TEMP_SUFFIX) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity {
        Identity {
            server: "http://localhost".into(),
            username: "ada".into(),
            account_id: Uuid::from_u128(1),
            collection_id: Uuid::from_u128(2),
            device_id: Uuid::from_u128(3),
        }
    }

    fn entry(identity: &Identity) -> AccountEntry {
        AccountEntry {
            account_id: identity.account_id,
            server: identity.server.clone(),
            username: identity.username.clone(),
        }
    }

    #[test]
    fn a_record_survives_closing_and_reopening_with_the_password() {
        let root = tempfile::tempdir().unwrap();
        let identity = identity();
        let store = Store::create(root.path(), identity.clone(), "pw", b"device").unwrap();
        store.write(VAULT_RECORD, b"vault bytes").unwrap();
        drop(store);

        let (store, device) = Store::open(root.path(), &entry(&identity), "pw").unwrap();
        assert_eq!(device, b"device");
        assert_eq!(store.read(VAULT_RECORD).unwrap().unwrap(), b"vault bytes");
        assert_eq!(store.read(OUTBOX_RECORD).unwrap(), None);
    }

    #[test]
    fn the_wrong_password_is_told_apart_from_a_damaged_file() {
        let root = tempfile::tempdir().unwrap();
        let identity = identity();
        drop(Store::create(root.path(), identity.clone(), "pw", b"device").unwrap());
        assert!(matches!(
            Store::open(root.path(), &entry(&identity), "nope"),
            Err(StoreError::WrongPassword)
        ));
        let path = Store::account_dir(root.path(), identity.account_id)
            .join("g0")
            .join(DEVICE_RECORD);
        fs::write(&path, b"garbage").unwrap();
        assert!(matches!(
            Store::open(root.path(), &entry(&identity), "pw"),
            Err(StoreError::Corrupt(_))
        ));
    }

    #[test]
    fn a_record_copied_over_another_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let identity = identity();
        let store = Store::create(root.path(), identity.clone(), "pw", b"device").unwrap();
        store.write(VAULT_RECORD, b"the vault").unwrap();
        store.write(OUTBOX_RECORD, b"the outbox").unwrap();
        fs::copy(
            store.path().join("g0").join(VAULT_RECORD),
            store.path().join("g0").join(OUTBOX_RECORD),
        )
        .unwrap();
        assert!(matches!(
            store.read(OUTBOX_RECORD),
            Err(StoreError::Corrupt(_))
        ));
    }

    #[test]
    fn a_record_from_another_account_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let ours = identity();
        let theirs = Identity {
            account_id: Uuid::from_u128(9),
            ..identity()
        };
        let store = Store::create(root.path(), ours, "pw", b"device").unwrap();
        let other = Store::create(root.path(), theirs, "pw", b"device").unwrap();
        other.write(VAULT_RECORD, b"someone else's").unwrap();
        fs::copy(
            other.path().join("g0").join(VAULT_RECORD),
            store.path().join("g0").join(VAULT_RECORD),
        )
        .unwrap();
        assert!(matches!(
            store.read(VAULT_RECORD),
            Err(StoreError::Corrupt(_))
        ));
    }

    #[test]
    fn a_device_record_for_another_server_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let identity = identity();
        drop(Store::create(root.path(), identity.clone(), "pw", b"device").unwrap());
        let mut asked = entry(&identity);
        asked.server = "https://elsewhere".into();
        assert!(matches!(
            Store::open(root.path(), &asked, "pw"),
            Err(StoreError::Corrupt(_))
        ));
    }

    #[test]
    fn a_leftover_temporary_file_is_ignored_and_swept() {
        let root = tempfile::tempdir().unwrap();
        let identity = identity();
        let store = Store::create(root.path(), identity.clone(), "pw", b"device").unwrap();
        store.write(VAULT_RECORD, b"good").unwrap();
        let leftover = store.path().join("g0").join("vault.sbx.99.0.tmp");
        fs::write(&leftover, b"half a write").unwrap();
        drop(store);

        let (store, _) = Store::open(root.path(), &entry(&identity), "pw").unwrap();
        assert_eq!(store.read(VAULT_RECORD).unwrap().unwrap(), b"good");
        assert!(!leftover.exists());
    }

    #[test]
    fn a_second_open_of_the_same_account_is_refused_until_the_first_closes() {
        let root = tempfile::tempdir().unwrap();
        let identity = identity();
        let first = Store::create(root.path(), identity.clone(), "pw", b"device").unwrap();
        assert!(matches!(
            Store::open(root.path(), &entry(&identity), "pw"),
            Err(StoreError::Locked)
        ));
        drop(first);
        assert!(Store::open(root.path(), &entry(&identity), "pw").is_ok());
    }

    #[test]
    fn rekeying_moves_every_record_to_the_new_password() {
        let root = tempfile::tempdir().unwrap();
        let identity = identity();
        let mut store = Store::create(root.path(), identity.clone(), "old", b"device").unwrap();
        store.write(VAULT_RECORD, b"vault").unwrap();
        store.write(OUTBOX_RECORD, b"outbox").unwrap();
        store.rekey("new", &[VAULT_RECORD, OUTBOX_RECORD]).unwrap();
        drop(store);

        assert!(matches!(
            Store::open(root.path(), &entry(&identity), "old"),
            Err(StoreError::WrongPassword)
        ));
        let (store, device) = Store::open(root.path(), &entry(&identity), "new").unwrap();
        assert_eq!(device, b"device");
        assert_eq!(store.read(VAULT_RECORD).unwrap().unwrap(), b"vault");
        assert_eq!(store.read(OUTBOX_RECORD).unwrap().unwrap(), b"outbox");
    }

    #[test]
    fn a_rekey_cut_short_before_the_swap_leaves_the_old_password_working() {
        let root = tempfile::tempdir().unwrap();
        let identity = identity();
        let store = Store::create(root.path(), identity.clone(), "old", b"device").unwrap();
        store.write(VAULT_RECORD, b"vault").unwrap();
        // A crash after some of the next generation was written, before `current`
        // moved: the pointer still names g0.
        let partial = store.path().join("g1");
        fs::create_dir_all(&partial).unwrap();
        fs::write(partial.join(DEVICE_RECORD), b"half of the new generation").unwrap();
        drop(store);

        let (store, device) = Store::open(root.path(), &entry(&identity), "old").unwrap();
        assert_eq!(device, b"device");
        assert_eq!(store.read(VAULT_RECORD).unwrap().unwrap(), b"vault");
        assert!(!partial.exists());
    }

    #[test]
    fn an_old_generation_left_by_a_crash_after_the_swap_is_swept() {
        let root = tempfile::tempdir().unwrap();
        let identity = identity();
        let mut store = Store::create(root.path(), identity.clone(), "old", b"device").unwrap();
        store.rekey("new", &[]).unwrap();
        let stale = store.path().join("g0");
        fs::create_dir_all(&stale).unwrap();
        fs::write(stale.join("device.sbx"), b"stale").unwrap();
        drop(store);
        let (store, device) = Store::open(root.path(), &entry(&identity), "new").unwrap();
        assert_eq!(device, b"device");
        assert!(!store.path().join("g0").exists());
    }

    #[test]
    fn the_accounts_index_remembers_and_forgets() {
        let root = tempfile::tempdir().unwrap();
        let identity = identity();
        assert!(read_accounts(root.path()).is_empty());
        remember_account(root.path(), entry(&identity)).unwrap();
        remember_account(root.path(), entry(&identity)).unwrap();
        assert_eq!(read_accounts(root.path()), vec![entry(&identity)]);
        forget_account(root.path(), identity.account_id).unwrap();
        assert!(read_accounts(root.path()).is_empty());
    }
}
