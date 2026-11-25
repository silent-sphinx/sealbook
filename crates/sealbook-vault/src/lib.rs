//! The on-device vault for desktop hosts.
//!
//! A host (the Slint app) talks to one [`VaultHandle`]. Behind it a
//! `sealbook-vault` thread runs a current-thread tokio runtime with two tasks:
//!
//! - the **StateActor** owns the device's copy of the vault, the outbox and the
//!   typed [`VaultModel`]. It never waits on the network: an edit is queued,
//!   saved and shown at once.
//! - the **NetWorker** owns the [`SealbookClient`] and runs rounds (catch up,
//!   plan, send, settle) when something asks for one.
//!
//! The host never blocks on either. Commands return a [`Reply`], a oneshot
//! receiver to await inside `slint::spawn_local`, and everything the vault
//! volunteers arrives as a [`VaultEvent`] through the sink given to
//! [`VaultHandle::spawn`], which the host forwards with
//! `slint::invoke_from_event_loop`.

pub mod attachments;
pub mod calendar;
pub mod edits;
pub mod model;
pub mod store;
pub mod trash;

mod net;
mod state;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sealbook_client::{ClientError, LocalState};
use sealbook_core::{CoreDeviceKind, CoreError, PendingWrite};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;
use zeroize::Zeroizing;

pub use model::{Change, ChangeKind, ChangeSet, Entry, Item, VaultModel};
pub use store::{AccountEntry, StoreError};

/// How long a result takes to arrive: await it inside `slint::spawn_local`.
pub type Reply<T> = oneshot::Receiver<T>;

/// How rounds are paced. The defaults are the product's; tests shorten them.
#[derive(Clone, Debug)]
pub struct Timing {
    /// After an edit, how long to wait for more before syncing.
    pub debounce: Duration,
    /// How often to try while writes are waiting.
    pub pending_poll: Duration,
    /// How often to look for other devices' changes when nothing is waiting.
    pub idle_poll: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            debounce: Duration::from_secs(1),
            pending_poll: Duration::from_secs(60),
            idle_poll: Duration::from_secs(300),
        }
    }
}

pub struct VaultConfig {
    pub data_root: PathBuf,
    /// A server certificate to trust instead of the web roots, for a pinned or
    /// self-hosted server.
    pub pinned_certificate: Option<rustls_pki_types::CertificateDer<'static>>,
    pub device_kind: CoreDeviceKind,
    /// The platform line stored in this device's label ("macOS", ...).
    pub device_platform: String,
    pub timing: Timing,
}

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("no account is unlocked")]
    NotUnlocked,
    #[error("an account is already unlocked")]
    AlreadyUnlocked,
    #[error("the vault is busy with a key change; try again in a moment")]
    EditsBlocked,
    #[error("you are offline and nothing is saved on this device yet")]
    OfflineAndEmpty,
    #[error("the server could not be reached; some changes are still waiting to be sent")]
    NotSynced,
    #[error("the vault has shut down")]
    Gone,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncStatus {
    /// No round has run yet in this session.
    Starting,
    Syncing,
    /// The last round finished and nothing is waiting.
    Synced,
    /// The server could not be reached. Edits are saved and wait.
    Offline,
    /// Sync stopped and will not resume on its own: a manifest check failed, or
    /// the server speaks another protocol. The message says what.
    Halted(String),
}

#[derive(Clone, Debug)]
pub enum VaultEvent {
    /// The model changed. `changes` says which rows, for views that redraw only
    /// those.
    Snapshot {
        model: Arc<VaultModel>,
        changes: ChangeSet,
        /// Writes waiting for the server.
        pending: usize,
        /// Writes the server refused, kept for the person to see.
        failed: usize,
    },
    Sync(SyncStatus),
    /// Something to tell the person, such as a conflicted copy being kept.
    Notice(String),
    /// The session expired, the password changed elsewhere, or this device was
    /// removed from the account: ask for the password and call
    /// [`VaultHandle::reconnect`], which fails for a removed device. Saved data
    /// stays readable meanwhile.
    SignInNeeded,
    /// The account owes a key rotation before it can sync. `upgrade` is a
    /// protocol upgrade, otherwise an unfinished recovery.
    RotationOwed {
        upgrade: bool,
    },
    /// The vault locked: keys are wiped and the model is empty.
    Locked,
}

pub type EventSink = Arc<dyn Fn(VaultEvent) + Send + Sync>;

/// What an edit closure sees.
pub struct EditContext<'a> {
    pub editor: edits::Editor<'a>,
    pub model: &'a VaultModel,
    pub now: &'a str,
}

pub type EditFn = Box<dyn FnOnce(&EditContext<'_>) -> Result<Vec<PendingWrite>, CoreError> + Send>;

/// Operations that change keys. Each flushes the outbox first, holds edits back
/// while it runs, and reads the whole vault again afterwards.
#[derive(Debug)]
pub enum KeyChange {
    /// Rotate the collection key, revoking `revoke` along the way.
    Rotate {
        revoke: Vec<Uuid>,
    },
    ChangePhrase,
    /// Returns nothing; the vault's local records are sealed under the new
    /// password afterwards.
    ChangePassword {
        current: String,
        new: String,
    },
}

/// What a key change gives back: the new recovery phrase, when it issued one.
#[derive(Debug, Default)]
pub struct KeyChanged {
    pub recovery_phrase: Option<String>,
}

pub(crate) enum Command {
    Unlock {
        account: AccountEntry,
        password: Zeroizing<String>,
        reply: oneshot::Sender<Result<AccountEntry, VaultError>>,
    },
    /// An account this device has just registered or been paired into.
    Adopt {
        state: Box<LocalState>,
        password: Zeroizing<String>,
        reply: oneshot::Sender<Result<AccountEntry, VaultError>>,
    },
    Edit {
        build: EditFn,
        reply: oneshot::Sender<Result<ChangeSet, VaultError>>,
    },
    SyncNow,
    Focus,
    Reconnect {
        password: Zeroizing<String>,
        reply: oneshot::Sender<Result<(), VaultError>>,
    },
    KeyChange {
        change: KeyChange,
        reply: oneshot::Sender<Result<KeyChanged, VaultError>>,
    },
    Model {
        reply: oneshot::Sender<Option<Arc<VaultModel>>>,
    },
    Attachment(attachments::AttachmentCommand),
    /// Wipes keys and the model, keeping the files.
    Lock {
        reply: oneshot::Sender<()>,
    },
    Shutdown,
}

/// The host's end of the vault. Cheap to clone; every method returns at once.
#[derive(Clone)]
pub struct VaultHandle {
    commands: mpsc::UnboundedSender<Command>,
    thread: Arc<std::sync::Mutex<Option<std::thread::JoinHandle<()>>>>,
}

impl VaultHandle {
    /// Starts the vault thread. `sink` is called from it, so it must be cheap and
    /// must not block: forward to the UI thread and return.
    pub fn spawn(config: VaultConfig, sink: EventSink) -> Self {
        let (commands, inbox) = mpsc::unbounded_channel();
        let thread = std::thread::Builder::new()
            .name("sealbook-vault".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("a tokio runtime");
                // The client's futures are not `Send` (rotation holds a callback across an
                // await), so both tasks run on this thread's local set.
                let local = tokio::task::LocalSet::new();
                runtime.block_on(local.run_until(state::run(Arc::new(config), sink, inbox)));
            })
            .expect("the vault thread starts");
        Self {
            commands,
            thread: Arc::new(std::sync::Mutex::new(Some(thread))),
        }
    }

    fn ask<T>(&self, command: impl FnOnce(oneshot::Sender<T>) -> Command) -> Reply<T> {
        let (reply, receiver) = oneshot::channel();
        // A closed inbox drops `reply`, which the receiver reports as an error.
        let _ = self.commands.send(command(reply));
        receiver
    }

    /// Opens a saved account: the saved data shows at once, then the vault signs
    /// in and catches up. The password is not kept past the sign-in.
    pub fn unlock(
        &self,
        account: AccountEntry,
        password: String,
    ) -> Reply<Result<AccountEntry, VaultError>> {
        self.ask(|reply| Command::Unlock {
            account,
            password: Zeroizing::new(password),
            reply,
        })
    }

    /// Takes over an account this device has just registered or paired into.
    pub fn adopt(
        &self,
        state: LocalState,
        password: String,
    ) -> Reply<Result<AccountEntry, VaultError>> {
        self.ask(|reply| Command::Adopt {
            state: Box::new(state),
            password: Zeroizing::new(password),
            reply,
        })
    }

    /// Runs `build` against the current model and queues the writes it returns.
    /// The edit is saved and shown before the reply arrives; sending is later.
    pub fn edit(
        &self,
        build: impl FnOnce(&EditContext<'_>) -> Result<Vec<PendingWrite>, CoreError> + Send + 'static,
    ) -> Reply<Result<ChangeSet, VaultError>> {
        self.ask(|reply| Command::Edit {
            build: Box::new(build),
            reply,
        })
    }

    pub fn sync_now(&self) {
        let _ = self.commands.send(Command::SyncNow);
    }

    /// The window gained focus: look for other devices' changes now.
    pub fn focus(&self) {
        let _ = self.commands.send(Command::Focus);
    }

    /// Signs in again after [`VaultEvent::SignInNeeded`].
    pub fn reconnect(&self, password: String) -> Reply<Result<(), VaultError>> {
        self.ask(|reply| Command::Reconnect {
            password: Zeroizing::new(password),
            reply,
        })
    }

    pub fn key_change(&self, change: KeyChange) -> Reply<Result<KeyChanged, VaultError>> {
        self.ask(|reply| Command::KeyChange { change, reply })
    }

    /// An attachment's bytes, from the encrypted cache or the server, checked
    /// against the hash its note committed to. Runs on its own connection, so it
    /// does not wait behind a sync.
    pub fn attachment(
        &self,
        reference: sealbook_client::UploadedAttachment,
    ) -> Reply<Result<Vec<u8>, VaultError>> {
        let (reply, receiver) = oneshot::channel();
        let _ = self
            .commands
            .send(Command::Attachment(attachments::AttachmentCommand::Fetch {
                reference: Box::new(reference),
                reply,
            }));
        receiver
    }

    /// Encrypts and uploads `data`, returning the reference a note stores.
    pub fn upload_attachment(
        &self,
        data: Vec<u8>,
    ) -> Reply<Result<sealbook_client::UploadedAttachment, VaultError>> {
        let (reply, receiver) = oneshot::channel();
        let _ = self.commands.send(Command::Attachment(
            attachments::AttachmentCommand::Upload { data, reply },
        ));
        receiver
    }

    /// The current model, or `None` when locked.
    pub fn model(&self) -> Reply<Option<Arc<VaultModel>>> {
        self.ask(|reply| Command::Model { reply })
    }

    pub fn lock(&self) -> Reply<()> {
        self.ask(|reply| Command::Lock { reply })
    }

    /// Saves, stops the thread and waits for it. Call after the UI loop ends: the
    /// vault cannot tell the loop has gone, because `invoke_from_event_loop` keeps
    /// returning `Ok` after it.
    pub fn shutdown(&self) {
        let _ = self.commands.send(Command::Shutdown);
        if let Some(thread) = self.thread.lock().ok().and_then(|mut slot| slot.take()) {
            let _ = thread.join();
        }
    }
}
