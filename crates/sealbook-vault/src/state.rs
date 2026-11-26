//! The StateActor: the one owner of the device's copy of the vault, the outbox
//! and the model. It answers the host and the NetWorker in turn and never waits
//! on the network, so an edit is queued, saved and shown before the server hears
//! of it.

use std::sync::Arc;

use sealbook_client::LocalState;
use sealbook_client::{CatchUp, FlushSent};
use sealbook_core::{
    device_label_ensure, local_vault_read, local_vault_write, outbox_fail, outbox_push,
    outbox_read, outbox_settle, outbox_settle_sent, outbox_write, CoreDeviceLabelObject,
    CorePayloadKind, FlushDrop, LocalVault, Outbox, PendingWrite, DEVICE_LABEL_CONTENT_TYPE,
};
use sealbook_protocol::{
    DEFAULT_ADDRESS_BOOK_ID, DEFAULT_ADDRESS_BOOK_NAME, DEFAULT_BOOKMARK_COLLECTION_ID,
    DEFAULT_BOOKMARK_COLLECTION_NAME, DEFAULT_CALENDAR_COLOR, DEFAULT_CALENDAR_ID,
    DEFAULT_CALENDAR_NAME, DEFAULT_NOTEBOOK_ID, DEFAULT_NOTEBOOK_NAME, DEFAULT_TASK_LIST_ID,
    DEFAULT_TASK_LIST_NAME,
};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use crate::attachments::{AttachmentCache, AttachmentCommand, DEFAULT_BUDGET};
use crate::edits::{now_rfc3339, Editor, NotebookEdit};
use crate::model::{ChangeSet, VaultModel};
use crate::net::{NetCommand, NetWorker};
use crate::store::{
    self, AccountEntry, Identity, Store, StoreError, DEVICE_RECORD, OUTBOX_RECORD, VAULT_RECORD,
};
use crate::{
    Command, EditContext, EventSink, KeyChange, KeyChanged, SyncStatus, VaultConfig, VaultError,
    VaultEvent,
};

/// The copies the NetWorker plans a round from.
pub(crate) struct Input {
    pub vault: LocalVault,
    pub outbox: Outbox,
}

/// What the NetWorker tells the StateActor. Anything with a `reply` is the
/// NetWorker waiting for the copies as they are after the change.
pub(crate) enum NetReport {
    Input {
        reply: oneshot::Sender<Input>,
    },
    CaughtUp {
        read: CatchUp,
        reply: oneshot::Sender<Input>,
    },
    Dropped {
        drops: Vec<FlushDrop>,
        reply: oneshot::Sender<Input>,
    },
    Sent {
        sent: FlushSent,
        planned: Outbox,
        reply: oneshot::Sender<Input>,
    },
    Failed {
        ids: Vec<String>,
        reason: String,
        reply: oneshot::Sender<Input>,
    },
    /// The device record changed (a new session token, a pinned roster).
    Device(Box<LocalState>),
    Status(SyncStatus),
    /// The first sign-in of an unlock finished: online, or not.
    Connected {
        online: bool,
    },
    SignInNeeded,
    RotationOwed {
        upgrade: bool,
    },
    /// Edits are held back while a key change runs.
    Block(bool),
    /// The password changed: seal every local record under the new one.
    Rekey {
        password: Zeroizing<String>,
        reply: oneshot::Sender<Result<(), StoreError>>,
    },
}

pub(crate) enum Message {
    Command(Command),
    Net(NetReport),
}

struct Session {
    account: AccountEntry,
    store: Store,
    device: LocalState,
    vault: LocalVault,
    outbox: Outbox,
    model: Arc<VaultModel>,
    blocked: bool,
    defaults_checked: bool,
    /// Waiting for the first sign-in because there is nothing saved to show.
    unlock_reply: Option<oneshot::Sender<Result<AccountEntry, VaultError>>>,
}

struct Actor {
    config: Arc<VaultConfig>,
    sink: EventSink,
    net: mpsc::UnboundedSender<NetCommand>,
    attachments: mpsc::UnboundedSender<AttachmentCommand>,
    session: Option<Session>,
}

/// Runs the StateActor and the NetWorker until a [`Command::Shutdown`].
pub(crate) async fn run(
    config: Arc<VaultConfig>,
    sink: EventSink,
    mut commands: mpsc::UnboundedReceiver<Command>,
) {
    let (state_tx, mut inbox) = mpsc::unbounded_channel::<Message>();
    let (net_tx, net_rx) = mpsc::unbounded_channel::<NetCommand>();
    let worker = NetWorker::new(config.clone(), state_tx.clone());
    let net_task = tokio::task::spawn_local(worker.run(net_rx));
    let (attachment_tx, attachment_rx) = mpsc::unbounded_channel::<AttachmentCommand>();
    let attachment_task = tokio::task::spawn_local(crate::attachments::run(attachment_rx));

    let forward = {
        let state_tx = state_tx.clone();
        tokio::task::spawn_local(async move {
            while let Some(command) = commands.recv().await {
                if state_tx.send(Message::Command(command)).is_err() {
                    break;
                }
            }
        })
    };

    let mut actor = Actor {
        config,
        sink,
        net: net_tx.clone(),
        attachments: attachment_tx,
        session: None,
    };
    while let Some(message) = inbox.recv().await {
        match message {
            Message::Command(Command::Shutdown) => break,
            Message::Command(command) => actor.command(command).await,
            Message::Net(report) => actor.report(report).await,
        }
    }
    actor.close_session();
    let _ = net_tx.send(NetCommand::Stop);
    drop(net_tx);
    // A round waiting on a reply from here would wait forever: dropping the inbox
    // drops those replies. One stuck in a slow request is given a moment, then cut.
    drop(inbox);
    let abort = net_task.abort_handle();
    if tokio::time::timeout(std::time::Duration::from_secs(2), net_task)
        .await
        .is_err()
    {
        abort.abort();
    }
    forward.abort();
    attachment_task.abort();
}

impl Actor {
    fn emit(&self, event: VaultEvent) {
        (self.sink)(event);
    }

    fn snapshot(&self, changes: ChangeSet) {
        if let Some(session) = &self.session {
            self.emit(VaultEvent::Snapshot {
                model: session.model.clone(),
                changes,
                pending: session.outbox.writes.len(),
                failed: session.outbox.failed.len(),
            });
        }
    }

    async fn command(&mut self, command: Command) {
        match command {
            Command::Unlock {
                account,
                password,
                reply,
            } => self.unlock(account, password, reply).await,
            Command::Adopt {
                state,
                password,
                reply,
            } => self.adopt(*state, password, reply).await,
            Command::Edit { build, reply } => {
                let _ = reply.send(self.edit(build));
            }
            Command::SyncNow => {
                let _ = self.net.send(NetCommand::SyncNow);
            }
            Command::Focus => {
                let _ = self.net.send(NetCommand::Focus);
            }
            Command::Reconnect { password, reply } => {
                if self.session.is_some() {
                    let _ = self.net.send(NetCommand::Reconnect { password, reply });
                } else {
                    let _ = reply.send(Err(VaultError::NotUnlocked));
                }
            }
            Command::KeyChange { change, reply } => self.key_change(change, reply),
            Command::Attachment(command) => {
                if self.session.is_some() {
                    let _ = self.attachments.send(command);
                } else {
                    fail_attachment(command);
                }
            }
            Command::CheckPassword { password, reply } => {
                let Some(session) = &self.session else {
                    let _ = reply.send(false);
                    return;
                };
                let check = session.store.password_check();
                tokio::task::spawn_blocking(move || {
                    let _ = reply.send(check(&password));
                });
            }
            Command::Model { reply } => {
                let _ = reply.send(self.session.as_ref().map(|session| session.model.clone()));
            }
            Command::Lock { reply } => {
                self.lock();
                let _ = reply.send(());
            }
            Command::Shutdown => unreachable!("handled by the run loop"),
        }
    }

    async fn unlock(
        &mut self,
        account: AccountEntry,
        password: Zeroizing<String>,
        reply: oneshot::Sender<Result<AccountEntry, VaultError>>,
    ) {
        if self.session.is_some() {
            let _ = reply.send(Err(VaultError::AlreadyUnlocked));
            return;
        }
        let root = self.config.data_root.clone();
        let entry = account.clone();
        let pass = password.clone();
        // Stretching the password takes a moment: not on the runtime's thread.
        let opened = tokio::task::spawn_blocking(move || {
            let (store, device) = Store::open(&root, &entry, &pass)?;
            let device: LocalState = serde_json::from_slice(&device)
                .map_err(|_| StoreError::Corrupt(DEVICE_RECORD.to_string()))?;
            let vault = read_vault(&store)?;
            let outbox = read_outbox(&store)?;
            Ok::<_, StoreError>((store, device, vault, outbox))
        })
        .await;
        let (store, device, vault, outbox) = match opened {
            Ok(Ok(opened)) => opened,
            Ok(Err(error)) => {
                let _ = reply.send(Err(error.into()));
                return;
            }
            Err(_) => {
                let _ = reply.send(Err(VaultError::Gone));
                return;
            }
        };
        self.begin(
            account,
            store,
            device,
            vault,
            outbox,
            password,
            Some(reply),
            true,
        );
    }

    async fn adopt(
        &mut self,
        state: LocalState,
        password: Zeroizing<String>,
        reply: oneshot::Sender<Result<AccountEntry, VaultError>>,
    ) {
        if self.session.is_some() {
            let _ = reply.send(Err(VaultError::AlreadyUnlocked));
            return;
        }
        let root = self.config.data_root.clone();
        let identity = Identity {
            server: state.server.clone(),
            username: state.username.clone(),
            account_id: state.account_id,
            collection_id: state.collection_id,
            device_id: state.device_id,
        };
        let account = AccountEntry {
            account_id: state.account_id,
            server: state.server.clone(),
            username: state.username.clone(),
        };
        let device_bytes = Zeroizing::new(serde_json::to_vec(&state).expect("state serialises"));
        let pass = password.clone();
        let created = tokio::task::spawn_blocking(move || {
            let store = Store::create(&root, identity, &pass, &device_bytes)?;
            store::remember_account(
                &root,
                AccountEntry {
                    account_id: store.identity().account_id,
                    server: store.identity().server.clone(),
                    username: store.identity().username.clone(),
                },
            )?;
            Ok::<_, StoreError>(store)
        })
        .await;
        let store = match created {
            Ok(Ok(store)) => store,
            Ok(Err(error)) => {
                let _ = reply.send(Err(error.into()));
                return;
            }
            Err(_) => {
                let _ = reply.send(Err(VaultError::Gone));
                return;
            }
        };
        // A new account has nothing to show, but the person just signed in, so
        // the session is already live and there is nothing to wait for.
        let vault = LocalVault {
            version: sealbook_core::LOCAL_VAULT_VERSION,
            ..LocalVault::default()
        };
        self.begin(
            account,
            store,
            state,
            vault,
            Outbox::default(),
            password,
            Some(reply),
            false,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn begin(
        &mut self,
        account: AccountEntry,
        store: Store,
        device: LocalState,
        vault: LocalVault,
        outbox: Outbox,
        password: Zeroizing<String>,
        reply: Option<oneshot::Sender<Result<AccountEntry, VaultError>>>,
        wait_if_empty: bool,
    ) {
        let model = Arc::new(VaultModel::rebuild(&vault, &outbox));
        let empty = vault.objects.is_empty() && outbox.writes.is_empty();
        let mut session = Session {
            account: account.clone(),
            store,
            device: device.clone(),
            vault,
            outbox,
            model,
            blocked: false,
            defaults_checked: false,
            unlock_reply: None,
        };
        match reply {
            Some(reply) if empty && wait_if_empty => {
                session.unlock_reply = Some(reply);
            }
            Some(reply) => {
                let _ = reply.send(Ok(account));
            }
            None => {}
        }
        self.tell_attachments(&session);
        self.session = Some(session);
        self.snapshot(ChangeSet {
            changes: Vec::new(),
            everything: true,
        });
        let _ = self.net.send(NetCommand::Connect {
            state: Box::new(device),
            password,
        });
    }

    fn tell_attachments(&self, session: &Session) {
        let _ = self.attachments.send(AttachmentCommand::Session {
            state: Box::new(session.device.clone()),
            cache: AttachmentCache::new(
                session.store.path().join("attachments"),
                session.store.blob_sealer(),
                DEFAULT_BUDGET,
            ),
            pinned: self.config.pinned_certificate.get(),
        });
    }

    fn close_session(&mut self) {
        let _ = self.attachments.send(AttachmentCommand::End);
        if let Some(mut session) = self.session.take() {
            let _ = save_vault(&session.store, &session.vault);
            let _ = save_outbox(&session.store, &session.outbox);
            if let Some(reply) = session.unlock_reply.take() {
                let _ = reply.send(Err(VaultError::Gone));
            }
        }
    }

    fn lock(&mut self) {
        if self.session.is_none() {
            return;
        }
        self.close_session();
        let _ = self.net.send(NetCommand::Disconnect);
        self.emit(VaultEvent::Locked);
    }

    fn edit(&mut self, build: crate::EditFn) -> Result<ChangeSet, VaultError> {
        let session = self.session.as_mut().ok_or(VaultError::NotUnlocked)?;
        if session.blocked {
            return Err(VaultError::EditsBlocked);
        }
        let now = now_rfc3339();
        let writes = build(&EditContext {
            editor: Editor::new(&session.vault, &now),
            model: &session.model,
            now: &now,
        })?;
        if writes.is_empty() {
            return Ok(ChangeSet::default());
        }
        let ids = push_all(&mut session.outbox, writes);
        save_outbox(&session.store, &session.outbox)?;
        let changes =
            Arc::make_mut(&mut session.model).update(&session.vault, &session.outbox, &ids, false);
        self.snapshot(changes.clone());
        let _ = self.net.send(NetCommand::Edited);
        Ok(changes)
    }

    fn key_change(
        &mut self,
        change: KeyChange,
        reply: oneshot::Sender<Result<KeyChanged, VaultError>>,
    ) {
        if self.session.is_none() {
            let _ = reply.send(Err(VaultError::NotUnlocked));
            return;
        }
        let _ = self.net.send(NetCommand::KeyChange { change, reply });
    }

    async fn report(&mut self, report: NetReport) {
        match report {
            NetReport::Input { reply } => self.answer(reply, ChangeSet::default()),
            NetReport::CaughtUp { read, reply } => self.caught_up(read, reply),
            NetReport::Dropped { drops, reply } => self.dropped(drops, reply),
            NetReport::Sent {
                sent,
                planned,
                reply,
            } => self.sent(sent, planned, reply),
            NetReport::Failed { ids, reason, reply } => {
                if let Some(session) = self.session.as_mut() {
                    session.outbox = outbox_fail(&session.outbox, &ids, &reason);
                    let _ = save_outbox(&session.store, &session.outbox);
                    let changes = Arc::make_mut(&mut session.model).update(
                        &session.vault,
                        &session.outbox,
                        &ids,
                        false,
                    );
                    self.snapshot(changes);
                }
                self.answer(reply, ChangeSet::default());
            }
            NetReport::Device(state) => {
                let saved = self.session.as_mut().map(|session| {
                    let bytes = Zeroizing::new(serde_json::to_vec(&*state).expect("serialises"));
                    let saved = session.store.write(DEVICE_RECORD, &bytes);
                    session.device = *state;
                    saved
                });
                if let Some(session) = self.session.as_ref() {
                    self.tell_attachments(session);
                }
                if let Some(Err(error)) = saved {
                    self.emit(VaultEvent::Notice(format!(
                        "Could not save this device's sign-in: {error}"
                    )));
                }
            }
            NetReport::Status(status) => self.emit(VaultEvent::Sync(status)),
            NetReport::Connected { online } => {
                if let Some(session) = self.session.as_mut() {
                    if let Some(reply) = session.unlock_reply.take() {
                        let _ = reply.send(if online {
                            Ok(session.account.clone())
                        } else {
                            Err(VaultError::OfflineAndEmpty)
                        });
                        if !online {
                            self.lock();
                        }
                    }
                }
            }
            NetReport::SignInNeeded => {
                if let Some(session) = self.session.as_mut() {
                    if let Some(reply) = session.unlock_reply.take() {
                        let _ = reply.send(Err(VaultError::OfflineAndEmpty));
                        self.lock();
                        return;
                    }
                }
                self.emit(VaultEvent::SignInNeeded);
            }
            NetReport::RotationOwed { upgrade } => {
                if let Some(session) = self.session.as_mut() {
                    if let Some(reply) = session.unlock_reply.take() {
                        let _ = reply.send(Ok(session.account.clone()));
                    }
                }
                self.emit(VaultEvent::RotationOwed { upgrade });
            }
            NetReport::Block(on) => {
                if let Some(session) = self.session.as_mut() {
                    session.blocked = on;
                }
            }
            NetReport::Rekey { password, reply } => {
                let result = match self.session.as_mut() {
                    Some(session) => session
                        .store
                        .rekey(&password, &[VAULT_RECORD, OUTBOX_RECORD]),
                    None => Err(StoreError::Corrupt("no open account".into())),
                };
                let _ = reply.send(result);
            }
        }
    }

    fn answer(&self, reply: oneshot::Sender<Input>, changes: ChangeSet) {
        if let Some(session) = &self.session {
            let _ = reply.send(Input {
                vault: session.vault.clone(),
                outbox: session.outbox.clone(),
            });
            if !changes.is_empty() {
                self.snapshot(changes);
            }
        }
        // With no session the reply is dropped, which ends the NetWorker's round.
    }

    fn caught_up(&mut self, read: CatchUp, reply: oneshot::Sender<Input>) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let was_full = read.full;
        let ids: Vec<String> = read.rows.iter().map(|row| row.id.clone()).collect();
        session.vault = read.apply(&session.vault);
        let mut changes = Arc::make_mut(&mut session.model).update(
            &session.vault,
            &session.outbox,
            &ids,
            was_full,
        );
        if read.unreadable > 0 {
            self.emit(VaultEvent::Notice(format!(
                "{} item(s) could not be opened on this device and are not shown.",
                read.unreadable
            )));
        }
        if let Some(session) = self.session.as_mut() {
            if !session.defaults_checked && !session.blocked {
                session.defaults_checked = true;
                let extra = queue_defaults(session, &self.config);
                if let Ok(extra) = extra {
                    merge_changes(&mut changes, extra);
                }
            }
            let _ = save_vault(&session.store, &session.vault);
            let _ = save_outbox(&session.store, &session.outbox);
        }
        self.answer(reply, changes);
    }

    fn dropped(&mut self, drops: Vec<FlushDrop>, reply: oneshot::Sender<Input>) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let ids: Vec<String> = drops.iter().map(|drop| drop.id.clone()).collect();
        session.outbox = outbox_settle(&session.outbox, &ids);
        let _ = save_outbox(&session.store, &session.outbox);
        let changes =
            Arc::make_mut(&mut session.model).update(&session.vault, &session.outbox, &ids, false);
        for notice in drops.into_iter().filter_map(|drop| drop.notice) {
            self.emit(VaultEvent::Notice(notice));
        }
        self.answer(reply, changes);
    }

    fn sent(&mut self, sent: FlushSent, planned: Outbox, reply: oneshot::Sender<Input>) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        session.vault = sent.apply(&session.vault);
        session.outbox =
            outbox_settle_sent(&session.outbox, &planned, &session.vault, &sent.settles);
        let mut ids: Vec<String> = sent.rows.iter().map(|row| row.id.clone()).collect();
        ids.extend(sent.settles.iter().cloned());
        let _ = save_vault(&session.store, &session.vault);
        let _ = save_outbox(&session.store, &session.outbox);
        let changes =
            Arc::make_mut(&mut session.model).update(&session.vault, &session.outbox, &ids, false);
        for notice in sent.notices {
            self.emit(VaultEvent::Notice(notice));
        }
        self.answer(reply, changes);
    }
}

fn fail_attachment(command: AttachmentCommand) {
    match command {
        AttachmentCommand::Fetch { reply, .. } => {
            let _ = reply.send(Err(VaultError::NotUnlocked));
        }
        AttachmentCommand::Upload { reply, .. } => {
            let _ = reply.send(Err(VaultError::NotUnlocked));
        }
        _ => {}
    }
}

fn merge_changes(into: &mut ChangeSet, more: ChangeSet) {
    into.everything |= more.everything;
    into.changes.extend(more.changes);
}

/// Queues what a new account needs: the default containers and this device's
/// label. Written once, after the first read, so a vault another device already
/// set up is not overwritten.
fn queue_defaults(session: &mut Session, config: &VaultConfig) -> Result<ChangeSet, VaultError> {
    use sealbook_core::{
        CoreAddressBookDraft, CoreBookmarkCollectionDraft, CoreCalendarDraft, CoreTaskListDraft,
    };
    let now = now_rfc3339();
    let has = |id: &uuid::Uuid| session.model.get(&id.to_string()).is_some();
    let mut writes = Vec::new();
    {
        let editor = Editor::new(&session.vault, &now);
        if !has(&DEFAULT_ADDRESS_BOOK_ID) {
            writes.push(editor.address_book(
                &DEFAULT_ADDRESS_BOOK_ID.to_string(),
                &CoreAddressBookDraft {
                    name: DEFAULT_ADDRESS_BOOK_NAME.into(),
                    ..Default::default()
                },
            )?);
        }
        if !has(&DEFAULT_CALENDAR_ID) {
            writes.push(editor.calendar(
                &DEFAULT_CALENDAR_ID.to_string(),
                &CoreCalendarDraft {
                    name: DEFAULT_CALENDAR_NAME.into(),
                    color: DEFAULT_CALENDAR_COLOR.into(),
                    ..Default::default()
                },
            )?);
        }
        if !has(&DEFAULT_NOTEBOOK_ID) {
            writes.push(editor.notebook(
                &DEFAULT_NOTEBOOK_ID.to_string(),
                &NotebookEdit::named(DEFAULT_NOTEBOOK_NAME),
            )?);
        }
        if !has(&DEFAULT_TASK_LIST_ID) {
            writes.push(editor.task_list(
                &DEFAULT_TASK_LIST_ID.to_string(),
                &CoreTaskListDraft {
                    name: DEFAULT_TASK_LIST_NAME.into(),
                    ..Default::default()
                },
            )?);
        }
        if !has(&DEFAULT_BOOKMARK_COLLECTION_ID) {
            writes.push(editor.bookmark_collection(
                &DEFAULT_BOOKMARK_COLLECTION_ID.to_string(),
                &CoreBookmarkCollectionDraft {
                    name: DEFAULT_BOOKMARK_COLLECTION_NAME.into(),
                    ..Default::default()
                },
            )?);
        }
        let labels: Vec<CoreDeviceLabelObject> = session
            .model
            .entries()
            .filter(|entry| entry.kind == CorePayloadKind::DeviceLabel)
            .map(|entry| CoreDeviceLabelObject {
                object_id: entry.id.clone(),
                payload: entry.raw.clone(),
            })
            .collect();
        if let Some(label) = device_label_ensure(
            &labels,
            session.device.device_id,
            config.device_kind,
            &config.device_platform,
        )? {
            writes.push(editor.put(&label.object_id, DEVICE_LABEL_CONTENT_TYPE, label.payload));
        }
    }
    if writes.is_empty() {
        return Ok(ChangeSet::default());
    }
    let ids = push_all(&mut session.outbox, writes);
    Ok(Arc::make_mut(&mut session.model).update(&session.vault, &session.outbox, &ids, false))
}

fn push_all(outbox: &mut Outbox, writes: Vec<PendingWrite>) -> Vec<String> {
    let mut ids = Vec::with_capacity(writes.len());
    for write in writes {
        ids.push(write.id.clone());
        *outbox = outbox_push(outbox, write);
    }
    ids
}

fn read_vault(store: &Store) -> Result<LocalVault, StoreError> {
    match store.read(VAULT_RECORD)? {
        Some(bytes) => local_vault_read(&String::from_utf8_lossy(&bytes))
            .map_err(|_| StoreError::Corrupt(VAULT_RECORD.to_string())),
        None => Ok(LocalVault::default()),
    }
}

fn read_outbox(store: &Store) -> Result<Outbox, StoreError> {
    match store.read(OUTBOX_RECORD)? {
        Some(bytes) => outbox_read(&String::from_utf8_lossy(&bytes))
            .map_err(|_| StoreError::Corrupt(OUTBOX_RECORD.to_string())),
        None => Ok(Outbox::default()),
    }
}

fn save_vault(store: &Store, vault: &LocalVault) -> Result<(), StoreError> {
    store.write(VAULT_RECORD, local_vault_write(vault).as_bytes())
}

fn save_outbox(store: &Store, outbox: &Outbox) -> Result<(), StoreError> {
    store.write(OUTBOX_RECORD, outbox_write(outbox).as_bytes())
}
