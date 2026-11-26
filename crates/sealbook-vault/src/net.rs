//! The NetWorker: owns the client and runs rounds against the server.
//!
//! A round brings the device's copy up to date, plans what the outbox owes the
//! server against that copy, sends it in batches and settles what was sent. Every
//! rule it applies is core's; this is the loop around them and the pacing.

use std::collections::HashSet;
use std::sync::Arc;

use sealbook_client::{ClientError, ExportedObject, FlushSend, LocalState, SealbookClient};
use sealbook_core::{
    flush_batch_len, flush_failure, flush_plan, normalize_username, CoreExportAccount,
    FlushFailure, FlushWrite,
};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::state::{Input, Message, NetReport};
use crate::{
    AccountExport, AccountRequest, DeviceRoster, ImportOutcome, KeyChange, KeyChanged, SyncStatus,
    VaultConfig, VaultError,
};

/// Lost races a round tolerates before it gives up until the next trigger, as
/// the web does.
pub(crate) const MAX_LOST_RACES: u32 = 8;

pub(crate) enum NetCommand {
    Connect {
        state: Box<LocalState>,
        password: Zeroizing<String>,
    },
    Edited,
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
    Account(AccountRequest),
    /// The session ended: drop the client and its keys.
    Disconnect,
    Stop,
}

/// How a round ended.
enum End {
    Done,
    /// Try again at the next trigger: the network, the server, a busy collection.
    Retry,
    /// Stop until the session is restarted.
    Halt,
}

pub(crate) struct NetWorker {
    config: Arc<VaultConfig>,
    state: mpsc::UnboundedSender<Message>,
    client: Option<SealbookClient>,
    /// The collection key is held and the session is believed to be live.
    ready: bool,
    halted: bool,
    /// An unfinished rotation: nothing may be written until it is done.
    rotation_owed: bool,
    sign_in_reported: bool,
    last_print: u64,
    pending: usize,
}

impl NetWorker {
    pub(crate) fn new(config: Arc<VaultConfig>, state: mpsc::UnboundedSender<Message>) -> Self {
        Self {
            config,
            state,
            client: None,
            ready: false,
            halted: false,
            rotation_owed: false,
            sign_in_reported: false,
            last_print: 0,
            pending: 0,
        }
    }

    pub(crate) async fn run(mut self, mut commands: mpsc::UnboundedReceiver<NetCommand>) {
        let mut next_round: Option<Instant> = None;
        loop {
            let wait = async {
                match next_round {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                command = commands.recv() => {
                    let Some(command) = command else { return };
                    let now = Instant::now();
                    match command {
                        NetCommand::Stop => return,
                        NetCommand::Disconnect => {
                            self.reset();
                            next_round = None;
                            continue;
                        }
                        NetCommand::Connect { state, password } => {
                            self.connect(*state, password).await;
                            next_round = Some(now);
                        }
                        NetCommand::Edited => {
                            let due = now + self.config.timing.debounce;
                            next_round = Some(next_round.map_or(due, |at| at.min(due)));
                        }
                        NetCommand::SyncNow | NetCommand::Focus => next_round = Some(now),
                        NetCommand::Reconnect { password, reply } => {
                            let result = self.reconnect(password).await;
                            if result.is_ok() {
                                next_round = Some(now);
                            }
                            let _ = reply.send(result);
                        }
                        NetCommand::KeyChange { change, reply } => {
                            let result = self.key_change(change).await;
                            let _ = reply.send(result);
                            next_round = Some(Instant::now());
                        }
                        NetCommand::Account(request) => {
                            self.account(request).await;
                            next_round = self.client.is_some().then(Instant::now);
                        }
                    }
                }
                _ = wait => {
                    self.round().await;
                    let poll = if self.pending > 0 {
                        self.config.timing.pending_poll
                    } else {
                        self.config.timing.idle_poll
                    };
                    next_round = (!self.halted && self.client.is_some()).then(|| Instant::now() + poll);
                }
            }
        }
    }

    fn report(&self, report: NetReport) {
        let _ = self.state.send(Message::Net(report));
    }

    fn status(&self, status: SyncStatus) {
        self.report(NetReport::Status(status));
    }

    fn reset(&mut self) {
        self.client = None;
        self.ready = false;
        self.halted = false;
        self.rotation_owed = false;
        self.sign_in_reported = false;
        self.pending = 0;
    }

    /// Asks the StateActor for something and waits for the copies it answers
    /// with. `None` means the session ended, which ends the round.
    async fn ask(&self, make: impl FnOnce(oneshot::Sender<Input>) -> NetReport) -> Option<Input> {
        let (reply, receiver) = oneshot::channel();
        self.state.send(Message::Net(make(reply))).ok()?;
        receiver.await.ok()
    }

    fn save_device_if_changed(&mut self) {
        let Some(client) = &self.client else { return };
        let Some(state) = &client.state else { return };
        let print = state.fingerprint();
        if print != self.last_print {
            self.last_print = print;
            self.report(NetReport::Device(Box::new(state.clone())));
        }
    }

    async fn connect(&mut self, state: LocalState, password: Zeroizing<String>) {
        self.reset();
        self.last_print = state.fingerprint();
        let mut client =
            match SealbookClient::with_state_and_tls(state, self.config.pinned_certificate.get()) {
                Ok(client) => client,
                Err(error) => {
                    self.status(SyncStatus::Halted(error.to_string()));
                    self.halted = true;
                    self.report(NetReport::Connected { online: false });
                    return;
                }
            };
        self.status(SyncStatus::Syncing);
        let outcome = client.login(&password).await;
        self.client = Some(client);
        self.after_sign_in(outcome, true);
    }

    async fn reconnect(&mut self, password: Zeroizing<String>) -> Result<(), VaultError> {
        let Some(client) = self.client.as_mut() else {
            return Err(VaultError::NotUnlocked);
        };
        let outcome = client.login(&password).await;
        let result = match &outcome {
            Ok(()) => Ok(()),
            Err(ClientError::RecoveryRotationPending | ClientError::UpgradeRotationPending) => {
                Ok(())
            }
            Err(error) => Err(VaultError::Client(clone_error(error))),
        };
        if result.is_ok() {
            self.sign_in_reported = false;
        }
        self.after_sign_in(outcome, false);
        result
    }

    /// Reads what a sign-in attempt means for the session.
    fn after_sign_in(&mut self, outcome: Result<(), ClientError>, first: bool) {
        match outcome {
            Ok(()) => {
                self.ready = true;
                self.save_device_if_changed();
                if first {
                    self.report(NetReport::Connected { online: true });
                }
            }
            Err(
                error
                @ (ClientError::RecoveryRotationPending | ClientError::UpgradeRotationPending),
            ) => {
                let upgrade = matches!(error, ClientError::UpgradeRotationPending);
                self.rotation_owed = true;
                self.ready = false;
                self.report(NetReport::RotationOwed { upgrade });
                if first {
                    self.report(NetReport::Connected { online: true });
                }
            }
            Err(error) if error.http_status() == Some(0) => {
                self.status(SyncStatus::Offline);
                if first {
                    self.report(NetReport::Connected { online: false });
                }
            }
            Err(error) => {
                self.sign_in_failed(&error);
            }
        }
    }

    fn sign_in_failed(&mut self, error: &ClientError) {
        match error {
            ClientError::Manifest(_) | ClientError::ProtocolVersion(_) => {
                self.halted = true;
                self.status(SyncStatus::Halted(error.to_string()));
            }
            _ => {
                self.status(SyncStatus::Offline);
                if !self.sign_in_reported {
                    self.sign_in_reported = true;
                    self.report(NetReport::SignInNeeded);
                }
            }
        }
    }

    /// One round: read, plan, send, settle.
    async fn round(&mut self) {
        if self.halted || self.rotation_owed || self.client.is_none() {
            return;
        }
        self.status(SyncStatus::Syncing);
        let end = self.round_inner().await;
        self.save_device_if_changed();
        match end {
            End::Done if self.pending == 0 => self.status(SyncStatus::Synced),
            End::Done | End::Retry => self.status(SyncStatus::Offline),
            End::Halt => {}
        }
    }

    async fn ensure_key(&mut self) -> Result<(), End> {
        if self.ready {
            return Ok(());
        }
        let Some(client) = self.client.as_mut() else {
            return Err(End::Halt);
        };
        match client.refresh_collection_key().await {
            Ok(_) => {
                self.ready = true;
                Ok(())
            }
            Err(error) => Err(self.classify(&error)),
        }
    }

    /// Sorts a failure by what core says the status means.
    fn classify(&mut self, error: &ClientError) -> End {
        if let Some(status) = error.http_status() {
            return match flush_failure(status) {
                FlushFailure::SignIn => {
                    self.ready = false;
                    self.sign_in_failed(error);
                    End::Retry
                }
                FlushFailure::Retry => End::Retry,
                FlushFailure::Refused => {
                    self.status(SyncStatus::Halted(error.to_string()));
                    self.halted = true;
                    End::Halt
                }
            };
        }
        match error {
            ClientError::CollectionBusy | ClientError::StaleCollectionKey { .. } => End::Retry,
            _ => {
                self.halted = true;
                self.status(SyncStatus::Halted(error.to_string()));
                End::Halt
            }
        }
    }

    async fn round_inner(&mut self) -> End {
        if let Err(end) = self.ensure_key().await {
            return end;
        }
        let mut lost_races = 0;
        'round: loop {
            let Some(input) = self.ask(|reply| NetReport::Input { reply }).await else {
                return End::Halt;
            };
            let after = input.vault.latest_revision;
            let read = {
                let Some(client) = self.client.as_mut() else {
                    return End::Halt;
                };
                match client.catch_up(after).await {
                    Ok(read) => read,
                    Err(error) => return self.classify(&error),
                }
            };
            let Some(input) = self.ask(|reply| NetReport::CaughtUp { read, reply }).await else {
                return End::Halt;
            };
            self.pending = input.outbox.writes.len();
            let mut planned_from = input.outbox.clone();
            let date = jiff::Zoned::now().date().to_string();
            let plan = {
                let Some(key) = self.client.as_ref().and_then(|c| c.collection_key()) else {
                    return End::Halt;
                };
                flush_plan(&input.outbox, &input.vault, &date, key)
            };
            if !plan.dropped.is_empty() {
                let drops = plan.dropped.clone();
                let Some(input) = self.ask(|reply| NetReport::Dropped { drops, reply }).await
                else {
                    return End::Halt;
                };
                planned_from = input.outbox;
            }
            let mut writes: Vec<FlushWrite> = plan.writes;
            while !writes.is_empty() {
                let count = (flush_batch_len(&writes) as usize).clamp(1, writes.len());
                let sent = {
                    let Some(client) = self.client.as_mut() else {
                        return End::Halt;
                    };
                    client.send_flush_batch(&writes[..count], lost_races).await
                };
                match sent {
                    Ok(FlushSend::Moved { .. }) => {
                        lost_races += 1;
                        if lost_races > MAX_LOST_RACES {
                            return End::Retry;
                        }
                        continue 'round;
                    }
                    Ok(FlushSend::Sent(sent)) => {
                        let planned = planned_from.clone();
                        let Some(input) = self
                            .ask(|reply| NetReport::Sent {
                                sent,
                                planned,
                                reply,
                            })
                            .await
                        else {
                            return End::Halt;
                        };
                        self.pending = input.outbox.writes.len();
                        writes.drain(..count);
                    }
                    Err(error) => {
                        let batch: Vec<String> = writes[..count]
                            .iter()
                            .map(|write| write.settles.clone())
                            .collect();
                        return self.send_failed(error, batch).await;
                    }
                }
            }
            return End::Done;
        }
    }

    /// A write request failed: core's table says whether to keep the writes and
    /// try again, sign in again, or move them to the failed list.
    async fn send_failed(&mut self, error: ClientError, settles: Vec<String>) -> End {
        match error.http_status().map(flush_failure) {
            Some(FlushFailure::Refused) => {
                let reason = error.to_string();
                let mut ids = settles;
                ids.sort();
                ids.dedup();
                let _ = self
                    .ask(|reply| NetReport::Failed { ids, reason, reply })
                    .await;
                // The rest of the outbox is unaffected; carry on at the next trigger.
                End::Retry
            }
            _ => self.classify(&error),
        }
    }

    /// A rotate, revoke or phrase change: send what is waiting first, hold edits
    /// back while it runs, and read the whole vault again after.
    async fn key_change(&mut self, change: KeyChange) -> Result<KeyChanged, VaultError> {
        if self.client.is_none() {
            return Err(VaultError::NotUnlocked);
        }
        self.report(NetReport::Block(true));
        let outcome = self.key_change_blocked(change).await;
        self.report(NetReport::Block(false));
        outcome
    }

    async fn account(&mut self, request: AccountRequest) {
        if self.client.is_none() {
            return request.fail(VaultError::NotUnlocked);
        }
        match request {
            AccountRequest::Devices { reply } => {
                let _ = reply.send(self.devices().await);
            }
            AccountRequest::Export { reply } => {
                self.report(NetReport::Block(true));
                let result = self.export().await;
                self.report(NetReport::Block(false));
                let _ = reply.send(result);
            }
            AccountRequest::Import {
                objects,
                overwrite,
                reply,
            } => {
                self.report(NetReport::Block(true));
                let result = self.import(objects, overwrite).await;
                self.report(NetReport::Block(false));
                let _ = reply.send(result);
            }
            AccountRequest::Delete { password, reply } => {
                let result = self.delete(password).await;
                let _ = reply.send(result);
            }
        }
    }

    async fn devices(&mut self) -> Result<DeviceRoster, VaultError> {
        let client = self.client.as_mut().ok_or(VaultError::NotUnlocked)?;
        let devices = client.list_devices().await?;
        let current = client.core_state()?.device_id;
        self.save_device_if_changed();
        Ok(DeviceRoster {
            current,
            devices: devices.into_iter().map(|device| device.device_id).collect(),
        })
    }

    /// Sends what is waiting, so what follows sees every edit made here.
    async fn flush(&mut self) -> Result<(), VaultError> {
        if !matches!(self.round_inner().await, End::Done) || self.pending > 0 {
            return Err(VaultError::NotSynced);
        }
        Ok(())
    }

    async fn read_everything(&mut self) -> Result<(), VaultError> {
        let client = self.client.as_mut().ok_or(VaultError::NotUnlocked)?;
        let read = client.catch_up(0).await?;
        let _ = self
            .ask(|reply| NetReport::CaughtUp { read, reply })
            .await
            .ok_or(VaultError::Gone)?;
        Ok(())
    }

    async fn export(&mut self) -> Result<AccountExport, VaultError> {
        self.flush().await?;
        let client = self.client.as_mut().ok_or(VaultError::NotUnlocked)?;
        let vault = client.export_objects().await?;
        let state = client.state.as_ref().ok_or(VaultError::NotUnlocked)?;
        let account = CoreExportAccount {
            server: state.server.clone(),
            username: state.username.clone(),
            account_id: state.account_id.to_string(),
            collection_id: state.collection_id.to_string(),
            device_id: state.device_id.to_string(),
        };
        Ok(AccountExport { account, vault })
    }

    async fn import(
        &mut self,
        mut objects: Vec<ExportedObject>,
        overwrite: bool,
    ) -> Result<ImportOutcome, VaultError> {
        self.flush().await?;
        let total = objects.len();
        let client = self.client.as_mut().ok_or(VaultError::NotUnlocked)?;
        if !overwrite {
            let present: HashSet<Uuid> = client
                .export_objects()
                .await?
                .objects
                .into_iter()
                .map(|object| object.id)
                .collect();
            objects.retain(|object| !present.contains(&object.id));
        }
        let written = client.import_objects(&objects).await;
        // A failed import may have written earlier batches, so read either way.
        let read = self.read_everything().await;
        written?;
        read?;
        self.save_device_if_changed();
        Ok(ImportOutcome {
            imported: objects.len(),
            skipped: total - objects.len(),
        })
    }

    async fn delete(&mut self, password: Zeroizing<String>) -> Result<(), VaultError> {
        let client = self.client.as_mut().ok_or(VaultError::NotUnlocked)?;
        client.login(&password).await?;
        client.delete_account().await?;
        // Nothing is left to sync with, and a round would only ask to sign in.
        self.reset();
        Ok(())
    }

    async fn key_change_blocked(&mut self, change: KeyChange) -> Result<KeyChanged, VaultError> {
        self.flush().await?;
        self.ready = false;
        let client = self.client.as_mut().ok_or(VaultError::NotUnlocked)?;
        let mut done = KeyChanged::default();
        let mut new_password = None;
        let mut new_username = None;
        // A rename the server accepted before something failed still has to be
        // saved here, so its error waits until after that.
        let mut failed = None;
        match change {
            KeyChange::Rotate { mut revoke } => {
                revoke.sort_unstable();
                revoke.dedup();
                done.recovery_phrase = Some(client.rotate(&revoke).await?);
            }
            KeyChange::ChangePhrase => {
                done.recovery_phrase = Some(client.change_phrase().await?);
            }
            KeyChange::ChangePassword { current, new } => {
                let current = Zeroizing::new(current);
                let new = Zeroizing::new(new);
                client.change_password(&current, &new).await?;
                new_password = Some(new);
            }
            KeyChange::ChangeUsername { new, password } => {
                let password = Zeroizing::new(password);
                let wanted = normalize_username(&new);
                let result = client.change_username(&new, &password).await;
                if client.core_state()?.username == wanted {
                    new_username = Some(wanted);
                    new_password = Some(password);
                    failed = result.err();
                } else {
                    result?;
                }
            }
        }
        self.ready = true;
        self.save_device_if_changed();
        if let Some(password) = new_password {
            let (reply, receiver) = oneshot::channel();
            self.report(NetReport::Rekey {
                password,
                username: new_username,
                reply,
            });
            match receiver.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => return Err(VaultError::Gone),
            }
        }
        if let Some(error) = failed {
            self.ready = false;
            return Err(error.into());
        }
        // The vault's key (and, after a rotation, every row) changed: read it all.
        self.read_everything().await?;
        Ok(done)
    }
}

/// The parts of an error a reply carries across threads. `ClientError` is not
/// `Clone` (it wraps `reqwest::Error`), so a copy keeps its message and status.
fn clone_error(error: &ClientError) -> ClientError {
    match error.http_status() {
        Some(status) if status != 0 => ClientError::Status {
            status,
            message: error.to_string(),
        },
        _ => ClientError::Server(error.to_string()),
    }
}
