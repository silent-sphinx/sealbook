//! The vault against a real in-process server: every scenario drives a
//! `VaultHandle` the way the desktop does and watches its events.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sealbook_client::{LocalState, PairJoinPoll, SealbookClient};
use sealbook_core::{
    trash_restore_write, CoreContactDraft, CoreContactProfile, CoreDeviceKind, CoreNoteDraft,
    CorePayloadKind, CoreProfilePerson, CoreTaskDraft, CoreTaskListDraft,
};
use sealbook_protocol::DEFAULT_NOTEBOOK_ID;
use sealbook_vault::edits::new_id;
use sealbook_vault::trash;
use sealbook_vault::{
    AccountEntry, SyncStatus, Timing, VaultConfig, VaultError, VaultEvent, VaultHandle, VaultModel,
};
use tempfile::TempDir;
use uuid::Uuid;

const PASSWORD: &str = "correct horse battery";

struct Server {
    base: String,
    db: PathBuf,
    addr: SocketAddr,
    task: Option<tokio::task::JoinHandle<()>>,
    _dir: TempDir,
}

impl Server {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("sealbook.db");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut server = Self {
            base: format!("http://{addr}"),
            db,
            addr,
            task: None,
            _dir: dir,
        };
        server.serve(listener).await;
        server
    }

    async fn serve(&mut self, listener: tokio::net::TcpListener) {
        let app = sealbook_server::app(self.db.to_str().unwrap())
            .await
            .unwrap();
        self.task = Some(tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        }));
    }

    fn stop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }

    async fn restart(&mut self) {
        self.stop();
        let mut bound = None;
        for _ in 0..50 {
            match tokio::net::TcpListener::bind(self.addr).await {
                Ok(listener) => {
                    bound = Some(listener);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
        self.serve(bound.expect("the port frees up")).await;
    }
}

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<VaultEvent>>>);

impl Events {
    fn sink(&self) -> sealbook_vault::EventSink {
        let events = self.0.clone();
        Arc::new(move |event| events.lock().unwrap().push(event))
    }

    fn any(&self, matches: impl Fn(&VaultEvent) -> bool) -> bool {
        self.0.lock().unwrap().iter().any(matches)
    }

    fn latest_snapshot(&self) -> Option<(Arc<VaultModel>, usize, usize)> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find_map(|event| match event {
                VaultEvent::Snapshot {
                    model,
                    pending,
                    failed,
                    ..
                } => Some((model.clone(), *pending, *failed)),
                _ => None,
            })
    }
}

async fn eventually(what: &str, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

fn quick() -> Timing {
    Timing {
        debounce: Duration::from_millis(50),
        pending_poll: Duration::from_millis(400),
        idle_poll: Duration::from_millis(400),
    }
}

struct Device {
    handle: VaultHandle,
    events: Events,
    root: TempDir,
    account: AccountEntry,
}

fn spawn_vault(root: &Path, events: &Events) -> VaultHandle {
    spawn_timed_vault(root, events, quick())
}

fn spawn_timed_vault(root: &Path, events: &Events, timing: Timing) -> VaultHandle {
    VaultHandle::spawn(
        VaultConfig {
            data_root: root.to_path_buf(),
            pinned_certificate: sealbook_vault::ServerTrust::default(),
            device_kind: CoreDeviceKind::Unknown,
            device_platform: "test".into(),
            timing,
        },
        events.sink(),
    )
}

impl Device {
    async fn adopt(state: LocalState) -> Self {
        Self::adopt_timed(state, quick()).await
    }

    async fn adopt_timed(state: LocalState, timing: Timing) -> Self {
        let root = tempfile::tempdir().unwrap();
        let events = Events::default();
        let handle = spawn_timed_vault(root.path(), &events, timing);
        let account = handle
            .adopt(state, PASSWORD.into())
            .await
            .unwrap()
            .expect("adopt");
        Self {
            handle,
            events,
            root,
            account,
        }
    }

    async fn model(&self) -> Arc<VaultModel> {
        self.handle.model().await.unwrap().expect("unlocked")
    }

    async fn settled(&self) {
        let events = self.events.clone();
        eventually("the outbox to empty and a sync to finish", || {
            events
                .latest_snapshot()
                .is_some_and(|(_, pending, _)| pending == 0)
                && events.any(|event| matches!(event, VaultEvent::Sync(SyncStatus::Synced)))
        })
        .await;
    }
}

async fn register(server: &Server, name: &str) -> (SealbookClient, LocalState) {
    let mut client = SealbookClient::plaintext_http();
    client.register(&server.base, name, PASSWORD).await.unwrap();
    let state = client.state.clone().unwrap();
    (client, state)
}

/// Pairs a second device into the account `owner` holds.
async fn pair(server: &Server, owner: &mut SealbookClient, name: &str) -> SealbookClient {
    let mut joiner = SealbookClient::plaintext_http();
    let pairing = joiner.pair_join(&server.base, name).await.unwrap();
    let response = owner.pair_respond(&pairing.code).await.unwrap();
    assert_eq!(
        joiner
            .pair_join_step(&pairing, "test device")
            .await
            .unwrap(),
        PairJoinPoll::Confirm
    );
    let preview = owner.pair_preview_step(&response).await.unwrap().unwrap();
    owner.pair_approve(&response, &preview).await.unwrap();
    assert_eq!(
        joiner
            .pair_join_step(&pairing, "test device")
            .await
            .unwrap(),
        PairJoinPoll::Ready
    );
    joiner.login(PASSWORD).await.unwrap();
    joiner
}

fn contact(name: &str) -> CoreContactDraft {
    CoreContactDraft {
        name: name.into(),
        ..CoreContactDraft::default()
    }
}

fn note(title: &str, body: &str) -> CoreNoteDraft {
    CoreNoteDraft {
        title: title.into(),
        body: body.into(),
        notebook_id: DEFAULT_NOTEBOOK_ID.to_string(),
        ..CoreNoteDraft::default()
    }
}

fn names(model: &VaultModel) -> Vec<String> {
    let mut names: Vec<String> = model.contacts().map(|c| c.name.clone()).collect();
    names.sort();
    names
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_account_gets_its_default_containers_and_an_edit_reaches_the_server() {
    let server = Server::start().await;
    let (mut other, state) = register(&server, "alice").await;
    let device = Device::adopt(state).await;

    let id = new_id();
    let edit_id = id.clone();
    device
        .handle
        .edit(move |cx| {
            Ok(vec![cx
                .editor
                .contact(&edit_id, &contact("Ada Lovelace"))?])
        })
        .await
        .unwrap()
        .expect("edit");
    // The edit shows before the server has heard of it.
    assert_eq!(names(&*device.model().await), vec!["Ada Lovelace"]);
    device.settled().await;

    let model = device.model().await;
    assert!(model.address_books().count() >= 1, "default address book");
    assert!(model.calendars().count() >= 1, "default calendar");
    assert!(model.notebooks().count() >= 1, "default notebook");
    assert!(model.task_lists().count() >= 1, "default task list");
    assert!(model.device_labels().count() >= 1, "this device's label");

    let stored = other.list_contacts().await.unwrap();
    assert_eq!(stored.len(), 1);
    assert!(stored[0].1.contains("Ada Lovelace"));
}

#[tokio::test(flavor = "multi_thread")]
async fn saved_data_shows_after_a_restart_and_a_wrong_password_is_refused() {
    let server = Server::start().await;
    let (_other, state) = register(&server, "bob").await;
    let first = Device::adopt(state).await;
    let id = new_id();
    first
        .handle
        .edit(move |cx| Ok(vec![cx.editor.contact(&id, &contact("Grace Hopper"))?]))
        .await
        .unwrap()
        .unwrap();
    first.settled().await;
    assert!(!first.handle.check_password("wrong".into()).await.unwrap());
    assert!(first.handle.check_password(PASSWORD.into()).await.unwrap());
    let (root, account) = (first.root, first.account.clone());
    first.handle.shutdown();

    let events = Events::default();
    let second = spawn_vault(root.path(), &events);
    let wrong = second
        .unlock(account.clone(), "not the password".into())
        .await
        .unwrap();
    assert!(matches!(
        wrong,
        Err(VaultError::Store(sealbook_vault::StoreError::WrongPassword))
    ));
    second
        .unlock(account, PASSWORD.into())
        .await
        .unwrap()
        .expect("unlock");
    let model = second.model().await.unwrap().unwrap();
    assert_eq!(names(&model), vec!["Grace Hopper"]);
    second.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn edits_made_while_offline_are_kept_and_flush_when_the_server_is_back() {
    let mut server = Server::start().await;
    let (mut other, state) = register(&server, "carol").await;
    let first = Device::adopt(state).await;
    first.settled().await;
    let (root, account) = (first.root, first.account.clone());
    first.handle.shutdown();

    server.stop();
    let events = Events::default();
    let offline = spawn_vault(root.path(), &events);
    offline
        .unlock(account, PASSWORD.into())
        .await
        .unwrap()
        .expect("an offline unlock works once something is saved");
    let id = new_id();
    offline
        .edit(move |cx| Ok(vec![cx.editor.contact(&id, &contact("Written offline"))?]))
        .await
        .unwrap()
        .unwrap();
    eventually("the offline status", || {
        events.any(|event| matches!(event, VaultEvent::Sync(SyncStatus::Offline)))
    })
    .await;
    let (model, pending, _) = events.latest_snapshot().unwrap();
    assert_eq!(names(&model), vec!["Written offline"]);
    assert!(pending >= 1);

    server.restart().await;
    eventually("the queued edit to reach the server", || {
        events
            .latest_snapshot()
            .is_some_and(|(_, pending, _)| pending == 0)
    })
    .await;
    assert_eq!(other.list_contacts().await.unwrap().len(), 1);
    offline.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn an_offline_unlock_is_refused_when_nothing_is_saved() {
    let mut server = Server::start().await;
    let (_other, state) = register(&server, "dave").await;
    let account = AccountEntry {
        account_id: state.account_id,
        server: state.server.clone(),
        username: state.username.clone(),
    };
    // A saved account whose vault and outbox are both empty: made, never synced.
    let root = tempfile::tempdir().unwrap();
    {
        let identity = sealbook_vault::store::Identity {
            server: state.server.clone(),
            username: state.username.clone(),
            account_id: state.account_id,
            collection_id: state.collection_id,
            device_id: state.device_id,
        };
        let store = sealbook_vault::store::Store::create(
            root.path(),
            identity,
            PASSWORD,
            &serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        drop(store);
    }
    server.stop();
    let events = Events::default();
    let vault = spawn_vault(root.path(), &events);
    let result = vault.unlock(account, PASSWORD.into()).await.unwrap();
    assert!(
        matches!(result, Err(VaultError::OfflineAndEmpty)),
        "{result:?}"
    );
    vault.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_edits_from_two_devices_merge_or_keep_a_conflicted_copy() {
    let server = Server::start().await;
    let (mut owner, state) = register(&server, "erin").await;
    let joiner = pair(&server, &mut owner, "erin").await;
    let a = Device::adopt(state).await;
    let b = Device::adopt(joiner.state.clone().unwrap()).await;

    let id = new_id();
    let create_id = id.clone();
    a.handle
        .edit(move |cx| {
            Ok(vec![cx.editor.note(
                &create_id,
                &note("Plan", "line one\nline two\nline three"),
            )?])
        })
        .await
        .unwrap()
        .unwrap();
    a.settled().await;
    let wanted = id.clone();
    let b_model = b.handle.clone();
    eventually("device B to receive the note", || {
        let events = b.events.clone();
        let _ = &b_model;
        events
            .latest_snapshot()
            .is_some_and(|(model, _, _)| model.get(&wanted).is_some())
    })
    .await;

    // Both edit the same line while neither has seen the other's change.
    for (device, body) in [
        (&a, "line one\nA's line two\nline three"),
        (&b, "line one\nB's line two\nline three"),
    ] {
        let id = id.clone();
        let body = body.to_string();
        device
            .handle
            .edit(move |cx| Ok(vec![cx.editor.note(&id, &note("Plan", &body))?]))
            .await
            .unwrap()
            .unwrap();
    }
    eventually("a conflicted copy to appear on both devices", || {
        [&a, &b].iter().all(|device| {
            device
                .events
                .latest_snapshot()
                .is_some_and(|(model, pending, _)| pending == 0 && model.notes().count() == 2)
        })
    })
    .await;
    let bodies: Vec<String> = a.model().await.notes().map(|n| n.body.clone()).collect();
    assert!(bodies.iter().any(|body| body.contains("A's line two")));
    assert!(bodies.iter().any(|body| body.contains("B's line two")));
    assert!(
        a.events.any(|e| matches!(e, VaultEvent::Notice(_)))
            || b.events.any(|e| matches!(e, VaultEvent::Notice(_)))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rotation_by_another_device_is_picked_up() {
    let server = Server::start().await;
    let (mut owner, state) = register(&server, "frank").await;
    let a = Device::adopt(state.clone()).await;
    a.settled().await;

    // The "other device" here is a plain client on the same account, rotating the key.
    let mut other = pair(&server, &mut owner, "frank").await;
    other.rotate(&[]).await.unwrap();
    let id = Uuid::new_v4();
    other
        .put_contact(
            id,
            r#"{"@type":"Card","version":"1.0","name":{"full":"After rotation"}}"#,
        )
        .await
        .unwrap();

    a.handle.sync_now();
    eventually("the contact written under the new key", || {
        a.events
            .latest_snapshot()
            .is_some_and(|(model, _, _)| names(&model) == vec!["After rotation"])
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_revoked_elsewhere_is_signed_out() {
    let server = Server::start().await;
    let (mut owner, _state) = register(&server, "gina").await;
    let joiner = pair(&server, &mut owner, "gina").await;
    let revoked_state = joiner.state.clone().unwrap();
    let device_id = revoked_state.device_id;
    let device = Device::adopt(revoked_state).await;
    device.settled().await;

    owner.revoke_device(device_id).await.unwrap();
    device.handle.sync_now();
    eventually("a sign-in request", || {
        device.events.any(|e| matches!(e, VaultEvent::SignInNeeded))
    })
    .await;
    let outcome = device.handle.reconnect(PASSWORD.into()).await.unwrap();
    assert!(outcome.is_err(), "a revoked device cannot sign back in");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_write_the_server_refuses_goes_to_the_failed_list() {
    let server = Server::start().await;
    let (_owner, state) = register(&server, "hank").await;
    let device = Device::adopt(state).await;
    device.settled().await;

    let id = new_id();
    let huge = "x".repeat(9 * 1024 * 1024);
    device
        .handle
        .edit(move |cx| Ok(vec![cx.editor.note(&id, &note("Too big", &huge))?]))
        .await
        .unwrap()
        .unwrap();
    eventually("the oversized note to be set aside", || {
        device
            .events
            .latest_snapshot()
            .is_some_and(|(_, pending, failed)| pending == 0 && failed == 1)
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tampered_row_halts_sync_with_a_manifest_error() {
    let server = Server::start().await;
    let (mut owner, _state) = register(&server, "iris").await;
    let joiner = pair(&server, &mut owner, "iris").await;
    let device = Device::adopt(joiner.state.clone().unwrap()).await;
    device.settled().await;

    let edited = Uuid::new_v4();
    owner
        .put_contact(
            edited,
            r#"{"@type":"Card","version":"1.0","name":{"full":"One"}}"#,
        )
        .await
        .unwrap();
    owner
        .put_contact(
            edited,
            r#"{"@type":"Card","version":"1.0","name":{"full":"Two"}}"#,
        )
        .await
        .unwrap();
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", server.db.display()))
        .await
        .unwrap();
    sqlx::query(
        "UPDATE object_revisions SET ciphertext = (SELECT ciphertext FROM object_revisions o
             WHERE o.object_id = object_revisions.object_id ORDER BY o.revision LIMIT 1),
         nonce = (SELECT nonce FROM object_revisions o
             WHERE o.object_id = object_revisions.object_id ORDER BY o.revision LIMIT 1)
         WHERE object_id = ?1 AND revision =
             (SELECT MAX(revision) FROM object_revisions WHERE object_id = ?1)",
    )
    .bind(edited.to_string())
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;

    device.handle.sync_now();
    eventually("sync to halt", || {
        device
            .events
            .any(|e| matches!(e, VaultEvent::Sync(SyncStatus::Halted(_))))
    })
    .await;
    assert!(device.model().await.contacts().all(|c| c.name != "Two"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_window_cannot_open_an_account_that_is_open() {
    let server = Server::start().await;
    let (_owner, state) = register(&server, "june").await;
    let device = Device::adopt(state).await;
    let events = Events::default();
    let second = spawn_vault(device.root.path(), &events);
    let result = second
        .unlock(device.account.clone(), PASSWORD.into())
        .await
        .unwrap();
    assert!(matches!(
        result,
        Err(VaultError::Store(sealbook_vault::StoreError::Locked))
    ));
    second.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_change_of_password_reseals_the_saved_data() {
    let server = Server::start().await;
    let (_owner, state) = register(&server, "kim").await;
    let device = Device::adopt(state).await;
    let id = new_id();
    device
        .handle
        .edit(move |cx| Ok(vec![cx.editor.contact(&id, &contact("Before"))?]))
        .await
        .unwrap()
        .unwrap();
    device.settled().await;
    device
        .handle
        .key_change(sealbook_vault::KeyChange::ChangePassword {
            current: PASSWORD.into(),
            new: "a different phrase entirely".into(),
        })
        .await
        .unwrap()
        .expect("change password");
    let (root, account) = (device.root, device.account.clone());
    device.handle.shutdown();

    let events = Events::default();
    let reopened = spawn_vault(root.path(), &events);
    assert!(reopened
        .unlock(account.clone(), PASSWORD.into())
        .await
        .unwrap()
        .is_err());
    reopened
        .unlock(account, "a different phrase entirely".into())
        .await
        .unwrap()
        .expect("the new password opens it");
    assert_eq!(
        names(&reopened.model().await.unwrap().unwrap()),
        vec!["Before"]
    );
    reopened.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_change_of_username_reseals_the_saved_data() {
    let server = Server::start().await;
    let (_owner, state) = register(&server, "mona").await;
    let device = Device::adopt(state).await;
    device.settled().await;
    device
        .handle
        .key_change(sealbook_vault::KeyChange::ChangeUsername {
            new: "monica".into(),
            password: PASSWORD.into(),
        })
        .await
        .unwrap()
        .expect("change username");
    let root = device.root;
    device.handle.shutdown();

    let accounts = sealbook_vault::store::read_accounts(root.path());
    assert_eq!(accounts[0].username, "monica");
    let events = Events::default();
    let reopened = spawn_vault(root.path(), &events);
    reopened
        .unlock(accounts[0].clone(), PASSWORD.into())
        .await
        .unwrap()
        .expect("opens under the new name");
    eventually("the new name to sign in and sync", || {
        events.any(|event| matches!(event, VaultEvent::Sync(SyncStatus::Synced)))
    })
    .await;
    reopened.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn an_account_lists_devices_exports_imports_and_is_deleted() {
    let server = Server::start().await;
    let (_owner, state) = register(&server, "nia").await;
    let this_device = state.device_id;
    let device = Device::adopt(state).await;
    let id = new_id();
    device
        .handle
        .edit(move |cx| Ok(vec![cx.editor.contact(&id, &contact("Kept"))?]))
        .await
        .unwrap()
        .unwrap();

    let roster = device.handle.devices().await.unwrap().expect("devices");
    assert_eq!(roster.current, this_device);
    assert!(roster.devices.contains(&this_device));

    // The export sends the waiting edit first, so it is in the file.
    let exported = device
        .handle
        .export_account()
        .await
        .unwrap()
        .expect("export");
    assert_eq!(exported.account.username, "nia");
    let exported = exported.vault;
    assert!(exported
        .objects
        .iter()
        .any(|object| object.payload.contains("Kept")));

    let again = device
        .handle
        .import_account(exported.objects.clone(), false)
        .await
        .unwrap()
        .expect("import");
    assert_eq!(again.imported, 0);
    assert_eq!(again.skipped, exported.objects.len());
    let replaced = device
        .handle
        .import_account(exported.objects.clone(), true)
        .await
        .unwrap()
        .expect("import over");
    assert_eq!(replaced.imported, exported.objects.len());
    let model = device.model().await;
    assert_eq!(names(&model), vec!["Kept"]);

    assert!(device
        .handle
        .delete_account("not the password".into())
        .await
        .unwrap()
        .is_err());
    device
        .handle
        .delete_account(PASSWORD.into())
        .await
        .unwrap()
        .expect("delete");
    device.handle.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn an_uploaded_attachment_downloads_from_the_cache_and_from_the_server() {
    let server = Server::start().await;
    let (_owner, state) = register(&server, "lena").await;
    let device = Device::adopt(state).await;
    device.settled().await;

    let data: Vec<u8> = (0..200_000u32).map(|n| (n % 251) as u8).collect();
    let reference = device
        .handle
        .upload_attachment(data.clone())
        .await
        .unwrap()
        .expect("upload");
    assert_eq!(
        device
            .handle
            .attachment(reference.clone())
            .await
            .unwrap()
            .unwrap(),
        data,
        "served from the cache the upload filled"
    );

    // Empty the cache: the next read goes to the server and is checked against the hash.
    let cache_dir =
        sealbook_vault::store::Store::account_dir(device.root.path(), device.account.account_id)
            .join("attachments");
    std::fs::remove_dir_all(&cache_dir).unwrap();
    assert_eq!(
        device.handle.attachment(reference).await.unwrap().unwrap(),
        data
    );
    assert!(cache_dir.exists(), "and the download is cached again");
}

/// A stamp far past the retention period.
const LONG_AGO: &str = "2020-01-01T00:00:00Z";

/// Adds a card and puts it in the trash, stamped `LONG_AGO`.
async fn add_expired_contact(device: &Device, name: &'static str) -> String {
    let id = new_id();
    let add = id.clone();
    device
        .handle
        .edit(move |cx| Ok(vec![cx.editor.contact(&add, &contact(name))?]))
        .await
        .unwrap()
        .unwrap();
    device.settled().await;
    let bin = id.clone();
    device
        .handle
        .edit(move |cx| {
            Ok(trash::trash(&cx.editor, cx.model, &bin, LONG_AGO)?
                .into_iter()
                .collect())
        })
        .await
        .unwrap()
        .unwrap();
    device.settled().await;
    id
}

#[tokio::test(flavor = "multi_thread")]
async fn the_sweep_deletes_what_has_expired_and_unlinks_deleted_contacts() {
    let server = Server::start().await;
    let (mut other, state) = register(&server, "sweeper").await;
    let device = Device::adopt(state).await;
    device.settled().await;

    let gone = add_expired_contact(&device, "Gone").await;
    let (list, task, friend, recent) = (new_id(), new_id(), new_id(), new_id());
    {
        let (list, task, friend, recent, gone) = (
            list.clone(),
            task.clone(),
            friend.clone(),
            recent.clone(),
            gone.clone(),
        );
        device
            .handle
            .edit(move |cx| {
                let mut linked = contact("Friend");
                linked.profile = Some(CoreContactProfile {
                    family: vec![CoreProfilePerson {
                        name: "Gone".into(),
                        contact_id: Some(gone),
                        ..Default::default()
                    }],
                    ..Default::default()
                });
                Ok(vec![
                    cx.editor.task_list(
                        &list,
                        &CoreTaskListDraft {
                            name: "Old".into(),
                            ..Default::default()
                        },
                    )?,
                    cx.editor.task(
                        &task,
                        &CoreTaskDraft {
                            title: "Inside".into(),
                            task_list_id: list.clone(),
                            ..Default::default()
                        },
                    )?,
                    cx.editor.contact(&friend, &linked)?,
                    cx.editor.contact(&recent, &contact("Recent"))?,
                ])
            })
            .await
            .unwrap()
            .unwrap();
    }
    device.settled().await;
    {
        let (list, recent) = (list.clone(), recent.clone());
        device
            .handle
            .edit(move |cx| {
                let mut writes = Vec::new();
                writes.extend(trash::trash(&cx.editor, cx.model, &list, LONG_AGO)?);
                writes.extend(trash::trash(&cx.editor, cx.model, &recent, cx.now)?);
                Ok(writes)
            })
            .await
            .unwrap()
            .unwrap();
    }
    device.settled().await;

    // The list, the task inside it and the one card.
    assert_eq!(device.handle.sweep_trash().await.unwrap().unwrap(), 3);
    device.settled().await;

    let model = device.model().await;
    for id in [&gone, &list, &task] {
        assert!(model.get(id).is_none(), "{id} should be deleted");
    }
    assert!(model.get(&recent).is_some(), "not yet expired");
    let card = model.contacts().find(|c| c.id == friend).unwrap();
    assert!(card.profile.iter().all(|profile| profile.family.is_empty()));

    let stored: Vec<String> = other
        .export_objects()
        .await
        .unwrap()
        .objects
        .into_iter()
        .map(|object| object.id.to_string())
        .collect();
    for id in [&gone, &list, &task] {
        assert!(!stored.contains(id), "{id} should be gone from the server");
    }
    assert!(stored.contains(&recent));
    assert_eq!(device.handle.sweep_trash().await.unwrap().unwrap(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_sweep_keeps_an_item_restored_elsewhere_since_the_last_sync() {
    let server = Server::start().await;
    let (mut other, state) = register(&server, "stale").await;
    // No idle polling, so this device's copy stays behind the server's.
    let timing = Timing {
        idle_poll: Duration::from_secs(3600),
        ..quick()
    };
    let device = Device::adopt_timed(state, timing).await;
    device.settled().await;
    let id = add_expired_contact(&device, "Back again").await;

    let mut object = other
        .export_objects()
        .await
        .unwrap()
        .objects
        .into_iter()
        .find(|object| object.id.to_string() == id)
        .unwrap();
    object.payload = trash_restore_write(CorePayloadKind::Contact, &object.payload, None).unwrap();
    other.import_objects(&[object]).await.unwrap();
    assert!(trash::hidden(&*device.model().await).contains(&id));

    assert_eq!(device.handle.sweep_trash().await.unwrap().unwrap(), 0);
    let model = device.model().await;
    assert!(model.get(&id).is_some());
    assert!(!trash::hidden(&model).contains(&id));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_sweep_deletes_nothing_offline() {
    let mut server = Server::start().await;
    let (_, state) = register(&server, "offline-sweep").await;
    let device = Device::adopt(state).await;
    device.settled().await;
    let id = add_expired_contact(&device, "Waiting").await;

    server.stop();
    assert!(device.handle.sweep_trash().await.unwrap().is_err());
    assert!(device.model().await.get(&id).is_some());
}
