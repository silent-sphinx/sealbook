use std::net::SocketAddr;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore};
use sealbook_client::SealbookClient;
use sealbook_crypto::opaque::{
    client_login_start, client_register_finish, client_register_start, SealbookCipherSuite,
};
use sealbook_crypto::{
    decrypt_object, enrollment_transcript, entropy_from_phrase, generate_device_hpke,
    generate_device_signing, login_start_transcript, object_aad, open_login_challenge,
    phrase_lookup_id, phrase_recovery_transcript, sign, sign_phrase_recovery, wrap_for_device,
    CollectionKey, DeviceHpkeSecret, DeviceHpkeWrap, DeviceSigningSecrets, EncryptedObject,
    PAIR_CONFIRMATION_LEN, PHRASE_SCHEME, XWING_CIPHERSUITE,
};
use sealbook_protocol::{
    DualSignatureBody, KeyWrapBody, LoginChallengeRequest, LoginChallengeResponse,
    LoginStartRequest, RecoverFinishRequest, RecoverStartRequest, RecoverStartResponse,
    SEALED_CONTENT_TYPE,
};
use sqlx::Row;
use uuid::Uuid;

/// The replacement-password material a recovery carries, and the payload digest
/// the phrase proof must cover.
struct RecoveryPassword {
    upload: Vec<u8>,
    kdf_salt: Vec<u8>,
    nonce: Vec<u8>,
    wrapped_ck: Vec<u8>,
    ciphersuite: String,
    payload: [u8; 32],
}

/// Finishes the OPAQUE registration a `recover/start` began and re-wraps the
/// collection key under the new password, as a recovering client would.
fn recovery_password(
    password: &str,
    opaque_response: &[u8],
    registration: sealbook_crypto::opaque::ClientRegistration<SealbookCipherSuite>,
    ck: &CollectionKey,
) -> RecoveryPassword {
    let upload =
        client_register_finish(registration, password.as_bytes(), opaque_response).unwrap();
    let kdf_salt = sealbook_crypto::generate_kdf_salt();
    let wrap = sealbook_crypto::wrap_collection_key(password.as_bytes(), &kdf_salt, ck).unwrap();
    let payload = sealbook_crypto::recovery_password_payload(
        &upload,
        &kdf_salt,
        &wrap.nonce,
        &wrap.ciphertext,
        &wrap.ciphersuite,
    );
    RecoveryPassword {
        upload,
        kdf_salt: kdf_salt.to_vec(),
        nonce: wrap.nonce.to_vec(),
        wrapped_ck: wrap.ciphertext,
        ciphersuite: wrap.ciphersuite,
        payload,
    }
}

/// Signs and MACs the roster a hand-built request has to carry.
#[allow(clippy::too_many_arguments)]
fn hand_roster(
    collection_id: Uuid,
    roster_seq: u64,
    key_epoch: u64,
    devices: Vec<sealbook_protocol::DevicePublicKeys>,
    phrase_mldsa_pk: Vec<u8>,
    phrase_ed25519_pk: Vec<u8>,
    signer: sealbook_crypto::RosterSigner,
    secrets: &DeviceSigningSecrets,
    key: &CollectionKey,
) -> sealbook_protocol::RosterBody {
    let mut roster = sealbook_crypto::Roster {
        roster_seq,
        key_epoch,
        devices: devices
            .into_iter()
            .map(|device| sealbook_crypto::RosterDevice {
                device_id: device.device_id,
                mldsa_pk: device.mldsa_pk,
                ed25519_pk: device.ed25519_pk,
                xwing_hpke_pk: device.xwing_hpke_pk,
            })
            .collect(),
        phrase_mldsa_pk,
        phrase_ed25519_pk,
        signer,
        signature: sealbook_crypto::DualSignature {
            mldsa: Vec::new(),
            ed25519: Vec::new(),
        },
        mac: Vec::new(),
    };
    let transcript = roster.transcript(collection_id);
    roster.signature = sign(secrets, &transcript).unwrap();
    roster.mac = sealbook_crypto::roster_mac(key, &transcript)
        .unwrap()
        .to_vec();
    sealbook_protocol::RosterBody::from_roster(roster)
}

/// The roster a phrase-signed recovery of `device` onto the account would carry.
fn recovery_roster(
    start: &RecoverStartResponse,
    entropy: &[u8; 32],
    device: &sealbook_protocol::DevicePublicKeys,
    key: &CollectionKey,
) -> sealbook_protocol::RosterBody {
    let current = start
        .roster
        .clone()
        .expect("a matched recovery serves the roster");
    let mut devices = current.devices.clone();
    devices.push(device.clone());
    let (phrase_secrets, phrase_public) = sealbook_crypto::phrase_recovery_keys(entropy).unwrap();
    hand_roster(
        start.collection_id.expect("and the collection"),
        current.roster_seq + 1,
        current.key_epoch,
        devices,
        phrase_public.mldsa_pk,
        phrase_public.ed25519_pk,
        sealbook_crypto::RosterSigner::Phrase,
        &phrase_secrets,
        key,
    )
}

async fn spawn_http(db_path: &str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = sealbook_server::app(db_path).await.unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn register_put_list_and_server_cannot_read_plaintext() {
    let dir = std::env::temp_dir().join(format!("sealbook-e2e-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let db_path = db.to_str().unwrap().to_string();
    let base = spawn_http(&db_path).await;

    let mut client = SealbookClient::plaintext_http();
    client
        .register(&base, "alice", "correct horse battery")
        .await
        .expect("register");

    let marker = "Ada Lovelace MUST NOT APPEAR IN SQLITE";
    let json = format!(r#"{{"@type":"Card","name":{{"full":"{marker}"}}}}"#);
    client
        .put_contact(Uuid::new_v4(), &json)
        .await
        .expect("put");

    let listed = client.list_contacts().await.expect("list");
    assert_eq!(listed.len(), 1);
    assert!(listed[0].1.contains("Ada Lovelace"));

    let raw = std::fs::read(&db).expect("read sqlite");
    let hay = String::from_utf8_lossy(&raw);
    assert!(
        !hay.contains("Ada Lovelace"),
        "server database leaked contact plaintext"
    );
    assert!(
        !hay.contains("MUST NOT APPEAR"),
        "server database leaked contact plaintext"
    );
}

#[tokio::test]
async fn pair_second_device_then_login() {
    let dir = std::env::temp_dir().join(format!("sealbook-pair-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let mut owner = SealbookClient::plaintext_http();
    let _phrase = owner
        .register(&base, "pairalice", "correct horse battery")
        .await
        .expect("register");

    let mut joiner = SealbookClient::plaintext_http();
    let (pair_code, confirm) = joiner.pair_join(&base, "pairalice").await.expect("join");
    assert_eq!(confirm.len(), PAIR_CONFIRMATION_LEN);

    owner
        .pair_approve(&pair_code, &confirm)
        .await
        .expect("approve");
    assert!(joiner.pair_ready(&pair_code).await.expect("ready"));

    joiner
        .login("correct horse battery")
        .await
        .expect("joiner login");
    let listed = joiner.list_contacts().await.expect("list");
    assert!(listed.is_empty());
}

#[tokio::test]
async fn recover_with_phrase_on_new_device() {
    let dir = std::env::temp_dir().join(format!("sealbook-recover-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let mut owner = SealbookClient::plaintext_http();
    let phrase = owner
        .register(&base, "recalice", "correct horse battery")
        .await
        .expect("register");
    let marker = "PhraseRecovered Contact";
    owner
        .put_contact(
            Uuid::new_v4(),
            &format!(r#"{{"@type":"Card","name":{{"full":"{marker}"}}}}"#),
        )
        .await
        .expect("put");

    let mut recovered = SealbookClient::plaintext_http();
    recovered
        .recover(&base, "recalice", &phrase, "correct horse battery")
        .await
        .expect("recover");
    assert!(
        owner.list_contacts().await.is_err(),
        "recovery must revoke old sessions"
    );
    let listed = recovered.list_contacts().await.expect("list");
    assert_eq!(listed.len(), 1);
    assert!(listed[0].1.contains(marker));

    let raw = std::fs::read(&db).expect("read sqlite");
    let hay = String::from_utf8_lossy(&raw);
    assert!(!hay.contains(marker), "phrase leaked contact plaintext");
    assert!(
        !hay.contains(&phrase),
        "full recovery phrase stored in sqlite"
    );
}

#[tokio::test]
async fn recovery_challenge_cannot_be_replayed() {
    let dir = std::env::temp_dir().join(format!("sealbook-replay-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;
    let mut owner = SealbookClient::plaintext_http();
    let phrase = owner
        .register(&base, "replayalice", "correct horse battery")
        .await
        .expect("register");
    let columns = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    let account_columns = sqlx::query("PRAGMA table_info(accounts)")
        .fetch_all(&columns)
        .await
        .unwrap();
    assert!(account_columns
        .iter()
        .all(|row| row.get::<String, _>("name") != "phrase_verifier"));
    assert!(account_columns
        .iter()
        .any(|row| row.get::<String, _>("name") == "phrase_mldsa_pk"));
    columns.close().await;
    let (opaque_request, registration) = client_register_start(b"correct horse battery").unwrap();
    let response: RecoverStartResponse = reqwest::Client::new()
        .post(format!("{base}/v1/recover/start"))
        .json(&RecoverStartRequest {
            username: "replayalice".into(),
            opaque_request,
            lookup_id: phrase_lookup_id(&entropy_from_phrase(&phrase).unwrap())
                .unwrap()
                .to_vec(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let entropy = entropy_from_phrase(&phrase).unwrap();
    let (hpke_sk, hpke_pk) = generate_device_hpke().unwrap();
    let (sign_sk, sign_pk) = generate_device_signing().unwrap();
    let device_id = Uuid::new_v4();
    let enrollment = enrollment_transcript(
        device_id,
        &sign_pk.mldsa_pk,
        &sign_pk.ed25519_pk,
        &hpke_pk.0,
    );
    let enrollment_sig = sign(&sign_sk, &enrollment).unwrap();
    let wrap = wrap_for_device(&hpke_pk, owner.collection_key().unwrap()).unwrap();
    let pw = recovery_password(
        "correct horse battery",
        &response.opaque_response,
        registration,
        owner.collection_key().unwrap(),
    );
    let transcript = phrase_recovery_transcript(
        "replayalice",
        response.recovery_id,
        &response.challenge,
        device_id,
        &sign_pk.mldsa_pk,
        &sign_pk.ed25519_pk,
        &hpke_pk.0,
        &pw.payload,
    );
    let device = sealbook_protocol::DevicePublicKeys {
        device_id,
        mldsa_pk: sign_pk.mldsa_pk.clone(),
        ed25519_pk: sign_pk.ed25519_pk.clone(),
        xwing_hpke_pk: hpke_pk.0.clone(),
    };
    let roster = recovery_roster(
        &response,
        &entropy,
        &device,
        owner.collection_key().unwrap(),
    );
    let finish = RecoverFinishRequest {
        username: "replayalice".into(),
        recovery_id: response.recovery_id,
        challenge: response.challenge,
        phrase_proof: {
            let proof = sign_phrase_recovery(&entropy, &transcript).unwrap();
            DualSignatureBody {
                mldsa: proof.mldsa,
                ed25519: proof.ed25519,
            }
        },
        device: sealbook_protocol::DevicePublicKeys {
            device_id,
            mldsa_pk: sign_pk.mldsa_pk,
            ed25519_pk: sign_pk.ed25519_pk,
            xwing_hpke_pk: hpke_pk.0,
        },
        enrollment_signature: DualSignatureBody {
            mldsa: enrollment_sig.mldsa,
            ed25519: enrollment_sig.ed25519,
        },
        wrap: KeyWrapBody {
            recipient_kind: "device".into(),
            recipient_id: device_id.to_string(),
            hpke_enc: wrap.enc,
            wrapped_ck: wrap.ciphertext,
            ciphersuite: XWING_CIPHERSUITE.into(),
        },
        roster,
        upload: pw.upload.clone(),
        kdf_salt: pw.kdf_salt.clone(),
        recovery_nonce: pw.nonce.clone(),
        recovery_wrapped_ck: pw.wrapped_ck.clone(),
        recovery_ciphersuite: pw.ciphersuite.clone(),
    };
    let http = reqwest::Client::new();
    let first = http
        .post(format!("{base}/v1/recover/finish"))
        .json(&finish)
        .send()
        .await
        .unwrap();
    assert!(first.error_for_status().is_ok());
    let replay = http
        .post(format!("{base}/v1/recover/finish"))
        .json(&finish)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), reqwest::StatusCode::UNAUTHORIZED);
    drop(hpke_sk);
    drop(sign_sk);
}

#[tokio::test]
async fn password_change_completion_requires_transaction() {
    let dir = std::env::temp_dir().join(format!("sealbook-password-change-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;
    let mut owner = SealbookClient::plaintext_http();
    owner
        .register(&base, "passwordalice", "correct horse battery")
        .await
        .expect("register");
    let token = owner
        .state
        .as_ref()
        .and_then(|state| state.session_token.as_deref())
        .unwrap();
    let response = reqwest::Client::new()
        .post(format!("{base}/v1/account/password"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "password_change_id": Uuid::new_v4(),
            "challenge": URL_SAFE_NO_PAD.encode([0u8; 32]),
            "signature": { "mldsa": "", "ed25519": "" },
            "upload": "",
            "kdf_salt": "AAAAAAAAAAAAAAAAAAAAAA",
            "recovery_nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "recovery_wrapped_ck": "",
            "recovery_ciphersuite": "aead-recovery-argon2id"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn address_books_are_encrypted_and_hidden_from_contact_list() {
    let dir = std::env::temp_dir().join(format!("sealbook-books-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let mut client = SealbookClient::plaintext_http();
    client
        .register(&base, "bookalice", "correct horse battery")
        .await
        .expect("register");

    let default_id = client
        .ensure_default_address_book()
        .await
        .expect("default book");
    assert_eq!(default_id, sealbook_client::DEFAULT_ADDRESS_BOOK_ID);

    let work_id = Uuid::new_v4();
    client
        .put_address_book(work_id, "Work")
        .await
        .expect("work book");

    let default_json = format!(
        r#"{{"@type":"Card","name":{{"full":"Ada Default"}},"{}":"{default_id}"}}"#,
        sealbook_client::ADDRESS_BOOK_ID_PROP
    );
    let work_json = format!(
        r#"{{"@type":"Card","name":{{"full":"Ada Work"}},"{}":"{work_id}"}}"#,
        sealbook_client::ADDRESS_BOOK_ID_PROP
    );
    client
        .put_contact(Uuid::new_v4(), &default_json)
        .await
        .expect("default contact");
    client
        .put_contact(Uuid::new_v4(), &work_json)
        .await
        .expect("work contact");

    let books = client.list_address_books().await.expect("books");
    assert_eq!(books.len(), 2);
    assert_eq!(books[0].0, default_id);
    assert_eq!(books[0].1, "Default Address Book");
    assert!(books
        .iter()
        .any(|(id, name)| *id == work_id && name == "Work"));

    let contacts = client.list_contacts().await.expect("list");
    assert_eq!(contacts.len(), 2);
    assert!(contacts
        .iter()
        .any(|(_, json)| json.contains("Ada Default")));
    assert!(contacts.iter().any(|(_, json)| json.contains("Ada Work")));
    assert!(contacts
        .iter()
        .all(|(_, json)| !json.contains("AddressBook")));

    let raw = std::fs::read(&db).expect("read sqlite");
    let hay = String::from_utf8_lossy(&raw);
    assert!(
        !hay.contains("Default Address Book"),
        "address book name leaked"
    );
    assert!(!hay.contains("Ada Default"), "contact plaintext leaked");
    assert!(!hay.contains("Ada Work"), "contact plaintext leaked");
}

/// The decrypted `body` of one note, so a test compares what the user typed
/// rather than its JSON escaping.
fn note_body(notes: &[(Uuid, String)], id: Uuid) -> String {
    let json = notes
        .iter()
        .find(|(candidate, _)| *candidate == id)
        .map(|(_, json)| json.as_str())
        .expect("note stored");
    serde_json::from_str::<serde_json::Value>(json)
        .expect("note json")
        .get("body")
        .and_then(|body| body.as_str())
        .expect("note body")
        .to_string()
}

fn note_json(title: &str, body: &str, notebook: Uuid) -> String {
    serde_json::json!({
        "@type": "Note",
        "version": "1.0",
        "title": title,
        "body": body,
        "notebookId": notebook.to_string(),
    })
    .to_string()
}

#[tokio::test]
async fn notes_and_notebooks_are_encrypted_and_hidden_from_the_contact_list() {
    let dir = std::env::temp_dir().join(format!("sealbook-notes-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let mut client = SealbookClient::plaintext_http();
    client
        .register(&base, "notealice", "correct horse battery")
        .await
        .expect("register");

    let default_id = client
        .ensure_default_notebook()
        .await
        .expect("default notebook");
    assert_eq!(default_id, sealbook_client::DEFAULT_NOTEBOOK_ID);

    let work_id = Uuid::new_v4();
    client
        .put_notebook(work_id, "Field Notes")
        .await
        .expect("work notebook");

    // Multi-line, so the padding round trip is proven for the shape a note
    // actually has rather than for a single line.
    let plan = "# Monday\n\n- ship notes\n- Zanzibar hummingbird\n";
    let idea = "Tuesday: Quetzalcoatlus sketches\n\n> and a quote\n";
    let plan_id = Uuid::new_v4();
    let idea_id = Uuid::new_v4();
    client
        .put_note(plan_id, &note_json("Weekly plan", plan, default_id))
        .await
        .expect("plan note");
    client
        .put_note(idea_id, &note_json("Ideas", idea, work_id))
        .await
        .expect("idea note");

    let notebooks = client.list_notebooks().await.expect("notebooks");
    assert_eq!(notebooks.len(), 2);
    assert_eq!(notebooks[0].0, default_id);
    assert_eq!(notebooks[0].1, "Default Notebook");
    assert!(notebooks
        .iter()
        .any(|(id, name)| *id == work_id && name == "Field Notes"));

    let notes = client.list_notes().await.expect("notes");
    assert_eq!(notes.len(), 2);
    assert_eq!(
        note_body(&notes, plan_id),
        plan,
        "the note body did not survive the round trip byte for byte"
    );
    assert_eq!(note_body(&notes, idea_id), idea);
    assert!(notes
        .iter()
        .all(|(_, json)| !json.contains("\"@type\":\"Notebook\"")));

    // A note is not a contact. The web client's type dispatch has an
    // "anything else is a contact" fallback, so this is the assertion that
    // catches a content type going astray.
    let contacts = client.list_contacts().await.expect("contacts");
    assert!(contacts.is_empty(), "a note was listed as a contact");

    let raw = std::fs::read(&db).expect("read sqlite");
    let hay = String::from_utf8_lossy(&raw);
    assert!(!hay.contains("Field Notes"), "notebook name leaked");
    assert!(!hay.contains("Weekly plan"), "note title leaked");
    assert!(!hay.contains("Zanzibar"), "note body leaked");
    assert!(!hay.contains("Quetzalcoatlus"), "note body leaked");
}

/// A note is the first content type that can realistically exceed what used to
/// be the per-object ceiling, which is why the ceiling moved. This is the test
/// that fails on the old constant.
#[tokio::test]
async fn a_note_larger_than_the_old_object_limit_round_trips() {
    let dir = std::env::temp_dir().join(format!("sealbook-bignote-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let mut client = SealbookClient::plaintext_http();
    client
        .register(&base, "bignote", "correct horse battery")
        .await
        .expect("register");
    let notebook = client
        .ensure_default_notebook()
        .await
        .expect("default notebook");

    // Over the old 1 MiB ceiling once padded, and under the current 8 MiB one.
    let body = format!("Okapi{}", "m".repeat(5 * 1024 * 1024));
    let id = Uuid::new_v4();
    client
        .put_note(id, &note_json("Long", &body, notebook))
        .await
        .expect("a note over the old ceiling must be accepted");

    let notes = client.list_notes().await.expect("notes");
    assert_eq!(
        note_body(&notes, id),
        body,
        "the long body did not round trip"
    );

    // Padded sizes are powers of two above the bucket table, so a body of this
    // size lands on exactly 8 MiB.
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .expect("open db");
    let padded: i64 = sqlx::query_scalar("SELECT padded_size FROM objects WHERE id = ?")
        .bind(id.to_string())
        .fetch_one(&pool)
        .await
        .expect("padded size");
    assert_eq!(padded, 8 * 1024 * 1024);
    pool.close().await;

    let raw = std::fs::read(&db).expect("read sqlite");
    assert!(
        !String::from_utf8_lossy(&raw).contains("Okapi"),
        "note body leaked"
    );
}

/// Deliberately does not assert on the error message. Padded sizes are powers of
/// two, so an object past the 8 MiB ceiling makes a request body past
/// `MAX_OBJECT_BODY` and axum rejects it before `validate_object` runs. The
/// `padded_size` range check is covered by a unit test instead.
#[tokio::test]
async fn a_note_past_the_object_size_limit_is_refused() {
    let dir = std::env::temp_dir().join(format!("sealbook-hugenote-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let mut client = SealbookClient::plaintext_http();
    client
        .register(&base, "hugenote", "correct horse battery")
        .await
        .expect("register");
    let notebook = client
        .ensure_default_notebook()
        .await
        .expect("default notebook");

    let body = format!("Pangolin{}", "m".repeat(9 * 1024 * 1024));
    let result = client
        .put_note(Uuid::new_v4(), &note_json("Too long", &body, notebook))
        .await;
    assert!(result.is_err(), "a note past the ceiling must be refused");

    let notes = client.list_notes().await.expect("notes");
    assert!(
        notes.iter().all(|(_, json)| !json.contains("Pangolin")),
        "a refused note must not be stored"
    );
}

#[tokio::test]
async fn https_tls13_round_trip() {
    let dir = std::env::temp_dir().join(format!("sealbook-tls-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let db_path = db.to_str().unwrap().to_string();

    let material = sealbook_server::tls::generate_self_signed().unwrap();
    let cert = material.cert_der.clone();
    let app = sealbook_server::app(&db_path).await.unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let handle = axum_server::Handle::new();
    let handle2 = handle.clone();
    let config = axum_server::tls_rustls::RustlsConfig::from_config(material.server_config);
    tokio::spawn(async move {
        axum_server::bind_rustls(addr, config)
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    let bound = loop {
        if let Some(a) = handle2.listening().await {
            break a;
        }
    };

    let mut client = SealbookClient::https(Some(cert)).unwrap();
    client
        .register(
            &format!("https://127.0.0.1:{}", bound.port()),
            "bob",
            "correct horse battery",
        )
        .await
        .expect("https register");
}

/// Pinning does not skip name verification, so the handshake is the only thing
/// that proves a configured SAN is served. The negative half keeps this from
/// passing on a certificate that happens to match any name.
#[tokio::test]
async fn a_configured_san_completes_a_handshake_and_an_unconfigured_one_does_not() {
    let dir = std::env::temp_dir().join(format!("sealbook-san-tls-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");

    let sans = sealbook_server::tls::TlsSans::parse("sealbook.lan").unwrap();
    let material = sealbook_server::tls::generate_self_signed_for(&sans).unwrap();
    let cert = material.cert_der.clone();
    let app = sealbook_server::app(db.to_str().unwrap()).await.unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let handle = axum_server::Handle::new();
    let handle2 = handle.clone();
    let config = axum_server::tls_rustls::RustlsConfig::from_config(material.server_config);
    tokio::spawn(async move {
        axum_server::bind_rustls(addr, config)
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    let bound = loop {
        if let Some(address) = handle2.listening().await {
            break address;
        }
    };

    // Each client reaches the loopback listener under the name being verified,
    // which is what serving on an address other than loopback looks like to
    // rustls without needing one in the test environment.
    let probe = |name: &str| {
        let tls =
            sealbook_client::pq_tls_config(sealbook_client::TrustAnchors::Pinned(cert.clone()))
                .unwrap();
        reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .resolve(name, SocketAddr::from(([127, 0, 0, 1], bound.port())))
            .build()
            .unwrap()
            .get(format!("https://{name}:{}/health", bound.port()))
            .send()
    };

    let configured = probe("sealbook.lan").await;
    assert!(
        configured.is_ok(),
        "a configured SAN must verify: {:?}",
        configured.err()
    );
    assert!(probe("sealbook.other").await.is_err());

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn classical_tls_client_is_rejected() {
    let dir = std::env::temp_dir().join(format!("sealbook-pq-only-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let material = sealbook_server::tls::generate_self_signed().unwrap();
    let cert = material.cert_der.clone();
    let app = sealbook_server::app(db.to_str().unwrap()).await.unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let handle = axum_server::Handle::new();
    let handle2 = handle.clone();
    let config = axum_server::tls_rustls::RustlsConfig::from_config(material.server_config);
    tokio::spawn(async move {
        axum_server::bind_rustls(addr, config)
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    let bound = loop {
        if let Some(address) = handle2.listening().await {
            break address;
        }
    };

    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider
        .kx_groups
        .retain(|group| group.name() == rustls::NamedGroup::X25519);
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert.to_vec())).unwrap();
    let client_config = ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(client_config)
        .build()
        .unwrap();

    let result = client
        .get(format!("https://127.0.0.1:{}/health", bound.port()))
        .send()
        .await;
    assert!(
        result.is_err(),
        "classical-only TLS client unexpectedly connected"
    );
}

#[test]
fn rustls_prefers_post_quantum_kx() {
    assert!(sealbook_server::tls::preferred_kx_is_pq());
}

/// The mirror of `classical_tls_client_is_rejected`: the client must also
/// refuse a classical-only *server*, so that a TLS-terminating proxy cannot
/// silently downgrade the connection and reopen harvest-now-decrypt-later.
#[tokio::test]
async fn sealbook_client_refuses_a_classical_only_server() {
    let dir = std::env::temp_dir().join(format!("sealbook-client-pq-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let material = sealbook_server::tls::generate_self_signed().unwrap();
    let cert = material.cert_der.clone();
    let app = sealbook_server::app(db.to_str().unwrap()).await.unwrap();

    // Stand up a server that offers only classical X25519, imitating a proxy
    // that has not been configured for the hybrid group.
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider
        .kx_groups
        .retain(|group| group.name() == rustls::NamedGroup::X25519);
    let key =
        rustls::pki_types::PrivateKeyDer::from_pem_slice(material.key_pem.as_bytes()).unwrap();
    let classical_config = rustls::ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();

    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let handle = axum_server::Handle::new();
    let handle2 = handle.clone();
    let config =
        axum_server::tls_rustls::RustlsConfig::from_config(std::sync::Arc::new(classical_config));
    tokio::spawn(async move {
        let _ = axum_server::bind_rustls(addr, config)
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await;
    });
    let bound = loop {
        if let Some(address) = handle2.listening().await {
            break address;
        }
    };

    let mut client = SealbookClient::https(Some(cert)).unwrap();
    let result = client
        .register(
            &format!("https://127.0.0.1:{}", bound.port()),
            "downgrade",
            "correct horse battery",
        )
        .await;
    assert!(
        result.is_err(),
        "sealbook-client accepted a classical-only TLS server"
    );
}

#[tokio::test]
async fn security_headers_are_present_on_all_responses() {
    let dir = std::env::temp_dir().join(format!("sealbook-sec-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let db_path = db.to_str().unwrap().to_string();
    let base = spawn_http(&db_path).await;

    let resp = reqwest::Client::new()
        .get(format!("{base}/health"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let h = resp.headers();
    assert_eq!(h.get("x-frame-options").unwrap(), "DENY");
    assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(
        h.get("referrer-policy").unwrap(),
        "strict-origin-when-cross-origin"
    );
    assert_eq!(h.get("cross-origin-opener-policy").unwrap(), "same-origin");
    assert_eq!(
        h.get("cross-origin-resource-policy").unwrap(),
        "same-origin"
    );
    assert!(h
        .get("strict-transport-security")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("max-age=31536000"));
    assert!(h
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("default-src 'self'"));
}

#[tokio::test]
async fn crypto_profile_reports_hybrid_algorithms() {
    let dir = std::env::temp_dir().join(format!("sealbook-crypto-profile-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let profile: serde_json::Value = reqwest::Client::new()
        .get(format!("{base}/health/crypto"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(profile["tls_version"], "TLS1.3");
    assert_eq!(profile["tls_kx_preferred"], "X25519MLKEM768");
    assert_eq!(profile["hpke_ciphersuite"], XWING_CIPHERSUITE);
    assert_eq!(profile["signature_algorithms"][0], "ML-DSA-65");
    assert_eq!(profile["signature_algorithms"][1], "Ed25519");
    assert_eq!(profile["phrase_recovery_scheme"], PHRASE_SCHEME);
    assert_eq!(profile["opaque_requires_device_proof"], true);
    // The Argon2 cost parameters must be visible, not just the algorithm name.
    assert!(profile["opaque_ksf"].as_str().unwrap().contains("m65536"));
    assert!(profile["recovery_ciphersuite"]
        .as_str()
        .unwrap()
        .contains("m65536"));
}

/// The central fix for the OPAQUE finding: an attacker who cannot sign as a
/// registered device must not be able to pull an OPAQUE credential response
/// out of the server, because that response is what enables an offline
/// password attack once Ristretto255 falls.
#[tokio::test]
async fn login_start_releases_no_opaque_response_without_a_device_proof() {
    let dir = std::env::temp_dir().join(format!("sealbook-login-proof-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let mut owner = SealbookClient::plaintext_http();
    owner
        .register(&base, "proofalice", "correct horse battery")
        .await
        .expect("register");
    let device_id = owner.state.as_ref().unwrap().device_id;

    let http = reqwest::Client::new();
    let challenge: LoginChallengeResponse = http
        .post(format!("{base}/v1/opaque/login/challenge"))
        .json(&LoginChallengeRequest {
            username: "proofalice".into(),
            device_id,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // The attacker sees the sealed challenge but cannot open it, so it guesses.
    let (request, _state) = client_login_start(b"guessed password").unwrap();
    let forged = LoginStartRequest {
        challenge_id: challenge.challenge_id,
        username: "proofalice".into(),
        device_id,
        challenge: vec![0u8; 32],
        request,
        device_signature: DualSignatureBody {
            mldsa: vec![0u8; 3309],
            ed25519: vec![0u8; 64],
        },
    };
    let response = http
        .post(format!("{base}/v1/opaque/login/start"))
        .json(&forged)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    let body = response.text().await.unwrap();
    assert!(
        !body.contains("response"),
        "login/start leaked an OPAQUE credential response: {body}"
    );
    // The happy path is covered by the register/login tests above; repeating a
    // genuine login here would exceed the per-username login rate limit.
}

/// Even with the correct challenge, the ML-DSA half of the signature must be
/// checked; an Ed25519-only forgery is exactly what a quantum attacker could
/// produce.
#[tokio::test]
async fn login_start_rejects_a_classically_valid_but_pq_forged_proof() {
    let dir = std::env::temp_dir().join(format!("sealbook-login-forge-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let mut owner = SealbookClient::plaintext_http();
    owner
        .register(&base, "forgealice", "correct horse battery")
        .await
        .expect("register");
    let (device_id, hpke_sk, ed25519_sk) = {
        let state = owner.state.as_ref().unwrap();
        (
            state.device_id,
            state.hpke_sk.clone(),
            state.ed25519_sk.clone(),
        )
    };

    let http = reqwest::Client::new();
    let challenge: LoginChallengeResponse = http
        .post(format!("{base}/v1/opaque/login/challenge"))
        .json(&LoginChallengeRequest {
            username: "forgealice".into(),
            device_id,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    let opened = open_login_challenge(
        &DeviceHpkeSecret::from_bytes(hpke_sk),
        &DeviceHpkeWrap {
            enc: challenge.challenge_enc,
            ciphertext: challenge.challenge_ct,
            ciphersuite: XWING_CIPHERSUITE,
        },
    )
    .unwrap();

    let (request, _state) = client_login_start(b"correct horse battery").unwrap();
    let transcript = login_start_transcript(
        challenge.challenge_id,
        "forgealice",
        device_id,
        &opened,
        &request,
    );
    // Sign with the real Ed25519 key but an unrelated ML-DSA key.
    let (rogue_sk, _) = generate_device_signing().unwrap();
    let real_ed = sign(
        &DeviceSigningSecrets {
            mldsa_seed: rogue_sk.mldsa_seed.clone(),
            ed25519_sk,
        },
        &transcript,
    )
    .unwrap();
    let rogue = sign(&rogue_sk, &transcript).unwrap();

    let response = http
        .post(format!("{base}/v1/opaque/login/start"))
        .json(&LoginStartRequest {
            challenge_id: challenge.challenge_id,
            username: "forgealice".into(),
            device_id,
            challenge: opened.to_vec(),
            request,
            device_signature: DualSignatureBody {
                mldsa: rogue.mldsa,
                ed25519: real_ed.ed25519,
            },
        })
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
}

/// A recovery proof must satisfy both signature schemes. Forging only Ed25519,
/// which is what a quantum attacker could do, must not enroll a device.
#[tokio::test]
async fn recovery_rejects_a_proof_with_a_foreign_mldsa_signature() {
    let dir = std::env::temp_dir().join(format!("sealbook-recover-forge-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let mut owner = SealbookClient::plaintext_http();
    let phrase = owner
        .register(&base, "forgebob", "correct horse battery")
        .await
        .expect("register");
    let entropy = entropy_from_phrase(&phrase).unwrap();

    let http = reqwest::Client::new();
    let (opaque_request, registration) = client_register_start(b"correct horse battery").unwrap();
    let start: RecoverStartResponse = http
        .post(format!("{base}/v1/recover/start"))
        .json(&RecoverStartRequest {
            username: "forgebob".into(),
            lookup_id: phrase_lookup_id(&entropy).unwrap().to_vec(),
            opaque_request,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    let (hpke_sk, hpke_pk) = generate_device_hpke().unwrap();
    let (sign_sk, sign_pk) = generate_device_signing().unwrap();
    let device_id = Uuid::new_v4();
    let enrollment = enrollment_transcript(
        device_id,
        &sign_pk.mldsa_pk,
        &sign_pk.ed25519_pk,
        &hpke_pk.0,
    );
    let enrollment_sig = sign(&sign_sk, &enrollment).unwrap();
    let wrap = wrap_for_device(&hpke_pk, owner.collection_key().unwrap()).unwrap();
    let pw = recovery_password(
        "correct horse battery",
        &start.opaque_response,
        registration,
        owner.collection_key().unwrap(),
    );
    let transcript = phrase_recovery_transcript(
        "forgebob",
        start.recovery_id,
        &start.challenge,
        device_id,
        &sign_pk.mldsa_pk,
        &sign_pk.ed25519_pk,
        &hpke_pk.0,
        &pw.payload,
    );
    let roster = recovery_roster(
        &start,
        &entropy,
        &sealbook_protocol::DevicePublicKeys {
            device_id,
            mldsa_pk: sign_pk.mldsa_pk.clone(),
            ed25519_pk: sign_pk.ed25519_pk.clone(),
            xwing_hpke_pk: hpke_pk.0.clone(),
        },
        owner.collection_key().unwrap(),
    );
    let genuine = sign_phrase_recovery(&entropy, &transcript).unwrap();
    // Swap in an ML-DSA signature derived from a different phrase.
    let foreign = sign_phrase_recovery(&[9u8; 32], &transcript).unwrap();

    let response = http
        .post(format!("{base}/v1/recover/finish"))
        .json(&RecoverFinishRequest {
            username: "forgebob".into(),
            recovery_id: start.recovery_id,
            challenge: start.challenge,
            phrase_proof: DualSignatureBody {
                mldsa: foreign.mldsa,
                ed25519: genuine.ed25519,
            },
            device: sealbook_protocol::DevicePublicKeys {
                device_id,
                mldsa_pk: sign_pk.mldsa_pk,
                ed25519_pk: sign_pk.ed25519_pk,
                xwing_hpke_pk: hpke_pk.0,
            },
            enrollment_signature: DualSignatureBody {
                mldsa: enrollment_sig.mldsa,
                ed25519: enrollment_sig.ed25519,
            },
            wrap: KeyWrapBody {
                recipient_kind: "device".into(),
                recipient_id: device_id.to_string(),
                hpke_enc: wrap.enc,
                wrapped_ck: wrap.ciphertext,
                ciphersuite: XWING_CIPHERSUITE.into(),
            },
            roster,
            upload: pw.upload,
            kdf_salt: pw.kdf_salt,
            recovery_nonce: pw.nonce,
            recovery_wrapped_ck: pw.wrapped_ck,
            recovery_ciphersuite: pw.ciphersuite,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    drop(hpke_sk);
}

/// `recover/start` must not hand out the recovery verification keys; only an
/// opaque lookup handle is accepted, and the wrap comes back without them.
#[tokio::test]
async fn recover_start_does_not_disclose_recovery_public_keys() {
    let dir = std::env::temp_dir().join(format!("sealbook-recover-disclose-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let mut owner = SealbookClient::plaintext_http();
    let phrase = owner
        .register(&base, "lookupbob", "correct horse battery")
        .await
        .expect("register");
    let entropy = entropy_from_phrase(&phrase).unwrap();
    let public = sealbook_crypto::phrase_recovery_public(&entropy).unwrap();

    let body = reqwest::Client::new()
        .post(format!("{base}/v1/recover/start"))
        .json(&RecoverStartRequest {
            username: "lookupbob".into(),
            lookup_id: phrase_lookup_id(&entropy).unwrap().to_vec(),
            opaque_request: client_register_start(b"correct horse battery").unwrap().0,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();

    let encoded = URL_SAFE_NO_PAD.encode(&public.mldsa_pk);
    assert!(
        !body.contains(&encoded),
        "recover/start disclosed the ML-DSA recovery key"
    );
    let encoded = URL_SAFE_NO_PAD.encode(&public.ed25519_pk);
    assert!(
        !body.contains(&encoded),
        "recover/start disclosed the Ed25519 recovery key"
    );
}

/// Splitting login into a challenge request plus a start request must not halve
/// how many login attempts a user gets per minute: the two steps use separate
/// rate-limit buckets.
#[tokio::test]
async fn three_message_login_does_not_halve_the_login_rate_limit() {
    let dir = std::env::temp_dir().join(format!("sealbook-login-rate-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let db_path = db.to_str().unwrap().to_string();
    let base = spawn_http(&db_path).await;

    let mut client = SealbookClient::plaintext_http();
    client
        .register(&base, "ratealice", "correct horse battery")
        .await
        .expect("register");

    // register performs one login; three more must still succeed inside the
    // same window, which fails if challenge and start share a bucket.
    for attempt in 0..3 {
        client
            .login("correct horse battery")
            .await
            .unwrap_or_else(|err| panic!("login attempt {attempt} rejected: {err}"));
    }
}

/// The core of the fix: after revocation the removed device must not be able
/// to read anything, even data it had already synced. Marking it revoked is
/// not enough, because it still holds the old collection key.
#[tokio::test]
async fn revoking_a_device_rotates_the_collection_key() {
    let dir = std::env::temp_dir().join(format!("sealbook-rotate-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let db_path = db.to_str().unwrap().to_string();
    let base = spawn_http(&db_path).await;

    let mut owner = SealbookClient::plaintext_http();
    owner
        .register(&base, "rotalice", "correct horse battery")
        .await
        .expect("register");
    owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Ada Lovelace"}}"#,
        )
        .await
        .expect("put");

    // Pair a second device, which then holds the same collection key.
    let mut joiner = SealbookClient::plaintext_http();
    let (pair_code, confirm) = joiner.pair_join(&base, "rotalice").await.expect("join");
    owner
        .pair_approve(&pair_code, &confirm)
        .await
        .expect("approve");
    assert!(joiner.pair_ready(&pair_code).await.expect("ready"));
    joiner
        .login("correct horse battery")
        .await
        .expect("joiner login");
    let stolen_key = joiner.collection_key().unwrap().as_bytes().to_vec();
    let joiner_device = joiner.state.as_ref().unwrap().device_id;
    assert_eq!(joiner.list_contacts().await.expect("joiner list").len(), 1);

    let epoch_before = owner.server_key_epoch().await.expect("epoch");
    assert_eq!(
        owner.cached_key_epoch(),
        epoch_before,
        "login must report the epoch its key wraps belong to"
    );

    // Revoke it from the owner device.
    let new_phrase = owner
        .revoke_device(joiner_device, "correct horse battery")
        .await
        .expect("revoke");
    assert_eq!(new_phrase.split_whitespace().count(), 24);

    // The key actually changed, and the epoch advanced.
    let rotated_key = owner.collection_key().unwrap().as_bytes().to_vec();
    assert_ne!(
        rotated_key, stolen_key,
        "collection key was not rotated on revocation"
    );
    assert_eq!(
        owner.server_key_epoch().await.expect("epoch"),
        epoch_before + 1
    );
    assert_eq!(owner.cached_key_epoch(), epoch_before + 1);

    // The owner can still read its data, re-encrypted under the new key.
    let listed = owner.list_contacts().await.expect("owner list");
    assert_eq!(listed.len(), 1);
    assert!(listed[0].1.contains("Ada Lovelace"));

    // The revoked device's session is gone and it cannot log back in.
    assert!(
        joiner.list_contacts().await.is_err(),
        "revoked device still had a working session"
    );
    assert!(
        joiner.login("correct horse battery").await.is_err(),
        "revoked device was able to log back in"
    );

    // The property that actually matters: holding the old collection key is no
    // longer enough to read the stored ciphertext.
    let collection_id = owner.state.as_ref().unwrap().collection_id;
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    let row = sqlx::query(
        "SELECT id, nonce, ciphertext, padded_size FROM objects WHERE tombstone = 0 LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    pool.close().await;

    let object_id = Uuid::parse_str(&row.get::<String, _>("id")).unwrap();
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&row.get::<Vec<u8>, _>("nonce"));
    let encrypted = EncryptedObject {
        nonce,
        ciphertext: row.get("ciphertext"),
        padded_size: row.get::<i64, _>("padded_size") as usize,
    };
    let aad = object_aad(object_id.as_bytes(), collection_id.as_bytes());

    let old_key = CollectionKey::from_bytes(stolen_key.clone().try_into().unwrap());
    assert!(
        decrypt_object(&old_key, &encrypted, &aad).is_err(),
        "the revoked device's key still decrypts stored objects"
    );
    let new_key = CollectionKey::from_bytes(rotated_key.clone().try_into().unwrap());
    decrypt_object(&new_key, &encrypted, &aad)
        .expect("the rotated key must still open the re-encrypted object");

    let raw = std::fs::read(&db).expect("read sqlite");
    let hay = String::from_utf8_lossy(&raw);
    assert!(!hay.contains("Ada Lovelace"));
}

/// The old wrap must be deleted, not merely orphaned: if it survived, anyone
/// who recovered the revoked device's key could still unwrap the new key.
#[tokio::test]
async fn revocation_removes_the_old_key_wraps() {
    let dir = std::env::temp_dir().join(format!("sealbook-rotate-wraps-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let db_path = db.to_str().unwrap().to_string();
    let base = spawn_http(&db_path).await;

    let mut owner = SealbookClient::plaintext_http();
    owner
        .register(&base, "wrapalice", "correct horse battery")
        .await
        .expect("register");
    let mut joiner = SealbookClient::plaintext_http();
    let (pair_code, confirm) = joiner.pair_join(&base, "wrapalice").await.expect("join");
    owner
        .pair_approve(&pair_code, &confirm)
        .await
        .expect("approve");
    joiner.login("correct horse battery").await.expect("login");
    let joiner_device = joiner.state.as_ref().unwrap().device_id;

    owner
        .revoke_device(joiner_device, "correct horse battery")
        .await
        .expect("revoke");

    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    let wraps = sqlx::query("SELECT recipient_kind, recipient_id FROM key_wraps")
        .fetch_all(&pool)
        .await
        .unwrap();
    pool.close().await;
    assert!(
        !wraps
            .iter()
            .any(|row| row.get::<String, _>("recipient_id") == joiner_device.to_string()),
        "the revoked device's key wrap survived the rotation"
    );
    // Still exactly one wrap each for the remaining device, password and phrase.
    assert_eq!(wraps.len(), 3);
}

/// The new phrase must work and the old one must not, since the collection key
/// it protected no longer exists.
#[tokio::test]
async fn rotation_issues_a_working_new_recovery_phrase() {
    let dir = std::env::temp_dir().join(format!("sealbook-rotate-phrase-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let db_path = db.to_str().unwrap().to_string();
    let base = spawn_http(&db_path).await;

    let mut owner = SealbookClient::plaintext_http();
    let old_phrase = owner
        .register(&base, "phralice", "correct horse battery")
        .await
        .expect("register");
    owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Grace Hopper"}}"#,
        )
        .await
        .expect("put");
    let mut joiner = SealbookClient::plaintext_http();
    let (pair_code, confirm) = joiner.pair_join(&base, "phralice").await.expect("join");
    owner
        .pair_approve(&pair_code, &confirm)
        .await
        .expect("approve");
    joiner.login("correct horse battery").await.expect("login");
    let joiner_device = joiner.state.as_ref().unwrap().device_id;

    let new_phrase = owner
        .revoke_device(joiner_device, "correct horse battery")
        .await
        .expect("revoke");
    assert_ne!(new_phrase, old_phrase);

    let mut stale = SealbookClient::plaintext_http();
    assert!(
        stale
            .recover(&base, "phralice", &old_phrase, "correct horse battery")
            .await
            .is_err(),
        "the superseded recovery phrase still worked"
    );

    let mut fresh = SealbookClient::plaintext_http();
    fresh
        .recover(&base, "phralice", &new_phrase, "correct horse battery")
        .await
        .expect("recover with the new phrase");
    let listed = fresh.list_contacts().await.expect("list");
    assert_eq!(listed.len(), 1);
    assert!(listed[0].1.contains("Grace Hopper"));
}

/// A rotation carries the whole vault, so it must not be held to the small
/// request limit the rest of the API uses.
///
/// Under the previous blanket 256 KiB limit this failed with `413`, which meant
/// revocation did not happen at all: the device being removed kept a collection
/// key that still opened everything it had synced.
#[tokio::test]
async fn revoking_a_device_works_on_a_vault_larger_than_the_default_body_limit() {
    let dir = std::env::temp_dir().join(format!("sealbook-big-rotate-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let db_path = db.to_str().unwrap().to_string();
    let base = spawn_http(&db_path).await;

    let mut owner = SealbookClient::plaintext_http();
    owner
        .register(&base, "bigalice", "correct horse battery")
        .await
        .expect("register");

    // Roughly 4 KiB of plaintext each, so the rotation payload comfortably
    // exceeds the 256 KiB limit that applies to every other route.
    let filler = "x".repeat(3900);
    for index in 0..80 {
        owner
            .put_contact(
                Uuid::new_v4(),
                &format!(
                    r#"{{"@type":"Card","name":{{"full":"Contact {index}"}},"notes":"{filler}"}}"#
                ),
            )
            .await
            .expect("put");
    }

    let mut joiner = SealbookClient::plaintext_http();
    let (pair_code, confirm) = joiner.pair_join(&base, "bigalice").await.expect("join");
    owner
        .pair_approve(&pair_code, &confirm)
        .await
        .expect("approve");
    assert!(joiner.pair_ready(&pair_code).await.expect("ready"));
    joiner
        .login("correct horse battery")
        .await
        .expect("joiner login");
    let stolen_key = joiner.collection_key().unwrap().as_bytes().to_vec();
    let joiner_device = joiner.state.as_ref().unwrap().device_id;

    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    let stored: i64 = sqlx::query_scalar("SELECT SUM(padded_size) FROM objects")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        stored > 256 * 1024,
        "test is not exercising the limit: vault is only {stored} bytes"
    );

    owner
        .revoke_device(joiner_device, "correct horse battery")
        .await
        .expect("revoke a device holding a large vault");

    assert_ne!(
        owner.collection_key().unwrap().as_bytes().to_vec(),
        stolen_key,
        "collection key was not rotated"
    );
    let listed = owner.list_contacts().await.expect("owner list");
    assert_eq!(listed.len(), 80, "every object must survive the rotation");
    assert!(listed.iter().all(|(_, body)| body.contains("Contact")));
    assert!(
        joiner.list_contacts().await.is_err(),
        "revoked device still had a working session"
    );

    pool.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// The container health check has to negotiate the same PQ-only TLS the server
/// insists on, which is why it is built into the binary rather than done with
/// `curl`.
#[tokio::test]
async fn the_health_check_probes_a_live_pq_tls_server() {
    let dir = std::env::temp_dir().join(format!("sealbook-health-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let db_path = db.to_str().unwrap().to_string();

    let material = sealbook_server::tls::generate_self_signed().unwrap();
    let app = sealbook_server::app(&db_path).await.unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let handle = axum_server::Handle::new();
    let listening = handle.clone();
    let config = axum_server::tls_rustls::RustlsConfig::from_config(material.server_config);
    tokio::spawn(async move {
        axum_server::bind_rustls(addr, config)
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    let bound = loop {
        if let Some(bound) = listening.listening().await {
            break bound;
        }
    };

    let target = format!("127.0.0.1:{}", bound.port());
    // The probe is synchronous, so it has to run off the runtime thread or the
    // server it is probing can never answer.
    tokio::task::spawn_blocking(move || sealbook_server::healthcheck::run(&target))
        .await
        .unwrap()
        .expect("health check should pass against a live server");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn the_health_check_fails_when_nothing_is_listening() {
    // Bind and drop, so the port is almost certainly free and definitely unserved.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let target = format!("127.0.0.1:{port}");
    let result = tokio::task::spawn_blocking(move || sealbook_server::healthcheck::run(&target))
        .await
        .unwrap();
    assert!(result.is_err(), "probe reported a dead server as healthy");
}

// ── Signed manifest: what a lying server looks like from the client side ──

/// Helper: a client registered with one contact, and the paths to its database.
async fn account_with_contacts(
    label: &str,
    count: usize,
) -> (std::path::PathBuf, String, SealbookClient) {
    let dir = std::env::temp_dir().join(format!("sealbook-{label}-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let db_path = db.to_str().unwrap().to_string();
    let base = spawn_http(&db_path).await;
    let mut client = SealbookClient::plaintext_http();
    client
        .register(&base, "manifestalice", "correct horse battery")
        .await
        .expect("register");
    for index in 0..count {
        client
            .put_contact(
                Uuid::new_v4(),
                &format!(r#"{{"@type":"Card","name":{{"full":"Contact {index}"}}}}"#),
            )
            .await
            .expect("put");
    }
    (db, base, client)
}

/// Withholding an object is what a server does to hide a contact's existence.
/// The manifest commits to the object count and to every id, so the client notices.
#[tokio::test]
async fn a_withheld_object_is_detected() {
    let (db, _base, mut client) = account_with_contacts("withhold", 3).await;
    assert_eq!(client.list_contacts().await.expect("list").len(), 3);

    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    sqlx::query("DELETE FROM objects WHERE id = (SELECT id FROM objects LIMIT 1)")
        .execute(&pool)
        .await
        .unwrap();

    let error = client
        .list_contacts()
        .await
        .expect_err("a withheld object must not pass verification");
    assert!(
        error.to_string().contains("manifest"),
        "wrong error: {error}"
    );
    pool.close().await;
}

/// Serving an old ciphertext under the current revision number is the rollback
/// the content digest exists to catch: the revision still matches, the bytes do not.
#[tokio::test]
async fn a_substituted_ciphertext_is_detected() {
    let (db, _base, mut client) = account_with_contacts("rollback", 2).await;

    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    // Swap in the other object's ciphertext, leaving every other column alone.
    let rows: Vec<(String, Vec<u8>, Vec<u8>)> =
        sqlx::query("SELECT id, nonce, ciphertext FROM objects ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap()
            .into_iter()
            .map(|row| (row.get("id"), row.get("nonce"), row.get("ciphertext")))
            .collect();
    sqlx::query("UPDATE objects SET nonce = ?, ciphertext = ? WHERE id = ?")
        .bind(&rows[1].1)
        .bind(&rows[1].2)
        .bind(&rows[0].0)
        .execute(&pool)
        .await
        .unwrap();

    let error = client
        .list_contacts()
        .await
        .expect_err("substituted ciphertext must not pass verification");
    assert!(
        error.to_string().contains("manifest"),
        "wrong error: {error}"
    );
    pool.close().await;
}

/// Rolling an object back to a genuinely earlier revision changes the revision the
/// manifest committed to, so it is caught as well.
#[tokio::test]
async fn a_rolled_back_revision_is_detected() {
    let (db, _base, mut client) = account_with_contacts("revision", 2).await;

    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    sqlx::query(
        "UPDATE objects SET revision = 1 WHERE revision = (SELECT MAX(revision) FROM objects)",
    )
    .execute(&pool)
    .await
    .unwrap();

    let error = client
        .list_contacts()
        .await
        .expect_err("a rolled-back revision must not pass verification");
    assert!(
        error.to_string().contains("manifest"),
        "wrong error: {error}"
    );
    pool.close().await;
}

/// A write has to present the next manifest sequence, which is what serialises
/// two devices writing at once instead of letting one silently overwrite the other.
#[tokio::test]
async fn a_replayed_manifest_sequence_is_refused() {
    let (db, base, client) = account_with_contacts("replay", 1).await;
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    let state = client.state.as_ref().unwrap();
    let token = state.session_token.clone().unwrap();
    let collection = state.collection_id;

    // Replay the stored manifest verbatim alongside a fresh object.
    let row = sqlx::query(
        "SELECT manifest_seq, key_epoch, latest_revision, object_count, digest, device_id,
                mldsa_sig, ed25519_sig FROM manifests",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let response = reqwest::Client::new()
        .put(format!("{base}/v1/collections/{collection}/objects"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "id": Uuid::new_v4(),
            "revision": row.get::<i64, _>("latest_revision") + 1,
            "nonce": URL_SAFE_NO_PAD.encode([7u8; 24]),
            "ciphertext": URL_SAFE_NO_PAD.encode([0u8; 272]),
            "padded_size": 256,
            "content_type": SEALED_CONTENT_TYPE,
            "tombstone": false,
            "manifest": {
                "manifest_seq": row.get::<i64, _>("manifest_seq"),
                "key_epoch": row.get::<i64, _>("key_epoch"),
                "latest_revision": row.get::<i64, _>("latest_revision") + 1,
                "object_count": row.get::<i64, _>("object_count"),
                "digest": URL_SAFE_NO_PAD.encode(row.get::<Vec<u8>, _>("digest")),
                "device_id": row.get::<String, _>("device_id"),
                "signature": {
                    "mldsa": URL_SAFE_NO_PAD.encode(row.get::<Vec<u8>, _>("mldsa_sig")),
                    "ed25519": URL_SAFE_NO_PAD.encode(row.get::<Vec<u8>, _>("ed25519_sig")),
                }
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::CONFLICT);
    pool.close().await;
}

/// A manifest that does not describe what the server now holds is refused, so a
/// stored manifest can always be handed to another device as the truth.
#[tokio::test]
async fn a_manifest_that_does_not_match_the_write_is_refused() {
    let (db, base, client) = account_with_contacts("mismatch", 1).await;
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    let state = client.state.as_ref().unwrap();
    let token = state.session_token.clone().unwrap();
    let collection = state.collection_id;
    let row = sqlx::query("SELECT manifest_seq, key_epoch, latest_revision FROM manifests")
        .fetch_one(&pool)
        .await
        .unwrap();

    let response = reqwest::Client::new()
        .put(format!("{base}/v1/collections/{collection}/objects"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "id": Uuid::new_v4(),
            "revision": row.get::<i64, _>("latest_revision") + 1,
            "nonce": URL_SAFE_NO_PAD.encode([7u8; 24]),
            "ciphertext": URL_SAFE_NO_PAD.encode([0u8; 272]),
            "padded_size": 256,
            "content_type": SEALED_CONTENT_TYPE,
            "tombstone": false,
            "manifest": {
                "manifest_seq": row.get::<i64, _>("manifest_seq") + 1,
                "key_epoch": row.get::<i64, _>("key_epoch"),
                "latest_revision": row.get::<i64, _>("latest_revision") + 1,
                "object_count": 99,
                "digest": URL_SAFE_NO_PAD.encode([0u8; 32]),
                "device_id": state.device_id.to_string(),
                "signature": { "mldsa": "", "ed25519": "" }
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    pool.close().await;
}

// ── Account mutations need a device signature, not just a fresh token ──

/// A bearer token is no longer enough to replace the recovery wrap, which is how a
/// stolen token could destroy password-based recovery while looking legitimate.
#[tokio::test]
async fn a_password_change_without_a_device_signature_is_refused() {
    let dir = std::env::temp_dir().join(format!("sealbook-pwsig-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;
    let mut owner = SealbookClient::plaintext_http();
    owner
        .register(&base, "pwsigalice", "correct horse battery")
        .await
        .expect("register");
    let token = owner
        .state
        .as_ref()
        .and_then(|state| state.session_token.clone())
        .unwrap();

    // Start a real transaction, so only the signature is missing.
    let (request, _state) =
        sealbook_crypto::opaque::client_register_start(b"attacker password").unwrap();
    let start: serde_json::Value = reqwest::Client::new()
        .post(format!("{base}/v1/account/password/start"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "request": URL_SAFE_NO_PAD.encode(&request) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let response = reqwest::Client::new()
        .post(format!("{base}/v1/account/password"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "password_change_id": start["password_change_id"],
            "challenge": start["challenge"],
            "signature": { "mldsa": "", "ed25519": "" },
            "upload": URL_SAFE_NO_PAD.encode([0u8; 32]),
            "kdf_salt": URL_SAFE_NO_PAD.encode([0u8; 16]),
            "recovery_nonce": URL_SAFE_NO_PAD.encode([0u8; 24]),
            "recovery_wrapped_ck": URL_SAFE_NO_PAD.encode([0u8; 48]),
            "recovery_ciphersuite": "aead-recovery-argon2id-m65536-t3-p1"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

    // And the real thing still works.
    owner
        .change_password("correct horse battery", "a different passphrase")
        .await
        .expect("legitimate password change");
    assert!(owner.list_contacts().await.is_ok());
}

/// Deleting an account needs a device signature too.
#[tokio::test]
async fn deleting_an_account_without_a_device_signature_is_refused() {
    let dir = std::env::temp_dir().join(format!("sealbook-delsig-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;
    let mut owner = SealbookClient::plaintext_http();
    owner
        .register(&base, "delsigalice", "correct horse battery")
        .await
        .expect("register");
    let token = owner
        .state
        .as_ref()
        .and_then(|state| state.session_token.clone())
        .unwrap();

    let challenge: serde_json::Value = reqwest::Client::new()
        .post(format!("{base}/v1/account/challenge"))
        .bearer_auth(&token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let response = reqwest::Client::new()
        .delete(format!("{base}/v1/account"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "challenge_id": challenge["challenge_id"],
            "challenge": challenge["challenge"],
            "signature": { "mldsa": "", "ed25519": "" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(
        owner.list_contacts().await.is_ok(),
        "the account should still exist"
    );

    // The account holder's own device can still delete it.
    owner.delete_account().await.expect("delete");
}

/// Renaming an account is signed, and the signature covers the new name.
#[tokio::test]
async fn renaming_an_account_is_signed_and_keeps_the_vault_readable() {
    let dir = std::env::temp_dir().join(format!("sealbook-rename-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;
    let mut owner = SealbookClient::plaintext_http();
    owner
        .register(&base, "renamealice", "correct horse battery")
        .await
        .expect("register");
    owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Ada Lovelace"}}"#,
        )
        .await
        .expect("put");

    owner
        .change_username("renamedalice", "correct horse battery")
        .await
        .expect("rename");
    assert_eq!(owner.list_contacts().await.expect("list").len(), 1);
}

// ── Rotation on phrase change and recovery ──

/// Changing the phrase rotates the key, so the phrase it replaces cannot open the
/// vault any more — the wrap an old holder captured no longer decrypts.
#[tokio::test]
async fn changing_the_phrase_rotates_the_key_and_retires_the_old_one() {
    let dir = std::env::temp_dir().join(format!("sealbook-phrase-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;
    let mut owner = SealbookClient::plaintext_http();
    let old_phrase = owner
        .register(&base, "phrasealice", "correct horse battery")
        .await
        .expect("register");
    owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Ada Lovelace"}}"#,
        )
        .await
        .expect("put");
    let key_before = owner.collection_key().unwrap().as_bytes().to_vec();

    let new_phrase = owner
        .change_phrase("correct horse battery")
        .await
        .expect("change phrase");
    assert_ne!(new_phrase, old_phrase);
    assert_ne!(
        owner.collection_key().unwrap().as_bytes().to_vec(),
        key_before,
        "changing the phrase must rotate the collection key"
    );
    assert_eq!(owner.list_contacts().await.expect("list").len(), 1);

    // The retired phrase cannot recover any more.
    let mut stale = SealbookClient::plaintext_http();
    assert!(
        stale
            .recover(&base, "phrasealice", &old_phrase, "correct horse battery")
            .await
            .is_err(),
        "the replaced phrase must no longer recover the account"
    );

    // The new one can.
    let mut fresh = SealbookClient::plaintext_http();
    fresh
        .recover(&base, "phrasealice", &new_phrase, "correct horse battery")
        .await
        .expect("recover with the new phrase");
    assert_eq!(fresh.list_contacts().await.expect("list").len(), 1);
}

/// Recovery rotates too, so a phrase someone else has a copy of stops working the
/// moment it is used once.
#[tokio::test]
async fn recovery_rotates_the_key_so_the_used_phrase_stops_working() {
    let dir = std::env::temp_dir().join(format!("sealbook-recrot-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;
    let mut owner = SealbookClient::plaintext_http();
    let phrase = owner
        .register(&base, "recrotalice", "correct horse battery")
        .await
        .expect("register");
    owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Ada Lovelace"}}"#,
        )
        .await
        .expect("put");

    let mut recovered = SealbookClient::plaintext_http();
    let replacement = recovered
        .recover(&base, "recrotalice", &phrase, "correct horse battery")
        .await
        .expect("recover");
    assert_eq!(recovered.list_contacts().await.expect("list").len(), 1);
    assert_ne!(replacement, phrase, "recovery must issue a new phrase");

    // Someone else holding a copy of the phrase that was just used gets nothing.
    let mut attacker = SealbookClient::plaintext_http();
    assert!(
        attacker
            .recover(&base, "recrotalice", &phrase, "correct horse battery")
            .await
            .is_err(),
        "the used phrase must not work a second time"
    );
}

// ── Quotas and pagination ──

#[tokio::test]
async fn a_write_past_the_object_quota_is_refused() {
    let dir = std::env::temp_dir().join(format!("sealbook-quota-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = sealbook_server::app_with_limits(
        db.to_str().unwrap(),
        sealbook_server::Limits {
            max_objects: 2,
            max_bytes: 1024 * 1024,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let base = format!("http://{addr}");

    let mut owner = SealbookClient::plaintext_http();
    owner
        .register(&base, "quotaalice", "correct horse battery")
        .await
        .expect("register");
    for index in 0..2 {
        owner
            .put_contact(
                Uuid::new_v4(),
                &format!(r#"{{"@type":"Card","name":{{"full":"Contact {index}"}}}}"#),
            )
            .await
            .expect("put within quota");
    }
    let error = owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"One too many"}}"#,
        )
        .await
        .expect_err("a third object must be refused");
    assert!(error.to_string().contains("quota"), "wrong error: {error}");

    // Updating an object that already exists is still allowed at the ceiling.
    let existing = owner.list_contacts().await.expect("list")[0].0;
    owner
        .put_contact(
            existing,
            r#"{"@type":"Card","name":{"full":"Contact edited"}}"#,
        )
        .await
        .expect("an update must not count as a new object");
}

/// Deleting an object has to give its quota slot back.
///
/// A tombstone stays a row, and nothing compacts it, so counting one against
/// `max_objects` meant a vault that had been filled and emptied was permanently
/// full: every further write was refused although the account held nothing.
#[tokio::test]
async fn a_deleted_object_frees_its_quota_slot() {
    let dir = std::env::temp_dir().join(format!("sealbook-churn-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = sealbook_server::app_with_limits(
        db.to_str().unwrap(),
        sealbook_server::Limits {
            max_objects: 2,
            max_bytes: 1024 * 1024,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let base = format!("http://{addr}");

    let mut owner = SealbookClient::plaintext_http();
    owner
        .register(&base, "churnalice", "correct horse battery")
        .await
        .expect("register");

    let first = Uuid::new_v4();
    owner
        .put_contact(first, r#"{"@type":"Card","name":{"full":"First"}}"#)
        .await
        .expect("put first");
    owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Second"}}"#,
        )
        .await
        .expect("put second");
    owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"One too many"}}"#,
        )
        .await
        .expect_err("the vault is full");

    owner.delete_contact(first).await.expect("delete");

    // The tombstone still occupies a row, but the account holds one object, so
    // there is room for another.
    owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Replacement"}}"#,
        )
        .await
        .expect("a deleted object must free its slot");
    owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Still too many"}}"#,
        )
        .await
        .expect_err("the live ceiling still applies");

    let listed = owner.list_contacts().await.expect("list");
    assert_eq!(listed.len(), 2, "wrong live contents: {listed:?}");

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn the_change_feed_paginates() {
    let (_db, base, mut client) = account_with_contacts("paginate", 5).await;
    let state = client.state.as_ref().unwrap();
    let token = state.session_token.clone().unwrap();
    let collection = state.collection_id;

    let page: serde_json::Value = reqwest::Client::new()
        .get(format!(
            "{base}/v1/collections/{collection}/changes?after=0&limit=2"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page["objects"].as_array().unwrap().len(), 2);
    assert_eq!(page["has_more"], serde_json::json!(true));

    // Walking the pages reaches everything, which is what the client does.
    assert_eq!(client.list_contacts().await.expect("list").len(), 5);
}

#[tokio::test]
async fn a_changes_page_is_bounded_by_bytes_and_not_only_by_count() {
    let dir = std::env::temp_dir().join(format!("sealbook-bytecap-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let mut owner = SealbookClient::plaintext_http();
    owner
        .register(&base, "bytecap", "correct horse battery")
        .await
        .expect("register");
    let notebook = owner
        .ensure_default_notebook()
        .await
        .expect("default notebook");

    // Padded sizes are powers of two, so each of these pads to 4 MiB and three
    // of them cannot share one 8 MiB page.
    for index in 0..3 {
        owner
            .put_note(
                Uuid::new_v4(),
                &note_json(
                    &format!("big {index}"),
                    &"m".repeat(3 * 1024 * 1024),
                    notebook,
                ),
            )
            .await
            .expect("put a large note");
    }

    let state = owner.state.as_ref().unwrap();
    let token = state.session_token.clone().unwrap();
    let collection = state.collection_id;
    // `limit` well past the object count, so a page cut can only be the byte
    // ceiling doing it.
    let page: serde_json::Value = reqwest::Client::new()
        .get(format!(
            "{base}/v1/collections/{collection}/changes?after=0&limit=2000&snapshot=true"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let served = page["objects"].as_array().unwrap();
    assert_eq!(
        page["has_more"],
        serde_json::json!(true),
        "a page holding the whole vault was not cut"
    );
    let bytes: u64 = served
        .iter()
        .map(|object| object["padded_size"].as_u64().unwrap())
        .sum();
    assert!(
        bytes <= 8 * 1024 * 1024,
        "a page carried {bytes} bytes of ciphertext"
    );
    let large = served
        .iter()
        .filter(|object| object["padded_size"].as_u64().unwrap() == 4 * 1024 * 1024)
        .count();
    assert!(
        (1..3).contains(&large),
        "the page served {large} of the three large notes"
    );

    assert_eq!(owner.list_notes().await.expect("notes").len(), 3);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn authenticated_reads_are_metered_per_account_and_route() {
    let (dir, base, client) = account_with_contacts("readcap", 1).await;
    let state = client.state.as_ref().unwrap();
    let token = state.session_token.clone().unwrap();
    let collection = state.collection_id;
    let http = reqwest::Client::new();

    let mut refused_after = None;
    for attempt in 1..=700 {
        let status = http
            .get(format!(
                "{base}/v1/collections/{collection}/changes?after=0&limit=1"
            ))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            refused_after = Some(attempt);
            break;
        }
        assert!(status.is_success(), "unexpected {status} on read {attempt}");
    }
    let refused_after = refused_after.expect("an unmetered read route must become metered");
    assert!(
        refused_after > 100,
        "the budget has to leave room for a full sync, refused after {refused_after}"
    );

    // Per route, so exhausting the change feed does not take the manifest with
    // it: a client that has been throttled on one read can still check another.
    let manifest = http
        .get(format!("{base}/v1/collections/{collection}/manifest"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert!(manifest.status().is_success(), "{}", manifest.status());

    let _ = std::fs::remove_dir_all(&dir);
}

/// A rotation installs a new password KDF salt and a new recovery-phrase record.
#[tokio::test]
async fn the_incremental_manifest_digest_matches_a_full_rebuild() {
    use sealbook_crypto::{manifest_digest, ManifestDigestEntry};

    let dir = std::env::temp_dir().join(format!("sealbook-digest-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db_file = dir.join("sealbook.db");
    let base = spawn_http(db_file.to_str().unwrap()).await;

    let mut owner = SealbookClient::plaintext_http();
    owner
        .register(&base, "digestalice", "correct horse battery")
        .await
        .expect("register");

    // Ids with a chosen first byte, so objects deliberately share buckets: three
    // in bucket 0x11, three in 0x11 again after replacement, and some spread out.
    let id_in_bucket = |bucket: u8, tail: u8| {
        let mut bytes = [0u8; 16];
        bytes[0] = bucket;
        bytes[15] = tail;
        Uuid::from_bytes(bytes)
    };

    let mut ids = Vec::new();
    for tail in 0..6u8 {
        ids.push(id_in_bucket(0x11, tail));
    }
    for tail in 0..4u8 {
        ids.push(id_in_bucket(0xff, tail));
    }
    ids.push(id_in_bucket(0x00, 1));
    for (index, id) in ids.iter().enumerate() {
        owner
            .put_contact(
                *id,
                &format!(r#"{{"@type":"Card","name":{{"full":"Contact {index}"}}}}"#),
            )
            .await
            .expect("put");
    }

    // Replacements inside a shared bucket, then deletes, then a write after the
    // deletes — each one exercises a different branch of the bucket update.
    owner
        .put_contact(
            ids[0],
            r#"{"@type":"Card","name":{"full":"Edited nought"}}"#,
        )
        .await
        .expect("replace");
    owner
        .put_contact(ids[7], r#"{"@type":"Card","name":{"full":"Edited seven"}}"#)
        .await
        .expect("replace");
    owner.delete_contact(ids[2]).await.expect("delete");
    owner.delete_contact(ids[8]).await.expect("delete");
    owner
        .put_contact(
            id_in_bucket(0x11, 99),
            r#"{"@type":"Card","name":{"full":"Late"}}"#,
        )
        .await
        .expect("put after delete");

    // What the digest should be, computed the way a client does: one pass over
    // every entry, tombstones included.
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db_file.display()))
        .await
        .unwrap();
    let rows = sqlx::query("SELECT id, revision, tombstone, content_digest FROM objects")
        .fetch_all(&pool)
        .await
        .unwrap();
    let entries: Vec<ManifestDigestEntry> = rows
        .iter()
        .map(|row| {
            let mut content_digest = [0u8; 32];
            content_digest.copy_from_slice(&row.get::<Vec<u8>, _>("content_digest"));
            ManifestDigestEntry {
                id: Uuid::parse_str(&row.get::<String, _>("id")).unwrap(),
                revision: row.get::<i64, _>("revision") as u64,
                tombstone: row.get::<i64, _>("tombstone") != 0,
                content_digest,
            }
        })
        .collect();
    let expected = manifest_digest(&entries);

    let stored: Vec<u8> = sqlx::query_scalar("SELECT digest FROM manifests")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        stored,
        expected.to_vec(),
        "the stored manifest digest drifted from the objects"
    );

    // And the state's own count has to match the rows, since the root binds it.
    let (counted, real): (i64, i64) = (
        sqlx::query_scalar("SELECT object_count FROM manifest_digest_state")
            .fetch_one(&pool)
            .await
            .unwrap(),
        sqlx::query_scalar("SELECT COUNT(*) FROM objects")
            .fetch_one(&pool)
            .await
            .unwrap(),
    );
    assert_eq!(counted, real, "the bucket state's object count drifted");
    assert_eq!(real, 12, "wrong number of rows: {real}");
    pool.close().await;

    // A rotation rebuilds the state from scratch; the digest must land in the
    // same place the incremental path would have.
    let mut joiner = SealbookClient::plaintext_http();
    let (pair_code, confirm) = joiner.pair_join(&base, "digestalice").await.expect("join");
    owner
        .pair_approve(&pair_code, &confirm)
        .await
        .expect("approve");
    assert!(joiner.pair_ready(&pair_code).await.expect("ready"));
    joiner.login("correct horse battery").await.expect("login");
    let joiner_device = joiner.state.as_ref().unwrap().device_id;
    owner
        .revoke_device(joiner_device, "correct horse battery")
        .await
        .expect("revoke");

    // Still writable, which means the rebuilt state still agrees with the client.
    owner
        .put_contact(
            id_in_bucket(0x11, 200),
            r#"{"@type":"Card","name":{"full":"After rotation"}}"#,
        )
        .await
        .expect("a write after a rotation must agree with the rebuilt state");

    let listed = owner.list_contacts().await.expect("list");
    assert_eq!(listed.len(), 11, "wrong live contents: {listed:?}");

    let _ = std::fs::remove_dir_all(dir);
}

/// A rotation must not be able to tombstone an object it is re-encrypting.
#[tokio::test]
async fn a_rotation_that_tombstones_a_live_object_is_refused() {
    use sealbook_crypto::{
        generate_kdf_salt, generate_phrase, phrase_lookup_id, phrase_recovery_public,
        wrap_collection_key, wrap_for_device, wrap_for_phrase, DeviceHpkePublic,
        PHRASE_CIPHERSUITE, PHRASE_SCHEME, RECOVERY_CIPHERSUITE,
    };
    use sealbook_protocol::{
        DevicePublicKeys, ManifestBody, PhraseRecoveryBody, RotateRequest, RotatedObject,
    };

    let dir = std::env::temp_dir().join(format!("sealbook-rot-tomb-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let password = "correct horse battery";
    let mut owner = SealbookClient::plaintext_http();
    owner.register(&base, "tombalice", password).await.unwrap();
    let object_id = Uuid::new_v4();
    owner
        .put_contact(
            object_id,
            r#"{"@type":"Card","name":{"full":"Ada Lovelace"}}"#,
        )
        .await
        .expect("put");

    let state = owner.state.as_ref().unwrap();
    let (collection_id, device_id, token) = (
        state.collection_id,
        state.device_id,
        state.session_token.clone().unwrap(),
    );
    let http = reqwest::Client::new();
    let devices: Vec<DevicePublicKeys> = http
        .get(format!("{base}/v1/account/devices"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let device = devices
        .into_iter()
        .find(|candidate| candidate.device_id == device_id)
        .expect("the registering device must be enrolled");

    // Wraps the server will accept, so that the request reaches the object checks
    // rather than being turned away earlier.
    let new_ck = CollectionKey::generate();
    let salt = generate_kdf_salt();
    let (_phrase, entropy) = generate_phrase().unwrap();
    let device_wrap = wrap_for_device(&DeviceHpkePublic(device.xwing_hpke_pk.clone()), &new_ck)
        .expect("wrap for device");
    let recovery_wrap =
        wrap_collection_key(password.as_bytes(), &salt, &new_ck).expect("wrap for password");
    let phrase_wrap = wrap_for_phrase(&entropy, &new_ck).expect("wrap for phrase");
    let phrase_public = phrase_recovery_public(&entropy).unwrap();
    let key_epoch = owner.server_key_epoch().await.unwrap() + 1;

    // The live object, re-sent as a tombstone. Empty ciphertext and a zero padded
    // size are the shape a tombstone is allowed to have, so only the flag itself
    // is wrong.
    let request = RotateRequest {
        key_epoch,
        revoke_device_id: None,
        kdf_salt: salt.to_vec(),
        key_wraps: vec![
            KeyWrapBody {
                recipient_kind: "device".into(),
                recipient_id: device_id.to_string(),
                hpke_enc: device_wrap.enc,
                wrapped_ck: device_wrap.ciphertext,
                ciphersuite: XWING_CIPHERSUITE.into(),
            },
            KeyWrapBody {
                recipient_kind: "recovery".into(),
                recipient_id: "tombalice".into(),
                hpke_enc: recovery_wrap.nonce.to_vec(),
                wrapped_ck: recovery_wrap.ciphertext,
                ciphersuite: RECOVERY_CIPHERSUITE.into(),
            },
            KeyWrapBody {
                recipient_kind: "phrase".into(),
                recipient_id: "tombalice".into(),
                hpke_enc: phrase_wrap.nonce.to_vec(),
                wrapped_ck: phrase_wrap.ciphertext,
                ciphersuite: PHRASE_CIPHERSUITE.into(),
            },
        ],
        phrase_recovery: PhraseRecoveryBody {
            mldsa_pk: phrase_public.mldsa_pk.clone(),
            ed25519_pk: phrase_public.ed25519_pk.clone(),
            lookup_id: phrase_lookup_id(&entropy).unwrap().to_vec(),
            scheme: PHRASE_SCHEME.into(),
        },
        objects: vec![RotatedObject {
            id: object_id,
            revision: 2,
            nonce: Vec::new(),
            ciphertext: Vec::new(),
            padded_size: 0,
            content_type: SEALED_CONTENT_TYPE.into(),
            tombstone: true,
        }],
        manifest: ManifestBody {
            manifest_seq: 3,
            key_epoch,
            latest_revision: 2,
            object_count: 1,
            digest: vec![0u8; 32],
            device_id,
            signature: DualSignatureBody {
                mldsa: Vec::new(),
                ed25519: Vec::new(),
            },
        },
        rotation_signature: DualSignatureBody {
            mldsa: Vec::new(),
            ed25519: Vec::new(),
        },
        roster: hand_roster(
            collection_id,
            2,
            key_epoch,
            vec![device.clone()],
            phrase_public.mldsa_pk.clone(),
            phrase_public.ed25519_pk.clone(),
            sealbook_crypto::RosterSigner::Device(device_id),
            &DeviceSigningSecrets {
                mldsa_seed: owner.state.as_ref().unwrap().mldsa_seed.clone(),
                ed25519_sk: owner.state.as_ref().unwrap().ed25519_sk.clone(),
            },
            &new_ck,
        ),
        drop_tombstones: Vec::new(),
    };

    let response = http
        .post(format!("{base}/v1/collections/{collection_id}/rotate"))
        .bearer_auth(&token)
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    let body = response.text().await.unwrap();
    assert!(
        body.contains("tombstone"),
        "refused for the wrong reason: {body}"
    );

    // And the two tables still agree: the object is live in both.
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    let live: i64 = sqlx::query_scalar("SELECT tombstone FROM objects WHERE id = ?")
        .bind(object_id.to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(live, 0, "the object must still be live");
    let tombstoned_revisions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM object_revisions WHERE tombstone = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(tombstoned_revisions, 0, "a delete was logged anyway");
    pool.close().await;

    let _ = std::fs::remove_dir_all(dir);
}

/// able to modify a rotation body could therefore swap in a `lookup_id` and phrase
/// verification key it controlled, and then enrol a device of its own through the
/// recovery flow.
///
/// Built by hand rather than through the client, because the point is a body that
/// was modified *after* it was signed, which a client will never produce.
#[tokio::test]
async fn a_rotation_whose_recovery_material_was_modified_after_signing_is_refused() {
    use sealbook_crypto::{
        generate_kdf_salt, generate_phrase, key_rotation_transcript, key_wraps_digest,
        manifest_digest, manifest_transcript, phrase_lookup_id, phrase_recovery_public,
        rotated_objects_digest, rotation_recovery_payload, wrap_collection_key, wrap_for_device,
        wrap_for_phrase, DeviceHpkePublic, ObjectDigestEntry, WrapDigestEntry, PHRASE_CIPHERSUITE,
        PHRASE_SCHEME, RECOVERY_CIPHERSUITE,
    };
    use sealbook_protocol::{DevicePublicKeys, ManifestBody, PhraseRecoveryBody, RotateRequest};

    let dir = std::env::temp_dir().join(format!("sealbook-rot-tamper-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let password = "correct horse battery";
    let mut owner = SealbookClient::plaintext_http();
    owner
        .register(&base, "tamperalice", password)
        .await
        .unwrap();

    let state = owner.state.as_ref().unwrap();
    let (collection_id, device_id, token) = (
        state.collection_id,
        state.device_id,
        state.session_token.clone().unwrap(),
    );
    let secrets = DeviceSigningSecrets {
        mldsa_seed: state.mldsa_seed.clone(),
        ed25519_sk: state.ed25519_sk.clone(),
    };
    let http = reqwest::Client::new();

    // The device's X-Wing public key, to wrap the new collection key to it.
    let devices: Vec<DevicePublicKeys> = http
        .get(format!("{base}/v1/account/devices"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let device = devices
        .into_iter()
        .find(|candidate| candidate.device_id == device_id)
        .expect("the registering device must be enrolled");

    // A rotation of an empty vault: no objects to re-encrypt, so the only moving
    // parts are the wraps, the recovery record and the manifest.
    let new_ck = CollectionKey::generate();
    let salt = generate_kdf_salt();
    let (_phrase, entropy) = generate_phrase().unwrap();
    let device_wrap = wrap_for_device(&DeviceHpkePublic(device.xwing_hpke_pk.clone()), &new_ck)
        .expect("wrap for device");
    let recovery_wrap =
        wrap_collection_key(password.as_bytes(), &salt, &new_ck).expect("wrap for password");
    let phrase_wrap = wrap_for_phrase(&entropy, &new_ck).expect("wrap for phrase");
    let key_wraps = vec![
        KeyWrapBody {
            recipient_kind: "device".into(),
            recipient_id: device_id.to_string(),
            hpke_enc: device_wrap.enc,
            wrapped_ck: device_wrap.ciphertext,
            ciphersuite: XWING_CIPHERSUITE.into(),
        },
        KeyWrapBody {
            recipient_kind: "recovery".into(),
            recipient_id: "tamperalice".into(),
            hpke_enc: recovery_wrap.nonce.to_vec(),
            wrapped_ck: recovery_wrap.ciphertext,
            ciphersuite: RECOVERY_CIPHERSUITE.into(),
        },
        KeyWrapBody {
            recipient_kind: "phrase".into(),
            recipient_id: "tamperalice".into(),
            hpke_enc: phrase_wrap.nonce.to_vec(),
            wrapped_ck: phrase_wrap.ciphertext,
            ciphersuite: PHRASE_CIPHERSUITE.into(),
        },
    ];
    let phrase_public = phrase_recovery_public(&entropy).unwrap();
    let phrase_recovery = PhraseRecoveryBody {
        mldsa_pk: phrase_public.mldsa_pk.clone(),
        ed25519_pk: phrase_public.ed25519_pk.clone(),
        lookup_id: phrase_lookup_id(&entropy).unwrap().to_vec(),
        scheme: PHRASE_SCHEME.into(),
    };

    // An empty collection still gets a signed manifest, at the next sequence.
    let key_epoch = owner.server_key_epoch().await.unwrap() + 1;
    let empty_digest = manifest_digest(&[]);
    let manifest_seq = 2;
    let manifest_sig = sign(
        &secrets,
        &manifest_transcript(collection_id, manifest_seq, key_epoch, 0, 0, &empty_digest),
    )
    .unwrap();
    let manifest = ManifestBody {
        manifest_seq,
        key_epoch,
        latest_revision: 0,
        object_count: 0,
        digest: empty_digest.to_vec(),
        device_id,
        signature: DualSignatureBody {
            mldsa: manifest_sig.mldsa,
            ed25519: manifest_sig.ed25519,
        },
    };

    let wrap_entries: Vec<WrapDigestEntry<'_>> = key_wraps
        .iter()
        .map(|wrap| WrapDigestEntry {
            recipient_kind: &wrap.recipient_kind,
            recipient_id: &wrap.recipient_id,
            hpke_enc: &wrap.hpke_enc,
            wrapped_ck: &wrap.wrapped_ck,
            ciphersuite: &wrap.ciphersuite,
        })
        .collect();
    let no_objects: Vec<ObjectDigestEntry<'_>> = Vec::new();
    let signature = sign(
        &secrets,
        &key_rotation_transcript(
            collection_id,
            None,
            key_epoch,
            &key_wraps_digest(&wrap_entries),
            &rotated_objects_digest(&no_objects),
            &empty_digest,
            &rotation_recovery_payload(
                &salt,
                &phrase_recovery.mldsa_pk,
                &phrase_recovery.ed25519_pk,
                &phrase_recovery.lookup_id,
                &phrase_recovery.scheme,
            ),
        ),
    )
    .unwrap();
    let roster = hand_roster(
        collection_id,
        2,
        key_epoch,
        vec![device.clone()],
        phrase_recovery.mldsa_pk.clone(),
        phrase_recovery.ed25519_pk.clone(),
        sealbook_crypto::RosterSigner::Device(device_id),
        &secrets,
        &new_ck,
    );
    let valid = RotateRequest {
        key_epoch,
        revoke_device_id: None,
        kdf_salt: salt.to_vec(),
        key_wraps,
        phrase_recovery,
        objects: Vec::new(),
        manifest,
        rotation_signature: DualSignatureBody {
            mldsa: signature.mldsa,
            ed25519: signature.ed25519,
        },
        roster,
        drop_tombstones: Vec::new(),
    };
    let url = format!("{base}/v1/collections/{collection_id}/rotate");

    // Swap the phrase lookup id for one an attacker knows, leaving everything else
    // — including the signature — untouched. This is the request that used to be
    // accepted.
    let forged = RotateRequest {
        phrase_recovery: PhraseRecoveryBody {
            lookup_id: vec![0xAB; valid.phrase_recovery.lookup_id.len()],
            ..valid.phrase_recovery.clone()
        },
        ..valid.clone()
    };
    let response = http
        .post(&url)
        .bearer_auth(&token)
        .json(&forged)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        400,
        "a substituted phrase lookup id must be refused"
    );

    // The same for the KDF salt, which is what a password recovery is derived
    // against.
    let forged = RotateRequest {
        kdf_salt: vec![0xCD; valid.kdf_salt.len()],
        ..valid.clone()
    };
    let response = http
        .post(&url)
        .bearer_auth(&token)
        .json(&forged)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        400,
        "a substituted KDF salt must be refused"
    );

    // And the control: untouched, the same rotation is accepted. Without this the
    // assertions above would pass even if the request were malformed for some
    // unrelated reason.
    let response = http
        .post(&url)
        .bearer_auth(&token)
        .json(&valid)
        .send()
        .await
        .unwrap();
    let status = response.status();
    assert_eq!(
        status,
        200,
        "the unmodified rotation must be accepted: {}",
        response.text().await.unwrap_or_default()
    );
    assert_eq!(
        owner.server_key_epoch().await.unwrap(),
        key_epoch,
        "the accepted rotation must have advanced the key epoch"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Revisions age out, so a client can name a watermark whose successors are gone.
/// Serving the remaining tail would silently skip the writes in between, which is
/// the one thing a sync protocol must not do. The server answers with the full
/// current state and says so.
#[tokio::test]
async fn a_client_behind_the_retained_revisions_is_told_to_resync() {
    let dir = std::env::temp_dir().join(format!("sealbook-resync-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let mut owner = SealbookClient::plaintext_http();
    owner
        .register(&base, "resyncalice", "correct horse battery")
        .await
        .unwrap();
    for index in 0..4 {
        owner
            .put_contact(
                Uuid::new_v4(),
                &format!(r#"{{"@type":"Card","name":{{"full":"Contact {index}"}}}}"#),
            )
            .await
            .unwrap();
    }

    let state = owner.state.as_ref().unwrap();
    let (collection_id, token) = (state.collection_id, state.session_token.clone().unwrap());
    let http = reqwest::Client::new();
    let changes = |after: u64, snapshot: bool| {
        let (http, token, base) = (http.clone(), token.clone(), base.clone());
        async move {
            http.get(format!(
                "{base}/v1/collections/{collection_id}/changes?after={after}&snapshot={snapshot}"
            ))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap()
        }
    };

    // While the log is intact, an incremental request stays incremental.
    let page = changes(2, false).await;
    assert_eq!(page["resync"], serde_json::json!(false));
    assert_eq!(
        page["objects"].as_array().unwrap().len(),
        2,
        "revisions 3 and 4 should have been served incrementally"
    );

    // Age the log out from under the client, as the sweeper would.
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    sqlx::query("UPDATE object_revisions SET created_at = 0")
        .execute(&pool)
        .await
        .unwrap();
    let pruned = sealbook_server::prune_old_revisions(&pool, std::time::Duration::from_secs(60))
        .await
        .unwrap();
    assert!(pruned > 0, "the sweep should have reclaimed something");
    pool.close().await;

    // The same request now cannot be answered incrementally, and says so rather
    // than serving the tail and quietly dropping what came before it.
    let page = changes(2, false).await;
    assert_eq!(
        page["resync"],
        serde_json::json!(true),
        "a client past the retained floor must be told to resync"
    );
    assert!(
        page["objects"].as_array().unwrap().is_empty(),
        "the resync signal must not carry a partial snapshot, which would look \
         like an answer while omitting everything below the stale watermark"
    );

    // Restarting as a snapshot walk gets the whole collection, from live objects,
    // so nothing depends on what the sweep reclaimed.
    let page = changes(0, true).await;
    assert_eq!(page["resync"], serde_json::json!(true));
    assert_eq!(
        page["objects"].as_array().unwrap().len(),
        4,
        "a snapshot walk must carry the whole collection"
    );

    // A caught-up client is not sent round a resync just because the log is empty.
    let latest = page["latest_revision"].as_u64().unwrap();
    let page = changes(latest, false).await;
    assert_eq!(
        page["resync"],
        serde_json::json!(false),
        "a client already at the newest revision has nothing to resync"
    );
    assert!(page["objects"].as_array().unwrap().is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

/// Every enrolled device gets a wrap in every rotation, and a rotation carries the
/// whole vault in one request, so an unbounded device list makes revocation
/// progressively more expensive. It is also how someone holding a session token
/// would quietly keep a foothold.
///
/// The filler devices go in directly, because the pairing rate limit is reached
/// long before the cap is and this test is about the cap.
#[tokio::test]
async fn an_account_cannot_enrol_devices_without_limit() {
    let dir = std::env::temp_dir().join(format!("sealbook-devcap-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let password = "correct horse battery";
    let mut owner = SealbookClient::plaintext_http();
    owner.register(&base, "capalice", password).await.unwrap();
    let owner_device = owner.state.as_ref().unwrap().device_id;

    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    let account_id: String = sqlx::query_scalar("SELECT id FROM accounts WHERE username = ?")
        .bind("capalice")
        .fetch_one(&pool)
        .await
        .unwrap();
    let template = sqlx::query("SELECT mldsa_pk, ed25519_pk, xwing_hpke_pk FROM devices LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();

    // Registration enrolled one, so fill to one short of the cap.
    for _ in 0..14 {
        sqlx::query(
            "INSERT INTO devices (id, account_id, mldsa_pk, ed25519_pk, xwing_hpke_pk, created_at)
             VALUES (?, ?, ?, ?, ?, 0)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&account_id)
        .bind(template.get::<Vec<u8>, _>("mldsa_pk"))
        .bind(template.get::<Vec<u8>, _>("ed25519_pk"))
        .bind(template.get::<Vec<u8>, _>("xwing_hpke_pk"))
        .execute(&pool)
        .await
        .unwrap();
    }
    // Devices written straight into the table have to be in the signed roster
    // too, or the next pairing's roster could not match the server's.
    let enrolled: Vec<sealbook_protocol::DevicePublicKeys> = sqlx::query(
        "SELECT id, mldsa_pk, ed25519_pk, xwing_hpke_pk FROM devices WHERE account_id = ?",
    )
    .bind(&account_id)
    .fetch_all(&pool)
    .await
    .unwrap()
    .into_iter()
    .map(|row| sealbook_protocol::DevicePublicKeys {
        device_id: Uuid::parse_str(&row.get::<String, _>("id")).unwrap(),
        mldsa_pk: row.get("mldsa_pk"),
        ed25519_pk: row.get("ed25519_pk"),
        xwing_hpke_pk: row.get("xwing_hpke_pk"),
    })
    .collect();
    let (collection_id, phrase_mldsa_pk, phrase_ed25519_pk): (String, Vec<u8>, Vec<u8>) =
        sqlx::query_as(
            "SELECT c.id, a.phrase_mldsa_pk, a.phrase_ed25519_pk
             FROM accounts a JOIN collections c ON c.account_id = a.id WHERE a.id = ?",
        )
        .bind(&account_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let owner_state = owner.state.as_ref().unwrap();
    let filled = hand_roster(
        Uuid::parse_str(&collection_id).unwrap(),
        2,
        1,
        enrolled,
        phrase_mldsa_pk,
        phrase_ed25519_pk,
        sealbook_crypto::RosterSigner::Device(owner_device),
        &DeviceSigningSecrets {
            mldsa_seed: owner_state.mldsa_seed.clone(),
            ed25519_sk: owner_state.ed25519_sk.clone(),
        },
        owner.collection_key().unwrap(),
    );
    sqlx::query("INSERT INTO device_rosters (collection_id, roster_seq, body) VALUES (?, 2, ?)")
        .bind(&collection_id)
        .bind(serde_json::to_string(&filled).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    // The sixteenth is accepted; it is the last slot.
    let mut sixteenth = SealbookClient::plaintext_http();
    let (pair_code, confirm) = sixteenth.pair_join(&base, "capalice").await.unwrap();
    owner
        .pair_approve(&pair_code, &confirm)
        .await
        .expect("the last free slot must be usable");
    assert_eq!(owner.list_devices().await.expect("list").len(), 16);

    // The seventeenth is refused, and says what to do about it.
    let mut seventeenth = SealbookClient::plaintext_http();
    let (pair_code, confirm) = seventeenth.pair_join(&base, "capalice").await.unwrap();
    let message = owner
        .pair_approve(&pair_code, &confirm)
        .await
        .expect_err("enrolling past the cap must be refused")
        .to_string();
    assert!(
        message.contains("maximum number of devices"),
        "the refusal should say what to do about it, got: {message}"
    );

    // Revoking frees the slot, and the account is otherwise untouched.
    let victim = owner
        .list_devices()
        .await
        .unwrap()
        .into_iter()
        .map(|device| device.device_id)
        .find(|id| *id != owner_device)
        .unwrap();
    owner.revoke_device(victim, password).await.expect("revoke");
    assert_eq!(owner.list_devices().await.expect("list").len(), 15);

    let mut replacement = SealbookClient::plaintext_http();
    let (pair_code, confirm) = replacement.pair_join(&base, "capalice").await.unwrap();
    owner
        .pair_approve(&pair_code, &confirm)
        .await
        .expect("a freed slot must be usable");

    let _ = std::fs::remove_dir_all(&dir);
}

/// #4: `recover_finish` enrolled its device as the first statement of its
/// transaction, so an account at the cap could not recover at all. Freeing a
/// slot needs a revocation, a revocation needs a session, and a session needs
/// the password the phrase exists to replace.
#[tokio::test]
async fn an_account_at_the_device_cap_can_still_recover() {
    let dir = std::env::temp_dir().join(format!("sealbook-caprecover-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let forgotten = "correct horse battery";
    let mut owner = SealbookClient::plaintext_http();
    let phrase = owner.register(&base, "capcarol", forgotten).await.unwrap();
    let owner_device = owner.state.as_ref().unwrap().device_id;
    owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Ada Lovelace"}}"#,
        )
        .await
        .unwrap();

    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    let account_id: String = sqlx::query_scalar("SELECT id FROM accounts WHERE username = ?")
        .bind("capcarol")
        .fetch_one(&pool)
        .await
        .unwrap();
    let template = sqlx::query("SELECT mldsa_pk, ed25519_pk, xwing_hpke_pk FROM devices LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();

    // Registration enrolled one, so fill the remaining fifteen slots.
    for _ in 0..15 {
        sqlx::query(
            "INSERT INTO devices (id, account_id, mldsa_pk, ed25519_pk, xwing_hpke_pk, created_at)
             VALUES (?, ?, ?, ?, ?, 0)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&account_id)
        .bind(template.get::<Vec<u8>, _>("mldsa_pk"))
        .bind(template.get::<Vec<u8>, _>("ed25519_pk"))
        .bind(template.get::<Vec<u8>, _>("xwing_hpke_pk"))
        .execute(&pool)
        .await
        .unwrap();
    }
    let enrolled: Vec<sealbook_protocol::DevicePublicKeys> = sqlx::query(
        "SELECT id, mldsa_pk, ed25519_pk, xwing_hpke_pk FROM devices WHERE account_id = ?",
    )
    .bind(&account_id)
    .fetch_all(&pool)
    .await
    .unwrap()
    .into_iter()
    .map(|row| sealbook_protocol::DevicePublicKeys {
        device_id: Uuid::parse_str(&row.get::<String, _>("id")).unwrap(),
        mldsa_pk: row.get("mldsa_pk"),
        ed25519_pk: row.get("ed25519_pk"),
        xwing_hpke_pk: row.get("xwing_hpke_pk"),
    })
    .collect();
    assert_eq!(enrolled.len(), 16, "the account must start at the cap");
    let (collection_id, phrase_mldsa_pk, phrase_ed25519_pk): (String, Vec<u8>, Vec<u8>) =
        sqlx::query_as(
            "SELECT c.id, a.phrase_mldsa_pk, a.phrase_ed25519_pk
             FROM accounts a JOIN collections c ON c.account_id = a.id WHERE a.id = ?",
        )
        .bind(&account_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let owner_state = owner.state.as_ref().unwrap();
    let filled = hand_roster(
        Uuid::parse_str(&collection_id).unwrap(),
        2,
        1,
        enrolled,
        phrase_mldsa_pk,
        phrase_ed25519_pk,
        sealbook_crypto::RosterSigner::Device(owner_device),
        &DeviceSigningSecrets {
            mldsa_seed: owner_state.mldsa_seed.clone(),
            ed25519_sk: owner_state.ed25519_sk.clone(),
        },
        owner.collection_key().unwrap(),
    );
    sqlx::query("INSERT INTO device_rosters (collection_id, roster_seq, body) VALUES (?, 2, ?)")
        .bind(&collection_id)
        .bind(serde_json::to_string(&filled).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    // The cap really is reached: a pairing from the live session is refused.
    let mut extra = SealbookClient::plaintext_http();
    let (pair_code, confirm) = extra.pair_join(&base, "capcarol").await.unwrap();
    assert!(
        owner.pair_approve(&pair_code, &confirm).await.is_err(),
        "a pairing past the cap must still be refused"
    );

    // The phrase gets in anyway, and the vault comes back decrypted.
    let chosen = "a different password entirely";
    let mut recovered = SealbookClient::plaintext_http();
    let next_phrase = recovered
        .recover(&base, "capcarol", &phrase, chosen)
        .await
        .expect("a full device list must not make an account unrecoverable");
    assert_eq!(next_phrase.split_whitespace().count(), 24);
    let contacts = recovered.list_contacts().await.expect("read the vault");
    assert_eq!(contacts.len(), 1);
    assert!(contacts[0].1.contains("Ada Lovelace"));
    assert_eq!(
        recovered.list_devices().await.expect("list").len(),
        17,
        "recovery takes a slot past the cap rather than being refused one"
    );

    // And the slot it took is reclaimable, from the session it just obtained.
    let victim = recovered
        .list_devices()
        .await
        .unwrap()
        .into_iter()
        .map(|device| device.device_id)
        .find(|id| *id != recovered.state.as_ref().unwrap().device_id)
        .unwrap();
    recovered
        .revoke_device(victim, chosen)
        .await
        .expect("revoke");
    assert_eq!(recovered.list_devices().await.expect("list").len(), 16);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn the_quota_counters_never_drift_from_the_objects() {
    let dir = std::env::temp_dir().join(format!("sealbook-usage-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let db_path = db.to_str().unwrap().to_string();
    let base = spawn_http(&db_path).await;

    let mut owner = SealbookClient::plaintext_http();
    owner
        .register(&base, "usagealice", "correct horse battery")
        .await
        .expect("register");

    let check = |label: &'static str, path: String| async move {
        let pool = sqlx::SqlitePool::connect(&format!("sqlite://{path}"))
            .await
            .expect("open db");
        let row = sqlx::query(
            "SELECT r.object_count, r.byte_total, r.tombstone_count,
                    (SELECT COUNT(*) FROM objects o WHERE o.account_id = r.account_id)
                        AS real_count,
                    (SELECT COALESCE(SUM(padded_size), 0) FROM objects o
                      WHERE o.account_id = r.account_id) AS real_bytes,
                    (SELECT COALESCE(SUM(tombstone), 0) FROM objects o
                      WHERE o.account_id = r.account_id) AS real_tombstones
             FROM revision_seq r",
        )
        .fetch_one(&pool)
        .await
        .expect("read usage");
        pool.close().await;
        let (stored_count, stored_bytes, stored_tombstones): (i64, i64, i64) = (
            row.get("object_count"),
            row.get("byte_total"),
            row.get("tombstone_count"),
        );
        let (real_count, real_bytes, real_tombstones): (i64, i64, i64) = (
            row.get("real_count"),
            row.get("real_bytes"),
            row.get("real_tombstones"),
        );
        assert_eq!(
            (stored_count, stored_bytes, stored_tombstones),
            (real_count, real_bytes, real_tombstones),
            "counters drifted after {label}: stored {stored_count} objects / \
             {stored_bytes} bytes / {stored_tombstones} tombstones, objects say \
             {real_count} / {real_bytes} / {real_tombstones}"
        );
        real_count
    };

    // Three new objects.
    let mut ids = Vec::new();
    for index in 0..3 {
        let id = Uuid::new_v4();
        ids.push(id);
        owner
            .put_contact(
                id,
                &format!(r#"{{"@type":"Card","name":{{"full":"Contact {index}"}}}}"#),
            )
            .await
            .expect("put");
    }
    assert_eq!(check("three inserts", db_path.clone()).await, 3);

    // A replacement must not change the count.
    owner
        .put_contact(ids[0], r#"{"@type":"Card","name":{"full":"Edited"}}"#)
        .await
        .expect("replace");
    assert_eq!(check("a replacement", db_path.clone()).await, 3);

    // A replacement large enough to land in a different padding bucket.
    let bulky = format!(
        r#"{{"@type":"Card","name":{{"full":"{}"}}}}"#,
        "x".repeat(4096)
    );
    owner.put_contact(ids[1], &bulky).await.expect("grow");
    assert_eq!(check("a size change", db_path.clone()).await, 3);

    // A tombstone stays a row, so the count holds. :)
    owner.delete_contact(ids[2]).await.expect("delete");
    assert_eq!(check("a tombstone", db_path.clone()).await, 3);

    // A rotation re-pads every object, which moves the byte total, and now runs
    // with a tombstone already in the vault.
    let mut joiner = SealbookClient::plaintext_http();
    let (pair_code, confirm) = joiner.pair_join(&base, "usagealice").await.expect("join");
    owner
        .pair_approve(&pair_code, &confirm)
        .await
        .expect("approve");
    assert!(joiner.pair_ready(&pair_code).await.expect("ready"));
    joiner.login("correct horse battery").await.expect("login");
    let joiner_device = joiner.state.as_ref().unwrap().device_id;
    owner
        .revoke_device(joiner_device, "correct horse battery")
        .await
        .expect("revoke");
    assert_eq!(check("a key rotation", db_path.clone()).await, 3);

    let _ = std::fs::remove_dir_all(dir);
}

/// Revoking a device must work on a vault that has had something deleted.
///
/// A rotation cannot re-encrypt a tombstone, there being no plaintext left, but
/// the manifest commits to every row in the collection. The client used to omit
/// tombstones from the manifest it signed, so the server found it one entry short
/// and refused the rotation. Revocation is the operation that most needs to work,
/// and every path that invalidates a collection key goes through it.
#[tokio::test]
async fn a_revocation_succeeds_with_a_tombstone_in_the_vault() {
    let dir = std::env::temp_dir().join(format!("sealbook-tombrot-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let mut owner = SealbookClient::plaintext_http();
    owner
        .register(&base, "tombalice", "correct horse battery")
        .await
        .expect("register");
    let keep = Uuid::new_v4();
    let doomed = Uuid::new_v4();
    owner
        .put_contact(keep, r#"{"@type":"Card","name":{"full":"Ada Lovelace"}}"#)
        .await
        .expect("put keep");
    owner
        .put_contact(doomed, r#"{"@type":"Card","name":{"full":"Deleted Soon"}}"#)
        .await
        .expect("put doomed");
    owner.delete_contact(doomed).await.expect("delete");

    let mut joiner = SealbookClient::plaintext_http();
    let (code, confirm) = joiner.pair_join(&base, "tombalice").await.expect("join");
    owner.pair_approve(&code, &confirm).await.expect("approve");
    assert!(joiner.pair_ready(&code).await.expect("ready"));
    joiner.login("correct horse battery").await.expect("login");
    let stolen_key = joiner.collection_key().unwrap().as_bytes().to_vec();
    let joiner_device = joiner.state.as_ref().unwrap().device_id;

    owner
        .revoke_device(joiner_device, "correct horse battery")
        .await
        .expect("a tombstone must not block revocation");

    // The key really rotated, and the surviving object still reads back.
    assert_ne!(
        owner.collection_key().unwrap().as_bytes().to_vec(),
        stolen_key,
        "the collection key was not rotated"
    );
    let contacts = owner.list_contacts().await.expect("list");
    assert_eq!(
        contacts.len(),
        1,
        "the live object must survive: {contacts:?}"
    );
    assert_eq!(contacts[0].0, keep);
    assert!(contacts[0].1.contains("Ada Lovelace"));

    let _ = std::fs::remove_dir_all(dir);
}

/// Deleting an account must leave nothing of it behind, in any table.
///
/// The tables are read from the schema rather than listed here, so a table added
/// later without a cascade back to `accounts` fails this test instead of quietly
/// retaining rows after someone asks to be forgotten.
#[tokio::test]
async fn deleting_an_account_leaves_nothing_in_any_table() {
    let dir = std::env::temp_dir().join(format!("sealbook-erase-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let mut owner = SealbookClient::plaintext_http();
    owner
        .register(&base, "erasealice", "correct horse battery")
        .await
        .expect("register");

    // Something in every table that hangs off the account: objects and their
    // revisions, a tombstone, a second device, extra sessions and key wraps.
    let keep = Uuid::new_v4();
    let doomed = Uuid::new_v4();
    owner
        .put_contact(keep, r#"{"@type":"Card","name":{"full":"Ada Lovelace"}}"#)
        .await
        .expect("put");
    owner
        .put_contact(doomed, r#"{"@type":"Card","name":{"full":"Gone"}}"#)
        .await
        .expect("put");
    owner.delete_contact(doomed).await.expect("delete contact");
    owner
        .put_contact(keep, r#"{"@type":"Card","name":{"full":"Ada, edited"}}"#)
        .await
        .expect("revise");

    let mut joiner = SealbookClient::plaintext_http();
    let (code, confirm) = joiner.pair_join(&base, "erasealice").await.expect("join");
    owner.pair_approve(&code, &confirm).await.expect("approve");
    assert!(joiner.pair_ready(&code).await.expect("ready"));
    joiner.login("correct horse battery").await.expect("login");

    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .expect("open db");
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != 'meta'",
    )
    .fetch_all(&pool)
    .await
    .expect("list tables");
    assert!(tables.len() >= 9, "schema looks wrong: {tables:?}");

    // Everything is populated before the delete, or the test proves nothing.
    for table in &tables {
        let rows: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&pool)
            .await
            .expect("count");
        assert!(
            rows > 0,
            "{table} was empty before the delete, so it proves nothing"
        );
    }

    owner.delete_account().await.expect("delete account");

    for table in &tables {
        let rows: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(
            rows, 0,
            "{table} still holds {rows} row(s) after the account was deleted"
        );
    }

    // The server's own secrets are not account data and must survive.
    let secrets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta")
        .fetch_one(&pool)
        .await
        .expect("count meta");
    assert!(secrets > 0, "deleting an account wiped the server keys");

    pool.close().await;
    let _ = std::fs::remove_dir_all(dir);
}

/// Writes a device the server controls straight into the account, as a malicious
/// or compromised server would. Returns its id.
async fn inject_device(db: &std::path::Path, username: &str) -> Uuid {
    let (_, hpke_pk) = generate_device_hpke().unwrap();
    let (_, sign_pk) = generate_device_signing().unwrap();
    let device_id = Uuid::new_v4();
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO devices (id, account_id, mldsa_pk, ed25519_pk, xwing_hpke_pk, created_at)
         SELECT ?, id, ?, ?, ?, 0 FROM accounts WHERE username = ?",
    )
    .bind(device_id.to_string())
    .bind(&sign_pk.mldsa_pk)
    .bind(&sign_pk.ed25519_pk)
    .bind(&hpke_pk.0)
    .bind(username)
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;
    device_id
}

/// The finding this roster exists for: a device the server adds on its own is
/// never handed the collection key, and its manifests are not believed.
#[tokio::test]
async fn a_device_the_server_injects_never_receives_the_collection_key() {
    let dir = std::env::temp_dir().join(format!("sealbook-inject-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let password = "correct horse battery";
    let mut owner = SealbookClient::plaintext_http();
    owner
        .register(&base, "injectalice", password)
        .await
        .unwrap();
    owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Ada Lovelace"}}"#,
        )
        .await
        .unwrap();

    let injected = inject_device(&db, "injectalice").await;
    let unsigned: Vec<sealbook_protocol::DevicePublicKeys> = reqwest::Client::new()
        .get(format!("{base}/v1/account/devices"))
        .bearer_auth(owner.state.as_ref().unwrap().session_token.clone().unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        unsigned.iter().any(|device| device.device_id == injected),
        "the server's own list does show the injected device"
    );
    let verified = owner.list_devices().await.unwrap();
    assert!(
        verified.iter().all(|device| device.device_id != injected),
        "the verified roster must not"
    );

    // A rotation wraps only for the roster, so the server, which expects a wrap
    // for its device too, refuses it. Refusing is the safe failure: no key left.
    assert!(owner.change_phrase(password).await.is_err());
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    let wraps: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM key_wraps WHERE recipient_kind = 'device' AND recipient_id = ?",
    )
    .bind(injected.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        wraps, 0,
        "the injected device was wrapped the collection key"
    );
    pool.close().await;

    let _ = std::fs::remove_dir_all(&dir);
}

/// With a device of its own it can sign for, a server could otherwise withhold
/// the whole vault behind a manifest that matches what it serves.
#[tokio::test]
async fn a_manifest_signed_by_an_injected_device_is_rejected() {
    let dir = std::env::temp_dir().join(format!("sealbook-inject-mf-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let mut owner = SealbookClient::plaintext_http();
    owner
        .register(&base, "withholdalice", "correct horse battery")
        .await
        .unwrap();
    owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Ada Lovelace"}}"#,
        )
        .await
        .unwrap();
    assert_eq!(owner.list_contacts().await.unwrap().len(), 1);

    let (secrets, public) = generate_device_signing().unwrap();
    let (_, hpke_pk) = generate_device_hpke().unwrap();
    let injected = Uuid::new_v4();
    let collection_id = owner.state.as_ref().unwrap().collection_id;
    let empty = sealbook_crypto::manifest_digest(&[]);
    let signature = sign(
        &secrets,
        &sealbook_crypto::manifest_transcript(collection_id, 99, 1, 2, 0, &empty),
    )
    .unwrap();

    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO devices (id, account_id, mldsa_pk, ed25519_pk, xwing_hpke_pk, created_at)
         SELECT ?, id, ?, ?, ?, 0 FROM accounts WHERE username = 'withholdalice'",
    )
    .bind(injected.to_string())
    .bind(&public.mldsa_pk)
    .bind(&public.ed25519_pk)
    .bind(&hpke_pk.0)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("DELETE FROM objects WHERE collection_id = ?")
        .bind(collection_id.to_string())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE manifests SET manifest_seq = 99, latest_revision = 2, object_count = 0,
             digest = ?, device_id = ?, mldsa_sig = ?, ed25519_sig = ?
         WHERE collection_id = ?",
    )
    .bind(empty.to_vec())
    .bind(injected.to_string())
    .bind(&signature.mldsa)
    .bind(&signature.ed25519)
    .bind(collection_id.to_string())
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;

    let error = owner
        .list_contacts()
        .await
        .expect_err("an empty vault signed by the server's device must not be believed")
        .to_string();
    assert!(
        error.contains("does not have"),
        "expected the signer to be unknown, got: {error}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Forging the roster history itself fails both ways: a pinned device sees a step
/// no member signed, and a device with no pin sees a MAC it cannot verify.
#[tokio::test]
async fn a_forged_roster_is_rejected_with_or_without_a_pin() {
    let dir = std::env::temp_dir().join(format!("sealbook-roster-forge-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let password = "correct horse battery";
    let mut owner = SealbookClient::plaintext_http();
    owner.register(&base, "forgealice", password).await.unwrap();
    let state = owner.state.clone().unwrap();

    let (attacker_secrets, attacker_public) = generate_device_signing().unwrap();
    let (_, attacker_hpke) = generate_device_hpke().unwrap();
    let attacker = sealbook_protocol::DevicePublicKeys {
        device_id: Uuid::new_v4(),
        mldsa_pk: attacker_public.mldsa_pk.clone(),
        ed25519_pk: attacker_public.ed25519_pk.clone(),
        xwing_hpke_pk: attacker_hpke.0.clone(),
    };
    let mut devices = owner.list_devices().await.unwrap();
    devices.push(attacker.clone());

    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    let (phrase_mldsa_pk, phrase_ed25519_pk): (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT phrase_mldsa_pk, phrase_ed25519_pk FROM accounts WHERE username = 'forgealice'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    // Signed by the server's own device and MAC'd under a key it made up, since
    // it has neither a member's signing key nor the collection key.
    let forged = hand_roster(
        state.collection_id,
        2,
        1,
        devices,
        phrase_mldsa_pk,
        phrase_ed25519_pk,
        sealbook_crypto::RosterSigner::Device(attacker.device_id),
        &attacker_secrets,
        &CollectionKey::generate(),
    );
    sqlx::query(
        "INSERT INTO devices (id, account_id, mldsa_pk, ed25519_pk, xwing_hpke_pk, created_at)
         SELECT ?, id, ?, ?, ?, 0 FROM accounts WHERE username = 'forgealice'",
    )
    .bind(attacker.device_id.to_string())
    .bind(&attacker.mldsa_pk)
    .bind(&attacker.ed25519_pk)
    .bind(&attacker.xwing_hpke_pk)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO device_rosters (collection_id, roster_seq, body) VALUES (?, 2, ?)")
        .bind(state.collection_id.to_string())
        .bind(serde_json::to_string(&forged).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    assert!(
        owner.list_devices().await.is_err(),
        "a pinned device accepted a roster step no member signed"
    );
    assert!(owner.change_phrase(password).await.is_err());

    let mut unpinned_state = state.clone();
    unpinned_state.roster_seq = 0;
    unpinned_state.roster_transcript.clear();
    let mut unpinned = SealbookClient::with_state(unpinned_state);
    let error = unpinned
        .login(password)
        .await
        .expect_err("a device with no pin accepted a roster the server made up")
        .to_string();
    assert!(error.contains("roster"), "got: {error}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Bug #2: the pin that makes a rollback detectable has to actually advance.
///
/// Rolls the server back to an *earlier manifest it really signed*, with the
/// objects that match it. Everything a client checks within a single response
/// agrees: the digest covers the entries served, the signature verifies, and the
/// signer is enrolled. The only thing that can catch it is the device
/// remembering a higher sequence, so this is the test that fails if the pin
/// stops advancing.
#[tokio::test]
async fn a_genuine_but_older_manifest_is_refused_once_a_newer_one_was_seen() {
    let dir = std::env::temp_dir().join(format!("sealbook-pin-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let mut client = SealbookClient::plaintext_http();
    client
        .register(&base, "pinalice", "correct horse battery")
        .await
        .expect("register");
    // Registration signs the collection's first manifest.
    assert_eq!(client.state.as_ref().unwrap().manifest_seq, 1);

    client
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Ada Lovelace"}}"#,
        )
        .await
        .expect("first put");
    assert_eq!(
        client.state.as_ref().unwrap().manifest_seq,
        2,
        "a write must pin the manifest sequence it signed"
    );

    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    // The collection exactly as it stands at manifest 2.
    let saved_objects = sqlx::query(
        "SELECT id, collection_id, account_id, revision, tombstone, ciphertext, nonce,
                padded_size, content_type, content_digest FROM objects",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let saved_manifest = sqlx::query(
        "SELECT manifest_seq, key_epoch, latest_revision, object_count, digest, device_id,
                mldsa_sig, ed25519_sig, collection_id FROM manifests",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    client
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Grace Hopper"}}"#,
        )
        .await
        .expect("second put");
    assert_eq!(client.state.as_ref().unwrap().manifest_seq, 3);
    // A read of the current state leaves the pin where it is.
    assert_eq!(client.list_contacts().await.expect("list").len(), 2);
    assert_eq!(client.state.as_ref().unwrap().manifest_seq, 3);

    // Now wind the vault back to manifest 2, Grace Hopper and all.
    sqlx::query("DELETE FROM objects")
        .execute(&pool)
        .await
        .unwrap();
    for row in &saved_objects {
        sqlx::query(
            "INSERT INTO objects (id, collection_id, account_id, revision, tombstone, ciphertext,
                 nonce, padded_size, content_type, content_digest)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(row.get::<String, _>("id"))
        .bind(row.get::<String, _>("collection_id"))
        .bind(row.get::<String, _>("account_id"))
        .bind(row.get::<i64, _>("revision"))
        .bind(row.get::<i64, _>("tombstone"))
        .bind(row.get::<Vec<u8>, _>("ciphertext"))
        .bind(row.get::<Vec<u8>, _>("nonce"))
        .bind(row.get::<i64, _>("padded_size"))
        .bind(row.get::<String, _>("content_type"))
        .bind(row.get::<Vec<u8>, _>("content_digest"))
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query(
        "UPDATE manifests SET manifest_seq = ?, key_epoch = ?, latest_revision = ?,
             object_count = ?, digest = ?, device_id = ?, mldsa_sig = ?, ed25519_sig = ?
         WHERE collection_id = ?",
    )
    .bind(saved_manifest.get::<i64, _>("manifest_seq"))
    .bind(saved_manifest.get::<i64, _>("key_epoch"))
    .bind(saved_manifest.get::<i64, _>("latest_revision"))
    .bind(saved_manifest.get::<i64, _>("object_count"))
    .bind(saved_manifest.get::<Vec<u8>, _>("digest"))
    .bind(saved_manifest.get::<String, _>("device_id"))
    .bind(saved_manifest.get::<Vec<u8>, _>("mldsa_sig"))
    .bind(saved_manifest.get::<Vec<u8>, _>("ed25519_sig"))
    .bind(saved_manifest.get::<String, _>("collection_id"))
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;

    let error = client
        .list_contacts()
        .await
        .expect_err("a manifest older than the one this device has seen must be refused")
        .to_string();
    assert!(
        error.contains("went backwards"),
        "expected a rollback to be named as such, got: {error}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A fresh device, with no pin of its own yet, still has to end up pinned by the
/// state it is handed, or the first thing it does is trust a replay.
#[tokio::test]
async fn a_paired_device_pins_the_manifest_it_syncs() {
    let dir = std::env::temp_dir().join(format!("sealbook-pin-pair-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let password = "correct horse battery";
    let mut owner = SealbookClient::plaintext_http();
    owner.register(&base, "pinbob", password).await.unwrap();
    owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Ada Lovelace"}}"#,
        )
        .await
        .unwrap();

    let mut joiner = SealbookClient::plaintext_http();
    let (pair_code, confirm) = joiner.pair_join(&base, "pinbob").await.unwrap();
    owner.pair_approve(&pair_code, &confirm).await.unwrap();
    joiner.login(password).await.unwrap();
    assert_eq!(joiner.state.as_ref().unwrap().manifest_seq, 0);

    assert_eq!(joiner.list_contacts().await.expect("list").len(), 1);
    assert_eq!(
        joiner.state.as_ref().unwrap().manifest_seq,
        2,
        "reading the vault must pin the manifest the server served"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Bug #3: a recovery enrols a device but cannot rotate the collection key, so
/// until a client does, the phrase it used still opens the vault. The server
/// records the debt and holds the account to it.
#[tokio::test]
async fn an_interrupted_recovery_blocks_writes_until_the_key_is_rotated() {
    let dir = std::env::temp_dir().join(format!("sealbook-owed-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let password = "correct horse battery";
    let mut owner = SealbookClient::plaintext_http();
    owner.register(&base, "owedalice", password).await.unwrap();
    owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Ada Lovelace"}}"#,
        )
        .await
        .expect("a write before the recovery");

    // The state a recovery leaves behind when the client dies before rotating.
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    sqlx::query("UPDATE accounts SET recovery_pending = 1 WHERE username = 'owedalice'")
        .execute(&pool)
        .await
        .unwrap();

    let error = owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Grace Hopper"}}"#,
        )
        .await
        .expect_err("writing with a rotation owed must be refused")
        .to_string();
    assert!(
        error.contains("unfinished recovery"),
        "the refusal should say what is owed, got: {error}"
    );

    // Reading has to keep working, because a rotation re-encrypts what it reads.
    assert_eq!(owner.list_contacts().await.expect("read").len(), 1);

    let phrase = owner
        .complete_recovery_rotation(password)
        .await
        .expect("finishing the recovery");
    assert_eq!(phrase.split_whitespace().count(), 24);

    let pending: i64 =
        sqlx::query_scalar("SELECT recovery_pending FROM accounts WHERE username = 'owedalice'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(pending, 0, "the rotation must settle the debt");
    pool.close().await;

    owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Grace Hopper"}}"#,
        )
        .await
        .expect("writing again once the key has been rotated");
    assert_eq!(owner.list_contacts().await.expect("read").len(), 2);

    let _ = std::fs::remove_dir_all(&dir);
}

/// The same interruption, driven through the real recovery endpoints: enrol a
/// device and stop, exactly where a crashed client would. The phrase used stays
/// live until the rotation, so the next login must refuse to carry on quietly.
#[tokio::test]
async fn a_recovery_that_never_rotated_is_caught_at_the_next_login() {
    let dir = std::env::temp_dir().join(format!("sealbook-owed-e2e-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let password = "correct horse battery";
    let mut owner = SealbookClient::plaintext_http();
    let first_phrase = owner.register(&base, "owedbob", password).await.unwrap();
    owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Ada Lovelace"}}"#,
        )
        .await
        .unwrap();
    let entropy = entropy_from_phrase(&first_phrase).unwrap();

    // Recover onto a new device and go no further.
    let http = reqwest::Client::new();
    let (opaque_request, registration) = client_register_start(password.as_bytes()).unwrap();
    let start: RecoverStartResponse = http
        .post(format!("{base}/v1/recover/start"))
        .json(&RecoverStartRequest {
            username: "owedbob".into(),
            lookup_id: phrase_lookup_id(&entropy).unwrap().to_vec(),
            opaque_request,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let (hpke_sk, hpke_pk) = generate_device_hpke().unwrap();
    let (sign_sk, sign_pk) = generate_device_signing().unwrap();
    let device_id = Uuid::new_v4();
    let device = sealbook_protocol::DevicePublicKeys {
        device_id,
        mldsa_pk: sign_pk.mldsa_pk.clone(),
        ed25519_pk: sign_pk.ed25519_pk.clone(),
        xwing_hpke_pk: hpke_pk.0.clone(),
    };
    let enrollment = sign(
        &sign_sk,
        &enrollment_transcript(
            device_id,
            &sign_pk.mldsa_pk,
            &sign_pk.ed25519_pk,
            &hpke_pk.0,
        ),
    )
    .unwrap();
    let wrap = wrap_for_device(&hpke_pk, owner.collection_key().unwrap()).unwrap();
    let pw = recovery_password(
        password,
        &start.opaque_response,
        registration,
        owner.collection_key().unwrap(),
    );
    let proof = sign_phrase_recovery(
        &entropy,
        &phrase_recovery_transcript(
            "owedbob",
            start.recovery_id,
            &start.challenge,
            device_id,
            &sign_pk.mldsa_pk,
            &sign_pk.ed25519_pk,
            &hpke_pk.0,
            &pw.payload,
        ),
    )
    .unwrap();
    let roster = recovery_roster(&start, &entropy, &device, owner.collection_key().unwrap());
    http.post(format!("{base}/v1/recover/finish"))
        .json(&RecoverFinishRequest {
            username: "owedbob".into(),
            recovery_id: start.recovery_id,
            challenge: start.challenge.clone(),
            phrase_proof: DualSignatureBody {
                mldsa: proof.mldsa,
                ed25519: proof.ed25519,
            },
            device,
            enrollment_signature: DualSignatureBody {
                mldsa: enrollment.mldsa,
                ed25519: enrollment.ed25519,
            },
            wrap: KeyWrapBody {
                recipient_kind: "device".into(),
                recipient_id: device_id.to_string(),
                hpke_enc: wrap.enc,
                wrapped_ck: wrap.ciphertext,
                ciphersuite: XWING_CIPHERSUITE.into(),
            },
            roster,
            upload: pw.upload,
            kdf_salt: pw.kdf_salt,
            recovery_nonce: pw.nonce,
            recovery_wrapped_ck: pw.wrapped_ck,
            recovery_ciphersuite: pw.ciphersuite,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .expect("the recovery itself must succeed");
    drop(hpke_sk);
    drop(sign_sk);

    // This is the crash point. The key is untouched, so the phrase still opens it.
    let error = owner
        .login(password)
        .await
        .expect_err("a login must not quietly continue with a recovery outstanding")
        .to_string();
    assert!(
        error.contains("unfinished recovery"),
        "wrong error: {error}"
    );

    let second_phrase = owner
        .complete_recovery_rotation(password)
        .await
        .expect("finishing the recovery");
    assert_ne!(second_phrase, first_phrase);
    assert_eq!(owner.list_contacts().await.expect("read").len(), 1);

    // The phrase that was used, and every copy of it, is now dead.
    let mut stale = SealbookClient::plaintext_http();
    assert!(
        stale
            .recover(&base, "owedbob", &first_phrase, password)
            .await
            .is_err(),
        "the phrase used for the interrupted recovery must stop working"
    );

    let mut fresh = SealbookClient::plaintext_http();
    fresh
        .recover(&base, "owedbob", &second_phrase, password)
        .await
        .expect("the phrase the rotation issued must work");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Bug #4: the phrase has to recover an account whose password is the thing that
/// was lost. Before this, recovery still asked for the password, so forgetting it
/// meant the vault was gone however carefully the 24 words had been kept.
#[tokio::test]
async fn the_phrase_recovers_an_account_whose_password_was_forgotten() {
    let dir = std::env::temp_dir().join(format!("sealbook-pwreset-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let forgotten = "correct horse battery";
    let mut owner = SealbookClient::plaintext_http();
    let phrase = owner
        .register(&base, "resetalice", forgotten)
        .await
        .unwrap();
    owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Ada Lovelace"}}"#,
        )
        .await
        .unwrap();

    // A new device, the 24 words, and a password chosen now. The old one is
    // neither known nor asked for.
    let chosen = "a different password entirely";
    let mut recovered = SealbookClient::plaintext_http();
    let next_phrase = recovered
        .recover(&base, "resetalice", &phrase, chosen)
        .await
        .expect("the phrase alone must recover the account");
    assert_eq!(next_phrase.split_whitespace().count(), 24);
    assert_ne!(next_phrase, phrase);

    // The vault came back, decrypted.
    let contacts = recovered.list_contacts().await.expect("read the vault");
    assert_eq!(contacts.len(), 1);
    assert!(contacts[0].1.contains("Ada Lovelace"));

    // The password that was set works for a fresh sign-in, and writes are allowed,
    // so the rotation that recovery owes really did complete.
    let state = recovered.state.clone().unwrap();
    let mut again = SealbookClient::with_state(state);
    again
        .login(chosen)
        .await
        .expect("the password set during recovery must sign in");
    again
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Grace Hopper"}}"#,
        )
        .await
        .expect("write after recovery");
    assert_eq!(again.list_contacts().await.unwrap().len(), 2);

    // The forgotten password is gone, not merely unused.
    let mut stale = SealbookClient::with_state(recovered.state.clone().unwrap());
    assert!(
        stale.login(forgotten).await.is_err(),
        "the password replaced during recovery must stop working"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The phrase proof covers the credentials the recovery installs, so a proxy that
/// rewrites the body cannot swap in a password of its own and take the account.
#[tokio::test]
async fn a_recovery_whose_new_password_was_modified_after_signing_is_refused() {
    let dir = std::env::temp_dir().join(format!("sealbook-pwtamper-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let password = "correct horse battery";
    let mut owner = SealbookClient::plaintext_http();
    let phrase = owner.register(&base, "tamperbob", password).await.unwrap();
    let entropy = entropy_from_phrase(&phrase).unwrap();

    let http = reqwest::Client::new();
    let (opaque_request, registration) = client_register_start(password.as_bytes()).unwrap();
    let start: RecoverStartResponse = http
        .post(format!("{base}/v1/recover/start"))
        .json(&RecoverStartRequest {
            username: "tamperbob".into(),
            lookup_id: phrase_lookup_id(&entropy).unwrap().to_vec(),
            opaque_request,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    let (_hpke_sk, hpke_pk) = generate_device_hpke().unwrap();
    let (sign_sk, sign_pk) = generate_device_signing().unwrap();
    let device_id = Uuid::new_v4();
    let device = sealbook_protocol::DevicePublicKeys {
        device_id,
        mldsa_pk: sign_pk.mldsa_pk.clone(),
        ed25519_pk: sign_pk.ed25519_pk.clone(),
        xwing_hpke_pk: hpke_pk.0.clone(),
    };
    let enrollment = sign(
        &sign_sk,
        &enrollment_transcript(
            device_id,
            &sign_pk.mldsa_pk,
            &sign_pk.ed25519_pk,
            &hpke_pk.0,
        ),
    )
    .unwrap();
    let wrap = wrap_for_device(&hpke_pk, owner.collection_key().unwrap()).unwrap();
    let pw = recovery_password(
        password,
        &start.opaque_response,
        registration,
        owner.collection_key().unwrap(),
    );
    let proof = sign_phrase_recovery(
        &entropy,
        &phrase_recovery_transcript(
            "tamperbob",
            start.recovery_id,
            &start.challenge,
            device_id,
            &sign_pk.mldsa_pk,
            &sign_pk.ed25519_pk,
            &hpke_pk.0,
            &pw.payload,
        ),
    )
    .unwrap();
    let roster = recovery_roster(&start, &entropy, &device, owner.collection_key().unwrap());
    let valid = RecoverFinishRequest {
        username: "tamperbob".into(),
        recovery_id: start.recovery_id,
        challenge: start.challenge.clone(),
        phrase_proof: DualSignatureBody {
            mldsa: proof.mldsa,
            ed25519: proof.ed25519,
        },
        device,
        enrollment_signature: DualSignatureBody {
            mldsa: enrollment.mldsa,
            ed25519: enrollment.ed25519,
        },
        wrap: KeyWrapBody {
            recipient_kind: "device".into(),
            recipient_id: device_id.to_string(),
            hpke_enc: wrap.enc,
            wrapped_ck: wrap.ciphertext,
            ciphersuite: XWING_CIPHERSUITE.into(),
        },
        roster,
        upload: pw.upload,
        kdf_salt: pw.kdf_salt,
        recovery_nonce: pw.nonce,
        recovery_wrapped_ck: pw.wrapped_ck,
        recovery_ciphersuite: pw.ciphersuite,
    };

    // Substitute the KDF salt, leaving the signature untouched.
    let forged = RecoverFinishRequest {
        kdf_salt: vec![0xCD; valid.kdf_salt.len()],
        ..valid.clone()
    };
    let response = http
        .post(format!("{base}/v1/recover/finish"))
        .json(&forged)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        401,
        "a substituted KDF salt must be refused"
    );

    // The challenge is single use, so a fresh one is needed for the control. That
    // the unmodified request is accepted is what makes the rejection meaningful.
    let (opaque_request, registration) = client_register_start(password.as_bytes()).unwrap();
    let start: RecoverStartResponse = http
        .post(format!("{base}/v1/recover/start"))
        .json(&RecoverStartRequest {
            username: "tamperbob".into(),
            lookup_id: phrase_lookup_id(&entropy).unwrap().to_vec(),
            opaque_request,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let pw = recovery_password(
        password,
        &start.opaque_response,
        registration,
        owner.collection_key().unwrap(),
    );
    let proof = sign_phrase_recovery(
        &entropy,
        &phrase_recovery_transcript(
            "tamperbob",
            start.recovery_id,
            &start.challenge,
            device_id,
            &sign_pk.mldsa_pk,
            &sign_pk.ed25519_pk,
            &hpke_pk.0,
            &pw.payload,
        ),
    )
    .unwrap();
    let roster = recovery_roster(
        &start,
        &entropy,
        &valid.device,
        owner.collection_key().unwrap(),
    );
    let control = RecoverFinishRequest {
        recovery_id: start.recovery_id,
        challenge: start.challenge,
        phrase_proof: DualSignatureBody {
            mldsa: proof.mldsa,
            ed25519: proof.ed25519,
        },
        roster,
        upload: pw.upload,
        kdf_salt: pw.kdf_salt,
        recovery_nonce: pw.nonce,
        recovery_wrapped_ck: pw.wrapped_ck,
        recovery_ciphersuite: pw.ciphersuite,
        ..valid
    };
    let response = http
        .post(format!("{base}/v1/recover/finish"))
        .json(&control)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        200,
        "the unmodified recovery must be accepted: {}",
        response.text().await.unwrap_or_default()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_joining_device_refuses_a_roster_it_did_not_confirm() {
    let dir = std::env::temp_dir().join(format!("sealbook-anchor-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let password = "correct horse battery";
    let mut owner = SealbookClient::plaintext_http();
    owner
        .register(&base, "anchoralice", password)
        .await
        .unwrap();
    owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Ada Lovelace"}}"#,
        )
        .await
        .unwrap();

    let mut joiner = SealbookClient::plaintext_http();
    let (pair_code, confirm) = joiner.pair_join(&base, "anchoralice").await.expect("join");
    let anchored = joiner.state.as_ref().unwrap();
    assert_eq!(
        anchored.roster_seq, 1,
        "pairing must anchor the joining device on the roster the code commits to"
    );
    assert_eq!(anchored.roster_transcript.len(), 32);
    let joiner_device_id = anchored.device_id;
    owner
        .pair_approve(&pair_code, &confirm)
        .await
        .expect("approve");

    // The vault a malicious server would rather the new device saw: its own
    // collection key in the pairing wrap, and a roster under that key naming a
    // device it holds the signing seed for.
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    let collection_id: String = sqlx::query_scalar("SELECT id FROM collections")
        .fetch_one(&pool)
        .await
        .unwrap();
    let collection_uuid = Uuid::parse_str(&collection_id).unwrap();
    let joiner_hpke_pk: Vec<u8> =
        sqlx::query_scalar("SELECT xwing_hpke_pk FROM devices WHERE id = ?")
            .bind(joiner_device_id.to_string())
            .fetch_one(&pool)
            .await
            .unwrap();
    let account = sqlx::query("SELECT phrase_mldsa_pk, phrase_ed25519_pk FROM accounts")
        .fetch_one(&pool)
        .await
        .unwrap();
    let (server_secrets, server_public) = generate_device_signing().unwrap();
    let (_, server_hpke_pk) = generate_device_hpke().unwrap();
    let server_device = sealbook_protocol::DevicePublicKeys {
        device_id: Uuid::new_v4(),
        mldsa_pk: server_public.mldsa_pk.clone(),
        ed25519_pk: server_public.ed25519_pk.clone(),
        xwing_hpke_pk: server_hpke_pk.0.clone(),
    };
    let server_ck = CollectionKey::generate();
    let forged = hand_roster(
        collection_uuid,
        1,
        1,
        vec![
            server_device.clone(),
            sealbook_protocol::DevicePublicKeys {
                device_id: joiner_device_id,
                mldsa_pk: sqlx::query_scalar("SELECT mldsa_pk FROM devices WHERE id = ?")
                    .bind(joiner_device_id.to_string())
                    .fetch_one(&pool)
                    .await
                    .unwrap(),
                ed25519_pk: sqlx::query_scalar("SELECT ed25519_pk FROM devices WHERE id = ?")
                    .bind(joiner_device_id.to_string())
                    .fetch_one(&pool)
                    .await
                    .unwrap(),
                xwing_hpke_pk: joiner_hpke_pk.clone(),
            },
        ],
        account.get("phrase_mldsa_pk"),
        account.get("phrase_ed25519_pk"),
        sealbook_crypto::RosterSigner::Device(server_device.device_id),
        &server_secrets,
        &server_ck,
    );
    sqlx::query("DELETE FROM device_rosters WHERE collection_id = ?")
        .bind(&collection_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO device_rosters (collection_id, roster_seq, body) VALUES (?, 1, ?)")
        .bind(&collection_id)
        .bind(serde_json::to_string(&forged).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    let server_wrap = wrap_for_device(
        &sealbook_crypto::DeviceHpkePublic(joiner_hpke_pk),
        &server_ck,
    )
    .unwrap();
    sqlx::query(
        "UPDATE key_wraps SET hpke_enc = ?, wrapped_ck = ?
         WHERE collection_id = ? AND recipient_kind = 'device' AND recipient_id = ?",
    )
    .bind(&server_wrap.enc)
    .bind(&server_wrap.ciphertext)
    .bind(&collection_id)
    .bind(joiner_device_id.to_string())
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;

    let error = joiner
        .login(password)
        .await
        .expect_err("a roster the user never confirmed must not be accepted")
        .to_string();
    assert!(
        error.contains("pinned"),
        "the refusal should name the pin the pairing established, got: {error}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The confirmed code is good for one roster. If the device set changes between a
/// joining device asking to pair and the approval, the user's comparison no longer
/// covers what would be enrolled, so the pairing has to start again.
#[tokio::test]
async fn an_approval_is_refused_once_the_roster_has_moved_on() {
    let dir = std::env::temp_dir().join(format!("sealbook-stale-anchor-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let password = "correct horse battery";
    let mut owner = SealbookClient::plaintext_http();
    owner.register(&base, "stalealice", password).await.unwrap();

    let mut joiner = SealbookClient::plaintext_http();
    let (pair_code, confirm) = joiner.pair_join(&base, "stalealice").await.expect("join");
    // A new phrase rotates the key and advances the roster past the anchor the
    // joining device was served.
    owner.change_phrase(password).await.expect("rotate");

    let error = owner
        .pair_approve(&pair_code, &confirm)
        .await
        .expect_err("approving against a roster the user did not confirm must be refused")
        .to_string();
    assert!(
        error.contains("start the pairing again"),
        "the refusal should say what to do, got: {error}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The server is told one content type for every object, so it cannot tell a
/// contact from a calendar event from a note, and a tombstone does not say what
/// kind of object it replaced. The real type is sealed inside the ciphertext.
#[tokio::test]
async fn the_server_never_learns_what_kind_of_object_it_holds() {
    let dir = std::env::temp_dir().join(format!("sealbook-opaque-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let mut client = SealbookClient::plaintext_http();
    client
        .register(&base, "opaquealice", "correct horse battery")
        .await
        .expect("register");
    client.ensure_default_address_book().await.expect("book");
    client
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Ada Lovelace"}}"#,
        )
        .await
        .expect("contact");
    client
        .put_note(Uuid::new_v4(), r#"{"@type":"Note","title":"Okapi"}"#)
        .await
        .expect("note");
    let doomed = Uuid::new_v4();
    client
        .put_calendar_event(doomed, r#"{"@type":"Event","title":"Standup"}"#)
        .await
        .expect("event");
    client.delete_calendar_event(doomed).await.expect("delete");

    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .expect("open db");
    let types: Vec<String> = sqlx::query_scalar("SELECT DISTINCT content_type FROM objects")
        .fetch_all(&pool)
        .await
        .expect("content types");
    assert_eq!(
        types,
        vec![SEALED_CONTENT_TYPE.to_string()],
        "the stored label must not distinguish the kinds"
    );
    let revision_types: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT content_type FROM object_revisions")
            .fetch_all(&pool)
            .await
            .expect("revision content types");
    assert_eq!(
        revision_types,
        vec![SEALED_CONTENT_TYPE.to_string()],
        "the change feed must not distinguish them either"
    );
    pool.close().await;

    // The sealed types are not anywhere else in the file, so nothing recovers
    // them from a stolen database.
    let raw = std::fs::read(&db).expect("read sqlite");
    let hay = String::from_utf8_lossy(&raw);
    for leaked in [
        "application/jscontact+json",
        "application/sealbook.note+json",
        "application/sealbook.calendar-event+json",
    ] {
        assert!(!hay.contains(leaked), "{leaked} leaked into the database");
    }

    // The client still reads each object back as its own kind.
    assert_eq!(client.list_contacts().await.expect("contacts").len(), 1);
    assert_eq!(client.list_notes().await.expect("notes").len(), 1);
    assert!(client
        .list_calendar_events()
        .await
        .expect("events")
        .is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

/// A per-kind label is refused rather than stored, so a client cannot put the
/// type back in the clear by sending one.
#[tokio::test]
async fn a_per_kind_content_type_is_refused() {
    let (db, base, client) = account_with_contacts("perkind", 1).await;
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    let state = client.state.as_ref().unwrap();
    let token = state.session_token.clone().unwrap();
    let collection = state.collection_id;
    let row = sqlx::query(
        "SELECT manifest_seq, key_epoch, latest_revision, object_count, digest, device_id,
                mldsa_sig, ed25519_sig FROM manifests",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    let response = reqwest::Client::new()
        .put(format!("{base}/v1/collections/{collection}/objects"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "id": Uuid::new_v4(),
            "revision": row.get::<i64, _>("latest_revision") + 1,
            "nonce": URL_SAFE_NO_PAD.encode([7u8; 24]),
            "ciphertext": URL_SAFE_NO_PAD.encode([0u8; 272]),
            "padded_size": 256,
            "content_type": "application/jscontact+json",
            "tombstone": false,
            "manifest": {
                "manifest_seq": row.get::<i64, _>("manifest_seq") + 1,
                "key_epoch": row.get::<i64, _>("key_epoch"),
                "latest_revision": row.get::<i64, _>("latest_revision") + 1,
                "object_count": row.get::<i64, _>("object_count"),
                "digest": URL_SAFE_NO_PAD.encode(row.get::<Vec<u8>, _>("digest")),
                "device_id": row.get::<String, _>("device_id"),
                "signature": {
                    "mldsa": URL_SAFE_NO_PAD.encode(row.get::<Vec<u8>, _>("mldsa_sig")),
                    "ed25519": URL_SAFE_NO_PAD.encode(row.get::<Vec<u8>, _>("ed25519_sig")),
                }
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    pool.close().await;
    let _ = std::fs::remove_dir_all(db.parent().unwrap());
}

/// Tombstones are rows the manifest commits to, and only a device can sign a
/// manifest, so nothing but a rotation can ever retire one. Before this, nothing
/// did: an account that deleted `max_objects` distinct objects could never delete
/// again. A rotation now drops the ones the change feed can no longer carry.
#[tokio::test]
async fn a_rotation_retires_tombstones_the_change_feed_can_no_longer_carry() {
    let dir = std::env::temp_dir().join(format!("sealbook-tombstones-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let password = "correct horse battery";
    let mut client = SealbookClient::plaintext_http();
    client
        .register(&base, "tombalice", password)
        .await
        .expect("register");
    let doomed: Vec<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();
    for (index, id) in doomed.iter().enumerate() {
        client
            .put_contact(
                *id,
                &format!(r#"{{"@type":"Card","name":{{"full":"Gone {index}"}}}}"#),
            )
            .await
            .expect("put");
    }
    for id in &doomed {
        client.delete_contact(*id).await.expect("delete");
    }
    // A live write last, so the newest revision the sweep keeps is not itself a
    // tombstone and all three fall below the floor.
    let survivor = Uuid::new_v4();
    client
        .put_contact(survivor, r#"{"@type":"Card","name":{"full":"Still here"}}"#)
        .await
        .expect("put survivor");

    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .expect("open db");
    assert_eq!(
        tombstone_rows(&pool).await,
        3,
        "three deletes should leave three tombstone rows"
    );

    // Age the revision log out from under them. A client behind this point is
    // told to resync, and the live state it is then served already lacks the
    // deleted objects, so the rows have nothing left to say.
    sqlx::query("UPDATE object_revisions SET created_at = 0")
        .execute(&pool)
        .await
        .expect("age the log");
    sealbook_server::prune_old_revisions(&pool, std::time::Duration::from_secs(1))
        .await
        .expect("prune");

    // Rotating is the only thing that can retire them, because it is the only
    // thing that signs a new manifest over the whole collection.
    client.change_phrase(password).await.expect("rotate");

    assert_eq!(
        tombstone_rows(&pool).await,
        0,
        "the rotation should have retired every tombstone below the floor"
    );
    let counted: i64 = sqlx::query_scalar("SELECT tombstone_count FROM revision_seq")
        .fetch_one(&pool)
        .await
        .expect("tombstone_count");
    assert_eq!(counted, 0, "the quota counter must follow the rows");
    pool.close().await;

    // The vault is still readable and still writable, including deletes, which is
    // what the ceiling used to block for good.
    let contacts = client.list_contacts().await.expect("list");
    assert_eq!(
        contacts.len(),
        1,
        "the surviving contact must still be there"
    );
    assert_eq!(contacts[0].0, survivor);
    client.delete_contact(survivor).await.expect("delete again");
    assert!(client.list_contacts().await.expect("list").is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

/// The other direction: while the feed can still carry a delete, its row has to
/// stay. Retiring it would leave a lagging device verifying a set the manifest no
/// longer describes, which that device sees as tampering and refuses.
#[tokio::test]
async fn a_rotation_keeps_tombstones_the_change_feed_can_still_carry() {
    let dir = std::env::temp_dir().join(format!("sealbook-tombkeep-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let password = "correct horse battery";
    let mut client = SealbookClient::plaintext_http();
    client
        .register(&base, "keepalice", password)
        .await
        .expect("register");
    let doomed = Uuid::new_v4();
    client
        .put_contact(doomed, r#"{"@type":"Card","name":{"full":"Gone"}}"#)
        .await
        .expect("put");
    client.delete_contact(doomed).await.expect("delete");

    // No pruning, so the delete is still in the log and still reachable.
    client.change_phrase(password).await.expect("rotate");

    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .expect("open db");
    assert_eq!(
        tombstone_rows(&pool).await,
        1,
        "a tombstone the feed can still carry must survive the rotation"
    );
    pool.close().await;

    // And the rotated collection still verifies against its manifest, which is
    // what would break if the counts and the rows had drifted apart.
    assert!(client.list_contacts().await.expect("list").is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

async fn tombstone_rows(pool: &sqlx::SqlitePool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM objects WHERE tombstone = 1")
        .fetch_one(pool)
        .await
        .expect("count tombstones")
}

/// The client decides which tombstones to retire, so the server checks the list
/// against its own floor. Without that check a client could retire a delete the
/// feed still carries, and every lagging device would then refuse to sync.
#[tokio::test]
async fn a_rotation_that_retires_a_tombstone_above_the_floor_is_refused() {
    use sealbook_crypto::{
        content_digest, generate_kdf_salt, generate_phrase, key_rotation_transcript,
        key_wraps_digest, manifest_digest, manifest_transcript, phrase_lookup_id,
        phrase_recovery_public, rotated_objects_digest, rotation_recovery_payload, sign,
        wrap_collection_key, wrap_for_device, wrap_for_phrase, CollectionKey, DeviceHpkePublic,
        DeviceSigningSecrets, ManifestDigestEntry, ObjectDigestEntry, WrapDigestEntry,
        PHRASE_CIPHERSUITE, PHRASE_SCHEME, RECOVERY_CIPHERSUITE, XWING_CIPHERSUITE,
    };
    use sealbook_protocol::{DevicePublicKeys, ManifestBody, PhraseRecoveryBody, RotateRequest};

    let dir = std::env::temp_dir().join(format!("sealbook-tombfloor-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let password = "correct horse battery";
    let mut owner = SealbookClient::plaintext_http();
    owner.register(&base, "flooralice", password).await.unwrap();
    // One delete and nothing live, so the rotation has no object to re-encrypt
    // and the only entry in its manifest is the tombstone.
    let doomed = Uuid::new_v4();
    owner
        .put_contact(doomed, r#"{"@type":"Card","name":{"full":"Gone"}}"#)
        .await
        .expect("put");
    owner.delete_contact(doomed).await.expect("delete");

    let state = owner.state.as_ref().unwrap();
    let (collection_id, device_id, token) = (
        state.collection_id,
        state.device_id,
        state.session_token.clone().unwrap(),
    );
    let secrets = DeviceSigningSecrets {
        mldsa_seed: state.mldsa_seed.clone(),
        ed25519_sk: state.ed25519_sk.clone(),
    };
    let http = reqwest::Client::new();

    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    let tombstone_revision: i64 =
        sqlx::query_scalar("SELECT revision FROM objects WHERE tombstone = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
    let next_revision: i64 = sqlx::query_scalar("SELECT next_revision FROM revision_seq")
        .fetch_one(&pool)
        .await
        .unwrap();
    let manifest_seq: i64 = sqlx::query_scalar("SELECT manifest_seq FROM manifests")
        .fetch_one(&pool)
        .await
        .unwrap();
    pool.close().await;

    let devices: Vec<DevicePublicKeys> = http
        .get(format!("{base}/v1/account/devices"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let device = devices
        .into_iter()
        .find(|candidate| candidate.device_id == device_id)
        .expect("the registering device must be enrolled");

    let new_ck = CollectionKey::generate();
    let salt = generate_kdf_salt();
    let (_phrase, entropy) = generate_phrase().unwrap();
    let device_wrap =
        wrap_for_device(&DeviceHpkePublic(device.xwing_hpke_pk.clone()), &new_ck).unwrap();
    let recovery_wrap = wrap_collection_key(password.as_bytes(), &salt, &new_ck).unwrap();
    let phrase_wrap = wrap_for_phrase(&entropy, &new_ck).unwrap();
    let key_wraps = vec![
        KeyWrapBody {
            recipient_kind: "device".into(),
            recipient_id: device_id.to_string(),
            hpke_enc: device_wrap.enc,
            wrapped_ck: device_wrap.ciphertext,
            ciphersuite: XWING_CIPHERSUITE.into(),
        },
        KeyWrapBody {
            recipient_kind: "recovery".into(),
            recipient_id: "flooralice".into(),
            hpke_enc: recovery_wrap.nonce.to_vec(),
            wrapped_ck: recovery_wrap.ciphertext,
            ciphersuite: RECOVERY_CIPHERSUITE.into(),
        },
        KeyWrapBody {
            recipient_kind: "phrase".into(),
            recipient_id: "flooralice".into(),
            hpke_enc: phrase_wrap.nonce.to_vec(),
            wrapped_ck: phrase_wrap.ciphertext,
            ciphersuite: PHRASE_CIPHERSUITE.into(),
        },
    ];
    let phrase_public = phrase_recovery_public(&entropy).unwrap();
    let phrase_recovery = PhraseRecoveryBody {
        mldsa_pk: phrase_public.mldsa_pk.clone(),
        ed25519_pk: phrase_public.ed25519_pk.clone(),
        lookup_id: phrase_lookup_id(&entropy).unwrap().to_vec(),
        scheme: PHRASE_SCHEME.into(),
    };

    // A tombstone row carries no ciphertext, so its content digest is the digest
    // of two empty byte strings.
    let kept = ManifestDigestEntry {
        id: doomed,
        revision: tombstone_revision as u64,
        tombstone: true,
        content_digest: content_digest(&[], &[]),
    };
    let digest = manifest_digest(&[kept]);
    let key_epoch = owner.server_key_epoch().await.unwrap() + 1;
    let latest_revision = (next_revision - 1) as u64;
    let seq = (manifest_seq + 1) as u64;
    let manifest_sig = sign(
        &secrets,
        &manifest_transcript(collection_id, seq, key_epoch, latest_revision, 1, &digest),
    )
    .unwrap();
    let manifest = ManifestBody {
        manifest_seq: seq,
        key_epoch,
        latest_revision,
        object_count: 1,
        digest: digest.to_vec(),
        device_id,
        signature: DualSignatureBody {
            mldsa: manifest_sig.mldsa,
            ed25519: manifest_sig.ed25519,
        },
    };

    let wrap_entries: Vec<WrapDigestEntry<'_>> = key_wraps
        .iter()
        .map(|wrap| WrapDigestEntry {
            recipient_kind: &wrap.recipient_kind,
            recipient_id: &wrap.recipient_id,
            hpke_enc: &wrap.hpke_enc,
            wrapped_ck: &wrap.wrapped_ck,
            ciphersuite: &wrap.ciphersuite,
        })
        .collect();
    let no_objects: Vec<ObjectDigestEntry<'_>> = Vec::new();
    let signature = sign(
        &secrets,
        &key_rotation_transcript(
            collection_id,
            None,
            key_epoch,
            &key_wraps_digest(&wrap_entries),
            &rotated_objects_digest(&no_objects),
            &digest,
            &rotation_recovery_payload(
                &salt,
                &phrase_recovery.mldsa_pk,
                &phrase_recovery.ed25519_pk,
                &phrase_recovery.lookup_id,
                &phrase_recovery.scheme,
            ),
        ),
    )
    .unwrap();
    let roster = hand_roster(
        collection_id,
        2,
        key_epoch,
        vec![device.clone()],
        phrase_recovery.mldsa_pk.clone(),
        phrase_recovery.ed25519_pk.clone(),
        sealbook_crypto::RosterSigner::Device(device_id),
        &secrets,
        &new_ck,
    );
    let valid = RotateRequest {
        key_epoch,
        revoke_device_id: None,
        kdf_salt: salt.to_vec(),
        key_wraps,
        phrase_recovery,
        objects: Vec::new(),
        manifest,
        rotation_signature: DualSignatureBody {
            mldsa: signature.mldsa,
            ed25519: signature.ed25519,
        },
        roster,
        drop_tombstones: Vec::new(),
    };
    let url = format!("{base}/v1/collections/{collection_id}/rotate");

    // The delete is still in the log, so this tombstone is above the floor and
    // must not be retirable. Everything else about the request is valid.
    let forged = RotateRequest {
        drop_tombstones: vec![doomed],
        ..valid.clone()
    };
    let response = http
        .post(&url)
        .bearer_auth(&token)
        .json(&forged)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    let body: sealbook_protocol::ErrorBody = response.json().await.unwrap();
    assert!(
        body.error.contains("tombstone floor"),
        "the refusal should name the floor, got: {}",
        body.error
    );

    // The control: the same rotation, retiring nothing, is accepted. Without it
    // the assertion above would pass on any unrelated malformation.
    let response = http
        .post(&url)
        .bearer_auth(&token)
        .json(&valid)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        200,
        "the same rotation without a retirement must be accepted: {}",
        response.text().await.unwrap_or_default()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Bug #12. A write used to fetch every entry in the collection, so importing
/// *n* objects moved O(n^2) bytes. The root is a hash of 256 bucket digests and
/// a write changes one of them, so a write now reads that bucket and the digests.
#[tokio::test]
async fn a_write_reads_one_bucket_not_the_whole_collection() {
    use sealbook_crypto::{manifest_bucket_of, manifest_root, MANIFEST_BUCKETS};
    use sealbook_protocol::ManifestBucketsResponse;

    let count = 400;
    let (db, base, mut client) = account_with_contacts("buckets", count).await;
    let state = client.state.as_ref().unwrap();
    let token = state.session_token.clone().unwrap();
    let collection = state.collection_id;

    let ids: Vec<Uuid> = client
        .list_contacts()
        .await
        .expect("list")
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    assert_eq!(ids.len(), count);
    let bucket = manifest_bucket_of(ids[0]);

    let http = reqwest::Client::new();
    let response: ManifestBucketsResponse = http
        .get(format!(
            "{base}/v1/collections/{collection}/manifest/buckets?buckets={bucket:02x}"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(response.served, vec![bucket]);
    assert_eq!(response.buckets.len(), MANIFEST_BUCKETS * 32);
    assert_eq!(response.object_count, count as u64);
    // One bucket of a 400-object collection, not all 400. Ids spread over 256
    // buckets, so the mean is under two and this bound is far above it.
    assert!(
        response.entries.len() * 10 < count,
        "a single bucket of {count} objects should hold a fraction of them, got {}",
        response.entries.len()
    );
    assert!(
        !response.entries.is_empty(),
        "the bucket of a known object must not come back empty"
    );
    for entry in &response.entries {
        assert_eq!(
            manifest_bucket_of(entry.id),
            bucket,
            "an entry was served in the wrong bucket"
        );
    }

    // And the digests rebuild exactly the root the manifest is signed over, which
    // is what lets a client check the 255 buckets it was not served.
    let mut buckets = [[0u8; 32]; MANIFEST_BUCKETS];
    for (slot, chunk) in buckets.iter_mut().zip(response.buckets.chunks(32)) {
        slot.copy_from_slice(chunk);
    }
    let manifest = response.manifest.expect("the collection has a manifest");
    assert_eq!(
        manifest.digest,
        manifest_root(&buckets, response.object_count).to_vec(),
        "the bucket digests must rebuild the signed root"
    );

    let _ = std::fs::remove_dir_all(db.parent().unwrap());
}

/// The bucket digests are what a client checks the buckets it was *not* served
/// against, so editing one has to be refused rather than silently accepted.
#[tokio::test]
async fn a_write_refuses_an_edited_bucket_digest() {
    let (db, _base, mut client) = account_with_contacts("badbucket", 3).await;
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    // Flip a byte in the stored digests. Whichever bucket it lands in, the root
    // the client rebuilds stops matching the manifest it is served.
    let mut blob: Vec<u8> = sqlx::query_scalar("SELECT buckets FROM manifest_digest_state")
        .fetch_one(&pool)
        .await
        .expect("bucket state");
    blob[0] ^= 0xff;
    sqlx::query("UPDATE manifest_digest_state SET buckets = ?")
        .bind(&blob)
        .execute(&pool)
        .await
        .expect("corrupt the bucket state");
    pool.close().await;

    let error = client
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"After"}}"#,
        )
        .await
        .expect_err("a write against edited bucket digests must be refused")
        .to_string();
    assert!(
        error.contains("do not match the signed manifest"),
        "the refusal should name the mismatch, got: {error}"
    );

    let _ = std::fs::remove_dir_all(db.parent().unwrap());
}

/// And an object withheld from the bucket that *is* served fails the other half
/// of the check: the entries must hash to their bucket's digest.
#[tokio::test]
async fn a_write_refuses_an_object_withheld_from_its_bucket() {
    let (db, _base, mut client) = account_with_contacts("withheld", 6).await;
    let target = client
        .list_contacts()
        .await
        .expect("list")
        .first()
        .map(|(id, _)| *id)
        .expect("a contact to withhold");

    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    // Drop the row but leave the bucket digests alone, which is what a server
    // withholding one object from an otherwise honest answer looks like.
    sqlx::query("DELETE FROM objects WHERE id = ?")
        .bind(target.to_string())
        .execute(&pool)
        .await
        .expect("withhold the object");
    pool.close().await;

    // Write into the same bucket, so that bucket is the one served.
    let error = client
        .put_contact(target, r#"{"@type":"Card","name":{"full":"Replacement"}}"#)
        .await
        .expect_err("a withheld object must be refused")
        .to_string();
    assert!(
        error.contains("do not match its digest") || error.contains("do not match the signed"),
        "the refusal should name the mismatch, got: {error}"
    );

    let _ = std::fs::remove_dir_all(db.parent().unwrap());
}

/// The roster is cached per session now, because fetching it per write was the
/// second of the two reads every write made. A manifest signed by a device the
/// cache does not hold has to refetch rather than be refused, which is what a
/// pairing on another device looks like from here.
#[tokio::test]
async fn a_cached_roster_still_accepts_a_manifest_from_a_newly_paired_device() {
    let dir = std::env::temp_dir().join(format!("sealbook-rostercache-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let password = "correct horse battery";
    let mut owner = SealbookClient::plaintext_http();
    owner.register(&base, "cachealice", password).await.unwrap();
    // Two writes, so the owner has a roster cached from before the pairing.
    for index in 0..2 {
        owner
            .put_contact(
                Uuid::new_v4(),
                &format!(r#"{{"@type":"Card","name":{{"full":"Before {index}"}}}}"#),
            )
            .await
            .expect("owner writes");
    }

    let mut joiner = SealbookClient::plaintext_http();
    let (pair_code, confirm) = joiner.pair_join(&base, "cachealice").await.expect("join");
    owner
        .pair_approve(&pair_code, &confirm)
        .await
        .expect("approve");
    assert!(joiner.pair_ready(&pair_code).await.expect("ready"));
    joiner.login(password).await.expect("joiner login");

    // The joiner signs the next manifest. The owner's cached roster predates it,
    // so verifying that manifest has to go back for the roster.
    joiner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"From the new device"}}"#,
        )
        .await
        .expect("joiner writes");
    owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"After"}}"#,
        )
        .await
        .expect("the owner must accept a manifest signed by the paired device");
    assert_eq!(owner.list_contacts().await.expect("list").len(), 4);

    // And a rotation moves the epoch, which is what a revocation looks like, so
    // the cache has to be dropped for that too.
    owner.change_phrase(password).await.expect("rotate");
    owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"After the rotation"}}"#,
        )
        .await
        .expect("writes must work after the epoch moves");
    assert_eq!(owner.list_contacts().await.expect("list").len(), 5);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A batch is one request, one manifest signature and one sequence number for
/// however many objects it carries. Writing them one at a time is what made an
/// import cost a round trip and a signature each, and left nothing else able to
/// write in between.
#[tokio::test]
async fn a_batch_write_lands_every_object_under_one_manifest() {
    let dir = std::env::temp_dir().join(format!("sealbook-batch-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let mut client = SealbookClient::plaintext_http();
    client
        .register(&base, "batchalice", "correct horse battery")
        .await
        .expect("register");

    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    let manifest_seq_before: i64 = sqlx::query_scalar("SELECT manifest_seq FROM manifests")
        .fetch_optional(&pool)
        .await
        .expect("manifest")
        .unwrap_or(0);
    let next_revision_before: i64 = sqlx::query_scalar("SELECT next_revision FROM revision_seq")
        .fetch_one(&pool)
        .await
        .expect("revision_seq");

    let count = 40;
    let bodies: Vec<(Uuid, String)> = (0..count)
        .map(|index| {
            (
                Uuid::new_v4(),
                format!(r#"{{"@type":"Card","name":{{"full":"Imported {index}"}}}}"#),
            )
        })
        .collect();
    let batch: Vec<(Uuid, &str)> = bodies
        .iter()
        .map(|(id, body)| (*id, body.as_str()))
        .collect();
    let latest = client.put_contacts(&batch).await.expect("batch write");

    // Every object landed, and the whole-collection manifest check `list_contacts`
    // does still passes over the result.
    let listed = client.list_contacts().await.expect("list");
    assert_eq!(listed.len(), count);
    for (id, body) in &bodies {
        let found = listed
            .iter()
            .find(|(listed_id, _)| listed_id == id)
            .expect("every batched contact must be listed");
        assert_eq!(&found.1, body);
    }

    // One sequence number for the batch, and one revision per object in it.
    let manifest_seq_after: i64 = sqlx::query_scalar("SELECT manifest_seq FROM manifests")
        .fetch_one(&pool)
        .await
        .expect("manifest");
    let next_revision_after: i64 = sqlx::query_scalar("SELECT next_revision FROM revision_seq")
        .fetch_one(&pool)
        .await
        .expect("revision_seq");
    assert_eq!(
        manifest_seq_after,
        manifest_seq_before + 1,
        "a batch must advance the manifest sequence once, not once per object"
    );
    assert_eq!(
        next_revision_after,
        next_revision_before + count as i64,
        "every object in a batch takes its own revision"
    );
    assert_eq!(latest, (next_revision_after - 1) as u64);
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM object_revisions")
        .fetch_one(&pool)
        .await
        .expect("log");
    assert_eq!(
        rows, count as i64,
        "the change feed must carry one log row per batched object"
    );
    pool.close().await;

    // And the collection is still writable both ways afterwards: a single write
    // has to verify the manifest the batch signed, and a second batch has to
    // verify the one the single write signed.
    client
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"After the batch"}}"#,
        )
        .await
        .expect("a single write after a batch");
    let more = [(
        Uuid::new_v4(),
        r#"{"@type":"Card","name":{"full":"Second batch"}}"#,
    )];
    client.put_contacts(&more).await.expect("second batch");
    assert_eq!(client.list_contacts().await.expect("list").len(), count + 2);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Two objects of a batch in one bucket, and one of them replacing a row that is
/// already there.
///
/// The digests are per bucket, so a batch has to rehash each touched bucket once
/// over every entry that ends up in it. Rehashing per object, or counting a
/// replacement as a new object, leaves the client's root disagreeing with what the
/// server recomputes and the write is refused.
#[tokio::test]
async fn a_batch_rehashes_a_shared_bucket_once() {
    use sealbook_crypto::manifest_bucket_of;

    let dir = std::env::temp_dir().join(format!("sealbook-batchbucket-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let mut client = SealbookClient::plaintext_http();
    client
        .register(&base, "batchbob", "correct horse battery")
        .await
        .expect("register");

    // Three ids in one bucket, which random uuids reach in a few hundred draws.
    let mut by_bucket: std::collections::HashMap<u8, Vec<Uuid>> = std::collections::HashMap::new();
    let shared = loop {
        let id = Uuid::new_v4();
        let slot = by_bucket.entry(manifest_bucket_of(id)).or_default();
        slot.push(id);
        if slot.len() == 3 {
            break slot.clone();
        }
    };
    let elsewhere = {
        let bucket = manifest_bucket_of(shared[0]);
        loop {
            let id = Uuid::new_v4();
            if manifest_bucket_of(id) != bucket {
                break id;
            }
        }
    };

    // One of the three is written first, so the batch below replaces a row rather
    // than adding one and the object count must not move for it.
    client
        .put_contact(shared[0], r#"{"@type":"Card","name":{"full":"First"}}"#)
        .await
        .expect("seed the bucket");

    let batch = [
        (shared[0], r#"{"@type":"Card","name":{"full":"Replaced"}}"#),
        (
            shared[1],
            r#"{"@type":"Card","name":{"full":"Same bucket"}}"#,
        ),
        (
            shared[2],
            r#"{"@type":"Card","name":{"full":"Same again"}}"#,
        ),
        (
            elsewhere,
            r#"{"@type":"Card","name":{"full":"Another bucket"}}"#,
        ),
    ];
    client
        .put_contacts(&batch)
        .await
        .expect("a batch sharing a bucket must be accepted");

    let listed = client.list_contacts().await.expect("list");
    assert_eq!(listed.len(), 4, "the replacement must not have added a row");
    let replaced = listed
        .iter()
        .find(|(id, _)| *id == shared[0])
        .expect("the replaced contact");
    assert!(replaced.1.contains("Replaced"));

    // The next write reads one of those buckets back and checks it against the
    // digest the batch left behind.
    client
        .put_contact(shared[1], r#"{"@type":"Card","name":{"full":"Edited"}}"#)
        .await
        .expect("a write into a bucket a batch rehashed");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A batch is one transaction, so one that would end over the quota is refused
/// entire rather than filling the vault to the ceiling and failing partway.
#[tokio::test]
async fn a_batch_past_the_object_quota_is_refused_entire() {
    let dir = std::env::temp_dir().join(format!("sealbook-batchquota-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = sealbook_server::app_with_limits(
        db.to_str().unwrap(),
        sealbook_server::Limits {
            max_objects: 2,
            max_bytes: 1024 * 1024,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let base = format!("http://{addr}");

    let mut client = SealbookClient::plaintext_http();
    client
        .register(&base, "batchquota", "correct horse battery")
        .await
        .expect("register");

    let batch = [
        (Uuid::new_v4(), r#"{"@type":"Card","name":{"full":"One"}}"#),
        (Uuid::new_v4(), r#"{"@type":"Card","name":{"full":"Two"}}"#),
        (
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Three"}}"#,
        ),
    ];
    let error = client
        .put_contacts(&batch)
        .await
        .expect_err("a batch past the quota must be refused");
    assert!(error.to_string().contains("quota"), "wrong error: {error}");
    assert!(
        client.list_contacts().await.expect("list").is_empty(),
        "a refused batch must leave nothing behind"
    );

    // And the same objects fit once the batch is inside the quota.
    client
        .put_contacts(&batch[..2])
        .await
        .expect("a batch within the quota");
    assert_eq!(client.list_contacts().await.expect("list").len(), 2);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Two writes for one object in a batch would leave the collection holding one
/// row while the signed manifest committed to whichever was folded in last, so
/// both sides refuse it.
#[tokio::test]
async fn a_batch_naming_one_object_twice_is_refused() {
    use sealbook_protocol::{BatchObject, ManifestBody, PutObjectsRequest};

    let dir = std::env::temp_dir().join(format!("sealbook-batchdupe-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let mut client = SealbookClient::plaintext_http();
    client
        .register(&base, "batchdupe", "correct horse battery")
        .await
        .expect("register");

    let id = Uuid::new_v4();
    let error = client
        .put_contacts(&[
            (id, r#"{"@type":"Card","name":{"full":"First"}}"#),
            (id, r#"{"@type":"Card","name":{"full":"Second"}}"#),
        ])
        .await
        .expect_err("the client must refuse a duplicate id");
    assert!(
        error.to_string().contains("each object once"),
        "wrong error: {error}"
    );

    // And the server refuses it too, for a client that does not check. The batch
    // is shape-checked before anything is read, so a manifest that would never
    // verify is enough to show which check fires.
    let state = client.state.as_ref().unwrap();
    let token = state.session_token.clone().unwrap();
    let collection = state.collection_id;
    let device_id = state.device_id;
    let object = BatchObject {
        id,
        revision: 1,
        nonce: vec![0u8; 24],
        ciphertext: vec![0u8; 256 + 16],
        padded_size: 256,
        content_type: SEALED_CONTENT_TYPE.into(),
        tombstone: false,
    };
    let response = reqwest::Client::new()
        .put(format!("{base}/v1/collections/{collection}/objects/batch"))
        .bearer_auth(&token)
        .json(&PutObjectsRequest {
            objects: vec![object.clone(), object],
            manifest: ManifestBody {
                manifest_seq: 1,
                key_epoch: 1,
                latest_revision: 2,
                object_count: 1,
                digest: vec![0u8; 32],
                device_id,
                signature: DualSignatureBody {
                    mldsa: Vec::new(),
                    ed25519: Vec::new(),
                },
            },
        })
        .send()
        .await
        .expect("send");
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: sealbook_protocol::ErrorBody = response.json().await.expect("error body");
    assert!(
        body.error.contains("each object once"),
        "wrong error: {}",
        body.error
    );
    assert!(client.list_contacts().await.expect("list").is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

/// A device that has not noticed another device's rotation must not seal a write
/// under the key it still holds.
///
/// The epoch a write signs comes from the server's manifest while the ciphertext
/// is sealed with the cached key, so without a check between them the write
/// stored a row under the retired key: unreadable to every device, and
/// unrotatable, because a rotation has to re-encrypt that row and only a rotation
/// could remove it. The client refreshes its wrap inside the write instead.
#[tokio::test]
async fn a_write_after_someone_else_rotated_is_not_sealed_under_the_old_key() {
    let dir = std::env::temp_dir().join(format!("sealbook-epoch-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("sealbook.db");
    let base = spawn_http(db.to_str().unwrap()).await;

    let password = "correct horse battery";
    let mut owner = SealbookClient::plaintext_http();
    owner.register(&base, "epochalice", password).await.unwrap();
    owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"Before"}}"#,
        )
        .await
        .expect("first write");

    // A second device, which will do the rotating. The first one is left holding
    // the key of the epoch before it.
    let mut joiner = SealbookClient::plaintext_http();
    let (pair_code, confirm) = joiner.pair_join(&base, "epochalice").await.expect("join");
    owner
        .pair_approve(&pair_code, &confirm)
        .await
        .expect("approve");
    joiner.login(password).await.expect("joiner login");
    let stale_epoch = owner.cached_key_epoch();
    joiner.change_phrase(password).await.expect("rotate");
    assert_eq!(
        owner.cached_key_epoch(),
        stale_epoch,
        "the owner must still be holding the pre-rotation key for this to test anything"
    );

    // The write that used to go out under the stale key.
    owner
        .put_contact(
            Uuid::new_v4(),
            r#"{"@type":"Card","name":{"full":"After the rotation"}}"#,
        )
        .await
        .expect("a write across a rotation must still land");
    assert_eq!(
        owner.cached_key_epoch(),
        stale_epoch + 1,
        "the write should have refreshed this device's key"
    );

    // Both objects open, from both devices, which is what a row sealed under the
    // retired key would have broken.
    for client in [&mut owner, &mut joiner] {
        let listed = client.list_contacts().await.expect("list");
        assert_eq!(listed.len(), 2, "both contacts must still be readable");
    }

    // And the vault is still rotatable, which is the failure that cannot be
    // recovered from: a rotation re-encrypts every live object under the current
    // key, so one row sealed under an older one wedges it for good.
    owner
        .change_phrase(password)
        .await
        .expect("the vault must still be rotatable");
    assert_eq!(owner.list_contacts().await.expect("list").len(), 2);

    let _ = std::fs::remove_dir_all(&dir);
}
