use std::net::SocketAddr;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore};
use sealbook_client::SealbookClient;
use sealbook_crypto::opaque::client_login_start;
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
};
use sqlx::Row;
use uuid::Uuid;

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
    let response: RecoverStartResponse = reqwest::Client::new()
        .post(format!("{base}/v1/recover/start"))
        .json(&RecoverStartRequest {
            username: "replayalice".into(),
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
    let transcript = phrase_recovery_transcript(
        "replayalice",
        response.recovery_id,
        &response.challenge,
        device_id,
        &sign_pk.mldsa_pk,
        &sign_pk.ed25519_pk,
        &hpke_pk.0,
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
    let start: RecoverStartResponse = http
        .post(format!("{base}/v1/recover/start"))
        .json(&RecoverStartRequest {
            username: "forgebob".into(),
            lookup_id: phrase_lookup_id(&entropy).unwrap().to_vec(),
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
    let transcript = phrase_recovery_transcript(
        "forgebob",
        start.recovery_id,
        &start.challenge,
        device_id,
        &sign_pk.mldsa_pk,
        &sign_pk.ed25519_pk,
        &hpke_pk.0,
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
    let (db, _base, client) = account_with_contacts("withhold", 3).await;
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
    let (db, _base, client) = account_with_contacts("rollback", 2).await;

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
    let (db, _base, client) = account_with_contacts("revision", 2).await;

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
            "content_type": "application/jscontact+json",
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
            "content_type": "application/jscontact+json",
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

#[tokio::test]
async fn the_change_feed_paginates() {
    let (_db, base, client) = account_with_contacts("paginate", 5).await;
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

/// A rotation installs a new password KDF salt and a new recovery-phrase record.
/// Neither is a key wrap, so neither was covered by the rotation signature, and
/// both went into `accounts` on the word of whatever sent the request. Anything
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
