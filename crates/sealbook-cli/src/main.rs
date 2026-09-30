use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{fs::OpenOptions, io::Write};

use anyhow::{Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use clap::{Parser, Subcommand};
use keyring::Entry;
use rand::RngCore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use sealbook_client::{
    LocalState, SealbookClient, ADDRESS_BOOK_ID_PROP, DEFAULT_ADDRESS_BOOK_ID,
    DEFAULT_ADDRESS_BOOK_NAME,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const STATE_VERSION: u8 = 1;
const STATE_KEY_SERVICE: &str = "sealbook-cli";
const STATE_AAD: &[u8] = b"sealbook-cli-state-v1";

#[derive(serde::Serialize, serde::Deserialize)]
struct EncryptedState {
    version: u8,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Parser)]
#[command(name = "sealbook", about = "E2EE contacts client")]
struct Cli {
    #[arg(long, default_value = "https://127.0.0.1:8443")]
    server: String,
    #[arg(long, default_value = ".sealbook-state.json")]
    state: PathBuf,
    #[arg(long, default_value = "cert.pem")]
    tls_ca: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Register {
        #[arg(long)]
        username: String,
    },
    Login {},
    PairJoin {
        #[arg(long)]
        username: String,
    },
    Pair {
        #[arg(long)]
        code: String,
    },
    Recover {
        #[arg(long)]
        username: String,
    },
    /// Issue a new recovery phrase, rotating the vault key onto it.
    ///
    /// Replacing the phrase without rotating would leave anyone who has ever
    /// seen the old one still able to decrypt, because the key it unwraps would
    /// not have changed.
    Phrase {},
    Contacts {
        #[command(subcommand)]
        command: ContactsCommand,
    },
    Book {
        #[command(subcommand)]
        command: BookCommand,
    },
    Calendar {
        #[command(subcommand)]
        command: CalendarCommand,
    },
    Devices {
        #[command(subcommand)]
        command: DevicesCommand,
    },
}

#[derive(Subcommand)]
enum DevicesCommand {
    /// List the devices enrolled on this account.
    List {},
    /// Revoke a device and rotate the collection key.
    ///
    /// Revoking alone would not be enough: the device already holds the
    /// collection key. This mints a new one, re-encrypts every object under it,
    /// and issues a new recovery phrase.
    Revoke {
        #[arg(long)]
        device_id: Uuid,
    },
}

#[derive(Subcommand)]
enum BookCommand {
    List,
    Create {
        #[arg(long)]
        name: String,
    },
}

#[derive(Subcommand)]
enum ContactsCommand {
    Put {
        #[arg(long)]
        name: String,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        book: Option<String>,
    },
    Update {
        #[arg(long)]
        id: Uuid,
        #[arg(long)]
        name: String,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        book: Option<String>,
    },
    Delete {
        #[arg(long)]
        id: Uuid,
    },
    List {
        #[arg(long)]
        book: Option<String>,
    },
}

#[derive(Subcommand)]
enum CalendarCommand {
    Create {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "#7aa2f7")]
        color: String,
    },
    ListCalendars,
    Add {
        #[arg(long)]
        title: String,
        #[arg(long)]
        start: String,
        #[arg(long)]
        end: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        #[arg(long)]
        calendar: Option<Uuid>,
    },
    List,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let pinned = load_ca(&cli.tls_ca)?;
    match cli.command {
        Command::Register { username } => {
            let password = read_secret("Password: ", "SEALBOOK_PASSWORD")?;
            let mut client = SealbookClient::https(pinned.clone()).context("tls client")?;
            let phrase = client
                .register(&cli.server, &username, &password)
                .await
                .context("register")?;
            println!("registered {username}");
            println!("Write these recovery words down. They are shown once:\n{phrase}");
            save_state(&cli.state, client.state.as_ref().unwrap())?;
        }
        Command::Login {} => {
            let password = read_secret("Password: ", "SEALBOOK_PASSWORD")?;
            let state = load_state(&cli.state)?;
            let mut client =
                SealbookClient::with_state_and_tls(state, pinned.clone()).context("tls client")?;
            client.login(&password).await.context("login")?;
            save_state(&cli.state, client.state.as_ref().unwrap())?;
            println!("logged in");
        }
        Command::PairJoin { username } => {
            let mut client = SealbookClient::https(pinned.clone()).context("tls client")?;
            let (pair_id, confirm) = client
                .pair_join(&cli.server, &username)
                .await
                .context("pair join")?;
            save_state(&cli.state, client.state.as_ref().unwrap())?;
            println!("On your other device run:\n  sealbook pair --code {pair_id}");
            println!(
                "Confirm both screens show: {}",
                sealbook_client::format_confirmation(&confirm)
            );
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                if client.pair_ready(&pair_id).await.unwrap_or(false) {
                    println!("approved. sign in with: sealbook login");
                    break;
                }
            }
        }
        Command::Pair { code } => {
            let password = read_secret("Password: ", "SEALBOOK_PASSWORD")?;
            let state = load_state(&cli.state)?;
            let mut client =
                SealbookClient::with_state_and_tls(state, pinned.clone()).context("tls client")?;
            client.login(&password).await.context("login")?;
            let preview = client.pair_preview(&code).await.context("pair preview")?;
            println!(
                "Type the confirmation code shown on the joining device\n(spaces and case are ignored):"
            );
            let mut entered = String::new();
            std::io::stdin().read_line(&mut entered)?;
            client
                .pair_approve_preview(&code, &preview, entered.trim())
                .await
                .context("pair approve")?;
            save_state(&cli.state, client.state.as_ref().unwrap())?;
            println!("device approved");
        }
        Command::Recover { username } => {
            let phrase = read_secret("Recovery phrase: ", "SEALBOOK_PHRASE")?;
            let password = read_secret("Password: ", "SEALBOOK_PASSWORD")?;
            let mut client = SealbookClient::https(pinned.clone()).context("tls client")?;
            let new_phrase = client
                .recover(&cli.server, &username, &phrase, &password)
                .await
                .context("recover")?;
            save_state(&cli.state, client.state.as_ref().unwrap())?;
            println!("recovered {username}");
            println!(
                "\nRecovery rotated the vault key, so the phrase you just used no longer \
                 works.\nWrite these words down. They are shown once:"
            );
            println!("{new_phrase}");
        }
        Command::Phrase {} => {
            let state = load_state(&cli.state)?;
            let password = read_secret("Password: ", "SEALBOOK_PASSWORD")?;
            let mut client =
                SealbookClient::with_state_and_tls(state, pinned.clone()).context("tls client")?;
            client.login(&password).await.context("login")?;
            let new_phrase = client.change_phrase(&password).await.context("phrase")?;
            save_state(&cli.state, client.state.as_ref().unwrap())?;
            println!(
                "The vault key was rotated and your previous recovery phrase no longer \
                 works.\nWrite these words down. They are shown once:"
            );
            println!("{new_phrase}");
        }
        Command::Contacts { command } => match command {
            ContactsCommand::Put { name, email, book } => {
                let state = load_state(&cli.state)?;
                let password = std::env::var("SEALBOOK_PASSWORD")
                    .context("set SEALBOOK_PASSWORD to unwrap the collection key")?;
                let mut client = SealbookClient::with_state_and_tls(state, pinned.clone())
                    .context("tls client")?;
                client.login(&password).await.context("login")?;
                client
                    .ensure_default_address_book()
                    .await
                    .context("default address book")?;
                let books = client.list_address_books().await.context("books")?;
                let book_id =
                    resolve_book(&books, book.as_deref())?.unwrap_or(DEFAULT_ADDRESS_BOOK_ID);
                let contact = jscontact(&name, email.as_deref(), book_id);
                let id = Uuid::new_v4();
                let revision = client.put_contact(id, &contact).await.context("put")?;
                println!("stored encrypted contact {id} at revision {revision}");
            }
            ContactsCommand::Update {
                id,
                name,
                email,
                book,
            } => {
                let state = load_state(&cli.state)?;
                let password = std::env::var("SEALBOOK_PASSWORD")
                    .context("set SEALBOOK_PASSWORD to unwrap the collection key")?;
                let mut client = SealbookClient::with_state_and_tls(state, pinned.clone())
                    .context("tls client")?;
                client.login(&password).await.context("login")?;
                client
                    .ensure_default_address_book()
                    .await
                    .context("default address book")?;
                let books = client.list_address_books().await.context("books")?;
                let book_id =
                    resolve_book(&books, book.as_deref())?.unwrap_or(DEFAULT_ADDRESS_BOOK_ID);
                let contact = jscontact(&name, email.as_deref(), book_id);
                let revision = client.put_contact(id, &contact).await.context("update")?;
                println!("updated encrypted contact {id} at revision {revision}");
            }
            ContactsCommand::Delete { id } => {
                let state = load_state(&cli.state)?;
                let password = std::env::var("SEALBOOK_PASSWORD")
                    .context("set SEALBOOK_PASSWORD to unwrap the collection key")?;
                let mut client =
                    SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
                client.login(&password).await.context("login")?;
                let revision = client.delete_contact(id).await.context("delete")?;
                println!("deleted encrypted contact {id} at revision {revision}");
            }
            ContactsCommand::List { book } => {
                let state = load_state(&cli.state)?;
                let password = std::env::var("SEALBOOK_PASSWORD")
                    .context("set SEALBOOK_PASSWORD to unwrap the collection key")?;
                let mut client =
                    SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
                client.login(&password).await.context("login")?;
                client
                    .ensure_default_address_book()
                    .await
                    .context("default address book")?;
                let books = client.list_address_books().await.context("books")?;
                let book_id = resolve_book(&books, book.as_deref())?;
                let contacts = client.list_contacts().await.context("list")?;
                let visible: Vec<_> = contacts
                    .into_iter()
                    .filter(|(_, json)| match book_id {
                        None => true,
                        Some(id) => contact_book_id(json) == id,
                    })
                    .collect();
                if visible.is_empty() {
                    println!("(no contacts)");
                }
                for (id, json) in visible {
                    let book_name = book_name_for(&books, contact_book_id(&json));
                    println!("{id} [{book_name}] {json}");
                }
            }
        },
        Command::Book { command } => {
            let state = load_state(&cli.state)?;
            let password = std::env::var("SEALBOOK_PASSWORD")
                .context("set SEALBOOK_PASSWORD to unwrap the collection key")?;
            let mut client =
                SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
            client.login(&password).await.context("login")?;
            client
                .ensure_default_address_book()
                .await
                .context("default address book")?;
            match command {
                BookCommand::List => {
                    let books = client.list_address_books().await.context("books")?;
                    for (id, name) in books {
                        println!("{id} {name}");
                    }
                }
                BookCommand::Create { name } => {
                    let id = Uuid::new_v4();
                    client
                        .put_address_book(id, &name)
                        .await
                        .context("create address book")?;
                    println!("created address book {id} {name}");
                }
            }
        }
        Command::Devices { command } => {
            let state = load_state(&cli.state)?;
            let password = read_secret("Password: ", "SEALBOOK_PASSWORD")?;
            let mut client =
                SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
            client.login(&password).await.context("login")?;
            let this_device = client.state.as_ref().unwrap().device_id;
            match command {
                DevicesCommand::List {} => {
                    for device in client.list_devices().await? {
                        let marker = if device.device_id == this_device {
                            " (this device)"
                        } else {
                            ""
                        };
                        println!("{}{marker}", device.device_id);
                    }
                }
                DevicesCommand::Revoke { device_id } => {
                    println!(
                        "Revoking {device_id} rotates the vault key and re-encrypts every \
                         object.\nYour current recovery phrase will stop working and a new \
                         one will be issued."
                    );
                    let phrase = client.revoke_device(device_id, &password).await?;
                    save_state(&cli.state, client.state.as_ref().unwrap())?;
                    println!("\ndevice {device_id} revoked and the vault key rotated");
                    println!(
                        "\nYour previous recovery phrase no longer works. Write these words \
                         down; they are shown once:"
                    );
                    println!("{phrase}");
                }
            }
        }
        Command::Calendar { command } => {
            let state = load_state(&cli.state)?;
            let password = std::env::var("SEALBOOK_PASSWORD")
                .context("set SEALBOOK_PASSWORD to unwrap the collection key")?;
            let mut client =
                SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
            client.login(&password).await.context("login")?;
            match command {
                CalendarCommand::Create { name, color } => {
                    let id = Uuid::new_v4();
                    let revision = client.put_calendar(id, &name, &color).await?;
                    println!("stored encrypted calendar {id} at revision {revision}");
                }
                CalendarCommand::ListCalendars => {
                    for (id, calendar) in client.list_calendars().await? {
                        println!("{id} {calendar}");
                    }
                }
                CalendarCommand::Add {
                    title,
                    start,
                    end,
                    notes,
                    calendar,
                } => {
                    let event = serde_json::json!({
                        "@type": "CalendarEvent", "version": "1.0", "title": title,
                        "start": start, "end": end, "notes": notes, "calendarId": calendar,
                        "calendarId": calendar,
                    });
                    let id = Uuid::new_v4();
                    let revision = client.put_calendar_event(id, &event.to_string()).await?;
                    println!("stored encrypted calendar event {id} at revision {revision}");
                }
                CalendarCommand::List => {
                    for (id, event) in client.list_calendar_events().await? {
                        println!("{id} {event}");
                    }
                }
            }
        }
    }
    Ok(())
}

fn jscontact(name: &str, email: Option<&str>, book_id: Uuid) -> String {
    let mut card = serde_json::json!({
        "@type": "Card",
        "version": "1.0",
        "name": { "full": name },
    });
    card[ADDRESS_BOOK_ID_PROP] = serde_json::Value::String(book_id.to_string());
    if let Some(email) = email {
        card["emails"] = serde_json::json!({ "e1": { "address": email } });
    }
    card.to_string()
}

fn contact_book_id(json: &str) -> Uuid {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .and_then(|value| {
            value
                .get(ADDRESS_BOOK_ID_PROP)
                .and_then(|id| id.as_str())
                .and_then(|id| Uuid::parse_str(id).ok())
        })
        .unwrap_or(DEFAULT_ADDRESS_BOOK_ID)
}

fn book_name_for(books: &[(Uuid, String)], id: Uuid) -> String {
    books
        .iter()
        .find(|(book_id, _)| *book_id == id)
        .map(|(_, name)| name.clone())
        .unwrap_or_else(|| DEFAULT_ADDRESS_BOOK_NAME.to_string())
}

fn resolve_book(books: &[(Uuid, String)], spec: Option<&str>) -> Result<Option<Uuid>> {
    let Some(spec) = spec.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if spec.eq_ignore_ascii_case("all") {
        return Ok(None);
    }
    if let Ok(id) = Uuid::parse_str(spec) {
        if books.iter().any(|(book_id, _)| *book_id == id) {
            return Ok(Some(id));
        }
        anyhow::bail!("unknown address book {spec}");
    }
    let matches: Vec<_> = books
        .iter()
        .filter(|(_, name)| name.eq_ignore_ascii_case(spec))
        .collect();
    match matches.as_slice() {
        [] => anyhow::bail!("unknown address book {spec}"),
        [only] => Ok(Some(only.0)),
        _ => anyhow::bail!("multiple address books named {spec}"),
    }
}

fn save_state(path: &Path, state: &LocalState) -> Result<()> {
    let key = state_key(path)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let plaintext = serde_json::to_vec(state)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: STATE_AAD,
            },
        )
        .map_err(|_| anyhow::anyhow!("encrypt state"))?;
    let json = serde_json::to_vec(&EncryptedState {
        version: STATE_VERSION,
        nonce: nonce.to_vec(),
        ciphertext,
    })?;
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let mut file = OpenOptions::new();
    file.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        file.mode(0o600);
    }
    let mut output = file.open(&temporary)?;
    output.write_all(&json)?;
    output.sync_all()?;
    drop(output);
    std::fs::rename(temporary, path)?;
    Ok(())
}

fn read_secret(prompt: &str, environment: &str) -> Result<String> {
    if let Ok(value) = std::env::var(environment) {
        return Ok(value);
    }
    Ok(rpassword::prompt_password(prompt)?)
}

fn load_ca(path: &Path) -> Result<Option<CertificateDer<'static>>> {
    if !path.exists() {
        return Ok(None);
    }
    let pem = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let cert = CertificateDer::from_pem_slice(&pem).context("parse tls ca")?;
    Ok(Some(cert))
}

fn load_state(path: &Path) -> Result<LocalState> {
    validate_state_permissions(path)?;
    let bytes =
        std::fs::read(path).with_context(|| format!("missing state file {}", path.display()))?;
    if let Ok(envelope) = serde_json::from_slice::<EncryptedState>(&bytes) {
        if envelope.version != STATE_VERSION || envelope.nonce.len() != 24 {
            anyhow::bail!("unsupported or corrupt state file");
        }
        let key = state_key(path)?;
        let plaintext = XChaCha20Poly1305::new(Key::from_slice(&key))
            .decrypt(
                XNonce::from_slice(&envelope.nonce),
                Payload {
                    msg: &envelope.ciphertext,
                    aad: STATE_AAD,
                },
            )
            .map_err(|_| anyhow::anyhow!("unable to decrypt state file"))?;
        return Ok(serde_json::from_slice(&plaintext)?);
    }

    let legacy: LocalState =
        serde_json::from_slice(&bytes).context("invalid state file; expected encrypted state")?;
    save_state(path, &legacy).context("migrate plaintext state file")?;
    Ok(legacy)
}

fn state_key(path: &Path) -> Result<[u8; 32]> {
    let account = hex::encode(Sha256::digest(path.to_string_lossy().as_bytes()));
    let entry = Entry::new(STATE_KEY_SERVICE, &account)?;
    let password = match entry.get_password() {
        Ok(password) => password,
        Err(keyring::Error::NoEntry) => {
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            let password = hex::encode(key);
            entry.set_password(&password)?;
            password
        }
        Err(error) => return Err(error.into()),
    };
    let bytes = hex::decode(password).context("invalid state key in keychain")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid state key length"))
}

fn validate_state_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "state file {} is accessible by other users; restrict it to mode 0600",
                path.display()
            );
        }
    }
    Ok(())
}
