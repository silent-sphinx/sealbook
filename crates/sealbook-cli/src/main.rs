use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom, Write},
};

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
    DEFAULT_ADDRESS_BOOK_NAME, DEFAULT_NOTEBOOK_NAME,
};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
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
#[command(
    name = "sealbook",
    about = "E2EE vault client: contacts, calendars and notes"
)]
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
    /// Recover an account from its 24 recovery words, setting a new password.
    ///
    /// The old password is not needed and stops working: the phrase exists for
    /// the case where the password is what was lost.
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
    Notes {
        #[command(subcommand)]
        command: NotesCommand,
    },
    Notebook {
        #[command(subcommand)]
        command: NotebookCommand,
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
enum NotebookCommand {
    List,
    Create {
        #[arg(long)]
        name: String,
    },
    Delete {
        #[arg(long)]
        id: Uuid,
    },
}

#[derive(Subcommand)]
enum NotesCommand {
    /// Store a note. The markdown body comes from --body, --file, or stdin.
    Add {
        #[arg(long)]
        title: String,
        #[arg(long, conflicts_with = "file")]
        body: Option<String>,
        /// Read the body from a file. `-` means stdin.
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        notebook: Option<Uuid>,
    },
    /// Replace a note's title and body, keeping its original creation time.
    Update {
        #[arg(long)]
        id: Uuid,
        #[arg(long)]
        title: String,
        #[arg(long, conflicts_with = "file")]
        body: Option<String>,
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        notebook: Option<Uuid>,
    },
    /// Titles only. A body can be megabytes, so use `show` for one.
    List {
        #[arg(long)]
        notebook: Option<Uuid>,
    },
    /// Print one note's markdown body on stdout, unchanged.
    Show {
        #[arg(long)]
        id: Uuid,
    },
    Delete {
        #[arg(long)]
        id: Uuid,
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
            sign_in(&mut client, &password).await?;
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
            sign_in(&mut client, &password).await?;
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
            let password = read_new_password()?;
            let mut client = SealbookClient::https(pinned.clone()).context("tls client")?;
            let new_phrase = client
                .recover(&cli.server, &username, &phrase, &password)
                .await
                .context("recover")?;
            save_state(&cli.state, client.state.as_ref().unwrap())?;
            println!("recovered {username}");
            println!("The password you just set replaces the old one, which no longer works.");
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
            sign_in(&mut client, &password).await?;
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
                sign_in(&mut client, &password).await?;
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
                save_state(&cli.state, client.state.as_ref().unwrap())?;
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
                sign_in(&mut client, &password).await?;
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
                save_state(&cli.state, client.state.as_ref().unwrap())?;
            }
            ContactsCommand::Delete { id } => {
                let state = load_state(&cli.state)?;
                let password = std::env::var("SEALBOOK_PASSWORD")
                    .context("set SEALBOOK_PASSWORD to unwrap the collection key")?;
                let mut client =
                    SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
                sign_in(&mut client, &password).await?;
                let revision = client.delete_contact(id).await.context("delete")?;
                println!("deleted encrypted contact {id} at revision {revision}");
                save_state(&cli.state, client.state.as_ref().unwrap())?;
            }
            ContactsCommand::List { book } => {
                let state = load_state(&cli.state)?;
                let password = std::env::var("SEALBOOK_PASSWORD")
                    .context("set SEALBOOK_PASSWORD to unwrap the collection key")?;
                let mut client =
                    SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
                sign_in(&mut client, &password).await?;
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
                save_state(&cli.state, client.state.as_ref().unwrap())?;
            }
        },
        Command::Book { command } => {
            let state = load_state(&cli.state)?;
            let password = std::env::var("SEALBOOK_PASSWORD")
                .context("set SEALBOOK_PASSWORD to unwrap the collection key")?;
            let mut client =
                SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
            sign_in(&mut client, &password).await?;
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
            save_state(&cli.state, client.state.as_ref().unwrap())?;
        }
        Command::Devices { command } => {
            let state = load_state(&cli.state)?;
            let password = read_secret("Password: ", "SEALBOOK_PASSWORD")?;
            let mut client =
                SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
            sign_in(&mut client, &password).await?;
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
            save_state(&cli.state, client.state.as_ref().unwrap())?;
        }
        Command::Calendar { command } => {
            let state = load_state(&cli.state)?;
            let password = std::env::var("SEALBOOK_PASSWORD")
                .context("set SEALBOOK_PASSWORD to unwrap the collection key")?;
            let mut client =
                SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
            sign_in(&mut client, &password).await?;
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
            save_state(&cli.state, client.state.as_ref().unwrap())?;
        }
        Command::Notebook { command } => {
            let state = load_state(&cli.state)?;
            let password = std::env::var("SEALBOOK_PASSWORD")
                .context("set SEALBOOK_PASSWORD to unwrap the collection key")?;
            let mut client =
                SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
            sign_in(&mut client, &password).await?;
            client
                .ensure_default_notebook()
                .await
                .context("default notebook")?;
            match command {
                NotebookCommand::List => {
                    for (id, name) in client.list_notebooks().await.context("notebooks")? {
                        println!("{id} {name}");
                    }
                }
                NotebookCommand::Create { name } => {
                    let id = Uuid::new_v4();
                    client
                        .put_notebook(id, &name)
                        .await
                        .context("create notebook")?;
                    println!("created notebook {id} {name}");
                }
                NotebookCommand::Delete { id } => {
                    let revision = client
                        .delete_notebook(id)
                        .await
                        .context("delete notebook")?;
                    println!("deleted notebook {id} at revision {revision}");
                }
            }
            save_state(&cli.state, client.state.as_ref().unwrap())?;
        }
        Command::Notes { command } => {
            let state = load_state(&cli.state)?;
            let password = std::env::var("SEALBOOK_PASSWORD")
                .context("set SEALBOOK_PASSWORD to unwrap the collection key")?;
            let mut client =
                SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
            sign_in(&mut client, &password).await?;
            let default_notebook = client
                .ensure_default_notebook()
                .await
                .context("default notebook")?;
            match command {
                NotesCommand::Add {
                    title,
                    body,
                    file,
                    notebook,
                } => {
                    let body = read_note_body(body, file)?;
                    let id = Uuid::new_v4();
                    let note = note_json(&title, &body, notebook.unwrap_or(default_notebook), None);
                    let revision = client.put_note(id, &note).await.context("add note")?;
                    println!("stored encrypted note {id} at revision {revision}");
                }
                NotesCommand::Update {
                    id,
                    title,
                    body,
                    file,
                    notebook,
                } => {
                    let body = read_note_body(body, file)?;
                    // Only a client knows when a note was created: the server keeps
                    // no user timestamps, so an update that does not carry the
                    // original forward loses it.
                    let existing = find_note(&mut client, id).await?;
                    let created = note_created_at(&existing);
                    let note = note_json(
                        &title,
                        &body,
                        notebook.unwrap_or_else(|| note_notebook_id(&existing, default_notebook)),
                        created.as_deref(),
                    );
                    let revision = client.put_note(id, &note).await.context("update note")?;
                    println!("updated encrypted note {id} at revision {revision}");
                }
                NotesCommand::List { notebook } => {
                    let notebooks = client.list_notebooks().await.context("notebooks")?;
                    let notes = client.list_notes().await.context("notes")?;
                    let mut shown = 0;
                    for (id, json) in notes {
                        let book = note_notebook_id(&json, default_notebook);
                        if notebook.is_some_and(|want| want != book) {
                            continue;
                        }
                        let name = notebooks
                            .iter()
                            .find(|(candidate, _)| *candidate == book)
                            .map(|(_, name)| name.as_str())
                            .unwrap_or(DEFAULT_NOTEBOOK_NAME);
                        println!("{id} [{name}] {}", note_title(&json));
                        shown += 1;
                    }
                    if shown == 0 {
                        println!("(no notes)");
                    }
                }
                NotesCommand::Show { id } => {
                    let note = find_note(&mut client, id).await?;
                    print!("{}", note_body(&note));
                }
                NotesCommand::Delete { id } => {
                    let revision = client.delete_note(id).await.context("delete note")?;
                    println!("deleted encrypted note {id} at revision {revision}");
                }
            }
            save_state(&cli.state, client.state.as_ref().unwrap())?;
        }
    }
    Ok(())
}

/// The note body, from whichever of the three doors the caller used.
///
/// Reading stdin only when it is not a terminal keeps a forgotten flag from
/// looking like a hang.
fn read_note_body(body: Option<String>, file: Option<PathBuf>) -> Result<String> {
    use std::io::{IsTerminal, Read};
    if let Some(body) = body {
        return Ok(body);
    }
    if let Some(path) = file {
        if path.as_os_str() != "-" {
            return std::fs::read_to_string(&path)
                .with_context(|| format!("read note body from {}", path.display()));
        }
    } else if std::io::stdin().is_terminal() {
        anyhow::bail!("pass --body, --file <path>, or pipe the note body on stdin");
    }
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("read note body from stdin")?;
    Ok(buf)
}

/// Signs in, finishing an interrupted recovery if the server says one is owed.
///
/// A recovery enrols a device without rotating the collection key, so the phrase
/// it used still opens the vault until a rotation lands. If the first attempt
/// died in between, every later command would otherwise refuse to write with
/// nothing to act on. Doing it here means any command picks the rotation up, and
/// the replacement phrase is printed where the user will see it.
async fn sign_in(client: &mut SealbookClient, password: &str) -> Result<()> {
    match client.login(password).await {
        Ok(()) => Ok(()),
        Err(sealbook_client::ClientError::RecoveryRotationPending) => {
            eprintln!(
                "An earlier recovery on this account never finished: the vault key was left \
                 unrotated, so the recovery phrase used then still opens it. Finishing that \
                 now, which re-encrypts the vault and issues a new phrase."
            );
            let phrase = client
                .complete_recovery_rotation(password)
                .await
                .context("finish the interrupted recovery")?;
            println!(
                "\nThe vault key has been rotated. Your previous recovery phrase no longer \
                 works. Write these words down; they are shown once:"
            );
            println!("{phrase}");
            Ok(())
        }
        Err(error) => Err(anyhow::Error::new(error).context("login")),
    }
}

async fn find_note(client: &mut SealbookClient, id: Uuid) -> Result<String> {
    client
        .list_notes()
        .await
        .context("notes")?
        .into_iter()
        .find(|(candidate, _)| *candidate == id)
        .map(|(_, json)| json)
        .with_context(|| format!("no note with id {id}"))
}

fn note_json(title: &str, body: &str, notebook_id: Uuid, created_at: Option<&str>) -> String {
    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default();
    serde_json::json!({
        "@type": "Note",
        "version": "1.0",
        "title": title,
        "body": body,
        "notebookId": notebook_id.to_string(),
        "createdAt": created_at.unwrap_or(&now),
        "updatedAt": now,
    })
    .to_string()
}

fn note_field(json: &str, field: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .and_then(|value| {
            value
                .get(field)
                .and_then(|found| found.as_str())
                .map(ToOwned::to_owned)
        })
}

fn note_title(json: &str) -> String {
    note_field(json, "title")
        .map(|title| title.trim().to_string())
        .filter(|title| !title.is_empty())
        .unwrap_or_else(|| "Untitled".to_string())
}

fn note_body(json: &str) -> String {
    note_field(json, "body").unwrap_or_default()
}

fn note_created_at(json: &str) -> Option<String> {
    note_field(json, "createdAt")
}

fn note_notebook_id(json: &str, fallback: Uuid) -> Uuid {
    note_field(json, "notebookId")
        .and_then(|id| Uuid::parse_str(&id).ok())
        .unwrap_or(fallback)
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

/// Writes the device's local state back, encrypted.
///
/// Every command that signs in has to call this, not just the ones that change
/// the account. The state carries this device's manifest and roster pins, both of
/// which advance as soon as a manifest or roster is accepted, and both of which
/// are what make a server's rollback detectable. A command that skips the write
/// throws its pins away and leaves the next run trusting an older state again.
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

/// Reads a password that is being set rather than checked, so it is confirmed.
///
/// A typo in a recovery would otherwise lock the account to a password nobody
/// knows, with the phrase already spent.
fn read_new_password() -> Result<String> {
    if let Ok(value) = std::env::var("SEALBOOK_PASSWORD") {
        return Ok(value);
    }
    let password = rpassword::prompt_password("New password: ")?;
    let again = rpassword::prompt_password("Confirm new password: ")?;
    if password != again {
        anyhow::bail!("the passwords do not match");
    }
    if password.is_empty() {
        anyhow::bail!("the password cannot be empty");
    }
    Ok(password)
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
    migrate_plaintext_state(path, bytes.len() as u64, || save_state(path, &legacy))
        .context("migrate plaintext state file")?;
    Ok(legacy)
}

/// Replaces a legacy plaintext state file, overwriting the bytes it held.
///
/// `save_state` renames a new file over `path`, which unlinks the plaintext and
/// frees blocks still holding the device signing seeds. The handle is opened
/// before that rename and written through after it, so the bytes overwritten are
/// the old file's own and a crash between the two leaves the encrypted state in
/// place rather than a zeroed file.
fn migrate_plaintext_state(
    path: &Path,
    len: u64,
    replace: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let mut plaintext = OpenOptions::new().write(true).open(path)?;
    replace()?;
    overwrite(&mut plaintext, len)?;
    Ok(())
}

fn overwrite(file: &mut File, len: u64) -> std::io::Result<()> {
    const CHUNK: usize = 8 * 1024;
    let zeros = [0u8; CHUNK];
    file.seek(SeekFrom::Start(0))?;
    let mut remaining = len;
    while remaining > 0 {
        let take = remaining.min(CHUNK as u64) as usize;
        file.write_all(&zeros[..take])?;
        remaining -= take as u64;
    }
    file.sync_all()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The seeds have to leave the blocks they were in, not just the name.
    #[test]
    fn overwriting_a_plaintext_state_file_clears_the_blocks_behind_its_name() {
        let dir = std::env::temp_dir().join(format!("sealbook-shred-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let secret = b"{\"mldsa_seed\":\"do-not-leave-this-on-the-disk\"}";
        std::fs::write(&path, secret).unwrap();
        let link = dir.join("same-inode.json");
        std::fs::hard_link(&path, &link).unwrap();

        // Stands in for `save_state`, which would reach for the keyring.
        let replacement = dir.join("replacement");
        migrate_plaintext_state(&path, secret.len() as u64, || {
            std::fs::write(&replacement, b"encrypted")?;
            std::fs::rename(&replacement, &path)?;
            Ok(())
        })
        .unwrap();

        let through_link = std::fs::read(&link).unwrap();
        assert_eq!(
            through_link,
            vec![0u8; secret.len()],
            "the old blocks still hold the seeds"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"encrypted");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_note_payload_carries_every_field_exactly_once() {
        let notebook = Uuid::from_u128(2);
        let json = note_json("  Weekly plan  ", "# Monday\n\n- ship\n", notebook, None);
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(value["@type"], "Note");
        assert_eq!(value["version"], "1.0");
        assert_eq!(value["body"], "# Monday\n\n- ship\n");
        assert_eq!(value["notebookId"], notebook.to_string());
        assert_eq!(value["createdAt"], value["updatedAt"]);
        // One key per field. The calendar event payload once listed `calendarId`
        // twice, which `json!` accepts silently.
        assert_eq!(json.matches("\"notebookId\"").count(), 1);
        assert_eq!(json.matches("\"createdAt\"").count(), 1);
    }

    #[test]
    fn an_update_keeps_the_original_creation_time() {
        let created = "2020-05-04T03:02:01Z";
        let json = note_json("t", "b", Uuid::from_u128(2), Some(created));
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["createdAt"], created);
        assert_ne!(value["updatedAt"], created);
        assert_eq!(note_created_at(&json).as_deref(), Some(created));
    }

    #[test]
    fn note_fields_fall_back_rather_than_panicking() {
        let fallback = Uuid::from_u128(7);
        assert_eq!(note_title("not json"), "Untitled");
        assert_eq!(note_title(r#"{"title":"   "}"#), "Untitled");
        assert_eq!(note_title(r#"{"title":"  Plan "}"#), "Plan");
        assert_eq!(note_body("not json"), "");
        assert_eq!(note_created_at("not json"), None);
        assert_eq!(note_notebook_id("not json", fallback), fallback);
        assert_eq!(
            note_notebook_id(r#"{"notebookId":"nope"}"#, fallback),
            fallback
        );
        assert_eq!(
            note_notebook_id(
                r#"{"notebookId":"00000000-0000-0000-0000-000000000002"}"#,
                fallback
            ),
            Uuid::from_u128(2)
        );
    }

    #[test]
    fn the_body_comes_from_the_flag_or_the_file() {
        assert_eq!(
            read_note_body(Some("inline".into()), None).unwrap(),
            "inline"
        );

        let path = std::env::temp_dir().join(format!("sealbook-body-{}.md", Uuid::new_v4()));
        std::fs::write(&path, "# From a file\n").unwrap();
        assert_eq!(
            read_note_body(None, Some(path.clone())).unwrap(),
            "# From a file\n"
        );
        std::fs::remove_file(&path).unwrap();

        let missing = std::env::temp_dir().join(format!("sealbook-absent-{}.md", Uuid::new_v4()));
        assert!(read_note_body(None, Some(missing)).is_err());
    }
}
