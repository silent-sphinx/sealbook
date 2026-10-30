use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
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
    account_export_parse, account_export_write, contact_parse, contact_write, event_parse,
    note_parse, note_write, CoreAddressBookDraft, CoreCalendarDraft, CoreCalendarEventDraft,
    CoreChannelKind, CoreContactChannel, CoreContactDraft, CoreNoteDraft, ExportedObject,
    LocalState, SealbookClient, DEFAULT_ADDRESS_BOOK_ID, DEFAULT_ADDRESS_BOOK_NAME,
    DEFAULT_BOOKMARK_COLLECTION_NAME, DEFAULT_CALENDAR_COLOR, DEFAULT_CALENDAR_ID,
    DEFAULT_CALENDAR_NAME, DEFAULT_NOTEBOOK_NAME,
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
    about = "E2EE vault client: contacts, calendars, notes and bookmarks"
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
    /// Write the whole decrypted vault to one JSON file.
    ///
    /// The file is plaintext: everything the vault protects is readable in it,
    /// so it is written 0600 and belongs somewhere encrypted.
    Export {
        /// File to write, replacing it if it exists. Omit to write to stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Write the objects from an export file back into the vault.
    ///
    /// Ids come from the file, so an import into the account the file came from
    /// restores it rather than duplicating it. An object already in the vault is
    /// left alone unless `--overwrite` says otherwise.
    Import {
        /// File to read. Omit to read from stdin.
        #[arg(long)]
        file: Option<PathBuf>,
        /// Replace objects the vault already holds at the same id.
        #[arg(long)]
        overwrite: bool,
    },
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
    Bookmarks {
        #[command(subcommand)]
        command: BookmarksCommand,
    },
    Collection {
        #[command(subcommand)]
        command: CollectionCommand,
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
    /// Add the contacts in a vCard or CSV file, read by the same code every client uses.
    Import {
        /// File to read. Omit to read from stdin.
        #[arg(long)]
        file: Option<PathBuf>,
        /// Address book to add them to, unless a CSV row names its own.
        #[arg(long)]
        book: Option<String>,
    },
    /// Write the contacts as a vCard or CSV file.
    Export {
        /// `vcf` or `csv`.
        #[arg(long, default_value = "vcf")]
        format: String,
        /// File to write. Omit to write to stdout.
        #[arg(long)]
        out: Option<PathBuf>,
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
enum CollectionCommand {
    List,
    Create {
        #[arg(long)]
        name: String,
    },
    /// Rename a collection, leaving its place in the tree alone.
    Rename {
        #[arg(long)]
        id: Uuid,
        #[arg(long)]
        name: String,
    },
    Delete {
        #[arg(long)]
        id: Uuid,
    },
}

#[derive(Subcommand)]
enum BookmarksCommand {
    /// Save a URL.
    Add {
        #[arg(long)]
        url: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        collection: Option<Uuid>,
    },
    /// Replace a bookmark's URL and title, keeping its original creation time.
    ///
    /// The notes and tags a bookmark carries are not written from here, so an
    /// update made with this command leaves them as they were.
    Update {
        #[arg(long)]
        id: Uuid,
        #[arg(long)]
        url: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        collection: Option<Uuid>,
    },
    List {
        #[arg(long)]
        collection: Option<Uuid>,
    },
    /// Print one bookmark's URL on stdout.
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
        #[arg(long, default_value = DEFAULT_CALENDAR_COLOR)]
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
            let mut wait = Duration::from_millis(sealbook_client::PAIR_POLL_INTERVAL_MS.into());
            loop {
                tokio::time::sleep(wait).await;
                match client.pair_poll(&pair_id).await? {
                    sealbook_client::PairPoll::Ready => {
                        println!("approved. sign in with: sealbook login");
                        break;
                    }
                    sealbook_client::PairPoll::Expired => {
                        anyhow::bail!("that pairing request expired; start again")
                    }
                    sealbook_client::PairPoll::Wait { after_ms } => {
                        wait = Duration::from_millis(after_ms.into());
                    }
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
        Command::Export { out } => {
            let state = load_state(&cli.state)?;
            let password = read_secret("Password: ", "SEALBOOK_PASSWORD")?;
            let mut client =
                SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
            sign_in(&mut client, &password).await?;
            let exported = client.export_objects().await.context("export")?;
            let count = exported.objects.len();
            // An export missing objects is a backup missing objects, so it is
            // said plainly rather than left for the count to imply.
            if exported.unreadable > 0 {
                eprintln!(
                    "warning: {} object(s) in this vault could not be read by this device and are \
                     not in the export",
                    exported.unreadable
                );
            }
            let json = account_export(
                client.state.as_ref().unwrap(),
                exported.objects,
                exported.unreadable,
                &OffsetDateTime::now_utc().format(&Rfc3339)?,
            )
            .into_bytes();
            save_state(&cli.state, client.state.as_ref().unwrap())?;
            match out {
                Some(path) => {
                    write_private(&path, &json)
                        .with_context(|| format!("write {}", path.display()))?;
                    println!("exported {count} objects to {}", path.display());
                }
                None => {
                    let mut stdout = std::io::stdout();
                    stdout.write_all(&json)?;
                    stdout.write_all(b"\n")?;
                }
            }
        }
        Command::Import { file, overwrite } => {
            let document = match &file {
                Some(path) => std::fs::read_to_string(path)
                    .with_context(|| format!("read {}", path.display()))?,
                None => {
                    let mut buf = String::new();
                    std::io::stdin()
                        .read_to_string(&mut buf)
                        .context("read stdin")?;
                    buf
                }
            };
            let import = parse_account_export(&document)?;
            let state = load_state(&cli.state)?;
            let password = read_secret("Password: ", "SEALBOOK_PASSWORD")?;
            let mut client =
                SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
            sign_in(&mut client, &password).await?;

            // Read first: an id already in the vault is someone's current object,
            // and overwriting it is a data loss the flag has to ask for.
            let present: std::collections::HashSet<Uuid> = client
                .export_objects()
                .await
                .context("read the vault")?
                .objects
                .into_iter()
                .map(|object| object.id)
                .collect();
            let (writes, skipped) = split_for_import(import.objects, &present, overwrite);

            client.import_objects(&writes).await.context("import")?;
            save_state(&cli.state, client.state.as_ref().unwrap())?;

            println!(
                "imported {} object{} from {}",
                writes.len(),
                if writes.len() == 1 { "" } else { "s" },
                import.source
            );
            if import.unreadable > 0 {
                eprintln!(
                    "warning: the exporting device could not read {} object(s), so this file is \
                     not a complete copy of that vault",
                    import.unreadable
                );
            }
            if !skipped.is_empty() {
                println!(
                    "left {} already in the vault alone; pass --overwrite to replace them",
                    skipped.len()
                );
            }
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
                let contact = jscontact(&name, email.as_deref(), book_id, None)?;
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
                // Merged onto the stored card, so the fields this command does
                // not take are kept. Rebuilding from the three it does took a
                // card with a job, an address and a photo down to a name.
                let existing = find_contact(&mut client, id).await?;
                let contact = jscontact(&name, email.as_deref(), book_id, Some(&existing))?;
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
            ContactsCommand::Import { file, book } => {
                let text = match &file {
                    Some(path) => std::fs::read_to_string(path)
                        .with_context(|| format!("read {}", path.display()))?,
                    None => {
                        let mut buf = String::new();
                        std::io::stdin()
                            .read_to_string(&mut buf)
                            .context("read stdin")?;
                        buf
                    }
                };
                let name = file
                    .as_ref()
                    .map(|path| path.to_string_lossy().to_string())
                    .unwrap_or_default();
                let state = load_state(&cli.state)?;
                let password = read_secret("Password: ", "SEALBOOK_PASSWORD")?;
                let mut client =
                    SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
                sign_in(&mut client, &password).await?;
                client
                    .ensure_default_address_book()
                    .await
                    .context("default address book")?;
                let books = client.list_address_books().await.context("books")?;
                let book_id =
                    resolve_book(&books, book.as_deref())?.unwrap_or(DEFAULT_ADDRESS_BOOK_ID);
                let read = read_contacts(&name, &text, book_id)?;
                let now = now_rfc3339();
                for draft in &read.contacts {
                    let card = contact_write(draft, &now)?;
                    client
                        .put_contact(Uuid::new_v4(), &card)
                        .await
                        .context("put")?;
                }
                println!(
                    "imported {} contact(s), skipped {}",
                    read.contacts.len(),
                    read.skipped.len()
                );
                for skipped in &read.skipped {
                    println!("skipped {}: {}", skipped.label, skipped.reason);
                }
                save_state(&cli.state, client.state.as_ref().unwrap())?;
            }
            ContactsCommand::Export { format, out, book } => {
                let state = load_state(&cli.state)?;
                let password = read_secret("Password: ", "SEALBOOK_PASSWORD")?;
                let mut client =
                    SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
                sign_in(&mut client, &password).await?;
                client
                    .ensure_default_address_book()
                    .await
                    .context("default address book")?;
                let books = client.list_address_books().await.context("books")?;
                let book_id = resolve_book(&books, book.as_deref())?;
                let drafts: Vec<CoreContactDraft> = client
                    .list_contacts()
                    .await
                    .context("list")?
                    .into_iter()
                    .filter(|(_, json)| book_id.is_none_or(|id| contact_book_id(json) == id))
                    .map(|(id, json)| contact_parse(&id.to_string(), &json).draft())
                    .collect();
                let data = write_contacts(&format, &drafts, &books)?;
                match out {
                    Some(path) => std::fs::write(&path, data)
                        .with_context(|| format!("write {}", path.display()))?,
                    None => print!("{data}"),
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
                        .put_address_book(
                            id,
                            &CoreAddressBookDraft {
                                name: name.clone(),
                                raw: None,
                            },
                        )
                        .await
                        .context("create address book")?;
                    println!("created address book {id} {name}");
                }
            }
            save_state(&cli.state, client.state.as_ref().unwrap())?;
        }
        Command::Collection { command } => {
            let state = load_state(&cli.state)?;
            let password = std::env::var("SEALBOOK_PASSWORD")
                .context("set SEALBOOK_PASSWORD to unwrap the collection key")?;
            let mut client =
                SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
            sign_in(&mut client, &password).await?;
            client
                .ensure_default_bookmark_collection()
                .await
                .context("default collection")?;
            match command {
                CollectionCommand::List => {
                    for (id, name) in client
                        .list_bookmark_collections()
                        .await
                        .context("collections")?
                    {
                        println!("{id} {name}");
                    }
                }
                CollectionCommand::Create { name } => {
                    let id = Uuid::new_v4();
                    client
                        .put_bookmark_collection(id, &name, None)
                        .await
                        .context("create collection")?;
                    println!("created collection {id} {name}");
                }
                CollectionCommand::Rename { id, name } => {
                    // Merged onto the stored payload so `parentId`, which the web
                    // client owns, survives a rename made from here.
                    let existing = find_bookmark_collection(&mut client, id).await?;
                    client
                        .put_bookmark_collection(id, &name, Some(&existing))
                        .await
                        .context("rename collection")?;
                    println!("renamed collection {id} {name}");
                }
                CollectionCommand::Delete { id } => {
                    let revision = client
                        .delete_bookmark_collection(id)
                        .await
                        .context("delete collection")?;
                    println!("deleted collection {id} at revision {revision}");
                }
            }
            save_state(&cli.state, client.state.as_ref().unwrap())?;
        }
        Command::Bookmarks { command } => {
            let state = load_state(&cli.state)?;
            let password = std::env::var("SEALBOOK_PASSWORD")
                .context("set SEALBOOK_PASSWORD to unwrap the collection key")?;
            let mut client =
                SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
            sign_in(&mut client, &password).await?;
            let default_collection = client
                .ensure_default_bookmark_collection()
                .await
                .context("default collection")?;
            match command {
                BookmarksCommand::Add {
                    url,
                    title,
                    collection,
                } => {
                    let id = Uuid::new_v4();
                    let bookmark = bookmark_json(
                        &url,
                        title.as_deref(),
                        collection.unwrap_or(default_collection),
                        None,
                    )?;
                    let revision = client
                        .put_bookmark(id, &bookmark)
                        .await
                        .context("add bookmark")?;
                    println!("stored encrypted bookmark {id} at revision {revision}");
                }
                BookmarksCommand::Update {
                    id,
                    url,
                    title,
                    collection,
                } => {
                    let existing = find_bookmark(&mut client, id).await?;
                    let bookmark = bookmark_json(
                        &url,
                        title.as_deref(),
                        collection.unwrap_or_else(|| {
                            bookmark_collection_id(&existing, default_collection)
                        }),
                        Some(&existing),
                    )?;
                    let revision = client
                        .put_bookmark(id, &bookmark)
                        .await
                        .context("update bookmark")?;
                    println!("updated encrypted bookmark {id} at revision {revision}");
                }
                BookmarksCommand::List { collection } => {
                    let collections = client
                        .list_bookmark_collections()
                        .await
                        .context("collections")?;
                    let bookmarks = client.list_bookmarks().await.context("bookmarks")?;
                    let mut shown = 0;
                    for (id, json) in bookmarks {
                        let holder = bookmark_collection_id(&json, default_collection);
                        if collection.is_some_and(|want| want != holder) {
                            continue;
                        }
                        let name = collections
                            .iter()
                            .find(|(candidate, _)| *candidate == holder)
                            .map(|(_, name)| name.as_str())
                            .unwrap_or(DEFAULT_BOOKMARK_COLLECTION_NAME);
                        println!(
                            "{id} [{name}] {} {}",
                            bookmark_title(&json),
                            bookmark_url(&json)
                        );
                        shown += 1;
                    }
                    if shown == 0 {
                        println!("(no bookmarks)");
                    }
                }
                BookmarksCommand::Show { id } => {
                    let bookmark = find_bookmark(&mut client, id).await?;
                    println!("{}", bookmark_url(&bookmark));
                }
                BookmarksCommand::Delete { id } => {
                    let revision = client
                        .delete_bookmark(id)
                        .await
                        .context("delete bookmark")?;
                    println!("deleted encrypted bookmark {id} at revision {revision}");
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
            client
                .ensure_default_calendar()
                .await
                .context("default calendar")?;
            match command {
                CalendarCommand::Create { name, color } => {
                    let id = Uuid::new_v4();
                    let revision = client
                        .put_calendar(
                            id,
                            &CoreCalendarDraft {
                                name,
                                color,
                                ..Default::default()
                            },
                        )
                        .await?;
                    println!("stored encrypted calendar {id} at revision {revision}");
                }
                CalendarCommand::ListCalendars => {
                    for (id, name) in client.list_calendars().await? {
                        println!("{id} {name}");
                    }
                }
                CalendarCommand::Add {
                    title,
                    start,
                    end,
                    notes,
                    calendar,
                } => {
                    let id = Uuid::new_v4();
                    let revision = client
                        .put_calendar_event(
                            id,
                            &CoreCalendarEventDraft {
                                title,
                                start,
                                end,
                                notes,
                                // The other clients leave a missing calendar
                                // absent, which their grids read as "in no
                                // calendar". This command has no picker, so it
                                // names the default one rather than writing an
                                // event no calendar owns.
                                calendar_id: Some(
                                    calendar.unwrap_or(DEFAULT_CALENDAR_ID).to_string(),
                                ),
                                ..Default::default()
                            },
                        )
                        .await?;
                    println!("stored encrypted calendar event {id} at revision {revision}");
                }
                CalendarCommand::List => {
                    let calendars = client.list_calendars().await?;
                    for (id, json) in client.list_calendar_events().await? {
                        let event = event_parse(&id.to_string(), &json);
                        let name = event
                            .calendar_id
                            .as_deref()
                            .map(|calendar_id| {
                                calendars
                                    .iter()
                                    .find(|(candidate, _)| candidate.to_string() == calendar_id)
                                    .map(|(_, name)| name.as_str())
                                    .unwrap_or(DEFAULT_CALENDAR_NAME)
                            })
                            .unwrap_or("no calendar");
                        println!("{id} [{name}] {} {}", event.start, event.title);
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
                        .put_notebook(id, &name, None)
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
                    let note = note_write(
                        &CoreNoteDraft {
                            title,
                            body,
                            notebook_id: notebook.unwrap_or(default_notebook).to_string(),
                            ..Default::default()
                        },
                        &now_rfc3339(),
                    )?;
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
                    let existing = find_note(&mut client, id).await?;
                    let note = note_write(
                        &note_update_draft(&existing, id, title, body, notebook),
                        &now_rfc3339(),
                    )?;
                    let revision = client.put_note(id, &note).await.context("update note")?;
                    println!("updated encrypted note {id} at revision {revision}");
                }
                NotesCommand::List { notebook } => {
                    let notebooks = client.list_notebooks().await.context("notebooks")?;
                    let notes = client.list_notes().await.context("notes")?;
                    let mut shown = 0;
                    for (id, json) in notes {
                        let note = note_parse(&id.to_string(), &json);
                        if notebook.is_some_and(|want| want.to_string() != note.notebook_id) {
                            continue;
                        }
                        let name = notebooks
                            .iter()
                            .find(|(candidate, _)| candidate.to_string() == note.notebook_id)
                            .map(|(_, name)| name.as_str())
                            .unwrap_or(DEFAULT_NOTEBOOK_NAME);
                        println!("{id} [{name}] {}", note.title);
                        shown += 1;
                    }
                    if shown == 0 {
                        println!("(no notes)");
                    }
                }
                NotesCommand::Show { id } => {
                    let note = find_note(&mut client, id).await?;
                    print!("{}", note_parse(&id.to_string(), &note).body);
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

async fn find_contact(client: &mut SealbookClient, id: Uuid) -> Result<String> {
    client
        .list_contacts()
        .await
        .context("contacts")?
        .into_iter()
        .find(|(candidate, _)| *candidate == id)
        .map(|(_, json)| json)
        .with_context(|| format!("no contact with id {id}"))
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

async fn find_bookmark(client: &mut SealbookClient, id: Uuid) -> Result<String> {
    client
        .list_bookmarks()
        .await
        .context("bookmarks")?
        .into_iter()
        .find(|(candidate, _)| *candidate == id)
        .map(|(_, json)| json)
        .with_context(|| format!("no bookmark with id {id}"))
}

async fn find_bookmark_collection(client: &mut SealbookClient, id: Uuid) -> Result<String> {
    let collections = client
        .list_bookmark_collections()
        .await
        .context("collections")?;
    if !collections.iter().any(|(candidate, _)| *candidate == id) {
        anyhow::bail!("no collection with id {id}");
    }
    // `list_bookmark_collections` yields names, not payloads, and a rename has to
    // merge onto the stored JSON to keep `parentId`. So read the object itself.
    client
        .export_objects()
        .await
        .context("collections")?
        .objects
        .into_iter()
        .find(|object| object.id == id)
        .map(|object| object.payload)
        .with_context(|| format!("no collection with id {id}"))
}

/// Writes a bookmark through core, onto the stored one when there is one.
///
/// The stored bookmark is read into core's record and handed back whole, so
/// `notes`, `tags` and anything a newer client added travel through the edit.
/// A title left out keeps the stored one, and on a new bookmark is left empty:
/// the address is what a reader lists it by, and is not written as a title.
fn bookmark_json(
    url: &str,
    title: Option<&str>,
    collection_id: Uuid,
    previous: Option<&str>,
) -> Result<String> {
    let now = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let mut draft = previous
        .map(|raw| sealbook_client::bookmark_parse("", raw).draft())
        .unwrap_or_default();
    draft.url = url.to_string();
    if let Some(title) = title.map(str::trim).filter(|title| !title.is_empty()) {
        draft.title = title.to_string();
    }
    draft.collection_id = collection_id.to_string();
    Ok(sealbook_client::bookmark_write(&draft, &now)?)
}

fn bookmark_url(json: &str) -> String {
    sealbook_client::bookmark_parse("", json).url
}

fn bookmark_title(json: &str) -> String {
    sealbook_client::bookmark_parse("", json).title
}

fn bookmark_collection_id(json: &str, fallback: Uuid) -> Uuid {
    Uuid::parse_str(&sealbook_client::bookmark_parse("", json).collection_id).unwrap_or(fallback)
}

/// The draft a `notes update` writes, built from the stored note.
///
/// The note is read into core's record first and handed back whole, so a field
/// this CLI has no flag for travels through the edit: its place in the note
/// tree, its photo references, whether it is pinned, and anything a newer
/// client has since added. Before core owned the writer this command rebuilt
/// the payload from the three fields it takes and dropped the rest, which is
/// data loss with nothing on screen to show for it.
///
/// `pinned` is left as `None` rather than carried on the record: the CLI has no
/// opinion about pinning, so core leaves whatever is stored alone. Only the
/// creation time is read back deliberately — the server keeps no user
/// timestamps, so an update that does not carry it forward loses it.
fn note_update_draft(
    stored: &str,
    id: Uuid,
    title: String,
    body: String,
    notebook: Option<Uuid>,
) -> CoreNoteDraft {
    let note = note_parse(&id.to_string(), stored);
    CoreNoteDraft {
        title,
        body,
        notebook_id: notebook
            .map(|notebook| notebook.to_string())
            .unwrap_or(note.notebook_id),
        parent_id: note.parent_id,
        attachments: note.attachments,
        created_at: note.created_at,
        pinned: None,
        raw: Some(stored.to_string()),
    }
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// The contacts in a JSON, vCard or CSV file.
fn read_contacts(
    filename: &str,
    text: &str,
    book_id: Uuid,
) -> Result<sealbook_client::CoreContactFile> {
    sealbook_client::contacts_import(filename, text, &book_id.to_string())
        .map_err(|e| anyhow::anyhow!("{e}"))
}

fn write_contacts(
    format: &str,
    drafts: &[CoreContactDraft],
    books: &[(Uuid, String)],
) -> Result<String> {
    match format.to_lowercase().as_str() {
        "vcf" | "vcard" => Ok(sealbook_client::vcard_write(drafts)),
        "csv" => {
            let books: Vec<sealbook_client::CoreAddressBook> = books
                .iter()
                .map(|(id, name)| sealbook_client::CoreAddressBook {
                    id: id.to_string(),
                    name: name.clone(),
                    readable: true,
                    raw: String::new(),
                })
                .collect();
            Ok(sealbook_client::csv_write(drafts, &books))
        }
        other => anyhow::bail!("unknown format {other}: use vcf or csv"),
    }
}

/// A card for `contacts put` and `contacts update`.
///
/// Built from the stored card when there is one, so the fields this command does
/// not take are kept, and written through core like every other client's. The
/// email replaces the first one the card has and leaves the rest: this used to
/// replace the whole map, which dropped every other address and the context each
/// one carried.
fn jscontact(
    name: &str,
    email: Option<&str>,
    book_id: Uuid,
    previous: Option<&str>,
) -> Result<String> {
    let mut draft = match previous {
        Some(raw) => contact_parse(&Uuid::nil().to_string(), raw).draft(),
        None => CoreContactDraft::default(),
    };
    draft.name = name.to_string();
    draft.address_book_id = book_id.to_string();
    if let Some(email) = email {
        match draft.emails.first_mut() {
            Some(first) => first.value = email.to_string(),
            None => draft.emails.push(CoreContactChannel {
                kind: CoreChannelKind::Home,
                label: None,
                value: email.to_string(),
                extra: None,
            }),
        }
    }
    Ok(contact_write(&draft, &now_rfc3339())?)
}

/// The whole vault as one JSON document, written by core.
fn account_export(
    state: &LocalState,
    objects: Vec<ExportedObject>,
    unreadable: u64,
    exported_at: &str,
) -> String {
    let account = sealbook_client::CoreExportAccount {
        server: state.server.clone(),
        username: state.username.clone(),
        account_id: state.account_id.to_string(),
        collection_id: state.collection_id.to_string(),
        device_id: state.device_id.to_string(),
    };
    let objects: Vec<sealbook_client::CoreExportObject> = objects
        .into_iter()
        .map(|object| sealbook_client::CoreExportObject {
            id: object.id.to_string(),
            content_type: object.content_type,
            payload: object.payload,
        })
        .collect();
    account_export_write(
        &account,
        &objects,
        u32::try_from(unreadable).unwrap_or(u32::MAX),
        exported_at,
    )
}

/// Splits a file's objects into the ones to write and the ones to leave.
///
/// An id already live in the vault is someone's current object, and the file's
/// copy of it may be older, so replacing it is a data loss `--overwrite` has to
/// ask for. A tombstoned id is not live and so is written: restoring something
/// that was deleted after the backup is the point of a restore.
fn split_for_import(
    objects: Vec<ExportedObject>,
    present: &std::collections::HashSet<Uuid>,
    overwrite: bool,
) -> (Vec<ExportedObject>, Vec<ExportedObject>) {
    objects
        .into_iter()
        .partition(|object| overwrite || !present.contains(&object.id))
}

/// An export file, read back.
struct AccountImport {
    objects: Vec<ExportedObject>,
    /// The account the file was written from, for the line the import prints.
    source: String,
    /// Objects the exporting device could not open.
    unreadable: u32,
}

fn parse_account_export(document: &str) -> Result<AccountImport> {
    let import = account_export_parse(document)?;
    let objects = import
        .objects
        .into_iter()
        .map(|object| {
            Ok(ExportedObject {
                id: Uuid::parse_str(&object.id)?,
                content_type: object.content_type,
                payload: object.payload,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(AccountImport {
        objects,
        source: import.source,
        unreadable: import.unreadable,
    })
}

fn contact_book_id(json: &str) -> Uuid {
    Uuid::parse_str(&contact_parse("", json).address_book_id).unwrap_or(DEFAULT_ADDRESS_BOOK_ID)
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
    write_private(path, &json)
}

/// Writes `bytes` to `path` through a 0600 temporary file, replacing whatever
/// was there. The mode is set at creation rather than after the write, so the
/// contents are never briefly world-readable.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let mut file = OpenOptions::new();
    file.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        file.mode(0o600);
    }
    let mut output = file.open(&temporary)?;
    output.write_all(bytes)?;
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
    use sealbook_client::PAYLOAD_SCHEMA_VERSION;

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

    /// The CLI writes a note through core now, so what is worth testing here is
    /// the CLI's own half of the agreement: that the draft it builds for an
    /// update hands back every field it read. Forgetting one is the way a field
    /// still gets dropped, and it is how `parentId` was lost before.
    #[test]
    fn an_update_hands_back_every_field_it_read() {
        let notebook = Uuid::from_u128(2);
        let attachments = serde_json::json!([
            {
                "id": Uuid::from_u128(42).to_string(),
                "filename": "sunset.jpg",
                "mimeType": "image/jpeg",
                "byteSize": 1_234_567,
                "adk": "Zm9vYmFy",
                "contentHash": "YmF6cXV4",
                "chunkSize": 4_194_304,
                "chunkCount": 1,
            }
        ]);
        let stored = serde_json::json!({
            "@type": "Note",
            "version": "1.0",
            "title": "old",
            "body": "old body",
            "notebookId": notebook.to_string(),
            "createdAt": "2020-05-04T03:02:01Z",
            "updatedAt": "2020-05-04T03:02:01Z",
            "pinned": true,
            "parentId": Uuid::from_u128(9).to_string(),
            "tableOfContents": true,
            "attachments": attachments.clone(),
        })
        .to_string();

        let draft = note_update_draft(
            &stored,
            Uuid::from_u128(7),
            "new".into(),
            "new body".into(),
            None,
        );
        let json = note_write(&draft, "2026-10-28T12:00:00Z").expect("writes");
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["title"], "new");
        assert_eq!(value["body"], "new body");
        assert_eq!(value["notebookId"], notebook.to_string());
        // The server keeps no user timestamps, so this is the client's to carry.
        assert_eq!(value["createdAt"], "2020-05-04T03:02:01Z");
        assert_eq!(value["updatedAt"], "2026-10-28T12:00:00Z");
        assert_eq!(value["parentId"], Uuid::from_u128(9).to_string());
        assert_eq!(value["pinned"], true);
        assert_eq!(value["tableOfContents"], true);
        assert_eq!(
            value["attachments"], attachments,
            "editing a note through the CLI dropped its photo attachments"
        );
    }

    #[test]
    fn an_update_can_move_a_note_to_another_notebook() {
        let stored = serde_json::json!({
            "@type": "Note",
            "notebookId": Uuid::from_u128(2).to_string(),
        })
        .to_string();
        let moved = Uuid::from_u128(11);
        let draft = note_update_draft(
            &stored,
            Uuid::from_u128(7),
            "t".into(),
            "b".into(),
            Some(moved),
        );
        assert_eq!(draft.notebook_id, moved.to_string());
    }

    #[test]
    fn a_bookmark_carries_its_url_title_and_collection() {
        let collection = Uuid::from_u128(5);
        let json = bookmark_json("example.com/a", Some("Example"), collection, None).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["@type"], "Bookmark");
        assert_eq!(value["version"], PAYLOAD_SCHEMA_VERSION);
        assert_eq!(value["url"], "https://example.com/a");
        assert_eq!(value["title"], "Example");
        assert_eq!(value["collectionId"], collection.to_string());
        assert_eq!(json.matches("\"collectionId\"").count(), 1);
        assert_eq!(bookmark_url(&json), "https://example.com/a");
        assert_eq!(bookmark_title(&json), "Example");
        assert_eq!(
            bookmark_collection_id(&json, Uuid::from_u128(1)),
            collection
        );
    }

    #[test]
    fn a_bookmark_without_a_title_is_not_titled_with_its_url() {
        for title in [None, Some(""), Some("   ")] {
            let json =
                bookmark_json("https://example.com/b", title, Uuid::from_u128(5), None).unwrap();
            let value: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(value["title"], "");
        }
    }

    #[test]
    fn a_bookmark_update_keeps_the_original_creation_time_and_title() {
        let stored = serde_json::json!({
            "@type": "Bookmark",
            "url": "https://example.com/c",
            "title": "kept",
            "createdAt": "2020-05-04T03:02:01Z",
        })
        .to_string();
        let json = bookmark_json(
            "https://example.com/c",
            None,
            Uuid::from_u128(5),
            Some(&stored),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["createdAt"], "2020-05-04T03:02:01Z");
        assert_eq!(value["title"], "kept");
        assert_ne!(value["updatedAt"], "2020-05-04T03:02:01Z");
    }

    #[test]
    fn a_bookmark_update_keeps_the_fields_this_cli_does_not_write() {
        let stored = serde_json::json!({
            "@type": "Bookmark",
            "version": "1.0",
            "url": "https://example.com/old",
            "title": "old",
            "collectionId": Uuid::from_u128(5).to_string(),
            "createdAt": "2020-05-04T03:02:01Z",
            "updatedAt": "2020-05-04T03:02:01Z",
            "notes": "why I saved it",
            "tags": ["rust", "reading"],
            "favicon": "data:,",
        })
        .to_string();

        let json = bookmark_json(
            "https://example.com/new",
            Some("new"),
            Uuid::from_u128(5),
            Some(&stored),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["url"], "https://example.com/new");
        assert_eq!(value["title"], "new");
        assert_eq!(value["notes"], "why I saved it");
        assert_eq!(value["tags"], serde_json::json!(["rust", "reading"]));
        assert_eq!(value["favicon"], "data:,");
    }

    #[test]
    fn an_unreadable_bookmark_resolves_to_the_default_collection() {
        let fallback = Uuid::from_u128(5);
        assert_eq!(bookmark_collection_id("not json", fallback), fallback);
        assert_eq!(bookmark_collection_id("{}", fallback), fallback);
        assert_eq!(
            bookmark_collection_id(r#"{"collectionId":"nope"}"#, fallback),
            fallback
        );
    }

    #[test]
    fn a_vcard_file_is_read_and_written_back_by_core() {
        let book = Uuid::from_u128(7);
        let text =
            "BEGIN:VCARD\nFN:Ada\nEMAIL:ada@example.com\nEND:VCARD\nBEGIN:VCARD\nNOTE:x\nEND:VCARD";
        let read = read_contacts("people.vcf", text, book).unwrap();
        assert_eq!(read.contacts.len(), 1);
        assert_eq!(read.skipped.len(), 1);
        assert_eq!(read.contacts[0].address_book_id, book.to_string());
        let out = write_contacts("vcf", &read.contacts, &[]).unwrap();
        assert!(out.contains("FN:Ada"));
    }

    #[test]
    fn a_csv_file_is_the_fallback_and_exports_as_csv() {
        let read =
            read_contacts("people.csv", "Name,Email\nGrace,g@example.com", Uuid::nil()).unwrap();
        assert_eq!(read.contacts[0].name, "Grace");
        let out = write_contacts("csv", &read.contacts, &[]).unwrap();
        assert!(out.contains("Grace"));
        assert!(write_contacts("pdf", &read.contacts, &[]).is_err());
    }

    #[test]
    fn a_contact_update_keeps_the_fields_this_cli_does_not_write() {
        let stored = serde_json::json!({
            "@type": "Card",
            "version": "1.0",
            "name": { "full": "Ada Lovelace" },
            "emails": {
                "e1": { "address": "old@example.com", "contexts": { "work": true } },
                "e2": { "address": "other@example.com" }
            },
            "organizations": { "o1": { "name": "Analytical Engines" } },
            "titles": { "t1": { "name": "Mathematician", "organization": "o1" } },
            "addresses": {
                "a1": { "locality": "London" },
                "a2": { "locality": "Paris" }
            },
            "media": { "avatar": { "kind": "photo", "uri": "data:," } },
            "sealbook:profile": { "colleagues": [{ "name": "Charles" }] },
            "ranking": 9,
        })
        .to_string();

        let card = jscontact(
            "Ada King",
            Some("ada@example.com"),
            DEFAULT_ADDRESS_BOOK_ID,
            Some(&stored),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&card).unwrap();
        assert_eq!(value["name"]["full"], "Ada King");
        assert_eq!(value["emails"]["e1"]["address"], "ada@example.com");
        assert_eq!(value["emails"]["e1"]["contexts"]["work"], true);
        assert_eq!(value["emails"]["e2"]["address"], "other@example.com");
        // Everything this command cannot express survives it.
        assert_eq!(value["titles"]["t1"]["name"], "Mathematician");
        assert_eq!(value["addresses"]["a2"]["locality"], "Paris");
        assert_eq!(value["media"]["avatar"]["kind"], "photo");
        assert_eq!(
            value["sealbook:profile"]["colleagues"][0]["name"],
            "Charles"
        );
        assert_eq!(value["ranking"], 9);
        assert!(value["updated"].is_string());
    }

    /// The lenient read lives in core now, and the shared fixture pins it. What
    /// this keeps is the one place the CLI still turns a payload into a row:
    /// a note whose notebook is gone is still listed, under the default
    /// notebook's name rather than nothing.
    #[test]
    fn a_note_that_will_not_parse_is_still_a_row_the_user_can_delete() {
        let note = note_parse(&Uuid::from_u128(7).to_string(), "not json");
        assert_eq!(note.title, "Unreadable note");
        assert_eq!(note.notebook_id, Uuid::from_u128(2).to_string());
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

    fn export_state() -> LocalState {
        LocalState {
            server: "https://vault.example".into(),
            username: "alice".into(),
            account_id: Uuid::from_u128(10),
            collection_id: Uuid::from_u128(11),
            device_id: Uuid::from_u128(12),
            session_token: None,
            kdf_salt: Vec::new(),
            hpke_sk: Vec::new(),
            mldsa_seed: Vec::new(),
            ed25519_sk: Vec::new(),
            manifest_seq: 0,
            roster_seq: 0,
            roster_transcript: Vec::new(),
        }
    }

    fn exported(id: u128, content_type: &str, payload: &str) -> ExportedObject {
        ExportedObject {
            id: Uuid::from_u128(id),
            content_type: content_type.to_string(),
            payload: payload.to_string(),
        }
    }

    fn export_value(objects: Vec<ExportedObject>, exported_at: &str) -> serde_json::Value {
        let document = account_export(&export_state(), objects, 0, exported_at);
        serde_json::from_str(&document).unwrap()
    }

    #[test]
    fn an_export_carries_every_object_including_a_type_this_build_cannot_read() {
        let objects = vec![
            exported(1, "application/jscontact+json", r#"{"@type":"Card"}"#),
            exported(
                2,
                "application/sealbook.note+json",
                r#"{"@type":"Note","title":"Plan","pinned":true}"#,
            ),
            exported(3, "application/sealbook.future+json", r#"{"keep":"me"}"#),
        ];
        let document = export_value(objects, "2026-10-10T00:00:00Z");

        assert_eq!(document["@type"], "SealbookAccountExport");
        assert_eq!(document["version"], "1.0");
        assert_eq!(document["exportedAt"], "2026-10-10T00:00:00Z");
        assert_eq!(document["account"]["username"], "alice");
        assert_eq!(document["account"]["server"], "https://vault.example");
        assert_eq!(
            document["account"]["collectionId"],
            Uuid::from_u128(11).to_string()
        );
        assert_eq!(document["objectCount"], 3);

        let objects = document["objects"].as_array().expect("objects");
        assert_eq!(objects.len(), 3);
        let note = objects
            .iter()
            .find(|object| object["id"] == Uuid::from_u128(2).to_string())
            .expect("the note");
        assert_eq!(note["contentType"], "application/sealbook.note+json");
        // Stored fields the CLI itself never writes are in the backup.
        assert_eq!(note["payload"]["pinned"], true);
        let future = objects
            .iter()
            .find(|object| object["id"] == Uuid::from_u128(3).to_string())
            .expect("the future type");
        assert_eq!(future["payload"]["keep"], "me");
    }

    #[test]
    fn an_export_keeps_a_payload_that_is_not_json_rather_than_dropping_it() {
        let objects = vec![exported(1, "application/octet-stream", "not json at all")];
        let document = export_value(objects, "2026-10-10T00:00:00Z");
        let entry = &document["objects"][0];
        assert_eq!(entry["text"], "not json at all");
        assert!(entry["payload"].is_null());
    }

    #[test]
    fn a_task_object_survives_an_export_and_import_untouched() {
        let task = r#"{"@type":"Task","version":"1.0","title":"Water plants","taskListId":"00000000-0000-0000-0000-000000000006","dueDate":"2026-10-23T08:30:00.000Z","priority":7,"parentId":"p1","recurrence":{"frequency":"weekly","weekdays":[1,4],"interval":2},"recurrenceAnchor":"2026-10-22","completions":["2026-10-15T09:00:00.000Z"],"dueTimezone":"Europe/London"}"#;
        let list = r##"{"@type":"TaskList","version":"1.0","name":"Work","color":"#7aa2f7"}"##;
        let objects = vec![
            exported(1, sealbook_client::TASK_CONTENT_TYPE, task),
            exported(2, sealbook_client::TASK_LIST_CONTENT_TYPE, list),
        ];
        let document = export_value(objects, "2026-10-22T00:00:00Z");

        let exported_task = &document["objects"][0]["payload"];
        assert_eq!(exported_task["priority"], 7);
        assert_eq!(exported_task["recurrence"]["weekdays"][1], 4);
        assert_eq!(exported_task["dueTimezone"], "Europe/London");

        let import = parse_account_export(&document.to_string()).unwrap();
        let read: Vec<(String, serde_json::Value)> = import
            .objects
            .into_iter()
            .map(|object| {
                (
                    object.content_type,
                    serde_json::from_str(&object.payload).unwrap(),
                )
            })
            .collect();
        assert_eq!(read[0].0, "application/sealbook.task+json");
        assert_eq!(
            read[0].1,
            serde_json::from_str::<serde_json::Value>(task).unwrap()
        );
        assert_eq!(read[1].0, "application/sealbook.task-list+json");
        assert_eq!(
            read[1].1,
            serde_json::from_str::<serde_json::Value>(list).unwrap()
        );
    }

    #[test]
    fn an_export_reads_back_as_the_objects_it_was_written_from() {
        let objects = vec![
            exported(1, "application/jscontact+json", r#"{"@type":"Card"}"#),
            exported(2, "application/sealbook.future+json", r#"{"keep":"me"}"#),
            exported(3, "application/octet-stream", "not json at all"),
        ];
        let document = export_value(objects, "2026-10-10T00:00:00Z");
        let import = parse_account_export(&document.to_string()).unwrap();

        assert_eq!(import.source, "alice at https://vault.example");
        let read: Vec<(Uuid, String, String)> = import
            .objects
            .into_iter()
            .map(|object| (object.id, object.content_type, object.payload))
            .collect();
        assert_eq!(
            read,
            vec![
                (
                    Uuid::from_u128(1),
                    "application/jscontact+json".to_string(),
                    r#"{"@type":"Card"}"#.to_string()
                ),
                // The `text` escape hatch comes back as those bytes, not as JSON.
                (
                    Uuid::from_u128(3),
                    "application/octet-stream".to_string(),
                    "not json at all".to_string()
                ),
                (
                    Uuid::from_u128(2),
                    "application/sealbook.future+json".to_string(),
                    r#"{"keep":"me"}"#.to_string()
                ),
            ]
        );
    }

    #[test]
    fn an_import_refuses_a_file_it_cannot_restore() {
        assert!(parse_account_export("}{").is_err());
        assert!(parse_account_export(r#"{"@type":"SomethingElse"}"#).is_err());
        // A version whose major this build does not read.
        assert!(parse_account_export(
            r#"{"@type":"SealbookAccountExport","version":"2.0","objects":[]}"#
        )
        .is_err());
        // An object with no id, and one with no payload of either kind.
        assert!(parse_account_export(
            r#"{"@type":"SealbookAccountExport","version":"1.0","objects":[{"contentType":"a"}]}"#
        )
        .is_err());
        assert!(parse_account_export(
            r#"{"@type":"SealbookAccountExport","version":"1.0","objects":[
                 {"id":"00000000-0000-0000-0000-000000000001","contentType":"a"}]}"#
        )
        .is_err());
        // Two objects at one id: the batch write would refuse it later, and the
        // file is wrong either way.
        assert!(parse_account_export(
            r#"{"@type":"SealbookAccountExport","version":"1.0","objects":[
                 {"id":"00000000-0000-0000-0000-000000000001","contentType":"a","payload":{}},
                 {"id":"00000000-0000-0000-0000-000000000001","contentType":"a","payload":{}}]}"#
        )
        .is_err());
    }

    #[test]
    fn an_import_reads_a_newer_minor_version() {
        let import = parse_account_export(
            r#"{"@type":"SealbookAccountExport","version":"1.7","objects":[
                 {"id":"00000000-0000-0000-0000-000000000001","contentType":"a","payload":{},
                  "writtenByANewerClient":true}]}"#,
        )
        .unwrap();
        assert_eq!(import.objects.len(), 1);
    }

    /// The released v1.0.0 writer's own output, generated by that build and kept
    /// as a fixture, read by this build's parser. A diff saying the writer has
    /// not changed is weaker than this: it would not catch the parser drifting
    /// away from the file the release in the wild actually produces.
    #[test]
    fn an_import_leaves_a_live_object_alone_unless_overwriting() {
        let objects = vec![
            exported(1, "application/jscontact+json", r#"{"@type":"Card"}"#),
            exported(2, "application/jscontact+json", r#"{"@type":"Card"}"#),
        ];
        // Object 1 is live on the instance: signing in before importing creates
        // the default containers, so this is the ordinary case, not a rare one.
        let present = std::collections::HashSet::from([Uuid::from_u128(1)]);

        let (writes, skipped) = split_for_import(objects.clone(), &present, false);
        assert_eq!(
            writes.iter().map(|object| object.id).collect::<Vec<_>>(),
            vec![Uuid::from_u128(2)]
        );
        assert_eq!(
            skipped.iter().map(|object| object.id).collect::<Vec<_>>(),
            vec![Uuid::from_u128(1)]
        );

        let (writes, skipped) = split_for_import(objects, &present, true);
        assert_eq!(writes.len(), 2);
        assert!(skipped.is_empty());
    }

    #[test]
    fn an_import_into_an_empty_vault_writes_everything() {
        let objects = vec![exported(
            1,
            "application/jscontact+json",
            r#"{"@type":"Card"}"#,
        )];
        let (writes, skipped) = split_for_import(objects, &std::collections::HashSet::new(), false);
        assert_eq!(writes.len(), 1);
        assert!(skipped.is_empty());
    }

    #[test]
    fn a_v1_release_export_parses_into_every_object_it_carries() {
        let fixture = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../sealbook-protocol/fixtures/v1.0.0-account-export.json"
        );
        let document = std::fs::read_to_string(fixture).expect("the v1.0.0 fixture");
        let import = parse_account_export(&document).expect("a v1.0.0 export must import");

        assert_eq!(import.source, "alice at https://vault.example");
        let read: Vec<(Uuid, String, String)> = import
            .objects
            .into_iter()
            .map(|object| (object.id, object.content_type, object.payload))
            .collect();
        assert_eq!(read.len(), 6, "an object from the v1.0.0 file was dropped");

        // Every content type the release could write, including one it had no
        // parser for and one whose payload was not JSON.
        let types: Vec<&str> = read.iter().map(|(_, ct, _)| ct.as_str()).collect();
        assert_eq!(
            types,
            vec![
                "application/jscontact+json",
                "application/sealbook.addressbook+json",
                "application/sealbook.note+json",
                "application/sealbook.calendarevent+json",
                "application/sealbook.future+json",
                "application/octet-stream",
            ]
        );
        assert_eq!(read[0].0, Uuid::from_u128(1));

        // Fields the CLI never writes itself are still in what goes back.
        let note = &read[2].2;
        assert!(
            note.contains(r#""pinned":true"#),
            "note payload was rewritten: {note}"
        );
        assert!(note.contains("Weekly plan"));
        // The unparseable type goes back as it was stored.
        assert_eq!(read[4].2, r#"{"keep":"me"}"#);
        // The `text` escape hatch comes back as those bytes, not as JSON.
        assert_eq!(read[5].2, "not json at all");
    }

    #[test]
    fn an_export_file_is_not_readable_by_anyone_else() {
        let dir = std::env::temp_dir().join(format!("sealbook-export-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("account.json");
        std::fs::write(&path, b"stale").unwrap();

        write_private(&path, b"{}").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        std::fs::remove_dir_all(&dir).ok();
    }
}
