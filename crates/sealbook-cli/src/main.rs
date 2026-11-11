mod attach;
mod search;
mod settings;
mod tasks;

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
use jiff::tz::TimeZone;
use keyring::Entry;
use rand::RngCore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use sealbook_client::{
    account_export_parse, account_export_write, alert_label, calendar_parse, contact_parse,
    contact_write, event_parse, ics_parse, ics_write, note_parse, note_write, notes_import,
    notes_write_json, notes_write_markdown, recurrence_days, CoreAddressBookDraft,
    CoreCalendarDraft, CoreCalendarEventDraft, CoreChannelKind, CoreContactAddress,
    CoreContactChannel, CoreContactDate, CoreContactDateKind, CoreContactDraft, CoreContactWork,
    CoreDeviceKind, CoreEventAlert, CoreIcsEvent, CoreIcsExportEvent, CoreNoteDraft,
    CoreNoteFileEntry, CoreOrderItem, ExportedObject, LocalState, SealbookClient,
    DEFAULT_ADDRESS_BOOK_ID, DEFAULT_ADDRESS_BOOK_NAME, DEFAULT_BOOKMARK_COLLECTION_ID,
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
    /// Tasks and subtasks.
    Tasks {
        #[command(subcommand)]
        command: tasks::TasksCommand,
    },
    /// Task lists.
    Tasklist {
        #[command(subcommand)]
        command: tasks::TasklistCommand,
    },
    /// Search notes, tasks, bookmarks, events and contacts at once.
    ///
    /// Finished tasks, archived items, bookmarks kept out of "All" and any
    /// feature switched off are left out, as in the web's search.
    Search {
        query: String,
        /// Only these kinds; repeat for more than one.
        #[arg(long, value_enum)]
        kind: Vec<search::Kind>,
        /// Most hits to show of each kind.
        #[arg(long, default_value_t = 5)]
        limit: u32,
    },
    /// Files attached to notes (photos) and contacts.
    Attach {
        #[command(subcommand)]
        command: attach::AttachCommand,
    },
    /// Which features the account shows.
    Settings {
        #[command(subcommand)]
        command: settings::SettingsCommand,
    },
    Devices {
        #[command(subcommand)]
        command: DevicesCommand,
    },
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
}

#[derive(Subcommand)]
enum AccountCommand {
    /// Change the account password.
    ///
    /// The current password comes from SEALBOOK_PASSWORD or a prompt, and the
    /// new one from SEALBOOK_NEW_PASSWORD or a prompt asked twice. Other devices
    /// are signed out and sign in again with the new password.
    Password {},
    /// Rename the account. The password is asked for, since it is registered
    /// again under the new name.
    Rename {
        #[arg(long)]
        username: String,
    },
    /// Delete the account and everything in it, on every device.
    ///
    /// Asks for the account name typed back and then the password. There is no
    /// flag to skip either: this cannot be undone.
    Delete {},
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
    /// Rename a device. Leave out --device-id to rename this one, and give an
    /// empty name to restore the generated one.
    Rename {
        #[arg(long)]
        device_id: Option<Uuid>,
        #[arg(long)]
        name: String,
    },
    /// Remove the names left behind by revoked devices.
    Prune {},
}

#[derive(Subcommand)]
enum BookCommand {
    List,
    Create {
        #[arg(long)]
        name: String,
    },
    /// Rename an address book or change its colour, keeping the rest of it.
    Rename {
        #[arg(long)]
        id: Uuid,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        color: Option<String>,
    },
    /// Delete an address book. Its contacts are moved to another book or
    /// deleted with it, as web asks. The default book cannot be deleted.
    Delete {
        #[arg(long)]
        id: Uuid,
        /// Move its contacts to this book (a name or an id).
        #[arg(long)]
        move_to: Option<String>,
        /// Delete its contacts along with it.
        #[arg(long, conflicts_with = "move_to")]
        delete_contacts: bool,
    },
}

/// The card fields beyond name, email and addresses. A flag replaces its field
/// when given and leaves it alone when left out; each has a `--clear-` form.
#[derive(clap::Args, Debug, Default)]
struct ContactMore {
    /// A phone number: a bare number, or `value=+44 20 7946 0000;kind=mobile`
    /// (kind: home, work, mobile, or any other word as a label). Repeat for
    /// more than one; given at least once, replaces the card's numbers.
    #[arg(long = "phone", value_parser = parse_phone_spec)]
    phones: Vec<CoreContactChannel>,
    #[arg(long, conflicts_with = "phones")]
    clear_phones: bool,
    /// Organisation: sets the card's first job entry.
    #[arg(long)]
    org: Option<String>,
    /// Job title: sets the title on the card's first job entry.
    #[arg(long)]
    title: Option<String>,
    /// Removes the card's job entries.
    #[arg(long, conflicts_with_all = ["org", "title"])]
    clear_work: bool,
    #[arg(long)]
    nickname: Option<String>,
    #[arg(long, conflicts_with = "nickname")]
    clear_nickname: bool,
    /// Anniversary, as `YYYY`, `YYYY-MM` or `YYYY-MM-DD`.
    #[arg(long, value_parser = parse_partial_date)]
    anniversary: Option<String>,
    #[arg(long, conflicts_with = "anniversary")]
    clear_anniversary: bool,
}

#[derive(Subcommand, Debug)]
enum ProfileCommand {
    /// Print the profile as JSON.
    Show {
        #[arg(long)]
        id: Uuid,
    },
    /// Set one profile field. Fields: `howWeMet` (text), `interests` and
    /// `music` (comma-separated lists). An empty value clears the field.
    Set {
        #[arg(long)]
        id: Uuid,
        /// `name=value`.
        #[arg(long = "field", value_parser = parse_profile_field, required = true)]
        fields: Vec<(String, String)>,
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
        /// A postal address, as `key=value` pairs split by `;`. Keys: kind
        /// (home, work, or any other word as a label), street1, street2, city,
        /// region, postcode, country. Repeat for more than one.
        #[arg(long = "address", value_parser = parse_address_spec)]
        addresses: Vec<CoreContactAddress>,
        #[command(flatten)]
        more: ContactMore,
    },
    /// Find contacts with the search every client uses: names, numbers,
    /// emails and the rest of the card, best match first.
    Search {
        query: String,
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
        /// As for `put`. Given at least once, replaces the card's addresses;
        /// left out, keeps them.
        #[arg(long = "address", value_parser = parse_address_spec)]
        addresses: Vec<CoreContactAddress>,
        /// Removes every address the card has.
        #[arg(long, conflicts_with = "addresses")]
        clear_addresses: bool,
        #[command(flatten)]
        more: ContactMore,
    },
    /// Print one card readably: every field, and the profile if it has one.
    Show {
        #[arg(long)]
        id: Uuid,
    },
    /// Read or set the card's profile (how we met, interests, music).
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
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
    ///
    /// The file is plaintext, so it is written 0600.
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
    /// Rename a notebook or change its colour, keeping the rest of it.
    Rename {
        #[arg(long)]
        id: Uuid,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        color: Option<String>,
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
        /// Put the note under another note.
        #[arg(long)]
        parent: Option<Uuid>,
        /// Pin the note.
        #[arg(long)]
        pin: bool,
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
        /// Move the note under another note.
        #[arg(long)]
        parent: Option<Uuid>,
        /// Move the note to its notebook's top level.
        #[arg(long, conflicts_with = "parent")]
        clear_parent: bool,
        #[arg(long)]
        pin: bool,
        #[arg(long, conflicts_with = "pin")]
        unpin: bool,
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
    /// Add the notes in a markdown or JSON file, read by the same code every client uses.
    Import {
        /// File to read. Omit to read from stdin.
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        notebook: Option<Uuid>,
    },
    /// Write notes as one markdown file, or a JSON backup.
    Export {
        #[arg(long)]
        notebook: Option<Uuid>,
        #[arg(long, value_enum, default_value = "md")]
        format: NotesFormat,
        /// File to write. Omit to print to stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Delete {
        #[arg(long)]
        id: Uuid,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum NotesFormat {
    Md,
    Json,
}

#[derive(Subcommand)]
enum CollectionCommand {
    List,
    Create {
        #[arg(long)]
        name: String,
        /// Nest it under another collection.
        #[arg(long)]
        parent: Option<Uuid>,
        /// Hex colour. Only a top-level collection carries one.
        #[arg(long)]
        color: Option<String>,
    },
    /// Change a collection. A flag left out keeps the stored value.
    Rename {
        #[arg(long)]
        id: Uuid,
        #[arg(long)]
        name: Option<String>,
        /// Move it under another collection.
        #[arg(long)]
        parent: Option<Uuid>,
        /// Move it to the top level.
        #[arg(long, conflicts_with = "parent")]
        clear_parent: bool,
        #[arg(long)]
        color: Option<String>,
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
        /// A note on why it was saved.
        #[arg(long)]
        note: Option<String>,
        /// A tag. Repeat for more than one.
        #[arg(long = "tag")]
        tags: Vec<String>,
    },
    /// Replace a bookmark's URL and title, keeping its original creation time.
    ///
    /// A note or tags left out are kept as they were.
    Update {
        #[arg(long)]
        id: Uuid,
        #[arg(long)]
        url: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        collection: Option<Uuid>,
        #[arg(long)]
        note: Option<String>,
        #[arg(long, conflicts_with = "note")]
        clear_note: bool,
        /// Replaces the bookmark's tags. Repeat for more than one.
        #[arg(long = "tag")]
        tags: Vec<String>,
        #[arg(long, conflicts_with = "tags")]
        clear_tags: bool,
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
        /// A reminder: 15m, 2h, 1d or 1w before the start. For an all-day
        /// event add a time, as in 1d@09:00 or 0d@09:00 for the day itself.
        /// Repeat for more than one.
        #[arg(long = "alert", allow_hyphen_values = true)]
        alerts: Vec<String>,
    },
    /// List events. With `--from` and `--to`, repeating events are expanded
    /// into one line per occurrence inside the window.
    List {
        #[arg(long)]
        calendar: Option<Uuid>,
        /// First day, YYYY-MM-DD.
        #[arg(long)]
        from: Option<String>,
        /// Last day, YYYY-MM-DD, inclusive.
        #[arg(long)]
        to: Option<String>,
    },
    /// Change an event. A flag left out keeps the stored value.
    Update {
        #[arg(long)]
        id: Uuid,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        start: Option<String>,
        #[arg(long)]
        end: Option<String>,
        #[arg(long, conflicts_with = "end")]
        clear_end: bool,
        #[arg(long)]
        notes: Option<String>,
        #[arg(long, conflicts_with = "notes")]
        clear_notes: bool,
        #[arg(long)]
        calendar: Option<Uuid>,
        /// As for `add`. Replaces every reminder the event has.
        #[arg(long = "alert", allow_hyphen_values = true)]
        alerts: Vec<String>,
    },
    /// Delete one event.
    Delete {
        #[arg(long)]
        id: Uuid,
    },
    /// Rename a calendar, or change its colour.
    Rename {
        #[arg(long)]
        id: Uuid,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        color: Option<String>,
    },
    /// Delete a calendar and every event in it, as web does.
    Remove {
        #[arg(long)]
        id: Uuid,
        /// Confirm that the calendar's events go with it.
        #[arg(long)]
        yes: bool,
    },
    /// Write events as an `.ics` file.
    Export {
        /// Only this calendar. Omit for every event.
        #[arg(long)]
        calendar: Option<Uuid>,
        /// File to write. Omit to print to stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Show an event's reminders, or replace them.
    Alerts {
        event: Uuid,
        /// As for `add`. Replaces every reminder the event has.
        #[arg(long = "alert", allow_hyphen_values = true)]
        alerts: Vec<String>,
        /// Remove every reminder.
        #[arg(long, conflicts_with = "alerts")]
        clear: bool,
    },
    /// Add the events in an `.ics` file, read by the same code every client uses.
    Import {
        /// File to read. Omit to read from stdin.
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        calendar: Option<Uuid>,
        /// IANA zone for times the file gives without one. Defaults to this machine's.
        #[arg(long)]
        timezone: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let pinned = load_ca(&cli.tls_ca)?;
    let _ = WARN_IF_OFF.set(feature_of(&cli.command));
    match cli.command {
        Command::Register { username } => {
            let password = read_secret("Password: ", "SEALBOOK_PASSWORD")?;
            let mut client = SealbookClient::https(pinned.clone()).context("tls client")?;
            let phrase = client
                .register(&cli.server, &username, &password)
                .await
                .context("register")?;
            println!("registered {username}");
            label_this_device(&mut client).await;
            println!("Write these recovery words down. They are shown once:\n{phrase}");
            save_state(&cli.state, client.state.as_ref().unwrap())?;
        }
        Command::Login {} => {
            let password = read_secret("Password: ", "SEALBOOK_PASSWORD")?;
            let state = load_state(&cli.state)?;
            let mut client =
                SealbookClient::with_state_and_tls(state, pinned.clone()).context("tls client")?;
            sign_in(&mut client, &password).await?;
            label_this_device(&mut client).await;
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
            let password = read_new_password("SEALBOOK_PASSWORD")?;
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
            ContactsCommand::Put {
                name,
                email,
                book,
                addresses,
                more,
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
                let contact = jscontact(
                    &name,
                    email.as_deref(),
                    Some(addresses),
                    &more,
                    book_id,
                    None,
                )?;
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
                addresses,
                clear_addresses,
                more,
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
                // Merged onto the stored card, so the fields this command does
                // not take are kept. Rebuilding from the three it does took a
                // card with a job, an address and a photo down to a name.
                let existing = find_contact(&mut client, id).await?;
                // Left out, `--book` keeps the card where it is; it used to
                // send the card to the default book.
                let book_id = resolve_book(&books, book.as_deref())?
                    .unwrap_or_else(|| contact_book_id(&existing));
                let addresses = (clear_addresses || !addresses.is_empty()).then_some(addresses);
                let contact = jscontact(
                    &name,
                    email.as_deref(),
                    addresses,
                    &more,
                    book_id,
                    Some(&existing),
                )?;
                let revision = client.put_contact(id, &contact).await.context("update")?;
                println!("updated encrypted contact {id} at revision {revision}");
                save_state(&cli.state, client.state.as_ref().unwrap())?;
            }
            ContactsCommand::Show { id } => {
                let state = load_state(&cli.state)?;
                let password = std::env::var("SEALBOOK_PASSWORD")
                    .context("set SEALBOOK_PASSWORD to unwrap the collection key")?;
                let mut client =
                    SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
                sign_in(&mut client, &password).await?;
                let books = client.list_address_books().await.context("books")?;
                let json = find_contact(&mut client, id).await?;
                print!("{}", contact_card(&id.to_string(), &json, &books));
                save_state(&cli.state, client.state.as_ref().unwrap())?;
            }
            ContactsCommand::Profile { command } => {
                let state = load_state(&cli.state)?;
                let password = std::env::var("SEALBOOK_PASSWORD")
                    .context("set SEALBOOK_PASSWORD to unwrap the collection key")?;
                let mut client =
                    SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
                sign_in(&mut client, &password).await?;
                match command {
                    ProfileCommand::Show { id } => {
                        let json = find_contact(&mut client, id).await?;
                        let profile = contact_parse(&id.to_string(), &json).profile;
                        match profile.as_ref().and_then(sealbook_client::profile_write) {
                            Some(text) => println!("{text}"),
                            None => println!("(no profile)"),
                        }
                    }
                    ProfileCommand::Set { id, fields } => {
                        let json = find_contact(&mut client, id).await?;
                        let card = contact_with_profile(&json, &fields)?;
                        let revision = client.put_contact(id, &card).await.context("update")?;
                        println!("updated encrypted contact {id} at revision {revision}");
                    }
                }
                save_state(&cli.state, client.state.as_ref().unwrap())?;
            }
            ContactsCommand::Search { query, book } => {
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
                let contacts: Vec<(Uuid, String)> = client
                    .list_contacts()
                    .await
                    .context("list")?
                    .into_iter()
                    .filter(|(_, json)| book_id.is_none_or(|id| contact_book_id(json) == id))
                    .collect();
                let hits = contact_search(&contacts, &books, &query);
                if hits.is_empty() {
                    println!("(no matches)");
                }
                for id in hits {
                    if let Some((_, json)) = contacts.iter().find(|(c, _)| c.to_string() == id) {
                        let name = contact_parse(&id, json).name;
                        let book_name = book_name_for(&books, contact_book_id(json));
                        println!("{id} [{book_name}] {name}");
                    }
                }
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
                let contacts = in_core_order(
                    client.list_contacts().await.context("list")?,
                    |id, json| CoreOrderItem {
                        id: id.to_string(),
                        name: contact_parse(&id.to_string(), json).name,
                        ..Default::default()
                    },
                    sealbook_client::order_by_name,
                );
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
                let (name, text) = read_input(file.as_deref())?;
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
                    Some(path) => write_private(&path, data.as_bytes())
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
                                ..Default::default()
                            },
                        )
                        .await
                        .context("create address book")?;
                    println!("created address book {id} {name}");
                }
                BookCommand::Rename { id, name, color } => {
                    let stored = client
                        .list_address_book_payloads()
                        .await?
                        .into_iter()
                        .find(|(candidate, _)| *candidate == id)
                        .map(|(_, json)| json)
                        .with_context(|| format!("no address book {id}: see `book list`"))?;
                    let parsed = sealbook_client::address_book_parse(&id.to_string(), &stored);
                    let revision = client
                        .put_address_book(
                            id,
                            &CoreAddressBookDraft {
                                name: name.unwrap_or(parsed.name),
                                archived: parsed.archived,
                                color: color.or(parsed.color),
                                raw: Some(stored),
                            },
                        )
                        .await
                        .context("rename address book")?;
                    println!("stored encrypted address book {id} at revision {revision}");
                }
                BookCommand::Delete {
                    id,
                    move_to,
                    delete_contacts,
                } => {
                    if id == DEFAULT_ADDRESS_BOOK_ID {
                        anyhow::bail!("the default address book cannot be deleted");
                    }
                    let books = client.list_address_books().await.context("books")?;
                    if !books.iter().any(|(book, _)| *book == id) {
                        anyhow::bail!("no address book {id}: see `book list`");
                    }
                    let destination = resolve_book(&books, move_to.as_deref())?;
                    if destination == Some(id) {
                        anyhow::bail!("cannot move the contacts into the book being deleted");
                    }
                    let contained: Vec<(Uuid, String)> = client
                        .list_contacts()
                        .await?
                        .into_iter()
                        .filter(|(_, json)| contact_book_id(json) == id)
                        .collect();
                    if !contained.is_empty() && destination.is_none() && !delete_contacts {
                        anyhow::bail!(
                            "{} contact(s) are in this book: pass --move-to <book> to keep \
                             them or --delete-contacts to delete them with it",
                            contained.len()
                        );
                    }
                    for (contact, json) in &contained {
                        match destination {
                            Some(destination) => {
                                let moved = contact_moved(json, destination)?;
                                client.put_contact(*contact, &moved).await?;
                            }
                            None => {
                                client.delete_contact(*contact).await?;
                            }
                        }
                    }
                    client.delete_address_book(id).await?;
                    let verb = if destination.is_some() {
                        "moved"
                    } else {
                        "deleted"
                    };
                    println!(
                        "deleted address book {id}, {verb} {} contact(s)",
                        contained.len()
                    );
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
                CollectionCommand::Create {
                    name,
                    parent,
                    color,
                } => {
                    let id = Uuid::new_v4();
                    let draft =
                        collection_change(None, id, Some(name.clone()), parent.map(Some), color)?;
                    check_collection_parent(&mut client, id, &draft).await?;
                    client
                        .put_bookmark_collection_draft(id, &draft)
                        .await
                        .context("create collection")?;
                    println!("created collection {id} {name}");
                }
                CollectionCommand::Rename {
                    id,
                    name,
                    parent,
                    clear_parent,
                    color,
                } => {
                    // Merged onto the stored payload so keys this build does not
                    // know, such as `hideFromAll`, survive.
                    let existing = find_bookmark_collection(&mut client, id).await?;
                    let parent = if clear_parent {
                        Some(None)
                    } else {
                        parent.map(Some)
                    };
                    let draft = collection_change(Some(&existing), id, name, parent, color)?;
                    check_collection_parent(&mut client, id, &draft).await?;
                    client
                        .put_bookmark_collection_draft(id, &draft)
                        .await
                        .context("change collection")?;
                    println!("stored collection {id} {}", draft.name);
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
                    note,
                    tags,
                } => {
                    let id = Uuid::new_v4();
                    let bookmark = bookmark_json(
                        &url,
                        title.as_deref(),
                        collection.unwrap_or(default_collection),
                        None,
                        &BookmarkExtras {
                            notes: note,
                            tags: (!tags.is_empty()).then_some(tags),
                        },
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
                    note,
                    clear_note,
                    tags,
                    clear_tags,
                } => {
                    let existing = find_bookmark(&mut client, id).await?;
                    let bookmark = bookmark_json(
                        &url,
                        title.as_deref(),
                        collection.unwrap_or_else(|| {
                            bookmark_collection_id(&existing, default_collection)
                        }),
                        Some(&existing),
                        &BookmarkExtras {
                            notes: if clear_note {
                                Some(String::new())
                            } else {
                                note
                            },
                            tags: if clear_tags {
                                Some(Vec::new())
                            } else {
                                (!tags.is_empty()).then_some(tags)
                            },
                        },
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
                    let bookmarks = in_core_order(
                        client.list_bookmarks().await.context("bookmarks")?,
                        |id, json| {
                            let bookmark = sealbook_client::bookmark_parse(&id.to_string(), json);
                            CoreOrderItem {
                                id: id.to_string(),
                                name: bookmark.title,
                                pinned: false,
                                stamp: bookmark.updated_at.unwrap_or_default(),
                            }
                        },
                        |items| sealbook_client::order_by_recency(items, false),
                    );
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
        Command::Tasks { command } => {
            let state = load_state(&cli.state)?;
            let password = std::env::var("SEALBOOK_PASSWORD")
                .context("set SEALBOOK_PASSWORD to unwrap the collection key")?;
            let mut client =
                SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
            sign_in(&mut client, &password).await?;
            client
                .ensure_default_task_list()
                .await
                .context("default task list")?;
            tasks::run_tasks(&mut client, command).await?;
            save_state(&cli.state, client.state.as_ref().unwrap())?;
        }
        Command::Tasklist { command } => {
            let state = load_state(&cli.state)?;
            let password = std::env::var("SEALBOOK_PASSWORD")
                .context("set SEALBOOK_PASSWORD to unwrap the collection key")?;
            let mut client =
                SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
            sign_in(&mut client, &password).await?;
            client
                .ensure_default_task_list()
                .await
                .context("default task list")?;
            tasks::run_lists(&mut client, command).await?;
            save_state(&cli.state, client.state.as_ref().unwrap())?;
        }
        Command::Search { query, kind, limit } => {
            let mut client = connect(&cli.state, pinned).await?;
            search::run(&mut client, &query, &kind, limit).await?;
            save_state(&cli.state, client.state.as_ref().unwrap())?;
        }
        Command::Attach { command } => {
            let mut client = connect(&cli.state, pinned).await?;
            attach::run(&mut client, command, &now_rfc3339()).await?;
            save_state(&cli.state, client.state.as_ref().unwrap())?;
        }
        Command::Settings { command } => {
            let mut client = connect(&cli.state, pinned).await?;
            settings::run(&mut client, command).await?;
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
                    let _ = client
                        .ensure_device_label(CoreDeviceKind::Cli, &this_platform())
                        .await;
                    for device in client.device_entries().await? {
                        let marker = if device.is_current {
                            "  (this device)"
                        } else {
                            ""
                        };
                        println!(
                            "{}  {}  {}{marker}",
                            device.name, device.detail, device.device_id
                        );
                    }
                }
                DevicesCommand::Rename { device_id, name } => {
                    let target = device_id.unwrap_or(this_device);
                    client.rename_device(target, &name).await?;
                    let renamed = client
                        .device_entries()
                        .await?
                        .into_iter()
                        .find(|device| device.device_id == target)
                        .map(|device| device.name)
                        .unwrap_or_default();
                    println!("device {target} is now named {renamed}");
                }
                DevicesCommand::Revoke { device_id } => {
                    let name = client
                        .device_entries()
                        .await?
                        .into_iter()
                        .find(|device| device.device_id == device_id)
                        .map(|device| format!("{} ({device_id})", device.name))
                        .unwrap_or_else(|| device_id.to_string());
                    println!(
                        "Revoking {name} rotates the vault key and re-encrypts every \
                         object.\nYour current recovery phrase will stop working and a new \
                         one will be issued."
                    );
                    let phrase = client.revoke_device(device_id, &password).await?;
                    save_state(&cli.state, client.state.as_ref().unwrap())?;
                    println!("\ndevice {name} revoked and the vault key rotated");
                    println!(
                        "\nYour previous recovery phrase no longer works. Write these words \
                         down; they are shown once:"
                    );
                    println!("{phrase}");
                }
                DevicesCommand::Prune {} => {
                    let removed = client.remove_stale_device_labels().await?;
                    println!(
                        "removed {removed} stale device name{}",
                        if removed == 1 { "" } else { "s" }
                    );
                }
            }
            save_state(&cli.state, client.state.as_ref().unwrap())?;
        }
        Command::Account { command } => match command {
            AccountCommand::Password {} => {
                let state = load_state(&cli.state)?;
                let current = read_secret("Current password: ", "SEALBOOK_PASSWORD")?;
                let new = read_new_password("SEALBOOK_NEW_PASSWORD")?;
                let mut client =
                    SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
                // `change_password` signs in with the current password itself,
                // which is what proves it, so signing in here too would spend
                // a third of the server's per-minute login allowance for nothing.
                client
                    .change_password(&current, &new)
                    .await
                    .context("change password")?;
                // The state file's key lives in the keyring, not in the
                // password, so only the new KDF salt needs saving.
                save_state(&cli.state, client.state.as_ref().unwrap())?;
                println!(
                    "password changed. Other devices are signed out and sign in with the new one."
                );
            }
            AccountCommand::Rename { username } => {
                let state = load_state(&cli.state)?;
                let password = read_secret("Password: ", "SEALBOOK_PASSWORD")?;
                let mut client =
                    SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
                // `change_username` signs in itself; see `account password`.
                client
                    .change_username(&username, &password)
                    .await
                    .context("rename account")?;
                save_state(&cli.state, client.state.as_ref().unwrap())?;
                println!(
                    "account renamed to {}",
                    client.state.as_ref().unwrap().username
                );
            }
            AccountCommand::Delete {} => {
                let state = load_state(&cli.state)?;
                let username = state.username.clone();
                eprintln!(
                    "This deletes the account {username} and everything in it, on every \
                     device. It cannot be undone."
                );
                eprint!("Type the account name to confirm: ");
                std::io::stderr().flush()?;
                let mut typed = String::new();
                std::io::stdin().read_line(&mut typed)?;
                if !delete_confirmed(&typed, &username) {
                    anyhow::bail!("the name typed does not match {username}; nothing was deleted");
                }
                let password = read_secret("Password: ", "SEALBOOK_PASSWORD")?;
                let mut client =
                    SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
                // Signing in proves the password, as web and Android do before
                // they send the delete.
                sign_in(&mut client, &password).await?;
                client.delete_account().await.context("delete account")?;
                forget_state(&cli.state);
                println!("account {username} deleted");
            }
        },
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
                    alerts,
                } => {
                    let alerts = parse_alerts(&alerts)?;
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
                                alerts,
                                ..Default::default()
                            },
                        )
                        .await?;
                    println!("stored encrypted calendar event {id} at revision {revision}");
                }
                CalendarCommand::List { calendar, from, to } => {
                    let calendars = client.list_calendars().await?;
                    let window = calendar_window(from.as_deref(), to.as_deref())?;
                    for (id, json) in client.list_calendar_events().await? {
                        let event = event_parse(&id.to_string(), &json);
                        if calendar.is_some_and(|wanted| {
                            event.calendar_id.as_deref() != Some(&wanted.to_string())
                        }) {
                            continue;
                        }
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
                        for start in occurrence_starts(&event, window.as_ref()) {
                            println!("{id} [{name}] {start} {}", event.title);
                            for line in alert_lines(&event) {
                                println!("    {line}");
                            }
                        }
                    }
                }
                CalendarCommand::Update {
                    id,
                    title,
                    start,
                    end,
                    clear_end,
                    notes,
                    clear_notes,
                    calendar,
                    alerts,
                } => {
                    let stored = stored_event(&mut client, id).await?;
                    let alerts = parse_alerts(&alerts)?;
                    let mut draft = event_draft(event_parse(&id.to_string(), &stored));
                    if let Some(title) = title {
                        draft.title = title;
                    }
                    if let Some(start) = start {
                        draft.start = start;
                    }
                    if let Some(end) = end {
                        draft.end = Some(end);
                    }
                    if clear_end {
                        draft.end = None;
                    }
                    if let Some(notes) = notes {
                        draft.notes = Some(notes);
                    }
                    if clear_notes {
                        draft.notes = None;
                    }
                    if let Some(calendar) = calendar {
                        draft.calendar_id = Some(calendar.to_string());
                    }
                    if !alerts.is_empty() {
                        draft.alerts = alerts;
                    }
                    let revision = client.put_calendar_event(id, &draft).await?;
                    println!("stored encrypted calendar event {id} at revision {revision}");
                }
                CalendarCommand::Delete { id } => {
                    stored_event(&mut client, id).await?;
                    let revision = client.delete_calendar_event(id).await?;
                    println!("deleted calendar event {id} at revision {revision}");
                }
                CalendarCommand::Rename { id, name, color } => {
                    let calendar = stored_calendar(&mut client, id).await?;
                    let parsed = calendar_parse(&id.to_string(), &calendar);
                    let revision = client
                        .put_calendar(id, &calendar_rename_draft(parsed, name, color))
                        .await?;
                    println!("stored encrypted calendar {id} at revision {revision}");
                }
                CalendarCommand::Remove { id, yes } => {
                    stored_calendar(&mut client, id).await?;
                    let events: Vec<Uuid> = client
                        .list_calendar_events()
                        .await?
                        .into_iter()
                        .filter(|(_, json)| {
                            event_parse("", json).calendar_id.as_deref() == Some(&id.to_string())
                        })
                        .map(|(event, _)| event)
                        .collect();
                    if !yes {
                        anyhow::bail!(
                            "this deletes the calendar and its {} event(s) from every device; \
                             run again with --yes to confirm",
                            events.len()
                        );
                    }
                    for event in &events {
                        client.delete_calendar_event(*event).await?;
                    }
                    client.delete_calendar(id).await?;
                    println!("deleted calendar {id} and {} event(s)", events.len());
                }
                CalendarCommand::Export { calendar, out } => {
                    let calendars = client.list_calendars().await?;
                    let name = match calendar {
                        Some(wanted) => calendars
                            .iter()
                            .find(|(id, _)| *id == wanted)
                            .map(|(_, name)| name.clone())
                            .with_context(|| format!("no calendar {wanted}"))?,
                        None => "Sealbook".to_string(),
                    };
                    let events: Vec<CoreIcsExportEvent> = client
                        .list_calendar_events()
                        .await?
                        .into_iter()
                        .map(|(id, json)| (id, event_parse(&id.to_string(), &json)))
                        .filter(|(_, event)| {
                            calendar.is_none_or(|wanted| {
                                event.calendar_id.as_deref() == Some(&wanted.to_string())
                            })
                        })
                        .map(|(id, event)| CoreIcsExportEvent {
                            id: id.to_string(),
                            event: event_draft(event),
                        })
                        .collect();
                    let now = OffsetDateTime::now_utc().format(&Rfc3339)?;
                    let text = ics_write(&events, &name, &now);
                    match out {
                        Some(path) => {
                            write_private(&path, text.as_bytes())?;
                            println!("wrote {} event(s) to {}", events.len(), path.display());
                        }
                        None => print!("{text}"),
                    }
                }
                CalendarCommand::Alerts {
                    event,
                    alerts,
                    clear,
                } => {
                    let alerts = parse_alerts(&alerts)?;
                    let stored = client
                        .list_calendar_events()
                        .await?
                        .into_iter()
                        .find(|(id, _)| *id == event)
                        .map(|(_, json)| json)
                        .with_context(|| format!("no event {event}"))?;
                    let parsed = event_parse(&event.to_string(), &stored);
                    if alerts.is_empty() && !clear {
                        let lines = alert_lines(&parsed);
                        if lines.is_empty() {
                            println!("no reminders");
                        }
                        for line in lines {
                            println!("{line}");
                        }
                    } else {
                        let revision = client
                            .put_calendar_event(event, &event_alerts_draft(parsed, alerts))
                            .await?;
                        println!("stored encrypted calendar event {event} at revision {revision}");
                    }
                }
                CalendarCommand::Import {
                    file,
                    calendar,
                    timezone,
                } => {
                    let (_, text) = read_input(file.as_deref())?;
                    let (zone_name, zone) = import_zone(timezone.as_deref())?;
                    let calendar = calendar.unwrap_or(DEFAULT_CALENDAR_ID);
                    if !client
                        .list_calendars()
                        .await?
                        .iter()
                        .any(|(id, _)| *id == calendar)
                    {
                        anyhow::bail!("no calendar {calendar}: see `calendar list-calendars`");
                    }
                    let read = ics_parse(&text);
                    for event in &read.events {
                        let draft = imported_event(event, &zone_name, &zone, calendar)?;
                        client
                            .put_calendar_event(Uuid::new_v4(), &draft)
                            .await
                            .context("put event")?;
                    }
                    println!(
                        "imported {} event(s), skipped {}",
                        read.events.len(),
                        read.skipped.len()
                    );
                    for skipped in &read.skipped {
                        println!("skipped {}: {}", skipped.title, skipped.reason);
                    }
                    if read.dropped_rules > 0 {
                        println!(
                            "{} repeating event(s) imported once: their repeat rule cannot be stored",
                            read.dropped_rules
                        );
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
                NotebookCommand::Rename { id, name, color } => {
                    let stored = client
                        .list_notebook_payloads()
                        .await?
                        .into_iter()
                        .find(|(candidate, _)| *candidate == id)
                        .map(|(_, json)| json)
                        .with_context(|| format!("no notebook {id}: see `notebook list`"))?;
                    let parsed = sealbook_client::notebook_parse(&id.to_string(), &stored);
                    let revision = client
                        .put_notebook_colored(
                            id,
                            &name.unwrap_or(parsed.name),
                            color.as_deref().or(parsed.color.as_deref()),
                            Some(&stored),
                        )
                        .await
                        .context("rename notebook")?;
                    println!("stored encrypted notebook {id} at revision {revision}");
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
                    parent,
                    pin,
                } => {
                    let body = read_note_body(body, file)?;
                    let id = Uuid::new_v4();
                    if let Some(parent) = parent {
                        check_note_parent(&mut client, id, parent).await?;
                    }
                    let note = note_write(
                        &CoreNoteDraft {
                            title,
                            body,
                            notebook_id: notebook.unwrap_or(default_notebook).to_string(),
                            parent_id: parent.map(|parent| parent.to_string()),
                            pinned: pin.then_some(true),
                            ..Default::default()
                        },
                        &now_rfc3339(),
                    )?;
                    let revision = client.put_note(id, &note).await.context("add note")?;
                    println!("stored encrypted note {id} at revision {revision}");
                }
                NotesCommand::Import { file, notebook } => {
                    let (name, text) = read_input(file.as_deref())?;
                    let notebook = notebook.unwrap_or(default_notebook);
                    if !client
                        .list_notebooks()
                        .await
                        .context("notebooks")?
                        .iter()
                        .any(|(id, _)| *id == notebook)
                    {
                        anyhow::bail!("no notebook {notebook}: see `notebook list`");
                    }
                    let read = notes_import(&name, &text, &notebook.to_string())
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    let now = now_rfc3339();
                    for entry in read.notes.iter().cloned() {
                        let note = note_write(
                            &CoreNoteDraft {
                                title: entry.title,
                                body: entry.body,
                                notebook_id: entry.notebook_id,
                                created_at: entry.created_at,
                                pinned: entry.pinned,
                                ..Default::default()
                            },
                            &now,
                        )?;
                        client
                            .put_note(Uuid::new_v4(), &note)
                            .await
                            .context("put note")?;
                    }
                    println!(
                        "imported {} note(s) from {}, skipped {}",
                        read.notes.len(),
                        read.format,
                        read.skipped.len()
                    );
                    for skipped in &read.skipped {
                        println!("skipped {}: {}", skipped.title, skipped.reason);
                    }
                }
                NotesCommand::Update {
                    id,
                    title,
                    body,
                    file,
                    notebook,
                    parent,
                    clear_parent,
                    pin,
                    unpin,
                } => {
                    let body = read_note_body(body, file)?;
                    let existing = find_note(&mut client, id).await?;
                    if let Some(parent) = parent {
                        check_note_parent(&mut client, id, parent).await?;
                    }
                    let parent = if clear_parent {
                        Some(None)
                    } else {
                        parent.map(Some)
                    };
                    let pinned = if pin {
                        Some(true)
                    } else if unpin {
                        Some(false)
                    } else {
                        None
                    };
                    let note = note_write(
                        &note_update_draft(&existing, id, title, body, notebook, parent, pinned),
                        &now_rfc3339(),
                    )?;
                    let revision = client.put_note(id, &note).await.context("update note")?;
                    println!("updated encrypted note {id} at revision {revision}");
                }
                NotesCommand::List { notebook } => {
                    let notebooks = client.list_notebooks().await.context("notebooks")?;
                    let notes = in_core_order(
                        client.list_notes().await.context("notes")?,
                        |id, json| {
                            let note = note_parse(&id.to_string(), json);
                            CoreOrderItem {
                                id: id.to_string(),
                                name: note.title,
                                pinned: note.pinned.unwrap_or(false),
                                stamp: note.updated_at.unwrap_or_default(),
                            }
                        },
                        |items| sealbook_client::order_by_recency(items, true),
                    );
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
                NotesCommand::Export {
                    notebook,
                    format,
                    out,
                } => {
                    let notebooks: Vec<sealbook_client::CoreNotebook> = client
                        .list_notebook_payloads()
                        .await?
                        .into_iter()
                        .map(|(id, json)| sealbook_client::notebook_parse(&id.to_string(), &json))
                        .collect();
                    let entries: Vec<CoreNoteFileEntry> = client
                        .list_notes()
                        .await
                        .context("notes")?
                        .into_iter()
                        .map(|(id, json)| note_parse(&id.to_string(), &json))
                        .filter(|note| {
                            notebook.is_none_or(|want| want.to_string() == note.notebook_id)
                        })
                        .map(|note| CoreNoteFileEntry {
                            title: note.title,
                            body: note.body,
                            notebook_id: note.notebook_id,
                            created_at: note.created_at,
                            updated_at: note.updated_at,
                            pinned: note.pinned,
                        })
                        .collect();
                    let text = match format {
                        NotesFormat::Md => notes_write_markdown(&entries, &notebooks),
                        NotesFormat::Json => notes_write_json(&entries, &notebooks, &now_rfc3339()),
                    };
                    match out {
                        Some(path) => {
                            write_private(&path, text.as_bytes())?;
                            println!("wrote {} note(s) to {}", entries.len(), path.display());
                        }
                        None => print!("{text}"),
                    }
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
fn this_platform() -> String {
    sealbook_client::os_display_name(std::env::consts::OS)
}

/// Best effort: a device that cannot write its label still works, and shows
/// under its generated name until it can.
async fn label_this_device(client: &mut SealbookClient) {
    match client
        .ensure_device_label(CoreDeviceKind::Cli, &this_platform())
        .await
    {
        Ok(name) => println!("this device is named {name}"),
        Err(err) => eprintln!("warning: could not record this device's name: {err}"),
    }
}

/// The feature the running command belongs to, which `sign_in` checks is still
/// switched on. Set once, before any command runs.
static WARN_IF_OFF: std::sync::OnceLock<Option<&'static str>> = std::sync::OnceLock::new();

fn feature_of(command: &Command) -> Option<&'static str> {
    match command {
        Command::Contacts { .. } | Command::Book { .. } => Some("contacts"),
        Command::Calendar { .. } => Some("calendar"),
        Command::Notes { .. } | Command::Notebook { .. } => Some("notes"),
        Command::Bookmarks { .. } | Command::Collection { .. } => Some("bookmarks"),
        Command::Tasks { .. } | Command::Tasklist { .. } => Some("tasks"),
        _ => None,
    }
}

/// Reads the settings and says so when the command's feature is off. The
/// command still runs: the data is the user's, and only the apps hide it.
async fn warn_if_feature_off(client: &mut SealbookClient) {
    let Some(Some(feature)) = WARN_IF_OFF.get() else {
        return;
    };
    if let Ok(settings) = client.account_settings().await {
        if let Some(note) = settings::disabled_note(&settings, feature) {
            eprintln!("{note}");
        }
    }
}

/// Opens the saved state and signs in with `SEALBOOK_PASSWORD`.
async fn connect(
    state_path: &Path,
    pinned: Option<CertificateDer<'static>>,
) -> Result<SealbookClient> {
    let state = load_state(state_path)?;
    let password = std::env::var("SEALBOOK_PASSWORD")
        .context("set SEALBOOK_PASSWORD to unwrap the collection key")?;
    let mut client = SealbookClient::with_state_and_tls(state, pinned).context("tls client")?;
    sign_in(&mut client, &password).await?;
    Ok(client)
}

async fn sign_in(client: &mut SealbookClient, password: &str) -> Result<()> {
    sign_in_quietly(client, password).await?;
    warn_if_feature_off(client).await;
    Ok(())
}

async fn sign_in_quietly(client: &mut SealbookClient, password: &str) -> Result<()> {
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

/// Refuses a parent that would put a note under itself or one of its own
/// descendants, or that does not exist, by the rule tasks already use.
async fn check_note_parent(client: &mut SealbookClient, id: Uuid, parent: Uuid) -> Result<()> {
    let items: Vec<(String, Option<String>)> = client
        .list_notes()
        .await
        .context("notes")?
        .into_iter()
        .map(|(note, json)| {
            let note = note_parse(&note.to_string(), &json);
            (note.id, note.parent_id)
        })
        .collect();
    if !sealbook_client::may_reparent(&items, &id.to_string(), Some(&parent.to_string())) {
        anyhow::bail!(
            "note {parent} cannot be the parent of {id}: it does not exist, or sits under it"
        );
    }
    Ok(())
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

/// A collection as it will be written: the stored one with only the flags
/// given changed. `parent` is `Some(None)` to move to the top level.
fn collection_change(
    stored: Option<&str>,
    id: Uuid,
    name: Option<String>,
    parent: Option<Option<Uuid>>,
    color: Option<String>,
) -> Result<sealbook_client::CoreBookmarkCollectionDraft> {
    let mut draft = stored
        .map(|raw| sealbook_client::bookmark_collection_parse(&id.to_string(), raw).draft())
        .unwrap_or_default();
    if let Some(name) = name {
        draft.name = name;
    }
    if let Some(parent) = parent {
        draft.parent_id = parent.map(|parent| parent.to_string());
    }
    if let Some(color) = color {
        draft.color = Some(color);
    }
    if id == DEFAULT_BOOKMARK_COLLECTION_ID && draft.parent_id.is_some() {
        // The fallback every bookmark without a collection resolves to; web
        // keeps it at the top so it cannot be buried.
        anyhow::bail!("the default collection stays at the top level");
    }
    if draft.parent_id.is_some() && draft.color.is_some() {
        anyhow::bail!("only a top-level collection carries a colour: drop --color or --parent");
    }
    Ok(draft)
}

/// Refuses a parent that does not exist or would put a collection under itself
/// or one of its own descendants.
async fn check_collection_parent(
    client: &mut SealbookClient,
    id: Uuid,
    draft: &sealbook_client::CoreBookmarkCollectionDraft,
) -> Result<()> {
    let Some(parent) = &draft.parent_id else {
        return Ok(());
    };
    let items: Vec<(String, Option<String>)> = client
        .list_bookmark_collection_payloads()
        .await
        .context("collections")?
        .into_iter()
        .map(|(collection, json)| {
            let collection =
                sealbook_client::bookmark_collection_parse(&collection.to_string(), &json);
            (collection.id, collection.parent_id)
        })
        .collect();
    if !sealbook_client::may_reparent(&items, &id.to_string(), Some(parent)) {
        anyhow::bail!(
            "collection {parent} cannot be the parent of {id}: it does not exist, or sits under it"
        );
    }
    Ok(())
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
/// What a bookmark write may change beyond its address and place. `None` keeps
/// the stored value; an empty note or tag list clears it.
#[derive(Default)]
struct BookmarkExtras {
    notes: Option<String>,
    tags: Option<Vec<String>>,
}

fn bookmark_json(
    url: &str,
    title: Option<&str>,
    collection_id: Uuid,
    previous: Option<&str>,
    extras: &BookmarkExtras,
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
    if let Some(notes) = &extras.notes {
        draft.notes = notes.clone();
    }
    if let Some(tags) = &extras.tags {
        draft.tags = sealbook_client::normalize_tags(tags);
    }
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
    parent: Option<Option<Uuid>>,
    pinned: Option<bool>,
) -> CoreNoteDraft {
    let note = note_parse(&id.to_string(), stored);
    CoreNoteDraft {
        title,
        body,
        notebook_id: notebook
            .map(|notebook| notebook.to_string())
            .unwrap_or(note.notebook_id),
        // `Some(None)` is "move to the top level"; `None` keeps the stored parent.
        parent_id: match parent {
            Some(parent) => parent.map(|parent| parent.to_string()),
            None => note.parent_id,
        },
        attachments: note.attachments,
        created_at: note.created_at,
        pinned,
        raw: Some(stored.to_string()),
    }
}

/// Every field the event was read with, so a change to one keeps the rest, and
/// the stored payload rides along in `raw` so keys this build does not know
/// survive the write.
fn event_draft(event: sealbook_client::CoreCalendarEvent) -> CoreCalendarEventDraft {
    CoreCalendarEventDraft {
        title: event.title,
        start: event.start,
        end: event.end,
        notes: event.notes,
        location: event.location,
        participants: event.participants,
        timezone: event.timezone,
        calendar_id: event.calendar_id,
        recurrence: event.recurrence,
        unreadable_recurrence: event.unreadable_recurrence,
        alerts: event.alerts,
        unreadable_alerts: event.unreadable_alerts,
        raw: Some(event.raw),
    }
}

/// Replaces an event's reminders and nothing else.
fn event_alerts_draft(
    event: sealbook_client::CoreCalendarEvent,
    alerts: Vec<CoreEventAlert>,
) -> CoreCalendarEventDraft {
    CoreCalendarEventDraft {
        alerts,
        ..event_draft(event)
    }
}

/// A calendar with a new name and/or colour, favourite and archived flags and
/// unknown keys kept.
fn calendar_rename_draft(
    calendar: sealbook_client::CoreCalendar,
    name: Option<String>,
    color: Option<String>,
) -> CoreCalendarDraft {
    CoreCalendarDraft {
        name: name.unwrap_or(calendar.name),
        color: color.unwrap_or(calendar.color),
        favorite: calendar.favorite,
        archived: calendar.archived,
        raw: Some(calendar.raw),
    }
}

async fn stored_event(client: &mut SealbookClient, id: Uuid) -> Result<String> {
    client
        .list_calendar_events()
        .await?
        .into_iter()
        .find(|(candidate, _)| *candidate == id)
        .map(|(_, json)| json)
        .with_context(|| format!("no event {id}"))
}

async fn stored_calendar(client: &mut SealbookClient, id: Uuid) -> Result<String> {
    // list_calendars returns names only; the draft needs the stored payload.
    client
        .list_calendar_payloads()
        .await?
        .into_iter()
        .find(|(candidate, _)| *candidate == id)
        .map(|(_, json)| json)
        .with_context(|| format!("no calendar {id}: see `calendar list-calendars`"))
}

fn calendar_window(from: Option<&str>, to: Option<&str>) -> Result<Option<(String, String)>> {
    match (from, to) {
        (None, None) => Ok(None),
        (Some(from), Some(to)) => {
            for day in [from, to] {
                if !sealbook_client::is_calendar_day(day) {
                    anyhow::bail!("{day} is not a date: use YYYY-MM-DD");
                }
            }
            if from > to {
                anyhow::bail!("--from is after --to");
            }
            Ok(Some((from.to_string(), to.to_string())))
        }
        _ => anyhow::bail!("give both --from and --to, or neither"),
    }
}

/// The start of each occurrence to list. Without a window an event is its one
/// stored start. With one, a repeating event contributes each day of its series
/// inside it, keeping the stored time of day, and a single event only if it
/// starts inside.
fn occurrence_starts(
    event: &sealbook_client::CoreCalendarEvent,
    window: Option<&(String, String)>,
) -> Vec<String> {
    let Some((from, to)) = window else {
        return vec![event.start.clone()];
    };
    let time = event.start.get(10..).unwrap_or("");
    match &event.recurrence {
        Some(rule) => recurrence_days(&event.start, rule, from, to)
            .into_iter()
            .map(|day| format!("{day}{time}"))
            .collect(),
        None => {
            let day = event.start.get(..10).unwrap_or("");
            if day >= from.as_str() && day <= to.as_str() {
                vec![event.start.clone()]
            } else {
                Vec::new()
            }
        }
    }
}

fn alert_lines(event: &sealbook_client::CoreCalendarEvent) -> Vec<String> {
    let all_day = !event.start.contains('T');
    event
        .alerts
        .iter()
        .map(|alert| format!("reminder: {}", alert_label(alert.minutes_before, all_day)))
        .collect()
}

fn parse_alerts(values: &[String]) -> Result<Vec<CoreEventAlert>> {
    values
        .iter()
        .map(|value| {
            parse_alert(value)
                .map(|minutes_before| CoreEventAlert {
                    minutes_before,
                    extra: None,
                })
                .with_context(|| {
                    format!("read the reminder {value:?}: try 15m, 2h, 1d or 1d@09:00")
                })
        })
        .collect()
}

/// `15m`, `2h`, `1d`, `1w` or bare minutes before the start, and for an
/// all-day event a whole number of days with a time: `1d@09:00`.
fn parse_alert(value: &str) -> Option<i32> {
    let (span, time) = match value.trim().split_once('@') {
        Some((span, time)) => (span.trim(), Some(time.trim())),
        None => (value.trim(), None),
    };
    let (number, unit) = match span.char_indices().last()? {
        (index, unit) if unit.is_ascii_alphabetic() => (&span[..index], unit),
        _ => (span, 'm'),
    };
    let count: i32 = number.parse().ok()?;
    let minutes = count.checked_mul(match unit.to_ascii_lowercase() {
        'm' => 1,
        'h' => 60,
        'd' => 1_440,
        'w' => 10_080,
        _ => return None,
    })?;
    let minutes = match time {
        None => minutes,
        Some(time) => {
            let (hours, mins) = time.split_once(':')?;
            let (hours, mins): (i32, i32) = (hours.parse().ok()?, mins.parse().ok()?);
            if minutes % 1_440 != 0 || !(0..24).contains(&hours) || !(0..60).contains(&mins) {
                return None;
            }
            minutes - hours * 60 - mins
        }
    };
    (sealbook_client::MIN_ALERT_MINUTES_BEFORE..=sealbook_client::MAX_ALERT_MINUTES_BEFORE)
        .contains(&minutes)
        .then_some(minutes)
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// The file's name, for the format sniffing core does on it, and its text.
fn read_input(file: Option<&Path>) -> Result<(String, String)> {
    match file {
        Some(path) => Ok((
            path.to_string_lossy().to_string(),
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?,
        )),
        None => {
            let mut text = String::new();
            std::io::stdin()
                .read_to_string(&mut text)
                .context("read stdin")?;
            Ok((String::new(), text))
        }
    }
}

/// The zone an imported event without its own is placed in, and its name.
fn import_zone(name: Option<&str>) -> Result<(String, TimeZone)> {
    match name {
        Some(name) => {
            let zone = TimeZone::get(name).with_context(|| format!("unknown time zone {name}"))?;
            Ok((name.to_string(), zone))
        }
        None => {
            let zone = TimeZone::try_system().context("read this machine's time zone")?;
            let name = zone
                .iana_name()
                .context("this machine's time zone has no IANA name: pass --timezone")?
                .to_string();
            Ok((name, zone))
        }
    }
}

/// A time core left as local wall-clock text, as the UTC instant it names in
/// `zone`. A date or an instant is already final.
fn resolved(value: &str, zone: &TimeZone) -> Result<String> {
    if !value.contains('T') || value.ends_with('Z') {
        return Ok(value.to_string());
    }
    let local: jiff::civil::DateTime = value
        .parse()
        .with_context(|| format!("read the time {value}"))?;
    let instant = local.to_zoned(zone.clone())?.timestamp();
    Ok(instant.strftime("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// An event from an `.ics` file as the draft every client writes for it. A
/// `TZID` this machine's zone database does not know falls back to `zone`.
fn imported_event(
    event: &CoreIcsEvent,
    zone_name: &str,
    zone: &TimeZone,
    calendar: Uuid,
) -> Result<CoreCalendarEventDraft> {
    let zone_of = |name: Option<&str>| {
        name.and_then(|name| TimeZone::get(name).ok())
            .unwrap_or_else(|| zone.clone())
    };
    Ok(CoreCalendarEventDraft {
        title: event.title.clone(),
        start: resolved(&event.start, &zone_of(event.start_zone.as_deref()))?,
        end: event
            .end
            .as_deref()
            .map(|end| resolved(end, &zone_of(event.end_zone.as_deref())))
            .transpose()?,
        notes: event.notes.clone(),
        location: event.location.clone(),
        participants: event.participants.clone(),
        timezone: Some(event.start_zone.as_deref().unwrap_or(zone_name).to_string()),
        calendar_id: Some(calendar.to_string()),
        recurrence: event.recurrence.clone(),
        ..Default::default()
    })
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
                    archived: false,
                    color: None,
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
/// one carried. `addresses`, when given, replaces the card's list.
fn jscontact(
    name: &str,
    email: Option<&str>,
    addresses: Option<Vec<CoreContactAddress>>,
    more: &ContactMore,
    book_id: Uuid,
    previous: Option<&str>,
) -> Result<String> {
    let mut draft = match previous {
        Some(raw) => contact_parse(&Uuid::nil().to_string(), raw).draft(),
        None => CoreContactDraft::default(),
    };
    draft.name = name.to_string();
    draft.address_book_id = book_id.to_string();
    if let Some(addresses) = addresses {
        draft.addresses = addresses;
    }
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
    apply_more(&mut draft, more);
    Ok(contact_write(&draft, &now_rfc3339())?)
}

/// Applies the optional card fields: a field not given is left as stored.
fn apply_more(draft: &mut CoreContactDraft, more: &ContactMore) {
    if more.clear_phones {
        draft.phones.clear();
    } else if !more.phones.is_empty() {
        draft.phones = more.phones.clone();
    }
    if more.clear_work {
        draft.work.clear();
    }
    if more.org.is_some() || more.title.is_some() {
        if draft.work.is_empty() {
            draft.work.push(CoreContactWork {
                organization: String::new(),
                title: None,
                start: None,
                end: None,
                current: true,
                note: None,
                extra: None,
            });
        }
        let job = &mut draft.work[0];
        if let Some(org) = &more.org {
            job.organization = org.clone();
        }
        if let Some(title) = &more.title {
            job.title = Some(title.clone()).filter(|title| !title.trim().is_empty());
        }
    }
    if more.clear_nickname {
        draft.nickname = None;
    } else if let Some(nickname) = &more.nickname {
        draft.nickname = Some(nickname.clone()).filter(|nick| !nick.trim().is_empty());
    }
    if more.clear_anniversary {
        draft
            .dates
            .retain(|date| date.kind != CoreContactDateKind::Anniversary);
    } else if let Some(day) = &more.anniversary {
        match draft
            .dates
            .iter_mut()
            .find(|date| date.kind == CoreContactDateKind::Anniversary)
        {
            Some(date) => date.date = day.clone(),
            None => draft.dates.push(CoreContactDate {
                kind: CoreContactDateKind::Anniversary,
                label: None,
                date: day.clone(),
                extra: None,
            }),
        }
    }
}

/// One `--phone` value: a bare number, or `value=…;kind=mobile`.
fn parse_phone_spec(spec: &str) -> Result<CoreContactChannel, String> {
    let mut phone = CoreContactChannel {
        kind: CoreChannelKind::Mobile,
        label: None,
        value: String::new(),
        extra: None,
    };
    if !spec.contains('=') {
        phone.value = spec.trim().to_string();
    } else {
        for pair in spec.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            let (key, value) = pair
                .split_once('=')
                .ok_or_else(|| format!("expected key=value, found {pair:?}"))?;
            let value = value.trim();
            match key.trim().to_ascii_lowercase().as_str() {
                "value" | "number" => phone.value = value.to_string(),
                "kind" | "type" => match value.to_ascii_lowercase().as_str() {
                    "home" => phone.kind = CoreChannelKind::Home,
                    "work" => phone.kind = CoreChannelKind::Work,
                    "mobile" | "cell" => phone.kind = CoreChannelKind::Mobile,
                    _ => {
                        phone.kind = CoreChannelKind::Custom;
                        phone.label = Some(value.to_string());
                    }
                },
                other => return Err(format!("unknown phone key {other:?}")),
            }
        }
    }
    if phone.value.is_empty() {
        return Err("a phone needs a number".into());
    }
    Ok(phone)
}

/// `YYYY`, `YYYY-MM` or `YYYY-MM-DD`.
fn parse_partial_date(text: &str) -> Result<String, String> {
    let parts: Vec<&str> = text.trim().split('-').collect();
    let numeric =
        |part: &str, len: usize| part.len() == len && part.bytes().all(|b| b.is_ascii_digit());
    let ok = match parts.as_slice() {
        [y] => numeric(y, 4),
        [y, m] => numeric(y, 4) && numeric(m, 2),
        [y, m, d] => numeric(y, 4) && numeric(m, 2) && numeric(d, 2),
        _ => false,
    };
    if ok {
        Ok(text.trim().to_string())
    } else {
        Err(format!("{text:?} is not YYYY, YYYY-MM or YYYY-MM-DD"))
    }
}

/// One `--field name=value` for the profile.
fn parse_profile_field(spec: &str) -> Result<(String, String), String> {
    let (name, value) = spec
        .split_once('=')
        .ok_or_else(|| format!("expected name=value, found {spec:?}"))?;
    let name = name.trim();
    match name {
        "howWeMet" | "interests" | "music" => Ok((name.to_string(), value.to_string())),
        other => Err(format!(
            "unknown profile field {other:?}: use howWeMet, interests or music"
        )),
    }
}

/// The stored card with profile fields set, everything else kept. Text is
/// stored whole, never cut at the editor limit.
fn contact_with_profile(raw: &str, fields: &[(String, String)]) -> Result<String> {
    let mut draft = contact_parse(&Uuid::nil().to_string(), raw).draft();
    let mut profile = draft.profile.take().unwrap_or_default();
    for (name, value) in fields {
        let list = || {
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        match name.as_str() {
            "howWeMet" => profile.how_we_met = Some(value.clone()).filter(|v| !v.trim().is_empty()),
            "interests" => profile.interests = list(),
            "music" => profile.music = list(),
            _ => unreachable!("checked by parse_profile_field"),
        }
    }
    draft.profile = Some(profile);
    Ok(contact_write(&draft, &now_rfc3339())?)
}

/// A card as readable text.
fn contact_card(id: &str, raw: &str, books: &[(Uuid, String)]) -> String {
    use std::fmt::Write as _;
    let contact = contact_parse(id, raw);
    let mut out = String::new();
    let _ = writeln!(out, "{}", contact.display_name);
    let _ = writeln!(out, "id: {id}");
    let book = Uuid::parse_str(&contact.address_book_id).unwrap_or(DEFAULT_ADDRESS_BOOK_ID);
    let _ = writeln!(out, "book: {}", book_name_for(books, book));
    let label = |kind: CoreChannelKind, label: &Option<String>| match kind {
        CoreChannelKind::Work => "work".to_string(),
        CoreChannelKind::Home => "home".to_string(),
        CoreChannelKind::Mobile => "mobile".to_string(),
        CoreChannelKind::Custom => label.clone().unwrap_or_else(|| "other".into()),
    };
    if let Some(nick) = &contact.nickname {
        let _ = writeln!(out, "nickname: {nick}");
    }
    if let Some(pronouns) = &contact.pronouns {
        let _ = writeln!(out, "pronouns: {pronouns}");
    }
    for job in &contact.work {
        let title = job
            .title
            .as_deref()
            .map(|t| format!(", {t}"))
            .unwrap_or_default();
        let _ = writeln!(out, "work: {}{title}", job.organization);
    }
    for email in &contact.emails {
        let _ = writeln!(
            out,
            "email ({}): {}",
            label(email.kind, &email.label),
            email.value
        );
    }
    for phone in &contact.phones {
        let _ = writeln!(
            out,
            "phone ({}): {}",
            label(phone.kind, &phone.label),
            phone.value
        );
    }
    for address in &contact.addresses {
        let lines: Vec<&str> = [
            &address.street1,
            &address.street2,
            &address.locality,
            &address.region,
            &address.postcode,
            &address.country,
        ]
        .into_iter()
        .filter_map(|line| line.as_deref())
        .collect();
        let _ = writeln!(
            out,
            "address ({}): {}",
            label(address.kind, &address.label),
            lines.join(", ")
        );
    }
    for date in &contact.dates {
        let kind = match date.kind {
            CoreContactDateKind::Birthday => "birthday".to_string(),
            CoreContactDateKind::Anniversary => "anniversary".to_string(),
            CoreContactDateKind::Custom => date.label.clone().unwrap_or_else(|| "date".into()),
        };
        let _ = writeln!(out, "{kind}: {}", date.date);
    }
    for social in &contact.socials {
        let _ = writeln!(out, "{}: {}", social.platform, social.handle);
    }
    if let Some(notes) = &contact.notes {
        let _ = writeln!(out, "notes: {notes}");
    }
    if let Some(profile) = &contact.profile {
        if let Some(met) = &profile.how_we_met {
            let _ = writeln!(out, "how we met: {met}");
        }
        if !profile.interests.is_empty() {
            let _ = writeln!(out, "interests: {}", profile.interests.join(", "));
        }
        if !profile.music.is_empty() {
            let _ = writeln!(out, "music: {}", profile.music.join(", "));
        }
    }
    out
}

/// One `--address` value: `kind=work;street1=1 Main St;city=Leeds`.
fn parse_address_spec(spec: &str) -> Result<CoreContactAddress, String> {
    let mut address = CoreContactAddress::default();
    for pair in spec
        .split(';')
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
    {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| format!("expected key=value, found {pair:?}"))?;
        let value = Some(value.trim().to_string()).filter(|value| !value.is_empty());
        match key.trim().to_ascii_lowercase().as_str() {
            "kind" | "type" => match value.as_deref().map(str::to_ascii_lowercase).as_deref() {
                None | Some("home") => address.kind = CoreChannelKind::Home,
                Some("work") => address.kind = CoreChannelKind::Work,
                Some(_) => {
                    address.kind = CoreChannelKind::Custom;
                    address.label = value;
                }
            },
            "street1" | "street" => address.street1 = value,
            "street2" => address.street2 = value,
            "city" | "locality" | "town" => address.locality = value,
            "region" | "state" | "province" => address.region = value,
            "postcode" | "zip" | "postal" => address.postcode = value,
            "country" => address.country = value,
            other => return Err(format!("unknown address key {other:?}")),
        }
    }
    if address.is_blank() {
        return Err("an address needs at least one line".into());
    }
    Ok(address)
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

/// The same card in another address book, every other field kept.
/// Rows in the order core gives every client: the same vault lists the same way
/// everywhere. `describe` says what core needs to place a row.
fn in_core_order(
    rows: Vec<(Uuid, String)>,
    describe: impl Fn(&Uuid, &str) -> CoreOrderItem,
    order: impl Fn(&[CoreOrderItem]) -> Vec<String>,
) -> Vec<(Uuid, String)> {
    let items: Vec<CoreOrderItem> = rows.iter().map(|(id, json)| describe(id, json)).collect();
    let mut rows = rows;
    let ranked = order(&items);
    rows.sort_by_key(|(id, _)| {
        ranked
            .iter()
            .position(|ranked| *ranked == id.to_string())
            .unwrap_or(usize::MAX)
    });
    rows
}

fn contact_moved(raw: &str, book_id: Uuid) -> Result<String> {
    let mut draft = contact_parse(&Uuid::nil().to_string(), raw).draft();
    draft.address_book_id = book_id.to_string();
    Ok(contact_write(&draft, &now_rfc3339())?)
}

/// Contact ids matching `query`, in the order the shared search ranks them.
fn contact_search(
    contacts: &[(Uuid, String)],
    books: &[(Uuid, String)],
    query: &str,
) -> Vec<String> {
    let sources: Vec<sealbook_client::CoreContactSource> = contacts
        .iter()
        .map(|(id, raw)| sealbook_client::CoreContactSource {
            id: id.to_string(),
            raw: raw.clone(),
        })
        .collect();
    let names: Vec<sealbook_client::CoreBookName> = books
        .iter()
        .map(|(id, name)| sealbook_client::CoreBookName {
            id: id.to_string(),
            name: name.clone(),
        })
        .collect();
    sealbook_client::ContactIndex::new(&sources, &names).search(query)
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
fn read_new_password(environment: &str) -> Result<String> {
    if let Ok(value) = std::env::var(environment) {
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

/// The same check web makes: the stored name, typed back exactly. Surrounding
/// whitespace is the newline the terminal adds, not part of what was typed.
fn delete_confirmed(typed: &str, username: &str) -> bool {
    !username.is_empty() && typed.trim() == username
}

/// Removes the state file and its keyring key once the account is gone.
///
/// Both belong to an account that no longer exists, and the file holds that
/// device's signing seeds. Best effort: the account is already deleted, so a
/// failure here is reported and not raised.
fn forget_state(path: &Path) {
    if let Ok(len) = std::fs::metadata(path).map(|meta| meta.len()) {
        if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
            let _ = overwrite(&mut file, len);
        }
    }
    if let Err(err) = std::fs::remove_file(path) {
        eprintln!("warning: could not remove {}: {err}", path.display());
    }
    let account = hex::encode(Sha256::digest(path.to_string_lossy().as_bytes()));
    if let Ok(entry) = Entry::new(STATE_KEY_SERVICE, &account) {
        let _ = entry.delete_credential();
    }
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

    #[test]
    fn account_delete_needs_the_exact_name_typed_back() {
        assert!(delete_confirmed("alice\n", "alice"));
        assert!(delete_confirmed("  alice  \r\n", "alice"));
        assert!(!delete_confirmed("Alice\n", "alice"));
        assert!(!delete_confirmed("alic\n", "alice"));
        assert!(!delete_confirmed("\n", "alice"));
        assert!(!delete_confirmed("y\n", "alice"));
        assert!(!delete_confirmed("\n", ""));
    }

    #[test]
    fn a_reminder_reads_in_every_spelling_the_help_names() {
        assert_eq!(parse_alert("15m"), Some(15));
        assert_eq!(parse_alert("15"), Some(15));
        assert_eq!(parse_alert("2h"), Some(120));
        assert_eq!(parse_alert("1d"), Some(1_440));
        assert_eq!(parse_alert("1w"), Some(10_080));
        assert_eq!(parse_alert("1d@09:00"), Some(900));
        assert_eq!(parse_alert("0d@09:00"), Some(-540));
        assert_eq!(parse_alert("90m@09:00"), None);
        assert_eq!(parse_alert("5w"), None);
        assert_eq!(parse_alert("soon"), None);
    }

    #[test]
    fn changing_an_event_keeps_the_keys_this_build_does_not_know() {
        let stored = r#"{"@type":"CalendarEvent","version":"1.0","title":"Standup","start":"2026-10-01T09:00:00Z","location":"Room 3","x":{"y":1}}"#;
        let mut draft = event_draft(event_parse("e1", stored));
        draft.title = "Retro".to_string();
        draft.end = None;
        let written: serde_json::Value =
            serde_json::from_str(&sealbook_client::event_write(&draft).unwrap()).unwrap();
        assert_eq!(written["title"], "Retro");
        assert_eq!(written["location"], "Room 3");
        assert_eq!(written["x"]["y"], 1);
    }

    #[test]
    fn renaming_a_calendar_keeps_its_flags_and_unknown_keys() {
        let stored = r##"{"@type":"Calendar","version":"1.0","name":"Work","color":"#112233","favorite":true,"archived":true,"x":7}"##;
        let draft = calendar_rename_draft(
            sealbook_client::calendar_parse("c1", stored),
            Some("Job".to_string()),
            None,
        );
        let written: serde_json::Value =
            serde_json::from_str(&sealbook_client::calendar_write(&draft).unwrap()).unwrap();
        assert_eq!(written["name"], "Job");
        assert_eq!(written["color"], "#112233");
        assert_eq!(written["favorite"], true);
        assert_eq!(written["archived"], true);
        assert_eq!(written["x"], 7);
    }

    #[test]
    fn a_window_expands_repeats_and_filters_single_events() {
        let repeating = event_parse(
            "e1",
            r#"{"@type":"CalendarEvent","version":"1.0","title":"Standup","start":"2026-10-01T09:00:00Z","recurrence":{"frequency":"daily"}}"#,
        );
        let single = event_parse(
            "e2",
            r#"{"@type":"CalendarEvent","version":"1.0","title":"Once","start":"2026-10-02T09:00:00Z"}"#,
        );
        let window = calendar_window(Some("2026-10-02"), Some("2026-10-04")).unwrap();
        assert_eq!(
            occurrence_starts(&repeating, window.as_ref()),
            vec![
                "2026-10-02T09:00:00Z",
                "2026-10-03T09:00:00Z",
                "2026-10-04T09:00:00Z"
            ]
        );
        assert_eq!(occurrence_starts(&single, window.as_ref()).len(), 1);
        let later = calendar_window(Some("2026-11-01"), Some("2026-11-02")).unwrap();
        assert!(occurrence_starts(&single, later.as_ref()).is_empty());
        assert_eq!(occurrence_starts(&repeating, None).len(), 1);
        assert!(calendar_window(Some("2026-10-02"), None).is_err());
        assert!(calendar_window(Some("2026-10-05"), Some("2026-10-02")).is_err());
    }

    #[test]
    fn replacing_reminders_keeps_everything_else_the_event_had() {
        let stored = r#"{"@type":"CalendarEvent","version":"1.0","title":"Standup","start":"2026-10-01T09:00:00Z","location":"Room 3","recurrence":{"frequency":"daily"},"alerts":[{"minutesBefore":5},{"at":"later"}],"x":1}"#;
        let draft = event_alerts_draft(
            event_parse("e1", stored),
            vec![CoreEventAlert {
                minutes_before: 30,
                extra: None,
            }],
        );
        let written: serde_json::Value =
            serde_json::from_str(&sealbook_client::event_write(&draft).unwrap()).unwrap();
        assert_eq!(written["location"], "Room 3");
        assert_eq!(written["recurrence"]["frequency"], "daily");
        assert_eq!(written["x"], 1);
        assert_eq!(
            written["alerts"],
            serde_json::json!([{ "minutesBefore": 30 }, { "at": "later" }])
        );
    }
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
            None,
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
            None,
            None,
        );
        assert_eq!(draft.notebook_id, moved.to_string());
    }

    #[test]
    fn an_update_sets_clears_or_keeps_the_parent_and_pin() {
        let stored = serde_json::json!({
            "@type": "Note",
            "parentId": Uuid::from_u128(9).to_string(),
            "pinned": true,
        })
        .to_string();
        let id = Uuid::from_u128(7);
        let keep = note_update_draft(&stored, id, "t".into(), "b".into(), None, None, None);
        assert_eq!(keep.parent_id, Some(Uuid::from_u128(9).to_string()));
        let top = note_update_draft(&stored, id, "t".into(), "b".into(), None, Some(None), None);
        assert_eq!(top.parent_id, None);
        let moved = note_update_draft(
            &stored,
            id,
            "t".into(),
            "b".into(),
            None,
            Some(Some(Uuid::from_u128(3))),
            Some(false),
        );
        assert_eq!(moved.parent_id, Some(Uuid::from_u128(3).to_string()));
        let json = note_write(&moved, "2026-10-28T12:00:00Z").unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["pinned"], false);
    }

    #[test]
    fn moving_a_contact_changes_only_its_book() {
        let stored = jscontact(
            "Ada Lovelace",
            Some("ada@example.com"),
            None,
            &ContactMore::default(),
            Uuid::from_u128(2),
            None,
        )
        .unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&stored).unwrap();
        value["x-newer"] = serde_json::json!({"keep": true});
        let moved = contact_moved(&value.to_string(), Uuid::from_u128(5)).unwrap();
        assert_eq!(contact_book_id(&moved), Uuid::from_u128(5));
        let after: serde_json::Value = serde_json::from_str(&moved).unwrap();
        assert_eq!(after["x-newer"]["keep"], true);
        assert_eq!(contact_parse("", &moved).name, "Ada Lovelace");
    }

    #[test]
    fn contact_search_finds_by_email_and_name() {
        let book = Uuid::from_u128(2);
        let ada = jscontact(
            "Ada Lovelace",
            Some("ada@example.com"),
            None,
            &ContactMore::default(),
            book,
            None,
        )
        .unwrap();
        let bob = jscontact(
            "Bob Stone",
            Some("bob@example.org"),
            None,
            &ContactMore::default(),
            book,
            None,
        )
        .unwrap();
        let (a, b) = (Uuid::from_u128(10), Uuid::from_u128(11));
        let contacts = vec![(a, ada), (b, bob)];
        let books = vec![(book, "Work".to_string())];
        assert_eq!(
            contact_search(&contacts, &books, "lovelace"),
            vec![a.to_string()]
        );
        assert_eq!(
            contact_search(&contacts, &books, "example.org"),
            vec![b.to_string()]
        );
        assert!(contact_search(&contacts, &books, "zzzz").is_empty());
    }

    #[test]
    fn a_bookmark_write_sets_normalized_tags_and_note_or_keeps_them() {
        let stored = serde_json::json!({
            "@type": "Bookmark",
            "url": "https://example.com/a",
            "notes": "old note",
            "tags": ["rust"],
        })
        .to_string();
        let kept = bookmark_json(
            "https://example.com/a",
            None,
            Uuid::from_u128(5),
            Some(&stored),
            &BookmarkExtras::default(),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&kept).unwrap();
        assert_eq!(value["notes"], "old note");
        assert_eq!(value["tags"], serde_json::json!(["rust"]));
        let changed = bookmark_json(
            "https://example.com/a",
            None,
            Uuid::from_u128(5),
            Some(&stored),
            &BookmarkExtras {
                notes: Some("new".into()),
                tags: Some(vec![" Go ".into(), "go".into(), "".into(), "Web".into()]),
            },
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&changed).unwrap();
        assert_eq!(value["notes"], "new");
        assert_eq!(value["tags"], serde_json::json!(["Go", "Web"]));
        let cleared = bookmark_json(
            "https://example.com/a",
            None,
            Uuid::from_u128(5),
            Some(&stored),
            &BookmarkExtras {
                notes: Some(String::new()),
                tags: Some(Vec::new()),
            },
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&cleared).unwrap();
        assert!(value.get("notes").is_none());
        assert!(value.get("tags").is_none());
    }

    #[test]
    fn a_collection_change_keeps_what_it_was_not_asked_to_touch() {
        let id = Uuid::from_u128(8);
        let stored = serde_json::json!({
            "@type": "BookmarkCollection",
            "name": "Reading",
            "parentId": Uuid::from_u128(3).to_string(),
            "hideFromAll": true,
            "x": 1,
        })
        .to_string();
        let renamed =
            collection_change(Some(&stored), id, Some("Read".into()), None, None).unwrap();
        assert_eq!(renamed.parent_id, Some(Uuid::from_u128(3).to_string()));
        assert!(renamed.hide_from_all);
        let json = sealbook_client::bookmark_collection_write(&renamed).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["name"], "Read");
        assert_eq!(value["x"], 1);
        let top = collection_change(Some(&stored), id, None, Some(None), None).unwrap();
        assert_eq!(top.parent_id, None);
        // A colour belongs to the top level only.
        assert!(collection_change(Some(&stored), id, None, None, Some("#fff".into())).is_err());
        assert!(collection_change(None, id, Some("A".into()), None, Some("#fff".into())).is_ok());
        // The default collection is never buried.
        assert!(collection_change(
            None,
            DEFAULT_BOOKMARK_COLLECTION_ID,
            Some("A".into()),
            Some(Some(Uuid::from_u128(3))),
            None
        )
        .is_err());
    }

    #[test]
    fn notes_list_pinned_first_then_most_recently_edited() {
        let note = |title: &str, pinned: bool, updated: &str| {
            serde_json::json!({"@type": "Note", "title": title, "pinned": pinned, "updatedAt": updated})
                .to_string()
        };
        let rows = vec![
            (
                Uuid::from_u128(1),
                note("old", false, "2026-01-01T00:00:00Z"),
            ),
            (
                Uuid::from_u128(2),
                note("new", false, "2026-06-01T00:00:00Z"),
            ),
            (
                Uuid::from_u128(3),
                note("pin", true, "2025-01-01T00:00:00Z"),
            ),
        ];
        let ordered = in_core_order(
            rows,
            |id, json| {
                let note = note_parse(&id.to_string(), json);
                CoreOrderItem {
                    id: id.to_string(),
                    name: note.title,
                    pinned: note.pinned.unwrap_or(false),
                    stamp: note.updated_at.unwrap_or_default(),
                }
            },
            |items| sealbook_client::order_by_recency(items, true),
        );
        let titles: Vec<_> = ordered.iter().map(|(id, _)| id.as_u128()).collect();
        assert_eq!(titles, vec![3, 2, 1]);
    }

    #[test]
    fn a_note_may_not_become_its_own_ancestor() {
        let items = vec![
            ("a".to_string(), None),
            ("b".to_string(), Some("a".to_string())),
        ];
        assert!(sealbook_client::may_reparent(&items, "b", None));
        assert!(!sealbook_client::may_reparent(&items, "a", Some("b")));
        assert!(!sealbook_client::may_reparent(&items, "a", Some("a")));
        assert!(!sealbook_client::may_reparent(&items, "a", Some("gone")));
    }

    #[test]
    fn a_bookmark_carries_its_url_title_and_collection() {
        let collection = Uuid::from_u128(5);
        let json = bookmark_json(
            "example.com/a",
            Some("Example"),
            collection,
            None,
            &BookmarkExtras::default(),
        )
        .unwrap();
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
            let json = bookmark_json(
                "https://example.com/b",
                title,
                Uuid::from_u128(5),
                None,
                &BookmarkExtras::default(),
            )
            .unwrap();
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
            &BookmarkExtras::default(),
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
            &BookmarkExtras::default(),
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
            None,
            &ContactMore::default(),
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

    #[test]
    fn an_address_spec_reads_every_key_and_refuses_a_blank_one() {
        let work = parse_address_spec("kind=work; street1=1 Main St; city=Leeds; zip=LS1").unwrap();
        assert_eq!(work.kind, CoreChannelKind::Work);
        assert_eq!(work.street1.as_deref(), Some("1 Main St"));
        assert_eq!(work.locality.as_deref(), Some("Leeds"));
        assert_eq!(work.postcode.as_deref(), Some("LS1"));
        let cabin = parse_address_spec("kind=Cabin;country=Norway").unwrap();
        assert_eq!(cabin.kind, CoreChannelKind::Custom);
        assert_eq!(cabin.label.as_deref(), Some("Cabin"));
        assert!(parse_address_spec("kind=home").is_err());
        assert!(parse_address_spec("planet=Mars").is_err());
        assert!(parse_address_spec("city").is_err());
    }

    #[test]
    fn more_fields_replace_when_given_and_keep_when_left_out() {
        let stored = r#"{"@type":"Card","name":{"full":"Ada"},"nickNames":{"n1":{"name":"A"}},"organizations":{"o1":{"name":"Old Co","titles":{"t1":{"name":"Eng"}}}}}"#;
        let none = ContactMore::default();
        let kept = jscontact("Ada", None, None, &none, Uuid::nil(), Some(stored)).unwrap();
        let card = contact_parse("c", &kept);
        assert_eq!(card.nickname.as_deref(), Some("A"));
        assert_eq!(card.work[0].organization, "Old Co");
        let more = ContactMore {
            phones: vec![parse_phone_spec("value=+44 20 7946 0000;kind=work").unwrap()],
            org: Some("New Co".into()),
            title: Some("CTO".into()),
            anniversary: Some("2020-05".into()),
            ..Default::default()
        };
        let set = jscontact("Ada", None, None, &more, Uuid::nil(), Some(stored)).unwrap();
        let card = contact_parse("c", &set);
        assert_eq!(card.phones[0].value, "+44 20 7946 0000");
        assert_eq!(card.work[0].organization, "New Co");
        assert_eq!(card.work[0].title.as_deref(), Some("CTO"));
        assert_eq!(card.dates[0].date, "2020-05");
        let clear = ContactMore {
            clear_nickname: true,
            clear_work: true,
            clear_anniversary: true,
            ..Default::default()
        };
        let gone = jscontact("Ada", None, None, &clear, Uuid::nil(), Some(&set)).unwrap();
        let card = contact_parse("c", &gone);
        assert!(card.nickname.is_none() && card.work.is_empty() && card.dates.is_empty());
        assert_eq!(card.phones.len(), 1);
    }

    #[test]
    fn partial_dates_and_phones_are_checked() {
        assert!(parse_partial_date("2020").is_ok());
        assert!(parse_partial_date("2020-5").is_err());
        assert!(parse_phone_spec("kind=work").is_err());
        assert_eq!(parse_phone_spec("0123").unwrap().value, "0123");
        assert!(parse_profile_field("hobby=x").is_err());
    }

    #[test]
    fn profile_fields_set_whole_and_keep_the_rest_of_the_card() {
        let stored = r#"{"@type":"Card","name":{"full":"Ada"},"nickNames":{"n1":{"name":"A"}}}"#;
        let long = "x".repeat(5000);
        let out = contact_with_profile(
            stored,
            &[
                ("howWeMet".into(), long.clone()),
                ("interests".into(), "chess, maths ,".into()),
            ],
        )
        .unwrap();
        let card = contact_parse("c", &out);
        let profile = card.profile.unwrap();
        assert_eq!(profile.how_we_met.as_deref(), Some(long.as_str()));
        assert_eq!(profile.interests, vec!["chess", "maths"]);
        assert_eq!(card.nickname.as_deref(), Some("A"));
        assert!(contact_card("c", &out, &[]).contains("interests: chess, maths"));
    }

    #[test]
    fn addresses_given_to_an_update_replace_the_list_and_none_keep_it() {
        let stored = r#"{"@type":"Card","name":{"full":"Ada"},"addresses":{"a1":{"locality":"London"},"a2":{"locality":"Paris"}}}"#;
        let given = vec![
            parse_address_spec("city=Leeds").unwrap(),
            parse_address_spec("kind=work;city=York").unwrap(),
        ];
        let card = jscontact(
            "Ada",
            None,
            Some(given),
            &ContactMore::default(),
            DEFAULT_ADDRESS_BOOK_ID,
            Some(stored),
        )
        .unwrap();
        let read = contact_parse("c", &card);
        let cities: Vec<_> = read
            .addresses
            .iter()
            .map(|a| a.locality.clone().unwrap())
            .collect();
        assert_eq!(cities, ["Leeds", "York"]);

        let kept = jscontact(
            "Ada",
            None,
            None,
            &ContactMore::default(),
            DEFAULT_ADDRESS_BOOK_ID,
            Some(stored),
        )
        .unwrap();
        assert_eq!(contact_parse("c", &kept).addresses.len(), 2);

        let cleared = jscontact(
            "Ada",
            None,
            Some(Vec::new()),
            &ContactMore::default(),
            DEFAULT_ADDRESS_BOOK_ID,
            Some(stored),
        )
        .unwrap();
        assert!(contact_parse("c", &cleared).addresses.is_empty());
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

    fn ics(events: &str) -> String {
        format!("BEGIN:VCALENDAR\r\nVERSION:2.0\r\n{events}END:VCALENDAR\r\n")
    }

    #[test]
    fn an_imported_time_is_the_instant_its_own_zone_names() {
        let london = TimeZone::get("Europe/London").unwrap();
        let read = ics_parse(&ics("BEGIN:VEVENT\r\nSUMMARY:Standup\r\n\
             DTSTART;TZID=America/New_York:20260701T090000\r\n\
             DTEND;TZID=America/New_York:20260701T093000\r\n\
             RRULE:FREQ=WEEKLY;BYDAY=MO\r\nEND:VEVENT\r\n"));
        let draft = imported_event(
            &read.events[0],
            "Europe/London",
            &london,
            DEFAULT_CALENDAR_ID,
        )
        .unwrap();
        assert_eq!(draft.start, "2026-07-01T13:00:00Z");
        assert_eq!(draft.end.as_deref(), Some("2026-07-01T13:30:00Z"));
        assert_eq!(draft.timezone.as_deref(), Some("America/New_York"));
        assert_eq!(draft.calendar_id, Some(DEFAULT_CALENDAR_ID.to_string()));
        assert!(draft.recurrence.is_some());
    }

    #[test]
    fn an_imported_time_without_a_known_zone_is_placed_in_the_given_one() {
        let london = TimeZone::get("Europe/London").unwrap();
        let read = ics_parse(&ics(
            "BEGIN:VEVENT\r\nSUMMARY:Floating\r\nDTSTART:20260701T090000\r\nEND:VEVENT\r\n\
             BEGIN:VEVENT\r\nSUMMARY:Outlook\r\n\
             DTSTART;TZID=GMT Standard Time:20260102T090000\r\nEND:VEVENT\r\n",
        ));
        let calendar = Uuid::new_v4();
        let floating = imported_event(&read.events[0], "Europe/London", &london, calendar).unwrap();
        assert_eq!(floating.start, "2026-07-01T08:00:00Z");
        assert_eq!(floating.timezone.as_deref(), Some("Europe/London"));
        let outlook = imported_event(&read.events[1], "Europe/London", &london, calendar).unwrap();
        assert_eq!(outlook.start, "2026-01-02T09:00:00Z");
        assert_eq!(outlook.calendar_id, Some(calendar.to_string()));
    }

    #[test]
    fn an_imported_date_or_instant_is_written_as_it_was_read() {
        let london = TimeZone::get("Europe/London").unwrap();
        let read = ics_parse(&ics("BEGIN:VEVENT\r\nSUMMARY:Holiday\r\n\
             DTSTART;VALUE=DATE:20260803\r\nDTEND;VALUE=DATE:20260805\r\nEND:VEVENT\r\n\
             BEGIN:VEVENT\r\nSUMMARY:Call\r\nDTSTART:20260701T090000Z\r\nEND:VEVENT\r\n"));
        let holiday = imported_event(
            &read.events[0],
            "Europe/London",
            &london,
            DEFAULT_CALENDAR_ID,
        )
        .unwrap();
        assert_eq!(holiday.start, "2026-08-03");
        assert_eq!(holiday.end.as_deref(), Some("2026-08-04"));
        let call = imported_event(
            &read.events[1],
            "Europe/London",
            &london,
            DEFAULT_CALENDAR_ID,
        )
        .unwrap();
        assert_eq!(call.start, "2026-07-01T09:00:00Z");
    }

    #[test]
    fn an_unknown_import_zone_is_refused() {
        assert!(import_zone(Some("Mars/Olympus")).is_err());
        assert_eq!(import_zone(Some("Asia/Tokyo")).unwrap().0, "Asia/Tokyo");
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
