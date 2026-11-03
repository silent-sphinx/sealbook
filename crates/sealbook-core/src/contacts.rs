//! The contact card and address book payloads: which keys a writer owns, how a
//! card is written, and how one is read back.
//!
//! Contacts are the third content type to move here and the largest, a JSContact
//! card with a vendor profile in it. Four writers produced it: the web and
//! Android, which agreed on the owned key list because one was ported from the
//! other, and the CLI, which wrote five keys and replaced every email it was
//! handed. The rules are [`crate::payload`]'s: one owned set per record, absent
//! is omitted and never null, and a payload declaring a schema major this build
//! does not read is read but never written over.
//!
//! Three decisions are this type's own.
//!
//! **An entry the editor cannot show is carried, not deleted.** A card shows one
//! nickname, one note and one photo, and both hosts wrote the whole property back
//! from that one, so a card imported from another app with two nicknames lost the
//! second on the first edit. The writer now replaces the entry the host sees and
//! carries every other. Clearing the visible one removes only that one, which is
//! what a list does. Addresses are a list the editors show whole, so the writer
//! writes every one it is handed and carries only the stored entries it cannot
//! read.
//!
//! **Key order is the key's number, not the key.** `serde_json` keeps maps sorted,
//! so `e10` would read before `e2`. Entries are read in the order of the number a
//! key ends in, which is the order every client wrote them in.
//!
//! **A nameless card is not named by writing a name onto it.** The record has a
//! `name`, which is what is stored, and a `display_name` for a list. The web
//! seeded its editor from the display name and wrote the literal `Untitled` onto
//! the card on the next save; Android wrote the email's local part.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::contact_profile::{parse_profile, profile_json, CoreContactProfile};
use crate::notes::{attachment_json, parse_attachments, CoreNoteAttachment};
use crate::payload::{
    as_object, declared_readable, entry_with, extra_of, refuse_newer_major, trimmed, write_payload,
};
use crate::CoreError;
use sealbook_protocol::PAYLOAD_SCHEMA_VERSION;

pub use crate::contact_profile::{
    DEFAULT_RELATIONSHIP_KIND, MAX_PROFILE_ENTRIES, MAX_PROFILE_TEXT_CHARS, PROFILE_KEYS,
};
pub use sealbook_protocol::{
    ADDRESS_BOOK_CONTENT_TYPE, ADDRESS_BOOK_ID_PROP, DEFAULT_ADDRESS_BOOK_NAME,
    JSCONTACT_CONTENT_TYPE,
};

/// Written only when true, so a reader predating it sees the card it expects.
pub const CONTACT_ARCHIVED_PROP: &str = "sealbook:archived";
/// Absent on a contact with no attachments.
pub const CONTACT_ATTACHMENTS_PROP: &str = "sealbook:attachments";
pub const CONTACT_PROFILE_PROP: &str = "sealbook:profile";
/// When a workplace or an address began and ended, and whether it is current,
/// on its `organizations` or `addresses` entry.
pub const PERIOD_START_PROP: &str = "sealbook:start";
pub const PERIOD_END_PROP: &str = "sealbook:end";
pub const PERIOD_CURRENT_PROP: &str = "sealbook:current";
/// A workplace's note, on its `organizations` entry.
pub const WORK_NOTE_PROP: &str = "sealbook:note";
const WORK_KEYS: &[&str] = &[
    "name",
    PERIOD_START_PROP,
    PERIOD_END_PROP,
    PERIOD_CURRENT_PROP,
    WORK_NOTE_PROP,
];

/// What a card with no name, nickname, email or number is listed as.
pub const UNNAMED_CONTACT_NAME: &str = "Unnamed contact";

/// What an address book with no readable name is listed as, unless it is the
/// default one: see [`address_book_parse`].
pub const UNTITLED_ADDRESS_BOOK_NAME: &str = "Untitled Address Book";

/// The default address book's id, as a string, since that is how every host holds
/// a card's `sealbook:addressBookId`.
pub fn default_address_book_id() -> String {
    sealbook_protocol::DEFAULT_ADDRESS_BOOK_ID.to_string()
}

/// Every key a card writer owns, including the ones written only when the field
/// is non-empty and the legacy spellings a reader still accepts. A legacy key is
/// owned so that a write clears it: left in place, clearing a nickname would
/// bring an old `nicknames` entry back into view.
pub const CONTACT_KEYS: &[&str] = &[
    "@type",
    "version",
    "name",
    ADDRESS_BOOK_ID_PROP,
    CONTACT_ARCHIVED_PROP,
    CONTACT_ATTACHMENTS_PROP,
    "nickNames",
    "emails",
    "phones",
    "addresses",
    "organizations",
    "titles",
    "speakToAs",
    "anniversaries",
    "onlineServices",
    "notes",
    CONTACT_PROFILE_PROP,
    "media",
    "created",
    "updated",
    "nicknames",
    "pronouns",
    "fullName",
    "displayName",
    "photos",
    "photo",
    "avatar",
    "createdAt",
    "updatedAt",
];

/// Every key an address book writer owns.
pub const ADDRESS_BOOK_KEYS: &[&str] = &["@type", "version", "name", "archived"];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum CoreChannelKind {
    Work,
    #[default]
    Home,
    Mobile,
    Custom,
}

/// An email or a phone number. `label` is only meaningful for `Custom`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreContactChannel {
    pub kind: CoreChannelKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub value: String,
    /// Keys of the stored entry this build does not write, as a JSON object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub extra: Option<String>,
}

/// A postal address. `kind` is `Home`, `Work` or `Custom`, as the editors offer
/// them; an unmarked one reads as `Home`. `label` is only meaningful for `Custom`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreContactAddress {
    pub kind: CoreChannelKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub street1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub street2: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postcode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// When they moved in, as a partial ISO date.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub start: Option<String>,
    /// When they left. Absent while `current`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub end: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    #[cfg_attr(feature = "uniffi", uniffi(default = false))]
    pub current: bool,
    /// Keys of the stored entry this build does not write, as a JSON object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub extra: Option<String>,
}

impl CoreContactAddress {
    /// True when no line of it holds text, whatever its kind.
    pub fn is_blank(&self) -> bool {
        [
            &self.street1,
            &self.street2,
            &self.locality,
            &self.region,
            &self.postcode,
            &self.country,
        ]
        .into_iter()
        .all(|line| present(line).is_none())
    }

    /// The lines that hold text, in the order an envelope puts them.
    pub fn lines(&self) -> Vec<String> {
        [
            &self.street1,
            &self.street2,
            &self.locality,
            &self.region,
            &self.postcode,
            &self.country,
        ]
        .into_iter()
        .filter_map(present)
        .collect()
    }
}

/// One workplace and, when there is one, the title held there.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreContactWork {
    pub organization: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Partial ISO dates (`YYYY`, `YYYY-MM`, `YYYY-MM-DD`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub start: Option<String>,
    /// Never set alongside `current`; the writer drops it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub end: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    #[cfg_attr(feature = "uniffi", uniffi(default = false))]
    pub current: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub note: Option<String>,
    /// Keys of the stored entry this build does not write, as a JSON object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub extra: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum CoreContactDateKind {
    Birthday,
    Anniversary,
    Custom,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreContactDate {
    pub kind: CoreContactDateKind,
    /// Written only for `Custom`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub date: String,
    /// Keys of the stored entry this build does not write, as a JSON object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub extra: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreContactSocial {
    pub platform: String,
    pub handle: String,
    /// Keys of the stored entry this build does not write, as a JSON object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub extra: Option<String>,
}

/// One card as it is drafted, before it is written.
///
/// A host editing an existing card builds this from [`contact_parse`] and changes
/// the fields its UI owns, which is what carries a field it cannot show.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreContactDraft {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pronouns: Option<String>,
    pub emails: Vec<CoreContactChannel>,
    pub phones: Vec<CoreContactChannel>,
    pub addresses: Vec<CoreContactAddress>,
    pub work: Vec<CoreContactWork>,
    pub dates: Vec<CoreContactDate>,
    pub socials: Vec<CoreContactSocial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// A data URI, as the photo picker hands it over.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<CoreContactProfile>,
    pub attachments: Vec<CoreNoteAttachment>,
    /// Resolved on write: blank, or the sidebar's `all`, is the default book.
    pub address_book_id: String,
    /// Out of its address book and the list, with the card left in the vault.
    /// `address_book_id` is kept so restoring puts it back. Written only when set.
    pub archived: bool,
    /// Kept from the stored card; a card with none takes the `now` of its write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// The payload this draft came from, when it came from one. The write merges
    /// onto it. `None` for a card written from scratch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

/// One card as it was read back.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreContact {
    pub id: String,
    /// What is stored, empty when the card carries no name. This is what an
    /// editor seeds from.
    pub name: String,
    /// What a list shows: the name, else the nickname, else the email's local
    /// part, else the first number, else [`UNNAMED_CONTACT_NAME`].
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pronouns: Option<String>,
    pub emails: Vec<CoreContactChannel>,
    pub phones: Vec<CoreContactChannel>,
    pub addresses: Vec<CoreContactAddress>,
    pub work: Vec<CoreContactWork>,
    pub dates: Vec<CoreContactDate>,
    pub socials: Vec<CoreContactSocial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<CoreContactProfile>,
    pub attachments: Vec<CoreNoteAttachment>,
    pub address_book_id: String,
    pub archived: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Whether this build reads the schema major the payload declares. False
    /// means the fields above were still read, because a lenient parse beats a
    /// blank row, but [`contact_write`] will refuse to write over it.
    pub readable: bool,
    pub raw: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreAddressBookDraft {
    pub name: String,
    /// Written only when set, so a book never archived is byte-identical to one
    /// from a build predating the field.
    #[serde(default)]
    pub archived: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreAddressBook {
    pub id: String,
    pub name: String,
    pub archived: bool,
    pub readable: bool,
    pub raw: String,
}

impl CoreContact {
    /// This card as a draft of itself, `raw` set, so an edit changes the fields it
    /// names and the write carries the rest. For the hosts that edit in Rust; the
    /// others build the same thing from their own view model.
    pub fn draft(&self) -> CoreContactDraft {
        CoreContactDraft {
            name: self.name.clone(),
            nickname: self.nickname.clone(),
            pronouns: self.pronouns.clone(),
            emails: self.emails.clone(),
            phones: self.phones.clone(),
            addresses: self.addresses.clone(),
            work: self.work.clone(),
            dates: self.dates.clone(),
            socials: self.socials.clone(),
            notes: self.notes.clone(),
            avatar: self.avatar.clone(),
            profile: self.profile.clone(),
            attachments: self.attachments.clone(),
            address_book_id: self.address_book_id.clone(),
            archived: self.archived,
            created_at: self.created_at.clone(),
            raw: Some(self.raw.clone()),
        }
    }
}

// Reading helpers.

/// A key's entries in the order the clients wrote them in: by the number the key
/// ends in, then by the key. See the module note on key order.
fn ordered(object: &Map<String, Value>) -> Vec<(&String, &Value)> {
    fn rank(key: &str) -> (String, u64) {
        let digits = key.bytes().rev().take_while(u8::is_ascii_digit).count();
        let (prefix, number) = key.split_at(key.len() - digits);
        (prefix.to_string(), number.parse().unwrap_or(u64::MAX))
    }
    let mut entries: Vec<_> = object.iter().collect();
    entries.sort_by_key(|(key, _)| rank(key));
    entries
}

/// The entries under `key` that are objects, in order, with their ids.
fn objects<'a>(
    card: &'a Map<String, Value>,
    key: &str,
) -> Vec<(&'a String, &'a Map<String, Value>)> {
    card.get(key)
        .and_then(Value::as_object)
        .map(|map| {
            ordered(map)
                .into_iter()
                .filter_map(|(id, value)| Some((id, value.as_object()?)))
                .collect()
        })
        .unwrap_or_default()
}

fn flag(object: Option<&Value>, key: &str) -> bool {
    object
        .and_then(|value| value.get(key))
        .and_then(Value::as_bool)
        == Some(true)
}

fn present(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(ToOwned::to_owned)
}

fn first_of(entry: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| trimmed(entry, key))
}

/// A blank id, or the sidebar's `all`, is the default book.
pub fn resolve_address_book_id(id: Option<String>) -> String {
    match id.as_deref().map(str::trim) {
        Some(id) if !id.is_empty() && id != "all" => id.to_string(),
        _ => default_address_book_id(),
    }
}

fn channel_kind(
    entry: &Map<String, Value>,
    fallback: CoreChannelKind,
) -> (CoreChannelKind, Option<String>) {
    let label = trimmed(entry, "label");
    let kind = if flag(entry.get("features"), "mobile")
        || label
            .as_deref()
            .is_some_and(|label| label.eq_ignore_ascii_case("mobile"))
    {
        CoreChannelKind::Mobile
    } else if flag(entry.get("contexts"), "work") {
        CoreChannelKind::Work
    } else if flag(entry.get("contexts"), "private") {
        CoreChannelKind::Home
    } else if label.is_some() {
        CoreChannelKind::Custom
    } else {
        fallback
    };
    let label = (kind == CoreChannelKind::Custom).then_some(label).flatten();
    (kind, label)
}

/// An email with no hint of its kind is a home one, and a number with none is a
/// mobile: each is what the editors offer first for that field. The web read an
/// unmarked number as home, which a save then wrote back as a private context the
/// card never claimed.
fn parse_channels(
    card: &Map<String, Value>,
    key: &str,
    value_keys: &[&str],
    fallback: CoreChannelKind,
) -> Vec<CoreContactChannel> {
    let known: Vec<&str> = value_keys
        .iter()
        .copied()
        .chain(["contexts", "features", "label"])
        .collect();
    objects(card, key)
        .into_iter()
        .filter_map(|(_, entry)| {
            let value = first_of(entry, value_keys)?;
            let (kind, label) = channel_kind(entry, fallback);
            Some(CoreContactChannel {
                kind,
                label,
                value,
                extra: extra_of(entry, &known),
            })
        })
        .collect()
}

const ADDRESS_KEYS: &[&str] = &[
    "street",
    "locality",
    "region",
    "postCode",
    "postcode",
    "country",
    "contexts",
    "features",
    "label",
    PERIOD_START_PROP,
    PERIOD_END_PROP,
    PERIOD_CURRENT_PROP,
];

/// The start, end and current flag of an entry. A current entry has no end,
/// so a stored one is ignored.
fn period_of(entry: &Map<String, Value>) -> (Option<String>, Option<String>, bool) {
    let current = entry.get(PERIOD_CURRENT_PROP).and_then(Value::as_bool) == Some(true);
    let end = if current {
        None
    } else {
        trimmed(entry, PERIOD_END_PROP)
    };
    (trimmed(entry, PERIOD_START_PROP), end, current)
}

fn put_period(
    entry: &mut Map<String, Value>,
    start: &Option<String>,
    end: &Option<String>,
    current: bool,
) {
    if let Some(start) = present(start) {
        entry.insert(PERIOD_START_PROP.into(), json!(start));
    }
    if current {
        entry.insert(PERIOD_CURRENT_PROP.into(), json!(true));
    } else if let Some(end) = present(end) {
        entry.insert(PERIOD_END_PROP.into(), json!(end));
    }
}

fn parse_addresses(card: &Map<String, Value>) -> Vec<CoreContactAddress> {
    objects(card, "addresses")
        .into_iter()
        .filter_map(|(_, entry)| address_of(entry))
        .collect()
}

fn address_of(entry: &Map<String, Value>) -> Option<CoreContactAddress> {
    let street: Vec<String> = match entry.get("street") {
        Some(Value::Array(lines)) => lines
            .iter()
            .map(|line| line.as_str().map(str::trim).unwrap_or_default().to_string())
            .collect(),
        Some(Value::String(line)) => vec![line.trim().to_string()],
        _ => Vec::new(),
    };
    let line = |index: usize| street.get(index).filter(|text| !text.is_empty()).cloned();
    let (kind, label) = channel_kind(entry, CoreChannelKind::Home);
    let (start, end, current) = period_of(entry);
    let address = CoreContactAddress {
        kind,
        label,
        street1: line(0),
        street2: line(1),
        locality: trimmed(entry, "locality"),
        region: trimmed(entry, "region"),
        postcode: first_of(entry, &["postCode", "postcode"]),
        country: trimmed(entry, "country"),
        start,
        end,
        current,
        extra: extra_of(entry, ADDRESS_KEYS),
    };
    (!address.is_blank()).then_some(address)
}

fn parse_work(card: &Map<String, Value>) -> Vec<CoreContactWork> {
    let titles = objects(card, "titles");
    let mut work = Vec::new();
    for (org_id, org) in objects(card, "organizations") {
        let Some(organization) = trimmed(org, "name") else {
            continue;
        };
        let linked: Vec<String> = titles
            .iter()
            .filter(|(_, title)| title.get("organization").and_then(Value::as_str) == Some(org_id))
            .filter_map(|(_, title)| trimmed(title, "name"))
            .collect();
        let (start, end, current) = period_of(org);
        let row = |title: Option<String>| CoreContactWork {
            organization: organization.clone(),
            title,
            start: start.clone(),
            end: end.clone(),
            current,
            note: trimmed(org, WORK_NOTE_PROP),
            extra: extra_of(org, WORK_KEYS),
        };
        if linked.is_empty() {
            work.push(row(None));
        }
        for title in linked {
            work.push(row(Some(title)));
        }
    }
    work
}

/// Moves the profile's career rows onto `work`, which is where a workplace's
/// dates live now. A row naming a workplace already on the card fills in that
/// row's dates rather than listing the job twice. Runs on every read, so a
/// career row a build predating `PERIOD_START_PROP` writes later is moved too.
fn fold_career(work: &mut Vec<CoreContactWork>, profile: &mut Option<CoreContactProfile>) {
    let Some(profile) = profile.as_mut() else {
        return;
    };
    let same = |a: &str, b: &str| a.trim().eq_ignore_ascii_case(b.trim());
    for job in std::mem::take(&mut profile.career) {
        let current = job.end.is_none() && job.start.is_some();
        let matched = work.iter_mut().find(|row| {
            same(&row.organization, &job.organization)
                && same(
                    row.title.as_deref().unwrap_or_default(),
                    job.title.as_deref().unwrap_or_default(),
                )
                && row.start.is_none()
                && row.end.is_none()
        });
        match matched {
            Some(row) => {
                row.start = job.start;
                row.end = job.end;
                row.current = row.current || row.end.is_none();
                row.note = row.note.take().or(job.note);
            }
            None => work.push(CoreContactWork {
                organization: job.organization,
                title: job.title,
                start: job.start,
                end: job.end,
                current,
                note: job.note,
                extra: None,
            }),
        }
    }
}

fn parse_dates(card: &Map<String, Value>) -> Vec<CoreContactDate> {
    objects(card, "anniversaries")
        .into_iter()
        .filter_map(|(_, entry)| {
            let date = trimmed(entry, "date")?;
            let kind = match trimmed(entry, "kind")
                .map(|kind| kind.to_ascii_lowercase())
                .as_deref()
            {
                Some("birth" | "birthday") => CoreContactDateKind::Birthday,
                Some("wedding" | "anniversary") => CoreContactDateKind::Anniversary,
                _ => CoreContactDateKind::Custom,
            };
            Some(CoreContactDate {
                kind,
                label: trimmed(entry, "label"),
                date,
                extra: extra_of(entry, &["date", "kind", "label"]),
            })
        })
        .collect()
}

fn parse_socials(card: &Map<String, Value>) -> Vec<CoreContactSocial> {
    objects(card, "onlineServices")
        .into_iter()
        .filter_map(|(_, entry)| {
            Some(CoreContactSocial {
                platform: trimmed(entry, "service").unwrap_or_else(|| "custom".to_string()),
                handle: first_of(entry, &["user", "uri"])?,
                extra: extra_of(entry, &["service", "user", "uri"]),
            })
        })
        .collect()
}

fn parse_nickname(card: &Map<String, Value>) -> Option<String> {
    ["nickNames", "nicknames"].iter().find_map(|key| {
        objects(card, key)
            .into_iter()
            .find_map(|(_, entry)| trimmed(entry, "name"))
    })
}

fn parse_notes(card: &Map<String, Value>) -> Option<String> {
    match card.get("notes") {
        Some(Value::String(text)) => Some(text.trim().to_string()).filter(|text| !text.is_empty()),
        Some(Value::Object(_)) => objects(card, "notes")
            .into_iter()
            .find_map(|(_, entry)| trimmed(entry, "note")),
        _ => None,
    }
}

fn avatar_of(entry: &Map<String, Value>) -> Option<String> {
    first_of(entry, &["uri", "href"])
}

/// The photo, from the shape this build writes and then from the ones an
/// importer or an older build used.
fn parse_avatar(card: &Map<String, Value>) -> Option<String> {
    let media = card.get("media").and_then(Value::as_object);
    media
        .and_then(|media| media.get("avatar")?.as_object().and_then(avatar_of))
        .or_else(|| {
            objects(card, "media")
                .into_iter()
                .find_map(|(_, entry)| avatar_of(entry))
        })
        .or_else(|| {
            objects(card, "photos")
                .into_iter()
                .find_map(|(_, entry)| avatar_of(entry))
        })
        .or_else(|| match card.get("photo") {
            Some(Value::String(uri)) => Some(uri.trim().to_string()).filter(|uri| !uri.is_empty()),
            Some(Value::Object(entry)) => avatar_of(entry),
            _ => None,
        })
        .or_else(|| trimmed(card, "avatar"))
}

/// The stored name, from the shapes the clients and importers have written.
///
/// A stored `Untitled` is no name: it is what the web wrote onto a nameless card
/// when it saved one, and Android has always read it as none. So is `Work` on a
/// card with a `Work` organization, which an importer wrote for a card that was
/// only a company.
fn parse_name(card: &Map<String, Value>, work: &[CoreContactWork]) -> String {
    let name = card.get("name").and_then(Value::as_object);
    let from_name = |keys: &[&str]| name.and_then(|name| first_of(name, keys));
    let joined = |keys: &[&str]| {
        let parts: Vec<String> = keys
            .iter()
            .filter_map(|key| name.and_then(|name| trimmed(name, key)))
            .collect();
        (!parts.is_empty()).then(|| parts.join(" "))
    };
    let components = name
        .and_then(|name| name.get("components")?.as_array())
        .map(|parts| {
            parts
                .iter()
                .filter_map(|part| part.get("value")?.as_str())
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|joined| !joined.is_empty());
    let found = from_name(&["full", "formatted", "value"])
        .or_else(|| joined(&["given", "family", "givenName", "familyName"]))
        .or(components)
        .or_else(|| first_of(card, &["fullName", "displayName"]))
        .or_else(|| trimmed(card, "name"));
    found
        .filter(|name| !name.eq_ignore_ascii_case("untitled"))
        .filter(|name| {
            !(name.eq_ignore_ascii_case("work")
                && work
                    .iter()
                    .any(|work| work.organization.eq_ignore_ascii_case("work")))
        })
        .unwrap_or_default()
}

fn display_name(
    name: &str,
    nickname: &Option<String>,
    emails: &[CoreContactChannel],
    phones: &[CoreContactChannel],
) -> String {
    if !name.is_empty() {
        return name.to_string();
    }
    if let Some(nickname) = nickname {
        return nickname.clone();
    }
    if let Some(email) = emails.first() {
        let local = email.value.split('@').next().unwrap_or_default();
        let local = local.replace(['.', '_'], " ");
        let local = local.trim();
        if !local.is_empty() {
            return local.to_string();
        }
    }
    if let Some(phone) = phones.first() {
        return phone.value.clone();
    }
    UNNAMED_CONTACT_NAME.to_string()
}

/// Reads a stored card.
///
/// Lenient throughout: a payload that is not JSON, or is JSON but not an object,
/// or has a malformed entry in one of its maps, comes back as a named row rather
/// than taking the list down. Android's reader threw on a string where an email
/// object should be.
pub fn contact_parse(id: &str, raw: &str) -> CoreContact {
    let card = as_object(raw).unwrap_or_default();
    let emails = parse_channels(&card, "emails", &["address"], CoreChannelKind::Home);
    let phones = parse_channels(
        &card,
        "phones",
        &["number", "phoneNumber"],
        CoreChannelKind::Mobile,
    );
    let mut work = parse_work(&card);
    let name = parse_name(&card, &work);
    let mut profile = parse_profile(card.get(CONTACT_PROFILE_PROP));
    fold_career(&mut work, &mut profile);
    let nickname = parse_nickname(&card);
    let pronouns = card
        .get("speakToAs")
        .and_then(Value::as_object)
        .and_then(|speak| trimmed(speak, "pronouns"))
        .or_else(|| trimmed(&card, "pronouns"));
    CoreContact {
        id: id.to_string(),
        display_name: display_name(&name, &nickname, &emails, &phones),
        name,
        nickname,
        pronouns,
        emails,
        phones,
        addresses: parse_addresses(&card),
        work,
        dates: parse_dates(&card),
        socials: parse_socials(&card),
        notes: parse_notes(&card),
        avatar: parse_avatar(&card),
        profile,
        attachments: parse_attachments(card.get(CONTACT_ATTACHMENTS_PROP)),
        address_book_id: resolve_address_book_id(trimmed(&card, ADDRESS_BOOK_ID_PROP)),
        archived: card.get(CONTACT_ARCHIVED_PROP).and_then(Value::as_bool) == Some(true),
        created_at: first_of(&card, &["created", "createdAt"]),
        updated_at: first_of(&card, &["updated", "updatedAt"]),
        readable: declared_readable(&card),
        raw: raw.to_string(),
    }
}

// Writing helpers.

fn channel_entries(
    channels: &[CoreContactChannel],
    prefix: &str,
    value_key: &str,
    mobile_in_features: bool,
) -> Option<Value> {
    let mut out = Map::new();
    let mut index = 0;
    for channel in channels {
        let Some(value) = present(&Some(channel.value.clone())) else {
            continue;
        };
        index += 1;
        let mut entry = entry_with(&channel.extra);
        entry.insert(value_key.into(), json!(value));
        put_kind(&mut entry, channel.kind, &channel.label, mobile_in_features);
        out.insert(format!("{prefix}{index}"), Value::Object(entry));
    }
    (!out.is_empty()).then_some(Value::Object(out))
}

/// Writes the kind the way [`channel_kind`] reads it back.
fn put_kind(
    entry: &mut Map<String, Value>,
    kind: CoreChannelKind,
    label: &Option<String>,
    mobile_in_features: bool,
) {
    match kind {
        CoreChannelKind::Work => {
            entry.insert("contexts".into(), json!({ "work": true }));
        }
        CoreChannelKind::Home => {
            entry.insert("contexts".into(), json!({ "private": true }));
        }
        CoreChannelKind::Mobile if mobile_in_features => {
            entry.insert("features".into(), json!({ "mobile": true }));
        }
        CoreChannelKind::Mobile => {
            entry.insert("label".into(), json!("Mobile"));
        }
        CoreChannelKind::Custom => {
            if let Some(label) = present(label) {
                entry.insert("label".into(), json!(label));
            }
        }
    }
}

fn address_entry(address: &CoreContactAddress) -> Option<Value> {
    if address.is_blank() {
        return None;
    }
    let mut entry = entry_with(&address.extra);
    let street: Vec<String> = [&address.street1, &address.street2]
        .into_iter()
        .filter_map(present)
        .collect();
    if !street.is_empty() {
        entry.insert("street".into(), json!(street));
    }
    for (key, value) in [
        ("locality", &address.locality),
        ("region", &address.region),
        ("postCode", &address.postcode),
        ("country", &address.country),
    ] {
        if let Some(value) = present(value) {
            entry.insert(key.into(), json!(value));
        }
    }
    put_kind(&mut entry, address.kind, &address.label, false);
    put_period(&mut entry, &address.start, &address.end, address.current);
    Some(Value::Object(entry))
}

/// Every address the draft holds, numbered in order, plus each stored entry this
/// build cannot read, kept under its own id. A fresh entry's number skips the ids
/// those hold.
fn address_entries(
    previous: &Map<String, Value>,
    addresses: &[CoreContactAddress],
) -> Option<Value> {
    let mut map = Map::new();
    if let Some(stored) = previous.get("addresses").and_then(Value::as_object) {
        for (id, value) in stored {
            if value.as_object().and_then(address_of).is_none() {
                map.insert(id.clone(), value.clone());
            }
        }
    }
    let mut number = 0;
    for entry in addresses.iter().filter_map(address_entry) {
        let id = loop {
            number += 1;
            let id = format!("a{number}");
            if !map.contains_key(&id) {
                break id;
            }
        };
        map.insert(id, entry);
    }
    (!map.is_empty()).then_some(Value::Object(map))
}

/// Replaces the entry of `key` that a host shows, and carries every other.
///
/// `shown` says which stored entries the host's reader could pick up, and
/// `preferred` names the id it looks at first. The fresh entry takes the shown
/// one's id, or `default_id` when there is none. With no fresh entry the shown
/// one is removed and the rest stay, so the next read shows the next.
fn replace_shown(
    previous: &Map<String, Value>,
    key: &str,
    preferred: Option<&str>,
    shown: impl Fn(&Map<String, Value>) -> bool,
    fresh: Option<Value>,
    default_id: &str,
) -> Option<Value> {
    let mut map = Map::new();
    let mut shown_id = None;
    if let Some(stored) = previous.get(key).and_then(Value::as_object) {
        let filled = |value: &Value| value.as_object().is_some_and(&shown);
        shown_id = preferred
            .filter(|id| stored.get(*id).is_some_and(filled))
            .map(ToOwned::to_owned)
            .or_else(|| {
                ordered(stored)
                    .into_iter()
                    .find(|(_, value)| filled(value))
                    .map(|(id, _)| id.clone())
            });
        for (id, value) in stored {
            if Some(id) != shown_id.as_ref() {
                map.insert(id.clone(), value.clone());
            }
        }
    }
    if let Some(fresh) = fresh {
        map.insert(shown_id.unwrap_or_else(|| default_id.to_string()), fresh);
    }
    (!map.is_empty()).then_some(Value::Object(map))
}

fn work_entries(work: &[CoreContactWork]) -> (Option<Value>, Option<Value>) {
    let mut organizations = Map::new();
    let mut titles = Map::new();
    for row in work {
        let Some(organization) = present(&Some(row.organization.clone())) else {
            continue;
        };
        let org_id = format!("o{}", organizations.len() + 1);
        let mut org = entry_with(&row.extra);
        org.insert("name".into(), json!(organization));
        put_period(&mut org, &row.start, &row.end, row.current);
        if let Some(note) = present(&row.note) {
            org.insert(WORK_NOTE_PROP.into(), json!(note));
        }
        organizations.insert(org_id.clone(), Value::Object(org));
        if let Some(title) = present(&row.title) {
            titles.insert(
                format!("t{}", titles.len() + 1),
                json!({ "name": title, "kind": "title", "organization": org_id }),
            );
        }
    }
    (
        (!organizations.is_empty()).then_some(Value::Object(organizations)),
        (!titles.is_empty()).then_some(Value::Object(titles)),
    )
}

fn date_entries(dates: &[CoreContactDate]) -> Option<Value> {
    let mut out = Map::new();
    for date in dates {
        let Some(value) = present(&Some(date.date.clone())) else {
            continue;
        };
        let mut entry = entry_with(&date.extra);
        entry.insert("date".into(), json!(value));
        match date.kind {
            CoreContactDateKind::Birthday => entry.insert("kind".into(), json!("birth")),
            CoreContactDateKind::Anniversary => entry.insert("kind".into(), json!("wedding")),
            CoreContactDateKind::Custom => {
                if let Some(label) = present(&date.label) {
                    entry.insert("label".into(), json!(label));
                }
                entry.insert("kind".into(), json!("other"))
            }
        };
        out.insert(format!("a{}", out.len() + 1), Value::Object(entry));
    }
    (!out.is_empty()).then_some(Value::Object(out))
}

fn social_entries(socials: &[CoreContactSocial]) -> Option<Value> {
    let mut out = Map::new();
    for social in socials {
        let Some(handle) = present(&Some(social.handle.clone())) else {
            continue;
        };
        let service = present(&Some(social.platform.clone())).unwrap_or_else(|| "custom".into());
        let mut entry = entry_with(&social.extra);
        entry.insert("service".into(), json!(service));
        entry.insert("user".into(), json!(handle));
        out.insert(format!("os{}", out.len() + 1), Value::Object(entry));
    }
    (!out.is_empty()).then_some(Value::Object(out))
}

/// Serialises a card, merging onto whatever `draft.raw` carried.
///
/// `now` is the caller's clock, since core has none. It becomes `updated`, and
/// `created` for a card that has none.
pub fn contact_write(draft: &CoreContactDraft, now: &str) -> Result<String, CoreError> {
    refuse_newer_major(draft.raw.as_deref())?;
    let previous = draft.raw.as_deref().and_then(as_object).unwrap_or_default();

    let mut fields = Map::new();
    fields.insert("@type".into(), json!("Card"));
    fields.insert("version".into(), json!(PAYLOAD_SCHEMA_VERSION));
    fields.insert("name".into(), json!({ "full": draft.name.trim() }));
    fields.insert(
        ADDRESS_BOOK_ID_PROP.into(),
        json!(resolve_address_book_id(Some(draft.address_book_id.clone()))),
    );
    if draft.archived {
        fields.insert(CONTACT_ARCHIVED_PROP.into(), json!(true));
    }

    let mut put = |key: &str, value: Option<Value>| {
        if let Some(value) = value {
            fields.insert(key.into(), value);
        }
    };

    let nickname = present(&draft.nickname).map(|name| json!({ "name": name }));
    put(
        "nickNames",
        replace_shown(
            &previous,
            "nickNames",
            None,
            |entry| trimmed(entry, "name").is_some(),
            nickname,
            "n1",
        ),
    );
    put(
        "emails",
        channel_entries(&draft.emails, "e", "address", false),
    );
    put(
        "phones",
        channel_entries(&draft.phones, "p", "number", true),
    );
    put("addresses", address_entries(&previous, &draft.addresses));
    let (organizations, titles) = work_entries(&draft.work);
    put("organizations", organizations);
    put("titles", titles);

    // Beside `pronouns`, `speakToAs` can hold a greeting or a grammatical
    // gender another client wrote, which stay.
    let mut speak = previous
        .get("speakToAs")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    match present(&draft.pronouns) {
        Some(pronouns) => speak.insert("pronouns".into(), json!(pronouns)),
        None => speak.remove("pronouns"),
    };
    put(
        "speakToAs",
        (!speak.is_empty()).then_some(Value::Object(speak)),
    );

    put("anniversaries", date_entries(&draft.dates));
    put("onlineServices", social_entries(&draft.socials));
    put(
        "notes",
        replace_shown(
            &previous,
            "notes",
            None,
            |entry| trimmed(entry, "note").is_some(),
            present(&draft.notes).map(|note| json!({ "note": note })),
            "n1",
        ),
    );
    put(
        CONTACT_PROFILE_PROP,
        draft.profile.as_ref().and_then(profile_json),
    );
    if !draft.attachments.is_empty() {
        put(
            CONTACT_ATTACHMENTS_PROP,
            Some(Value::Array(
                draft.attachments.iter().map(attachment_json).collect(),
            )),
        );
    }
    put(
        "media",
        replace_shown(
            &previous,
            "media",
            Some("avatar"),
            |entry| avatar_of(entry).is_some(),
            present(&draft.avatar).map(|uri| json!({ "kind": "photo", "uri": uri })),
            "avatar",
        ),
    );
    fields.insert(
        "created".into(),
        json!(present(&draft.created_at).unwrap_or_else(|| now.to_string())),
    );
    fields.insert("updated".into(), json!(now));

    Ok(write_payload(
        draft.raw.as_deref(),
        Value::Object(fields),
        CONTACT_KEYS,
    ))
}

/// Reads a stored address book.
///
/// The default book's fallback is its own name, for the reason the default
/// notebook and calendar have theirs: it is what the client that created it
/// wrote, and anything else shows the one book every account has under a name
/// nobody chose.
pub fn address_book_parse(id: &str, raw: &str) -> CoreAddressBook {
    let object = as_object(raw);
    CoreAddressBook {
        id: id.to_string(),
        name: object
            .as_ref()
            .and_then(|object| trimmed(object, "name"))
            .unwrap_or_else(|| {
                if id == default_address_book_id() {
                    DEFAULT_ADDRESS_BOOK_NAME.to_string()
                } else {
                    UNTITLED_ADDRESS_BOOK_NAME.to_string()
                }
            }),
        archived: object
            .as_ref()
            .and_then(|object| object.get("archived"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        readable: object.as_ref().map(declared_readable).unwrap_or(true),
        raw: raw.to_string(),
    }
}

/// Serialises an address book, merging onto whatever `draft.raw` carried.
pub fn address_book_write(draft: &CoreAddressBookDraft) -> Result<String, CoreError> {
    refuse_newer_major(draft.raw.as_deref())?;
    let mut fields = Map::new();
    fields.insert("@type".into(), json!("AddressBook"));
    fields.insert("version".into(), json!(PAYLOAD_SCHEMA_VERSION));
    fields.insert("name".into(), json!(draft.name.trim()));
    if draft.archived {
        fields.insert("archived".into(), json!(true));
    }
    Ok(write_payload(
        draft.raw.as_deref(),
        Value::Object(fields),
        ADDRESS_BOOK_KEYS,
    ))
}

/// The name to show for a card's address book. A book that is gone, or a card in
/// none, shows the default book's name.
pub fn address_book_name_by_id(
    books: &[CoreAddressBook],
    address_book_id: Option<String>,
) -> String {
    let id = resolve_address_book_id(address_book_id);
    books
        .iter()
        .find(|book| book.id == id)
        .map(|book| book.name.clone())
        .unwrap_or_else(|| DEFAULT_ADDRESS_BOOK_NAME.to_string())
}

/// Everything above, in the shapes the bindings can carry.
#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{
        CoreAddressBook, CoreAddressBookDraft, CoreContact, CoreContactDraft, CoreContactProfile,
        CoreError,
    };

    fn names(keys: &[&str]) -> Vec<String> {
        keys.iter().map(|key| key.to_string()).collect()
    }

    #[uniffi::export(name = "contact_keys")]
    pub fn contact_keys() -> Vec<String> {
        names(super::CONTACT_KEYS)
    }

    #[uniffi::export(name = "address_book_keys")]
    pub fn address_book_keys() -> Vec<String> {
        names(super::ADDRESS_BOOK_KEYS)
    }

    #[uniffi::export(name = "contact_profile_keys")]
    pub fn contact_profile_keys() -> Vec<String> {
        names(super::PROFILE_KEYS)
    }

    #[uniffi::export(name = "default_address_book_id")]
    pub fn default_address_book_id() -> String {
        super::default_address_book_id()
    }

    #[uniffi::export(name = "resolve_address_book_id")]
    pub fn resolve_address_book_id(id: Option<String>) -> String {
        super::resolve_address_book_id(id)
    }

    #[uniffi::export(name = "contact_parse")]
    pub fn contact_parse(id: String, raw: String) -> CoreContact {
        super::contact_parse(&id, &raw)
    }

    #[uniffi::export(name = "contact_write")]
    pub fn contact_write(draft: CoreContactDraft, now: String) -> Result<String, CoreError> {
        super::contact_write(&draft, &now)
    }

    #[uniffi::export(name = "contact_profile_parse")]
    pub fn contact_profile_parse(raw: String) -> Option<CoreContactProfile> {
        crate::contact_profile::profile_parse(&raw)
    }

    #[uniffi::export(name = "contact_profile_write")]
    pub fn contact_profile_write(profile: CoreContactProfile) -> Option<String> {
        crate::contact_profile::profile_write(&profile)
    }

    #[uniffi::export(name = "address_book_parse")]
    pub fn address_book_parse(id: String, raw: String) -> CoreAddressBook {
        super::address_book_parse(&id, &raw)
    }

    #[uniffi::export(name = "address_book_write")]
    pub fn address_book_write(draft: CoreAddressBookDraft) -> Result<String, CoreError> {
        super::address_book_write(&draft)
    }

    #[uniffi::export(name = "address_book_name_by_id")]
    pub fn address_book_name_by_id(
        books: Vec<CoreAddressBook>,
        address_book_id: Option<String>,
    ) -> String {
        super::address_book_name_by_id(&books, address_book_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: &str = "2026-10-28T12:00:00.000Z";

    fn parsed(payload: &str) -> Map<String, Value> {
        as_object(payload).expect("object")
    }

    fn draft_of(raw: &str) -> CoreContactDraft {
        contact_parse("c", raw).draft()
    }

    #[test]
    fn every_address_reads_and_an_edit_to_one_keeps_the_others() {
        let raw = r#"{"@type":"Card","name":{"full":"Ada"},"addresses":{"a1":{"locality":"London"},"a2":{"locality":"Paris","contexts":{"work":true}}}}"#;
        let mut draft = draft_of(raw);
        assert_eq!(draft.addresses.len(), 2);
        assert_eq!(draft.addresses[1].kind, CoreChannelKind::Work);
        draft.addresses[0].locality = Some("Leeds".into());
        let written = parsed(&contact_write(&draft, NOW).unwrap());
        assert_eq!(written["addresses"]["a1"]["locality"], "Leeds");
        assert_eq!(written["addresses"]["a2"]["locality"], "Paris");
        assert_eq!(written["addresses"]["a2"]["contexts"]["work"], true);
    }

    #[test]
    fn removing_an_address_removes_only_that_one() {
        let raw = r#"{"addresses":{"a1":{"locality":"London"},"a2":{"locality":"Paris"}}}"#;
        let mut draft = draft_of(raw);
        draft.addresses.remove(0);
        let written = contact_write(&draft, NOW).unwrap();
        let again = contact_parse("c", &written);
        assert_eq!(again.addresses.len(), 1);
        assert_eq!(again.addresses[0].locality.as_deref(), Some("Paris"));
    }

    #[test]
    fn an_address_this_build_cannot_read_is_carried_and_not_overwritten() {
        let raw = r#"{"addresses":{"a1":{"components":[{"kind":"locality","value":"Oslo"}]},"a2":{"locality":"Paris","coordinates":"geo:1,2"}}}"#;
        let mut draft = draft_of(raw);
        assert_eq!(draft.addresses.len(), 1);
        draft.addresses.push(CoreContactAddress {
            kind: CoreChannelKind::Custom,
            label: Some("Cabin".into()),
            locality: Some("Bergen".into()),
            ..Default::default()
        });
        let written = parsed(&contact_write(&draft, NOW).unwrap());
        assert_eq!(written["addresses"]["a1"]["components"][0]["value"], "Oslo");
        assert_eq!(written["addresses"]["a2"]["locality"], "Paris");
        assert_eq!(written["addresses"]["a2"]["coordinates"], "geo:1,2");
        assert_eq!(written["addresses"]["a3"]["locality"], "Bergen");
        assert_eq!(written["addresses"]["a3"]["label"], "Cabin");
    }

    #[test]
    fn entries_read_in_the_order_of_their_number_not_their_key() {
        let mut emails = Map::new();
        for n in 1..=11 {
            emails.insert(format!("e{n}"), json!({ "address": format!("{n}@x.test") }));
        }
        let raw = json!({ "emails": emails }).to_string();
        let card = contact_parse("c", &raw);
        let values: Vec<_> = card
            .emails
            .iter()
            .map(|email| email.value.clone())
            .collect();
        assert_eq!(values[1], "2@x.test");
        assert_eq!(values[10], "11@x.test");
    }

    #[test]
    fn a_nameless_card_is_not_named_by_being_saved() {
        let raw = r#"{"@type":"Card","emails":{"e1":{"address":"ada.lovelace@example.com"}}}"#;
        let card = contact_parse("c", raw);
        assert_eq!(card.name, "");
        assert_eq!(card.display_name, "ada lovelace");
        let written = parsed(&contact_write(&draft_of(raw), NOW).unwrap());
        assert_eq!(written["name"]["full"], "");
    }

    #[test]
    fn a_malformed_entry_does_not_take_the_card_down() {
        let raw =
            r#"{"emails":{"e1":"ada@example.com","e2":{"address":"ok@example.com"}},"phones":[1]}"#;
        let card = contact_parse("c", raw);
        assert_eq!(card.emails.len(), 1);
        assert!(card.phones.is_empty());
    }

    #[test]
    fn a_photo_an_importer_wrote_can_be_removed() {
        let raw = r#"{"photo":{"href":"data:image/png;base64,AAAA"}}"#;
        let mut draft = draft_of(raw);
        assert!(draft.avatar.is_some());
        draft.avatar = None;
        let again = contact_parse("c", &contact_write(&draft, NOW).unwrap());
        assert!(again.avatar.is_none());
    }

    #[test]
    fn an_edit_keeps_a_key_from_a_later_build_and_the_pronoun_neighbours() {
        let raw =
            r#"{"@type":"Card","name":{"full":"Ada"},"speakToAs":{"greeting":"Dear"},"ranking":9}"#;
        let mut draft = draft_of(raw);
        draft.pronouns = Some("she/her".into());
        let written = parsed(&contact_write(&draft, NOW).unwrap());
        assert_eq!(written["ranking"], 9);
        assert_eq!(written["speakToAs"]["greeting"], "Dear");
        assert_eq!(written["speakToAs"]["pronouns"], "she/her");
    }

    #[test]
    fn a_card_from_a_newer_schema_major_is_read_but_never_written_over() {
        let raw = r#"{"@type":"Card","version":"2.0","name":{"full":"Ada"}}"#;
        let card = contact_parse("c", raw);
        assert!(!card.readable);
        assert_eq!(card.name, "Ada");
        assert!(contact_write(&draft_of(raw), NOW).is_err());
    }

    #[test]
    fn an_unmarked_number_reads_as_a_mobile_and_an_unmarked_email_as_a_home() {
        let raw = r#"{"emails":{"e1":{"address":"a@x.test"}},"phones":{"p1":{"number":"1"}}}"#;
        let card = contact_parse("c", raw);
        assert_eq!(card.emails[0].kind, CoreChannelKind::Home);
        assert_eq!(card.phones[0].kind, CoreChannelKind::Mobile);
    }

    #[test]
    fn the_address_book_fallbacks_are_the_default_name_and_the_untitled_one() {
        let default = address_book_parse(&default_address_book_id(), "{}");
        assert_eq!(default.name, DEFAULT_ADDRESS_BOOK_NAME);
        let other = address_book_parse("b", "not json");
        assert_eq!(other.name, UNTITLED_ADDRESS_BOOK_NAME);
    }
}
