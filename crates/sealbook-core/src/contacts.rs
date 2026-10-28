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
//! address, one nickname, one note and one photo, and both hosts wrote the whole
//! property back from that one, so a card imported from another app with two
//! addresses lost the second on the first edit. The writer now replaces the entry
//! the host sees and carries every other. Clearing the visible one removes only
//! that one, which is what a list does.
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
use crate::payload::{as_object, declared_readable, refuse_newer_major, trimmed, write_payload};
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
pub const ADDRESS_BOOK_KEYS: &[&str] = &["@type", "version", "name"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum CoreChannelKind {
    Work,
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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreContactAddress {
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
}

/// One workplace and, when there is one, the title held there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreContactWork {
    pub organization: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<CoreContactAddress>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<CoreContactAddress>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreAddressBook {
    pub id: String,
    pub name: String,
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
            address: self.address.clone(),
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

/// The entry's keys outside `known`, as a JSON object, or `None` when there are none.
fn extra_of(entry: &Map<String, Value>, known: &[&str]) -> Option<String> {
    let extra: Map<String, Value> = entry
        .iter()
        .filter(|(key, _)| !known.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    (!extra.is_empty()).then(|| Value::Object(extra).to_string())
}

/// A new entry seeded with the keys `extra` carried, for the writer to set its own over.
fn entry_with(extra: &Option<String>) -> Map<String, Value> {
    extra.as_deref().and_then(as_object).unwrap_or_default()
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

fn parse_address(card: &Map<String, Value>) -> Option<CoreContactAddress> {
    objects(card, "addresses")
        .into_iter()
        .find_map(|(_, entry)| address_of(entry))
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
    let address = CoreContactAddress {
        street1: line(0),
        street2: line(1),
        locality: trimmed(entry, "locality"),
        region: trimmed(entry, "region"),
        postcode: first_of(entry, &["postCode", "postcode"]),
        country: trimmed(entry, "country"),
    };
    (address != CoreContactAddress::default()).then_some(address)
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
        if linked.is_empty() {
            work.push(CoreContactWork {
                organization: organization.clone(),
                title: None,
                extra: extra_of(org, &["name"]),
            });
        }
        for title in linked {
            work.push(CoreContactWork {
                organization: organization.clone(),
                title: Some(title),
                extra: extra_of(org, &["name"]),
            });
        }
    }
    work
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
    let work = parse_work(&card);
    let name = parse_name(&card, &work);
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
        address: parse_address(&card),
        work,
        dates: parse_dates(&card),
        socials: parse_socials(&card),
        notes: parse_notes(&card),
        avatar: parse_avatar(&card),
        profile: parse_profile(card.get(CONTACT_PROFILE_PROP)),
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
        match channel.kind {
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
                if let Some(label) = present(&channel.label) {
                    entry.insert("label".into(), json!(label));
                }
            }
        }
        out.insert(format!("{prefix}{index}"), Value::Object(entry));
    }
    (!out.is_empty()).then_some(Value::Object(out))
}

fn address_entry(address: &CoreContactAddress) -> Option<Value> {
    let mut entry = Map::new();
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
    (!entry.is_empty()).then_some(Value::Object(entry))
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
    put(
        "addresses",
        replace_shown(
            &previous,
            "addresses",
            None,
            |entry| address_of(entry).is_some(),
            draft.address.as_ref().and_then(address_entry),
            "a1",
        ),
    );
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
        readable: object.as_ref().map(declared_readable).unwrap_or(true),
        raw: raw.to_string(),
    }
}

/// Serialises an address book, merging onto whatever `draft.raw` carried.
pub fn address_book_write(draft: &CoreAddressBookDraft) -> Result<String, CoreError> {
    refuse_newer_major(draft.raw.as_deref())?;
    Ok(write_payload(
        draft.raw.as_deref(),
        json!({
            "@type": "AddressBook",
            "version": PAYLOAD_SCHEMA_VERSION,
            "name": draft.name.trim(),
        }),
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
    fn a_second_address_survives_an_edit_to_the_first() {
        let raw = r#"{"@type":"Card","name":{"full":"Ada"},"addresses":{"a1":{"locality":"London"},"a2":{"locality":"Paris"}}}"#;
        let mut draft = draft_of(raw);
        draft.address.as_mut().unwrap().locality = Some("Leeds".into());
        let written = parsed(&contact_write(&draft, NOW).unwrap());
        assert_eq!(written["addresses"]["a1"]["locality"], "Leeds");
        assert_eq!(written["addresses"]["a2"]["locality"], "Paris");
    }

    #[test]
    fn clearing_the_shown_address_leaves_the_next_to_be_shown() {
        let raw = r#"{"addresses":{"a1":{"locality":"London"},"a2":{"locality":"Paris"}}}"#;
        let mut draft = draft_of(raw);
        draft.address = None;
        let written = contact_write(&draft, NOW).unwrap();
        let again = contact_parse("c", &written);
        assert_eq!(again.address.unwrap().locality.as_deref(), Some("Paris"));
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
