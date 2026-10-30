//! CSV import and export of contacts.
//!
//! The columns written are the ones both clients always wrote, so a file from
//! either restores in the other. The plain columns hold what other address-book
//! programs understand; the trailing `(JSON)` columns carry the whole lists, which
//! is what makes a Sealbook round trip lossless.

use serde_json::{json, Map, Value};

use crate::contact_profile::{profile_parse, profile_write};
use crate::contacts::{
    address_book_name_by_id, resolve_address_book_id, CoreAddressBook, CoreChannelKind,
    CoreContactAddress, CoreContactChannel, CoreContactDate, CoreContactDateKind, CoreContactDraft,
    CoreContactSocial, CoreContactWork,
};
use crate::vcard::{trim, CoreContactImport, CoreContactSkipped, NO_NAME};

const HEADERS: &[&str] = &[
    "Name",
    "Nickname",
    "Pronouns",
    "Avatar",
    "Email (Home)",
    "Email (Work)",
    "Phone (Mobile)",
    "Phone (Home)",
    "Phone (Work)",
    "Birthday",
    "Anniversary",
    "Socials",
    "Organization",
    "Job Title",
    "Street 1",
    "Street 2",
    "City",
    "Region",
    "Postal Code",
    "Country",
    "Notes",
    "Address Book",
    "Address Book ID",
    "Emails (JSON)",
    "Phones (JSON)",
    "Dates (JSON)",
    "Socials (JSON)",
    "Work (JSON)",
    "Address (JSON)",
    "Profile (JSON)",
    "Created At",
    "Updated At",
];

/// Characters a spreadsheet reads as the start of a formula.
const FORMULA: &[char] = &['=', '+', '-', '@', '\t', '\r'];

/// RFC 4180 rows: commas inside quotes, doubled quotes and multiline cells. A
/// row with no text in it is dropped.
pub fn csv_rows(text: &str) -> Vec<Vec<String>> {
    let chars: Vec<char> = text.chars().collect();
    let mut rows = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut cell = String::new();
    let mut quoted = false;
    let mut i = 0;

    fn end_row(row: &mut Vec<String>, cell: &mut String, rows: &mut Vec<Vec<String>>) {
        row.push(trim(cell).to_string());
        cell.clear();
        if row.iter().any(|c| !c.is_empty()) {
            rows.push(std::mem::take(row));
        } else {
            row.clear();
        }
    }

    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if quoted {
            if c == '"' && next == Some('"') {
                cell.push('"');
                i += 2;
                continue;
            }
            if c == '"' {
                quoted = false;
            } else {
                cell.push(c);
            }
            i += 1;
        } else if c == '"' {
            quoted = true;
            i += 1;
        } else if c == ',' {
            row.push(trim(&cell).to_string());
            cell.clear();
            i += 1;
        } else if c == '\r' || c == '\n' {
            end_row(&mut row, &mut cell, &mut rows);
            i += if c == '\r' && next == Some('\n') {
                2
            } else {
                1
            };
        } else {
            cell.push(c);
            i += 1;
        }
    }
    if !cell.is_empty() || !row.is_empty() {
        end_row(&mut row, &mut cell, &mut rows);
    }
    rows
}

fn normalize_header(header: &str) -> String {
    header
        .to_lowercase()
        .split(|c: char| c.is_whitespace() || c == '_' || c == '-')
        .collect()
}

/// Undoes the formula guard `cell` adds, leaving any other apostrophe alone.
fn unguard(value: &str) -> &str {
    let mut chars = value.chars();
    match (chars.next(), chars.next()) {
        (Some('\''), Some(c)) if FORMULA.contains(&c) => &value[1..],
        _ => value,
    }
}

struct Row<'a> {
    headers: &'a [String],
    cells: &'a [String],
}

impl Row<'_> {
    /// The first pattern with a value. A header equal to the pattern wins over one
    /// that merely contains it, which is what lets exports from other address books
    /// ("E-mail 1 - Value") come in too. A pattern starting `=` matches exactly
    /// only: `name` would otherwise find "First Name", and `address` "E-mail Address".
    /// The `(JSON)` columns are only found by a pattern that names them.
    fn get(&self, patterns: &[&str]) -> Option<String> {
        for pattern in patterns {
            let (exact_only, pattern) = match pattern.strip_prefix('=') {
                Some(rest) => (true, rest),
                None => (false, *pattern),
            };
            let clean = normalize_header(pattern);
            let json = clean.ends_with("(json)");
            let index = self.headers.iter().position(|h| *h == clean).or_else(|| {
                if exact_only {
                    None
                } else {
                    self.headers
                        .iter()
                        .position(|h| (json || !h.ends_with("(json)")) && h.contains(&clean))
                }
            });
            if let Some(value) = index.and_then(|i| self.cells.get(i)) {
                let value = trim(value);
                if !value.is_empty() {
                    return Some(unguard(value).to_string());
                }
            }
        }
        None
    }
}

fn channel(kind: CoreChannelKind, value: String) -> CoreContactChannel {
    CoreContactChannel {
        kind,
        label: None,
        value,
        extra: None,
    }
}

/// The contacts in a CSV file, as drafts for `address_book_id` unless a row names
/// its own book.
pub fn csv_parse(text: &str, address_book_id: &str) -> Vec<CoreContactDraft> {
    csv_import(text, address_book_id).contacts
}

/// The contacts in a CSV file, and the rows that could not be used.
pub fn csv_import(text: &str, address_book_id: &str) -> CoreContactImport {
    let rows = csv_rows(text);
    let mut contacts = Vec::new();
    let mut skipped = Vec::new();
    if rows.len() >= 2 {
        let headers: Vec<String> = rows[0].iter().map(|h| normalize_header(h)).collect();
        for (index, cells) in rows.iter().enumerate().skip(1) {
            if cells.iter().all(|c| trim(c).is_empty()) {
                continue;
            }
            let row = Row {
                headers: &headers,
                cells,
            };
            match read(&row, address_book_id) {
                Some(contact) => contacts.push(contact),
                None => skipped.push(CoreContactSkipped {
                    label: format!("Row {}", index + 1),
                    reason: NO_NAME.to_string(),
                }),
            }
        }
    }
    CoreContactImport { contacts, skipped }
}

fn read(row: &Row, default_book: &str) -> Option<CoreContactDraft> {
    let first = row.get(&["first name", "given name", "=first"]);
    let last = row.get(&["last name", "family name", "surname", "=last"]);
    let mut name = row.get(&["=name", "full name", "display name", "contact name"]);
    if name.is_none() {
        let joined = [first, last]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" ");
        name = (!trim(&joined).is_empty()).then(|| trim(&joined).to_string());
    }

    let mut emails: Vec<CoreContactChannel> = Vec::new();
    let mut add_email = |kind: CoreChannelKind, value: Option<String>| {
        if let Some(value) = value {
            if !emails
                .iter()
                .any(|e| e.value.to_lowercase() == value.to_lowercase())
            {
                emails.push(channel(kind, value));
            }
        }
    };
    add_email(
        CoreChannelKind::Home,
        row.get(&[
            "email (home)",
            "email 1 (home)",
            "home email",
            "email 1 - value",
            "email 1",
            "email",
        ]),
    );
    add_email(
        CoreChannelKind::Work,
        row.get(&[
            "email (work)",
            "email 2 (work)",
            "work email",
            "email 2 - value",
            "email 2",
            "business email",
        ]),
    );
    // Any other column about email.
    for (index, header) in row.headers.iter().enumerate() {
        if header.contains("email") && !header.ends_with("(json)") {
            let value = row.cells.get(index).map(|c| unguard(trim(c)).to_string());
            add_email(CoreChannelKind::Home, value.filter(|v| !v.is_empty()));
        }
    }

    let mut phones: Vec<CoreContactChannel> = Vec::new();
    let mut add_phone = |kind: CoreChannelKind, value: Option<String>| {
        if let Some(value) = value {
            if !phones.iter().any(|p| p.value == value) {
                phones.push(channel(kind, value));
            }
        }
    };
    add_phone(
        CoreChannelKind::Mobile,
        row.get(&[
            "phone (mobile)",
            "phone 1 (mobile)",
            "mobile phone",
            "cell phone",
            "phone 1 - value",
            "phone 1",
            "mobile",
            "phone",
        ]),
    );
    add_phone(
        CoreChannelKind::Home,
        row.get(&[
            "phone (home)",
            "phone 2 (home)",
            "home phone",
            "phone 2 - value",
            "phone 2",
        ]),
    );
    add_phone(
        CoreChannelKind::Work,
        row.get(&[
            "phone (work)",
            "phone 3 (work)",
            "work phone",
            "business phone",
            "phone 3 - value",
            "phone 3",
        ]),
    );

    let organization = row.get(&[
        "organization",
        "company",
        "company name",
        "organization 1 - name",
    ]);
    let title = row.get(&[
        "job title",
        "title",
        "role",
        "position",
        "organization 1 - title",
    ]);
    let mut work = if organization.is_some() || title.is_some() {
        vec![CoreContactWork {
            organization: organization.unwrap_or_default(),
            title,
            extra: None,
        }]
    } else {
        Vec::new()
    };

    let mut address = Some(CoreContactAddress {
        street1: row.get(&[
            "street 1",
            "address street",
            "street",
            "=address",
            "home street",
            "address 1 - street",
        ]),
        street2: row.get(&["street 2", "address line 2", "apartment", "suite"]),
        locality: row.get(&[
            "city",
            "address city",
            "locality",
            "home city",
            "address 1 - city",
        ]),
        region: row.get(&[
            "region",
            "address state",
            "state",
            "province",
            "home state",
            "address 1 - region",
        ]),
        postcode: row.get(&[
            "postal code",
            "address postcode",
            "postcode",
            "zip",
            "zip code",
            "home postal code",
            "address 1 - postal code",
        ]),
        country: row.get(&[
            "country",
            "address country",
            "home country",
            "address 1 - country",
        ]),
    })
    .filter(|a| {
        a.street1.is_some()
            || a.street2.is_some()
            || a.locality.is_some()
            || a.region.is_some()
            || a.postcode.is_some()
            || a.country.is_some()
    });

    let mut dates = Vec::new();
    if let Some(date) = row.get(&[
        "birthday",
        "birth date",
        "birthdate",
        "date of birth",
        "bday",
        "dob",
    ]) {
        dates.push(date_row(CoreContactDateKind::Birthday, None, date));
    }
    if let Some(date) = row.get(&["anniversary", "anniversary date", "wedding"]) {
        dates.push(date_row(CoreContactDateKind::Anniversary, None, date));
    }

    let mut socials: Vec<CoreContactSocial> = Vec::new();
    for platform in [
        "github",
        "twitter",
        "linkedin",
        "instagram",
        "bluesky",
        "discord",
        "telegram",
        "mastodon",
    ] {
        if let Some(handle) = row.get(&[&format!("social {platform}"), platform]) {
            let mut label = platform.to_string();
            label[..1].make_ascii_uppercase();
            socials.push(social(label, handle));
        }
    }
    if let Some(handle) = row.get(&["social x/twitter", "=x"]) {
        if !socials.iter().any(|s| s.handle == handle) {
            socials.push(social("Twitter / X".into(), handle));
        }
    }
    // The combined column: "Platform:handle; ...".
    if let Some(combined) = row.get(&["socials", "social", "social media"]) {
        for piece in combined.split([';', ',']) {
            let piece = trim(piece);
            if piece.is_empty() {
                continue;
            }
            let found = match piece.find(':').filter(|colon| *colon > 0) {
                Some(colon) => social(
                    trim(&piece[..colon]).to_string(),
                    trim(&piece[colon + 1..]).to_string(),
                ),
                None => social("Social".into(), piece.to_string()),
            };
            if !found.handle.is_empty() && !socials.iter().any(|s| s.handle == found.handle) {
                socials.push(found);
            }
        }
    }

    if name.is_none() {
        name = emails
            .first()
            .map(|e| e.value.split('@').next().unwrap_or("").to_string());
    }
    if name.is_none() {
        name = phones.first().map(|p| p.value.clone());
    }
    let name = name.filter(|n| !n.is_empty())?;

    // The JSON columns, when present, carry the complete lists rather than the
    // one-per-kind summary above.
    if let Some(rows) = row
        .get(&["emails (json)"])
        .and_then(|raw| entries(&raw, channel_of))
    {
        emails = rows;
    }
    if let Some(rows) = row
        .get(&["phones (json)"])
        .and_then(|raw| entries(&raw, channel_of))
    {
        phones = rows;
    }
    if let Some(rows) = row
        .get(&["dates (json)"])
        .and_then(|raw| entries(&raw, date_of))
    {
        dates = rows;
    }
    if let Some(rows) = row
        .get(&["socials (json)"])
        .and_then(|raw| entries(&raw, social_of))
    {
        socials = rows;
    }
    if let Some(rows) = row
        .get(&["work (json)"])
        .and_then(|raw| entries(&raw, work_of))
    {
        work = rows;
    }
    if let Some(raw) = row.get(&["address (json)"]) {
        if raw == "null" {
            address = None;
        } else if let Some(parsed) = address_of(&raw) {
            address = Some(parsed);
        }
    }
    let profile = row
        .get(&["profile (json)"])
        .and_then(|raw| profile_parse(&raw));

    let book = row
        .get(&["address book id"])
        .unwrap_or_else(|| default_book.to_string());
    Some(CoreContactDraft {
        name,
        nickname: row.get(&["nickname", "nick name"]),
        pronouns: row.get(&["pronouns", "pronoun", "x-pronouns"]),
        emails,
        phones,
        address,
        work,
        dates,
        socials,
        notes: row.get(&[
            "notes",
            "note",
            "memo",
            "comments",
            "comment",
            "description",
        ]),
        avatar: row.get(&["avatar", "photo"]),
        profile,
        address_book_id: resolve_address_book_id(Some(book)),
        created_at: row.get(&["created at"]),
        ..CoreContactDraft::default()
    })
}

fn date_row(kind: CoreContactDateKind, label: Option<String>, date: String) -> CoreContactDate {
    CoreContactDate {
        kind,
        label,
        date,
        extra: None,
    }
}

fn social(platform: String, handle: String) -> CoreContactSocial {
    CoreContactSocial {
        platform,
        handle,
        extra: None,
    }
}

fn text(entry: &Map<String, Value>, key: &str) -> Option<String> {
    entry
        .get(key)
        .and_then(Value::as_str)
        .map(|v| trim(v).to_string())
        .filter(|v| !v.is_empty())
}

/// The usable entries of a JSON array column, or `None` when the column is not an
/// array or holds nothing usable, so the plain columns stand.
fn entries<T>(raw: &str, read: fn(&Map<String, Value>) -> Option<T>) -> Option<Vec<T>> {
    let rows: Vec<T> = serde_json::from_str::<Value>(raw)
        .ok()?
        .as_array()?
        .iter()
        .filter_map(Value::as_object)
        .filter_map(read)
        .collect();
    (!rows.is_empty()).then_some(rows)
}

fn channel_of(entry: &Map<String, Value>) -> Option<CoreContactChannel> {
    let value = text(entry, "value")?;
    let kind = match text(entry, "kind")
        .unwrap_or_default()
        .to_lowercase()
        .as_str()
    {
        "work" => CoreChannelKind::Work,
        "mobile" => CoreChannelKind::Mobile,
        "custom" => CoreChannelKind::Custom,
        _ => CoreChannelKind::Home,
    };
    Some(CoreContactChannel {
        kind,
        label: text(entry, "label"),
        value,
        extra: None,
    })
}

fn date_of(entry: &Map<String, Value>) -> Option<CoreContactDate> {
    let date = text(entry, "date")?;
    let kind = match text(entry, "kind")
        .unwrap_or_else(|| "birthday".into())
        .to_lowercase()
        .as_str()
    {
        "birthday" | "birth" => CoreContactDateKind::Birthday,
        "anniversary" | "wedding" => CoreContactDateKind::Anniversary,
        _ => CoreContactDateKind::Custom,
    };
    Some(date_row(kind, text(entry, "label"), date))
}

fn social_of(entry: &Map<String, Value>) -> Option<CoreContactSocial> {
    let handle = text(entry, "handle")?;
    Some(social(
        text(entry, "platform").unwrap_or_else(|| "custom".into()),
        handle,
    ))
}

fn work_of(entry: &Map<String, Value>) -> Option<CoreContactWork> {
    let organization = text(entry, "organization");
    let title = text(entry, "title");
    if organization.is_none() && title.is_none() {
        return None;
    }
    Some(CoreContactWork {
        organization: organization.unwrap_or_default(),
        title,
        extra: None,
    })
}

fn address_of(raw: &str) -> Option<CoreContactAddress> {
    let value: Value = serde_json::from_str(raw).ok()?;
    let entry = value.as_object()?;
    let address = CoreContactAddress {
        street1: text(entry, "street1"),
        street2: text(entry, "street2"),
        locality: text(entry, "locality"),
        region: text(entry, "region"),
        postcode: text(entry, "postcode"),
        country: text(entry, "country"),
    };
    let empty = address.street1.is_none()
        && address.street2.is_none()
        && address.locality.is_none()
        && address.region.is_none()
        && address.postcode.is_none()
        && address.country.is_none();
    (!empty).then_some(address)
}

/// Quotes a cell, and defuses one a spreadsheet would execute as a formula: Excel
/// and Sheets run a cell opening with `=`, `+`, `-` or `@`, so exported contact
/// data could run in whoever opens it. A leading apostrophe marks it as text.
fn cell(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let guarded = if value.starts_with(FORMULA) {
        format!("'{value}")
    } else {
        value.to_string()
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

fn opt(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("")
}

fn first_of(channels: &[CoreContactChannel], kind: CoreChannelKind) -> &str {
    channels
        .iter()
        .find(|c| c.kind == kind)
        .map(|c| c.value.as_str())
        .unwrap_or("")
}

fn kind_name(kind: CoreChannelKind) -> &'static str {
    match kind {
        CoreChannelKind::Work => "work",
        CoreChannelKind::Home => "home",
        CoreChannelKind::Mobile => "mobile",
        CoreChannelKind::Custom => "custom",
    }
}

fn put(entry: &mut Map<String, Value>, key: &str, value: &Option<String>) {
    if let Some(value) = value.as_deref().filter(|v| !v.trim().is_empty()) {
        entry.insert(key.into(), json!(value));
    }
}

fn channels_json(channels: &[CoreContactChannel]) -> String {
    Value::Array(
        channels
            .iter()
            .map(|c| {
                let mut entry = Map::new();
                entry.insert("kind".into(), json!(kind_name(c.kind)));
                entry.insert("value".into(), json!(c.value));
                put(&mut entry, "label", &c.label);
                Value::Object(entry)
            })
            .collect(),
    )
    .to_string()
}

fn dates_json(dates: &[CoreContactDate]) -> String {
    Value::Array(
        dates
            .iter()
            .map(|d| {
                let mut entry = Map::new();
                let kind = match d.kind {
                    CoreContactDateKind::Birthday => "birthday",
                    CoreContactDateKind::Anniversary => "anniversary",
                    CoreContactDateKind::Custom => "custom",
                };
                entry.insert("kind".into(), json!(kind));
                entry.insert("date".into(), json!(d.date));
                put(&mut entry, "label", &d.label);
                Value::Object(entry)
            })
            .collect(),
    )
    .to_string()
}

fn work_json(work: &[CoreContactWork]) -> String {
    Value::Array(
        work.iter()
            .map(|w| {
                let mut entry = Map::new();
                entry.insert("organization".into(), json!(w.organization));
                put(&mut entry, "title", &w.title);
                Value::Object(entry)
            })
            .collect(),
    )
    .to_string()
}

fn address_json(address: &Option<CoreContactAddress>) -> String {
    let Some(a) = address else {
        return "null".to_string();
    };
    let mut entry = Map::new();
    put(&mut entry, "street1", &a.street1);
    put(&mut entry, "street2", &a.street2);
    put(&mut entry, "locality", &a.locality);
    put(&mut entry, "region", &a.region);
    put(&mut entry, "postcode", &a.postcode);
    put(&mut entry, "country", &a.country);
    Value::Object(entry).to_string()
}

/// A CSV file holding `contacts`, with each row's book named from `books`. The
/// `Updated At` column is written empty: a draft carries no updated time.
pub fn csv_write(contacts: &[CoreContactDraft], books: &[CoreAddressBook]) -> String {
    let mut rows = vec![HEADERS.join(",")];
    for c in contacts {
        let date = |kind: CoreContactDateKind| {
            c.dates
                .iter()
                .find(|d| d.kind == kind)
                .map(|d| d.date.as_str())
                .unwrap_or("")
        };
        let socials = c
            .socials
            .iter()
            .map(|s| format!("{}:{}", s.platform, s.handle))
            .collect::<Vec<_>>()
            .join("; ");
        let socials_json = Value::Array(
            c.socials
                .iter()
                .map(|s| json!({"platform": s.platform, "handle": s.handle}))
                .collect(),
        )
        .to_string();
        let work = c.work.first();
        let address = c.address.clone().unwrap_or_default();
        let profile = c
            .profile
            .as_ref()
            .and_then(profile_write)
            .unwrap_or_default();
        let book = address_book_name_by_id(books, Some(c.address_book_id.clone()));

        let values = [
            c.name.as_str(),
            opt(&c.nickname),
            opt(&c.pronouns),
            opt(&c.avatar),
            first_of(&c.emails, CoreChannelKind::Home),
            first_of(&c.emails, CoreChannelKind::Work),
            first_of(&c.phones, CoreChannelKind::Mobile),
            first_of(&c.phones, CoreChannelKind::Home),
            first_of(&c.phones, CoreChannelKind::Work),
            date(CoreContactDateKind::Birthday),
            date(CoreContactDateKind::Anniversary),
            &socials,
            work.map(|w| w.organization.as_str()).unwrap_or(""),
            work.map(|w| opt(&w.title)).unwrap_or(""),
            opt(&address.street1),
            opt(&address.street2),
            opt(&address.locality),
            opt(&address.region),
            opt(&address.postcode),
            opt(&address.country),
            opt(&c.notes),
            &book,
            &c.address_book_id,
            &channels_json(&c.emails),
            &channels_json(&c.phones),
            &dates_json(&c.dates),
            &socials_json,
            &work_json(&c.work),
            &address_json(&c.address),
            &profile,
            opt(&c.created_at),
            "",
        ];
        rows.push(values.iter().map(|v| cell(v)).collect::<Vec<_>>().join(","));
    }
    rows.join("\r\n")
}

/// Everything above, in the shapes the bindings can carry.
#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::CoreContactImport;
    use crate::contacts::{CoreAddressBook, CoreContactDraft};

    #[uniffi::export(name = "csv_import")]
    pub fn csv_import(text: String, address_book_id: String) -> CoreContactImport {
        super::csv_import(&text, &address_book_id)
    }

    #[uniffi::export(name = "csv_write")]
    pub fn csv_write(contacts: Vec<CoreContactDraft>, books: Vec<CoreAddressBook>) -> String {
        super::csv_write(&contacts, &books)
    }
}
