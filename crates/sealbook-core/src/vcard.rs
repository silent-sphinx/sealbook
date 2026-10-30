//! vCard import and export.
//!
//! One reader and one writer for every client, so a file imports to the same
//! cards and a card exports to the same lines wherever it is done. The reader is
//! lenient: a line it does not know is skipped, a card with no usable name is
//! dropped, and a damaged profile line loses the profile and not the card.

use crate::contact_profile::{profile_parse, profile_write};
use crate::contacts::{
    resolve_address_book_id, CoreChannelKind, CoreContactAddress, CoreContactChannel,
    CoreContactDate, CoreContactDateKind, CoreContactDraft, CoreContactSocial, CoreContactWork,
};

struct Prop {
    name: String,
    /// In the order first seen; a repeated key keeps its place and takes the later value.
    params: Vec<(String, String)>,
    value: String,
}

impl Prop {
    /// A parameter's value, where it has one that is not empty.
    fn param(&self, key: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
            .filter(|value| !value.is_empty())
    }
}

/// What a script engine's `trim` removes: Unicode space, plus the byte order mark.
pub(crate) fn trim(text: &str) -> &str {
    text.trim_matches(|c: char| (c.is_whitespace() && c != '\u{85}') || c == '\u{feff}')
}

pub(crate) fn unescape(value: &str) -> String {
    let value = value.replace("\\n", "\n").replace("\\N", "\n");
    let value = value
        .replace("\\,", ",")
        .replace("\\;", ";")
        .replace("\\\\", "\\");
    trim(&value).to_string()
}

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace(';', "\\;")
        .replace(',', "\\,")
        .replace("\r\n", "\\n")
        .replace('\n', "\\n")
}

fn normalize_date(raw: &str) -> String {
    let clean = trim(raw);
    if clean.len() == 8 && clean.bytes().all(|b| b.is_ascii_digit()) {
        return format!("{}-{}-{}", &clean[..4], &clean[4..6], &clean[6..]);
    }
    clean.to_string()
}

fn parse_line(raw: &str) -> Option<Prop> {
    let (left, value) = raw.split_once(':')?;
    let mut parts = left.split(';');
    let name = trim(parts.next().unwrap_or("")).to_uppercase();
    let mut params: Vec<(String, String)> = Vec::new();
    for part in parts {
        let part = trim(part);
        if part.is_empty() {
            continue;
        }
        let (key, value) = match part.split_once('=') {
            Some((key, value)) => (trim(key).to_uppercase(), trim(value).to_string()),
            None => (part.to_uppercase(), "true".to_string()),
        };
        match params.iter_mut().find(|(name, _)| *name == key) {
            Some(slot) => slot.1 = value,
            None => params.push((key, value)),
        }
    }
    Some(Prop {
        name,
        params,
        value: value.to_string(),
    })
}

/// The unescaped fields of a `;` separated value, missing ones as empty text.
fn fields(value: &str) -> Vec<String> {
    value.split(';').map(unescape).collect()
}

fn field(parts: &[String], index: usize) -> &str {
    parts.get(index).map(String::as_str).unwrap_or("")
}

fn some(text: &str) -> Option<String> {
    (!text.is_empty()).then(|| text.to_string())
}

fn channel(kind: CoreChannelKind, label: Option<String>, value: String) -> CoreContactChannel {
    CoreContactChannel {
        kind,
        label,
        value,
        extra: None,
    }
}

/// The cards in a vCard file, as drafts for `address_book_id`.
pub fn vcard_parse(text: &str, address_book_id: &str) -> Vec<CoreContactDraft> {
    let unfolded = text
        .replace("\r\n ", "")
        .replace("\r\n\t", "")
        .replace("\n ", "")
        .replace("\n\t", "");
    let book = resolve_address_book_id(Some(address_book_id.to_string()));

    let mut cards = Vec::new();
    let mut in_card = false;
    let mut props: Vec<Prop> = Vec::new();

    for line in unfolded.split('\n') {
        let line = trim(line);
        if line.is_empty() {
            continue;
        }
        if line.eq_ignore_ascii_case("BEGIN:VCARD") {
            in_card = true;
            props.clear();
            continue;
        }
        if line.eq_ignore_ascii_case("END:VCARD") {
            if in_card && !props.is_empty() {
                cards.extend(build(&props, &book));
            }
            in_card = false;
            props.clear();
            continue;
        }
        if in_card {
            props.extend(parse_line(line));
        }
    }

    // A single card whose BEGIN and END lines are missing.
    if cards.is_empty() && !props.is_empty() {
        cards.extend(build(&props, &book));
    }
    cards
}

fn build(props: &[Prop], book: &str) -> Option<CoreContactDraft> {
    let mut full = String::new();
    let mut family = String::new();
    let mut given = String::new();
    let mut nickname = String::new();
    let mut pronouns = String::new();
    let mut notes = String::new();
    let mut avatar = None;
    let mut profile = None;
    let mut created_at = None;
    let mut emails = Vec::new();
    let mut phones = Vec::new();
    let mut dates = Vec::new();
    let mut socials = Vec::new();
    let mut address = None;
    let mut organization = String::new();
    let mut title = String::new();

    for prop in props {
        match prop.name.as_str() {
            "FN" => full = unescape(&prop.value),
            "N" => {
                let parts = fields(&prop.value);
                family = field(&parts, 0).to_string();
                given = field(&parts, 1).to_string();
            }
            "NICKNAME" => nickname = unescape(&prop.value),
            "X-PRONOUNS" | "PRONOUNS" => pronouns = unescape(&prop.value),
            "EMAIL" => {
                let value = unescape(&prop.value);
                if value.is_empty() {
                    continue;
                }
                let kind = prop
                    .param("TYPE")
                    .or_else(|| prop.params.first().map(|(key, _)| key.as_str()))
                    .unwrap_or("")
                    .to_lowercase();
                let (kind, label) = if kind.contains("work") {
                    (CoreChannelKind::Work, None)
                } else if kind.contains("home") || kind.is_empty() {
                    (CoreChannelKind::Home, None)
                } else {
                    (CoreChannelKind::Custom, Some(kind))
                };
                emails.push(channel(kind, label, value));
            }
            "TEL" => {
                let value = unescape(&prop.value);
                if value.is_empty() {
                    continue;
                }
                let kind = match prop.param("TYPE") {
                    Some(kind) => kind.to_string(),
                    None => prop
                        .params
                        .iter()
                        .map(|(key, _)| key.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                }
                .to_lowercase();
                let (kind, label) = if kind.contains("cell") || kind.contains("mobile") {
                    (CoreChannelKind::Mobile, None)
                } else if kind.contains("work") {
                    (CoreChannelKind::Work, None)
                } else if kind.contains("home") {
                    (CoreChannelKind::Home, None)
                } else if kind.is_empty() {
                    (CoreChannelKind::Mobile, None)
                } else {
                    (CoreChannelKind::Custom, Some(kind))
                };
                phones.push(channel(kind, label, value));
            }
            "BDAY" | "ANNIVERSARY" | "X-ANNIVERSARY" => {
                let date = normalize_date(&unescape(&prop.value));
                if !date.is_empty() {
                    let kind = if prop.name == "BDAY" {
                        CoreContactDateKind::Birthday
                    } else {
                        CoreContactDateKind::Anniversary
                    };
                    dates.push(CoreContactDate {
                        kind,
                        label: None,
                        date,
                        extra: None,
                    });
                }
            }
            "X-DATE" => {
                let date = normalize_date(&unescape(&prop.value));
                if !date.is_empty() {
                    let label = prop
                        .param("LABEL")
                        .or_else(|| prop.param("TYPE"))
                        .unwrap_or("Event");
                    dates.push(CoreContactDate {
                        kind: CoreContactDateKind::Custom,
                        label: some(&unescape(label)),
                        date,
                        extra: None,
                    });
                }
            }
            "X-SOCIALPROFILE" => {
                let handle = unescape(&prop.value);
                if !handle.is_empty() {
                    let platform = prop
                        .param("TYPE")
                        .or_else(|| prop.param("SERVICE"))
                        .unwrap_or("Profile");
                    socials.push(CoreContactSocial {
                        platform: unescape(platform),
                        handle,
                        extra: None,
                    });
                }
            }
            "NOTE" => {
                let note = unescape(&prop.value);
                if !note.is_empty() {
                    notes = if notes.is_empty() {
                        note
                    } else {
                        format!("{notes}\n\n{note}")
                    };
                }
            }
            "ADR" => {
                // Post office box; extended; street; locality; region; code; country.
                let parts = fields(&prop.value);
                let street2 = field(&parts, 1);
                let street = field(&parts, 2);
                let street1 = if street.is_empty() { street2 } else { street };
                let street2 = if !street.is_empty() && !street2.is_empty() {
                    street2
                } else {
                    ""
                };
                let row = CoreContactAddress {
                    street1: some(street1),
                    street2: some(street2),
                    locality: some(field(&parts, 3)),
                    region: some(field(&parts, 4)),
                    postcode: some(field(&parts, 5)),
                    country: some(field(&parts, 6)),
                };
                if row.street1.is_some()
                    || row.locality.is_some()
                    || row.region.is_some()
                    || row.postcode.is_some()
                    || row.country.is_some()
                {
                    address = Some(row);
                }
            }
            "ORG" => organization = field(&fields(&prop.value), 0).to_string(),
            "TITLE" => title = unescape(&prop.value),
            "X-CREATED" | "CREATED" => created_at = some(&unescape(&prop.value)),
            "X-SEALBOOK-PROFILE" => {
                if let Some(parsed) = profile_parse(&unescape(&prop.value)) {
                    profile = Some(parsed);
                }
            }
            "PHOTO" => {
                let raw = trim(&prop.value);
                if raw.is_empty() {
                    continue;
                }
                let lower = raw.to_lowercase();
                if lower.starts_with("data:")
                    || lower.starts_with("http://")
                    || lower.starts_with("https://")
                {
                    avatar = Some(raw.to_string());
                } else {
                    let kind = prop.param("TYPE").unwrap_or("jpeg").to_lowercase();
                    let mime = if kind.contains("png") {
                        "image/png"
                    } else if kind.contains("webp") {
                        "image/webp"
                    } else {
                        "image/jpeg"
                    };
                    let body: String = raw.split_whitespace().collect();
                    avatar = Some(format!("data:{mime};base64,{body}"));
                }
            }
            _ => {}
        }
    }

    let mut name = full;
    if name.is_empty() {
        name = trim(&format!("{given} {family}")).to_string();
    }
    if name.is_empty() {
        if let Some(first) = emails.first() {
            name = first.value.split('@').next().unwrap_or("").to_string();
        }
    }
    if name.is_empty() {
        if let Some(first) = phones.first() {
            name = first.value.clone();
        }
    }
    if name.is_empty() {
        return None;
    }

    let work = if organization.is_empty() && title.is_empty() {
        Vec::new()
    } else {
        vec![CoreContactWork {
            organization,
            title: some(&title),
            extra: None,
        }]
    };

    Some(CoreContactDraft {
        name,
        nickname: some(&nickname),
        pronouns: some(&pronouns),
        emails,
        phones,
        address,
        work,
        dates,
        socials,
        notes: some(&notes),
        avatar,
        profile,
        address_book_id: book.to_string(),
        created_at,
        ..CoreContactDraft::default()
    })
}

/// A vCard 3.0 file holding `contacts`.
///
/// There is no standard spelling for the relationship sections, so they travel
/// as one vendor property: other readers ignore it, and a Sealbook round trip
/// keeps them.
pub fn vcard_write(contacts: &[CoreContactDraft]) -> String {
    contacts
        .iter()
        .map(card)
        .collect::<Vec<_>>()
        .join("\r\n\r\n")
}

fn card(c: &CoreContactDraft) -> String {
    let mut lines = vec![
        "BEGIN:VCARD".to_string(),
        "VERSION:3.0".to_string(),
        format!("FN:{}", escape(&c.name)),
    ];

    let words: Vec<&str> = trim(&c.name).split_whitespace().collect();
    if words.len() > 1 {
        lines.push(format!(
            "N:{};{};;;",
            escape(&words[1..].join(" ")),
            escape(words[0])
        ));
    } else {
        lines.push(format!("N:{};;;;", escape(&c.name)));
    }

    if let Some(nickname) = c.nickname.as_deref().filter(|v| !v.is_empty()) {
        lines.push(format!("NICKNAME:{}", escape(nickname)));
    }
    if let Some(pronouns) = c.pronouns.as_deref().filter(|v| !v.is_empty()) {
        lines.push(format!("X-PRONOUNS:{}", escape(pronouns)));
    }

    for email in &c.emails {
        let value = trim(&email.value);
        if value.is_empty() {
            continue;
        }
        let kind = match (&email.kind, email.label.as_deref()) {
            (CoreChannelKind::Work, _) => "WORK".to_string(),
            (CoreChannelKind::Custom, Some(label)) if !label.is_empty() => label.to_uppercase(),
            _ => "HOME".to_string(),
        };
        lines.push(format!("EMAIL;TYPE={kind}:{}", escape(value)));
    }

    for phone in &c.phones {
        let value = trim(&phone.value);
        if value.is_empty() {
            continue;
        }
        let kind = match (&phone.kind, phone.label.as_deref()) {
            (CoreChannelKind::Mobile, _) => "CELL".to_string(),
            (CoreChannelKind::Work, _) => "WORK".to_string(),
            (CoreChannelKind::Custom, Some(label)) if !label.is_empty() => label.to_uppercase(),
            _ => "HOME".to_string(),
        };
        lines.push(format!("TEL;TYPE={kind}:{}", escape(value)));
    }

    for date in &c.dates {
        if date.date.is_empty() {
            continue;
        }
        let value = escape(&date.date);
        lines.push(match date.kind {
            CoreContactDateKind::Birthday => format!("BDAY:{value}"),
            CoreContactDateKind::Anniversary => format!("ANNIVERSARY:{value}"),
            CoreContactDateKind::Custom => {
                let label = date.label.as_deref().filter(|v| !v.is_empty());
                format!("X-DATE;LABEL={}:{value}", escape(label.unwrap_or("Event")))
            }
        });
    }

    for social in &c.socials {
        if social.handle.is_empty() {
            continue;
        }
        lines.push(format!(
            "X-SOCIALPROFILE;TYPE={}:{}",
            escape(&social.platform),
            escape(&social.handle)
        ));
    }

    if let Some(address) = &c.address {
        let part = |value: &Option<String>| escape(value.as_deref().unwrap_or(""));
        let (extended, street) = (part(&address.street2), part(&address.street1));
        let (locality, region) = (part(&address.locality), part(&address.region));
        let (postcode, country) = (part(&address.postcode), part(&address.country));
        if !(street.is_empty()
            && locality.is_empty()
            && region.is_empty()
            && postcode.is_empty()
            && country.is_empty())
        {
            lines.push(format!(
                "ADR;TYPE=HOME:;{extended};{street};{locality};{region};{postcode};{country}"
            ));
        }
    }

    for work in &c.work {
        let organization = trim(&work.organization);
        if !organization.is_empty() {
            lines.push(format!("ORG:{}", escape(organization)));
        }
        if let Some(title) = work.title.as_deref().map(trim).filter(|v| !v.is_empty()) {
            lines.push(format!("TITLE:{}", escape(title)));
        }
    }

    if let Some(avatar) = c.avatar.as_deref().filter(|v| !v.is_empty()) {
        lines.push(photo(avatar));
    }

    if let Some(notes) = c.notes.as_deref().filter(|v| !v.is_empty()) {
        lines.push(format!("NOTE:{}", escape(notes)));
    }

    if let Some(profile) = c.profile.as_ref().and_then(profile_write) {
        lines.push(format!("X-SEALBOOK-PROFILE:{}", escape(&profile)));
    }

    if let Some(created) = c.created_at.as_deref().filter(|v| !v.is_empty()) {
        lines.push(format!("X-CREATED:{}", escape(created)));
    }

    lines.push("END:VCARD".to_string());
    lines.join("\r\n")
}

fn photo(avatar: &str) -> String {
    if !avatar.starts_with("data:") {
        return format!("PHOTO;VALUE=uri:{avatar}");
    }
    let image = avatar
        .strip_prefix("data:image/")
        .and_then(|rest| rest.split_once(";base64,"))
        .filter(|(format, body)| {
            !format.is_empty()
                && format
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-'))
                && !body.is_empty()
                && !body.contains('\n')
        });
    match image {
        Some((format, body)) => format!("PHOTO;ENCODING=b;TYPE={}:{body}", format.to_uppercase()),
        None => format!("PHOTO:{avatar}"),
    }
}

/// Everything above, in the shapes the bindings can carry.
#[cfg(feature = "uniffi")]
pub mod ffi {
    use crate::contacts::CoreContactDraft;

    #[uniffi::export(name = "vcard_parse")]
    pub fn vcard_parse(text: String, address_book_id: String) -> Vec<CoreContactDraft> {
        super::vcard_parse(&text, &address_book_id)
    }

    #[uniffi::export(name = "vcard_write")]
    pub fn vcard_write(contacts: Vec<CoreContactDraft>) -> String {
        super::vcard_write(&contacts)
    }
}
