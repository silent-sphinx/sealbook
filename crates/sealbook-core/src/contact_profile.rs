//! The `sealbook:profile` half of a contact card: the relationship-manager
//! sections that ride in the card under one vendor property.
//!
//! One property rather than a mapping onto JSContact's own objects, because every
//! section needs a field the standard shape lacks (a per-entry note, a date
//! range, a like or dislike polarity).
//!
//! The profile is a single owned key of the card, so a writer that rebuilds it
//! from its own view of the sections drops whatever that view lacks. Android's
//! had no `colleagues` section, so an edit on a phone deleted every colleague the
//! web had recorded. The record here carries all eleven sections and an `extra`
//! for a section a later build adds, and the writer puts both back.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::payload::as_object;

/// Longest free-text entry, in UTF-16 code units, which is the unit both the web
/// and Android counted in before this moved.
pub const MAX_PROFILE_TEXT_CHARS: usize = 1024;

/// Entries per section. Guards the card's padded size, not correctness.
pub const MAX_PROFILE_ENTRIES: usize = 64;

/// The kind a relationship entry takes when the stored one is missing.
pub const DEFAULT_RELATIONSHIP_KIND: &str = "Partner";

/// Every key a profile writer owns, apart from the ones it carries in `extra`.
pub const PROFILE_KEYS: &[&str] = &[
    "@type",
    "version",
    "howWeMet",
    "interests",
    "music",
    "food",
    "pets",
    "career",
    "relationships",
    "timeline",
    "family",
    "friends",
    "colleagues",
    "custom",
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum CoreFoodPolarity {
    #[default]
    Like,
    Dislike,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreProfileFood {
    pub polarity: CoreFoodPolarity,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreProfilePet {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub species: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Dates on the sections that carry them are partial ISO strings (`YYYY`,
/// `YYYY-MM`, `YYYY-MM-DD`), since a job or a life event often has only a year.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreProfileCareer {
    pub organization: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreProfileRelationship {
    pub name: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    /// Never set together with `current`: an ongoing relationship has no end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
    pub current: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreProfileLifeEvent {
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Family, friends and colleagues share a shape; only family shows `relation`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreProfilePerson {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Links the entry to another contact in the vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact_id: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreProfileCustom {
    pub title: String,
    pub text: String,
}

/// A profile as it is read or drafted.
///
/// Every list is always present. An empty profile is not written at all, so a
/// card nobody has filled the sections of carries no key and no bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreContactProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how_we_met: Option<String>,
    pub interests: Vec<String>,
    pub music: Vec<String>,
    pub food: Vec<CoreProfileFood>,
    pub pets: Vec<CoreProfilePet>,
    pub career: Vec<CoreProfileCareer>,
    pub relationships: Vec<CoreProfileRelationship>,
    pub timeline: Vec<CoreProfileLifeEvent>,
    pub family: Vec<CoreProfilePerson>,
    pub friends: Vec<CoreProfilePerson>,
    pub colleagues: Vec<CoreProfilePerson>,
    pub custom: Vec<CoreProfileCustom>,
    /// Whatever else the stored profile carried, as a JSON object, `{}` when it
    /// carried nothing else. No host reads it; it is what stops an edit from
    /// deleting a section a later build added.
    pub extra: String,
}

impl CoreContactProfile {
    /// True when nothing in it, including `extra`, would survive a write.
    pub fn is_empty(&self) -> bool {
        profile_json(self).is_none()
    }
}

/// Trimmed, then cut to [`MAX_PROFILE_TEXT_CHARS`] UTF-16 code units without
/// splitting a surrogate pair. `None` where nothing is left.
fn clean(text: &str) -> Option<String> {
    let mut units = 0;
    let mut out = String::new();
    for c in text.trim().chars() {
        units += c.len_utf16();
        if units > MAX_PROFILE_TEXT_CHARS {
            break;
        }
        out.push(c);
    }
    // Cutting can leave trailing space the trim above never saw.
    let out = out.trim_end().to_string();
    (!out.is_empty()).then_some(out)
}

fn clean_opt(text: &Option<String>) -> Option<String> {
    text.as_deref().and_then(clean)
}

fn text_of(object: &Map<String, Value>, key: &str) -> Option<String> {
    object.get(key).and_then(Value::as_str).and_then(clean)
}

fn entries<'a>(object: &'a Map<String, Value>, key: &str) -> Vec<&'a Map<String, Value>> {
    object
        .get(key)
        .and_then(Value::as_array)
        .map(|array| {
            array
                .iter()
                .take(MAX_PROFILE_ENTRIES)
                .filter_map(Value::as_object)
                .collect()
        })
        .unwrap_or_default()
}

fn tags(object: &Map<String, Value>, key: &str) -> Vec<String> {
    object
        .get(key)
        .and_then(Value::as_array)
        .map(|array| {
            array
                .iter()
                .take(MAX_PROFILE_ENTRIES)
                .filter_map(Value::as_str)
                .filter_map(clean)
                .collect()
        })
        .unwrap_or_default()
}

fn people(object: &Map<String, Value>, key: &str) -> Vec<CoreProfilePerson> {
    entries(object, key)
        .into_iter()
        .filter_map(|entry| {
            Some(CoreProfilePerson {
                name: text_of(entry, "name")?,
                relation: text_of(entry, "relation"),
                note: text_of(entry, "note"),
                contact_id: text_of(entry, "contactId"),
            })
        })
        .collect()
}

/// Reads the value under `sealbook:profile`. Entries that cannot be read are
/// dropped rather than failing the card; a profile with nothing readable in it
/// is no profile.
pub(crate) fn parse_profile(value: Option<&Value>) -> Option<CoreContactProfile> {
    let object = value?.as_object()?;
    let profile = CoreContactProfile {
        how_we_met: text_of(object, "howWeMet"),
        interests: tags(object, "interests"),
        music: tags(object, "music"),
        food: entries(object, "food")
            .into_iter()
            .filter_map(|entry| {
                Some(CoreProfileFood {
                    polarity: if entry.get("polarity").and_then(Value::as_str) == Some("dislike") {
                        CoreFoodPolarity::Dislike
                    } else {
                        CoreFoodPolarity::Like
                    },
                    value: text_of(entry, "value")?,
                    note: text_of(entry, "note"),
                })
            })
            .collect(),
        pets: entries(object, "pets")
            .into_iter()
            .filter_map(|entry| {
                Some(CoreProfilePet {
                    name: text_of(entry, "name")?,
                    species: text_of(entry, "species"),
                    note: text_of(entry, "note"),
                })
            })
            .collect(),
        career: entries(object, "career")
            .into_iter()
            .filter_map(|entry| {
                let organization = text_of(entry, "organization");
                let title = text_of(entry, "title");
                if organization.is_none() && title.is_none() {
                    return None;
                }
                Some(CoreProfileCareer {
                    organization: organization.unwrap_or_default(),
                    title,
                    start: text_of(entry, "start"),
                    end: text_of(entry, "end"),
                    note: text_of(entry, "note"),
                })
            })
            .collect(),
        relationships: entries(object, "relationships")
            .into_iter()
            .filter_map(|entry| {
                let current = entry.get("current").and_then(Value::as_bool) == Some(true);
                Some(CoreProfileRelationship {
                    name: text_of(entry, "name")?,
                    kind: text_of(entry, "kind")
                        .unwrap_or_else(|| DEFAULT_RELATIONSHIP_KIND.to_string()),
                    start: text_of(entry, "start"),
                    end: if current { None } else { text_of(entry, "end") },
                    current,
                    note: text_of(entry, "note"),
                })
            })
            .collect(),
        timeline: entries(object, "timeline")
            .into_iter()
            .filter_map(|entry| {
                Some(CoreProfileLifeEvent {
                    title: text_of(entry, "title")?,
                    date: text_of(entry, "date"),
                    description: text_of(entry, "description"),
                })
            })
            .collect(),
        family: people(object, "family"),
        friends: people(object, "friends"),
        colleagues: people(object, "colleagues"),
        custom: entries(object, "custom")
            .into_iter()
            .filter_map(|entry| {
                let title = text_of(entry, "title").unwrap_or_default();
                let text = text_of(entry, "text").unwrap_or_default();
                (!title.is_empty() || !text.is_empty()).then_some(CoreProfileCustom { title, text })
            })
            .collect(),
        extra: Value::Object(
            object
                .iter()
                .filter(|(key, _)| !PROFILE_KEYS.contains(&key.as_str()))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        )
        .to_string(),
    };
    (!profile.is_empty()).then_some(profile)
}

/// Reads a profile from its JSON text, for the importers and exporters that carry
/// one outside a card. `None` for text that is not a profile.
pub fn profile_parse(raw: &str) -> Option<CoreContactProfile> {
    parse_profile(serde_json::from_str::<Value>(raw).ok().as_ref())
}

/// A profile as JSON text, or `None` when nothing in it would survive a write.
pub fn profile_write(profile: &CoreContactProfile) -> Option<String> {
    profile_json(profile).map(|value| value.to_string())
}

fn put(entry: &mut Map<String, Value>, key: &str, value: &Option<String>) {
    if let Some(value) = clean_opt(value) {
        entry.insert(key.into(), json!(value));
    }
}

fn tag_list(values: &[String]) -> Option<Value> {
    let kept: Vec<String> = values
        .iter()
        .filter_map(|value| clean(value))
        .take(MAX_PROFILE_ENTRIES)
        .collect();
    (!kept.is_empty()).then(|| json!(kept))
}

fn list<T>(rows: &[T], build: impl Fn(&T) -> Option<Map<String, Value>>) -> Option<Value> {
    let built: Vec<Value> = rows
        .iter()
        .filter_map(build)
        .take(MAX_PROFILE_ENTRIES)
        .map(Value::Object)
        .collect();
    (!built.is_empty()).then_some(Value::Array(built))
}

fn person_list(rows: &[CoreProfilePerson]) -> Option<Value> {
    list(rows, |row| {
        let mut entry = Map::new();
        entry.insert("name".into(), json!(clean(&row.name)?));
        put(&mut entry, "relation", &row.relation);
        put(&mut entry, "note", &row.note);
        put(&mut entry, "contactId", &row.contact_id);
        Some(entry)
    })
}

/// The profile as it sits in the card, or `None` when nothing is filled in so an
/// empty profile adds no bytes and no key. Every optional field is omitted rather
/// than written null.
pub(crate) fn profile_json(profile: &CoreContactProfile) -> Option<Value> {
    let mut body = Map::new();

    if let Some(how_we_met) = clean_opt(&profile.how_we_met) {
        body.insert("howWeMet".into(), json!(how_we_met));
    }
    if let Some(value) = tag_list(&profile.interests) {
        body.insert("interests".into(), value);
    }
    if let Some(value) = tag_list(&profile.music) {
        body.insert("music".into(), value);
    }
    if let Some(value) = list(&profile.food, |row| {
        let mut entry = Map::new();
        entry.insert(
            "polarity".into(),
            json!(match row.polarity {
                CoreFoodPolarity::Like => "like",
                CoreFoodPolarity::Dislike => "dislike",
            }),
        );
        entry.insert("value".into(), json!(clean(&row.value)?));
        put(&mut entry, "note", &row.note);
        Some(entry)
    }) {
        body.insert("food".into(), value);
    }
    if let Some(value) = list(&profile.pets, |row| {
        let mut entry = Map::new();
        entry.insert("name".into(), json!(clean(&row.name)?));
        put(&mut entry, "species", &row.species);
        put(&mut entry, "note", &row.note);
        Some(entry)
    }) {
        body.insert("pets".into(), value);
    }
    if let Some(value) = list(&profile.career, |row| {
        let organization = clean(&row.organization);
        let title = clean_opt(&row.title);
        if organization.is_none() && title.is_none() {
            return None;
        }
        let mut entry = Map::new();
        if let Some(organization) = organization {
            entry.insert("organization".into(), json!(organization));
        }
        if let Some(title) = title {
            entry.insert("title".into(), json!(title));
        }
        put(&mut entry, "start", &row.start);
        put(&mut entry, "end", &row.end);
        put(&mut entry, "note", &row.note);
        Some(entry)
    }) {
        body.insert("career".into(), value);
    }
    if let Some(value) = list(&profile.relationships, |row| {
        let mut entry = Map::new();
        entry.insert("name".into(), json!(clean(&row.name)?));
        put(&mut entry, "kind", &Some(row.kind.clone()));
        put(&mut entry, "start", &row.start);
        // An ongoing relationship has no end, even if one lingers in a draft
        // from before the flag was set.
        if row.current {
            entry.insert("current".into(), json!(true));
        } else {
            put(&mut entry, "end", &row.end);
        }
        put(&mut entry, "note", &row.note);
        Some(entry)
    }) {
        body.insert("relationships".into(), value);
    }
    if let Some(value) = list(&profile.timeline, |row| {
        let mut entry = Map::new();
        entry.insert("title".into(), json!(clean(&row.title)?));
        put(&mut entry, "date", &row.date);
        put(&mut entry, "description", &row.description);
        Some(entry)
    }) {
        body.insert("timeline".into(), value);
    }
    for (key, rows) in [
        ("family", &profile.family),
        ("friends", &profile.friends),
        ("colleagues", &profile.colleagues),
    ] {
        if let Some(value) = person_list(rows) {
            body.insert(key.into(), value);
        }
    }
    if let Some(value) = list(&profile.custom, |row| {
        let title = clean(&row.title);
        let text = clean(&row.text);
        if title.is_none() && text.is_none() {
            return None;
        }
        let mut entry = Map::new();
        if let Some(title) = title {
            entry.insert("title".into(), json!(title));
        }
        if let Some(text) = text {
            entry.insert("text".into(), json!(text));
        }
        Some(entry)
    }) {
        body.insert("custom".into(), value);
    }

    // A section a later build added rides through under its own key, but never
    // over one this build owns. It keeps a profile alive on its own, since
    // dropping the property would delete it.
    let extra: Map<String, Value> = as_object(&profile.extra)
        .unwrap_or_default()
        .into_iter()
        .filter(|(key, _)| !PROFILE_KEYS.contains(&key.as_str()))
        .collect();
    if body.is_empty() && extra.is_empty() {
        return None;
    }
    body.extend(extra);
    body.insert("@type".into(), json!("SealbookProfile"));
    body.insert("version".into(), json!("1.0"));
    Some(Value::Object(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(value: Value) -> Option<CoreContactProfile> {
        parse_profile(Some(&value))
    }

    #[test]
    fn colleagues_survive_a_round_trip() {
        let stored = json!({ "colleagues": [{ "name": "Grace", "contactId": "abc" }] });
        let profile = parsed(stored).expect("profile");
        assert_eq!(profile.colleagues.len(), 1);
        let written = profile_json(&profile).expect("written");
        assert_eq!(written["colleagues"][0]["contactId"], "abc");
    }

    #[test]
    fn a_section_a_later_build_added_rides_through() {
        let profile = parsed(json!({ "howWeMet": "School", "hobbies": ["chess"] })).unwrap();
        let written = profile_json(&profile).unwrap();
        assert_eq!(written["hobbies"][0], "chess");
    }

    #[test]
    fn a_profile_with_nothing_readable_is_no_profile() {
        assert!(parsed(json!({ "food": [{ "value": "  " }], "interests": [1, 2] })).is_none());
        assert!(parsed(json!("text")).is_none());
        assert!(parse_profile(None).is_none());
    }

    #[test]
    fn text_is_cut_at_the_limit_in_utf16_units_without_splitting_a_pair() {
        let long = format!("{}{}", "a".repeat(MAX_PROFILE_TEXT_CHARS - 1), "\u{1F600}");
        let cut = clean(&long).unwrap();
        assert_eq!(cut.encode_utf16().count(), MAX_PROFILE_TEXT_CHARS - 1);
    }

    #[test]
    fn an_ongoing_relationship_writes_no_end() {
        let profile = CoreContactProfile {
            relationships: vec![CoreProfileRelationship {
                name: "Sam".into(),
                kind: "Spouse".into(),
                end: Some("2020".into()),
                current: true,
                ..Default::default()
            }],
            ..Default::default()
        };
        let written = profile_json(&profile).unwrap();
        assert!(written["relationships"][0].get("end").is_none());
        assert_eq!(written["relationships"][0]["current"], true);
    }
}
