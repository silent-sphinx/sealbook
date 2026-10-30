//! Contact search: one index that every client builds once and asks per
//! keystroke.
//!
//! Each whitespace-separated word of the query has to be found somewhere on the
//! card, so "ada engines" finds Ada Lovelace at Analytical Engines. Hits are
//! ranked by where they landed: a name before an employer, an employer before
//! a note. Case and accents are folded, and phone numbers match by digits.

use std::cmp::Ordering;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::contact_profile::CoreContactProfile;
use crate::order::name_key;
use crate::{contact_parse, CoreContact};

/// A stored card, as a host holds it.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreContactSource {
    pub id: String,
    pub raw: String,
}

/// An address book's name, which a search also reads.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreBookName {
    pub id: String,
    pub name: String,
}

struct Entry {
    id: String,
    sort_name: String,
    name: String,
    name_words: Vec<String>,
    secondary: Vec<String>,
    channels: Vec<String>,
    phone_digits: Vec<String>,
    rest: Vec<String>,
}

pub struct ContactIndex {
    entries: Vec<Entry>,
}

fn present(parts: impl IntoIterator<Item = String>) -> Vec<String> {
    parts.into_iter().filter(|part| !part.is_empty()).collect()
}

fn digits(text: &str) -> String {
    text.chars().filter(char::is_ascii_digit).collect()
}

/// Profile text folded into the search, row by row.
fn profile_text(profile: &CoreContactProfile) -> Vec<String> {
    let mut parts: Vec<&str> = Vec::new();
    fn add<'a>(parts: &mut Vec<&'a str>, text: Option<&'a String>) {
        if let Some(text) = text {
            parts.push(text);
        }
    }
    add(&mut parts, profile.how_we_met.as_ref());
    for value in profile.interests.iter().chain(&profile.music) {
        add(&mut parts, Some(value));
    }
    for food in &profile.food {
        add(&mut parts, Some(&food.value));
        add(&mut parts, food.note.as_ref());
    }
    for pet in &profile.pets {
        add(&mut parts, Some(&pet.name));
        add(&mut parts, pet.species.as_ref());
        add(&mut parts, pet.note.as_ref());
    }
    for job in &profile.career {
        add(&mut parts, Some(&job.organization));
        add(&mut parts, job.title.as_ref());
        add(&mut parts, job.note.as_ref());
    }
    for tie in &profile.relationships {
        add(&mut parts, Some(&tie.name));
        add(&mut parts, Some(&tie.kind));
        add(&mut parts, tie.note.as_ref());
    }
    for event in &profile.timeline {
        add(&mut parts, Some(&event.title));
        add(&mut parts, event.description.as_ref());
    }
    for person in profile
        .family
        .iter()
        .chain(&profile.friends)
        .chain(&profile.colleagues)
    {
        add(&mut parts, Some(&person.name));
        add(&mut parts, person.relation.as_ref());
        add(&mut parts, person.note.as_ref());
    }
    for section in &profile.custom {
        add(&mut parts, Some(&section.title));
        add(&mut parts, Some(&section.text));
    }
    parts.into_iter().map(name_key).collect()
}

fn entry(contact: &CoreContact, book_name: Option<&String>) -> Entry {
    let name = name_key(&contact.name);
    let name_words = name
        .split([' ', ','])
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect();

    let mut secondary: Vec<String> = contact.nickname.iter().map(|text| name_key(text)).collect();
    for work in &contact.work {
        secondary.push(name_key(&work.organization));
        secondary.extend(work.title.iter().map(|text| name_key(text)));
    }

    let mut channels: Vec<String> = contact.emails.iter().map(|c| name_key(&c.value)).collect();
    channels.extend(
        contact
            .socials
            .iter()
            .map(|social| name_key(&format!("{} {}", social.platform, social.handle))),
    );

    let mut rest: Vec<String> = Vec::new();
    rest.extend(contact.pronouns.iter().map(|text| name_key(text)));
    rest.extend(contact.notes.iter().map(|text| name_key(text)));
    if let Some(profile) = &contact.profile {
        let text = profile_text(profile).join(" ");
        rest.push(text);
    }
    if let Some(address) = &contact.address {
        let line = [
            &address.street1,
            &address.street2,
            &address.locality,
            &address.region,
            &address.postcode,
            &address.country,
        ]
        .into_iter()
        .flatten()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(" ");
        rest.push(name_key(&line));
    }
    rest.extend(contact.phones.iter().map(|phone| name_key(&phone.value)));
    rest.extend(book_name.map(|text| name_key(text)));

    Entry {
        id: contact.id.clone(),
        sort_name: contact.display_name.clone(),
        name,
        name_words,
        secondary: present(secondary),
        channels: present(channels),
        phone_digits: present(contact.phones.iter().map(|phone| digits(&phone.value))),
        rest: present(rest),
    }
}

/// The digit runs a word could be a phone number written as. A number stored in
/// full, "+44 7700 900123", is searched for as it is written locally, "07700
/// 900123", so the trunk zero is allowed to fall away. Under three digits says
/// nothing, so it is dropped.
fn digit_forms(word: &str) -> Vec<String> {
    let all = digits(word);
    if all.len() < 3 {
        return Vec::new();
    }
    let trimmed = all.trim_start_matches('0');
    if trimmed.len() >= 3 && trimmed != all {
        vec![all.clone(), trimmed.to_owned()]
    } else {
        vec![all]
    }
}

impl Entry {
    /// Where a word was found, lowest first, or None if it was not.
    fn score(&self, word: &str, forms: &[String]) -> Option<u8> {
        let any = |texts: &[String]| texts.iter().any(|text| text.contains(word));
        if self.name.starts_with(word) {
            Some(0)
        } else if self.name_words.iter().any(|w| w.starts_with(word)) {
            Some(1)
        } else if self.name.contains(word) {
            Some(2)
        } else if any(&self.secondary) {
            Some(3)
        } else if any(&self.channels)
            || forms
                .iter()
                .any(|form| self.phone_digits.iter().any(|d| d.contains(form.as_str())))
        {
            Some(4)
        } else if any(&self.rest) {
            Some(5)
        } else {
            None
        }
    }
}

impl ContactIndex {
    pub fn new(sources: &[CoreContactSource], books: &[CoreBookName]) -> Self {
        let book_names: HashMap<&str, &String> = books
            .iter()
            .map(|book| (book.id.as_str(), &book.name))
            .collect();
        let entries = sources
            .iter()
            .map(|source| {
                let contact = contact_parse(&source.id, &source.raw);
                let book = book_names.get(contact.address_book_id.as_str()).copied();
                entry(&contact, book)
            })
            .collect();
        Self { entries }
    }

    /// Ids of the cards matching `query`, best first. An empty query matches
    /// every card, in the order the index was built.
    pub fn search(&self, query: &str) -> Vec<String> {
        let folded = name_key(query.trim());
        let words: Vec<&str> = folded.split(' ').filter(|word| !word.is_empty()).collect();
        if words.is_empty() {
            return self.entries.iter().map(|e| e.id.clone()).collect();
        }
        let forms: Vec<Vec<String>> = words.iter().map(|word| digit_forms(word)).collect();

        let mut hits: Vec<(u8, &Entry)> = self
            .entries
            .iter()
            .filter_map(|entry| {
                let mut worst = 0;
                for (word, forms) in words.iter().zip(&forms) {
                    worst = worst.max(entry.score(word, forms)?);
                }
                Some((worst, entry))
            })
            .collect();
        hits.sort_by(|(a_score, a), (b_score, b)| {
            a_score
                .cmp(b_score)
                .then_with(|| name_key(&a.sort_name).cmp(&name_key(&b.sort_name)))
                .then_with(|| match a.sort_name.cmp(&b.sort_name) {
                    Ordering::Equal => a.id.cmp(&b.id),
                    other => other,
                })
        });
        hits.into_iter()
            .map(|(_, entry)| entry.id.clone())
            .collect()
    }
}

#[cfg(feature = "uniffi")]
pub mod ffi {
    use std::sync::Arc;

    use super::{ContactIndex, CoreBookName, CoreContactSource};

    #[derive(uniffi::Object)]
    pub struct ContactSearchIndex {
        inner: ContactIndex,
    }

    #[uniffi::export]
    impl ContactSearchIndex {
        #[uniffi::constructor]
        pub fn new(sources: Vec<CoreContactSource>, books: Vec<CoreBookName>) -> Arc<Self> {
            Arc::new(Self {
                inner: ContactIndex::new(&sources, &books),
            })
        }

        pub fn search(&self, query: String) -> Vec<String> {
            self.inner.search(&query)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        contact_write, CoreChannelKind, CoreContactChannel, CoreContactDraft, CoreContactWork,
    };

    fn phone(value: &str) -> CoreContactChannel {
        CoreContactChannel {
            kind: CoreChannelKind::Mobile,
            label: None,
            value: value.into(),
            extra: None,
        }
    }

    fn card(id: &str, draft: CoreContactDraft) -> CoreContactSource {
        CoreContactSource {
            id: id.into(),
            raw: contact_write(&draft, "2026-01-01T00:00:00Z").unwrap(),
        }
    }

    fn named(id: &str, name: &str) -> CoreContactSource {
        card(
            id,
            CoreContactDraft {
                name: name.into(),
                ..Default::default()
            },
        )
    }

    fn found(cards: &[CoreContactSource], query: &str) -> Vec<String> {
        ContactIndex::new(cards, &[]).search(query)
    }

    #[test]
    fn accents_and_case_fold_both_ways() {
        let cards = [named("a", "Ren\u{e9}e Dupont"), named("b", "Jose")];
        assert_eq!(found(&cards, "RENEE"), ["a"]);
        assert_eq!(found(&cards, "jos\u{e9}"), ["b"]);
    }

    #[test]
    fn every_word_must_be_found_in_any_order() {
        let cards = [card(
            "a",
            CoreContactDraft {
                name: "Ada Lovelace".into(),
                work: vec![CoreContactWork {
                    organization: "Analytical Engines".into(),
                    title: None,
                    extra: None,
                }],
                ..Default::default()
            },
        )];
        assert_eq!(found(&cards, "ada engines"), ["a"]);
        assert_eq!(found(&cards, "lovelace ada"), ["a"]);
        assert!(found(&cards, "ada babbage").is_empty());
    }

    #[test]
    fn a_name_ranks_before_a_note() {
        let cards = [
            card(
                "note",
                CoreContactDraft {
                    name: "Zed".into(),
                    notes: Some("met Brighton".into()),
                    ..Default::default()
                },
            ),
            named("name", "Brighton Smith"),
        ];
        assert_eq!(found(&cards, "brighton"), ["name", "note"]);
    }

    #[test]
    fn a_phone_number_matches_by_digits_and_without_the_trunk_zero() {
        let cards = [card(
            "a",
            CoreContactDraft {
                name: "Ada".into(),
                phones: vec![phone("+44 7700 900123")],
                ..Default::default()
            },
        )];
        assert_eq!(found(&cards, "07700 900123"), ["a"]);
        assert_eq!(found(&cards, "7700900"), ["a"]);
        assert!(found(&cards, "7700 900124").is_empty());
    }

    #[test]
    fn an_empty_query_keeps_the_order_it_was_built_in() {
        let cards = [named("b", "Bob"), named("a", "Alice")];
        assert_eq!(found(&cards, "  "), ["b", "a"]);
    }

    #[test]
    fn the_address_book_name_is_searched() {
        let cards = [card(
            "a",
            CoreContactDraft {
                name: "Ada".into(),
                address_book_id: "book".into(),
                ..Default::default()
            },
        )];
        let books = [CoreBookName {
            id: "book".into(),
            name: "Work".into(),
        }];
        assert_eq!(ContactIndex::new(&cards, &books).search("work"), ["a"]);
    }
}
