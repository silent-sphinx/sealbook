//! The import samples every client shares, read by core.
//!
//! `imports/expected.json` is the stored form each sample file must become, with
//! the clock fields left out.

use sealbook_core::*;
use serde_json::Value;

const DIR: &str = "../sealbook-protocol/fixtures/imports";
const NOW: &str = "2026-10-28T12:00:00.000Z";

fn read(name: &str) -> String {
    std::fs::read_to_string(format!("{DIR}/{name}")).expect("fixture")
}

fn stored(draft: &CoreContactDraft) -> Value {
    let raw = contact_write(draft, NOW).expect("write");
    let mut value: Value = serde_json::from_str(&raw).expect("json");
    for key in ["created", "updated"] {
        value.as_object_mut().unwrap().remove(key);
    }
    value
}

#[test]
fn the_vcard_sample_becomes_the_expected_cards() {
    let expected: Value = serde_json::from_str(&read("expected.json")).unwrap();
    let cards: Vec<Value> = vcard_parse(&read("contacts.vcf"), "book")
        .iter()
        .map(stored)
        .collect();
    assert_eq!(Value::Array(cards), expected["vcf"]);
}

#[test]
fn a_card_survives_an_export_and_an_import() {
    let cards = vcard_parse(&read("contacts.vcf"), "book");
    let again = vcard_parse(&vcard_write(&cards), "book");
    assert_eq!(again.len(), cards.len());
    for (before, after) in cards.iter().zip(&again) {
        assert_eq!(stored(before), stored(after));
    }
}

#[test]
fn a_card_with_no_name_to_use_is_dropped() {
    let text = "BEGIN:VCARD\nNOTE:only a note\nEND:VCARD\nBEGIN:VCARD\nTEL:+1 555\nEND:VCARD";
    let cards = vcard_parse(text, "book");
    assert_eq!(cards.len(), 1);
    assert_eq!(cards[0].name, "+1 555");
}

#[test]
fn a_card_without_begin_and_end_is_read_once() {
    assert_eq!(vcard_parse("FN:Solo", "book").len(), 0);
    let text = "BEGIN:VCARD\nFN:Solo";
    assert_eq!(vcard_parse(text, "book").len(), 1);
}

#[test]
fn a_damaged_profile_line_keeps_the_card() {
    let text = "BEGIN:VCARD\nFN:Ada\nX-SEALBOOK-PROFILE:not json\nEND:VCARD";
    let cards = vcard_parse(text, "book");
    assert_eq!(cards[0].name, "Ada");
    assert!(cards[0].profile.is_none());
}

#[test]
fn an_unmarked_address_book_is_the_default() {
    let cards = vcard_parse("BEGIN:VCARD\nFN:Ada\nEND:VCARD", "all");
    assert_eq!(cards[0].address_book_id, default_address_book_id());
}
