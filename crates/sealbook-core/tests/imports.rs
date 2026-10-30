//! The import samples every client shares, read by core.
//!
//! `imports/expected.json` is the stored form each sample file must become, with
//! the clock fields left out. Regenerate the CSV and vCard parts with:
//! `REGENERATE_IMPORT_FIXTURE=1 cargo test -p sealbook-core --test imports -- --ignored regenerate`

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

#[test]
fn the_csv_sample_becomes_the_expected_cards() {
    let expected: Value = serde_json::from_str(&read("expected.json")).unwrap();
    let cards: Vec<Value> = csv_parse(&read("contacts.csv"), "book")
        .iter()
        .map(stored)
        .collect();
    assert_eq!(Value::Array(cards), expected["csv"]);
}

#[test]
#[ignore]
fn regenerate() {
    if std::env::var("REGENERATE_IMPORT_FIXTURE").is_err() {
        return;
    }
    let mut expected: Value = serde_json::from_str(&read("expected.json")).unwrap();
    let cards = |drafts: Vec<CoreContactDraft>| Value::Array(drafts.iter().map(stored).collect());
    expected["vcf"] = cards(vcard_parse(&read("contacts.vcf"), "book"));
    expected["csv"] = cards(csv_parse(&read("contacts.csv"), "book"));
    let text = serde_json::to_string_pretty(&expected).unwrap() + "\n";
    std::fs::write(format!("{DIR}/expected.json"), text).unwrap();
}

#[test]
fn a_csv_card_survives_an_export_and_an_import() {
    let cards = csv_parse(&read("contacts.csv"), "book");
    let books = [];
    let again = csv_parse(&csv_write(&cards, &books), "book");
    assert_eq!(again.len(), cards.len());
    for (before, after) in cards.iter().zip(&again) {
        assert_eq!(stored(before), stored(after));
    }
}

#[test]
fn a_full_card_survives_a_csv_export_and_import() {
    let text = "BEGIN:VCARD\nFN:Ada Lovelace\nEMAIL;TYPE=HOME:a@home.example\nEMAIL;TYPE=WORK:a@work.example\nEMAIL;TYPE=lab:a@lab.example\nTEL;TYPE=CELL:+441111\nTEL;TYPE=WORK:+442222\nBDAY:1815-12-10\nX-DATE;LABEL=First program:1843-01-01\nX-SOCIALPROFILE;TYPE=GitHub:ada\nADR;TYPE=HOME:;Flat 3;12 Nowhere St;London;;;\nORG:Engines\nTITLE:Maths\nNOTE:one\\, two\nEND:VCARD";
    let cards = vcard_parse(text, "book");
    let again = csv_parse(&csv_write(&cards, &[]), "book");
    assert_eq!(stored(&cards[0]), stored(&again[0]));
}

#[test]
fn a_formula_is_guarded_going_out_and_unguarded_coming_in() {
    let mut card = vcard_parse("BEGIN:VCARD\nFN:=cmd\nTEL:+15550100\nEND:VCARD", "book").remove(0);
    card.phones[0].value = "+15550100".into();
    let csv = csv_write(&[card], &[]);
    assert!(csv.contains("'=cmd"));
    assert!(csv.contains("'+15550100"));
    let back = csv_parse(&csv, "book");
    assert_eq!(back[0].name, "=cmd");
    assert_eq!(back[0].phones[0].value, "+15550100");
}

#[test]
fn a_name_column_is_not_found_in_first_name() {
    let cards = csv_parse("First Name,Last Name\nAda,Lovelace", "book");
    assert_eq!(cards[0].name, "Ada Lovelace");
}

#[test]
fn a_json_column_is_not_read_as_an_email() {
    let cards = csv_parse("Name,Emails (JSON)\nAda,not json", "book");
    assert!(cards[0].emails.is_empty());
}

#[test]
fn rows_hold_commas_quotes_and_line_breaks_inside_quotes() {
    assert_eq!(csv_rows("a,b\n1,2"), [["a", "b"], ["1", "2"]]);
    assert_eq!(csv_rows("a,b\r\n1,2"), [["a", "b"], ["1", "2"]]);
    assert_eq!(
        csv_rows("name,note\n\"Doe, Jane\",hello")[1],
        ["Doe, Jane", "hello"]
    );
    assert_eq!(
        csv_rows("a\n\"She said \"\"hi\"\"\"")[1],
        ["She said \"hi\""]
    );
    assert_eq!(
        csv_rows("a\n\"line one\nline two\"")[1],
        ["line one\nline two"]
    );
    assert_eq!(csv_rows("a,b,c\n1,,3")[1], ["1", "", "3"]);
    assert!(csv_rows("").is_empty());
}
