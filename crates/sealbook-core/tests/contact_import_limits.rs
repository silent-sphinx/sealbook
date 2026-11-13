//! Hostile vCard, CSV and JSON contact files: how many cards they may carry,
//! what they may put in an avatar, and what an export does with odd labels.

use sealbook_core::*;

const BOOK: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

fn nameless_import_over_the_cap() -> usize {
    1_001
}

#[test]
fn a_vcard_file_over_the_contact_cap_is_refused() {
    let text = "BEGIN:VCARD\nFN:a\nEND:VCARD\n".repeat(nameless_import_over_the_cap());
    let read = vcard_import(&text, BOOK);
    assert!(read.contacts.is_empty());
    assert_eq!(read.skipped.len(), 1);
}

#[test]
fn a_vcard_file_at_the_contact_cap_is_read() {
    let text = "BEGIN:VCARD\nFN:a\nEND:VCARD\n".repeat(1_000);
    assert_eq!(vcard_import(&text, BOOK).contacts.len(), 1_000);
}

#[test]
fn a_csv_file_over_the_contact_cap_is_refused() {
    let text = format!("Name\n{}", "a\n".repeat(nameless_import_over_the_cap()));
    let read = csv_import(&text, BOOK);
    assert!(read.contacts.is_empty());
    assert_eq!(read.skipped.len(), 1);
}

#[test]
fn a_csv_file_at_the_contact_cap_is_read() {
    let text = format!("Name\n{}", "a\n".repeat(1_000));
    assert_eq!(csv_import(&text, BOOK).contacts.len(), 1_000);
}

fn avatar_of_vcard(photo: &str) -> Option<String> {
    let text = format!("BEGIN:VCARD\nFN:a\n{photo}\nEND:VCARD");
    vcard_import(&text, BOOK).contacts.remove(0).avatar
}

fn avatar_of_csv(value: &str) -> Option<String> {
    let text = format!("Name,Avatar\na,\"{value}\"\n");
    csv_import(&text, BOOK).contacts.remove(0).avatar
}

fn avatar_of_json(value: &str) -> Option<String> {
    let text = format!(r#"[{{"name":"a","avatar":"{value}"}}]"#);
    json_import(&text, BOOK).unwrap().contacts.remove(0).avatar
}

#[test]
fn an_avatar_that_is_not_an_image_or_https_url_is_dropped() {
    for bad in [
        "javascript:alert(1)",
        "data:text/html;base64,PHNjcmlwdD4=",
        "data:image/svg+xml;base64,PHN2Zz4=",
        "http://example.com/a.png",
        "file:///etc/passwd",
    ] {
        assert_eq!(avatar_of_vcard(&format!("PHOTO:{bad}")), None, "{bad}");
        assert_eq!(avatar_of_csv(bad), None, "{bad}");
        assert_eq!(avatar_of_json(bad), None, "{bad}");
    }
}

#[test]
fn an_image_or_https_avatar_is_kept() {
    for good in [
        "data:image/png;base64,iVBORw0KGgo=",
        "data:image/jpeg;base64,/9j/4AAQ",
        "https://example.com/a.png",
    ] {
        assert_eq!(
            avatar_of_vcard(&format!("PHOTO:{good}")).as_deref(),
            Some(good)
        );
        assert_eq!(avatar_of_csv(good).as_deref(), Some(good));
        assert_eq!(avatar_of_json(good).as_deref(), Some(good));
    }
}

#[test]
fn a_bare_base64_vcard_photo_is_still_read() {
    let avatar = avatar_of_vcard("PHOTO;ENCODING=b;TYPE=PNG:iVBORw0KGgo=");
    assert_eq!(
        avatar.as_deref(),
        Some("data:image/png;base64,iVBORw0KGgo=")
    );
}

fn card_with(name: &str, note: Option<&str>) -> CoreContactDraft {
    CoreContactDraft {
        name: name.to_string(),
        notes: note.map(str::to_string),
        address_book_id: BOOK.to_string(),
        ..CoreContactDraft::default()
    }
}

#[test]
fn a_backslash_before_n_survives_a_vcard_round_trip() {
    for note in [
        r"C:\new",
        r"a\\nb",
        r"trailing\",
        "line\nbreak and \\n literal",
    ] {
        let text = vcard_write(&[card_with("a", Some(note))]);
        let back = vcard_parse(&text, BOOK);
        assert_eq!(back[0].notes.as_deref(), Some(note), "{note}");
    }
}

fn channel(kind: CoreChannelKind, label: &str) -> CoreContactChannel {
    CoreContactChannel {
        kind,
        label: Some(label.to_string()),
        value: "a@b.c".to_string(),
        extra: None,
    }
}

#[test]
fn a_label_cannot_add_lines_to_an_exported_card() {
    let evil = "x:\r\nEND:VCARD\r\nBEGIN:VCARD\r\nFN:evil";
    let mut card = card_with("a", None);
    card.emails.push(channel(CoreChannelKind::Custom, evil));
    card.phones.push(channel(CoreChannelKind::Custom, evil));
    card.socials.push(CoreContactSocial {
        platform: evil.to_string(),
        handle: "h".to_string(),
        extra: None,
    });
    card.dates.push(CoreContactDate {
        kind: CoreContactDateKind::Custom,
        label: Some(evil.to_string()),
        date: "2020-01-01".to_string(),
        extra: None,
    });
    let text = vcard_write(&[card]);
    assert_eq!(text.matches("BEGIN:VCARD").count(), 1, "{text:?}");
    assert_eq!(vcard_parse(&text, BOOK).len(), 1);
}

#[test]
fn a_lone_carriage_return_in_a_value_stays_in_its_line() {
    let text = vcard_write(&[card_with("a\rTEL:123", Some("n\rEND:VCARD"))]);
    assert!(!text.replace("\r\n", "").contains('\r'), "{text:?}");
}
