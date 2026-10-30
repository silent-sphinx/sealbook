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
    expected["ics_parsed"] = serde_json::to_value(ics_parse(&read("calendar.ics"))).unwrap();
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

#[test]
fn the_ics_sample_becomes_the_expected_events() {
    let expected: Value = serde_json::from_str(&read("expected.json")).unwrap();
    let parsed = serde_json::to_value(ics_parse(&read("calendar.ics"))).unwrap();
    assert_eq!(parsed, expected["ics_parsed"]);
}

fn one(text: &str) -> CoreIcsEvent {
    let body = format!("BEGIN:VEVENT\n{text}\nEND:VEVENT");
    let mut parsed = ics_parse(&body);
    assert!(parsed.skipped.is_empty(), "{:?}", parsed.skipped);
    parsed.events.remove(0)
}

#[test]
fn an_ics_time_comes_back_as_utc_or_local_with_its_zone() {
    let utc = one("SUMMARY:A\nDTSTART:20261001T090000Z");
    assert_eq!(
        (utc.start.as_str(), utc.start_zone),
        ("2026-10-01T09:00:00Z", None)
    );
    let zoned = one("SUMMARY:A\nDTSTART;TZID=Europe/London:20261002T1230\nDTEND;TZID=Asia/Tokyo:20261002T133000");
    assert_eq!(zoned.start, "2026-10-02T12:30:00");
    assert_eq!(zoned.start_zone.as_deref(), Some("Europe/London"));
    assert_eq!(zoned.end.as_deref(), Some("2026-10-02T13:30:00"));
    assert_eq!(zoned.end_zone.as_deref(), Some("Asia/Tokyo"));
}

#[test]
fn an_all_day_end_is_inclusive() {
    let event = one("SUMMARY:A\nDTSTART;VALUE=DATE:20261224\nDTEND;VALUE=DATE:20261228");
    assert_eq!(event.end.as_deref(), Some("2026-12-27"));
}

#[test]
fn an_unreadable_date_skips_one_event_and_says_why() {
    let text = "BEGIN:VEVENT\nSUMMARY:Bad\nDTSTART:20261301\nEND:VEVENT\nBEGIN:VEVENT\nSUMMARY:Good\nDTSTART:20261001T090000Z\nEND:VEVENT\nBEGIN:VEVENT\nSUMMARY:None\nEND:VEVENT\nBEGIN:VEVENT\nDTSTART:20261001T250000\nEND:VEVENT";
    let parsed = ics_parse(text);
    assert_eq!(parsed.events.len(), 1);
    assert_eq!(parsed.skipped.len(), 3);
    assert_eq!(parsed.skipped[0].reason, "Unsupported ICS date: 20261301");
    assert_eq!(parsed.skipped[1].reason, "it has no start date");
    assert_eq!(parsed.skipped[2].title, "Untitled event");
}

#[test]
fn text_loses_its_markup_and_keeps_its_meaning() {
    let event = one("SUMMARY:A\nDTSTART:20261001T090000Z\nDESCRIPTION:text/html\\,<p>Hi &amp; bye<br/>Room%203</p>\nLOCATION:Location: Room 3\nATTENDEE:mailto:ada@x.example");
    assert_eq!(event.notes.as_deref(), Some("Hi & bye\nRoom 3"));
    assert_eq!(event.location.as_deref(), Some("Room 3"));
    assert_eq!(event.participants, ["ada@x.example"]);
}

#[test]
fn a_percent_sign_that_is_not_an_escape_is_left_alone() {
    let event = one("SUMMARY:A\nDTSTART:20261001T090000Z\nDESCRIPTION:100% sure");
    assert_eq!(event.notes.as_deref(), Some("100% sure"));
}

#[test]
fn rules_keep_what_the_protocol_can_say() {
    let weekly = ics_rrule("FREQ=WEEKLY;BYDAY=MO,WE,FR", "2026-10-05").unwrap();
    assert_eq!(weekly.weekdays, [1, 3, 5]);
    assert_eq!(
        ics_rrule("FREQ=WEEKLY", "2026-10-07").unwrap().weekdays,
        [3]
    );
    let nth = ics_rrule("FREQ=MONTHLY;BYDAY=3TU", "2026-10-20").unwrap();
    assert_eq!(
        nth.nth_weekday,
        Some(CoreNthWeekday {
            ordinal: 3,
            weekday: 2
        })
    );
    assert_eq!(
        ics_rrule("FREQ=MONTHLY", "2026-10-20")
            .unwrap()
            .day_of_month,
        Some(20)
    );
    assert!(ics_rrule("FREQ=MONTHLY;BYDAY=-1FR", "2026-10-20")
        .unwrap()
        .nth_weekday
        .is_none());
    let until = ics_rrule("FREQ=DAILY;UNTIL=20261031T235959Z;COUNT=5", "2026-10-01").unwrap();
    assert_eq!(
        (until.until.as_deref(), until.count),
        (Some("2026-10-31"), Some(5))
    );
    assert_eq!(
        ics_rrule("FREQ=DAILY;INTERVAL=1", "2026-10-01")
            .unwrap()
            .interval,
        None
    );
    assert_eq!(
        ics_rrule("FREQ=DAILY;INTERVAL=2", "2026-10-01")
            .unwrap()
            .interval,
        Some(2)
    );
    assert!(ics_rrule("FREQ=HOURLY;INTERVAL=6", "2026-10-01").is_none());
    assert!(ics_rrule("", "2026-10-01").is_none());
}

#[test]
fn a_stamp_is_utc_seconds_whatever_form_the_instant_came_in() {
    assert_eq!(ics_stamp("2026-10-01T09:00:00.000Z"), "20261001T090000Z");
    assert_eq!(ics_stamp("2026-10-01T09:00:00Z"), "20261001T090000Z");
    assert_eq!(ics_stamp("2026-10-01T10:30:00+01:00"), "20261001T093000Z");
    assert_eq!(ics_stamp("2026-10-01"), "20261001");
}

#[test]
fn a_long_line_folds_on_octets() {
    let folded = ics_fold(&format!("SUMMARY:{}", "\u{e9}".repeat(40)));
    for (at, line) in folded.split("\r\n").enumerate() {
        let size = line.len();
        assert!(size <= if at == 0 { 75 } else { 75 }, "{size}");
    }
    assert!(folded.contains("\r\n "));
}

fn export(start: &str, end: Option<&str>) -> CoreIcsExportEvent {
    CoreIcsExportEvent {
        id: "e1".into(),
        event: CoreCalendarEventDraft {
            title: "Gym, then tea".into(),
            start: start.into(),
            end: end.map(str::to_string),
            participants: vec!["Ada".into(), "grace@x.example".into()],
            ..CoreCalendarEventDraft::default()
        },
    }
}

#[test]
fn an_event_survives_an_export_and_an_import() {
    let mut event = export("2026-10-05T18:00:00Z", Some("2026-10-05T19:00:00Z"));
    event.event.recurrence = ics_rrule("FREQ=WEEKLY;INTERVAL=2;BYDAY=MO,WE;COUNT=6", "2026-10-05");
    event.event.notes = Some("one\ntwo; three".into());
    let text = ics_write(&[event.clone()], "Work", "2026-10-30T12:00:00Z");
    assert!(text.contains("PRODID:-//Sealbook//EN\r\n"));
    assert!(text.contains("DTSTAMP:20261030T120000Z\r\n"));
    assert!(text.contains("UID:e1@sealbook\r\n"));
    assert!(text.contains("ATTENDEE;CN=Ada:invalid:nomail\r\n"));
    assert!(text.ends_with("END:VCALENDAR\r\n"));
    let back = ics_parse(&text).events.remove(0);
    assert_eq!(back.title, "Gym, then tea");
    assert_eq!(back.start, "2026-10-05T18:00:00Z");
    assert_eq!(back.end.as_deref(), Some("2026-10-05T19:00:00Z"));
    assert_eq!(back.notes.as_deref(), Some("one\ntwo; three"));
    assert_eq!(back.recurrence, event.event.recurrence);
    assert_eq!(
        back.participants,
        ["Ada", "grace@x.example"].map(String::from)
    );
}

#[test]
fn an_all_day_event_writes_an_exclusive_end() {
    let text = ics_write(
        &[export("2026-12-24", Some("2026-12-27"))],
        "Work",
        "2026-10-30T12:00:00Z",
    );
    assert!(text.contains("DTSTART;VALUE=DATE:20261224\r\n"));
    assert!(text.contains("DTEND;VALUE=DATE:20261228\r\n"));
    let back = ics_parse(&text).events.remove(0);
    assert_eq!(
        (back.start.as_str(), back.end.as_deref()),
        ("2026-12-24", Some("2026-12-27"))
    );
}

#[test]
fn vcard_cards_with_nothing_to_name_them_by_are_reported() {
    let text = "BEGIN:VCARD\nNOTE:x\nEND:VCARD\nBEGIN:VCARD\nFN:Ada\nEND:VCARD";
    let imported = vcard_import(text, "book");
    assert_eq!(imported.contacts.len(), 1);
    assert_eq!(imported.skipped.len(), 1);
    assert_eq!(imported.skipped[0].label, "Card 1");
}

#[test]
fn csv_rows_with_nothing_to_name_them_by_are_reported() {
    let imported = csv_import("Name,Notes\nAda,x\n,only a note\n\nBob,y", "book");
    assert_eq!(imported.contacts.len(), 2);
    assert_eq!(imported.skipped.len(), 1);
    assert_eq!(imported.skipped[0].label, "Row 3");
}

#[test]
fn rules_that_cannot_be_kept_are_counted() {
    let event = |rule: &str| {
        format!(
            "BEGIN:VCALENDAR\nBEGIN:VEVENT\nSUMMARY:x\nDTSTART:20261001T090000Z\nRRULE:{rule}\nEND:VEVENT\nEND:VCALENDAR"
        )
    };
    assert_eq!(ics_parse(&event("FREQ=HOURLY")).dropped_rules, 1);
    assert_eq!(ics_parse(&event("FREQ=DAILY")).dropped_rules, 0);
}
