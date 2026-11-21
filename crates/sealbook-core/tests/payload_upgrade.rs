//! The 1.0 to 1.1 payload upgrade.
//!
//! The cases live in `payloads/upgrade.json` so every client runs the same
//! ones. The tables there are written by core, so the assertions below that name
//! a value are the check on core rather than the fixture: they hold the
//! behaviour the migration plan promises, independently of what was recorded.
//!
//! `REGENERATE_UPGRADE_FIXTURE=1 cargo test -p sealbook-core --test payload_upgrade -- --ignored regenerate`

use sealbook_core::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const FIXTURE: &str = "../sealbook-protocol/fixtures/payloads/upgrade.json";

const NOTE: &str = "application/sealbook.note+json";
const NOTEBOOK: &str = "application/sealbook.notebook+json";
const TASK: &str = "application/sealbook.task+json";
const TASK_LIST: &str = "application/sealbook.task-list+json";
const BOOKMARK: &str = "application/sealbook.bookmark+json";
const COLLECTION: &str = "application/sealbook.bookmark-collection+json";
const EVENT: &str = "application/sealbook.calendar-event+json";
const CALENDAR: &str = "application/sealbook.calendar+json";
const CARD: &str = "application/jscontact+json";
const BOOK: &str = "application/sealbook.addressbook+json";

#[derive(Serialize, Deserialize)]
struct Fixture {
    upgrades: Vec<Upgrade>,
    untouched: Vec<Untouched>,
}

#[derive(Serialize, Deserialize)]
struct Upgrade {
    case: String,
    content_type: String,
    from: String,
    to: String,
}

#[derive(Serialize, Deserialize)]
struct Untouched {
    case: String,
    content_type: String,
    raw: String,
}

fn upgrade_cases() -> Vec<(&'static str, &'static str, String)> {
    let cases: Vec<(&str, &str, Value)> = vec![
        (
            "a note declaring 1.0",
            NOTE,
            json!({"@type":"Note","version":"1.0","title":"T","body":"b","notebookId":"n","createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-02T00:00:00Z","keepMe":{"deep":[1,{"also":true}]}}),
        ),
        (
            "a note with no version",
            NOTE,
            json!({"@type":"Note","title":"T","body":"b","notebookId":"n"}),
        ),
        (
            "a notebook",
            NOTEBOOK,
            json!({"@type":"Notebook","version":"1.0","name":"Work","keepMe":1}),
        ),
        (
            "a task",
            TASK,
            json!({"@type":"Task","version":"1.0","title":"T","taskListId":"l","keepMe":[1]}),
        ),
        (
            "a task list",
            TASK_LIST,
            json!({"@type":"TaskList","version":"1.0","name":"L","keepMe":{"a":1}}),
        ),
        (
            "a bookmark",
            BOOKMARK,
            json!({"@type":"Bookmark","version":"1.0","url":"https://a.example","title":"A","collectionId":"c"}),
        ),
        (
            "a bookmark collection",
            COLLECTION,
            json!({"@type":"BookmarkCollection","version":"1.0","name":"C","archived":true}),
        ),
        (
            "an event in no calendar",
            EVENT,
            json!({"@type":"CalendarEvent","version":"1.0","title":"Standup","start":"2026-10-01T09:00:00.000Z","keepMe":{"x":[{"y":1}]}}),
        ),
        (
            "an event with a blank calendar",
            EVENT,
            json!({"@type":"CalendarEvent","version":"1.0","title":"Standup","start":"2026-10-01","calendarId":"  "}),
        ),
        (
            "an event already in a calendar",
            EVENT,
            json!({"@type":"CalendarEvent","version":"1.0","title":"Standup","start":"2026-10-01","calendarId":"cccccccc-cccc-4ccc-8ccc-cccccccccccc"}),
        ),
        (
            "a calendar with favorite false",
            CALENDAR,
            json!({"@type":"Calendar","version":"1.0","name":"Work","color":"#7aa2f7","favorite":false}),
        ),
        (
            "a calendar with favorite true",
            CALENDAR,
            json!({"@type":"Calendar","version":"1.0","name":"Work","color":"#7aa2f7","favorite":true}),
        ),
        (
            "an address book",
            BOOK,
            json!({"@type":"AddressBook","version":"1.0","name":"People","keepMe":true}),
        ),
        (
            "a card with every field only under a legacy key",
            CARD,
            json!({
                "@type":"Card","version":"1.0",
                "fullName":"Ada Lovelace",
                "nicknames":{"n1":{"name":"Ada"}},
                "pronouns":"she/her",
                "photo":"data:image/png;base64,AAAA",
                "createdAt":"2026-01-01T00:00:00Z",
                "updatedAt":"2026-02-02T00:00:00Z",
                "emails":{"e1":{"address":"ada@analytical.example"}},
                "sealbook:addressBookId":"00000000-0000-0000-0000-000000000001",
                "uid":"urn:uuid:keep-me"
            }),
        ),
        (
            "a card with display name, photos and avatar legacy keys",
            CARD,
            json!({
                "@type":"Card","version":"1.0",
                "displayName":"Grace Hopper",
                "photos":{"p1":{"kind":"photo","uri":"data:image/png;base64,BBBB"}},
                "sealbook:addressBookId":"00000000-0000-0000-0000-000000000001"
            }),
        ),
        (
            "a card holding both a legacy and a canonical value",
            CARD,
            json!({
                "@type":"Card","version":"1.0",
                "name":{"full":"Canonical Name"},"fullName":"Legacy Name",
                "nickNames":{"n1":{"name":"Canon"}},"nicknames":{"n1":{"name":"Legacy"}},
                "speakToAs":{"pronouns":"they/them"},"pronouns":"he/him",
                "media":{"avatar":{"kind":"photo","uri":"data:image/png;base64,CCCC"}},"avatar":"data:image/png;base64,DDDD",
                "created":"2026-03-03T00:00:00Z","createdAt":"2025-01-01T00:00:00Z",
                "updated":"2026-04-04T00:00:00Z","updatedAt":"2025-02-02T00:00:00Z",
                "sealbook:addressBookId":"00000000-0000-0000-0000-000000000001"
            }),
        ),
        (
            "a card that carries a key the record does not model",
            CARD,
            json!({
                "@type":"Card","version":"1.0","name":{"full":"Kept"},
                "kind":"individual","uid":"urn:uuid:1234",
                "localizations":{"de":{"name":{"full":"Behalten"}}},
                "sealbook:addressBookId":"00000000-0000-0000-0000-000000000001"
            }),
        ),
    ];
    cases
        .into_iter()
        .map(|(case, content_type, value)| (case, content_type, value.to_string()))
        .collect()
}

fn untouched_cases() -> Vec<(&'static str, &'static str, String)> {
    vec![
        (
            "a payload already at 1.1",
            NOTE,
            r#"{"@type":"Note","version":"1.1","title":"T"}"#.into(),
        ),
        (
            "a payload from a later minor",
            NOTE,
            r#"{"@type":"Note","version":"1.7","title":"T"}"#.into(),
        ),
        (
            "a payload from a later major",
            EVENT,
            r#"{"@type":"CalendarEvent","version":"2.0","title":"T","start":"2026-10-01"}"#.into(),
        ),
        (
            "a card already at 1.1",
            CARD,
            r#"{"@type":"Card","version":"1.0","sealbook:version":"1.1","name":{"full":"A"},"fullName":"Legacy kept until a write"}"#.into(),
        ),
        (
            "a card from a later Sealbook major",
            CARD,
            r#"{"@type":"Card","version":"1.0","sealbook:version":"2.0","name":{"full":"A"}}"#.into(),
        ),
        (
            "a payload of a type core does not know",
            "application/x-future",
            r#"{"@type":"Hologram","version":"1.0"}"#.into(),
        ),
        ("text that is not JSON", NOTE, "not json".into()),
        ("JSON that is not an object", NOTE, "[1,2]".into()),
    ]
}

fn fixture() -> Fixture {
    let text = std::fs::read_to_string(FIXTURE).expect("the upgrade fixture");
    serde_json::from_str(&text).expect("parses")
}

fn parsed(text: &str) -> Value {
    serde_json::from_str(text).expect("a JSON payload")
}

#[test]
fn every_case_matches_the_fixture() {
    let fixture = fixture();
    let cases = upgrade_cases();
    assert_eq!(fixture.upgrades.len(), cases.len());
    for (expected, (case, content_type, from)) in fixture.upgrades.iter().zip(cases) {
        assert_eq!(expected.case, case);
        assert_eq!(expected.content_type, content_type);
        assert_eq!(expected.from, from, "{case}: the input drifted");
        assert_eq!(
            payload_upgrade(content_type, &from).as_deref(),
            Some(expected.to.as_str()),
            "{case}"
        );
    }
    let cases = untouched_cases();
    assert_eq!(fixture.untouched.len(), cases.len());
    for (expected, (case, content_type, raw)) in fixture.untouched.iter().zip(cases) {
        assert_eq!(expected.case, case);
        assert_eq!(expected.raw, raw, "{case}: the input drifted");
        assert_eq!(payload_upgrade(content_type, &raw), None, "{case}");
    }
}

#[test]
fn an_upgraded_payload_is_unchanged_by_a_second_upgrade() {
    for (case, content_type, from) in upgrade_cases() {
        let once = payload_upgrade(content_type, &from).expect(case);
        assert_eq!(payload_upgrade(content_type, &once), None, "{case}");
    }
}

#[test]
fn every_upgraded_payload_declares_the_current_version() {
    for (case, content_type, from) in upgrade_cases() {
        let to = parsed(&payload_upgrade(content_type, &from).expect(case));
        if content_type == CARD {
            assert_eq!(
                to["version"], "1.0",
                "{case}: a card's version is JSContact's"
            );
            assert_eq!(to["sealbook:version"], PAYLOAD_SCHEMA_VERSION, "{case}");
        } else {
            assert_eq!(to["version"], PAYLOAD_SCHEMA_VERSION, "{case}");
        }
    }
}

#[test]
fn an_event_with_no_calendar_goes_into_the_default_one() {
    let to = |case: &str| {
        let (_, content_type, from) = upgrade_cases()
            .into_iter()
            .find(|(name, ..)| *name == case)
            .unwrap();
        parsed(&payload_upgrade(content_type, &from).unwrap())
    };
    let default = default_calendar_id();
    assert_eq!(to("an event in no calendar")["calendarId"], default);
    assert_eq!(to("an event with a blank calendar")["calendarId"], default);
    assert_eq!(
        to("an event already in a calendar")["calendarId"],
        "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    );
    // The read agrees, whether or not the stored text has been rewritten.
    let stored = r#"{"@type":"CalendarEvent","version":"1.0","title":"T","start":"2026-10-01"}"#;
    assert_eq!(event_parse("e", stored).calendar_id, Some(default));
}

#[test]
fn favorite_false_goes_and_favorite_true_stays() {
    let upgrade = |favorite: bool| {
        parsed(
            &payload_upgrade(
                CALENDAR,
                &json!({"@type":"Calendar","version":"1.0","name":"W","favorite":favorite})
                    .to_string(),
            )
            .unwrap(),
        )
    };
    assert!(upgrade(false).get("favorite").is_none());
    assert_eq!(upgrade(true)["favorite"], true);
}

#[test]
fn an_unknown_key_survives_at_every_nesting_level() {
    let from = json!({
        "@type":"Note","version":"1.0","title":"T","body":"b","notebookId":"n",
        "top":1,
        "attachments":[{"id":"a","nested":{"deeper":[{"deepest":true}]}}],
    })
    .to_string();
    let to = parsed(&payload_upgrade(NOTE, &from).unwrap());
    assert_eq!(to["top"], 1);
    assert_eq!(to["attachments"][0]["nested"]["deeper"][0]["deepest"], true);

    let card = json!({
        "@type":"Card","version":"1.0","name":{"full":"A","extraName":1},
        "emails":{"e1":{"address":"a@example.com","pref":1,"extra":{"k":[1]}}},
        "uid":"urn:uuid:1","sealbook:addressBookId":"00000000-0000-0000-0000-000000000001"
    })
    .to_string();
    let to = parsed(&payload_upgrade(CARD, &card).unwrap());
    assert_eq!(to["uid"], "urn:uuid:1");
    assert_eq!(to["emails"]["e1"]["extra"]["k"][0], 1);
    assert_eq!(to["emails"]["e1"]["pref"], 1);
}

fn card(name: &str) -> Value {
    let (_, _, from) = upgrade_cases()
        .into_iter()
        .find(|(case, ..)| *case == name)
        .unwrap();
    parsed(&payload_upgrade(CARD, &from).unwrap())
}

#[test]
fn a_card_value_held_only_under_a_legacy_key_moves_to_its_canonical_key() {
    let to = card("a card with every field only under a legacy key");
    assert_eq!(to["name"]["full"], "Ada Lovelace");
    assert_eq!(to["nickNames"]["n1"]["name"], "Ada");
    assert_eq!(to["speakToAs"]["pronouns"], "she/her");
    assert_eq!(to["media"]["avatar"]["uri"], "data:image/png;base64,AAAA");
    assert_eq!(to["created"], "2026-01-01T00:00:00Z");
    assert_eq!(to["updated"], "2026-02-02T00:00:00Z");
    for legacy in [
        "fullName",
        "displayName",
        "nicknames",
        "pronouns",
        "photo",
        "photos",
        "avatar",
        "createdAt",
        "updatedAt",
    ] {
        assert!(to.get(legacy).is_none(), "{legacy} survived the upgrade");
    }
    assert_eq!(to["uid"], "urn:uuid:keep-me");

    let to = card("a card with display name, photos and avatar legacy keys");
    assert_eq!(to["name"]["full"], "Grace Hopper");
    assert_eq!(to["media"]["avatar"]["uri"], "data:image/png;base64,BBBB");
}

#[test]
fn a_canonical_card_value_wins_over_a_legacy_one() {
    let to = card("a card holding both a legacy and a canonical value");
    assert_eq!(to["name"]["full"], "Canonical Name");
    assert_eq!(to["nickNames"]["n1"]["name"], "Canon");
    assert_eq!(to["speakToAs"]["pronouns"], "they/them");
    assert_eq!(to["media"]["avatar"]["uri"], "data:image/png;base64,CCCC");
    assert_eq!(to["created"], "2026-03-03T00:00:00Z");
    assert_eq!(to["updated"], "2026-04-04T00:00:00Z");
}

#[test]
fn a_card_key_the_record_does_not_model_survives() {
    let to = card("a card that carries a key the record does not model");
    assert_eq!(to["kind"], "individual");
    assert_eq!(to["uid"], "urn:uuid:1234");
    assert_eq!(to["localizations"]["de"]["name"]["full"], "Behalten");
}

#[test]
fn an_upgrade_invents_no_date() {
    let from = r#"{"@type":"Card","version":"1.0","name":{"full":"A"},"sealbook:addressBookId":"00000000-0000-0000-0000-000000000001"}"#;
    let to = parsed(&payload_upgrade(CARD, from).unwrap());
    assert!(to.get("created").is_none());
    assert!(to.get("updated").is_none());
    let from = r#"{"@type":"Notebook","version":"1.0","name":"W"}"#;
    let to = parsed(&payload_upgrade(NOTEBOOK, from).unwrap());
    assert!(to.get("createdAt").is_none());
    assert!(to.get("updatedAt").is_none());
}

#[test]
fn a_written_card_is_rfc_9553_version_1_0() {
    let written = contact_write(
        &CoreContactDraft {
            name: "Ada".into(),
            address_book_id: default_address_book_id(),
            ..Default::default()
        },
        "2026-10-28T12:00:00Z",
    )
    .unwrap();
    let card = parsed(&written);
    assert_eq!(card["version"], "1.0");
    assert_eq!(card["sealbook:version"], PAYLOAD_SCHEMA_VERSION);
    assert!(contact_parse("c", &written).readable);
}

#[test]
fn a_card_from_a_later_sealbook_major_is_not_readable() {
    let raw = r#"{"@type":"Card","version":"1.0","sealbook:version":"2.0","name":{"full":"A"}}"#;
    assert!(!contact_parse("c", raw).readable);
    assert!(matches!(
        contact_write(
            &CoreContactDraft {
                name: "B".into(),
                raw: Some(raw.into()),
                ..Default::default()
            },
            "2026-10-28T12:00:00Z"
        ),
        Err(CoreError::PayloadSchema { .. })
    ));
}

#[test]
fn a_write_over_a_1_0_payload_does_not_keep_the_old_shape() {
    let previous = r##"{"@type":"Calendar","version":"1.0","name":"Work","color":"#7aa2f7","favorite":false,"sharedWith":["x"]}"##;
    let written = parsed(
        &calendar_write(
            &CoreCalendarDraft {
                name: "Work".into(),
                color: "#7aa2f7".into(),
                raw: Some(previous.into()),
                ..Default::default()
            },
            "2026-10-28T12:00:00Z",
        )
        .unwrap(),
    );
    assert_eq!(written["version"], PAYLOAD_SCHEMA_VERSION);
    assert!(written.get("favorite").is_none());
    assert_eq!(written["sharedWith"][0], "x");
}

#[test]
fn an_offline_edit_queued_under_1_0_merges_with_a_1_1_copy() {
    let base = r#"{"@type":"Task","version":"1.0","title":"Call","taskListId":"l","notes":"a","createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z"}"#;
    let local = r#"{"@type":"Task","version":"1.0","title":"Call Ada","taskListId":"l","notes":"a","createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-02T00:00:00Z"}"#;
    let remote = r#"{"@type":"Task","version":"1.1","title":"Call","taskListId":"l","notes":"b","createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-03T00:00:00Z"}"#;
    let MergeOutcome::Merged { payload, .. } =
        merge_payload(TASK, Some(base), local, remote, "2026-01-04")
    else {
        panic!("a clean merge");
    };
    let merged = parsed(&payload);
    assert_eq!(merged["version"], "1.1");
    assert_eq!(merged["title"], "Call Ada");
    assert_eq!(merged["notes"], "b");
}

#[test]
fn an_event_that_now_carries_updated_at_merges_by_it() {
    let base = r#"{"@type":"CalendarEvent","version":"1.1","title":"T","start":"2026-10-01","calendarId":"c","updatedAt":"2026-01-01T00:00:00Z"}"#;
    let local = r#"{"@type":"CalendarEvent","version":"1.1","title":"T","start":"2026-10-01","calendarId":"c","updatedAt":"2026-01-03T00:00:00Z"}"#;
    let remote = r#"{"@type":"CalendarEvent","version":"1.1","title":"T","start":"2026-10-01","calendarId":"c","updatedAt":"2026-01-02T00:00:00Z"}"#;
    let MergeOutcome::Merged { payload, .. } =
        merge_payload(EVENT, Some(base), local, remote, "2026-01-04")
    else {
        panic!("a clean merge");
    };
    // The later of the two wins, and here that is this device's.
    assert_eq!(parsed(&payload)["updatedAt"], "2026-01-03T00:00:00Z");
}

#[test]
fn every_write_stamps_both_dates_and_keeps_the_first() {
    let now = "2026-10-28T12:00:00Z";
    let earlier = "2026-01-01T00:00:00Z";
    let first = parsed(
        &event_write(
            &CoreCalendarEventDraft {
                title: "T".into(),
                start: "2026-10-01".into(),
                ..Default::default()
            },
            earlier,
        )
        .unwrap(),
    );
    assert_eq!(first["createdAt"], earlier);
    assert_eq!(first["updatedAt"], earlier);
    let again = parsed(
        &event_write(
            &CoreCalendarEventDraft {
                title: "T2".into(),
                start: "2026-10-01".into(),
                raw: Some(first.to_string()),
                ..Default::default()
            },
            now,
        )
        .unwrap(),
    );
    assert_eq!(again["createdAt"], earlier);
    assert_eq!(again["updatedAt"], now);

    let notebook = parsed(&notebook_write("W", None, None, false, false, None, earlier).unwrap());
    let renamed = parsed(
        &notebook_write(
            "W2",
            None,
            None,
            false,
            false,
            Some(&notebook.to_string()),
            now,
        )
        .unwrap(),
    );
    assert_eq!(renamed["createdAt"], earlier);
    assert_eq!(renamed["updatedAt"], now);
    let read = notebook_parse("n", &renamed.to_string());
    assert_eq!(read.created_at.as_deref(), Some(earlier));
    assert_eq!(read.updated_at.as_deref(), Some(now));
}

#[test]
#[ignore = "writes the shared fixture"]
fn regenerate() {
    if std::env::var("REGENERATE_UPGRADE_FIXTURE").is_err() {
        return;
    }
    let fixture = Fixture {
        upgrades: upgrade_cases()
            .into_iter()
            .map(|(case, content_type, from)| Upgrade {
                case: case.into(),
                content_type: content_type.into(),
                to: payload_upgrade(content_type, &from).expect(case),
                from,
            })
            .collect(),
        untouched: untouched_cases()
            .into_iter()
            .map(|(case, content_type, raw)| Untouched {
                case: case.into(),
                content_type: content_type.into(),
                raw,
            })
            .collect(),
    };
    std::fs::write(
        FIXTURE,
        serde_json::to_string_pretty(&fixture).unwrap() + "\n",
    )
    .unwrap();
}
