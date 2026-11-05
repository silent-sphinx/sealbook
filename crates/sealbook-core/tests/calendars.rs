//! Calendar and event payloads, against the fixture the three clients share.
//!
//! What is pinned here is the plaintext itself, byte for byte, as it is for
//! notes: this layer has no server check behind it, because objects are sealed
//! before they leave and the content type string is all the server ever sees.
//! The bytes are reproducible because core now writes them for all three hosts,
//! and because nothing in a calendar payload comes from a clock or a random
//! draw.
//!
//! The cases are the ones the clients disagreed about: whether a field is
//! trimmed, whether an absent one is omitted or written null, what an unnamed
//! calendar is listed as, whether a rename keeps the colour and the flags, what
//! becomes of a repeat rule this build cannot name, and what happens to a
//! payload from a newer schema major.
//!
//! Regenerate with:
//! `REGENERATE_CALENDAR_FIXTURE=1 cargo test -p sealbook-core --test calendars -- --ignored regenerate`

use sealbook_core::*;
use serde::{Deserialize, Serialize};

const FIXTURE: &str = "../sealbook-protocol/fixtures/payloads/calendars.json";

const EVENT: &str = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const CALENDAR: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

#[derive(Serialize, Deserialize)]
struct Fixture {
    constants: Constants,
    calendar_writes: Vec<CalendarWriteCase>,
    calendar_parses: Vec<CalendarParseCase>,
    event_writes: Vec<EventWriteCase>,
    event_parses: Vec<EventParseCase>,
    refusals: Vec<RefusalCase>,
}

#[derive(Serialize, Deserialize)]
struct Constants {
    calendar_content_type: String,
    calendar_event_content_type: String,
    calendar_keys: Vec<String>,
    calendar_event_keys: Vec<String>,
    default_calendar_id: String,
    default_calendar_name: String,
    default_calendar_color: String,
    untitled_calendar_name: String,
    untitled_event_title: String,
    max_event_alerts: usize,
    min_alert_minutes_before: i32,
    max_alert_minutes_before: i32,
    timed_alert_presets: Vec<AlertLabel>,
    all_day_alert_presets: Vec<AlertLabel>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct AlertLabel {
    minutes_before: i32,
    label: String,
}

fn alert_labels(all_day: bool) -> Vec<AlertLabel> {
    alert_presets(all_day)
        .into_iter()
        .map(|minutes_before| AlertLabel {
            minutes_before,
            label: alert_label(minutes_before, all_day),
        })
        .collect()
}

#[derive(Serialize, Deserialize)]
struct CalendarWriteCase {
    case: String,
    draft: CoreCalendarDraft,
    payload: String,
}

#[derive(Serialize, Deserialize)]
struct CalendarParseCase {
    case: String,
    id: String,
    raw: String,
    calendar: CoreCalendar,
}

#[derive(Serialize, Deserialize)]
struct EventWriteCase {
    case: String,
    draft: CoreCalendarEventDraft,
    payload: String,
}

#[derive(Serialize, Deserialize)]
struct EventParseCase {
    case: String,
    id: String,
    raw: String,
    event: CoreCalendarEvent,
}

/// The variant name, which is what the fixture pins rather than the sentence
/// each host words for itself.
#[derive(Serialize, Deserialize)]
struct RefusalCase {
    case: String,
    error: String,
}

fn fixture() -> Fixture {
    let text = std::fs::read_to_string(FIXTURE).expect("fixture");
    serde_json::from_str(&text).expect("fixture parses")
}

fn blank_calendar() -> CoreCalendarDraft {
    CoreCalendarDraft {
        name: String::new(),
        color: DEFAULT_CALENDAR_COLOR.into(),
        favorite: false,
        archived: false,
        raw: None,
    }
}

fn blank_event() -> CoreCalendarEventDraft {
    CoreCalendarEventDraft {
        title: String::new(),
        start: String::new(),
        end: None,
        notes: None,
        location: None,
        participants: Vec::new(),
        timezone: None,
        calendar_id: None,
        recurrence: None,
        unreadable_recurrence: None,
        alerts: Vec::new(),
        unreadable_alerts: Vec::new(),
        raw: None,
    }
}

/// A calendar as a client stores one that has been through every feature, plus a
/// key from a build this one predates.
fn stored_calendar() -> String {
    serde_json::json!({
        "@type": "Calendar",
        "version": "1.0",
        "name": "Old Team",
        "color": "#9ece6a",
        "favorite": true,
        "archived": true,
        "sharedWith": ["someone@example.com"]
    })
    .to_string()
}

/// The richest event payload any client writes, with a key from a later build.
fn stored_event() -> String {
    serde_json::json!({
        "@type": "CalendarEvent",
        "version": "1.0",
        "title": "Standup",
        "start": "2026-10-01T09:00:00.000Z",
        "end": "2026-10-01T09:15:00.000Z",
        "notes": "Daily sync",
        "location": "Room 3",
        "participants": ["alice@example.com", "bob@example.com"],
        "timezone": "Europe/London",
        "calendarId": CALENDAR,
        "recurrence": {
            "frequency": "weekly",
            "interval": 2,
            "weekdays": [1, 2, 3, 4, 5],
            "until": "2026-12-31"
        },
        "alerts": [{ "minutesBefore": 10 }, { "at": "from a later build" }],
        "conference": { "from": "a later build" }
    })
    .to_string()
}

/// A rule naming a frequency this build does not know, which is the case Android
/// silently deleted on the next save.
fn stored_unreadable_rule() -> String {
    serde_json::json!({
        "@type": "CalendarEvent",
        "version": "1.0",
        "title": "Pay day",
        "start": "2026-10-01",
        "recurrence": { "frequency": "hourly", "interval": 3 }
    })
    .to_string()
}

fn calendar_write_cases() -> Vec<(String, CoreCalendarDraft)> {
    let stored = stored_calendar();
    let parsed = calendar_parse(CALENDAR, &stored);
    vec![
        (
            "a calendar created from scratch".into(),
            CoreCalendarDraft {
                name: "Work".into(),
                ..blank_calendar()
            },
        ),
        (
            "a name with surrounding space, and a favourite".into(),
            CoreCalendarDraft {
                name: "  Work  ".into(),
                favorite: true,
                ..blank_calendar()
            },
        ),
        (
            "a blank colour takes the one every client defaults to".into(),
            CoreCalendarDraft {
                name: "Work".into(),
                color: "   ".into(),
                ..blank_calendar()
            },
        ),
        (
            "a calendar put away, which is the only time the key is written".into(),
            CoreCalendarDraft {
                name: "Old Team".into(),
                color: "#9ece6a".into(),
                archived: true,
                ..blank_calendar()
            },
        ),
        (
            "a rename that keeps the colour, the flags and a key from a later build".into(),
            CoreCalendarDraft {
                name: "Renamed".into(),
                color: parsed.color.clone(),
                favorite: parsed.favorite,
                archived: parsed.archived,
                raw: Some(stored.clone()),
            },
        ),
        (
            "taking a calendar back out of the archive clears the key".into(),
            CoreCalendarDraft {
                name: parsed.name.clone(),
                color: parsed.color.clone(),
                favorite: parsed.favorite,
                archived: false,
                raw: Some(stored),
            },
        ),
    ]
}

fn calendar_parse_cases() -> Vec<(String, String, String)> {
    vec![
        (
            "a calendar that has been through every feature".into(),
            CALENDAR.into(),
            stored_calendar(),
        ),
        (
            "the default calendar, unnamed".into(),
            default_calendar_id(),
            "{}".into(),
        ),
        (
            "any other calendar, unnamed".into(),
            CALENDAR.into(),
            "{}".into(),
        ),
        (
            "a payload that is not JSON at all".into(),
            CALENDAR.into(),
            "this was never a calendar".into(),
        ),
        (
            "a name and a colour that are only space".into(),
            CALENDAR.into(),
            r#"{"name":"  ","color":"   ","favorite":true}"#.into(),
        ),
        (
            "a payload from a newer schema major".into(),
            CALENDAR.into(),
            r#"{"@type":"Calendar","version":"2.0","name":"future"}"#.into(),
        ),
    ]
}

fn event_write_cases() -> Vec<(String, CoreCalendarEventDraft)> {
    let stored = stored_event();
    let parsed = event_parse(EVENT, &stored);
    let unreadable = event_parse(EVENT, &stored_unreadable_rule());
    vec![
        (
            "a timed event with nothing optional set".into(),
            CoreCalendarEventDraft {
                title: "Standup".into(),
                start: "2026-10-01T09:00:00.000Z".into(),
                ..blank_event()
            },
        ),
        (
            "an all-day event, whose end is the inclusive last day".into(),
            CoreCalendarEventDraft {
                title: "Conference".into(),
                start: "2026-10-01".into(),
                end: Some("2026-10-03".into()),
                calendar_id: Some(default_calendar_id()),
                ..blank_event()
            },
        ),
        (
            "blank optional fields, which are the same as absent ones".into(),
            CoreCalendarEventDraft {
                title: "  Standup  ".into(),
                start: " 2026-10-01T09:00:00.000Z ".into(),
                end: Some("   ".into()),
                notes: Some(String::new()),
                location: Some(" Room 3 ".into()),
                participants: vec!["  ".into(), " alice@example.com ".into()],
                calendar_id: Some("  ".into()),
                ..blank_event()
            },
        ),
        (
            "a weekly rule on five weekdays, every other week, with an end date".into(),
            CoreCalendarEventDraft {
                title: parsed.title.clone(),
                start: parsed.start.clone(),
                end: parsed.end.clone(),
                notes: parsed.notes.clone(),
                location: parsed.location.clone(),
                participants: parsed.participants.clone(),
                timezone: parsed.timezone.clone(),
                calendar_id: parsed.calendar_id.clone(),
                recurrence: parsed.recurrence.clone(),
                alerts: parsed.alerts.clone(),
                unreadable_alerts: parsed.unreadable_alerts.clone(),
                raw: Some(stored.clone()),
                ..blank_event()
            },
        ),
        (
            "the third Tuesday of every month, counted out".into(),
            CoreCalendarEventDraft {
                title: "Board".into(),
                start: "2026-10-20T16:00:00.000Z".into(),
                timezone: Some("Europe/London".into()),
                recurrence: Some(CoreRecurrence {
                    frequency: CoreRecurrenceFrequency::Monthly,
                    interval: None,
                    until: None,
                    count: Some(12),
                    weekdays: Vec::new(),
                    day_of_month: None,
                    nth_weekday: Some(CoreNthWeekday {
                        ordinal: 3,
                        weekday: 2,
                        extra: None,
                    }),
                    extra: None,
                }),
                ..blank_event()
            },
        ),
        (
            "an edit that clears the repeat, the guests, the notes and the reminders".into(),
            CoreCalendarEventDraft {
                title: parsed.title.clone(),
                start: parsed.start.clone(),
                calendar_id: parsed.calendar_id.clone(),
                raw: Some(stored),
                ..blank_event()
            },
        ),
        (
            "timed reminders out of order, one twice, one out of range".into(),
            CoreCalendarEventDraft {
                title: "Dentist".into(),
                start: "2026-10-01T09:00:00.000Z".into(),
                alerts: [15, 1440, 15, 99_999]
                    .into_iter()
                    .map(|minutes_before| CoreEventAlert {
                        minutes_before,
                        extra: None,
                    })
                    .collect(),
                ..blank_event()
            },
        ),
        (
            "all-day reminders the day before and on the day, at 09:00".into(),
            CoreCalendarEventDraft {
                title: "Birthday".into(),
                start: "2026-10-01".into(),
                alerts: [-540, 900]
                    .into_iter()
                    .map(|minutes_before| CoreEventAlert {
                        minutes_before,
                        extra: None,
                    })
                    .collect(),
                ..blank_event()
            },
        ),
        (
            "an edit to an event whose rule this build cannot name".into(),
            CoreCalendarEventDraft {
                title: "Pay day, moved".into(),
                start: unreadable.start.clone(),
                unreadable_recurrence: unreadable.unreadable_recurrence.clone(),
                raw: Some(unreadable.raw.clone()),
                ..blank_event()
            },
        ),
    ]
}

fn event_parse_cases() -> Vec<(String, String, String)> {
    vec![
        (
            "the richest payload any client writes".into(),
            EVENT.into(),
            stored_event(),
        ),
        ("an empty object".into(), EVENT.into(), "{}".into()),
        (
            "a payload that is not JSON at all".into(),
            EVENT.into(),
            "this was never an event".into(),
        ),
        (
            "a payload that is JSON but not an object".into(),
            EVENT.into(),
            "[1,2,3]".into(),
        ),
        (
            "a title that is only space, and a start that is not a string".into(),
            EVENT.into(),
            r#"{"title":"   ","start":42}"#.into(),
        ),
        (
            "guests that are not all strings".into(),
            EVENT.into(),
            r#"{"title":"t","participants":["alice@example.com",null,"  ",7]}"#.into(),
        ),
        (
            "a rule naming a frequency this build does not know".into(),
            EVENT.into(),
            stored_unreadable_rule(),
        ),
        (
            "a rule whose fields are out of range".into(),
            EVENT.into(),
            r#"{"title":"t","recurrence":{"frequency":"WEEKLY","interval":1,"weekdays":[1,9,3],"count":0,"dayOfMonth":40,"nthWeekday":{"ordinal":7,"weekday":2}}}"#.into(),
        ),
        (
            "reminders that are not all readable".into(),
            EVENT.into(),
            r#"{"title":"t","start":"2026-10-01","alerts":[{"minutesBefore":-540},"junk",{"minutesBefore":1.5},{"minutesBefore":900,"sound":"chime"},{"minutesBefore":-540}]}"#.into(),
        ),
        (
            "a payload from a newer schema major".into(),
            EVENT.into(),
            r#"{"@type":"CalendarEvent","version":"2.0","title":"future"}"#.into(),
        ),
    ]
}

fn error_name(error: &CoreError) -> String {
    error.kind().to_string()
}

#[test]
fn every_written_calendar_is_the_one_spelling_the_fixture_holds() {
    let fixture = fixture();
    assert_eq!(fixture.calendar_writes.len(), calendar_write_cases().len());
    for (expected, (case, draft)) in fixture.calendar_writes.iter().zip(calendar_write_cases()) {
        assert_eq!(expected.case, case);
        assert_eq!(expected.draft, draft, "{case}: the draft drifted");
        assert_eq!(
            calendar_write(&draft).expect("writes"),
            expected.payload,
            "{case}"
        );
    }
}

#[test]
fn every_calendar_reads_back_as_the_record_the_fixture_holds() {
    for (expected, (case, id, raw)) in fixture().calendar_parses.iter().zip(calendar_parse_cases())
    {
        assert_eq!(expected.case, case);
        assert_eq!(expected.raw, raw, "{case}: the input drifted");
        assert_eq!(calendar_parse(&id, &raw), expected.calendar, "{case}");
    }
}

#[test]
fn every_written_event_is_the_one_spelling_the_fixture_holds() {
    let fixture = fixture();
    assert_eq!(fixture.event_writes.len(), event_write_cases().len());
    for (expected, (case, draft)) in fixture.event_writes.iter().zip(event_write_cases()) {
        assert_eq!(expected.case, case);
        assert_eq!(expected.draft, draft, "{case}: the draft drifted");
        assert_eq!(
            event_write(&draft).expect("writes"),
            expected.payload,
            "{case}"
        );
    }
}

#[test]
fn every_event_reads_back_as_the_record_the_fixture_holds() {
    for (expected, (case, id, raw)) in fixture().event_parses.iter().zip(event_parse_cases()) {
        assert_eq!(expected.case, case);
        assert_eq!(expected.raw, raw, "{case}: the input drifted");
        assert_eq!(event_parse(&id, &raw), expected.event, "{case}");
    }
}

#[test]
fn the_fixture_states_the_constants_the_three_hosts_mirror() {
    let constants = fixture().constants;
    assert_eq!(constants.calendar_content_type, CALENDAR_CONTENT_TYPE);
    assert_eq!(
        constants.calendar_event_content_type,
        CALENDAR_EVENT_CONTENT_TYPE
    );
    assert_eq!(constants.calendar_keys, CALENDAR_KEYS);
    assert_eq!(constants.calendar_event_keys, CALENDAR_EVENT_KEYS);
    assert_eq!(constants.default_calendar_id, default_calendar_id());
    assert_eq!(constants.default_calendar_name, DEFAULT_CALENDAR_NAME);
    assert_eq!(constants.default_calendar_color, DEFAULT_CALENDAR_COLOR);
    assert_eq!(constants.untitled_calendar_name, UNTITLED_CALENDAR_NAME);
    assert_eq!(constants.untitled_event_title, UNTITLED_EVENT_TITLE);
    assert_eq!(constants.max_event_alerts, MAX_EVENT_ALERTS);
    assert_eq!(constants.min_alert_minutes_before, MIN_ALERT_MINUTES_BEFORE);
    assert_eq!(constants.max_alert_minutes_before, MAX_ALERT_MINUTES_BEFORE);
    assert_eq!(constants.timed_alert_presets, alert_labels(false));
    assert_eq!(constants.all_day_alert_presets, alert_labels(true));
}

/// The one refusal this layer has. Both records answer to it, because a field
/// whose meaning changed is as likely in a calendar as in an event.
#[test]
fn a_payload_from_a_newer_schema_major_is_read_but_never_written_over() {
    let refusals = fixture().refusals;

    let future = r#"{"@type":"Calendar","version":"2.0","name":"future"}"#;
    let calendar = calendar_parse(CALENDAR, future);
    assert_eq!(calendar.name, "future");
    assert!(!calendar.readable);
    let refused = calendar_write(&CoreCalendarDraft {
        name: "edited".into(),
        raw: Some(future.into()),
        ..blank_calendar()
    })
    .expect_err("refuses");
    assert_eq!(error_name(&refused), refusals[0].error);

    let future = r#"{"@type":"CalendarEvent","version":"2.0","title":"future"}"#;
    assert!(!event_parse(EVENT, future).readable);
    let refused = event_write(&CoreCalendarEventDraft {
        title: "edited".into(),
        raw: Some(future.into()),
        ..blank_event()
    })
    .expect_err("refuses");
    assert_eq!(error_name(&refused), refusals[1].error);
}

/// A calendar id an event points at that is not in the list, which is what a
/// deleted calendar leaves behind, against an event in no calendar at all.
#[test]
fn an_event_in_no_calendar_has_no_calendar_name_to_show() {
    let calendars = vec![calendar_parse(&default_calendar_id(), r#"{"name":"Mine"}"#)];
    assert_eq!(calendar_name_by_id(&calendars, None), None);
    assert_eq!(
        calendar_name_by_id(&calendars, Some(default_calendar_id())),
        Some("Mine".into())
    );
    assert_eq!(
        calendar_name_by_id(&calendars, Some(CALENDAR.into())),
        Some(DEFAULT_CALENDAR_NAME.into())
    );
}

#[test]
#[ignore = "writes the shared fixture"]
fn regenerate() {
    if std::env::var("REGENERATE_CALENDAR_FIXTURE").is_err() {
        return;
    }
    let fixture = Fixture {
        constants: Constants {
            calendar_content_type: CALENDAR_CONTENT_TYPE.into(),
            calendar_event_content_type: CALENDAR_EVENT_CONTENT_TYPE.into(),
            calendar_keys: CALENDAR_KEYS.iter().map(|key| key.to_string()).collect(),
            calendar_event_keys: CALENDAR_EVENT_KEYS
                .iter()
                .map(|key| key.to_string())
                .collect(),
            default_calendar_id: default_calendar_id(),
            default_calendar_name: DEFAULT_CALENDAR_NAME.into(),
            default_calendar_color: DEFAULT_CALENDAR_COLOR.into(),
            untitled_calendar_name: UNTITLED_CALENDAR_NAME.into(),
            untitled_event_title: UNTITLED_EVENT_TITLE.into(),
            max_event_alerts: MAX_EVENT_ALERTS,
            min_alert_minutes_before: MIN_ALERT_MINUTES_BEFORE,
            max_alert_minutes_before: MAX_ALERT_MINUTES_BEFORE,
            timed_alert_presets: alert_labels(false),
            all_day_alert_presets: alert_labels(true),
        },
        calendar_writes: calendar_write_cases()
            .into_iter()
            .map(|(case, draft)| CalendarWriteCase {
                case,
                payload: calendar_write(&draft).expect("writes"),
                draft,
            })
            .collect(),
        calendar_parses: calendar_parse_cases()
            .into_iter()
            .map(|(case, id, raw)| CalendarParseCase {
                case,
                calendar: calendar_parse(&id, &raw),
                id,
                raw,
            })
            .collect(),
        event_writes: event_write_cases()
            .into_iter()
            .map(|(case, draft)| EventWriteCase {
                case,
                payload: event_write(&draft).expect("writes"),
                draft,
            })
            .collect(),
        event_parses: event_parse_cases()
            .into_iter()
            .map(|(case, id, raw)| EventParseCase {
                case,
                event: event_parse(&id, &raw),
                id,
                raw,
            })
            .collect(),
        refusals: vec![
            RefusalCase {
                case: "editing a calendar from a newer schema major".into(),
                error: "PayloadSchema".into(),
            },
            RefusalCase {
                case: "editing an event from a newer schema major".into(),
                error: "PayloadSchema".into(),
            },
        ],
    };

    std::fs::create_dir_all("../sealbook-protocol/fixtures/payloads").unwrap();
    std::fs::write(
        FIXTURE,
        format!("{}\n", serde_json::to_string_pretty(&fixture).unwrap()),
    )
    .unwrap();
}
