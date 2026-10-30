//! The calendar and event payloads: which keys a writer owns, how one is
//! written, and how one is read back.
//!
//! Calendars are the second content type to move here, and the one the plan put
//! next because three writers were held together by nothing but a parity test
//! over three literal payloads: the web wrote whatever its view model carried,
//! Android trimmed and omitted, and the CLI rebuilt a calendar from scratch on
//! every rename.
//!
//! The rules are [`crate::payload`]'s, as they are for every type here. One
//! owned set per record, which is the union of every key any client writes.
//! Absent is omitted, never null. And a payload declaring a schema major this
//! build does not read is read but never written over.
//!
//! Two decisions are this type's own.
//!
//! **A recurrence rule this build cannot name is dropped, not guessed at.**
//! That is Android's rule and it is the right one: a single event on the grid is
//! wrong but visible, where a rule read as "the nearest frequency we know"
//! invents a series on dates the client that wrote it never meant. The dropped
//! rule still survives the round trip, because it comes back in
//! [`CoreCalendarEvent::unreadable_recurrence`] and the writer puts it back
//! verbatim. Android dropped it: it parsed the rule to null and `recurrence` is
//! an owned key, so the next save from the phone turned a series written by a
//! newer client into a single event on every device.
//!
//! **An event with no `calendarId` stays that way.** The CLI resolved a missing
//! one to the default calendar and the other two left it absent, and absent is
//! what the web's grid reads as "in no calendar, so never hidden by a calendar
//! toggle". Resolving it here would have moved every such event into the
//! default calendar, which is a visibility change rather than a spelling one, so
//! the default stays the CLI's own: it passes the id it wants.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::payload::{
    as_object, declared_readable, entry_with, extra_of, refuse_newer_major, trimmed, write_payload,
};
use crate::CoreError;
use sealbook_protocol::PAYLOAD_SCHEMA_VERSION;

pub use sealbook_protocol::{
    CALENDAR_CONTENT_TYPE, CALENDAR_EVENT_CONTENT_TYPE, DEFAULT_CALENDAR_COLOR,
    DEFAULT_CALENDAR_NAME,
};

/// What a calendar with no readable name is listed as, unless it is the default
/// one: see [`calendar_parse`].
pub const UNTITLED_CALENDAR_NAME: &str = "Untitled calendar";

pub const UNTITLED_EVENT_TITLE: &str = "Untitled event";

/// The default calendar's id, as a string, since that is how every host holds an
/// event's `calendarId`: the field is read leniently and a value that is not a
/// UUID is carried rather than rewritten.
pub fn default_calendar_id() -> String {
    sealbook_protocol::DEFAULT_CALENDAR_ID.to_string()
}

/// Every key a calendar writer owns.
pub const CALENDAR_KEYS: &[&str] = &["@type", "version", "name", "color", "favorite", "archived"];

/// Every key an event writer owns.
pub const CALENDAR_EVENT_KEYS: &[&str] = &[
    "@type",
    "version",
    "title",
    "start",
    "end",
    "notes",
    "location",
    "participants",
    "timezone",
    "calendarId",
    "recurrence",
];

/// How often a rule repeats.
///
/// Deliberately narrower than an RFC 5545 `FREQ`: it carries what every client
/// can render identically. An imported rule beyond this is reduced to the
/// closest thing here or dropped, rather than stored as text no other client
/// would honour.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum CoreRecurrenceFrequency {
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

impl CoreRecurrenceFrequency {
    fn wire(self) -> &'static str {
        match self {
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
            Self::Yearly => "yearly",
        }
    }

    pub(crate) fn from_wire(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "daily" => Some(Self::Daily),
            "weekly" => Some(Self::Weekly),
            "monthly" => Some(Self::Monthly),
            "yearly" => Some(Self::Yearly),
            _ => None,
        }
    }
}

/// Which occurrence of a weekday within a month a monthly rule lands on, as in
/// "the third Tuesday". `ordinal` is 1 to 5 and `weekday` is 0 (Sunday) to 6.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreNthWeekday {
    pub ordinal: u32,
    pub weekday: u32,
}

/// A repeat rule, in the shape the payload stores it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreRecurrence {
    pub frequency: CoreRecurrenceFrequency,
    /// Omitted below 2, since every rule repeats at least once per period.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<u32>,
    /// Inclusive last day, as `YYYY-MM-DD`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    /// 0 (Sunday) to 6, for weekly rules. Empty is written as no key at all,
    /// but it is always present on the record, as `participants` is: an absent
    /// list and an empty one mean the same thing to a host and a required field
    /// is one less shape for a binding to get wrong.
    pub weekdays: Vec<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub day_of_month: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nth_weekday: Option<CoreNthWeekday>,
    /// Keys of the stored rule this build does not write, as a JSON object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub extra: Option<String>,
}

/// One calendar as it is drafted, before it is written.
///
/// A host editing an existing calendar builds this from [`calendar_parse`] and
/// changes the fields its UI owns, which is what carries a field it cannot show.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreCalendarDraft {
    pub name: String,
    /// Hex, as the pickers hand it over. A blank one takes
    /// [`DEFAULT_CALENDAR_COLOR`] rather than being written empty, since a
    /// calendar with no colour has no dot on any client.
    pub color: String,
    pub favorite: bool,
    /// Put away: out of the lists and the pickers, with its events left in the
    /// vault untouched. Written only when set, so a calendar that has never been
    /// archived is byte-identical to one from a build predating the field.
    pub archived: bool,
    /// The payload this draft came from, when it came from one. The write merges
    /// onto it. `None` for a calendar written from scratch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

/// One calendar as it was read back.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreCalendar {
    pub id: String,
    pub name: String,
    pub color: String,
    pub favorite: bool,
    pub archived: bool,
    /// Whether this build reads the schema major the payload declares. False
    /// means the fields above were still read, because a lenient parse beats a
    /// blank row, but [`calendar_write`] will refuse to write over it.
    pub readable: bool,
    pub raw: String,
}

/// One event as it is drafted, before it is written.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreCalendarEventDraft {
    pub title: String,
    /// A timed event is a UTC instant (`2026-10-01T09:00:00Z`) and an all-day
    /// event is a plain local date (`2026-10-01`) whose `end` is **inclusive**.
    /// The shape carries the distinction, so there is no all-day flag to drift.
    pub start: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// Empty writes no `participants` key at all.
    pub participants: Vec<String>,
    /// The zone a timed instant was composed in, so an event keeps its
    /// wall-clock time when the device moves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calendar_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recurrence: Option<CoreRecurrence>,
    /// The stored rule this build could not name, as JSON, carried from
    /// [`CoreCalendarEvent::unreadable_recurrence`] so the write puts it back.
    /// `recurrence` wins where both are set, so a host replacing the rule need
    /// only set its own; a host clearing the repeat clears both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable_recurrence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

/// One event as it was read back.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreCalendarEvent {
    pub id: String,
    pub title: String,
    pub start: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    pub participants: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calendar_id: Option<String>,
    /// `None` both for an event that does not repeat and for one whose rule
    /// names a frequency this build does not know; the second case comes back in
    /// `unreadable_recurrence` instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recurrence: Option<CoreRecurrence>,
    /// The stored rule this build could not name, as JSON. No host reads it; it
    /// exists so a write can put back what it could not understand, which is the
    /// degrade-invisibly rule one level in from the payload, as
    /// `CoreNoteAttachment::extra` is for a photo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable_recurrence: Option<String>,
    pub readable: bool,
    pub raw: String,
}

/// Reads a stored calendar payload.
///
/// Lenient throughout: a payload that is not JSON, or that is JSON but not an
/// object, comes back as a named row rather than taking the list down, because a
/// calendar the user cannot see is one they cannot delete.
pub fn calendar_parse(id: &str, raw: &str) -> CoreCalendar {
    let object = as_object(raw);
    let field = |key: &str| object.as_ref().and_then(|object| trimmed(object, key));
    let flag = |key: &str| {
        object
            .as_ref()
            .and_then(|object| object.get(key))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    };
    CoreCalendar {
        id: id.to_string(),
        name: field("name").unwrap_or_else(|| fallback_calendar_name(id)),
        color: field("color").unwrap_or_else(|| DEFAULT_CALENDAR_COLOR.to_string()),
        favorite: flag("favorite"),
        archived: flag("archived"),
        readable: object.as_ref().map(declared_readable).unwrap_or(true),
        raw: raw.to_string(),
    }
}

/// Serialises a calendar, merging onto whatever `draft.raw` carried.
pub fn calendar_write(draft: &CoreCalendarDraft) -> Result<String, CoreError> {
    refuse_newer_major(draft.raw.as_deref())?;

    let mut fields = Map::new();
    fields.insert("@type".into(), json!("Calendar"));
    fields.insert("version".into(), json!(PAYLOAD_SCHEMA_VERSION));
    fields.insert("name".into(), json!(draft.name.trim()));
    fields.insert("color".into(), json!(calendar_color(&draft.color)));
    fields.insert("favorite".into(), json!(draft.favorite));
    if draft.archived {
        fields.insert("archived".into(), json!(true));
    }
    Ok(write_payload(
        draft.raw.as_deref(),
        Value::Object(fields),
        CALENDAR_KEYS,
    ))
}

/// Reads a stored event payload.
pub fn event_parse(id: &str, raw: &str) -> CoreCalendarEvent {
    let Some(object) = as_object(raw) else {
        return CoreCalendarEvent {
            id: id.to_string(),
            title: UNTITLED_EVENT_TITLE.to_string(),
            start: String::new(),
            end: None,
            notes: None,
            location: None,
            participants: Vec::new(),
            timezone: None,
            calendar_id: None,
            recurrence: None,
            unreadable_recurrence: None,
            readable: true,
            raw: raw.to_string(),
        };
    };
    CoreCalendarEvent {
        id: id.to_string(),
        title: trimmed(&object, "title").unwrap_or_else(|| UNTITLED_EVENT_TITLE.to_string()),
        start: trimmed(&object, "start").unwrap_or_default(),
        end: trimmed(&object, "end"),
        notes: trimmed(&object, "notes"),
        location: trimmed(&object, "location"),
        participants: parse_participants(object.get("participants")),
        timezone: trimmed(&object, "timezone"),
        calendar_id: trimmed(&object, "calendarId"),
        recurrence: stored_rule(&object).and_then(parse_recurrence),
        unreadable_recurrence: stored_rule(&object)
            .filter(|stored| parse_recurrence(stored).is_none())
            .map(|stored| Value::Object(stored.clone()).to_string()),
        readable: declared_readable(&object),
        raw: raw.to_string(),
    }
}

/// Serialises an event, merging onto whatever `draft.raw` carried.
pub fn event_write(draft: &CoreCalendarEventDraft) -> Result<String, CoreError> {
    refuse_newer_major(draft.raw.as_deref())?;

    let mut fields = Map::new();
    fields.insert("@type".into(), json!("CalendarEvent"));
    fields.insert("version".into(), json!(PAYLOAD_SCHEMA_VERSION));
    fields.insert("title".into(), json!(draft.title.trim()));
    fields.insert("start".into(), json!(draft.start.trim()));
    for (key, value) in [
        ("end", &draft.end),
        ("notes", &draft.notes),
        ("location", &draft.location),
        ("timezone", &draft.timezone),
        ("calendarId", &draft.calendar_id),
    ] {
        if let Some(value) = present(value) {
            fields.insert(key.into(), json!(value));
        }
    }
    let participants = trimmed_list(&draft.participants);
    if !participants.is_empty() {
        fields.insert("participants".into(), json!(participants));
    }
    if let Some(rule) = &draft.recurrence {
        fields.insert("recurrence".into(), recurrence_json(rule));
    } else if let Some(stored) = draft.unreadable_recurrence.as_deref().and_then(as_object) {
        fields.insert("recurrence".into(), Value::Object(stored));
    }
    Ok(write_payload(
        draft.raw.as_deref(),
        Value::Object(fields),
        CALENDAR_EVENT_KEYS,
    ))
}

/// The name to show for an event's calendar, when the calendar list is in hand.
///
/// An event pointing at a calendar that is not in the list, which is what a
/// deleted calendar leaves behind, shows the default calendar's name rather than
/// nothing. An event in no calendar at all has no name to show.
pub fn calendar_name_by_id(
    calendars: &[CoreCalendar],
    calendar_id: Option<String>,
) -> Option<String> {
    let id = present(&calendar_id)?;
    Some(
        calendars
            .iter()
            .find(|calendar| calendar.id == id)
            .map(|calendar| calendar.name.clone())
            .unwrap_or_else(|| DEFAULT_CALENDAR_NAME.to_string()),
    )
}

/// The default calendar is the one every client creates for itself, so an
/// unnamed one is that name rather than `Untitled calendar`: the same rule the
/// default notebook takes, and for the same reason. Two clients that disagreed
/// here showed the one calendar every account has under two names.
fn fallback_calendar_name(id: &str) -> String {
    if id == default_calendar_id() {
        DEFAULT_CALENDAR_NAME.to_string()
    } else {
        UNTITLED_CALENDAR_NAME.to_string()
    }
}

fn calendar_color(color: &str) -> String {
    let color = color.trim();
    if color.is_empty() {
        DEFAULT_CALENDAR_COLOR.to_string()
    } else {
        color.to_string()
    }
}

pub(crate) fn present(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn trimmed_list(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_participants(value: Option<&Value>) -> Vec<String> {
    let Some(entries) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// A stored rule, or `None` where it names a frequency this build does not know.
///
/// The fields are each dropped rather than clamped when they are out of range: a
/// weekday of 9 or a 40th of the month is a rule no client can expand, and
/// keeping the rest of a rule is closer to what was meant than guessing at the
/// part that will not read.
const RECURRENCE_KEYS: &[&str] = &[
    "frequency",
    "interval",
    "until",
    "count",
    "weekdays",
    "dayOfMonth",
    "nthWeekday",
];

pub(crate) fn parse_recurrence(object: &Map<String, Value>) -> Option<CoreRecurrence> {
    let frequency = object
        .get("frequency")
        .and_then(Value::as_str)
        .and_then(CoreRecurrenceFrequency::from_wire)?;
    let number = |key: &str| object.get(key).and_then(Value::as_u64);
    let weekdays = object
        .get("weekdays")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(Value::as_u64)
                .filter(|day| *day <= 6)
                .map(|day| day as u32)
                .collect::<Vec<u32>>()
        })
        .unwrap_or_default();
    let nth_weekday = object
        .get("nthWeekday")
        .and_then(Value::as_object)
        .and_then(|nth| {
            let ordinal = nth.get("ordinal").and_then(Value::as_u64)?;
            let weekday = nth.get("weekday").and_then(Value::as_u64)?;
            ((1..=5).contains(&ordinal) && weekday <= 6).then_some(CoreNthWeekday {
                ordinal: ordinal as u32,
                weekday: weekday as u32,
            })
        });
    Some(CoreRecurrence {
        frequency,
        interval: number("interval")
            .filter(|interval| *interval > 1)
            .map(|interval| interval as u32),
        until: trimmed(object, "until"),
        count: number("count")
            .filter(|count| *count > 0)
            .map(|count| count as u32),
        weekdays,
        day_of_month: number("dayOfMonth")
            .filter(|day| (1..=31).contains(day))
            .map(|day| day as u32),
        nth_weekday,
        extra: extra_of(object, RECURRENCE_KEYS),
    })
}

pub(crate) fn stored_rule(object: &Map<String, Value>) -> Option<&Map<String, Value>> {
    object.get("recurrence").and_then(Value::as_object)
}

pub(crate) fn recurrence_json(rule: &CoreRecurrence) -> Value {
    let mut object = entry_with(&rule.extra);
    object.insert("frequency".into(), json!(rule.frequency.wire()));
    if let Some(interval) = rule.interval.filter(|interval| *interval > 1) {
        object.insert("interval".into(), json!(interval));
    }
    if let Some(until) = present(&rule.until) {
        object.insert("until".into(), json!(until));
    }
    if let Some(count) = rule.count.filter(|count| *count > 0) {
        object.insert("count".into(), json!(count));
    }
    if !rule.weekdays.is_empty() {
        object.insert("weekdays".into(), json!(rule.weekdays));
    }
    if let Some(day) = rule.day_of_month {
        object.insert("dayOfMonth".into(), json!(day));
    }
    if let Some(nth) = rule.nth_weekday {
        object.insert(
            "nthWeekday".into(),
            json!({ "ordinal": nth.ordinal, "weekday": nth.weekday }),
        );
    }
    Value::Object(object)
}

/// Everything above, in the shapes the bindings can carry.
#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{
        CoreCalendar, CoreCalendarDraft, CoreCalendarEvent, CoreCalendarEventDraft, CoreError,
    };

    #[uniffi::export(name = "calendar_keys")]
    pub fn calendar_keys() -> Vec<String> {
        super::CALENDAR_KEYS
            .iter()
            .map(|key| key.to_string())
            .collect()
    }

    #[uniffi::export(name = "calendar_event_keys")]
    pub fn calendar_event_keys() -> Vec<String> {
        super::CALENDAR_EVENT_KEYS
            .iter()
            .map(|key| key.to_string())
            .collect()
    }

    #[uniffi::export(name = "default_calendar_id")]
    pub fn default_calendar_id() -> String {
        super::default_calendar_id()
    }

    #[uniffi::export(name = "calendar_parse")]
    pub fn calendar_parse(id: String, raw: String) -> CoreCalendar {
        super::calendar_parse(&id, &raw)
    }

    #[uniffi::export(name = "calendar_write")]
    pub fn calendar_write(draft: CoreCalendarDraft) -> Result<String, CoreError> {
        super::calendar_write(&draft)
    }

    #[uniffi::export(name = "event_parse")]
    pub fn event_parse(id: String, raw: String) -> CoreCalendarEvent {
        super::event_parse(&id, &raw)
    }

    #[uniffi::export(name = "event_write")]
    pub fn event_write(draft: CoreCalendarEventDraft) -> Result<String, CoreError> {
        super::event_write(&draft)
    }

    #[uniffi::export(name = "calendar_name_by_id")]
    pub fn calendar_name_by_id(
        calendars: Vec<CoreCalendar>,
        calendar_id: Option<String>,
    ) -> Option<String> {
        super::calendar_name_by_id(&calendars, calendar_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(payload: &str) -> Map<String, Value> {
        match serde_json::from_str::<Value>(payload).unwrap() {
            Value::Object(object) => object,
            other => panic!("not an object: {other}"),
        }
    }

    fn draft() -> CoreCalendarDraft {
        CoreCalendarDraft {
            name: "Work".into(),
            color: DEFAULT_CALENDAR_COLOR.into(),
            ..Default::default()
        }
    }

    fn event() -> CoreCalendarEventDraft {
        CoreCalendarEventDraft {
            title: "Standup".into(),
            start: "2026-10-01T09:00:00.000Z".into(),
            ..Default::default()
        }
    }

    #[test]
    fn a_calendar_that_was_never_archived_carries_no_archived_key() {
        let written = parsed(&calendar_write(&draft()).unwrap());
        assert!(!written.contains_key("archived"));
        assert_eq!(written["favorite"], false);
    }

    /// The CLI's `put_calendar` rebuilt the payload rather than merging onto it,
    /// so a rename from the CLI dropped the colour, the favourite flag and the
    /// archived flag the other clients had written.
    #[test]
    fn a_rename_keeps_what_the_renaming_host_did_not_change() {
        let stored = calendar_write(&CoreCalendarDraft {
            favorite: true,
            archived: true,
            color: "#9ece6a".into(),
            ..draft()
        })
        .unwrap();
        let mut from_a_later_build = parsed(&stored);
        from_a_later_build.insert("shared".into(), json!({ "with": "someone" }));
        let stored = Value::Object(from_a_later_build).to_string();

        let calendar = calendar_parse("c1", &stored);
        let renamed = parsed(
            &calendar_write(&CoreCalendarDraft {
                name: "Renamed".into(),
                color: calendar.color,
                favorite: calendar.favorite,
                archived: calendar.archived,
                raw: Some(stored),
            })
            .unwrap(),
        );
        assert_eq!(renamed["name"], "Renamed");
        assert_eq!(renamed["color"], "#9ece6a");
        assert_eq!(renamed["favorite"], true);
        assert_eq!(renamed["archived"], true);
        assert_eq!(renamed["shared"], json!({ "with": "someone" }));
    }

    #[test]
    fn a_blank_colour_takes_the_one_every_client_defaults_to() {
        let written = parsed(
            &calendar_write(&CoreCalendarDraft {
                color: "   ".into(),
                ..draft()
            })
            .unwrap(),
        );
        assert_eq!(written["color"], DEFAULT_CALENDAR_COLOR);
    }

    #[test]
    fn an_unnamed_default_calendar_is_the_one_name_every_account_sees() {
        assert_eq!(
            calendar_parse(&default_calendar_id(), "{}").name,
            DEFAULT_CALENDAR_NAME
        );
        assert_eq!(calendar_parse("c1", "{}").name, UNTITLED_CALENDAR_NAME);
        assert_eq!(
            calendar_parse("c1", "not json").name,
            UNTITLED_CALENDAR_NAME
        );
    }

    /// Absent optional values are omitted rather than written null, which is
    /// what a reader predating a field expects to see. The CLI wrote nulls.
    #[test]
    fn an_event_with_nothing_optional_set_carries_only_what_it_has() {
        let written = parsed(&event_write(&event()).unwrap());
        assert_eq!(
            written.keys().map(String::as_str).collect::<Vec<_>>(),
            ["@type", "start", "title", "version"]
        );
    }

    #[test]
    fn an_events_blank_optional_fields_are_the_same_as_absent_ones() {
        let written = parsed(
            &event_write(&CoreCalendarEventDraft {
                end: Some("   ".into()),
                notes: Some(String::new()),
                participants: vec!["  ".into(), " alice@example.com ".into()],
                calendar_id: Some("  ".into()),
                ..event()
            })
            .unwrap(),
        );
        assert!(!written.contains_key("end"));
        assert!(!written.contains_key("notes"));
        assert!(!written.contains_key("calendarId"));
        assert_eq!(written["participants"], json!(["alice@example.com"]));
    }

    #[test]
    fn a_rule_naming_a_frequency_this_build_does_not_know_is_dropped_not_guessed_at() {
        let stored = r#"{"@type":"CalendarEvent","version":"1.0","title":"t","start":"2026-10-01","recurrence":{"frequency":"hourly","interval":3}}"#;
        let event = event_parse("e1", stored);
        assert_eq!(event.recurrence, None);

        // And it survives, because the writer puts back what it could not read.
        let written = parsed(
            &event_write(&CoreCalendarEventDraft {
                title: event.title,
                start: event.start,
                unreadable_recurrence: event.unreadable_recurrence,
                raw: Some(event.raw),
                ..Default::default()
            })
            .unwrap(),
        );
        assert_eq!(
            written["recurrence"],
            json!({ "frequency": "hourly", "interval": 3 })
        );
    }

    #[test]
    fn a_rule_field_out_of_range_is_dropped_and_the_rest_of_the_rule_reads() {
        let stored = r#"{"recurrence":{"frequency":"WEEKLY","interval":1,"weekdays":[1,9,3],"count":0,"dayOfMonth":40,"nthWeekday":{"ordinal":7,"weekday":2}}}"#;
        let rule = event_parse("e1", stored).recurrence.expect("a rule");
        assert_eq!(rule.frequency, CoreRecurrenceFrequency::Weekly);
        assert_eq!(rule.interval, None);
        assert_eq!(rule.weekdays, vec![1, 3]);
        assert_eq!(rule.count, None);
        assert_eq!(rule.day_of_month, None);
        assert_eq!(rule.nth_weekday, None);
    }

    #[test]
    fn a_payload_that_is_not_an_object_still_reads_as_a_row_the_user_can_delete() {
        for raw in ["", "not json", "[1,2]", "null"] {
            let event = event_parse("e1", raw);
            assert_eq!(event.title, UNTITLED_EVENT_TITLE);
            assert_eq!(event.raw, raw);
            assert!(event.readable);
        }
    }

    #[test]
    fn a_payload_from_a_newer_schema_major_is_read_but_never_written_over() {
        let future = r#"{"@type":"CalendarEvent","version":"2.0","title":"future"}"#;
        let stored = event_parse("e1", future);
        assert_eq!(stored.title, "future");
        assert!(!stored.readable);
        assert!(matches!(
            event_write(&CoreCalendarEventDraft {
                raw: Some(future.into()),
                ..event()
            }),
            Err(CoreError::PayloadSchema { .. })
        ));

        let future = r#"{"@type":"Calendar","version":"3.1","name":"future"}"#;
        assert!(!calendar_parse("c1", future).readable);
        assert!(matches!(
            calendar_write(&CoreCalendarDraft {
                raw: Some(future.into()),
                ..draft()
            }),
            Err(CoreError::PayloadSchema { .. })
        ));
    }

    #[test]
    fn an_event_in_no_calendar_has_no_calendar_name_to_show() {
        let calendars = vec![calendar_parse(&default_calendar_id(), r#"{"name":"Mine"}"#)];
        assert_eq!(calendar_name_by_id(&calendars, None), None);
        assert_eq!(
            calendar_name_by_id(&calendars, Some(default_calendar_id())),
            Some("Mine".into())
        );
        assert_eq!(
            calendar_name_by_id(&calendars, Some("gone".into())),
            Some(DEFAULT_CALENDAR_NAME.into())
        );
    }
}
