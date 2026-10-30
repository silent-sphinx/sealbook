//! iCalendar (RFC 5545) import and export.
//!
//! One reader and one writer for every client. The reader is forgiving, because
//! real `.ics` files carry HTML descriptions, mailto attendees and rules richer
//! than the protocol stores, and lossy in one direction only: a rule that cannot
//! be expressed as a [`CoreRecurrence`] is dropped rather than approximated, so
//! an imported series never lands on days the file did not name.
//!
//! Core has no zone database, so a time written in a zone comes back as the local
//! wall-clock time plus the zone's name, and the host turns it into an instant.
//! A time written in UTC, and an all-day date, come back final.

use serde::{Deserialize, Serialize};

use crate::calendars::{
    CoreCalendarEventDraft, CoreNthWeekday, CoreRecurrence, CoreRecurrenceFrequency,
    UNTITLED_EVENT_TITLE,
};
use crate::recurrence::{civil_from_days, format_day, parse_day, weekday, Day};
use crate::vcard::{trim, unescape};

/// One event read from a calendar file.
///
/// `start` and `end` are each one of: a plain date (`2026-10-01`, an all-day
/// event, with `end` already inclusive), a UTC instant (`2026-10-01T09:00:00Z`),
/// or a local wall-clock time with no zone (`2026-10-01T09:00:00`), which the host
/// resolves in `start_zone` or `end_zone`, or its own zone where that is absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreIcsEvent {
    pub title: String,
    pub start: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
    /// The `TZID` of `DTSTART`, which is also the zone the event is stored in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_zone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_zone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    pub participants: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recurrence: Option<CoreRecurrence>,
}

/// An event the file held that could not be used, and why, so a host can say so
/// rather than lose it quietly. One unreadable date in an export of hundreds must
/// not cost the rest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreIcsSkipped {
    pub title: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreIcsImport {
    pub events: Vec<CoreIcsEvent>,
    pub skipped: Vec<CoreIcsSkipped>,
    /// Events that repeat by a rule Sealbook cannot express; they import as
    /// single events.
    pub dropped_rules: u32,
}

/// An event to write out, with the id its `UID` is made from.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreIcsExportEvent {
    pub id: String,
    pub event: CoreCalendarEventDraft,
}

struct Property {
    value: String,
    params: Vec<(String, String)>,
}

impl Property {
    fn param(&self, key: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }
}

type Fields = Vec<(String, Vec<Property>)>;

fn first<'a>(fields: &'a Fields, name: &str) -> Option<&'a Property> {
    fields
        .iter()
        .find(|(key, _)| key == name)
        .and_then(|(_, list)| list.first())
}

fn unfold(input: &str) -> Vec<String> {
    input
        .replace("\r\n ", "")
        .replace("\r\n\t", "")
        .replace("\n ", "")
        .replace("\n\t", "")
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line).to_string())
        .collect()
}

fn properties(lines: &[String]) -> Fields {
    let mut fields: Fields = Vec::new();
    for line in lines {
        let Some(separator) = line.find(':').filter(|at| *at >= 1) else {
            continue;
        };
        let (name_part, value) = (&line[..separator], &line[separator + 1..]);
        let mut parts = name_part.split(';');
        let name = parts.next().unwrap_or("").to_uppercase();
        let mut params: Vec<(String, String)> = Vec::new();
        for parameter in parts {
            if let Some(equals) = parameter.find('=').filter(|at| *at > 0) {
                let value = &parameter[equals + 1..];
                let value = value.strip_prefix('"').unwrap_or(value);
                let value = value.strip_suffix('"').unwrap_or(value);
                let key = parameter[..equals].to_uppercase();
                match params.iter_mut().find(|(existing, _)| *existing == key) {
                    Some(slot) => slot.1 = value.to_string(),
                    None => params.push((key, value.to_string())),
                }
            }
        }
        let property = Property {
            value: value.to_string(),
            params,
        };
        match fields.iter_mut().find(|(key, _)| *key == name) {
            Some((_, list)) => list.push(property),
            None => fields.push((name, vec![property])),
        }
    }
    fields
}

/// Text as `encodeURIComponent` would have written it, decoded; the original
/// where a `%` is not followed by a valid escape.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let pair = bytes.get(i + 1..i + 3).and_then(|hex| {
            let hex = std::str::from_utf8(hex).ok()?;
            u8::from_str_radix(hex, 16).ok()
        });
        match pair {
            Some(byte) => {
                out.push(byte);
                i += 3;
            }
            None => return text.to_string(),
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| text.to_string())
}

fn starts_with_ci(text: &str, prefix: &str) -> bool {
    text.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

/// Replaces each tag `open` + spaces + optional `/` + `>` with a line break.
fn break_on(text: &str, open: &str, allow_slash: bool) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find('<') {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        let mut matched = None;
        if starts_with_ci(tail, open) {
            let mut after = &tail[open.len()..];
            after = after.trim_start_matches(|c: char| c.is_whitespace());
            if allow_slash {
                after = after.strip_prefix('/').unwrap_or(after);
            }
            matched = after.strip_prefix('>');
        }
        match matched {
            Some(after) => {
                out.push('\n');
                rest = after;
            }
            None => {
                out.push('<');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn strip_tags(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find('<') {
        out.push_str(&rest[..at]);
        match rest[at..].find('>') {
            Some(end) => rest = &rest[at + end + 1..],
            None => {
                out.push_str(&rest[at..]);
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

fn replace_ci(text: &str, needle: &str, with: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest
        .char_indices()
        .map(|(at, _)| at)
        .find(|at| starts_with_ci(&rest[*at..], needle))
    {
        out.push_str(&rest[..at]);
        out.push_str(with);
        rest = &rest[at + needle.len()..];
    }
    out.push_str(rest);
    out
}

/// An ICS TEXT value as something worth showing.
///
/// Calendar services put an HTML description in `DESCRIPTION` or `X-ALT-DESC`;
/// left alone, importing an invitation filled the notes with markup. Tags and the
/// handful of entities that appear in practice are reduced to text, and anything
/// else is kept as written.
fn decode_text(value: &str) -> String {
    let decoded = percent_decode(&unescape(value));
    let decoded = if starts_with_ci(&decoded, "text/html") {
        let rest = decoded["text/html".len()..].trim_start();
        rest.strip_prefix(',')
            .map(str::to_string)
            .unwrap_or(decoded)
    } else {
        decoded
    };
    let decoded = break_on(&decoded, "<br", true);
    let decoded = break_on(&decoded, "</p", false);
    let decoded = strip_tags(&decoded);
    let decoded = replace_ci(&decoded, "&nbsp;", " ");
    let decoded = replace_ci(&decoded, "&amp;", "&");
    let decoded = replace_ci(&decoded, "&lt;", "<");
    let decoded = replace_ci(&decoded, "&gt;", ">");
    let decoded = replace_ci(&decoded, "&quot;", "\"");
    let decoded = decoded.replace("&#39;", "'");
    trim(&decoded).to_string()
}

fn location_of(value: &str) -> Option<String> {
    let location = decode_text(value);
    let location = if starts_with_ci(&location, "location") {
        let rest = location["location".len()..].trim_start();
        rest.strip_prefix(':')
            .map(|after| after.to_string())
            .unwrap_or(location)
    } else {
        location
    };
    let location = trim(&location);
    (!location.is_empty()).then(|| location.to_string())
}

struct Moment {
    value: String,
    all_day: bool,
}

fn digits(text: &str) -> Option<i64> {
    (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}

fn parse_moment(property: &Property) -> Result<Moment, String> {
    let raw = trim(&property.value);
    let unsupported = || format!("Unsupported ICS date: {raw}");
    let date_part = |text: &str| -> Option<String> {
        let (y, m, d) = (
            digits(text.get(..4)?)?,
            digits(text.get(4..6)?)?,
            digits(text.get(6..8)?)?,
        );
        let day = parse_day(&format!("{y:04}-{m:02}-{d:02}"))?;
        Some(format_day(day))
    };
    let is_date = property
        .param("VALUE")
        .is_some_and(|v| v.eq_ignore_ascii_case("DATE"));
    if is_date || raw.len() == 8 {
        return date_part(raw)
            .map(|value| Moment {
                value,
                all_day: true,
            })
            .ok_or_else(unsupported);
    }
    let (body, utc) = match raw.strip_suffix('Z') {
        Some(body) => (body, true),
        None => (raw, false),
    };
    let well_formed = body.len() >= 13
        && body.is_char_boundary(8)
        && body.as_bytes()[8] == b'T'
        && matches!(body.len(), 13 | 15);
    if !well_formed {
        return Err(unsupported());
    }
    let day = date_part(body).ok_or_else(unsupported)?;
    let time = &body[9..];
    let hour = digits(&time[..2]).filter(|h| *h < 24);
    let minute = digits(&time[2..4]).filter(|m| *m < 60);
    let second = if time.len() == 4 {
        Some(0)
    } else {
        digits(&time[4..6]).filter(|s| *s < 60)
    };
    match (hour, minute, second) {
        (Some(h), Some(m), Some(s)) => Ok(Moment {
            value: format!("{day}T{h:02}:{m:02}:{s:02}{}", if utc { "Z" } else { "" }),
            all_day: false,
        }),
        _ => Err(unsupported()),
    }
}

fn parse_weekday(value: &str) -> Option<u32> {
    let tail: String = value
        .chars()
        .rev()
        .take(2)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    ["SU", "MO", "TU", "WE", "TH", "FR", "SA"]
        .iter()
        .position(|name| name.eq_ignore_ascii_case(&tail))
        .map(|at| at as u32)
}

/// A rule as a [`CoreRecurrence`], or `None` when the protocol cannot express it.
///
/// `BYSETPOS`, `BYMONTH`, several `BYDAY` ordinals and the rest have no stored
/// equivalent; the parts that do are read and the rest ignored.
pub fn ics_rrule(rule: &str, start: &str) -> Option<CoreRecurrence> {
    if trim(rule).is_empty() {
        return None;
    }
    let values: Vec<(String, &str)> = rule
        .split(';')
        .filter_map(|part| {
            let equals = part.find('=').filter(|at| *at > 0)?;
            Some((part[..equals].to_uppercase(), &part[equals + 1..]))
        })
        .collect();
    let get = |key: &str| {
        values
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| *value)
    };

    let frequency = CoreRecurrenceFrequency::from_wire(get("FREQ")?)?;
    let until = get("UNTIL")
        .map(|v| v.strip_suffix('Z').unwrap_or(v))
        .filter(|v| v.len() >= 8 && v.is_char_boundary(8))
        .and_then(|v| {
            let (y, m, d) = (digits(&v[..4])?, digits(&v[4..6])?, digits(&v[6..8])?);
            parse_day(&format!("{y:04}-{m:02}-{d:02}")).map(format_day)
        });
    let start_day = parse_day(start)?;
    let mut weekdays = Vec::new();
    let mut day_of_month = None;
    let mut nth_weekday = None;

    match frequency {
        CoreRecurrenceFrequency::Weekly => {
            weekdays = get("BYDAY")
                .map(|v| v.split(',').filter_map(parse_weekday).collect())
                .unwrap_or_default();
            if weekdays.is_empty() {
                weekdays = vec![weekday(start_day) as u32];
            }
        }
        CoreRecurrenceFrequency::Monthly => {
            if let Some(by_day) = get("BYDAY").filter(|v| !v.contains(',')) {
                let ordinal = by_day
                    .trim_start_matches('+')
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect::<String>()
                    .parse::<u32>()
                    .ok()
                    .filter(|_| !by_day.starts_with('-'));
                if let (Some(weekday), Some(ordinal)) = (parse_weekday(by_day), ordinal) {
                    if (1..=5).contains(&ordinal) {
                        nth_weekday = Some(CoreNthWeekday { ordinal, weekday });
                    }
                }
            }
            day_of_month = get("BYMONTHDAY")
                .and_then(|v| v.parse::<u32>().ok())
                .filter(|d| (1..=31).contains(d));
            if day_of_month.is_none() && nth_weekday.is_none() {
                let (_, _, date) = civil_from_days(start_day.0);
                day_of_month = Some(date as u32);
            }
        }
        _ => {}
    }

    Some(CoreRecurrence {
        frequency,
        interval: get("INTERVAL")
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|n| *n > 1),
        until,
        count: get("COUNT")
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|n| *n > 0),
        weekdays,
        day_of_month,
        nth_weekday,
        extra: None,
    })
}

/// The events in a calendar file.
pub fn ics_parse(input: &str) -> CoreIcsImport {
    let lines = unfold(input);
    let mut events = Vec::new();
    let mut skipped = Vec::new();
    let mut dropped_rules = 0;
    let mut index = 0;
    while index < lines.len() {
        if !trim(&lines[index]).eq_ignore_ascii_case("BEGIN:VEVENT") {
            index += 1;
            continue;
        }
        index += 1;
        let mut body = Vec::new();
        while index < lines.len() && !trim(&lines[index]).eq_ignore_ascii_case("END:VEVENT") {
            body.push(lines[index].clone());
            index += 1;
        }
        index += 1;
        let fields = properties(&body);
        let title = decode_text(
            first(&fields, "SUMMARY")
                .map(|p| p.value.as_str())
                .unwrap_or(""),
        );
        let title = if title.is_empty() {
            UNTITLED_EVENT_TITLE.to_string()
        } else {
            title
        };
        match event_of(&fields, &title) {
            Ok((event, dropped)) => {
                dropped_rules += u32::from(dropped);
                events.push(event);
            }
            Err(reason) => skipped.push(CoreIcsSkipped { title, reason }),
        }
    }
    CoreIcsImport {
        events,
        skipped,
        dropped_rules,
    }
}

fn event_of(fields: &Fields, title: &str) -> Result<(CoreIcsEvent, bool), String> {
    let start_property =
        first(fields, "DTSTART").ok_or_else(|| "it has no start date".to_string())?;
    let start = parse_moment(start_property)?;
    let end_property = first(fields, "DTEND");
    let end = end_property.map(parse_moment).transpose()?;

    // DTEND is exclusive for a DATE value; the protocol stores an inclusive end.
    let stored_end = end.and_then(|end| {
        if start.all_day != end.all_day {
            return None;
        }
        if !start.all_day {
            return Some(end.value);
        }
        let last = Day(parse_day(&end.value)?.0 - 1);
        (last >= parse_day(&start.value)?).then(|| format_day(last))
    });

    let participants: Vec<String> = fields
        .iter()
        .find(|(key, _)| key == "ATTENDEE")
        .map(|(_, list)| list.as_slice())
        .unwrap_or(&[])
        .iter()
        .map(|attendee| {
            let value = attendee.value.as_str();
            // A name with no address is written with a placeholder; the name is
            // what the person typed.
            decode_text(if starts_with_ci(value, "mailto:") {
                &value["mailto:".len()..]
            } else {
                attendee.param("CN").unwrap_or(value)
            })
        })
        .filter(|value| !value.is_empty())
        .collect();

    let described = first(fields, "X-ALT-DESC")
        .or_else(|| first(fields, "DESCRIPTION"))
        .map(|p| decode_text(&p.value))
        .filter(|text| !text.is_empty());

    let rule = first(fields, "RRULE");
    let recurrence = rule.and_then(|rule| ics_rrule(&rule.value, &start.value));
    let dropped = rule.is_some() && recurrence.is_none();

    let event = CoreIcsEvent {
        title: title.to_string(),
        recurrence,
        start: start.value,
        end: stored_end,
        start_zone: start_property.param("TZID").map(str::to_string),
        end_zone: end_property
            .and_then(|p| p.param("TZID"))
            .map(str::to_string),
        notes: described,
        location: first(fields, "LOCATION").and_then(|p| location_of(&p.value)),
        participants,
    };
    Ok((event, dropped))
}

// Export.

/// RFC 5545 escaping for a TEXT value: backslash, semicolon, comma, newline.
fn escape_text(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace(';', "\\;")
        .replace(',', "\\,")
        .replace("\r\n", "\\n")
        .replace('\n', "\\n")
}

/// Folds a content line to the 75 octets RFC 5545 allows, continuing with a
/// leading space. Measured in UTF-8 bytes, so a line of non-ASCII text is not
/// silently over-long.
pub fn ics_fold(line: &str) -> String {
    if line.len() <= 75 {
        return line.to_string();
    }
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut bytes = 0;
    for c in line.chars() {
        let size = c.len_utf8();
        // A continuation line spends one octet on its leading space.
        let limit = if out.is_empty() { 75 } else { 74 };
        if bytes + size > limit {
            out.push(std::mem::take(&mut current));
            bytes = 0;
        }
        current.push(c);
        bytes += size;
    }
    if !current.is_empty() {
        out.push(current);
    }
    out.join("\r\n ")
}

/// A stored instant as UTC seconds since the epoch: `Z`, a numeric offset or no
/// zone (taken as UTC), with or without fractional seconds.
fn instant_seconds(value: &str) -> Option<i64> {
    let day = parse_day(value)?;
    let rest = value.get(10..)?.strip_prefix('T')?;
    let hour = digits(rest.get(..2)?).filter(|h| *h < 24)?;
    let rest = rest.get(2..)?.strip_prefix(':')?;
    let minute = digits(rest.get(..2)?).filter(|m| *m < 60)?;
    let mut rest = &rest[2..];
    let mut second = 0;
    if let Some(after) = rest.strip_prefix(':') {
        second = digits(after.get(..2)?).filter(|s| *s < 61)?;
        rest = &after[2..];
        if let Some(fraction) = rest.strip_prefix('.') {
            let kept = fraction.trim_start_matches(|c: char| c.is_ascii_digit());
            rest = kept;
        }
    }
    let offset = match rest {
        "" | "Z" | "z" => 0,
        zone => {
            let sign = match zone.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let zone = &zone[1..];
            let (h, m) = match zone.len() {
                5 if zone.as_bytes()[2] == b':' => (&zone[..2], &zone[3..]),
                4 => (&zone[..2], &zone[2..]),
                2 => (zone, "00"),
                _ => return None,
            };
            sign * (digits(h)? * 3600 + digits(m)? * 60)
        }
    };
    Some(day.0 * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

/// `20260927T090000Z` for a timed value, `20260927` for an all-day date.
pub fn ics_stamp(value: &str) -> String {
    if !value.contains('T') {
        return value.chars().take(10).filter(|c| *c != '-').collect();
    }
    match instant_seconds(value) {
        Some(seconds) => {
            let (year, month, day) = civil_from_days(seconds.div_euclid(86_400));
            let rest = seconds.rem_euclid(86_400);
            format!(
                "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
                rest / 3600,
                rest % 3600 / 60,
                rest % 60
            )
        }
        None => {
            let squashed: String = value.chars().filter(|c| *c != '-' && *c != ':').collect();
            format!("{}Z", squashed.chars().take(15).collect::<String>())
        }
    }
}

fn rrule_of(rule: &CoreRecurrence) -> String {
    const NAMES: [&str; 7] = ["SU", "MO", "TU", "WE", "TH", "FR", "SA"];
    let frequency = match rule.frequency {
        CoreRecurrenceFrequency::Daily => "DAILY",
        CoreRecurrenceFrequency::Weekly => "WEEKLY",
        CoreRecurrenceFrequency::Monthly => "MONTHLY",
        CoreRecurrenceFrequency::Yearly => "YEARLY",
    };
    let mut parts = vec![format!("FREQ={frequency}")];
    if let Some(interval) = rule.interval.filter(|n| *n > 1) {
        parts.push(format!("INTERVAL={interval}"));
    }
    let days: Vec<&str> = rule
        .weekdays
        .iter()
        .filter_map(|d| NAMES.get(*d as usize).copied())
        .collect();
    if !days.is_empty() {
        parts.push(format!("BYDAY={}", days.join(",")));
    }
    if let Some(nth) = &rule.nth_weekday {
        let name = NAMES.get(nth.weekday as usize).copied().unwrap_or("MO");
        parts.push(format!("BYDAY={}{name}", nth.ordinal));
    }
    if let Some(day) = rule.day_of_month {
        parts.push(format!("BYMONTHDAY={day}"));
    }
    if let Some(count) = rule.count.filter(|n| *n > 0) {
        parts.push(format!("COUNT={count}"));
    }
    if let Some(until) = &rule.until {
        parts.push(format!("UNTIL={}", ics_stamp(until)));
    }
    parts.join(";")
}

/// An RFC 5545 calendar holding `events`. `now` is the caller's clock, for
/// `DTSTAMP`.
///
/// An all-day event is written as DATE values with the exclusive `DTEND` the spec
/// requires, which is one day after the inclusive end the protocol stores.
pub fn ics_write(events: &[CoreIcsExportEvent], calendar_name: &str, now: &str) -> String {
    let mut lines = vec![
        "BEGIN:VCALENDAR".to_string(),
        "VERSION:2.0".to_string(),
        "PRODID:-//Sealbook//EN".to_string(),
        "CALSCALE:GREGORIAN".to_string(),
        format!("X-WR-CALNAME:{}", escape_text(calendar_name)),
    ];
    let stamp = ics_stamp(now);

    for CoreIcsExportEvent { id, event } in events {
        lines.push("BEGIN:VEVENT".to_string());
        let id = if trim(id).is_empty() {
            uuid::Uuid::new_v4().to_string()
        } else {
            id.clone()
        };
        lines.push(format!("UID:{id}@sealbook"));
        lines.push(format!("DTSTAMP:{stamp}"));

        if event.start.contains('T') {
            lines.push(format!("DTSTART:{}", ics_stamp(&event.start)));
            if let Some(end) = &event.end {
                lines.push(format!("DTEND:{}", ics_stamp(end)));
            }
        } else {
            lines.push(format!("DTSTART;VALUE=DATE:{}", ics_stamp(&event.start)));
            // The protocol stores an inclusive end date; DTEND is exclusive.
            let inclusive = event
                .end
                .as_deref()
                .and_then(parse_day)
                .or_else(|| parse_day(&event.start));
            if let Some(day) = inclusive {
                let next = format_day(Day(day.0 + 1));
                lines.push(format!("DTEND;VALUE=DATE:{}", ics_stamp(&next)));
            }
        }

        lines.push(format!("SUMMARY:{}", escape_text(&event.title)));
        if let Some(location) = event.location.as_deref().filter(|v| !trim(v).is_empty()) {
            lines.push(format!("LOCATION:{}", escape_text(location)));
        }
        if let Some(notes) = event.notes.as_deref().filter(|v| !trim(v).is_empty()) {
            lines.push(format!("DESCRIPTION:{}", escape_text(notes)));
        }
        for participant in &event.participants {
            let name = trim(participant);
            if name.is_empty() {
                continue;
            }
            lines.push(if name.contains('@') {
                format!("ATTENDEE;CN={}:mailto:{name}", escape_text(name))
            } else {
                format!("ATTENDEE;CN={}:invalid:nomail", escape_text(name))
            });
        }
        if let Some(rule) = &event.recurrence {
            lines.push(format!("RRULE:{}", rrule_of(rule)));
        }
        lines.push("END:VEVENT".to_string());
    }

    lines.push("END:VCALENDAR".to_string());
    let mut out: String = lines
        .iter()
        .map(|line| ics_fold(line))
        .collect::<Vec<_>>()
        .join("\r\n");
    out.push_str("\r\n");
    out
}

/// Everything above, in the shapes the bindings can carry.
#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{CoreIcsExportEvent, CoreIcsImport};

    #[uniffi::export(name = "ics_parse")]
    pub fn ics_parse(input: String) -> CoreIcsImport {
        super::ics_parse(&input)
    }

    #[uniffi::export(name = "ics_write")]
    pub fn ics_write(
        events: Vec<CoreIcsExportEvent>,
        calendar_name: String,
        now: String,
    ) -> String {
        super::ics_write(&events, &calendar_name, &now)
    }
}
