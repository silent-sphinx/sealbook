//! Calendar views over the model, time-zone aware: the occurrences of events in a
//! window, the overview agenda, tasks on their due days, calendar search and the
//! bulk edit.
//!
//! This takes over what the CLI did with `event_draft` and `occurrence_starts`
//! and what the web does in `timezone.ts`, `recurrence.ts`, `overview.ts`,
//! `taskCalendar.ts`, `calendarSearch.ts` and `calendarBulk.ts`. The recurrence
//! rules themselves are core's (`recurrence_days`); this adds time zones, spans
//! and ordering around them.
//!
//! Days are `YYYY-MM-DD` strings and instants are RFC 3339 UTC strings, as stored.
//! Time of day is returned as 24-hour `HH:MM`, for the host to format.

use std::collections::BTreeMap;

use jiff::civil::Date;
use jiff::tz::TimeZone;
use jiff::{Span, Timestamp, Zoned};
use sealbook_core::{
    normalize_due_date, recurrence_days, CoreCalendar, CoreCalendarEvent, CoreTask,
    DEFAULT_CALENDAR_COLOR,
};

/// The title shown for an event that has none.
pub const UNTITLED_EVENT_TITLE: &str = "Untitled event";

pub const AGENDA_DAYS: usize = 7;
pub const SEARCH_RESULT_LIMIT: usize = 25;
const SEARCH_SCAN_LIMIT: usize = 80;

fn zone(name: &str) -> TimeZone {
    TimeZone::get(name).unwrap_or(TimeZone::UTC)
}

fn parse_day(value: &str) -> Option<Date> {
    value.get(..10)?.parse().ok()
}

fn day_key(date: Date) -> String {
    format!("{:04}-{:02}-{:02}", date.year(), date.month(), date.day())
}

/// An instant as wall-clock time in `timezone`, `YYYY-MM-DDTHH:MM`, or `None`
/// for a value that is not an instant.
pub fn utc_to_local_input(value: &str, timezone: &str) -> Option<String> {
    let instant: Timestamp = value.parse().ok()?;
    let local = instant.to_zoned(zone(timezone)).datetime();
    Some(format!(
        "{}T{:02}:{:02}",
        day_key(local.date()),
        local.hour(),
        local.minute()
    ))
}

/// Wall-clock time in `timezone` (`YYYY-MM-DD` or `YYYY-MM-DDTHH:MM`) as a UTC
/// instant. A time that falls in a gap (the clocks going forward) resolves to
/// the moment after it, and an ambiguous one (the clocks going back) to the
/// first, as `Date` does in a browser.
pub fn local_input_to_utc(value: &str, timezone: &str) -> Option<String> {
    let (day, time) = match value.split_once('T') {
        Some((day, time)) => (day, time),
        None => (value, "00:00"),
    };
    let date: Date = day.parse().ok()?;
    let (hour, minute) = time.get(..5)?.split_once(':')?;
    let wall = date.at(hour.parse().ok()?, minute.parse().ok()?, 0, 0);
    let zoned = wall.to_zoned(zone(timezone)).ok()?;
    Some(
        zoned
            .timestamp()
            .strftime("%Y-%m-%dT%H:%M:%S.000Z")
            .to_string(),
    )
}

/// `UTC+01:00`, for the zone's offset at `at`.
pub fn utc_offset_label(timezone: &str, at: Timestamp) -> String {
    let seconds = zone(timezone).to_offset(at).seconds();
    let sign = if seconds < 0 { '-' } else { '+' };
    let seconds = seconds.abs();
    format!(
        "UTC{sign}{:02}:{:02}",
        seconds / 3600,
        (seconds % 3600) / 60
    )
}

/// One occurrence of an event in a window. A repeating event's occurrences have
/// the id `"<event>:<day>"`; `source_id` is always the stored event's.
#[derive(Clone, Debug, PartialEq)]
pub struct Occurrence {
    pub event: CoreCalendarEvent,
    pub source_id: String,
    /// The local day this occurrence starts on.
    pub day: String,
}

fn is_all_day(event: &CoreCalendarEvent) -> bool {
    !event.start.contains('T')
}

/// The event's own start as a local `(day, time)`; all-day events have no time.
fn local_start(event: &CoreCalendarEvent, fallback: &str) -> Option<(Date, Option<String>)> {
    let timezone = event.timezone.as_deref().unwrap_or(fallback);
    if is_all_day(event) {
        return Some((parse_day(&event.start)?, None));
    }
    let local = utc_to_local_input(&event.start, timezone)?;
    Some((parse_day(&local)?, Some(local[10..].to_string())))
}

/// The same event on `day`, at the same local time, for the same duration.
fn on_day(event: &CoreCalendarEvent, day: Date, fallback: &str) -> Option<CoreCalendarEvent> {
    let timezone = event.timezone.as_deref().unwrap_or(fallback);
    let key = day_key(day);
    let mut next = event.clone();
    next.id = format!("{}:{key}", event.id);
    if is_all_day(event) {
        next.start = key;
        if let Some(end) = event.end.as_deref().and_then(parse_day) {
            let from = parse_day(&event.start)?;
            let days = from.until(end).ok()?.get_days().max(0);
            next.end = Some(day_key(day.checked_add(Span::new().days(days)).ok()?));
        }
        return Some(next);
    }
    let (_, time) = local_start(event, fallback)?;
    let start = local_input_to_utc(&format!("{key}{}", time?), timezone)?;
    if let Some(end) = event.end.as_deref().filter(|end| end.contains('T')) {
        let before: Timestamp = event.start.parse().ok()?;
        let after: Timestamp = end.parse().ok()?;
        let duration = after.duration_since(before);
        let moved: Timestamp = start.parse().ok()?;
        next.end = Some(
            moved
                .checked_add(duration)
                .ok()?
                .strftime("%Y-%m-%dT%H:%M:%S.000Z")
                .to_string(),
        );
    }
    next.start = start;
    Some(next)
}

/// The occurrences that start on a local day from `from` to `to` inclusive.
pub fn expand_events<'a>(
    events: impl IntoIterator<Item = &'a CoreCalendarEvent>,
    from: &str,
    to: &str,
    fallback_timezone: &str,
) -> Vec<Occurrence> {
    let mut out = Vec::new();
    let (Some(first), Some(last)) = (parse_day(from), parse_day(to)) else {
        return out;
    };
    for event in events {
        let Some((anchor, _)) = local_start(event, fallback_timezone) else {
            continue;
        };
        match &event.recurrence {
            None => {
                if anchor >= first && anchor <= last {
                    out.push(Occurrence {
                        event: event.clone(),
                        source_id: event.id.clone(),
                        day: day_key(anchor),
                    });
                }
            }
            Some(rule) => {
                for day in recurrence_days(&day_key(anchor), rule, &day_key(first), &day_key(last))
                {
                    let Some(date) = parse_day(&day) else {
                        continue;
                    };
                    if let Some(next) = on_day(event, date, fallback_timezone) {
                        out.push(Occurrence {
                            event: next,
                            source_id: event.id.clone(),
                            day,
                        });
                    }
                }
            }
        }
    }
    out
}

/// The local days an occurrence covers and the time to show on the first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventSpan {
    pub start_day: String,
    pub end_day: String,
    /// `HH:MM`, `None` for an all-day event.
    pub time: Option<String>,
}

pub fn span_of(event: &CoreCalendarEvent, fallback_timezone: &str) -> EventSpan {
    if is_all_day(event) {
        let start = event.start.get(..10).unwrap_or(&event.start).to_string();
        let end = event
            .end
            .as_deref()
            .and_then(|end| end.get(..10))
            .unwrap_or(&start)
            .to_string();
        return EventSpan {
            end_day: end.max(start.clone()),
            start_day: start,
            time: None,
        };
    }
    let timezone = event.timezone.as_deref().unwrap_or(fallback_timezone);
    let start = utc_to_local_input(&event.start, timezone).unwrap_or_default();
    let start_day = start.get(..10).unwrap_or("").to_string();
    let mut end_day = start_day.clone();
    if let Some(end) = event.end.as_deref().filter(|end| end.contains('T')) {
        if let Some(local) = utc_to_local_input(end, timezone) {
            end_day = local[..10].to_string();
            // An event that ends at midnight does not spill onto the next day.
            if end_day > start_day && local.ends_with("T00:00") {
                if let Some(day) = parse_day(&end_day).and_then(|d| d.yesterday().ok()) {
                    end_day = day_key(day);
                }
            }
        }
    }
    EventSpan {
        end_day: end_day.max(start_day.clone()),
        time: start.get(11..16).map(str::to_string),
        start_day,
    }
}

/// Calendars the grid shows: not archived, and not hidden from the combined view.
pub fn is_calendar_visible(calendar: &CoreCalendar) -> bool {
    !calendar.archived && !calendar.hide_from_all
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgendaEntry {
    /// The occurrence, unique within the agenda.
    pub id: String,
    /// The stored event, which is what the calendar opens.
    pub event_id: String,
    pub title: String,
    /// `None` for an all-day event, or a timed one carried over from an earlier day.
    pub time: Option<String>,
    pub color: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgendaDay {
    pub day: String,
    pub entries: Vec<AgendaEntry>,
}

/// The next `days` days from `today`, each with the events on it, all-day first.
/// Events of calendars the grid hides are left out, so the overview never shows
/// what the calendar does not. Every day is returned, empty or not.
pub fn agenda_days<'a>(
    events: impl IntoIterator<Item = &'a CoreCalendarEvent>,
    calendars: &[&CoreCalendar],
    today: &str,
    timezone: &str,
    days: usize,
) -> Vec<AgendaDay> {
    let Some(first) = parse_day(today) else {
        return Vec::new();
    };
    let hidden: Vec<&str> = calendars
        .iter()
        .filter(|calendar| !is_calendar_visible(calendar))
        .map(|calendar| calendar.id.as_str())
        .collect();
    let shown: Vec<&CoreCalendarEvent> = events
        .into_iter()
        .filter(|event| {
            event
                .calendar_id
                .as_deref()
                .is_none_or(|id| !hidden.contains(&id))
        })
        .collect();
    // Occurrences are found by their start, so the window opens early enough to
    // catch the longest event already under way on the first day.
    let longest = shown
        .iter()
        .filter_map(|event| {
            let from = parse_day(&event.start)?;
            let to = parse_day(event.end.as_deref().unwrap_or(&event.start))?;
            Some(from.until(to).ok()?.get_days().max(0))
        })
        .max()
        .unwrap_or(0);
    let last = first
        .checked_add(Span::new().days(days.saturating_sub(1) as i64))
        .unwrap_or(first);
    let early = first
        .checked_sub(Span::new().days(i64::from(longest)))
        .unwrap_or(first);
    let occurrences = expand_events(
        shown.iter().copied(),
        &day_key(early),
        &day_key(last),
        timezone,
    );
    let colors: BTreeMap<&str, &str> = calendars
        .iter()
        .map(|calendar| (calendar.id.as_str(), calendar.color.as_str()))
        .collect();
    let spans: Vec<(EventSpan, &Occurrence)> = occurrences
        .iter()
        .map(|occurrence| (span_of(&occurrence.event, timezone), occurrence))
        .collect();

    (0..days)
        .map(|offset| {
            let day = day_key(
                first
                    .checked_add(Span::new().days(offset as i64))
                    .unwrap_or(first),
            );
            let mut entries: Vec<(String, AgendaEntry)> = spans
                .iter()
                .filter(|(span, _)| day >= span.start_day && day <= span.end_day)
                .map(|(span, occurrence)| {
                    let event = &occurrence.event;
                    let title = event.title.trim();
                    (
                        event.start.clone(),
                        AgendaEntry {
                            id: event.id.clone(),
                            event_id: occurrence.source_id.clone(),
                            title: if title.is_empty() {
                                UNTITLED_EVENT_TITLE.to_string()
                            } else {
                                title.to_string()
                            },
                            time: (span.start_day == day).then(|| span.time.clone()).flatten(),
                            color: event
                                .calendar_id
                                .as_deref()
                                .and_then(|id| colors.get(id))
                                .map(|color| (*color).to_string()),
                        },
                    )
                })
                .collect();
            entries.sort_by(|(a_start, a), (b_start, b)| {
                a.time
                    .is_some()
                    .cmp(&b.time.is_some())
                    .then_with(|| a_start.cmp(b_start))
                    .then_with(|| a.title.cmp(&b.title))
            });
            AgendaDay {
                day,
                entries: entries.into_iter().map(|(_, entry)| entry).collect(),
            }
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskMark {
    pub id: String,
    pub title: String,
    /// `HH:MM`, `None` for a task due on a day.
    pub time: Option<String>,
    pub overdue: bool,
}

/// The local day a due value falls on.
fn due_day(due: &str, timezone: &str) -> Option<String> {
    if !due.contains('T') {
        return Some(due.to_string());
    }
    let instant: Timestamp = due.parse().ok().or_else(|| {
        // A due time without an offset is read as the zone's wall-clock time.
        local_input_to_utc(due, timezone)?.parse().ok()
    })?;
    Some(day_key(instant.to_zoned(zone(timezone)).date()))
}

/// Open tasks with a due date, by the local day they are due on, in the order
/// given. `now` is an RFC 3339 instant.
pub fn due_task_marks<'a>(
    tasks: impl IntoIterator<Item = &'a CoreTask>,
    now: &str,
    timezone: &str,
) -> BTreeMap<String, Vec<TaskMark>> {
    let now_instant: Option<Timestamp> = now.parse().ok();
    let today = now_instant.map(|instant| day_key(instant.to_zoned(zone(timezone)).date()));
    let mut marks: BTreeMap<String, Vec<TaskMark>> = BTreeMap::new();
    for task in tasks {
        let Some(due) = task.due_date.as_deref().and_then(normalize_due_date) else {
            continue;
        };
        if task.done {
            continue;
        }
        let Some(day) = due_day(&due, timezone) else {
            continue;
        };
        let all_day = !due.contains('T');
        let overdue = if all_day {
            today.as_deref().is_some_and(|today| due.as_str() < today)
        } else {
            matches!((due.parse::<Timestamp>().ok(), now_instant), (Some(due), Some(now)) if due < now)
        };
        marks.entry(day).or_default().push(TaskMark {
            id: task.id.clone(),
            title: task.title.clone(),
            time: (!all_day)
                .then(|| {
                    utc_to_local_input(&due, timezone)
                        .and_then(|local| local.get(11..16).map(str::to_string))
                })
                .flatten(),
            overdue,
        });
    }
    marks
}

#[derive(Clone, Debug, PartialEq)]
pub struct SearchResult {
    pub event: CoreCalendarEvent,
    /// The day the event falls on: its own, or for a repeating one the next from today.
    pub day: String,
    /// `HH:MM`, `None` for an all-day event.
    pub time: Option<String>,
    pub color: String,
    pub calendar_name: Option<String>,
}

fn matches_query(event: &CoreCalendarEvent, query: &str) -> bool {
    let has = |text: &str| text.to_lowercase().contains(query);
    has(&event.title)
        || event.location.as_deref().is_some_and(has)
        || event.notes.as_deref().is_some_and(has)
        || event
            .participants
            .iter()
            .any(|participant| has(participant))
}

/// Where an event lands for a search, with the labels a result row shows.
pub fn resolve_event(
    event: &CoreCalendarEvent,
    calendars: &[&CoreCalendar],
    today: &str,
    fallback_timezone: &str,
) -> SearchResult {
    let mut shown = event.clone();
    if event.recurrence.is_some() {
        if let Some(first) = parse_day(today) {
            let horizon = first.checked_add(Span::new().years(2)).unwrap_or(first);
            let next = expand_events(
                std::iter::once(event),
                &day_key(first),
                &day_key(horizon),
                fallback_timezone,
            )
            .into_iter()
            .next();
            if let Some(next) = next {
                shown = next.event;
            }
        }
    }
    let span = span_of(&shown, fallback_timezone);
    let calendar = event
        .calendar_id
        .as_deref()
        .and_then(|id| calendars.iter().find(|calendar| calendar.id == id));
    SearchResult {
        day: span.start_day,
        time: span.time,
        color: calendar.map_or_else(
            || DEFAULT_CALENDAR_COLOR.to_string(),
            |calendar| calendar.color.clone(),
        ),
        calendar_name: calendar.map(|calendar| calendar.name.clone()),
        event: shown,
    }
}

/// Events matching `query` in title, place, notes or people: upcoming ones soonest
/// first, then past ones newest first.
pub fn search_events<'a>(
    events: impl IntoIterator<Item = &'a CoreCalendarEvent>,
    calendars: &[&CoreCalendar],
    query: &str,
    today: &str,
    fallback_timezone: &str,
) -> Vec<SearchResult> {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return Vec::new();
    }
    let mut found: Vec<SearchResult> = events
        .into_iter()
        .filter(|event| matches_query(event, &query))
        .take(SEARCH_SCAN_LIMIT)
        .map(|event| resolve_event(event, calendars, today, fallback_timezone))
        .collect();
    found.sort_by(|a, b| {
        let (a_ahead, b_ahead) = (a.day.as_str() >= today, b.day.as_str() >= today);
        b_ahead.cmp(&a_ahead).then_with(|| {
            if a_ahead {
                a.day.cmp(&b.day)
            } else {
                b.day.cmp(&a.day)
            }
        })
    });
    found.truncate(SEARCH_RESULT_LIMIT);
    found
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TitleMatch {
    Prefix,
    Contains,
    Suffix,
    Exact,
}

/// Which events a bulk edit applies to. `calendar` is [`CalendarChoice`].
#[derive(Clone, Debug)]
pub struct EventFilter {
    pub text: String,
    pub match_kind: TitleMatch,
    pub case_sensitive: bool,
    pub calendar: CalendarChoice,
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CalendarChoice {
    All,
    /// Events with no calendar.
    None,
    One(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TitleEdit {
    Keep,
    Strip,
    Replace { find: String, replace: String },
    Prefix(String),
    Suffix(String),
    Set(String),
}

#[derive(Clone, Debug)]
pub struct BulkEdit {
    pub title: TitleEdit,
    /// Move every event to this calendar, or leave each where it is.
    pub calendar_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PlannedChange {
    pub event: CoreCalendarEvent,
    pub title: String,
    pub calendar_id: Option<String>,
    pub changed: bool,
}

const SEPARATORS: &[char] = &[
    ' ', '\t', '\n', '-', '\u{2013}', '\u{2014}', ':', '|', '/', '\u{b7}', '.', ',', ';',
];

fn fold(text: &str, case_sensitive: bool) -> String {
    if case_sensitive {
        text.to_string()
    } else {
        text.to_lowercase()
    }
}

pub fn matches_title(title: &str, filter: &EventFilter) -> bool {
    if filter.text.is_empty() {
        return true;
    }
    let haystack = fold(title, filter.case_sensitive);
    let needle = fold(&filter.text, filter.case_sensitive);
    match filter.match_kind {
        TitleMatch::Prefix => haystack.starts_with(&needle),
        TitleMatch::Suffix => haystack.ends_with(&needle),
        TitleMatch::Exact => haystack == needle,
        TitleMatch::Contains => haystack.contains(&needle),
    }
}

/// The local day the event starts on.
pub fn event_day(event: &CoreCalendarEvent, timezone: &str) -> String {
    span_of(event, timezone).start_day
}

pub fn filter_events<'a>(
    events: impl IntoIterator<Item = &'a CoreCalendarEvent>,
    filter: &EventFilter,
    timezone: &str,
) -> Vec<&'a CoreCalendarEvent> {
    let mut kept: Vec<&CoreCalendarEvent> = events
        .into_iter()
        .filter(|event| match &filter.calendar {
            CalendarChoice::All => true,
            CalendarChoice::None => event.calendar_id.is_none(),
            CalendarChoice::One(id) => event.calendar_id.as_deref() == Some(id.as_str()),
        })
        .filter(|event| matches_title(&event.title, filter))
        .filter(|event| {
            if filter.from.is_none() && filter.to.is_none() {
                return true;
            }
            let day = event_day(event, timezone);
            filter.from.as_ref().is_none_or(|from| day >= *from)
                && filter.to.as_ref().is_none_or(|to| day <= *to)
        })
        .collect();
    kept.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| a.title.cmp(&b.title)));
    kept
}

/// Replaces every occurrence of `find` in `text` with `with`, comparing without
/// regard to case unless told otherwise. Matching is done on characters, so it is
/// safe for any text.
fn replace_all(text: &str, find: &str, with: &str, case_sensitive: bool) -> String {
    if find.is_empty() {
        return text.to_string();
    }
    let chars: Vec<char> = text.chars().collect();
    let needle: Vec<char> = fold(find, case_sensitive).chars().collect();
    let folded: Vec<char> = chars
        .iter()
        .map(|c| {
            if case_sensitive {
                *c
            } else {
                c.to_lowercase().next().unwrap_or(*c)
            }
        })
        .collect();
    let mut out = String::new();
    let mut at = 0;
    while at < chars.len() {
        if at + needle.len() <= chars.len() && folded[at..at + needle.len()] == needle[..] {
            out.push_str(with);
            at += needle.len();
        } else {
            out.push(chars[at]);
            at += 1;
        }
    }
    out
}

fn collapse_spaces(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last_space = false;
    for c in text.chars() {
        let space = c.is_whitespace();
        if !(space && last_space) {
            out.push(if space { ' ' } else { c });
        }
        last_space = space;
    }
    out
}

/// Removes the filter's text from a title, then the separators the cut leaves
/// behind, so "HOL - Paris" less "HOL" reads "Paris". A title that would end up
/// empty is returned unchanged.
pub fn strip_match(title: &str, filter: &EventFilter) -> String {
    if filter.text.is_empty()
        || filter.match_kind == TitleMatch::Exact
        || !matches_title(title, filter)
    {
        return title.to_string();
    }
    let cut = filter.text.chars().count();
    let next = match filter.match_kind {
        TitleMatch::Prefix => title
            .chars()
            .skip(cut)
            .collect::<String>()
            .trim_start_matches(SEPARATORS)
            .to_string(),
        TitleMatch::Suffix => {
            let keep = title.chars().count().saturating_sub(cut);
            title
                .chars()
                .take(keep)
                .collect::<String>()
                .trim_end_matches(SEPARATORS)
                .to_string()
        }
        _ => {
            let replaced = replace_all(title, &filter.text, " ", filter.case_sensitive);
            collapse_spaces(&replaced)
                .trim_matches(SEPARATORS)
                .to_string()
        }
    };
    let next = next.trim();
    if next.is_empty() {
        title.to_string()
    } else {
        next.to_string()
    }
}

pub fn edit_title(title: &str, edit: &TitleEdit, filter: &EventFilter) -> String {
    match edit {
        TitleEdit::Strip => strip_match(title, filter),
        TitleEdit::Replace { find, replace } => {
            if find.is_empty() {
                return title.to_string();
            }
            let next = collapse_spaces(&replace_all(title, find, replace, filter.case_sensitive));
            let next = next.trim();
            if next.is_empty() {
                title.to_string()
            } else {
                next.to_string()
            }
        }
        TitleEdit::Prefix(text) if !text.is_empty() => format!("{text}{title}"),
        TitleEdit::Suffix(text) if !text.is_empty() => format!("{title}{text}"),
        TitleEdit::Set(text) if !text.trim().is_empty() => text.trim().to_string(),
        _ => title.to_string(),
    }
}

pub fn plan_bulk_edit(
    events: &[&CoreCalendarEvent],
    edit: &BulkEdit,
    filter: &EventFilter,
) -> Vec<PlannedChange> {
    events
        .iter()
        .map(|event| {
            let title = edit_title(&event.title, &edit.title, filter);
            let calendar_id = edit
                .calendar_id
                .clone()
                .or_else(|| event.calendar_id.clone());
            PlannedChange {
                changed: title != event.title || calendar_id != event.calendar_id,
                event: (*event).clone(),
                title,
                calendar_id,
            }
        })
        .collect()
}

/// The draft of a stored event, with every field it carries, so an edit that
/// changes one thing writes the rest back and keeps keys this build does not know.
pub fn event_draft(event: CoreCalendarEvent) -> sealbook_core::CoreCalendarEventDraft {
    sealbook_core::CoreCalendarEventDraft {
        title: event.title,
        start: event.start,
        end: event.end,
        notes: event.notes,
        location: event.location,
        participants: event.participants,
        timezone: event.timezone,
        calendar_id: event.calendar_id,
        recurrence: event.recurrence,
        unreadable_recurrence: event.unreadable_recurrence,
        alerts: event.alerts,
        unreadable_alerts: event.unreadable_alerts,
        raw: Some(event.raw),
    }
}

/// The local date and time `now` is in `timezone`, as the host's "today".
pub fn today_in(timezone: &str, now: Timestamp) -> String {
    let zoned: Zoned = now.to_zoned(zone(timezone));
    day_key(zoned.date())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealbook_core::{CoreRecurrence, CoreRecurrenceFrequency};

    fn event(id: &str, title: &str, start: &str) -> CoreCalendarEvent {
        sealbook_core::event_parse(
            id,
            &serde_json::json!({"@type": "Event", "version": 1, "title": title, "start": start})
                .to_string(),
        )
    }

    fn with(
        mut event: CoreCalendarEvent,
        change: impl FnOnce(&mut CoreCalendarEvent),
    ) -> CoreCalendarEvent {
        change(&mut event);
        event
    }

    fn weekly() -> CoreRecurrence {
        CoreRecurrence {
            frequency: CoreRecurrenceFrequency::Weekly,
            interval: None,
            until: None,
            count: None,
            weekdays: Vec::new(),
            day_of_month: None,
            nth_weekday: None,
            extra: None,
        }
    }

    #[test]
    fn instants_and_wall_clock_times_convert_both_ways_across_daylight_saving() {
        // London is on GMT in January and BST in July.
        assert_eq!(
            utc_to_local_input("2026-01-10T09:00:00.000Z", "Europe/London").unwrap(),
            "2026-01-10T09:00"
        );
        assert_eq!(
            utc_to_local_input("2026-07-10T09:00:00.000Z", "Europe/London").unwrap(),
            "2026-07-10T10:00"
        );
        assert_eq!(
            local_input_to_utc("2026-07-10T10:00", "Europe/London").unwrap(),
            "2026-07-10T09:00:00.000Z"
        );
        // 01:30 on the day the clocks go forward does not exist: it lands after the gap.
        assert_eq!(
            local_input_to_utc("2026-03-29T01:30", "Europe/London").unwrap(),
            "2026-03-29T01:30:00.000Z"
        );
        assert!(utc_to_local_input("not a time", "UTC").is_none());
    }

    #[test]
    fn the_offset_label_follows_the_zone_and_the_date() {
        let winter: Timestamp = "2026-01-10T12:00:00Z".parse().unwrap();
        let summer: Timestamp = "2026-07-10T12:00:00Z".parse().unwrap();
        assert_eq!(utc_offset_label("Europe/London", winter), "UTC+00:00");
        assert_eq!(utc_offset_label("Europe/London", summer), "UTC+01:00");
        assert_eq!(utc_offset_label("Asia/Kolkata", winter), "UTC+05:30");
        assert_eq!(utc_offset_label("America/New_York", winter), "UTC-05:00");
    }

    #[test]
    fn a_repeating_event_keeps_its_local_time_across_a_clock_change() {
        let weekly_event = with(event("e1", "Standup", "2026-03-23T09:00:00.000Z"), |e| {
            e.timezone = Some("Europe/London".into());
            e.recurrence = Some(weekly());
            e.end = Some("2026-03-23T09:30:00.000Z".into());
        });
        let found = expand_events([&weekly_event], "2026-03-23", "2026-04-06", "UTC");
        assert_eq!(found.len(), 3);
        // 09:00 GMT before the change, 09:00 BST (08:00 UTC) after.
        assert_eq!(found[0].event.start, "2026-03-23T09:00:00.000Z");
        assert_eq!(found[2].event.start, "2026-04-06T08:00:00.000Z");
        assert_eq!(
            found[2].event.end.as_deref(),
            Some("2026-04-06T08:30:00.000Z")
        );
        assert_eq!(found[1].event.id, "e1:2026-03-30");
        assert!(found.iter().all(|o| o.source_id == "e1"));
    }

    #[test]
    fn a_single_event_is_in_the_window_by_its_local_day() {
        // 23:30 UTC on the 9th is already the 10th in Tokyo.
        let late = with(event("e2", "Late", "2026-02-09T23:30:00.000Z"), |e| {
            e.timezone = Some("Asia/Tokyo".into())
        });
        assert_eq!(
            expand_events([&late], "2026-02-10", "2026-02-10", "UTC").len(),
            1
        );
        assert!(expand_events([&late], "2026-02-09", "2026-02-09", "UTC").is_empty());
    }

    #[test]
    fn an_all_day_event_spans_its_days_and_a_repeat_keeps_its_length() {
        let trip = with(event("e3", "Trip", "2026-05-04"), |e| {
            e.end = Some("2026-05-06".into());
            e.recurrence = Some(weekly());
        });
        let found = expand_events([&trip], "2026-05-04", "2026-05-12", "UTC");
        assert_eq!(found.len(), 2);
        assert_eq!(found[1].event.start, "2026-05-11");
        assert_eq!(found[1].event.end.as_deref(), Some("2026-05-13"));
        let span = span_of(&found[1].event, "UTC");
        assert_eq!(
            (span.start_day.as_str(), span.end_day.as_str()),
            ("2026-05-11", "2026-05-13")
        );
        assert!(span.time.is_none());
    }

    #[test]
    fn an_event_ending_at_midnight_does_not_spill_onto_the_next_day() {
        let late = with(event("e4", "Party", "2026-06-01T20:00:00.000Z"), |e| {
            e.end = Some("2026-06-02T00:00:00.000Z".into())
        });
        let span = span_of(&late, "UTC");
        assert_eq!(span.end_day, "2026-06-01");
        assert_eq!(span.time.as_deref(), Some("20:00"));
    }

    fn calendar(id: &str, name: &str, hidden: bool) -> CoreCalendar {
        let mut calendar = sealbook_core::calendar_parse(
            id,
            &serde_json::json!({"@type": "Calendar", "version": 1, "name": name, "color": "#112233"})
                .to_string(),
        );
        calendar.hide_from_all = hidden;
        calendar
    }

    #[test]
    fn the_agenda_lists_seven_days_all_day_first_and_skips_hidden_calendars() {
        let work = calendar("work", "Work", false);
        let secret = calendar("secret", "Secret", true);
        let timed = with(event("a", "Standup", "2026-06-01T09:00:00.000Z"), |e| {
            e.calendar_id = Some("work".into())
        });
        let all_day = event("b", "Holiday", "2026-06-01");
        let hidden = with(event("c", "Hidden", "2026-06-01T10:00:00.000Z"), |e| {
            e.calendar_id = Some("secret".into())
        });
        let multi = with(event("d", "Conference", "2026-05-31"), |e| {
            e.end = Some("2026-06-02".into())
        });
        let days = agenda_days(
            [&timed, &all_day, &hidden, &multi],
            &[&work, &secret],
            "2026-06-01",
            "UTC",
            AGENDA_DAYS,
        );
        assert_eq!(days.len(), 7);
        assert_eq!(days[0].day, "2026-06-01");
        let first: Vec<_> = days[0].entries.iter().map(|e| e.title.as_str()).collect();
        assert_eq!(first, vec!["Conference", "Holiday", "Standup"]);
        assert_eq!(days[0].entries[2].time.as_deref(), Some("09:00"));
        assert_eq!(days[0].entries[2].color.as_deref(), Some("#112233"));
        assert_eq!(
            days[1].entries.len(),
            1,
            "the conference runs into the second day"
        );
        assert!(days[1].entries[0].time.is_none());
        assert!(days[2].entries.is_empty());
    }

    #[test]
    fn open_tasks_are_marked_on_their_local_due_day_and_overdue_ones_say_so() {
        let task = |id: &str, due: &str, done: bool| {
            let mut task = sealbook_core::task_parse(
                id,
                &serde_json::json!({"@type": "Task", "version": 1, "title": id, "dueDate": due})
                    .to_string(),
            );
            task.done = done;
            task
        };
        let a = task("past", "2026-05-30", false);
        let b = task("today-timed", "2026-06-01T08:30:00.000Z", false);
        let c = task("finished", "2026-06-01", true);
        let d = task("later", "2026-06-05", false);
        let marks = due_task_marks([&a, &b, &c, &d], "2026-06-01T12:00:00Z", "UTC");
        assert!(marks["2026-05-30"][0].overdue);
        assert_eq!(marks["2026-06-01"].len(), 1, "the done one is left out");
        assert_eq!(marks["2026-06-01"][0].time.as_deref(), Some("08:30"));
        assert!(marks["2026-06-01"][0].overdue, "08:30 is before noon");
        assert!(!marks["2026-06-05"][0].overdue);
    }

    #[test]
    fn search_finds_by_place_and_people_and_orders_upcoming_before_past() {
        let calendars = [&calendar("work", "Work", false)].map(|c| c.clone());
        let refs: Vec<&CoreCalendar> = calendars.iter().collect();
        let past = event("p", "Lunch with Ada", "2026-01-05T12:00:00.000Z");
        let soon = with(event("s", "Planning", "2026-06-03T10:00:00.000Z"), |e| {
            e.participants = vec!["Ada L".into()]
        });
        let none = event("n", "Dentist", "2026-06-04T10:00:00.000Z");
        let found = search_events([&past, &soon, &none], &refs, "  ada ", "2026-06-01", "UTC");
        let ids: Vec<_> = found.iter().map(|r| r.event.id.as_str()).collect();
        assert_eq!(ids, vec!["s", "p"]);
        assert!(search_events([&past], &refs, "   ", "2026-06-01", "UTC").is_empty());
    }

    #[test]
    fn a_repeating_event_in_search_lands_on_its_next_day() {
        let calendars: Vec<CoreCalendar> = Vec::new();
        let refs: Vec<&CoreCalendar> = calendars.iter().collect();
        let weekly_event = with(event("w", "Yoga", "2026-01-05T18:00:00.000Z"), |e| {
            e.recurrence = Some(weekly())
        });
        let found = search_events([&weekly_event], &refs, "yoga", "2026-06-02", "UTC");
        assert_eq!(found[0].day, "2026-06-08");
        assert_eq!(found[0].color, DEFAULT_CALENDAR_COLOR);
    }

    fn filter(text: &str, kind: TitleMatch) -> EventFilter {
        EventFilter {
            text: text.into(),
            match_kind: kind,
            case_sensitive: false,
            calendar: CalendarChoice::All,
            from: None,
            to: None,
        }
    }

    #[test]
    fn stripping_a_match_takes_the_separators_it_leaves_with_it() {
        assert_eq!(
            strip_match("HOL - Paris", &filter("hol", TitleMatch::Prefix)),
            "Paris"
        );
        assert_eq!(
            strip_match("Paris | HOL", &filter("HOL", TitleMatch::Suffix)),
            "Paris"
        );
        assert_eq!(
            strip_match("Team HOL sync", &filter("hol", TitleMatch::Contains)),
            "Team sync"
        );
        assert_eq!(
            strip_match("HOL", &filter("HOL", TitleMatch::Prefix)),
            "HOL",
            "never to empty"
        );
        assert_eq!(
            strip_match("Paris", &filter("HOL", TitleMatch::Prefix)),
            "Paris"
        );
    }

    #[test]
    fn a_bulk_edit_plans_titles_and_calendars_and_says_what_changed() {
        let a = with(event("a", "HOL - Paris", "2026-06-01"), |e| {
            e.calendar_id = Some("old".into())
        });
        let b = event("b", "Dentist", "2026-06-02");
        let f = filter("HOL", TitleMatch::Prefix);
        let kept = filter_events([&a, &b], &f, "UTC");
        assert_eq!(kept.len(), 1);
        let plan = plan_bulk_edit(
            &kept,
            &BulkEdit {
                title: TitleEdit::Strip,
                calendar_id: Some("new".into()),
            },
            &f,
        );
        assert_eq!(plan[0].title, "Paris");
        assert_eq!(plan[0].calendar_id.as_deref(), Some("new"));
        assert!(plan[0].changed);
        let untouched = plan_bulk_edit(
            &[&b],
            &BulkEdit {
                title: TitleEdit::Keep,
                calendar_id: None,
            },
            &f,
        );
        assert!(!untouched[0].changed);
    }

    #[test]
    fn a_filter_by_calendar_and_day_range_orders_by_start() {
        let a = with(event("a", "One", "2026-06-03T10:00:00.000Z"), |e| {
            e.calendar_id = Some("x".into())
        });
        let b = with(event("b", "Two", "2026-06-01T10:00:00.000Z"), |e| {
            e.calendar_id = Some("x".into())
        });
        // Parsing fills in the default calendar, so a calendar-less event is made explicitly.
        let c = with(event("c", "Three", "2026-06-02T10:00:00.000Z"), |e| {
            e.calendar_id = None
        });
        let mut f = filter("", TitleMatch::Contains);
        f.calendar = CalendarChoice::One("x".into());
        let ids: Vec<_> = filter_events([&a, &b, &c], &f, "UTC")
            .iter()
            .map(|e| e.id.clone())
            .collect();
        assert_eq!(ids, vec!["b", "a"]);
        f.calendar = CalendarChoice::None;
        assert_eq!(filter_events([&a, &b, &c], &f, "UTC").len(), 1);
        f.calendar = CalendarChoice::All;
        f.from = Some("2026-06-02".into());
        f.to = Some("2026-06-02".into());
        assert_eq!(filter_events([&a, &b, &c], &f, "UTC").len(), 1);
    }

    #[test]
    fn replace_and_set_and_affixes_edit_titles_without_emptying_them() {
        let f = filter("", TitleMatch::Contains);
        let replace = TitleEdit::Replace {
            find: "hol".into(),
            replace: "Holiday".into(),
        };
        assert_eq!(edit_title("HOL Paris", &replace, &f), "Holiday Paris");
        assert_eq!(edit_title("X", &TitleEdit::Prefix("A ".into()), &f), "A X");
        assert_eq!(edit_title("X", &TitleEdit::Suffix("!".into()), &f), "X!");
        assert_eq!(edit_title("X", &TitleEdit::Set("  ".into()), &f), "X");
        assert_eq!(edit_title("X", &TitleEdit::Set(" Y ".into()), &f), "Y");
    }

    #[test]
    fn an_event_draft_carries_the_stored_payload_so_unknown_keys_survive() {
        let stored = event("e", "Keep me", "2026-06-01");
        let draft = event_draft(stored.clone());
        assert_eq!(draft.raw.as_deref(), Some(stored.raw.as_str()));
        assert_eq!(draft.title, "Keep me");
    }
}
