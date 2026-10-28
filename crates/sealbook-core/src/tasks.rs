//! The task and task list payloads: which keys a writer owns, how one is
//! written, and how one is read back.
//!
//! Only the web writes tasks today, so there was no second client to disagree
//! with. What the web had instead was a writer that spread whatever it was
//! handed: ticking a task re-saved the title it was listed under, and a
//! recurrence rule from a newer build was cleared by the next edit. Moving the
//! type here is what lets an Android or CLI tasks feature start as a UI job.
//!
//! Four rules decide everything below.
//!
//! **One owned set.** [`TASK_KEYS`] and [`TASK_LIST_KEYS`] are what any client
//! writes. A host reads the stored record into [`CoreTask`] first and writes it
//! back through [`CoreTask::draft`], so a field its UI cannot show still travels.
//!
//! **Absent is omitted, never null.** An open task carries no `done`, a task
//! with no due date no `dueDate`, and a top-level list no `parentId`.
//!
//! **A task is not titled by being saved.** A task with no title lists as
//! [`UNTITLED_TASK_TITLE`], which is the reader's fallback.
//! [`CoreTask::derived_title`] says it was not stored, and [`CoreTask::draft`]
//! hands the writer an empty title.
//!
//! **A recurrence rule this build cannot name survives.** The rule is the
//! calendar event's [`CoreRecurrence`], read by the same code, and one with a
//! frequency this build does not know comes back in
//! [`CoreTask::unreadable_recurrence`] for the writer to put back verbatim.
//!
//! What is deliberately not here is the rolling forward of a recurring task.
//! That is a date walk that `recurrence.ts` and Android's `EventSpan.kt` also
//! do, and it moves in phase 9 with them.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::bookmarks::{normalize_tags, tone, ToneNode};
use crate::calendars::{parse_recurrence, present, recurrence_json, stored_rule};
use crate::payload::{
    as_object, declared_readable, refuse_newer_major, text, trimmed, write_payload,
};
use crate::{CoreError, CoreRecurrence};
use sealbook_protocol::PAYLOAD_SCHEMA_VERSION;

pub use sealbook_protocol::{DEFAULT_TASK_LIST_NAME, TASK_CONTENT_TYPE, TASK_LIST_CONTENT_TYPE};

/// What a task with no stored title is listed as.
pub const UNTITLED_TASK_TITLE: &str = "Untitled task";

/// What a task whose payload will not parse is listed as.
pub const UNREADABLE_TASK_TITLE: &str = "Unreadable task";

pub const UNTITLED_TASK_LIST_NAME: &str = "Untitled";

/// Completions kept on one recurring task, newest first. A write past it drops
/// the oldest.
pub const MAX_TASK_COMPLETIONS: usize = 50;

pub const TASK_KEYS: &[&str] = &[
    "@type",
    "version",
    "title",
    "notes",
    "done",
    "completedAt",
    "completions",
    "dueDate",
    "priority",
    "tags",
    "taskListId",
    "parentId",
    "recurrence",
    "recurrenceAnchor",
    "createdAt",
    "updatedAt",
];

pub const TASK_LIST_KEYS: &[&str] = &["@type", "version", "name", "parentId", "color"];

/// The default task list's id, as a string, since that is how every host holds a
/// task's `taskListId`.
pub fn default_task_list_id() -> String {
    sealbook_protocol::DEFAULT_TASK_LIST_ID.to_string()
}

/// A task's `taskListId`, with a blank or missing one resolved to the default
/// list every account has.
pub fn resolve_task_list_id(task_list_id: Option<String>) -> String {
    task_list_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(default_task_list_id)
}

/// A due value as it should be stored, or `None` where it names no real moment.
///
/// `YYYY-MM-DD` is a task due on a day and has to be a day on the calendar. A
/// value with a `T` is a task due at a time: `HH:MM`, optionally seconds and a
/// fraction, optionally a `Z` or `+HH:MM` offset. The `T` is what tells the two
/// apart, as in a calendar event's `start`.
pub fn normalize_due_date(value: &str) -> Option<String> {
    let value = value.trim();
    if !value.is_ascii() {
        return None;
    }
    let bytes = value.as_bytes();
    if bytes.len() == 10 {
        return valid_day(value).then(|| value.to_string());
    }
    if bytes.len() < 16 || bytes[10] != b'T' || !valid_day(&value[..10]) {
        return None;
    }
    valid_time(&value[11..]).then(|| value.to_string())
}

fn valid_day(day: &str) -> bool {
    let bytes = day.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let (Some(year), Some(month), Some(date)) =
        (digits(&day[..4]), digits(&day[5..7]), digits(&day[8..10]))
    else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let length = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=length).contains(&date)
}

fn valid_time(time: &str) -> bool {
    let bytes = time.as_bytes();
    if bytes.len() < 5 || bytes[2] != b':' {
        return false;
    }
    let (Some(hour), Some(minute)) = (digits(&time[..2]), digits(&time[3..5])) else {
        return false;
    };
    if hour > 23 || minute > 59 {
        return false;
    }
    let mut rest = &time[5..];
    if let Some(after) = rest.strip_prefix(':') {
        let Some(second) = after.get(..2).and_then(digits) else {
            return false;
        };
        if second > 59 {
            return false;
        }
        rest = &after[2..];
        if let Some(fraction) = rest.strip_prefix('.') {
            let length = fraction.bytes().take_while(u8::is_ascii_digit).count();
            if length == 0 {
                return false;
            }
            rest = &fraction[length..];
        }
    }
    match rest {
        "" | "Z" => true,
        offset => {
            let Some(sign) = offset.chars().next() else {
                return false;
            };
            let zone = &offset[1..];
            matches!(sign, '+' | '-')
                && zone.len() == 5
                && zone.as_bytes()[2] == b':'
                && digits(&zone[..2]).is_some_and(|hour| hour <= 23)
                && digits(&zone[3..]).is_some_and(|minute| minute <= 59)
        }
    }
}

fn digits(text: &str) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// A priority a writer may store: a whole number above zero. 1 is low, 2 medium
/// and 3 high, but any larger value from a newer build is kept and sorts above.
fn read_priority(value: Option<&Value>) -> Option<u32> {
    value
        .and_then(Value::as_u64)
        .filter(|priority| *priority > 0)
        .and_then(|priority| u32::try_from(priority).ok())
}

/// Completion times: genuine non-empty strings, trimmed, newest first, capped at
/// [`MAX_TASK_COMPLETIONS`].
fn completions_from(entries: impl IntoIterator<Item = String>) -> Vec<String> {
    entries
        .into_iter()
        .map(|entry| entry.trim().to_string())
        .filter(|entry| !entry.is_empty())
        .take(MAX_TASK_COMPLETIONS)
        .collect()
}

fn string_entries(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// One task as it is drafted, before it is written.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreTaskDraft {
    /// May be empty: the reader lists such a task as [`UNTITLED_TASK_TITLE`].
    pub title: String,
    /// Empty writes no `notes` key.
    pub notes: String,
    /// False writes no `done` key.
    pub done: bool,
    /// Written only on a done task.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    /// Newest first. Empty writes no `completions` key.
    pub completions: Vec<String>,
    /// `YYYY-MM-DD` or a timed value; see [`normalize_due_date`]. One that names
    /// no real moment writes no key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub due_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
    /// Empty writes no `tags` key.
    pub tags: Vec<String>,
    pub task_list_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recurrence: Option<CoreRecurrence>,
    /// The stored rule this build could not name, as JSON, carried from
    /// [`CoreTask::unreadable_recurrence`]. `recurrence` wins where both are set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable_recurrence: Option<String>,
    /// The date the rule counts from, written once and kept through every
    /// roll-forward. Written only on a task that repeats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recurrence_anchor: Option<String>,
    /// Client-generated: the server keeps no user timestamps. `None` on a new
    /// task, which takes the `now` passed to [`task_write`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// The payload this draft came from, when it came from one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

/// One task as it was read back.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreTask {
    pub id: String,
    /// The title to list: the stored one, else [`UNTITLED_TASK_TITLE`].
    pub title: String,
    /// True when [`CoreTask::title`] is a fallback and the payload stores no
    /// title, so a save must not write it back.
    pub derived_title: bool,
    pub notes: String,
    pub done: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    pub completions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub due_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
    pub tags: Vec<String>,
    pub task_list_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recurrence: Option<CoreRecurrence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable_recurrence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recurrence_anchor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Whether this build reads the schema major the payload declares. False
    /// means the fields above were still read, but [`task_write`] refuses.
    pub readable: bool,
    pub raw: String,
}

impl CoreTask {
    /// The draft that writes this task back unchanged, for a host to edit the
    /// fields it names.
    pub fn draft(&self) -> CoreTaskDraft {
        CoreTaskDraft {
            title: if self.derived_title {
                String::new()
            } else {
                self.title.clone()
            },
            notes: self.notes.clone(),
            done: self.done,
            completed_at: self.completed_at.clone(),
            completions: self.completions.clone(),
            due_date: self.due_date.clone(),
            priority: self.priority,
            tags: self.tags.clone(),
            task_list_id: self.task_list_id.clone(),
            parent_id: self.parent_id.clone(),
            recurrence: self.recurrence.clone(),
            unreadable_recurrence: self.unreadable_recurrence.clone(),
            recurrence_anchor: self.recurrence_anchor.clone(),
            created_at: self.created_at.clone(),
            raw: Some(self.raw.clone()),
        }
    }
}

/// A task list as it is drafted.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreTaskListDraft {
    pub name: String,
    /// `None` is a list at the top level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    /// Only a top-level list carries one; see [`task_list_tone`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreTaskList {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    pub readable: bool,
    pub raw: String,
}

impl CoreTaskList {
    pub fn draft(&self) -> CoreTaskListDraft {
        CoreTaskListDraft {
            name: self.name.clone(),
            parent_id: self.parent_id.clone(),
            color: self.color.clone(),
            raw: Some(self.raw.clone()),
        }
    }
}

/// Reads a stored task payload.
///
/// Lenient throughout: a payload that is not a JSON object comes back under
/// [`UNREADABLE_TASK_TITLE`], because a task the user cannot see is one the user
/// cannot delete.
pub fn task_parse(id: &str, raw: &str) -> CoreTask {
    let Some(object) = as_object(raw) else {
        return CoreTask {
            id: id.to_string(),
            title: UNREADABLE_TASK_TITLE.to_string(),
            derived_title: true,
            notes: String::new(),
            done: false,
            completed_at: None,
            completions: Vec::new(),
            due_date: None,
            priority: None,
            tags: Vec::new(),
            task_list_id: default_task_list_id(),
            parent_id: None,
            recurrence: None,
            unreadable_recurrence: None,
            recurrence_anchor: None,
            created_at: None,
            updated_at: None,
            readable: true,
            raw: raw.to_string(),
        };
    };
    let stored_title = trimmed(&object, "title");
    let done = object.get("done").and_then(Value::as_bool) == Some(true);
    let rule = stored_rule(&object);
    CoreTask {
        id: id.to_string(),
        derived_title: stored_title.is_none(),
        title: stored_title.unwrap_or_else(|| UNTITLED_TASK_TITLE.to_string()),
        notes: text(&object, "notes").trim().to_string(),
        done,
        completed_at: trimmed(&object, "completedAt").filter(|_| done),
        completions: completions_from(string_entries(object.get("completions"))),
        due_date: trimmed(&object, "dueDate").and_then(|due| normalize_due_date(&due)),
        priority: read_priority(object.get("priority")),
        tags: normalize_tags(&string_entries(object.get("tags"))),
        task_list_id: resolve_task_list_id(trimmed(&object, "taskListId")),
        parent_id: trimmed(&object, "parentId"),
        recurrence: rule.and_then(parse_recurrence),
        unreadable_recurrence: rule
            .filter(|stored| parse_recurrence(stored).is_none())
            .map(|stored| Value::Object(stored.clone()).to_string()),
        recurrence_anchor: trimmed(&object, "recurrenceAnchor")
            .and_then(|anchor| normalize_due_date(&anchor)),
        created_at: trimmed(&object, "createdAt"),
        updated_at: trimmed(&object, "updatedAt"),
        readable: declared_readable(&object),
        raw: raw.to_string(),
    }
}

/// Serialises a task, merging onto whatever `draft.raw` carried.
///
/// `now` is the caller's clock: core has none. It becomes `updatedAt`, and
/// `createdAt` too on a task that has none.
pub fn task_write(draft: &CoreTaskDraft, now: &str) -> Result<String, CoreError> {
    refuse_newer_major(draft.raw.as_deref())?;

    let notes = draft.notes.trim();
    let tags = normalize_tags(&draft.tags);
    let completions = completions_from(draft.completions.iter().cloned());
    let repeats = draft.recurrence.is_some()
        || draft
            .unreadable_recurrence
            .as_deref()
            .and_then(as_object)
            .is_some();
    let mut fields = Map::new();
    fields.insert("@type".into(), json!("Task"));
    fields.insert("version".into(), json!(PAYLOAD_SCHEMA_VERSION));
    fields.insert("title".into(), json!(draft.title.trim()));
    if !notes.is_empty() {
        fields.insert("notes".into(), json!(notes));
    }
    if draft.done {
        fields.insert("done".into(), json!(true));
        if let Some(at) = present(&draft.completed_at) {
            fields.insert("completedAt".into(), json!(at));
        }
    }
    if !completions.is_empty() {
        fields.insert("completions".into(), json!(completions));
    }
    if let Some(due) = draft.due_date.as_deref().and_then(normalize_due_date) {
        fields.insert("dueDate".into(), json!(due));
    }
    if let Some(priority) = draft.priority.filter(|priority| *priority > 0) {
        fields.insert("priority".into(), json!(priority));
    }
    if !tags.is_empty() {
        fields.insert("tags".into(), json!(tags));
    }
    fields.insert(
        "taskListId".into(),
        json!(resolve_task_list_id(Some(draft.task_list_id.clone()))),
    );
    if let Some(parent) = present(&draft.parent_id) {
        fields.insert("parentId".into(), json!(parent));
    }
    if let Some(rule) = &draft.recurrence {
        fields.insert("recurrence".into(), recurrence_json(rule));
    } else if let Some(stored) = draft.unreadable_recurrence.as_deref().and_then(as_object) {
        fields.insert("recurrence".into(), Value::Object(stored));
    }
    if repeats {
        if let Some(anchor) = draft
            .recurrence_anchor
            .as_deref()
            .and_then(normalize_due_date)
        {
            fields.insert("recurrenceAnchor".into(), json!(anchor));
        }
    }
    fields.insert(
        "createdAt".into(),
        json!(draft.created_at.as_deref().unwrap_or(now)),
    );
    fields.insert("updatedAt".into(), json!(now));
    Ok(write_payload(
        draft.raw.as_deref(),
        Value::Object(fields),
        TASK_KEYS,
    ))
}

pub fn task_list_parse(id: &str, raw: &str) -> CoreTaskList {
    let object = as_object(raw);
    let read = |key: &str| object.as_ref().and_then(|object| trimmed(object, key));
    CoreTaskList {
        id: id.to_string(),
        name: read("name").unwrap_or_else(|| fallback_list_name(id)),
        parent_id: read("parentId"),
        color: read("color"),
        readable: object.as_ref().map(declared_readable).unwrap_or(true),
        raw: raw.to_string(),
    }
}

pub fn task_list_write(draft: &CoreTaskListDraft) -> Result<String, CoreError> {
    refuse_newer_major(draft.raw.as_deref())?;

    let mut fields = Map::new();
    fields.insert("@type".into(), json!("TaskList"));
    fields.insert("version".into(), json!(PAYLOAD_SCHEMA_VERSION));
    fields.insert("name".into(), json!(draft.name.trim()));
    if let Some(parent) = present(&draft.parent_id) {
        fields.insert("parentId".into(), json!(parent));
    }
    if let Some(color) = present(&draft.color) {
        fields.insert("color".into(), json!(color));
    }
    Ok(write_payload(
        draft.raw.as_deref(),
        Value::Object(fields),
        TASK_LIST_KEYS,
    ))
}

/// The default list is the one every client creates for itself, so an unnamed one
/// is that name rather than `Untitled`.
fn fallback_list_name(id: &str) -> String {
    if id == default_task_list_id() {
        DEFAULT_TASK_LIST_NAME.to_string()
    } else {
        UNTITLED_TASK_LIST_NAME.to_string()
    }
}

/// The name to show for a task's list. A list that is gone shows the default
/// list's name rather than nothing.
pub fn task_list_name_by_id(lists: &[CoreTaskList], task_list_id: Option<String>) -> String {
    let id = resolve_task_list_id(task_list_id);
    lists
        .iter()
        .find(|list| list.id == id)
        .map(|list| list.name.clone())
        .unwrap_or_else(|| DEFAULT_TASK_LIST_NAME.to_string())
}

/// A list's colour: its root's explicit colour, else one hashed from the root's
/// id. The same rule as a bookmark collection's.
pub fn task_list_tone(lists: &[CoreTaskList], id: &str) -> String {
    let nodes: Vec<ToneNode> = lists
        .iter()
        .map(|list| ToneNode {
            id: &list.id,
            parent_id: list.parent_id.as_deref(),
            color: list.color.as_deref(),
        })
        .collect();
    tone(&nodes, id)
}

/// Everything above, in the shapes the bindings can carry.
#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{CoreError, CoreTask, CoreTaskDraft, CoreTaskList, CoreTaskListDraft};

    fn keys(keys: &[&str]) -> Vec<String> {
        keys.iter().map(|key| key.to_string()).collect()
    }

    #[uniffi::export(name = "task_keys")]
    pub fn task_keys() -> Vec<String> {
        keys(super::TASK_KEYS)
    }

    #[uniffi::export(name = "task_list_keys")]
    pub fn task_list_keys() -> Vec<String> {
        keys(super::TASK_LIST_KEYS)
    }

    #[uniffi::export(name = "default_task_list_id")]
    pub fn default_task_list_id() -> String {
        super::default_task_list_id()
    }

    #[uniffi::export(name = "resolve_task_list_id")]
    pub fn resolve_task_list_id(task_list_id: Option<String>) -> String {
        super::resolve_task_list_id(task_list_id)
    }

    #[uniffi::export(name = "normalize_due_date")]
    pub fn normalize_due_date(value: String) -> Option<String> {
        super::normalize_due_date(&value)
    }

    #[uniffi::export(name = "task_parse")]
    pub fn task_parse(id: String, raw: String) -> CoreTask {
        super::task_parse(&id, &raw)
    }

    #[uniffi::export(name = "task_write")]
    pub fn task_write(draft: CoreTaskDraft, now: String) -> Result<String, CoreError> {
        super::task_write(&draft, &now)
    }

    #[uniffi::export(name = "task_list_parse")]
    pub fn task_list_parse(id: String, raw: String) -> CoreTaskList {
        super::task_list_parse(&id, &raw)
    }

    #[uniffi::export(name = "task_list_write")]
    pub fn task_list_write(draft: CoreTaskListDraft) -> Result<String, CoreError> {
        super::task_list_write(&draft)
    }

    #[uniffi::export(name = "task_list_name_by_id")]
    pub fn task_list_name_by_id(lists: Vec<CoreTaskList>, task_list_id: Option<String>) -> String {
        super::task_list_name_by_id(&lists, task_list_id)
    }

    #[uniffi::export(name = "task_list_tone")]
    pub fn task_list_tone(lists: Vec<CoreTaskList>, id: String) -> String {
        super::task_list_tone(&lists, &id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: &str = "2026-10-28T12:00:00Z";

    fn draft() -> CoreTaskDraft {
        CoreTaskDraft {
            title: "Pay rent".into(),
            task_list_id: default_task_list_id(),
            ..Default::default()
        }
    }

    fn written(draft: &CoreTaskDraft) -> Map<String, Value> {
        as_object(&task_write(draft, NOW).unwrap()).expect("an object")
    }

    #[test]
    fn an_open_task_carries_only_what_it_has() {
        let task = written(&draft());
        for absent in [
            "notes",
            "done",
            "completedAt",
            "completions",
            "dueDate",
            "priority",
            "tags",
            "parentId",
            "recurrence",
            "recurrenceAnchor",
        ] {
            assert!(!task.contains_key(absent), "{absent} was written");
        }
    }

    #[test]
    fn a_due_value_must_name_a_real_moment() {
        for good in [
            "2026-10-28",
            "2024-02-29",
            "2026-10-28T09:30",
            "2026-10-28T09:30:15.250Z",
            "2026-10-28T09:30:00+01:00",
        ] {
            assert_eq!(normalize_due_date(good).as_deref(), Some(good), "{good}");
        }
        for bad in [
            "",
            "tomorrow",
            "2026-02-30",
            "2026-13-01",
            "2025-02-29",
            "2026-10-28T25:00",
            "2026-10-28T09",
            "2026-10-28 09:30",
            "2026-10-28T09:30:00+0100",
        ] {
            assert_eq!(normalize_due_date(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_completed_at_is_written_only_on_a_done_task() {
        let open = CoreTaskDraft {
            completed_at: Some("2026-10-27T00:00:00Z".into()),
            ..draft()
        };
        assert!(!written(&open).contains_key("completedAt"));
        let done = CoreTaskDraft { done: true, ..open };
        assert_eq!(written(&done)["completedAt"], "2026-10-27T00:00:00Z");
    }

    #[test]
    fn an_anchor_is_written_only_on_a_task_that_repeats() {
        let anchored = CoreTaskDraft {
            recurrence_anchor: Some("2026-10-01".into()),
            ..draft()
        };
        assert!(!written(&anchored).contains_key("recurrenceAnchor"));
    }

    #[test]
    fn a_rule_this_build_cannot_name_comes_back_on_the_next_save() {
        let stored = r#"{"@type":"Task","title":"t","dueDate":"2026-10-01","recurrence":{"frequency":"hourly"},"recurrenceAnchor":"2026-10-01"}"#;
        let task = task_parse("t", stored);
        assert!(task.recurrence.is_none());
        let rewritten = written(&task.draft());
        assert_eq!(rewritten["recurrence"]["frequency"], "hourly");
        assert_eq!(rewritten["recurrenceAnchor"], "2026-10-01");
    }

    #[test]
    fn a_task_with_no_stored_title_is_not_titled_by_a_save() {
        let task = task_parse("t", r#"{"@type":"Task","title":"  "}"#);
        assert_eq!(task.title, UNTITLED_TASK_TITLE);
        assert!(task.derived_title);
        assert_eq!(written(&task.draft())["title"], "");
    }

    #[test]
    fn completions_are_trimmed_and_capped_at_the_newest() {
        let many: Vec<String> = (0..60).map(|n| format!(" t{n} ")).collect();
        let read = completions_from(many);
        assert_eq!(read.len(), MAX_TASK_COMPLETIONS);
        assert_eq!(read[0], "t0");
    }

    #[test]
    fn a_nested_list_takes_its_roots_colour() {
        let parse = |id: &str, raw: &str| task_list_parse(id, raw);
        let lists = vec![
            parse("root", r##"{"name":"R","color":"#123456"}"##),
            parse("child", r#"{"name":"C","parentId":"root"}"#),
        ];
        assert_eq!(task_list_tone(&lists, "child"), "#123456");
    }

    #[test]
    fn an_unnamed_list_is_named_for_whether_it_is_the_default() {
        let default = task_list_parse(&default_task_list_id(), "{}");
        assert_eq!(default.name, DEFAULT_TASK_LIST_NAME);
        assert_eq!(task_list_parse("x", "nope").name, "Untitled");
    }
}
