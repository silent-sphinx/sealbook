//! What ticking, deleting or moving a task does to it and to the tasks around
//! it, the order tasks list in, and the task export file.
//!
//! Each action is a plan: the drafts to write and the ids to delete. The host
//! writes them in order and owns nothing but the screen.
//!
//! Core has no clock and no time zones. A timed due value is a UTC instant, so
//! the host hands over its local wall-clock form in [`CoreTaskClock`] and turns
//! a rolled [`CoreTaskCompletion::local_due`] back into UTC, the same boundary
//! `ics_parse` draws.

use std::cmp::Ordering;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::calendars::recurrence_json;
use crate::order::name_key;
use crate::payload::as_object;
use crate::recurrence::{parse_day, recurrence_next, Day};
use crate::tasks::{
    default_task_list_id, normalize_due_date, resolve_task_list_id, task_list_name_by_id,
    task_parse, CoreTask, CoreTaskDraft, CoreTaskList, CoreTaskListDraft, MAX_TASK_COMPLETIONS,
};
use crate::tree::{can_reparent, subtree, TreeRef};
use crate::CoreError;

pub const TASK_MOVE_REFUSAL: &str = "A task cannot be moved inside itself.";
pub const TASK_LIST_MOVE_REFUSAL: &str = "A list cannot be moved inside itself.";
pub const DEFAULT_TASK_LIST_REMOVE_REFUSAL: &str = "The default list cannot be deleted.";
pub const TASK_IMPORT_REFUSAL: &str =
    "Unrecognised format. Expected a Sealbook task export or a JSON array of tasks.";

/// The `@type` of a task export file.
pub const TASK_EXPORT_TYPE: &str = "sealbook-task-export";

/// The host's clock, and a task's stored values in the host's local time.
///
/// `due_local` and `anchor_local` are `YYYY-MM-DD` for an all-day value and
/// `YYYY-MM-DDTHH:MM` (seconds optional) for a timed one.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreTaskClock {
    /// UTC, written as `completedAt` and into `completions`.
    pub now: String,
    /// The local `YYYY-MM-DD`.
    pub today: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub due_local: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_local: Option<String>,
}

/// One task to write, under its id.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreTaskWrite {
    pub id: String,
    pub draft: CoreTaskDraft,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreTaskListWrite {
    pub id: String,
    pub draft: CoreTaskListDraft,
}

/// What ticking a task writes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreTaskCompletion {
    pub task: CoreTaskDraft,
    /// True when a recurring task stayed open and moved to its next date.
    pub rolled: bool,
    /// The next local due time of a rolled timed task. `task.due_date` is
    /// `None` until the host stores this value's UTC form there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_due: Option<String>,
    /// Done subtasks reopened by the roll, written after the task.
    pub reopened: Vec<CoreTaskWrite>,
}

/// The writes and deletes one task action makes. A non-empty `refusal` is the
/// sentence to show instead, with nothing to write.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreTaskPlan {
    pub tasks: Vec<CoreTaskWrite>,
    pub removed_tasks: Vec<String>,
    pub lists: Vec<CoreTaskListWrite>,
    pub removed_lists: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
}

impl CoreTaskPlan {
    fn refused(sentence: &str) -> Self {
        CoreTaskPlan {
            refusal: Some(sentence.to_string()),
            ..Default::default()
        }
    }
}

/// What the task order needs of one task. `due_at` is the due moment in epoch
/// milliseconds, local midnight for an all-day task, and `None` for no due date.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreTaskOrderItem {
    pub id: String,
    pub title: String,
    pub done: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub due_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
}

/// One task read from an import file. `source_id` is the id the file gave it,
/// which a subtask's `draft.parent_id` still points at.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreImportedTask {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    pub draft: CoreTaskDraft,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreTaskImport {
    /// Every parent before its subtasks.
    pub tasks: Vec<CoreImportedTask>,
    pub skipped: u32,
}

fn task_refs(tasks: &[CoreTask]) -> Vec<TreeRef<'_>> {
    tasks
        .iter()
        .map(|task| TreeRef {
            id: &task.id,
            parent_id: task.parent_id.as_deref(),
        })
        .collect()
}

fn list_refs(lists: &[CoreTaskList]) -> Vec<TreeRef<'_>> {
    lists
        .iter()
        .map(|list| TreeRef {
            id: &list.id,
            parent_id: list.parent_id.as_deref(),
        })
        .collect()
}

fn blank_to_none(id: Option<String>) -> Option<String> {
    id.map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
}

fn day_of(value: &str) -> &str {
    value.get(..10).unwrap_or(value)
}

/// The task and every task under it, the task first.
pub fn task_subtree(tasks: &[CoreTask], id: &str) -> Vec<String> {
    subtree(&task_refs(tasks), id)
}

/// Whether `id` may be moved under `parent_id`.
pub fn task_can_move(tasks: &[CoreTask], id: &str, parent_id: Option<String>) -> bool {
    can_reparent(&task_refs(tasks), id, blank_to_none(parent_id).as_deref())
}

/// Whether list `id` may be moved under `parent_id`. The default list stays at
/// the top level.
pub fn task_list_can_move(lists: &[CoreTaskList], id: &str, parent_id: Option<String>) -> bool {
    let parent_id = blank_to_none(parent_id);
    if id == default_task_list_id() {
        return parent_id.is_none();
    }
    can_reparent(&list_refs(lists), id, parent_id.as_deref())
}

/// The draft that reopens a task.
pub fn task_reopen(task: &CoreTask) -> CoreTaskDraft {
    CoreTaskDraft {
        done: false,
        completed_at: None,
        ..task.draft()
    }
}

/// The next due date of a recurring task, the local time it keeps if timed,
/// and the anchor to store. `None` when it does not repeat or the series is
/// spent.
fn rolled(task: &CoreTask, clock: &CoreTaskClock) -> Option<(String, Option<String>, String)> {
    let rule = task.recurrence.as_ref()?;
    let due = task.due_date.as_deref().and_then(normalize_due_date)?;
    let timed = due.contains('T');
    let due_local = if timed {
        clock.due_local.clone().unwrap_or_else(|| due.clone())
    } else {
        due.clone()
    };
    let stored_anchor = task
        .recurrence_anchor
        .as_deref()
        .and_then(normalize_due_date);
    let anchor_local = match &stored_anchor {
        Some(anchor) => clock.anchor_local.clone().unwrap_or_else(|| anchor.clone()),
        None => due_local.clone(),
    };
    let current = day_of(&due_local);
    let after = current.max(clock.today.as_str());
    let next = recurrence_next(day_of(&anchor_local), rule, after)?;
    let time = timed.then(|| match due_local.get(10..) {
        Some(time) if time.starts_with('T') => time.to_string(),
        _ => "T00:00".to_string(),
    });
    Some((next, time, stored_anchor.unwrap_or(due)))
}

/// Ticks a task. A recurring task with a later occurrence stays open, moves to
/// it and reopens its done subtasks; anything else is marked done.
pub fn task_complete(
    task: &CoreTask,
    tasks: &[CoreTask],
    clock: &CoreTaskClock,
) -> CoreTaskCompletion {
    let mut draft = task.draft();
    if task.recurrence.is_some() {
        draft.completions = std::iter::once(clock.now.clone())
            .chain(task.completions.iter().cloned())
            .take(MAX_TASK_COMPLETIONS)
            .collect();
    }
    let Some((next, time, anchor)) = rolled(task, clock) else {
        draft.done = true;
        draft.completed_at = Some(clock.now.clone());
        return CoreTaskCompletion {
            task: draft,
            rolled: false,
            local_due: None,
            reopened: Vec::new(),
        };
    };
    draft.done = false;
    draft.completed_at = None;
    draft.recurrence_anchor = Some(anchor);
    let local_due = match time {
        Some(time) => {
            draft.due_date = None;
            Some(format!("{next}{time}"))
        }
        None => {
            draft.due_date = Some(next);
            None
        }
    };
    let by_id: HashMap<&str, &CoreTask> = tasks
        .iter()
        .map(|entry| (entry.id.as_str(), entry))
        .collect();
    let reopened = task_subtree(tasks, &task.id)
        .iter()
        .skip(1)
        .filter_map(|id| by_id.get(id.as_str()))
        .filter(|child| child.done)
        .map(|child| CoreTaskWrite {
            id: child.id.clone(),
            draft: task_reopen(child),
        })
        .collect();
    CoreTaskCompletion {
        task: draft,
        rolled: true,
        local_due,
        reopened,
    }
}

/// Deletes a task. Its direct subtasks move up to its parent.
pub fn task_remove_plan(tasks: &[CoreTask], id: &str) -> CoreTaskPlan {
    let parent = tasks
        .iter()
        .find(|task| task.id == id)
        .and_then(|task| task.parent_id.clone());
    let writes = tasks
        .iter()
        .filter(|task| task.id != id && task.parent_id.as_deref() == Some(id))
        .map(|task| CoreTaskWrite {
            id: task.id.clone(),
            draft: CoreTaskDraft {
                parent_id: parent.clone(),
                ..task.draft()
            },
        })
        .collect();
    CoreTaskPlan {
        tasks: writes,
        removed_tasks: vec![id.to_string()],
        ..Default::default()
    }
}

/// Moves a task under `parent_id`, or to the top level. A task moved under a
/// parent in another list joins that list, and its subtasks follow it.
pub fn task_move_plan(tasks: &[CoreTask], id: &str, parent_id: Option<String>) -> CoreTaskPlan {
    let parent_id = blank_to_none(parent_id);
    let Some(task) = tasks.iter().find(|task| task.id == id) else {
        return CoreTaskPlan::default();
    };
    if !task_can_move(tasks, id, parent_id.clone()) {
        return CoreTaskPlan::refused(TASK_MOVE_REFUSAL);
    }
    let parent = parent_id
        .as_deref()
        .and_then(|parent| tasks.iter().find(|entry| entry.id == parent));
    let list = resolve_task_list_id(Some(parent.unwrap_or(task).task_list_id.clone()));
    let relisted = list != resolve_task_list_id(Some(task.task_list_id.clone()));
    if task.parent_id == parent_id && !relisted {
        return CoreTaskPlan::default();
    }
    let mut writes = vec![CoreTaskWrite {
        id: id.to_string(),
        draft: CoreTaskDraft {
            parent_id: parent_id.clone(),
            task_list_id: list.clone(),
            ..task.draft()
        },
    }];
    if relisted {
        let by_id: HashMap<&str, &CoreTask> = tasks
            .iter()
            .map(|entry| (entry.id.as_str(), entry))
            .collect();
        for child_id in task_subtree(tasks, id).iter().skip(1) {
            if let Some(child) = by_id.get(child_id.as_str()) {
                writes.push(CoreTaskWrite {
                    id: child.id.clone(),
                    draft: CoreTaskDraft {
                        task_list_id: list.clone(),
                        ..child.draft()
                    },
                });
            }
        }
    }
    CoreTaskPlan {
        tasks: writes,
        ..Default::default()
    }
}

/// The subtasks that follow a task edited into list `task_list_id`. The edited
/// task itself leaves its parent, which is the host's form to write.
pub fn task_relist_plan(tasks: &[CoreTask], id: &str, task_list_id: &str) -> CoreTaskPlan {
    let list = resolve_task_list_id(Some(task_list_id.to_string()));
    let by_id: HashMap<&str, &CoreTask> = tasks
        .iter()
        .map(|entry| (entry.id.as_str(), entry))
        .collect();
    let writes = task_subtree(tasks, id)
        .iter()
        .skip(1)
        .filter_map(|child_id| by_id.get(child_id.as_str()))
        .map(|child| CoreTaskWrite {
            id: child.id.clone(),
            draft: CoreTaskDraft {
                task_list_id: list.clone(),
                ..child.draft()
            },
        })
        .collect();
    CoreTaskPlan {
        tasks: writes,
        ..Default::default()
    }
}

/// Moves a list under `parent_id`, or to the top level.
pub fn task_list_move_plan(
    lists: &[CoreTaskList],
    id: &str,
    parent_id: Option<String>,
) -> CoreTaskPlan {
    let parent_id = blank_to_none(parent_id);
    let Some(list) = lists.iter().find(|list| list.id == id) else {
        return CoreTaskPlan::default();
    };
    if !task_list_can_move(lists, id, parent_id.clone()) {
        return CoreTaskPlan::refused(TASK_LIST_MOVE_REFUSAL);
    }
    if list.parent_id == parent_id {
        return CoreTaskPlan::default();
    }
    CoreTaskPlan {
        lists: vec![CoreTaskListWrite {
            id: id.to_string(),
            draft: CoreTaskListDraft {
                parent_id,
                ..list.draft()
            },
        }],
        ..Default::default()
    }
}

/// Deletes a list. Its child lists move up to its parent, and its tasks move to
/// its parent, or to the default list from the top level.
pub fn task_list_remove_plan(lists: &[CoreTaskList], tasks: &[CoreTask], id: &str) -> CoreTaskPlan {
    if id == default_task_list_id() {
        return CoreTaskPlan::refused(DEFAULT_TASK_LIST_REMOVE_REFUSAL);
    }
    let parent = lists
        .iter()
        .find(|list| list.id == id)
        .and_then(|list| list.parent_id.clone());
    let home = parent.clone().unwrap_or_else(default_task_list_id);
    let child_lists = lists
        .iter()
        .filter(|list| list.id != id && list.parent_id.as_deref() == Some(id))
        .map(|list| CoreTaskListWrite {
            id: list.id.clone(),
            draft: CoreTaskListDraft {
                parent_id: parent.clone(),
                ..list.draft()
            },
        })
        .collect();
    let moved = tasks
        .iter()
        .filter(|task| resolve_task_list_id(Some(task.task_list_id.clone())) == id)
        .map(|task| CoreTaskWrite {
            id: task.id.clone(),
            draft: CoreTaskDraft {
                task_list_id: home.clone(),
                ..task.draft()
            },
        })
        .collect();
    CoreTaskPlan {
        tasks: moved,
        lists: child_lists,
        removed_lists: vec![id.to_string()],
        ..Default::default()
    }
}

/// Ids in list order: open before done, then soonest due, then highest
/// priority, then title.
pub fn order_tasks(items: &[CoreTaskOrderItem]) -> Vec<String> {
    let due = |item: &CoreTaskOrderItem| {
        item.due_at
            .filter(|at| at.is_finite())
            .unwrap_or(f64::INFINITY)
    };
    let mut sorted: Vec<&CoreTaskOrderItem> = items.iter().collect();
    sorted.sort_by(|a, b| {
        a.done
            .cmp(&b.done)
            .then_with(|| due(a).partial_cmp(&due(b)).unwrap_or(Ordering::Equal))
            .then_with(|| b.priority.unwrap_or(0).cmp(&a.priority.unwrap_or(0)))
            .then_with(|| name_key(&a.title).cmp(&name_key(&b.title)))
            .then_with(|| a.title.cmp(&b.title))
            .then_with(|| a.id.cmp(&b.id))
    });
    sorted.into_iter().map(|item| item.id.clone()).collect()
}

/// What the agenda needs of one task, its times in the host's local wall clock.
///
/// `due_local` is `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM`, as in [`CoreTaskClock`].
/// `completed_local` is the local `YYYY-MM-DDTHH:MM` of `completedAt`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreTaskAgendaItem {
    pub id: String,
    pub title: String,
    pub done: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub due_local: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_local: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
}

/// Task ids grouped by when they are due, each group in display order.
///
/// `week` holds the five days after tomorrow, so it and `tomorrow` cover the
/// next seven. A timed task whose time has passed is overdue on its own day.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreTaskAgenda {
    pub overdue: Vec<String>,
    pub today: Vec<String>,
    pub tomorrow: Vec<String>,
    pub week: Vec<String>,
    pub later: Vec<String>,
    pub undated: Vec<String>,
    pub done_today: Vec<String>,
}

fn minute_of(value: &str) -> &str {
    value.get(..16).unwrap_or(value)
}

/// The open tasks by due date, and the tasks completed today, for a host
/// whose local time is `now_local` (`YYYY-MM-DDTHH:MM`).
pub fn task_agenda(items: &[CoreTaskAgendaItem], now_local: &str) -> CoreTaskAgenda {
    let mut agenda = CoreTaskAgenda::default();
    let Some(today) = parse_day(now_local) else {
        return agenda;
    };
    let mut open: Vec<(&CoreTaskAgendaItem, Option<Day>)> = Vec::new();
    let mut done: Vec<&CoreTaskAgendaItem> = Vec::new();
    for item in items {
        if item.done {
            let finished = item.completed_local.as_deref().and_then(parse_day);
            if finished == Some(today) {
                done.push(item);
            }
        } else {
            open.push((item, item.due_local.as_deref().and_then(parse_day)));
        }
    }
    fn due_key(item: &CoreTaskAgendaItem) -> Option<&str> {
        item.due_local.as_deref().map(minute_of)
    }
    open.sort_by(|(a, a_day), (b, b_day)| {
        a_day
            .is_none()
            .cmp(&b_day.is_none())
            .then_with(|| a_day.and(due_key(a)).cmp(&b_day.and(due_key(b))))
            .then_with(|| b.priority.unwrap_or(0).cmp(&a.priority.unwrap_or(0)))
            .then_with(|| name_key(&a.title).cmp(&name_key(&b.title)))
            .then_with(|| a.title.cmp(&b.title))
            .then_with(|| a.id.cmp(&b.id))
    });
    let now_minute = minute_of(now_local);
    for (item, day) in open {
        let section = match day {
            None => &mut agenda.undated,
            Some(day) => {
                let timed = item
                    .due_local
                    .as_deref()
                    .is_some_and(|due| due.contains('T'));
                let passed = timed && due_key(item).is_some_and(|due| due < now_minute);
                match day.0 - today.0 {
                    delta if delta < 0 => &mut agenda.overdue,
                    0 if passed => &mut agenda.overdue,
                    0 => &mut agenda.today,
                    1 => &mut agenda.tomorrow,
                    2..=7 => &mut agenda.week,
                    _ => &mut agenda.later,
                }
            }
        };
        section.push(item.id.clone());
    }
    done.sort_by(|a, b| {
        b.completed_local
            .as_deref()
            .map(minute_of)
            .cmp(&a.completed_local.as_deref().map(minute_of))
            .then_with(|| name_key(&a.title).cmp(&name_key(&b.title)))
            .then_with(|| a.id.cmp(&b.id))
    });
    agenda.done_today = done.into_iter().map(|item| item.id.clone()).collect();
    agenda
}

/// The stored rule, readable or not, as the export writes it.
fn export_recurrence(task: &CoreTask) -> Option<Value> {
    if let Some(rule) = &task.recurrence {
        return Some(recurrence_json(rule));
    }
    task.unreadable_recurrence
        .as_deref()
        .and_then(as_object)
        .map(Value::Object)
}

fn export_entry(task: &CoreTask, lists: &[CoreTaskList]) -> Value {
    let mut entry = Map::new();
    entry.insert("id".into(), json!(task.id));
    entry.insert("title".into(), json!(task.title));
    if !task.notes.is_empty() {
        entry.insert("notes".into(), json!(task.notes));
    }
    if task.done {
        entry.insert("done".into(), json!(true));
    }
    let optional = [
        ("completedAt", task.completed_at.clone()),
        ("dueDate", task.due_date.clone()),
        ("parentId", task.parent_id.clone()),
        ("recurrenceAnchor", task.recurrence_anchor.clone()),
        ("createdAt", task.created_at.clone()),
        ("updatedAt", task.updated_at.clone()),
    ];
    for (key, value) in optional {
        if let Some(value) = value {
            entry.insert(key.into(), json!(value));
        }
    }
    if !task.completions.is_empty() {
        entry.insert("completions".into(), json!(task.completions));
    }
    if let Some(priority) = task.priority {
        entry.insert("priority".into(), json!(priority));
    }
    if !task.tags.is_empty() {
        entry.insert("tags".into(), json!(task.tags));
    }
    if let Some(rule) = export_recurrence(task) {
        entry.insert("recurrence".into(), rule);
    }
    entry.insert(
        "listName".into(),
        json!(task_list_name_by_id(lists, Some(task.task_list_id.clone()))),
    );
    Value::Object(entry)
}

/// A task export file. Each task carries its list's name, and the lists ride
/// along for a reader that wants them.
pub fn task_export(tasks: &[CoreTask], lists: &[CoreTaskList], now: &str) -> String {
    let lists_out: Vec<Value> = lists
        .iter()
        .map(|list| {
            let mut entry = Map::new();
            entry.insert("id".into(), json!(list.id));
            entry.insert("name".into(), json!(list.name));
            if let Some(parent) = &list.parent_id {
                entry.insert("parentId".into(), json!(parent));
            }
            if let Some(color) = &list.color {
                entry.insert("color".into(), json!(color));
            }
            Value::Object(entry)
        })
        .collect();
    let document = json!({
        "@type": TASK_EXPORT_TYPE,
        "version": 1,
        "exportedAt": now,
        "tasks": tasks.iter().map(|task| export_entry(task, lists)).collect::<Vec<_>>(),
        "lists": lists_out,
    });
    serde_json::to_string_pretty(&document).unwrap_or_default()
}

/// Reads a task export, or a bare JSON array of task-like objects. Each entry is
/// read as a stored task is, so an import obeys the same rules. An entry with no
/// title is skipped. The result is in import order: a parent before its
/// subtasks, and a subtask whose parent the file does not hold, or that sits on
/// a cycle, at the top level.
pub fn task_import(text: &str) -> Result<CoreTaskImport, CoreError> {
    let parsed: Value =
        serde_json::from_str(text.trim()).map_err(|_| CoreError::malformed(TASK_IMPORT_REFUSAL))?;
    let entries = match &parsed {
        Value::Array(entries) => entries,
        Value::Object(body) if body.get("@type") == Some(&json!(TASK_EXPORT_TYPE)) => body
            .get("tasks")
            .and_then(Value::as_array)
            .ok_or_else(|| CoreError::malformed(TASK_IMPORT_REFUSAL))?,
        _ => return Err(CoreError::malformed(TASK_IMPORT_REFUSAL)),
    };
    let mut tasks = Vec::new();
    let mut skipped = 0u32;
    for entry in entries {
        let Some(fields) = entry.as_object() else {
            skipped += 1;
            continue;
        };
        if fields
            .get("title")
            .and_then(Value::as_str)
            .is_none_or(|title| title.trim().is_empty())
        {
            skipped += 1;
            continue;
        }
        let mut stored = fields.clone();
        stored.insert("@type".into(), json!("Task"));
        let task = task_parse("import", &Value::Object(stored).to_string());
        tasks.push(CoreImportedTask {
            source_id: fields
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .map(ToOwned::to_owned),
            draft: CoreTaskDraft {
                raw: None,
                ..task.draft()
            },
        });
    }
    Ok(CoreTaskImport {
        tasks: import_order(tasks),
        skipped,
    })
}

fn import_order(mut tasks: Vec<CoreImportedTask>) -> Vec<CoreImportedTask> {
    let mut by_source: HashMap<String, usize> = HashMap::new();
    for (index, task) in tasks.iter().enumerate() {
        if let Some(source) = &task.source_id {
            by_source.entry(source.clone()).or_insert(index);
        }
    }
    let mut placed = vec![false; tasks.len()];
    let mut order = Vec::with_capacity(tasks.len());
    for index in 0..tasks.len() {
        let mut trail = vec![false; tasks.len()];
        place(
            index,
            &mut tasks,
            &by_source,
            &mut trail,
            &mut placed,
            &mut order,
        );
    }
    let mut slots: Vec<Option<CoreImportedTask>> = tasks.into_iter().map(Some).collect();
    order
        .into_iter()
        .filter_map(|index| slots[index].take())
        .collect()
}

fn place(
    index: usize,
    tasks: &mut [CoreImportedTask],
    by_source: &HashMap<String, usize>,
    trail: &mut [bool],
    placed: &mut [bool],
    order: &mut Vec<usize>,
) {
    if placed[index] {
        return;
    }
    let parent = tasks[index]
        .draft
        .parent_id
        .as_ref()
        .and_then(|parent| by_source.get(parent).copied());
    match parent {
        Some(parent) if parent != index && !trail[parent] => {
            trail[index] = true;
            place(parent, tasks, by_source, trail, placed, order);
        }
        _ => tasks[index].draft.parent_id = None,
    }
    placed[index] = true;
    order.push(index);
}

/// Everything above, in the shapes the bindings can carry.
#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{
        CoreError, CoreTask, CoreTaskAgenda, CoreTaskAgendaItem, CoreTaskClock, CoreTaskCompletion,
        CoreTaskDraft, CoreTaskImport, CoreTaskList, CoreTaskOrderItem, CoreTaskPlan,
    };

    #[uniffi::export(name = "task_agenda")]
    pub fn task_agenda(items: Vec<CoreTaskAgendaItem>, now_local: String) -> CoreTaskAgenda {
        super::task_agenda(&items, &now_local)
    }

    #[uniffi::export(name = "task_subtree")]
    pub fn task_subtree(tasks: Vec<CoreTask>, id: String) -> Vec<String> {
        super::task_subtree(&tasks, &id)
    }

    #[uniffi::export(name = "task_can_move")]
    pub fn task_can_move(tasks: Vec<CoreTask>, id: String, parent_id: Option<String>) -> bool {
        super::task_can_move(&tasks, &id, parent_id)
    }

    #[uniffi::export(name = "task_list_can_move")]
    pub fn task_list_can_move(
        lists: Vec<CoreTaskList>,
        id: String,
        parent_id: Option<String>,
    ) -> bool {
        super::task_list_can_move(&lists, &id, parent_id)
    }

    #[uniffi::export(name = "task_reopen")]
    pub fn task_reopen(task: CoreTask) -> CoreTaskDraft {
        super::task_reopen(&task)
    }

    #[uniffi::export(name = "task_complete")]
    pub fn task_complete(
        task: CoreTask,
        tasks: Vec<CoreTask>,
        clock: CoreTaskClock,
    ) -> CoreTaskCompletion {
        super::task_complete(&task, &tasks, &clock)
    }

    #[uniffi::export(name = "task_remove_plan")]
    pub fn task_remove_plan(tasks: Vec<CoreTask>, id: String) -> CoreTaskPlan {
        super::task_remove_plan(&tasks, &id)
    }

    #[uniffi::export(name = "task_move_plan")]
    pub fn task_move_plan(
        tasks: Vec<CoreTask>,
        id: String,
        parent_id: Option<String>,
    ) -> CoreTaskPlan {
        super::task_move_plan(&tasks, &id, parent_id)
    }

    #[uniffi::export(name = "task_relist_plan")]
    pub fn task_relist_plan(
        tasks: Vec<CoreTask>,
        id: String,
        task_list_id: String,
    ) -> CoreTaskPlan {
        super::task_relist_plan(&tasks, &id, &task_list_id)
    }

    #[uniffi::export(name = "task_list_move_plan")]
    pub fn task_list_move_plan(
        lists: Vec<CoreTaskList>,
        id: String,
        parent_id: Option<String>,
    ) -> CoreTaskPlan {
        super::task_list_move_plan(&lists, &id, parent_id)
    }

    #[uniffi::export(name = "task_list_remove_plan")]
    pub fn task_list_remove_plan(
        lists: Vec<CoreTaskList>,
        tasks: Vec<CoreTask>,
        id: String,
    ) -> CoreTaskPlan {
        super::task_list_remove_plan(&lists, &tasks, &id)
    }

    #[uniffi::export(name = "order_tasks")]
    pub fn order_tasks(items: Vec<CoreTaskOrderItem>) -> Vec<String> {
        super::order_tasks(&items)
    }

    #[uniffi::export(name = "task_export")]
    pub fn task_export(tasks: Vec<CoreTask>, lists: Vec<CoreTaskList>, now: String) -> String {
        super::task_export(&tasks, &lists, &now)
    }

    #[uniffi::export(name = "task_import")]
    pub fn task_import(text: String) -> Result<CoreTaskImport, CoreError> {
        super::task_import(&text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::{task_list_parse, DEFAULT_TASK_LIST_NAME};

    const NOW: &str = "2026-11-02T09:00:00Z";

    fn task(id: &str, payload: Value) -> CoreTask {
        task_parse(id, &payload.to_string())
    }

    fn clock(today: &str) -> CoreTaskClock {
        CoreTaskClock {
            now: NOW.into(),
            today: today.into(),
            ..Default::default()
        }
    }

    fn weekly(due: &str) -> CoreTask {
        task(
            "p",
            json!({"title": "Water plants", "dueDate": due, "recurrence": {"frequency": "weekly"}}),
        )
    }

    #[test]
    fn a_one_off_task_is_marked_done() {
        let plain = task(
            "a",
            json!({"title": "Post letter", "dueDate": "2026-11-02"}),
        );
        let done = task_complete(&plain, std::slice::from_ref(&plain), &clock("2026-11-02"));
        assert!(!done.rolled);
        assert!(done.task.done);
        assert_eq!(done.task.completed_at.as_deref(), Some(NOW));
        assert!(done.task.completions.is_empty());
        assert_eq!(done.task.due_date.as_deref(), Some("2026-11-02"));
    }

    #[test]
    fn a_recurring_task_rolls_on_and_reopens_its_done_subtasks() {
        let parent = weekly("2026-11-02");
        let child = task("c", json!({"title": "Feed", "parentId": "p", "done": true}));
        let grandchild = task("g", json!({"title": "Mist", "parentId": "c", "done": true}));
        let open = task("o", json!({"title": "Repot", "parentId": "p"}));
        let all = [parent.clone(), child, grandchild, open];
        let rolled = task_complete(&parent, &all, &clock("2026-11-02"));
        assert!(rolled.rolled);
        assert!(!rolled.task.done);
        assert_eq!(rolled.task.due_date.as_deref(), Some("2026-11-09"));
        assert_eq!(rolled.task.recurrence_anchor.as_deref(), Some("2026-11-02"));
        assert_eq!(rolled.task.completions, vec![NOW.to_string()]);
        let mut reopened: Vec<_> = rolled.reopened.iter().map(|w| w.id.as_str()).collect();
        reopened.sort();
        assert_eq!(reopened, ["c", "g"]);
        assert!(rolled
            .reopened
            .iter()
            .all(|w| !w.draft.done && w.draft.completed_at.is_none()));
    }

    #[test]
    fn an_overdue_task_rolls_past_today_from_its_anchor() {
        let mut late = weekly("2026-10-05");
        late.recurrence_anchor = Some("2026-10-05".into());
        let rolled = task_complete(&late, &[], &clock("2026-11-02"));
        assert_eq!(rolled.task.due_date.as_deref(), Some("2026-11-09"));
        assert_eq!(rolled.task.recurrence_anchor.as_deref(), Some("2026-10-05"));
    }

    #[test]
    fn a_timed_task_hands_back_its_next_local_time() {
        let timed = weekly("2026-11-02T17:30:00Z");
        let clock = CoreTaskClock {
            due_local: Some("2026-11-02T18:30".into()),
            ..clock("2026-11-02")
        };
        let rolled = task_complete(&timed, &[], &clock);
        assert_eq!(rolled.local_due.as_deref(), Some("2026-11-09T18:30"));
        assert_eq!(rolled.task.due_date, None);
        assert_eq!(
            rolled.task.recurrence_anchor.as_deref(),
            Some("2026-11-02T17:30:00Z")
        );
    }

    #[test]
    fn a_spent_series_is_marked_done() {
        let last = task(
            "p",
            json!({"title": "Course", "dueDate": "2026-11-02",
                   "recurrence": {"frequency": "daily", "count": 1}}),
        );
        let done = task_complete(&last, &[], &clock("2026-11-02"));
        assert!(!done.rolled);
        assert!(done.task.done);
        assert_eq!(done.task.completions.len(), 1);
    }

    #[test]
    fn completions_stay_capped() {
        let mut busy = weekly("2026-11-02");
        busy.completions = (0..MAX_TASK_COMPLETIONS)
            .map(|n| format!("old {n}"))
            .collect();
        let rolled = task_complete(&busy, &[], &clock("2026-11-02"));
        assert_eq!(rolled.task.completions.len(), MAX_TASK_COMPLETIONS);
        assert_eq!(rolled.task.completions[0], NOW);
    }

    #[test]
    fn deleting_a_task_moves_its_subtasks_up_without_titling_them() {
        let tasks = [
            task("root", json!({"title": "Root"})),
            task("p", json!({"title": "Parent", "parentId": "root"})),
            task("c", json!({"parentId": "p"})),
        ];
        let plan = task_remove_plan(&tasks, "p");
        assert_eq!(plan.removed_tasks, ["p"]);
        assert_eq!(plan.tasks.len(), 1);
        assert_eq!(plan.tasks[0].draft.parent_id.as_deref(), Some("root"));
        assert_eq!(plan.tasks[0].draft.title, "");
    }

    #[test]
    fn a_moved_task_takes_its_subtree_into_the_new_list() {
        let tasks = [
            task("home", json!({"title": "Home", "taskListId": "L2"})),
            task("p", json!({"title": "Parent"})),
            task("c", json!({"title": "Child", "parentId": "p"})),
        ];
        let plan = task_move_plan(&tasks, "p", Some("home".into()));
        assert_eq!(plan.refusal, None);
        let lists: Vec<_> = plan
            .tasks
            .iter()
            .map(|w| (w.id.as_str(), w.draft.task_list_id.as_str()))
            .collect();
        assert_eq!(lists, [("p", "L2"), ("c", "L2")]);
        assert_eq!(plan.tasks[0].draft.parent_id.as_deref(), Some("home"));

        assert_eq!(
            task_move_plan(&tasks, "p", Some("c".into()))
                .refusal
                .as_deref(),
            Some(TASK_MOVE_REFUSAL)
        );
        assert_eq!(
            task_move_plan(&tasks, "c", Some("p".into())),
            CoreTaskPlan::default()
        );
    }

    #[test]
    fn deleting_a_list_rehomes_its_lists_and_tasks() {
        let lists = [
            task_list_parse(&default_task_list_id(), r#"{"name":"Default"}"#),
            task_list_parse("work", r#"{"name":"Work"}"#),
            task_list_parse("proj", r#"{"name":"Project","parentId":"work"}"#),
            task_list_parse("sub", r#"{"name":"Sub","parentId":"proj"}"#),
        ];
        let tasks = [
            task("a", json!({"title": "A", "taskListId": "proj"})),
            task("b", json!({"title": "B", "taskListId": "work"})),
        ];
        let plan = task_list_remove_plan(&lists, &tasks, "proj");
        assert_eq!(plan.removed_lists, ["proj"]);
        assert_eq!(plan.lists[0].id, "sub");
        assert_eq!(plan.lists[0].draft.parent_id.as_deref(), Some("work"));
        assert_eq!(plan.tasks.len(), 1);
        assert_eq!(plan.tasks[0].draft.task_list_id, "work");

        let top = task_list_remove_plan(&lists, &tasks, "work");
        assert_eq!(top.tasks[0].draft.task_list_id, default_task_list_id());
        assert_eq!(top.lists[0].draft.parent_id, None);

        let refused = task_list_remove_plan(&lists, &tasks, &default_task_list_id());
        assert_eq!(
            refused.refusal.as_deref(),
            Some(DEFAULT_TASK_LIST_REMOVE_REFUSAL)
        );
        assert!(refused.removed_lists.is_empty());
    }

    #[test]
    fn the_default_list_stays_at_the_top() {
        let lists = [
            task_list_parse(&default_task_list_id(), r#"{"name":"Default"}"#),
            task_list_parse("work", r#"{"name":"Work"}"#),
        ];
        let refused = task_list_move_plan(&lists, &default_task_list_id(), Some("work".into()));
        assert_eq!(refused.refusal.as_deref(), Some(TASK_LIST_MOVE_REFUSAL));
        let moved = task_list_move_plan(&lists, "work", Some(default_task_list_id()));
        assert_eq!(moved.lists[0].draft.parent_id, Some(default_task_list_id()));
    }

    #[test]
    fn tasks_list_open_then_due_then_priority_then_title() {
        let item =
            |id: &str, done: bool, due_at: Option<f64>, priority: Option<u32>| CoreTaskOrderItem {
                id: id.into(),
                title: id.into(),
                done,
                due_at,
                priority,
            };
        let items = [
            item("done", true, Some(1.0), None),
            item("undated", false, None, Some(3)),
            item("later", false, Some(20.0), None),
            item("b", false, Some(10.0), None),
            item("a", false, Some(10.0), None),
            item("urgent", false, Some(10.0), Some(3)),
        ];
        assert_eq!(
            order_tasks(&items),
            ["urgent", "a", "b", "later", "undated", "done"]
        );
    }

    #[test]
    fn an_export_reads_back_in_parent_first_order() {
        let lists = [task_list_parse("work", r#"{"name":"Work"}"#)];
        let tasks = [
            task(
                "c",
                json!({"title": "Child", "parentId": "p", "taskListId": "work",
                       "recurrence": {"frequency": "fortnightly"}}),
            ),
            task(
                "p",
                json!({"title": "Parent", "dueDate": "2026-11-02", "priority": 2,
                       "tags": ["home"], "recurrence": {"frequency": "weekly", "interval": 2}}),
            ),
        ];
        let file = task_export(&tasks, &lists, NOW);
        let document: Value = serde_json::from_str(&file).unwrap();
        assert_eq!(document["tasks"][0]["listName"], "Work");
        assert_eq!(document["tasks"][1]["listName"], DEFAULT_TASK_LIST_NAME);

        let read = task_import(&file).unwrap();
        assert_eq!(read.skipped, 0);
        let order: Vec<_> = read.tasks.iter().map(|t| t.source_id.as_deref()).collect();
        assert_eq!(order, [Some("p"), Some("c")]);
        let parent = &read.tasks[0].draft;
        assert_eq!(parent.due_date.as_deref(), Some("2026-11-02"));
        assert_eq!(parent.priority, Some(2));
        assert_eq!(parent.tags, ["home"]);
        assert_eq!(parent.recurrence.as_ref().and_then(|r| r.interval), Some(2));
        assert_eq!(parent.raw, None);
        assert!(read.tasks[1].draft.unreadable_recurrence.is_some());
        assert_eq!(read.tasks[1].draft.parent_id.as_deref(), Some("p"));
    }

    #[test]
    fn an_import_drops_a_missing_or_circular_parent_and_skips_the_untitled() {
        let file = json!([
            {"id": "a", "title": "A", "parentId": "b"},
            {"id": "b", "title": "B", "parentId": "a"},
            {"id": "c", "title": "C", "parentId": "gone"},
            {"id": "d", "title": "  "},
            "not a task",
        ]);
        let read = task_import(&file.to_string()).unwrap();
        assert_eq!(read.skipped, 2);
        let parents: Vec<_> = read
            .tasks
            .iter()
            .map(|t| (t.source_id.clone().unwrap(), t.draft.parent_id.clone()))
            .collect();
        assert_eq!(
            parents,
            [
                ("b".to_string(), None),
                ("a".to_string(), Some("b".to_string())),
                ("c".to_string(), None),
            ]
        );
    }

    #[test]
    fn an_unknown_file_is_refused_with_a_sentence() {
        for text in ["{}", "not json", r#"{"@type":"something-else","tasks":[]}"#] {
            let Err(CoreError::Malformed { detail }) = task_import(text) else {
                panic!("{text} was read");
            };
            assert_eq!(detail, TASK_IMPORT_REFUSAL);
        }
    }
}
