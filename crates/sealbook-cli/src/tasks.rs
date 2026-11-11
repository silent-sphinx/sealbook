//! What the task commands need that core leaves to the host: the clock and the
//! local time zone, reading flags into a draft, applying a plan, and the text
//! of a listing.
//!
//! The rules themselves (what ticking, moving or deleting writes, the order,
//! the agenda groups, the export file) are core's. Nothing here decides one.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use clap::Subcommand;
use jiff::{civil, tz::TimeZone, Span, Timestamp};
use sealbook_client::{
    default_task_list_id, normalize_due_date, normalize_tags, order_tasks, resolve_task_list_id,
    task_agenda, task_complete, task_export, task_import, task_list_move_plan,
    task_list_name_by_id, task_list_remove_plan, task_list_write, task_move_plan, task_parse,
    task_relist_plan, task_remove_plan, task_reopen, task_write, write_batches, CoreRecurrence,
    CoreRecurrenceFrequency, CoreTask, CoreTaskAgendaItem, CoreTaskClock, CoreTaskDraft,
    CoreTaskList, CoreTaskListDraft, CoreTaskOrderItem, CoreTaskPlan, CoreTaskWrite,
    SealbookClient,
};
use uuid::Uuid;

const UTC_FORM: &str = "%Y-%m-%dT%H:%M:%SZ";

/// The moment a command runs at, and the zone a person means a date in.
pub struct Clock {
    zone: TimeZone,
    now: Timestamp,
}

impl Clock {
    pub fn system() -> Result<Self> {
        let zone = TimeZone::try_system().context("read this machine's time zone")?;
        Ok(Self::at(zone, Timestamp::now()))
    }

    pub fn at(zone: TimeZone, now: Timestamp) -> Self {
        Self { zone, now }
    }

    /// The instant to stamp a write with.
    pub fn now_utc(&self) -> String {
        self.now.strftime(UTC_FORM).to_string()
    }

    /// Today in the local zone, `YYYY-MM-DD`.
    pub fn today(&self) -> String {
        self.now
            .to_zoned(self.zone.clone())
            .date()
            .strftime("%Y-%m-%d")
            .to_string()
    }

    fn now_local(&self) -> String {
        self.now
            .to_zoned(self.zone.clone())
            .datetime()
            .strftime("%Y-%m-%dT%H:%M")
            .to_string()
    }

    /// A stored timed value as the instant it names. A value with no offset is
    /// read as UTC, which is how every client writes one.
    fn instant(&self, value: &str) -> Option<Timestamp> {
        let value = normalize_due_date(value)?;
        if value.len() == 10 {
            return None;
        }
        if has_zone(&value) {
            value.parse::<Timestamp>().ok()
        } else {
            let local: civil::DateTime = value.parse().ok()?;
            Some(local.to_zoned(TimeZone::UTC).ok()?.timestamp())
        }
    }

    /// A stored due or completion value in local time: a day as it is, an
    /// instant as `YYYY-MM-DDTHH:MM:SS`.
    pub fn local_of(&self, value: &str) -> Option<String> {
        let normal = normalize_due_date(value)?;
        if normal.len() == 10 {
            return Some(normal);
        }
        Some(
            self.instant(&normal)?
                .to_zoned(self.zone.clone())
                .datetime()
                .strftime("%Y-%m-%dT%H:%M:%S")
                .to_string(),
        )
    }

    /// The due moment in epoch milliseconds, local midnight for a day.
    fn due_ms(&self, value: &str) -> Option<f64> {
        let normal = normalize_due_date(value)?;
        let at = if normal.len() == 10 {
            let day: civil::Date = normal.parse().ok()?;
            day.to_zoned(self.zone.clone()).ok()?.timestamp()
        } else {
            self.instant(&normal)?
        };
        Some(at.as_millisecond() as f64)
    }

    /// A due value as typed: `YYYY-MM-DD`, `today`, `tomorrow`, or a time
    /// (`YYYY-MM-DDTHH:MM`) that is read in the local zone unless it carries its
    /// own `Z` or offset. Timed values are stored as UTC.
    pub fn parse_due(&self, text: &str) -> Result<String> {
        let text = text.trim();
        match text.to_ascii_lowercase().as_str() {
            "today" => return Ok(self.today()),
            "tomorrow" => {
                let day: civil::Date = self.today().parse()?;
                return Ok(day.checked_add(Span::new().days(1))?.to_string());
            }
            _ => {}
        }
        let value = normalize_due_date(text).ok_or_else(|| {
            anyhow!("{text} is not a due date: use YYYY-MM-DD, YYYY-MM-DDTHH:MM, today or tomorrow")
        })?;
        if value.len() > 10 && !has_zone(&value) {
            return self.utc_of_local(&value);
        }
        Ok(value)
    }

    /// Local wall-clock text as the UTC instant it names.
    pub fn utc_of_local(&self, local: &str) -> Result<String> {
        let local: civil::DateTime = local
            .parse()
            .with_context(|| format!("read the time {local}"))?;
        let at = local.to_zoned(self.zone.clone())?.timestamp();
        Ok(at.strftime(UTC_FORM).to_string())
    }

    /// What core's `task_complete` needs of the clock, for this task.
    pub fn for_task(&self, task: &CoreTask) -> CoreTaskClock {
        let timed_local = |value: &Option<String>| {
            value
                .as_deref()
                .filter(|value| normalize_due_date(value).is_some_and(|v| v.len() > 10))
                .and_then(|value| self.local_of(value))
        };
        CoreTaskClock {
            now: self.now_utc(),
            today: self.today(),
            due_local: timed_local(&task.due_date),
            anchor_local: timed_local(&task.recurrence_anchor),
        }
    }

    /// A due value for a listing: a day, or local `YYYY-MM-DD HH:MM`.
    pub fn due_label(&self, value: &str) -> String {
        match self.local_of(value) {
            Some(local) if local.len() > 10 => local[..16].replace('T', " "),
            Some(local) => local,
            None => value.to_string(),
        }
    }
}

fn has_zone(value: &str) -> bool {
    value.ends_with('Z')
        || value
            .get(11..)
            .is_some_and(|time| time.contains(['+', '-']))
}

/// Flags that change a task's fields. A flag left out keeps the stored value.
#[derive(clap::Args, Debug, Default)]
pub struct TaskFields {
    #[arg(long)]
    pub notes: Option<String>,
    #[arg(long, conflicts_with = "notes")]
    pub clear_notes: bool,
    /// YYYY-MM-DD, YYYY-MM-DDTHH:MM (local time), today or tomorrow.
    #[arg(long)]
    pub due: Option<String>,
    #[arg(long, conflicts_with = "due")]
    pub clear_due: bool,
    /// low, medium, high, or a number from 1 up.
    #[arg(long, value_parser = parse_priority)]
    pub priority: Option<u32>,
    #[arg(long, conflicts_with = "priority")]
    pub clear_priority: bool,
    /// A tag. Repeat for more than one; replaces the stored tags.
    #[arg(long = "tag")]
    pub tags: Vec<String>,
    #[arg(long, conflicts_with = "tags")]
    pub clear_tags: bool,
    /// daily, weekly, monthly or yearly, then optional `;every=N`, `;on=mon,thu`,
    /// `;day=15`, `;until=YYYY-MM-DD` or `;count=N`. Needs a due date.
    #[arg(long, value_parser = parse_repeat)]
    pub repeat: Option<CoreRecurrence>,
    #[arg(long, conflicts_with = "repeat")]
    pub clear_repeat: bool,
}

/// Writes the flags onto a draft, leaving every field they do not name as it
/// was.
pub fn apply_fields(draft: &mut CoreTaskDraft, fields: &TaskFields, clock: &Clock) -> Result<()> {
    if fields.clear_notes {
        draft.notes.clear();
    } else if let Some(notes) = &fields.notes {
        draft.notes = notes.clone();
    }
    if fields.clear_due {
        draft.due_date = None;
        draft.recurrence_anchor = None;
    } else if let Some(due) = &fields.due {
        draft.due_date = Some(clock.parse_due(due)?);
        // A new date is where the rule counts from.
        draft.recurrence_anchor = None;
    }
    if fields.clear_priority {
        draft.priority = None;
    } else if let Some(priority) = fields.priority {
        draft.priority = Some(priority);
    }
    if fields.clear_tags {
        draft.tags.clear();
    } else if !fields.tags.is_empty() {
        draft.tags = normalize_tags(&fields.tags);
    }
    if fields.clear_repeat {
        draft.recurrence = None;
        draft.unreadable_recurrence = None;
        draft.recurrence_anchor = None;
    } else if let Some(rule) = &fields.repeat {
        draft.recurrence = Some(rule.clone());
        draft.unreadable_recurrence = None;
        draft.recurrence_anchor = None;
    }
    if draft.recurrence.is_some() && draft.due_date.is_none() {
        bail!("a repeating task needs a due date: pass --due, or --clear-repeat");
    }
    Ok(())
}

pub fn parse_priority(text: &str) -> Result<u32, String> {
    match text.trim().to_ascii_lowercase().as_str() {
        "low" => Ok(1),
        "medium" | "med" => Ok(2),
        "high" => Ok(3),
        other => other
            .parse::<u32>()
            .ok()
            .filter(|priority| *priority > 0)
            .ok_or_else(|| format!("{text} is not a priority: use low, medium, high or 1 and up")),
    }
}

fn priority_label(priority: u32) -> String {
    match priority {
        1 => "low".into(),
        2 => "medium".into(),
        3 => "high".into(),
        other => format!("priority {other}"),
    }
}

const WEEKDAYS: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

/// `weekly;every=2;on=mon,thu;until=2027-01-01` and the like.
pub fn parse_repeat(spec: &str) -> Result<CoreRecurrence, String> {
    let mut parts = spec.split(';').map(str::trim);
    let frequency = match parts
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "daily" => CoreRecurrenceFrequency::Daily,
        "weekly" => CoreRecurrenceFrequency::Weekly,
        "monthly" => CoreRecurrenceFrequency::Monthly,
        "yearly" => CoreRecurrenceFrequency::Yearly,
        other => {
            return Err(format!(
                "{other:?} is not a repeat: start with daily, weekly, monthly or yearly"
            ))
        }
    };
    let mut rule = CoreRecurrence {
        frequency,
        interval: None,
        until: None,
        count: None,
        weekdays: Vec::new(),
        day_of_month: None,
        nth_weekday: None,
        extra: None,
    };
    let number = |key: &str, value: &str| {
        value
            .parse::<u32>()
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| format!("{key} wants a whole number above 0, not {value}"))
    };
    for part in parts.filter(|part| !part.is_empty()) {
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| format!("{part:?} should be key=value"))?;
        let value = value.trim();
        match key.trim() {
            "every" => rule.interval = Some(number("every", value)?).filter(|n| *n > 1),
            "count" => rule.count = Some(number("count", value)?),
            "until" => {
                if !sealbook_client::is_calendar_day(value) {
                    return Err(format!("until wants YYYY-MM-DD, not {value}"));
                }
                rule.until = Some(value.to_string());
            }
            "day" => {
                let day = number("day", value)?;
                if day > 31 {
                    return Err(format!("day wants 1 to 31, not {day}"));
                }
                rule.day_of_month = Some(day);
            }
            "on" => {
                for name in value.split(',') {
                    let name = name.trim().to_ascii_lowercase();
                    let index = WEEKDAYS
                        .iter()
                        .position(|day| name.starts_with(day))
                        .ok_or_else(|| format!("{name:?} is not a weekday: use mon, tue ..."))?;
                    let index = index as u32;
                    if !rule.weekdays.contains(&index) {
                        rule.weekdays.push(index);
                    }
                }
                rule.weekdays.sort_unstable();
            }
            other => return Err(format!("unknown repeat setting {other:?}")),
        }
    }
    if !rule.weekdays.is_empty() && frequency != CoreRecurrenceFrequency::Weekly {
        return Err("on= only goes with a weekly repeat".into());
    }
    if rule.day_of_month.is_some() && frequency != CoreRecurrenceFrequency::Monthly {
        return Err("day= only goes with a monthly repeat".into());
    }
    if rule.until.is_some() && rule.count.is_some() {
        return Err("give until or count, not both".into());
    }
    Ok(rule)
}

pub fn describe_repeat(rule: &CoreRecurrence) -> String {
    let (unit, plural) = match rule.frequency {
        CoreRecurrenceFrequency::Daily => ("day", "days"),
        CoreRecurrenceFrequency::Weekly => ("week", "weeks"),
        CoreRecurrenceFrequency::Monthly => ("month", "months"),
        CoreRecurrenceFrequency::Yearly => ("year", "years"),
    };
    let mut out = match rule.interval {
        Some(n) if n > 1 => format!("every {n} {plural}"),
        _ => format!("every {unit}"),
    };
    if !rule.weekdays.is_empty() {
        let days: Vec<&str> = rule
            .weekdays
            .iter()
            .filter_map(|day| WEEKDAYS.get(*day as usize).copied())
            .collect();
        out.push_str(&format!(" on {}", days.join(", ")));
    }
    if let Some(day) = rule.day_of_month {
        out.push_str(&format!(" on day {day}"));
    }
    if let Some(until) = &rule.until {
        out.push_str(&format!(" until {until}"));
    }
    if let Some(count) = rule.count {
        out.push_str(&format!(", {count} times"));
    }
    out
}

/// Every task and task list, read the way each client reads them.
pub async fn load(client: &mut SealbookClient) -> Result<(Vec<CoreTask>, Vec<CoreTaskList>)> {
    let tasks = client
        .list_tasks()
        .await
        .context("tasks")?
        .into_iter()
        .map(|(id, raw)| task_parse(&id.to_string(), &raw))
        .collect();
    let lists = client
        .list_task_list_payloads()
        .await
        .context("task lists")?
        .into_iter()
        .map(|(id, raw)| sealbook_client::task_list_parse(&id.to_string(), &raw))
        .collect();
    Ok((tasks, lists))
}

/// A list by id or by name.
pub fn resolve_list(lists: &[CoreTaskList], spec: &str) -> Result<Uuid> {
    let spec = spec.trim();
    if let Ok(id) = Uuid::parse_str(spec) {
        if lists.iter().any(|list| list.id == id.to_string()) {
            return Ok(id);
        }
        bail!("unknown task list {spec}: see `tasklist list`");
    }
    let matches: Vec<&CoreTaskList> = lists
        .iter()
        .filter(|list| list.name.eq_ignore_ascii_case(spec))
        .collect();
    match matches.as_slice() {
        [] => bail!("unknown task list {spec}: see `tasklist list`"),
        [only] => Ok(only.id.parse()?),
        _ => bail!("more than one task list is named {spec}: use its id"),
    }
}

/// Writes what a plan says, in the order that leaves nothing pointing at what
/// is gone: the tasks and lists to write, then the ones to delete.
pub async fn apply_plan(client: &mut SealbookClient, plan: &CoreTaskPlan, now: &str) -> Result<()> {
    if let Some(refusal) = &plan.refusal {
        bail!("{refusal}");
    }
    let mut encoded: Vec<(Uuid, String)> = Vec::with_capacity(plan.tasks.len());
    for write in &plan.tasks {
        encoded.push((write.id.parse()?, task_write(&write.draft, now)?));
    }
    let lengths: Vec<u64> = encoded.iter().map(|(_, body)| body.len() as u64).collect();
    let mut rest = encoded.as_slice();
    for count in write_batches(&lengths) {
        let (chunk, tail) = rest.split_at(count as usize);
        let batch: Vec<(Uuid, &str)> = chunk
            .iter()
            .map(|(id, body)| (*id, body.as_str()))
            .collect();
        client.put_tasks(&batch).await.context("write tasks")?;
        rest = tail;
    }
    for write in &plan.lists {
        let body = sealbook_client::task_list_write(&write.draft)?;
        client
            .put_task_list(write.id.parse()?, &body)
            .await
            .context("write task list")?;
    }
    for id in &plan.removed_tasks {
        client
            .delete_task(id.parse()?)
            .await
            .context("delete task")?;
    }
    for id in &plan.removed_lists {
        client
            .delete_task_list(id.parse()?)
            .await
            .context("delete task list")?;
    }
    Ok(())
}

/// One line for a task: its id, list and state, then what is worth knowing.
pub fn task_line(task: &CoreTask, lists: &[CoreTaskList], clock: &Clock, depth: usize) -> String {
    let list = task_list_name_by_id(lists, Some(task.task_list_id.clone()));
    let mut meta: Vec<String> = Vec::new();
    if let Some(due) = &task.due_date {
        meta.push(format!("due {}", clock.due_label(due)));
    }
    if let Some(priority) = task.priority {
        meta.push(priority_label(priority));
    }
    meta.extend(task.tags.iter().map(|tag| format!("#{tag}")));
    if let Some(rule) = &task.recurrence {
        meta.push(format!("repeats {}", describe_repeat(rule)));
    }
    let meta = if meta.is_empty() {
        String::new()
    } else {
        format!("  ({})", meta.join(", "))
    };
    format!(
        "{} [{list}] {}[{}] {}{meta}",
        task.id,
        "  ".repeat(depth),
        if task.done { "x" } else { " " },
        task.title
    )
}

/// The tasks in list order, each subtask under its parent. Open tasks only,
/// plus any done parent that still has an open task under it, unless `all`.
pub fn list_lines(
    tasks: &[CoreTask],
    lists: &[CoreTaskList],
    clock: &Clock,
    all: bool,
    list: Option<Uuid>,
) -> Vec<String> {
    let in_list: Vec<&CoreTask> = tasks
        .iter()
        .filter(|task| {
            list.is_none_or(|want| {
                resolve_task_list_id(Some(task.task_list_id.clone())) == want.to_string()
            })
        })
        .collect();
    let by_id: HashMap<&str, &CoreTask> = in_list.iter().map(|t| (t.id.as_str(), *t)).collect();
    let mut shown: HashSet<&str> = HashSet::new();
    for task in &in_list {
        if all || !task.done {
            let mut at = Some(*task);
            let mut hops = 0;
            while let Some(current) = at {
                if !shown.insert(current.id.as_str()) || hops > in_list.len() {
                    break;
                }
                hops += 1;
                at = current
                    .parent_id
                    .as_deref()
                    .and_then(|parent| by_id.get(parent).copied());
            }
        }
    }
    let items: Vec<CoreTaskOrderItem> = in_list
        .iter()
        .filter(|task| shown.contains(task.id.as_str()))
        .map(|task| CoreTaskOrderItem {
            id: task.id.clone(),
            title: task.title.clone(),
            done: task.done,
            due_at: task.due_date.as_deref().and_then(|due| clock.due_ms(due)),
            priority: task.priority,
        })
        .collect();
    let order = order_tasks(&items);
    let mut children: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut roots: Vec<&str> = Vec::new();
    for id in &order {
        let task = by_id[id.as_str()];
        match task
            .parent_id
            .as_deref()
            .filter(|parent| shown.contains(parent))
        {
            Some(parent) => children.entry(parent).or_default().push(id.as_str()),
            None => roots.push(id.as_str()),
        }
    }
    let mut lines = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    fn walk<'a>(
        id: &'a str,
        depth: usize,
        by_id: &HashMap<&'a str, &'a CoreTask>,
        children: &HashMap<&'a str, Vec<&'a str>>,
        seen: &mut HashSet<&'a str>,
        out: &mut Vec<String>,
        render: &dyn Fn(&CoreTask, usize) -> String,
    ) {
        if !seen.insert(id) {
            return;
        }
        out.push(render(by_id[id], depth));
        for child in children.get(id).into_iter().flatten() {
            walk(child, depth + 1, by_id, children, seen, out, render);
        }
    }
    let render = |task: &CoreTask, depth: usize| task_line(task, lists, clock, depth);
    for root in &roots {
        walk(root, 0, &by_id, &children, &mut seen, &mut lines, &render);
    }
    // A cycle has no root of its own; list what it holds rather than lose it.
    for id in &order {
        walk(id, 0, &by_id, &children, &mut seen, &mut lines, &render);
    }
    lines
}

/// The open tasks grouped by when they are due, as core groups them.
pub fn agenda_lines(tasks: &[CoreTask], lists: &[CoreTaskList], clock: &Clock) -> Vec<String> {
    let items: Vec<CoreTaskAgendaItem> = tasks
        .iter()
        .map(|task| CoreTaskAgendaItem {
            id: task.id.clone(),
            title: task.title.clone(),
            done: task.done,
            due_local: task
                .due_date
                .as_deref()
                .and_then(|due| clock.local_of(due))
                .map(|local| local.chars().take(16).collect()),
            completed_local: task
                .completed_at
                .as_deref()
                .and_then(|at| clock.local_of(at))
                .map(|local| local.chars().take(16).collect()),
            priority: task.priority,
        })
        .collect();
    let agenda = task_agenda(&items, &clock.now_local());
    let by_id: HashMap<&str, &CoreTask> = tasks.iter().map(|t| (t.id.as_str(), t)).collect();
    let groups: [(&str, &Vec<String>); 7] = [
        ("Overdue", &agenda.overdue),
        ("Today", &agenda.today),
        ("Tomorrow", &agenda.tomorrow),
        ("Next five days", &agenda.week),
        ("Later", &agenda.later),
        ("No date", &agenda.undated),
        ("Done today", &agenda.done_today),
    ];
    let mut lines = Vec::new();
    for (heading, ids) in groups {
        if ids.is_empty() {
            continue;
        }
        lines.push(format!("{heading}:"));
        for id in ids {
            if let Some(task) = by_id.get(id.as_str()) {
                lines.push(format!("  {}", task_line(task, lists, clock, 0)));
            }
        }
    }
    if lines.is_empty() {
        lines.push("(no tasks)".into());
    }
    lines
}

/// The list a new task goes in: its parent's, else the one asked for, else the
/// default. A parent in another list than the one asked for is a conflict.
pub fn home_list(
    tasks: &[CoreTask],
    lists: &[CoreTaskList],
    list: Option<&str>,
    parent: Option<Uuid>,
) -> Result<String> {
    let asked = list.map(|spec| resolve_list(lists, spec)).transpose()?;
    let Some(parent) = parent else {
        return Ok(asked.map_or_else(default_task_list_id, |id| id.to_string()));
    };
    let parent = tasks
        .iter()
        .find(|task| task.id == parent.to_string())
        .with_context(|| format!("no task {parent}"))?;
    let home = resolve_task_list_id(Some(parent.task_list_id.clone()));
    if asked.is_some_and(|asked| asked.to_string() != home) {
        bail!(
            "task {} is in another list: a subtask shares its parent's list",
            parent.id
        );
    }
    Ok(home)
}

#[derive(Subcommand)]
pub enum TasklistCommand {
    /// Lists with how many open tasks each holds, sub-lists indented.
    List,
    Create {
        #[arg(long)]
        name: String,
        /// Nest it under another list (id or name).
        #[arg(long)]
        parent: Option<String>,
        /// Hex colour. Only a top-level list carries one.
        #[arg(long)]
        color: Option<String>,
    },
    /// Change a list's name or colour. A flag left out keeps the stored value.
    Rename {
        /// The list, by id or name.
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        color: Option<String>,
    },
    /// Move a list under another, or to the top level.
    Move {
        #[arg(long)]
        id: String,
        #[arg(long)]
        parent: Option<String>,
        #[arg(long, conflicts_with = "parent")]
        top: bool,
    },
    /// Delete a list. Its tasks and sub-lists move up to its parent, or to the
    /// default list from the top level.
    Delete {
        #[arg(long)]
        id: String,
    },
}

#[derive(Subcommand)]
pub enum TasksCommand {
    Add {
        #[arg(long)]
        title: String,
        /// The list, by id or name. Defaults to the parent's, else the default list.
        #[arg(long)]
        list: Option<String>,
        /// Make it a subtask of this task.
        #[arg(long)]
        parent: Option<Uuid>,
        #[command(flatten)]
        fields: TaskFields,
    },
    /// Change a task. A flag left out keeps the stored value.
    Update {
        #[arg(long)]
        id: Uuid,
        #[arg(long)]
        title: Option<String>,
        /// Move it, and its subtasks, to another list. It leaves its parent.
        #[arg(long)]
        list: Option<String>,
        #[command(flatten)]
        fields: TaskFields,
    },
    /// Tick a task. A repeating task rolls to its next date and reopens its
    /// subtasks; any other is marked done.
    Done {
        #[arg(long)]
        id: Uuid,
    },
    Reopen {
        #[arg(long)]
        id: Uuid,
    },
    /// Put a task under another, at the top of its list, or in another list.
    Move {
        #[arg(long)]
        id: Uuid,
        #[arg(long, conflicts_with_all = ["top", "to_list"])]
        parent: Option<Uuid>,
        #[arg(long, conflicts_with = "to_list")]
        top: bool,
        #[arg(long)]
        to_list: Option<String>,
    },
    /// Delete a task. Its subtasks move up to its parent.
    Delete {
        #[arg(long)]
        id: Uuid,
    },
    /// Open tasks in list order, subtasks under their parent.
    List {
        #[arg(long)]
        list: Option<String>,
        /// Include done tasks.
        #[arg(long)]
        all: bool,
    },
    Show {
        #[arg(long)]
        id: Uuid,
    },
    /// Open tasks by when they are due: overdue, today, tomorrow and so on.
    Agenda,
    /// Read a task export (or a JSON array of tasks) into one list.
    Import {
        #[arg(long)]
        file: PathBuf,
        /// The list to import into, by id or name. Defaults to the default list.
        #[arg(long, conflicts_with = "new_list")]
        list: Option<String>,
        /// Create a list with this name and import into it.
        #[arg(long)]
        new_list: Option<String>,
    },
    /// Write a task export. Without --out, prints it.
    Export {
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        list: Option<String>,
    },
}

fn found(tasks: &[CoreTask], id: Uuid) -> Result<&CoreTask> {
    tasks
        .iter()
        .find(|task| task.id == id.to_string())
        .with_context(|| format!("no task {id}: see `tasks list --all`"))
}

fn write_of(id: &str, draft: CoreTaskDraft) -> CoreTaskWrite {
    CoreTaskWrite {
        id: id.to_string(),
        draft,
    }
}

fn utc_now() -> String {
    Timestamp::now().strftime(UTC_FORM).to_string()
}

pub async fn run_lists(client: &mut SealbookClient, command: TasklistCommand) -> Result<()> {
    let (tasks, lists) = load(client).await?;
    let now = utc_now();
    match command {
        TasklistCommand::List => {
            let open = |list: &CoreTaskList| {
                tasks
                    .iter()
                    .filter(|task| {
                        !task.done
                            && resolve_task_list_id(Some(task.task_list_id.clone())) == list.id
                    })
                    .count()
            };
            let mut children: HashMap<Option<&str>, Vec<&CoreTaskList>> = HashMap::new();
            let known: HashSet<&str> = lists.iter().map(|list| list.id.as_str()).collect();
            for list in &lists {
                let parent = list.parent_id.as_deref().filter(|p| known.contains(p));
                children.entry(parent).or_default().push(list);
            }
            for siblings in children.values_mut() {
                siblings.sort_by_key(|list| {
                    (list.id != default_task_list_id(), list.name.to_lowercase())
                });
            }
            fn walk(
                parent: Option<&str>,
                depth: usize,
                children: &HashMap<Option<&str>, Vec<&CoreTaskList>>,
                open: &dyn Fn(&CoreTaskList) -> usize,
                seen: &mut HashSet<String>,
            ) {
                for list in children.get(&parent).into_iter().flatten() {
                    if !seen.insert(list.id.clone()) {
                        continue;
                    }
                    println!(
                        "{} {}{} ({} open)",
                        list.id,
                        "  ".repeat(depth),
                        list.name,
                        open(list)
                    );
                    walk(Some(&list.id), depth + 1, children, open, seen);
                }
            }
            let mut seen = HashSet::new();
            walk(None, 0, &children, &open, &mut seen);
        }
        TasklistCommand::Create {
            name,
            parent,
            color,
        } => {
            let name = name.trim().to_string();
            if name.is_empty() {
                bail!("a list needs a name");
            }
            let parent_id = parent
                .map(|spec| resolve_list(&lists, &spec))
                .transpose()?
                .map(|id| id.to_string());
            let id = Uuid::new_v4();
            let body = task_list_write(&CoreTaskListDraft {
                name: name.clone(),
                parent_id,
                color,
                raw: None,
            })?;
            client
                .put_task_list(id, &body)
                .await
                .context("create task list")?;
            println!("created task list {id} {name}");
        }
        TasklistCommand::Rename { id, name, color } => {
            let id = resolve_list(&lists, &id)?;
            let list = lists
                .iter()
                .find(|list| list.id == id.to_string())
                .context("task list")?;
            let mut draft = list.draft();
            if let Some(name) = name {
                if name.trim().is_empty() {
                    bail!("a list needs a name");
                }
                draft.name = name.trim().to_string();
            }
            if color.is_some() {
                draft.color = color;
            }
            let body = task_list_write(&draft)?;
            client
                .put_task_list(id, &body)
                .await
                .context("change task list")?;
            println!("stored task list {id} {}", draft.name);
        }
        TasklistCommand::Move { id, parent, top } => {
            let id = resolve_list(&lists, &id)?;
            let parent = match (parent, top) {
                (Some(spec), _) => Some(resolve_list(&lists, &spec)?.to_string()),
                (None, true) => None,
                (None, false) => bail!("say where: --parent <list> or --top"),
            };
            let plan = task_list_move_plan(&lists, &id.to_string(), parent);
            if plan.lists.is_empty() && plan.refusal.is_none() {
                println!("task list {id} is already there");
                return Ok(());
            }
            apply_plan(client, &plan, &now).await?;
            println!("moved task list {id}");
        }
        TasklistCommand::Delete { id } => {
            let id = resolve_list(&lists, &id)?;
            let plan = task_list_remove_plan(&lists, &tasks, &id.to_string());
            apply_plan(client, &plan, &now).await?;
            println!(
                "deleted task list {id}, moved {} task(s) and {} sub-list(s) up",
                plan.tasks.len(),
                plan.lists.len()
            );
        }
    }
    Ok(())
}

pub async fn run_tasks(client: &mut SealbookClient, command: TasksCommand) -> Result<()> {
    let (tasks, lists) = load(client).await?;
    let clock = Clock::system()?;
    let now = clock.now_utc();
    match command {
        TasksCommand::Add {
            title,
            list,
            parent,
            fields,
        } => {
            let title = title.trim().to_string();
            if title.is_empty() {
                bail!("a task needs a title");
            }
            let home = home_list(&tasks, &lists, list.as_deref(), parent)?;
            let mut draft = CoreTaskDraft {
                title,
                task_list_id: home,
                parent_id: parent.map(|id| id.to_string()),
                ..Default::default()
            };
            apply_fields(&mut draft, &fields, &clock)?;
            let id = Uuid::new_v4();
            let body = task_write(&draft, &now)?;
            let revision = client.put_task(id, &body).await.context("add task")?;
            println!("stored encrypted task {id} at revision {revision}");
        }
        TasksCommand::Update {
            id,
            title,
            list,
            fields,
        } => {
            let task = found(&tasks, id)?;
            let mut draft = task.draft();
            if let Some(title) = title {
                if title.trim().is_empty() {
                    bail!("a task needs a title");
                }
                draft.title = title.trim().to_string();
            }
            apply_fields(&mut draft, &fields, &clock)?;
            let mut plan = CoreTaskPlan::default();
            if let Some(spec) = list {
                let target = resolve_list(&lists, &spec)?.to_string();
                if target != resolve_task_list_id(Some(task.task_list_id.clone())) {
                    draft.task_list_id = target.clone();
                    draft.parent_id = None;
                    plan.tasks = task_relist_plan(&tasks, &task.id, &target).tasks;
                }
            }
            plan.tasks.insert(0, write_of(&task.id, draft));
            apply_plan(client, &plan, &now).await?;
            println!("updated task {id}");
        }
        TasksCommand::Done { id } => {
            let task = found(&tasks, id)?;
            if task.done {
                bail!("task {id} is already done");
            }
            let completion = task_complete(task, &tasks, &clock.for_task(task));
            let mut draft = completion.task;
            if let Some(local) = &completion.local_due {
                draft.due_date = Some(clock.utc_of_local(local)?);
            }
            let mut plan = CoreTaskPlan {
                tasks: vec![write_of(&task.id, draft.clone())],
                ..Default::default()
            };
            plan.tasks.extend(completion.reopened.iter().cloned());
            apply_plan(client, &plan, &now).await?;
            if completion.rolled {
                let next = draft
                    .due_date
                    .as_deref()
                    .map(|due| clock.due_label(due))
                    .unwrap_or_default();
                println!(
                    "ticked {id}; it repeats, next due {next}{}",
                    match completion.reopened.len() {
                        0 => String::new(),
                        n => format!(", {n} subtask(s) reopened"),
                    }
                );
            } else {
                println!("done {id}");
            }
        }
        TasksCommand::Reopen { id } => {
            let task = found(&tasks, id)?;
            if !task.done {
                bail!("task {id} is not done");
            }
            let plan = CoreTaskPlan {
                tasks: vec![write_of(&task.id, task_reopen(task))],
                ..Default::default()
            };
            apply_plan(client, &plan, &now).await?;
            println!("reopened {id}");
        }
        TasksCommand::Move {
            id,
            parent,
            top,
            to_list,
        } => {
            let task = found(&tasks, id)?;
            let plan = match (parent, top, to_list) {
                (Some(parent), _, _) => {
                    found(&tasks, parent)?;
                    task_move_plan(&tasks, &task.id, Some(parent.to_string()))
                }
                (None, true, _) => task_move_plan(&tasks, &task.id, None),
                (None, false, Some(spec)) => {
                    let target = resolve_list(&lists, &spec)?.to_string();
                    let mut draft = task.draft();
                    draft.task_list_id = target.clone();
                    draft.parent_id = None;
                    let mut plan = task_relist_plan(&tasks, &task.id, &target);
                    plan.tasks.insert(0, write_of(&task.id, draft));
                    plan
                }
                (None, false, None) => {
                    bail!("say where: --parent <task>, --top or --to-list <list>")
                }
            };
            if plan.tasks.is_empty() && plan.refusal.is_none() {
                println!("task {id} is already there");
                return Ok(());
            }
            apply_plan(client, &plan, &now).await?;
            println!("moved task {id} ({} written)", plan.tasks.len());
        }
        TasksCommand::Delete { id } => {
            let task = found(&tasks, id)?;
            let plan = task_remove_plan(&tasks, &task.id);
            apply_plan(client, &plan, &now).await?;
            println!(
                "deleted task {id}, moved {} subtask(s) up",
                plan.tasks.len()
            );
        }
        TasksCommand::List { list, all } => {
            let list = list.map(|spec| resolve_list(&lists, &spec)).transpose()?;
            let lines = list_lines(&tasks, &lists, &clock, all, list);
            if lines.is_empty() {
                println!("(no tasks)");
            }
            for line in lines {
                println!("{line}");
            }
        }
        TasksCommand::Show { id } => {
            let task = found(&tasks, id)?;
            println!("{}", task_line(task, &lists, &clock, 0));
            if !task.notes.is_empty() {
                println!();
                println!("{}", task.notes);
            }
            if let Some(parent) = &task.parent_id {
                println!("parent: {parent}");
            }
            if let Some(done) = &task.completed_at {
                println!("completed: {}", clock.due_label(done));
            }
            if !task.completions.is_empty() {
                println!("completed {} time(s) so far", task.completions.len());
            }
        }
        TasksCommand::Agenda => {
            for line in agenda_lines(&tasks, &lists, &clock) {
                println!("{line}");
            }
        }
        TasksCommand::Import {
            file,
            list,
            new_list,
        } => {
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("read {}", file.display()))?;
            let read = task_import(&text)?;
            if read.tasks.is_empty() {
                if read.skipped > 0 {
                    bail!("every entry in {} was missing a title", file.display());
                }
                bail!("no tasks could be read from {}", file.display());
            }
            let mut plan = CoreTaskPlan::default();
            let target = match (list, new_list) {
                (_, Some(name)) => {
                    let name = name.trim().to_string();
                    if name.is_empty() {
                        bail!("a list needs a name");
                    }
                    let id = Uuid::new_v4();
                    plan.lists.push(sealbook_client::CoreTaskListWrite {
                        id: id.to_string(),
                        draft: CoreTaskListDraft {
                            name,
                            ..Default::default()
                        },
                    });
                    id.to_string()
                }
                (Some(spec), None) => resolve_list(&lists, &spec)?.to_string(),
                (None, None) => default_task_list_id(),
            };
            let mut new_ids: HashMap<String, String> = HashMap::new();
            for entry in &read.tasks {
                let id = Uuid::new_v4().to_string();
                if let Some(source) = &entry.source_id {
                    new_ids.insert(source.clone(), id.clone());
                }
                let mut draft = entry.draft.clone();
                draft.task_list_id = target.clone();
                draft.parent_id = draft
                    .parent_id
                    .as_ref()
                    .and_then(|parent| new_ids.get(parent).cloned());
                plan.tasks.push(write_of(&id, draft));
            }
            // The new list goes first, so no task is ever written into a list
            // the vault does not hold yet.
            let new_lists = std::mem::take(&mut plan.lists);
            for write in &new_lists {
                let body = task_list_write(&write.draft)?;
                client
                    .put_task_list(write.id.parse()?, &body)
                    .await
                    .context("create task list")?;
            }
            apply_plan(client, &plan, &now).await?;
            println!(
                "imported {} task(s){}",
                plan.tasks.len(),
                match read.skipped {
                    0 => String::new(),
                    n => format!("; {n} had no title and were skipped"),
                }
            );
        }
        TasksCommand::Export { out, list } => {
            let list = list.map(|spec| resolve_list(&lists, &spec)).transpose()?;
            let mut chosen: Vec<CoreTask> = tasks
                .iter()
                .filter(|task| {
                    list.is_none_or(|want| {
                        resolve_task_list_id(Some(task.task_list_id.clone())) == want.to_string()
                    })
                })
                .cloned()
                .collect();
            let items: Vec<CoreTaskOrderItem> = chosen
                .iter()
                .map(|task| CoreTaskOrderItem {
                    id: task.id.clone(),
                    title: task.title.clone(),
                    done: task.done,
                    due_at: task.due_date.as_deref().and_then(|due| clock.due_ms(due)),
                    priority: task.priority,
                })
                .collect();
            let order = order_tasks(&items);
            chosen.sort_by_key(|task| order.iter().position(|id| *id == task.id));
            let data = task_export(&chosen, &lists, &now);
            match out {
                Some(path) => {
                    std::fs::write(&path, data)
                        .with_context(|| format!("write {}", path.display()))?;
                    println!("exported {} task(s) to {}", chosen.len(), path.display());
                }
                None => println!("{data}"),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clock(zone: &str, now: &str) -> Clock {
        Clock::at(TimeZone::get(zone).unwrap(), now.parse().unwrap())
    }

    fn task(id: &str, raw: &str) -> CoreTask {
        task_parse(id, raw)
    }

    #[test]
    fn today_and_due_follow_the_local_zone() {
        // 23:30 UTC on the 11th is already the 12th in Auckland.
        let c = clock("Pacific/Auckland", "2026-11-11T23:30:00Z");
        assert_eq!(c.today(), "2026-11-12");
        assert_eq!(c.parse_due("tomorrow").unwrap(), "2026-11-13");
        assert_eq!(c.parse_due("2026-12-01").unwrap(), "2026-12-01");
        // 09:00 NZDT (+13) is 20:00 the day before in UTC.
        assert_eq!(
            c.parse_due("2026-12-01T09:00").unwrap(),
            "2026-11-30T20:00:00Z"
        );
        // A value with its own designator is kept as given.
        assert_eq!(
            c.parse_due("2026-12-01T09:00Z").unwrap(),
            "2026-12-01T09:00Z"
        );
        assert!(c.parse_due("2026-02-30").is_err());
        assert!(c.parse_due("next week").is_err());
    }

    #[test]
    fn stored_instants_read_back_in_local_time() {
        let c = clock("America/New_York", "2026-11-11T12:00:00Z");
        assert_eq!(
            c.local_of("2026-11-02T14:30:00Z").unwrap(),
            "2026-11-02T09:30:00"
        );
        assert_eq!(c.local_of("2026-11-02").unwrap(), "2026-11-02");
        assert_eq!(c.due_label("2026-11-02T14:30:00Z"), "2026-11-02 09:30");
        // Local midnight of a day, so an all-day task sorts by the local day.
        let day = c.due_ms("2026-11-02").unwrap();
        let noon = c.due_ms("2026-11-02T17:00:00Z").unwrap();
        assert_eq!(noon - day, 12.0 * 3_600_000.0);
    }

    #[test]
    fn repeat_specs() {
        let rule = parse_repeat("weekly;every=2;on=thu,mon;until=2027-01-01").unwrap();
        assert_eq!(rule.frequency, CoreRecurrenceFrequency::Weekly);
        assert_eq!(rule.interval, Some(2));
        assert_eq!(rule.weekdays, vec![1, 4]);
        assert_eq!(rule.until.as_deref(), Some("2027-01-01"));
        assert_eq!(
            describe_repeat(&rule),
            "every 2 weeks on mon, thu until 2027-01-01"
        );
        assert_eq!(parse_repeat("daily").unwrap().interval, None);
        assert!(parse_repeat("hourly").is_err());
        assert!(parse_repeat("daily;on=mon").is_err());
        assert!(parse_repeat("weekly;day=3").is_err());
        assert!(parse_repeat("daily;until=2027-01-01;count=3").is_err());
        assert!(parse_repeat("daily;every=0").is_err());
        assert!(parse_repeat("monthly;until=2027-02-30").is_err());
    }

    #[test]
    fn priorities() {
        assert_eq!(parse_priority("High"), Ok(3));
        assert_eq!(parse_priority("5"), Ok(5));
        assert!(parse_priority("0").is_err());
        assert!(parse_priority("urgent").is_err());
    }

    #[test]
    fn fields_merge_onto_the_draft() {
        let c = clock("UTC", "2026-11-11T12:00:00Z");
        let stored = task(
            "t1",
            r#"{"@type":"Task","title":"Pay rent","notes":"flat 2","priority":2,"tags":["home"],"dueDate":"2026-11-15","futureKey":1}"#,
        );
        let mut draft = stored.draft();
        apply_fields(
            &mut draft,
            &TaskFields {
                priority: Some(3),
                clear_tags: true,
                ..Default::default()
            },
            &c,
        )
        .unwrap();
        // Untouched fields stay, and so does a key this build does not know.
        assert_eq!(draft.notes, "flat 2");
        assert_eq!(draft.due_date.as_deref(), Some("2026-11-15"));
        assert_eq!(draft.priority, Some(3));
        assert!(draft.tags.is_empty());
        let written = task_write(&draft, "2026-11-11T12:00:00Z").unwrap();
        assert!(written.contains("\"futureKey\""), "{written}");
        assert!(!written.contains("\"tags\""), "{written}");
    }

    #[test]
    fn a_repeat_needs_a_due_date() {
        let c = clock("UTC", "2026-11-11T12:00:00Z");
        let mut draft = CoreTaskDraft {
            title: "x".into(),
            ..Default::default()
        };
        let repeat = TaskFields {
            repeat: Some(parse_repeat("daily").unwrap()),
            ..Default::default()
        };
        assert!(apply_fields(&mut draft, &repeat, &c).is_err());
        let with_due = TaskFields {
            due: Some("2026-11-12".into()),
            repeat: repeat.repeat.clone(),
            ..Default::default()
        };
        apply_fields(&mut draft, &with_due, &c).unwrap();
        assert!(draft.recurrence.is_some());
        // Dropping the date of a repeating task is refused unless the repeat goes too.
        let clear = TaskFields {
            clear_due: true,
            ..Default::default()
        };
        assert!(apply_fields(&mut draft, &clear, &c).is_err());
    }

    #[test]
    fn listing_nests_subtasks_and_hides_done_ones() {
        let c = clock("UTC", "2026-11-11T12:00:00Z");
        let tasks = vec![
            task(
                "a",
                r#"{"@type":"Task","title":"Parent","dueDate":"2026-11-20"}"#,
            ),
            task("b", r#"{"@type":"Task","title":"Child","parentId":"a"}"#),
            task("d", r#"{"@type":"Task","title":"Finished","done":true}"#),
            task("e", r#"{"@type":"Task","title":"Done parent","done":true}"#),
            task(
                "f",
                r#"{"@type":"Task","title":"Open child","parentId":"e"}"#,
            ),
        ];
        let open = list_lines(&tasks, &[], &c, false, None);
        let titles: Vec<String> = open
            .iter()
            .map(|line| line.split("] ").skip(1).collect::<Vec<_>>().join("] "))
            .collect();
        assert!(
            titles.iter().any(|t| t.starts_with("[ ] Parent")),
            "{open:?}"
        );
        assert!(open.iter().any(|l| l.contains("  [ ] Child")), "{open:?}");
        // A done parent stays while it has an open task under it.
        assert!(
            open.iter().any(|l| l.contains("[x] Done parent")),
            "{open:?}"
        );
        assert!(!open.iter().any(|l| l.contains("Finished")), "{open:?}");
        let every = list_lines(&tasks, &[], &c, true, None);
        assert!(every.iter().any(|l| l.contains("Finished")), "{every:?}");
        // The child follows its parent directly.
        let parent_at = every.iter().position(|l| l.contains("] Parent")).unwrap();
        assert!(every[parent_at + 1].contains("Child"), "{every:?}");
    }

    #[test]
    fn a_cycle_is_still_listed() {
        let c = clock("UTC", "2026-11-11T12:00:00Z");
        let tasks = vec![
            task("a", r#"{"@type":"Task","title":"One","parentId":"b"}"#),
            task("b", r#"{"@type":"Task","title":"Two","parentId":"a"}"#),
        ];
        let lines = list_lines(&tasks, &[], &c, false, None);
        assert_eq!(lines.len(), 2, "{lines:?}");
    }

    #[test]
    fn agenda_groups_by_local_day() {
        let c = clock("UTC", "2026-11-11T12:00:00Z");
        let tasks = vec![
            task(
                "a",
                r#"{"@type":"Task","title":"Late","dueDate":"2026-11-01"}"#,
            ),
            task(
                "b",
                r#"{"@type":"Task","title":"Now","dueDate":"2026-11-11"}"#,
            ),
            task("c", r#"{"@type":"Task","title":"Whenever"}"#),
        ];
        let lines = agenda_lines(&tasks, &[], &c);
        let at = |needle: &str| lines.iter().position(|l| l.contains(needle)).unwrap();
        assert_eq!(lines[0], "Overdue:");
        assert!(
            at("Late") < at("Now") && at("Now") < at("Whenever"),
            "{lines:?}"
        );
        assert!(lines.iter().any(|l| l == "No date:"));
    }

    #[test]
    fn completion_clock_carries_a_timed_due_in_local_time() {
        let c = clock("America/New_York", "2026-11-11T12:00:00Z");
        let timed = task(
            "t",
            r#"{"@type":"Task","title":"Call","dueDate":"2026-11-12T14:00:00Z"}"#,
        );
        let clock_for = c.for_task(&timed);
        assert_eq!(clock_for.today, "2026-11-11");
        assert_eq!(clock_for.due_local.as_deref(), Some("2026-11-12T09:00:00"));
        let day = task(
            "d",
            r#"{"@type":"Task","title":"Day","dueDate":"2026-11-12"}"#,
        );
        assert_eq!(c.for_task(&day).due_local, None);
    }
}
