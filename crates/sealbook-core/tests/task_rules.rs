//! What ticking, moving and deleting tasks writes, against the fixture the
//! clients share.
//!
//! Each case starts from stored payloads and records every write as the exact
//! payload it produces, so a host checks itself by parsing the inputs, calling
//! its binding and writing each draft with the fixture's `now`.
//!
//! Regenerate with:
//! `REGENERATE_TASK_RULES_FIXTURE=1 cargo test -p sealbook-core --test task_rules -- --ignored regenerate`

use sealbook_core::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

const FIXTURE: &str = "../sealbook-protocol/fixtures/payloads/task-rules.json";

const NOW: &str = "2026-11-02T09:00:00.000Z";

#[derive(Clone, Serialize, Deserialize)]
struct Stored {
    id: String,
    raw: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Written {
    id: String,
    payload: String,
}

#[derive(Serialize, Deserialize)]
struct Fixture {
    now: String,
    refusals: Refusals,
    completions: Vec<CompletionCase>,
    plans: Vec<PlanCase>,
    orders: Vec<OrderCase>,
    imports: Vec<ImportCase>,
}

#[derive(Serialize, Deserialize)]
struct Refusals {
    task_move: String,
    list_move: String,
    default_list_remove: String,
    import: String,
}

#[derive(Serialize, Deserialize)]
struct CompletionCase {
    case: String,
    tasks: Vec<Stored>,
    id: String,
    clock: CoreTaskClock,
    rolled: bool,
    local_due: Option<String>,
    writes: Vec<Written>,
}

#[derive(Serialize, Deserialize)]
struct PlanCase {
    case: String,
    /// `remove`, `move`, `relist`, `list_move` or `list_remove`. For `relist`,
    /// `parent_id` holds the list the task was edited into.
    action: String,
    tasks: Vec<Stored>,
    lists: Vec<Stored>,
    id: String,
    parent_id: Option<String>,
    refusal: Option<String>,
    task_writes: Vec<Written>,
    list_writes: Vec<Written>,
    removed_tasks: Vec<String>,
    removed_lists: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct OrderCase {
    case: String,
    items: Vec<CoreTaskOrderItem>,
    order: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct ImportCase {
    case: String,
    text: String,
    refused: bool,
    skipped: u32,
    tasks: Vec<ImportedWrite>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct ImportedWrite {
    source_id: Option<String>,
    payload: String,
}

fn stored(id: &str, payload: serde_json::Value) -> Stored {
    Stored {
        id: id.into(),
        raw: payload.to_string(),
    }
}

fn tasks_of(stored: &[Stored]) -> Vec<CoreTask> {
    stored.iter().map(|s| task_parse(&s.id, &s.raw)).collect()
}

fn lists_of(stored: &[Stored]) -> Vec<CoreTaskList> {
    stored
        .iter()
        .map(|s| task_list_parse(&s.id, &s.raw))
        .collect()
}

fn task_written(write: &CoreTaskWrite) -> Written {
    Written {
        id: write.id.clone(),
        payload: task_write(&write.draft, NOW).expect("writable"),
    }
}

fn list_written(write: &CoreTaskListWrite) -> Written {
    Written {
        id: write.id.clone(),
        payload: task_list_write(&write.draft).expect("writable"),
    }
}

fn clock(today: &str, due_local: Option<&str>) -> CoreTaskClock {
    CoreTaskClock {
        now: NOW.into(),
        today: today.into(),
        due_local: due_local.map(Into::into),
        anchor_local: None,
    }
}

fn completion_inputs() -> Vec<(String, Vec<Stored>, String, CoreTaskClock)> {
    let weekly = |due: &str| {
        stored(
            "p",
            json!({"@type": "Task", "version": "1.0", "title": "Water plants", "dueDate": due,
                   "recurrence": {"frequency": "weekly"}, "createdAt": "2026-10-01T00:00:00Z"}),
        )
    };
    vec![
        (
            "a one-off task is marked done".into(),
            vec![stored(
                "a",
                json!({"title": "Post letter", "dueDate": "2026-11-02"}),
            )],
            "a".into(),
            clock("2026-11-02", None),
        ),
        (
            "a recurring task rolls a week and reopens its done subtasks, nested ones too".into(),
            vec![
                weekly("2026-11-02"),
                stored(
                    "c",
                    json!({"title": "Feed", "parentId": "p", "done": true,
                           "completedAt": "2026-11-01T10:00:00Z"}),
                ),
                stored("g", json!({"title": "Mist", "parentId": "c", "done": true})),
                stored("o", json!({"title": "Repot", "parentId": "p"})),
            ],
            "p".into(),
            clock("2026-11-02", None),
        ),
        (
            "an overdue recurring task rolls past today".into(),
            vec![weekly("2026-10-05")],
            "p".into(),
            clock("2026-11-02", None),
        ),
        (
            "a timed recurring task keeps its local time for the host to store".into(),
            vec![weekly("2026-11-02T17:30:00Z")],
            "p".into(),
            clock("2026-11-02", Some("2026-11-02T18:30")),
        ),
        (
            "a spent series is marked done".into(),
            vec![stored(
                "p",
                json!({"title": "Course", "dueDate": "2026-11-02",
                       "recurrence": {"frequency": "daily", "count": 1}}),
            )],
            "p".into(),
            clock("2026-11-02", None),
        ),
        (
            "an untitled task stays untitled".into(),
            vec![stored("u", json!({"dueDate": "2026-11-02"}))],
            "u".into(),
            clock("2026-11-02", None),
        ),
    ]
}

fn complete(
    tasks: &[Stored],
    id: &str,
    clock: &CoreTaskClock,
) -> (bool, Option<String>, Vec<Written>) {
    let all = tasks_of(tasks);
    let task = all.iter().find(|t| t.id == id).expect("the case's task");
    let done = task_complete(task, &all, clock);
    let mut writes = vec![task_written(&CoreTaskWrite {
        id: id.into(),
        draft: done.task,
    })];
    writes.extend(done.reopened.iter().map(task_written));
    (done.rolled, done.local_due, writes)
}

type PlanInput = (
    String,
    String,
    Vec<Stored>,
    Vec<Stored>,
    String,
    Option<String>,
);

fn plan_inputs() -> Vec<PlanInput> {
    let default = default_task_list_id();
    let tree = vec![
        stored("root", json!({"title": "Root"})),
        stored("p", json!({"title": "Parent", "parentId": "root"})),
        stored("c", json!({"parentId": "p"})),
        stored("home", json!({"title": "Home", "taskListId": "work"})),
    ];
    let lists = vec![
        stored(&default, json!({"name": "Default Task List"})),
        stored("work", json!({"name": "Work", "color": "#9ece6a"})),
        stored("proj", json!({"name": "Project", "parentId": "work"})),
        stored("sub", json!({"name": "Sub", "parentId": "proj"})),
    ];
    let listed = vec![
        stored("a", json!({"title": "A", "taskListId": "proj"})),
        stored("b", json!({"title": "B", "taskListId": "work"})),
    ];
    vec![
        (
            "deleting a task moves its subtasks up a level".into(),
            "remove".into(),
            tree.clone(),
            vec![],
            "p".into(),
            None,
        ),
        (
            "a task moved under a task in another list takes its subtree there".into(),
            "move".into(),
            tree.clone(),
            vec![],
            "p".into(),
            Some("home".into()),
        ),
        (
            "a task moved to the top level".into(),
            "move".into(),
            tree.clone(),
            vec![],
            "c".into(),
            None,
        ),
        (
            "a task cannot move inside itself".into(),
            "move".into(),
            tree.clone(),
            vec![],
            "root".into(),
            Some("c".into()),
        ),
        (
            "a task edited into another list takes its subtasks along".into(),
            "relist".into(),
            tree.clone(),
            vec![],
            "root".into(),
            Some("work".into()),
        ),
        (
            "a move that changes nothing writes nothing".into(),
            "move".into(),
            tree,
            vec![],
            "c".into(),
            Some("p".into()),
        ),
        (
            "deleting a nested list moves its lists and tasks to its parent".into(),
            "list_remove".into(),
            listed.clone(),
            lists.clone(),
            "proj".into(),
            None,
        ),
        (
            "deleting a top-level list moves its tasks to the default list".into(),
            "list_remove".into(),
            listed.clone(),
            lists.clone(),
            "work".into(),
            None,
        ),
        (
            "the default list cannot be deleted".into(),
            "list_remove".into(),
            listed,
            lists.clone(),
            default.clone(),
            None,
        ),
        (
            "a list moved under another".into(),
            "list_move".into(),
            vec![],
            lists.clone(),
            "sub".into(),
            Some("work".into()),
        ),
        (
            "a list cannot move inside itself".into(),
            "list_move".into(),
            vec![],
            lists.clone(),
            "work".into(),
            Some("sub".into()),
        ),
        (
            "the default list stays at the top level".into(),
            "list_move".into(),
            vec![],
            lists,
            default,
            Some("work".into()),
        ),
    ]
}

fn plan(
    action: &str,
    tasks: &[Stored],
    lists: &[Stored],
    id: &str,
    parent: Option<String>,
) -> CoreTaskPlan {
    let (tasks, lists) = (tasks_of(tasks), lists_of(lists));
    match action {
        "remove" => task_remove_plan(&tasks, id),
        "move" => task_move_plan(&tasks, id, parent),
        "list_move" => task_list_move_plan(&lists, id, parent),
        "list_remove" => task_list_remove_plan(&lists, &tasks, id),
        "relist" => task_relist_plan(&tasks, id, parent.as_deref().unwrap_or_default()),
        other => panic!("unknown action {other}"),
    }
}

fn order_inputs() -> Vec<(String, Vec<CoreTaskOrderItem>)> {
    let item = |id: &str, title: &str, done: bool, due_at: Option<f64>, priority: Option<u32>| {
        CoreTaskOrderItem {
            id: id.into(),
            title: title.into(),
            done,
            due_at,
            priority,
        }
    };
    vec![(
        "open before done, then due, then priority, then title without case or accents".into(),
        vec![
            item("1", "Done early", true, Some(1.0), None),
            item("2", "No date", false, None, Some(3)),
            item("3", "Later", false, Some(2_000.0), None),
            item("4", "beta", false, Some(1_000.0), None),
            item("5", "Álpha", false, Some(1_000.0), None),
            item("6", "Urgent", false, Some(1_000.0), Some(3)),
        ],
    )]
}

fn import_inputs() -> Vec<(String, String)> {
    let lists = [task_list_parse("work", r#"{"name":"Work"}"#)];
    let exported = task_export(
        &[
            task_parse(
                "c",
                &json!({"title": "Child", "parentId": "p", "taskListId": "work",
                        "recurrence": {"frequency": "fortnightly"}})
                .to_string(),
            ),
            task_parse(
                "p",
                &json!({"title": "Parent", "dueDate": "2026-11-02", "priority": 2,
                        "tags": ["home"], "recurrence": {"frequency": "weekly", "interval": 2},
                        "createdAt": "2026-10-01T00:00:00Z"})
                .to_string(),
            ),
        ],
        &lists,
        NOW,
    );
    vec![
        ("an export reads back parents first".into(), exported),
        (
            "a bare array drops a missing or circular parent and skips the untitled".into(),
            json!([
                {"id": "a", "title": "A", "parentId": "b"},
                {"id": "b", "title": "B", "parentId": "a"},
                {"id": "c", "title": "C", "parentId": "gone"},
                {"id": "d", "title": "  "},
                "not a task",
            ])
            .to_string(),
        ),
        ("a file that is not JSON".into(), "not json".into()),
        (
            "an object that is not a task export".into(),
            r#"{"@type":"sealbook-note-export","tasks":[]}"#.into(),
        ),
    ]
}

fn import(text: &str) -> (bool, u32, Vec<ImportedWrite>) {
    match task_import(text) {
        Err(CoreError::Malformed { detail }) => {
            assert_eq!(detail, TASK_IMPORT_REFUSAL);
            (true, 0, Vec::new())
        }
        Err(other) => panic!("unexpected {other}"),
        Ok(read) => (
            false,
            read.skipped,
            read.tasks
                .into_iter()
                .map(|task| ImportedWrite {
                    source_id: task.source_id,
                    payload: task_write(&task.draft, NOW).expect("writable"),
                })
                .collect(),
        ),
    }
}

fn fixture() -> Fixture {
    let text = std::fs::read_to_string(FIXTURE).expect("fixture");
    serde_json::from_str(&text).expect("fixture parses")
}

#[test]
fn every_tick_writes_what_the_fixture_holds() {
    let fixture = fixture();
    assert_eq!(fixture.completions.len(), completion_inputs().len());
    for case in &fixture.completions {
        let (rolled, local_due, writes) = complete(&case.tasks, &case.id, &case.clock);
        assert_eq!(rolled, case.rolled, "{}", case.case);
        assert_eq!(local_due, case.local_due, "{}", case.case);
        assert_eq!(writes, case.writes, "{}", case.case);
    }
}

#[test]
fn every_plan_writes_what_the_fixture_holds() {
    let fixture = fixture();
    assert_eq!(fixture.plans.len(), plan_inputs().len());
    for case in &fixture.plans {
        let plan = plan(
            &case.action,
            &case.tasks,
            &case.lists,
            &case.id,
            case.parent_id.clone(),
        );
        assert_eq!(plan.refusal, case.refusal, "{}", case.case);
        let tasks: Vec<_> = plan.tasks.iter().map(task_written).collect();
        let lists: Vec<_> = plan.lists.iter().map(list_written).collect();
        assert_eq!(tasks, case.task_writes, "{}", case.case);
        assert_eq!(lists, case.list_writes, "{}", case.case);
        assert_eq!(plan.removed_tasks, case.removed_tasks, "{}", case.case);
        assert_eq!(plan.removed_lists, case.removed_lists, "{}", case.case);
    }
}

#[test]
fn every_order_is_the_one_the_fixture_holds() {
    for case in fixture().orders {
        assert_eq!(order_tasks(&case.items), case.order, "{}", case.case);
    }
}

#[test]
fn every_import_reads_as_the_fixture_holds() {
    let fixture = fixture();
    assert_eq!(fixture.imports.len(), import_inputs().len());
    for case in &fixture.imports {
        let (refused, skipped, tasks) = import(&case.text);
        assert_eq!(refused, case.refused, "{}", case.case);
        assert_eq!(skipped, case.skipped, "{}", case.case);
        assert_eq!(tasks, case.tasks, "{}", case.case);
    }
}

#[test]
#[ignore]
fn regenerate() {
    if std::env::var("REGENERATE_TASK_RULES_FIXTURE").is_err() {
        return;
    }
    let fixture = Fixture {
        now: NOW.into(),
        refusals: Refusals {
            task_move: TASK_MOVE_REFUSAL.into(),
            list_move: TASK_LIST_MOVE_REFUSAL.into(),
            default_list_remove: DEFAULT_TASK_LIST_REMOVE_REFUSAL.into(),
            import: TASK_IMPORT_REFUSAL.into(),
        },
        completions: completion_inputs()
            .into_iter()
            .map(|(case, tasks, id, clock)| {
                let (rolled, local_due, writes) = complete(&tasks, &id, &clock);
                CompletionCase {
                    case,
                    tasks,
                    id,
                    clock,
                    rolled,
                    local_due,
                    writes,
                }
            })
            .collect(),
        plans: plan_inputs()
            .into_iter()
            .map(|(case, action, tasks, lists, id, parent_id)| {
                let plan = plan(&action, &tasks, &lists, &id, parent_id.clone());
                PlanCase {
                    case,
                    action,
                    tasks,
                    lists,
                    id,
                    parent_id,
                    refusal: plan.refusal,
                    task_writes: plan.tasks.iter().map(task_written).collect(),
                    list_writes: plan.lists.iter().map(list_written).collect(),
                    removed_tasks: plan.removed_tasks,
                    removed_lists: plan.removed_lists,
                }
            })
            .collect(),
        orders: order_inputs()
            .into_iter()
            .map(|(case, items)| OrderCase {
                case,
                order: order_tasks(&items),
                items,
            })
            .collect(),
        imports: import_inputs()
            .into_iter()
            .map(|(case, text)| {
                let (refused, skipped, tasks) = import(&text);
                ImportCase {
                    case,
                    text,
                    refused,
                    skipped,
                    tasks,
                }
            })
            .collect(),
    };
    std::fs::write(
        FIXTURE,
        format!("{}\n", serde_json::to_string_pretty(&fixture).unwrap()),
    )
    .unwrap();
}
