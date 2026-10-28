//! Task and task list payloads, against the fixture the clients share.
//!
//! What is pinned is the plaintext itself, byte for byte: the server sees only
//! the content type, so nothing but this fixture catches a client writing a key
//! the others do not read. The cases are the ones the web writer got wrong or
//! left to chance: a fallback title written back by a save, a due value that
//! names no real day, a completion time on a task that is open, and a repeat
//! rule from a newer build.
//!
//! Regenerate with:
//! `REGENERATE_TASK_FIXTURE=1 cargo test -p sealbook-core --test tasks -- --ignored regenerate`

use sealbook_core::*;
use serde::{Deserialize, Serialize};

const FIXTURE: &str = "../sealbook-protocol/fixtures/payloads/tasks.json";

/// Fixed so the written payloads are reproducible: core has no clock.
const NOW: &str = "2026-10-28T12:00:00Z";

const TASK: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ROOT: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const CHILD: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

#[derive(Serialize, Deserialize)]
struct Fixture {
    now: String,
    constants: Constants,
    writes: Vec<WriteCase>,
    parses: Vec<ParseCase>,
    due_dates: Vec<DueCase>,
    list_writes: Vec<ListWriteCase>,
    list_parses: Vec<ListParseCase>,
    tones: Vec<ToneCase>,
    refusals: Vec<RefusalCase>,
}

#[derive(Serialize, Deserialize)]
struct Constants {
    task_content_type: String,
    list_content_type: String,
    task_keys: Vec<String>,
    list_keys: Vec<String>,
    default_list_id: String,
    default_list_name: String,
    untitled_task_title: String,
    unreadable_task_title: String,
    untitled_list_name: String,
    max_completions: usize,
}

#[derive(Serialize, Deserialize)]
struct WriteCase {
    case: String,
    draft: CoreTaskDraft,
    payload: String,
}

#[derive(Serialize, Deserialize)]
struct ParseCase {
    case: String,
    id: String,
    raw: String,
    task: CoreTask,
}

#[derive(Serialize, Deserialize)]
struct DueCase {
    case: String,
    value: String,
    normalized: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ListWriteCase {
    case: String,
    draft: CoreTaskListDraft,
    payload: String,
}

#[derive(Serialize, Deserialize)]
struct ListParseCase {
    case: String,
    id: String,
    raw: String,
    list: CoreTaskList,
}

#[derive(Serialize, Deserialize)]
struct ToneCase {
    case: String,
    lists: Vec<CoreTaskList>,
    id: String,
    tone: String,
}

#[derive(Serialize, Deserialize)]
struct RefusalCase {
    case: String,
    error: String,
}

fn fixture() -> Fixture {
    let text = std::fs::read_to_string(FIXTURE).expect("fixture");
    serde_json::from_str(&text).expect("fixture parses")
}

fn blank() -> CoreTaskDraft {
    CoreTaskDraft {
        title: "Pay rent".into(),
        task_list_id: default_task_list_id(),
        ..Default::default()
    }
}

fn weekly() -> CoreRecurrence {
    CoreRecurrence {
        frequency: CoreRecurrenceFrequency::Weekly,
        interval: Some(2),
        until: None,
        count: None,
        weekdays: vec![1, 3],
        day_of_month: None,
        nth_weekday: None,
        extra: None,
    }
}

fn stored_with_everything() -> String {
    serde_json::json!({
        "@type": "Task",
        "version": "1.0",
        "title": "Pay rent",
        "notes": "before the 1st",
        "done": true,
        "completedAt": "2026-10-27T08:00:00.000Z",
        "completions": ["2026-09-27T08:00:00.000Z", "2026-08-27T08:00:00.000Z"],
        "dueDate": "2026-11-01",
        "priority": 3,
        "tags": ["home", "money"],
        "taskListId": ROOT,
        "parentId": CHILD,
        "recurrence": { "frequency": "monthly", "dayOfMonth": 1 },
        "recurrenceAnchor": "2026-09-01",
        "createdAt": "2026-01-01T00:00:00Z",
        "updatedAt": "2026-02-02T00:00:00Z",
        "somethingNewer": { "from": "a later build" }
    })
    .to_string()
}

fn write_cases() -> Vec<(String, CoreTaskDraft)> {
    let parsed = task_parse(TASK, &stored_with_everything());
    vec![
        ("an open task written from scratch".into(), blank()),
        (
            "a title and notes are trimmed".into(),
            CoreTaskDraft {
                title: "  Pay rent  ".into(),
                notes: "  before the 1st  ".into(),
                ..blank()
            },
        ),
        (
            "a blank list resolves to the default".into(),
            CoreTaskDraft {
                task_list_id: "   ".into(),
                ..blank()
            },
        ),
        (
            "a due day, a priority, tags trimmed and de-duplicated".into(),
            CoreTaskDraft {
                due_date: Some("2026-11-01".into()),
                priority: Some(2),
                tags: vec!["Home".into(), " home ".into(), "".into(), "money".into()],
                ..blank()
            },
        ),
        (
            "a due value that names no day writes no key".into(),
            CoreTaskDraft {
                due_date: Some("2026-02-30".into()),
                priority: Some(0),
                ..blank()
            },
        ),
        (
            "a completion time is written only on a done task".into(),
            CoreTaskDraft {
                completed_at: Some("2026-10-27T08:00:00.000Z".into()),
                ..blank()
            },
        ),
        (
            "a done task keeps its completion time".into(),
            CoreTaskDraft {
                done: true,
                completed_at: Some("2026-10-27T08:00:00.000Z".into()),
                ..blank()
            },
        ),
        (
            "a recurring task with its anchor".into(),
            CoreTaskDraft {
                due_date: Some("2026-11-03T09:00:00.000Z".into()),
                recurrence: Some(weekly()),
                recurrence_anchor: Some("2026-10-20T09:00:00.000Z".into()),
                ..blank()
            },
        ),
        (
            "an anchor without a rule is not written".into(),
            CoreTaskDraft {
                recurrence_anchor: Some("2026-10-20".into()),
                ..blank()
            },
        ),
        (
            "completions are trimmed and kept newest first".into(),
            CoreTaskDraft {
                recurrence: Some(weekly()),
                completions: vec![" 2026-10-20T09:00:00.000Z ".into(), "".into(), "b".into()],
                ..blank()
            },
        ),
        (
            "an edit keeps a key a later build added".into(),
            CoreTaskDraft {
                title: "Renamed".into(),
                ..parsed.draft()
            },
        ),
        (
            "an edit that reopens the task".into(),
            CoreTaskDraft {
                done: false,
                completed_at: None,
                ..parsed.draft()
            },
        ),
        (
            "an untitled task saved unchanged stays untitled".into(),
            task_parse(
                TASK,
                r#"{"@type":"Task","dueDate":"2026-11-01","createdAt":"2026-01-01T00:00:00Z"}"#,
            )
            .draft(),
        ),
        (
            "a newer minor keeps its version, its keys and the keys inside its repeat rule".into(),
            task_parse(
                TASK,
                r#"{"@type":"Task","version":"1.7","title":"t","dueDate":"2026-11-01","recurrence":{"frequency":"weekly","interval":2,"futureRule":{"n":1}},"recurrenceAnchor":"2026-11-01","futureKey":[1]}"#,
            )
            .draft(),
        ),
        (
            "a repeat rule from a newer build is put back".into(),
            task_parse(
                TASK,
                r#"{"@type":"Task","title":"t","dueDate":"2026-11-01","recurrence":{"frequency":"hourly","interval":3},"recurrenceAnchor":"2026-11-01"}"#,
            )
            .draft(),
        ),
    ]
}

fn parse_cases() -> Vec<(String, String, String)> {
    let case = |name: &str, raw: String| (name.to_string(), TASK.to_string(), raw);
    vec![
        case(
            "the richest payload any client writes",
            stored_with_everything(),
        ),
        case("an empty object", "{}".into()),
        case(
            "a title that is only space",
            r#"{"title":"   ","dueDate":"2026-11-01"}"#.into(),
        ),
        case("a payload that is not JSON at all", "never a task".into()),
        case("a payload that is JSON but not an object", "[1,2]".into()),
        case(
            "a completion time on a task that is open",
            r#"{"title":"t","completedAt":"2026-10-27T08:00:00.000Z"}"#.into(),
        ),
        case(
            "done as a string is not done",
            r#"{"title":"t","done":"true"}"#.into(),
        ),
        case(
            "due values that name no moment",
            r#"{"title":"t","dueDate":"2026-02-30","recurrenceAnchor":"soon"}"#.into(),
        ),
        case(
            "a priority that is not a whole number",
            r#"{"title":"t","priority":1.5}"#.into(),
        ),
        case(
            "a priority above the named ones",
            r#"{"title":"t","priority":7}"#.into(),
        ),
        case(
            "tags and completions that are not all strings",
            r#"{"title":"t","tags":["a",{"x":1},3,"A"],"completions":["x",4,"  ","y"]}"#.into(),
        ),
        case(
            "a repeat rule with a frequency this build does not know",
            r#"{"title":"t","dueDate":"2026-11-01","recurrence":{"frequency":"hourly"}}"#.into(),
        ),
        case(
            "a repeat rule with fields out of range",
            r#"{"title":"t","recurrence":{"frequency":"weekly","weekdays":[1,9],"dayOfMonth":40}}"#
                .into(),
        ),
        case(
            "a newer minor with keys unknown at the top and inside the repeat rule",
            r#"{"@type":"Task","version":"1.7","title":"t","dueDate":"2026-11-01","recurrence":{"frequency":"weekly","futureRule":{"n":1}},"futureKey":[1]}"#.into(),
        ),
        case(
            "a payload from a newer schema major",
            r#"{"@type":"Task","version":"2.0","title":"t"}"#.into(),
        ),
    ]
}

fn due_cases() -> Vec<(String, String)> {
    [
        ("a day", "2026-10-28"),
        ("a day with space around it", "  2026-10-28  "),
        ("the last day of a leap February", "2024-02-29"),
        (
            "the 29th of a February that is not a leap one",
            "2025-02-29",
        ),
        ("the 30th of February", "2026-02-30"),
        ("a month past twelve", "2026-13-01"),
        ("a time with no zone", "2026-10-28T09:30"),
        (
            "a time in UTC with milliseconds",
            "2026-10-28T09:30:15.250Z",
        ),
        ("a time with an offset", "2026-10-28T09:30:00+01:00"),
        ("an hour past the day", "2026-10-28T25:00"),
        ("a time with no minutes", "2026-10-28T09"),
        ("a space where the T goes", "2026-10-28 09:30"),
        ("an offset with no colon", "2026-10-28T09:30:00+0100"),
        ("words", "tomorrow"),
        ("nothing", ""),
    ]
    .iter()
    .map(|(case, value)| (case.to_string(), value.to_string()))
    .collect()
}

fn list_write_cases() -> Vec<(String, CoreTaskListDraft)> {
    let stored = serde_json::json!({
        "@type": "TaskList",
        "version": "1.0",
        "name": "Home",
        "parentId": ROOT,
        "color": "#112233",
        "sortKey": "from a later build"
    })
    .to_string();
    let parsed = task_list_parse(CHILD, &stored);
    vec![
        (
            "a list created from scratch".into(),
            CoreTaskListDraft {
                name: "Home".into(),
                ..Default::default()
            },
        ),
        (
            "a name with surrounding space, under another list".into(),
            CoreTaskListDraft {
                name: "  Home  ".into(),
                parent_id: Some(ROOT.into()),
                ..Default::default()
            },
        ),
        (
            "a coloured top-level list".into(),
            CoreTaskListDraft {
                name: "Home".into(),
                color: Some("#112233".into()),
                ..Default::default()
            },
        ),
        (
            "a rename keeps the parent, the colour and a later build's key".into(),
            CoreTaskListDraft {
                name: "Renamed".into(),
                ..parsed.draft()
            },
        ),
        (
            "moving to the top level clears the parent".into(),
            CoreTaskListDraft {
                parent_id: None,
                ..parsed.draft()
            },
        ),
    ]
}

fn list_parse_cases() -> Vec<(String, String, String)> {
    vec![
        (
            "a named, nested, coloured list".into(),
            CHILD.into(),
            format!(r##"{{"name":"  Home  ","parentId":"{ROOT}","color":"#112233"}}"##),
        ),
        (
            "the default list, unnamed".into(),
            default_task_list_id(),
            "{}".into(),
        ),
        (
            "any other list, not JSON".into(),
            CHILD.into(),
            "not json".into(),
        ),
        (
            "an empty parent and colour read as none".into(),
            CHILD.into(),
            r#"{"name":"Home","parentId":"  ","color":""}"#.into(),
        ),
    ]
}

fn tone_cases() -> Vec<(String, Vec<CoreTaskList>, String)> {
    let parse = |id: &str, raw: String| task_list_parse(id, &raw);
    let tree = vec![
        parse(ROOT, r##"{"name":"Root","color":"#112233"}"##.into()),
        parse(CHILD, format!(r#"{{"name":"Child","parentId":"{ROOT}"}}"#)),
        parse("plain", r#"{"name":"Plain"}"#.into()),
        parse("orphan", r#"{"name":"Orphan","parentId":"missing"}"#.into()),
        parse("loop-a", r#"{"name":"A","parentId":"loop-b"}"#.into()),
        parse("loop-b", r#"{"name":"B","parentId":"loop-a"}"#.into()),
    ];
    let case = |name: &str, id: &str| (name.to_string(), tree.clone(), id.to_string());
    vec![
        case("a root with an explicit colour", ROOT),
        case("a child takes its root's colour", CHILD),
        case("a root with none is hashed from its id", "plain"),
        case("a list whose parent is gone is its own root", "orphan"),
        case("a loop ends the walk", "loop-a"),
        case("an id in no list is hashed", "unknown"),
    ]
}

fn error_name(error: &CoreError) -> String {
    error.kind().to_string()
}

#[test]
fn every_written_payload_is_the_one_spelling_the_fixture_holds() {
    let fixture = fixture();
    assert_eq!(
        fixture.now, NOW,
        "the fixture was built under another clock"
    );
    assert_eq!(fixture.writes.len(), write_cases().len());
    for (expected, (case, draft)) in fixture.writes.iter().zip(write_cases()) {
        assert_eq!(expected.case, case);
        assert_eq!(expected.draft, draft, "{case}: the draft drifted");
        assert_eq!(
            task_write(&draft, NOW).expect("writes"),
            expected.payload,
            "{case}"
        );
    }
}

#[test]
fn every_payload_reads_back_as_the_record_the_fixture_holds() {
    let fixture = fixture();
    assert_eq!(fixture.parses.len(), parse_cases().len());
    for (expected, (case, id, raw)) in fixture.parses.iter().zip(parse_cases()) {
        assert_eq!(expected.case, case);
        assert_eq!(expected.raw, raw, "{case}: the input drifted");
        assert_eq!(task_parse(&id, &raw), expected.task, "{case}");
    }
}

#[test]
fn every_due_value_normalises_as_the_fixture_holds() {
    let fixture = fixture();
    assert_eq!(fixture.due_dates.len(), due_cases().len());
    for (expected, (case, value)) in fixture.due_dates.iter().zip(due_cases()) {
        assert_eq!(expected.case, case);
        assert_eq!(expected.value, value, "{case}: the input drifted");
        assert_eq!(normalize_due_date(&value), expected.normalized, "{case}");
    }
}

#[test]
fn every_list_payload_is_the_one_spelling_the_fixture_holds() {
    let fixture = fixture();
    assert_eq!(fixture.list_writes.len(), list_write_cases().len());
    for (expected, (case, draft)) in fixture.list_writes.iter().zip(list_write_cases()) {
        assert_eq!(expected.case, case);
        assert_eq!(expected.draft, draft, "{case}: the draft drifted");
        assert_eq!(
            task_list_write(&draft).expect("writes"),
            expected.payload,
            "{case}"
        );
    }
}

#[test]
fn every_list_reads_back_as_the_record_the_fixture_holds() {
    let fixture = fixture();
    assert_eq!(fixture.list_parses.len(), list_parse_cases().len());
    for (expected, (case, id, raw)) in fixture.list_parses.iter().zip(list_parse_cases()) {
        assert_eq!(expected.case, case);
        assert_eq!(task_list_parse(&id, &raw), expected.list, "{case}");
    }
}

#[test]
fn every_list_resolves_to_the_colour_the_fixture_holds() {
    let fixture = fixture();
    assert_eq!(fixture.tones.len(), tone_cases().len());
    for (expected, (case, lists, id)) in fixture.tones.iter().zip(tone_cases()) {
        assert_eq!(expected.case, case);
        assert_eq!(task_list_tone(&lists, &id), expected.tone, "{case}");
    }
}

#[test]
fn the_fixture_states_the_constants_the_hosts_mirror() {
    let constants = fixture().constants;
    assert_eq!(constants.task_content_type, TASK_CONTENT_TYPE);
    assert_eq!(constants.list_content_type, TASK_LIST_CONTENT_TYPE);
    assert_eq!(constants.task_keys, TASK_KEYS);
    assert_eq!(constants.list_keys, TASK_LIST_KEYS);
    assert_eq!(constants.default_list_id, default_task_list_id());
    assert_eq!(constants.default_list_name, DEFAULT_TASK_LIST_NAME);
    assert_eq!(constants.untitled_task_title, UNTITLED_TASK_TITLE);
    assert_eq!(constants.unreadable_task_title, UNREADABLE_TASK_TITLE);
    assert_eq!(constants.untitled_list_name, UNTITLED_TASK_LIST_NAME);
    assert_eq!(constants.max_completions, MAX_TASK_COMPLETIONS);
}

#[test]
fn a_payload_from_a_newer_schema_major_is_read_but_never_written_over() {
    let refusals = fixture().refusals;
    let future = r#"{"@type":"Task","version":"2.0","title":"t"}"#;

    assert!(!task_parse(TASK, future).readable);
    let refused = task_write(
        &CoreTaskDraft {
            raw: Some(future.into()),
            ..blank()
        },
        NOW,
    )
    .expect_err("refuses");
    assert_eq!(error_name(&refused), refusals[0].error);

    let list = r#"{"@type":"TaskList","version":"3.1","name":"future"}"#;
    assert!(!task_list_parse(CHILD, list).readable);
    let refused = task_list_write(&CoreTaskListDraft {
        name: "edited".into(),
        raw: Some(list.into()),
        ..Default::default()
    })
    .expect_err("refuses");
    assert_eq!(error_name(&refused), refusals[1].error);
}

/// The property the byte comparisons cannot state: every readable payload,
/// written from its own draft, reads back as the same task.
#[test]
fn a_task_written_from_what_was_read_reads_back_the_same() {
    for (case, id, raw) in parse_cases() {
        let task = task_parse(&id, &raw);
        if !task.readable || task.title == UNREADABLE_TASK_TITLE {
            continue;
        }
        let rewritten = task_write(&task.draft(), NOW).expect("writes");
        let again = task_parse(&id, &rewritten);
        assert_eq!(again.title, task.title, "{case}");
        assert_eq!(again.derived_title, task.derived_title, "{case}");
        assert_eq!(again.notes, task.notes, "{case}");
        assert_eq!(again.done, task.done, "{case}");
        assert_eq!(again.completed_at, task.completed_at, "{case}");
        assert_eq!(again.completions, task.completions, "{case}");
        assert_eq!(again.due_date, task.due_date, "{case}");
        assert_eq!(again.priority, task.priority, "{case}");
        assert_eq!(again.tags, task.tags, "{case}");
        assert_eq!(again.task_list_id, task.task_list_id, "{case}");
        assert_eq!(again.parent_id, task.parent_id, "{case}");
        assert_eq!(again.recurrence, task.recurrence, "{case}");
        assert_eq!(
            again.unreadable_recurrence, task.unreadable_recurrence,
            "{case}"
        );
    }
}

#[test]
#[ignore = "writes the shared fixture"]
fn regenerate() {
    if std::env::var("REGENERATE_TASK_FIXTURE").is_err() {
        return;
    }
    let fixture = Fixture {
        now: NOW.into(),
        constants: Constants {
            task_content_type: TASK_CONTENT_TYPE.into(),
            list_content_type: TASK_LIST_CONTENT_TYPE.into(),
            task_keys: TASK_KEYS.iter().map(|key| key.to_string()).collect(),
            list_keys: TASK_LIST_KEYS.iter().map(|key| key.to_string()).collect(),
            default_list_id: default_task_list_id(),
            default_list_name: DEFAULT_TASK_LIST_NAME.into(),
            untitled_task_title: UNTITLED_TASK_TITLE.into(),
            unreadable_task_title: UNREADABLE_TASK_TITLE.into(),
            untitled_list_name: UNTITLED_TASK_LIST_NAME.into(),
            max_completions: MAX_TASK_COMPLETIONS,
        },
        writes: write_cases()
            .into_iter()
            .map(|(case, draft)| WriteCase {
                case,
                payload: task_write(&draft, NOW).expect("writes"),
                draft,
            })
            .collect(),
        parses: parse_cases()
            .into_iter()
            .map(|(case, id, raw)| ParseCase {
                case,
                task: task_parse(&id, &raw),
                id,
                raw,
            })
            .collect(),
        due_dates: due_cases()
            .into_iter()
            .map(|(case, value)| DueCase {
                case,
                normalized: normalize_due_date(&value),
                value,
            })
            .collect(),
        list_writes: list_write_cases()
            .into_iter()
            .map(|(case, draft)| ListWriteCase {
                case,
                payload: task_list_write(&draft).expect("writes"),
                draft,
            })
            .collect(),
        list_parses: list_parse_cases()
            .into_iter()
            .map(|(case, id, raw)| ListParseCase {
                case,
                list: task_list_parse(&id, &raw),
                id,
                raw,
            })
            .collect(),
        tones: tone_cases()
            .into_iter()
            .map(|(case, lists, id)| ToneCase {
                case,
                tone: task_list_tone(&lists, &id),
                lists,
                id,
            })
            .collect(),
        refusals: vec![
            RefusalCase {
                case: "editing a task from a newer schema major".into(),
                error: "PayloadSchema".into(),
            },
            RefusalCase {
                case: "renaming a list from a newer schema major".into(),
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
