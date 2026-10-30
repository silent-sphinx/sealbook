//! Pipe-table repair, against the fixture every client's import is checked with.
//!
//! Regenerate with:
//! `REGENERATE_PIPE_TABLES_FIXTURE=1 cargo test -p sealbook-core --test pipe_tables -- --ignored regenerate`

use sealbook_core::repair_pipe_tables;
use serde::{Deserialize, Serialize};

const FIXTURE: &str = "../sealbook-protocol/fixtures/payloads/pipe-tables.json";

#[derive(Serialize, Deserialize)]
struct Fixture {
    cases: Vec<Case>,
}

#[derive(Serialize, Deserialize)]
struct Case {
    name: String,
    input: String,
    output: String,
}

fn read() -> Fixture {
    serde_json::from_str(&std::fs::read_to_string(FIXTURE).unwrap()).unwrap()
}

#[test]
fn repair_matches_the_fixture() {
    for case in read().cases {
        assert_eq!(
            repair_pipe_tables(&case.input),
            case.output,
            "{}",
            case.name
        );
    }
}

#[test]
fn a_repaired_note_is_left_alone() {
    for case in read().cases {
        assert_eq!(
            repair_pipe_tables(&case.output),
            case.output,
            "{}",
            case.name
        );
    }
}

#[test]
#[ignore]
fn regenerate() {
    if std::env::var("REGENERATE_PIPE_TABLES_FIXTURE").is_err() {
        return;
    }
    let mut fixture = read();
    for case in &mut fixture.cases {
        case.output = repair_pipe_tables(&case.input);
    }
    let text = serde_json::to_string_pretty(&fixture).unwrap();
    std::fs::write(FIXTURE, format!("{text}\n")).unwrap();
}
