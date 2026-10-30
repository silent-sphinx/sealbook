//! User-facing sentences, against the fixture every client's rendering is checked with.

use sealbook_core::{error_message, CoreError};
use serde::Deserialize;

const FIXTURE: &str = "../sealbook-protocol/fixtures/payloads/messages.json";

#[derive(Deserialize)]
struct Fixture {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    error: CoreError,
    message: Option<String>,
}

#[test]
fn messages_match_the_fixture() {
    let fixture: Fixture =
        serde_json::from_str(&std::fs::read_to_string(FIXTURE).unwrap()).unwrap();
    for case in fixture.cases {
        assert_eq!(error_message(&case.error), case.message, "{}", case.name);
    }
}
