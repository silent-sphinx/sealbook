//! List order, against the fixture every client's sorts are checked with.

use sealbook_core::{order_by_name, order_by_recency, order_containers, CoreOrderItem};
use serde::Deserialize;

const FIXTURE: &str = "../sealbook-protocol/fixtures/payloads/ordering.json";

#[derive(Deserialize)]
struct Fixture {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    rule: String,
    #[serde(default)]
    default_id: String,
    items: Vec<CoreOrderItem>,
    order: Vec<String>,
}

#[test]
fn order_matches_the_fixture() {
    let fixture: Fixture =
        serde_json::from_str(&std::fs::read_to_string(FIXTURE).unwrap()).unwrap();
    for case in fixture.cases {
        let got = match case.rule.as_str() {
            "name" => order_by_name(&case.items),
            "containers" => order_containers(&case.default_id, &case.items),
            "recency" => order_by_recency(&case.items, false),
            "recency_pinned" => order_by_recency(&case.items, true),
            other => panic!("{}: unknown rule {other}", case.name),
        };
        assert_eq!(got, case.order, "{}", case.name);
    }
}
