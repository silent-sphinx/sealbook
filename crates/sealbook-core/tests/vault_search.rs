//! Unified search, against the fixture every client's search is checked with.
//!
//! Regenerate with:
//! `REGENERATE_VAULT_SEARCH_FIXTURE=1 cargo test -p sealbook-core --test vault_search -- --ignored regenerate`

use sealbook_core::*;
use serde::{Deserialize, Serialize};

const FIXTURE: &str = "../sealbook-protocol/fixtures/payloads/vault-search.json";

#[derive(Serialize, Deserialize)]
struct Fixture {
    about: String,
    contacts: Vec<CoreContactSource>,
    sources: Vec<CoreSearchSource>,
    containers: Vec<CoreSearchContainer>,
    queries: Vec<Query>,
}

#[derive(Serialize, Deserialize)]
struct Query {
    case: String,
    query: String,
    per_kind: u32,
    #[serde(default)]
    hits: Vec<CoreSearchHit>,
}

fn load() -> Fixture {
    serde_json::from_str(&std::fs::read_to_string(FIXTURE).unwrap()).unwrap()
}

fn index(fixture: &Fixture) -> VaultIndex {
    VaultIndex::new(
        &fixture.contacts,
        &[],
        &fixture.sources,
        &fixture.containers,
    )
}

#[test]
fn search_matches_the_fixture() {
    let fixture = load();
    let index = index(&fixture);
    for query in &fixture.queries {
        assert_eq!(
            index.search(&query.query, query.per_kind),
            query.hits,
            "{}",
            query.case
        );
    }
}

#[test]
#[ignore]
fn regenerate() {
    if std::env::var("REGENERATE_VAULT_SEARCH_FIXTURE").is_err() {
        return;
    }
    let mut fixture = load();
    let index = index(&fixture);
    for query in &mut fixture.queries {
        query.hits = index.search(&query.query, query.per_kind);
    }
    let text = serde_json::to_string_pretty(&fixture).unwrap();
    std::fs::write(FIXTURE, format!("{text}\n")).unwrap();
}
