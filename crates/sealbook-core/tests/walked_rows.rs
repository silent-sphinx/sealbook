//! An incremental read's rows, checked against the signed manifest entries for
//! them, against the fixture the clients share.
//!
//! The cases are the web client's `walkedRows.test.ts`, with the exact answer
//! core gives for each. A host checks itself by calling its binding on the rows
//! and entries and comparing.
//!
//! Regenerate with:
//! `REGENERATE_WALKED_ROWS_FIXTURE=1 cargo test -p sealbook-core --test walked_rows -- --ignored regenerate`

use sealbook_core::{
    check_rows_against_entries, manifest_entry_for, CoreError, CoreManifestEntry, CoreSealedRow,
    RowsCheck,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../sealbook-protocol/fixtures/changes/walked-rows.json"
);

const A: u128 = 0xa;
const B: u128 = 0xb;
const NONCE: &str = "AAAAAAAAAAAAAAAA";
const CIPHERTEXT: &str = "Y2lwaGVydGV4dA";
const OLDER_CIPHERTEXT: &str = "b2xkZXIgdmVyc2lvbg";

#[derive(Serialize, Deserialize)]
struct Fixture {
    cases: Vec<Case>,
}

#[derive(Serialize, Deserialize)]
struct Case {
    case: String,
    rows: Vec<CoreSealedRow>,
    entries: Vec<CoreManifestEntry>,
    answer: Answer,
}

/// What the check says: a result, or a manifest error that must never be retried away.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Answer {
    Verified,
    Moved,
    ManifestError,
}

fn row(id: u128, revision: u64, tombstone: bool, ciphertext: &str) -> CoreSealedRow {
    CoreSealedRow {
        id: Uuid::from_u128(id),
        revision,
        tombstone,
        nonce: NONCE.into(),
        ciphertext: ciphertext.into(),
        padded_size: 16,
    }
}

fn entry_of(row: &CoreSealedRow) -> CoreManifestEntry {
    manifest_entry_for(
        row.id,
        row.revision,
        row.tombstone,
        &row.nonce,
        &row.ciphertext,
    )
    .unwrap()
}

fn inputs() -> Vec<(String, Vec<CoreSealedRow>, Vec<CoreManifestEntry>)> {
    let live = row(A, 5, false, CIPHERTEXT);
    let deleted = row(B, 6, true, CIPHERTEXT);
    let held = |row: &CoreSealedRow| entry_of(row);
    vec![
        (
            "rows that are what the manifest commits to".into(),
            vec![live.clone(), deleted.clone()],
            vec![held(&live), held(&deleted)],
        ),
        ("no rows need nothing".into(), vec![], vec![held(&live)]),
        (
            "a forged tombstone for an object the manifest holds live".into(),
            vec![row(A, 6, true, CIPHERTEXT)],
            vec![held(&row(A, 6, false, CIPHERTEXT))],
        ),
        (
            "an older ciphertext relabelled with the current revision".into(),
            vec![row(A, 5, false, OLDER_CIPHERTEXT)],
            vec![held(&live)],
        ),
        (
            "an object the manifest does not list".into(),
            vec![row(0xc, 5, false, CIPHERTEXT)],
            vec![held(&live)],
        ),
        (
            "an object newer than the manifest knows".into(),
            vec![row(A, 9, false, CIPHERTEXT)],
            vec![held(&row(A, 5, false, CIPHERTEXT))],
        ),
        (
            "a manifest already past the row asks for another read".into(),
            vec![live.clone()],
            vec![held(&row(A, 8, false, CIPHERTEXT))],
        ),
        (
            "a moved row does not excuse a forged one beside it".into(),
            vec![live.clone(), row(B, 6, true, OLDER_CIPHERTEXT)],
            vec![held(&row(A, 8, false, CIPHERTEXT)), held(&deleted)],
        ),
    ]
}

fn answer(rows: &[CoreSealedRow], entries: &[CoreManifestEntry]) -> Answer {
    match check_rows_against_entries(rows, entries) {
        Ok(RowsCheck::Verified) => Answer::Verified,
        Ok(RowsCheck::Moved) => Answer::Moved,
        Err(CoreError::Manifest { .. }) => Answer::ManifestError,
        Err(other) => panic!("unexpected error: {other:?}"),
    }
}

fn build() -> Fixture {
    Fixture {
        cases: inputs()
            .into_iter()
            .map(|(case, rows, entries)| {
                let answer = answer(&rows, &entries);
                Case {
                    case,
                    rows,
                    entries,
                    answer,
                }
            })
            .collect(),
    }
}

fn fixture() -> Fixture {
    let text = std::fs::read_to_string(FIXTURE).expect("fixture");
    serde_json::from_str(&text).expect("fixture parses")
}

#[test]
fn every_check_answers_what_the_fixture_holds() {
    for case in fixture().cases {
        assert_eq!(
            answer(&case.rows, &case.entries),
            case.answer,
            "{}",
            case.case
        );
    }
}

/// Spelled out rather than read from the fixture, so a wrong fixture cannot make a
/// wrong rule pass.
#[test]
fn the_answers_hold_independent_of_the_fixture() {
    let expected = [
        Answer::Verified,
        Answer::Verified,
        Answer::ManifestError,
        Answer::ManifestError,
        Answer::ManifestError,
        Answer::ManifestError,
        Answer::Moved,
        Answer::ManifestError,
    ];
    let cases = inputs();
    assert_eq!(cases.len(), expected.len());
    for ((case, rows, entries), expected) in cases.iter().zip(expected) {
        assert_eq!(answer(rows, entries), expected, "{case}");
    }
}

#[test]
fn a_row_that_is_not_base64_is_not_a_pass() {
    let mut bad = row(A, 5, false, CIPHERTEXT);
    bad.ciphertext = "not base64!".into();
    let entries = vec![entry_of(&row(A, 5, false, CIPHERTEXT))];
    assert!(check_rows_against_entries(&[bad], &entries).is_err());
}

#[test]
fn the_fixture_is_what_core_gives_today() {
    assert_eq!(
        serde_json::to_value(build()).unwrap(),
        serde_json::to_value(fixture()).unwrap(),
        "regenerate the walked rows fixture"
    );
}

#[test]
#[ignore]
fn regenerate() {
    if std::env::var("REGENERATE_WALKED_ROWS_FIXTURE").is_err() {
        return;
    }
    std::fs::write(
        FIXTURE,
        format!("{}\n", serde_json::to_string_pretty(&build()).unwrap()),
    )
    .unwrap();
}
