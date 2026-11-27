//! The note body grammar against the corpus shared with sealbook-web.

use sealbook_core::markdown::{attachment_ids_in, parse, safe_href, serialize};
use serde_json::Value;

const CORPUS: &str = "../sealbook-protocol/fixtures/notes/markdown.json";
const ROUNDTRIP: &str = "../sealbook-protocol/fixtures/notes/markdown-roundtrip.json";

fn cases(path: &str) -> Vec<Value> {
    let text = std::fs::read_to_string(path).unwrap();
    let mut fixture: Value = serde_json::from_str(&text).unwrap();
    serde_json::from_value(fixture["cases"].take()).unwrap()
}

/// The corpus records the web's `line` indexes as null; this tree has none.
fn without_lines(mut value: Value) -> Value {
    match &mut value {
        Value::Object(map) => {
            map.remove("line");
            for child in map.values_mut() {
                *child = without_lines(child.take());
            }
        }
        Value::Array(items) => {
            for child in items {
                *child = without_lines(child.take());
            }
        }
        _ => {}
    }
    value
}

#[test]
fn every_corpus_case_parses_to_the_recorded_tree() {
    let cases = cases(CORPUS);
    assert!(cases.len() > 80);
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|case| {
            let input = case["input"].as_str().unwrap();
            let expected = without_lines(case["blocks"].clone());
            let actual = serde_json::to_value(parse(input)).unwrap();
            (actual != expected).then(|| format!("{input:?}\n  want {expected}\n  got  {actual}"))
        })
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn every_body_is_written_back_as_the_web_writes_it() {
    let cases = cases(ROUNDTRIP);
    assert!(cases.len() > 100);
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|case| {
            let input = case["input"].as_str().unwrap();
            let expected = case["canonical"].as_str().unwrap();
            let actual = serialize(&parse(input));
            (actual != expected)
                .then(|| format!("{input:?}\n  want {expected:?}\n  got  {actual:?}"))
        })
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn only_web_and_mail_targets_become_links() {
    assert_eq!(
        safe_href("https://example.com").as_deref(),
        Some("https://example.com/")
    );
    assert!(safe_href("mailto:a@example.com").is_some());
    for hostile in [
        "javascript:alert(1)",
        "JAVASCRIPT:alert(1)",
        "java\tscript:alert(1)",
        "data:text/html,x",
        "vbscript:x",
        "file:///etc/passwd",
        "blob:https://example.com/x",
        "",
    ] {
        assert_eq!(safe_href(hostile), None, "{hostile:?}");
    }
}

#[test]
fn photo_ids_are_read_from_the_tree_and_not_from_code() {
    let body = "![a](attachment:one)\n\n- item ![b](attachment:two)";
    assert_eq!(attachment_ids_in(body), ["one", "two"]);
    let quoted = "```\n![a](attachment:one)\n```\n\nuse `![a](attachment:two)` here";
    assert!(attachment_ids_in(quoted).is_empty());
}

#[test]
fn hostile_bodies_finish() {
    for body in [
        "*".repeat(100_000),
        "_a".repeat(100_000),
        "`".repeat(100_000),
        "~~a".repeat(50_000),
        ">".repeat(100_000),
        "**".repeat(5_000) + &"a**".repeat(5_000),
        (0..2_000)
            .map(|i| format!("{}- x\n", " ".repeat(i)))
            .collect(),
    ] {
        serialize(&parse(&body));
    }
}
