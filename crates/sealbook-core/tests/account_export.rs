//! The account export document, against the fixture every client's writer and
//! reader is checked with.
//!
//! The write cases are the ones the three writers could disagree on: a scalar
//! payload, a `null` payload, a payload that is not JSON, an uppercase id, an
//! unsorted vault and a short backup. The read cases are the files a reader
//! has to take or refuse the same way.
//!
//! Regenerate with:
//! `REGENERATE_ACCOUNT_EXPORT_FIXTURE=1 cargo test -p sealbook-core --test account_export -- --ignored regenerate`

use sealbook_core::*;
use serde::{Deserialize, Serialize};

const FIXTURE: &str = "../sealbook-protocol/fixtures/payloads/account_export.json";

const NOTE: &str = "application/sealbook.note+json";
const CONTACT: &str = "application/vnd.sealbook.contact+json";
const A: &str = "0b9d4a52-1d6f-4c33-9a3e-5f8f3b1a7c01";
const B: &str = "7c1e6f20-84aa-4d6d-b0f4-2a9c5e3d8b02";
const C: &str = "e3a0c7b4-5f21-4a8e-8d19-6b7f0c2e4d03";
const D: &str = "01f2a3b4-c5d6-4e7f-8091-a2b3c4d5e6f7";

#[derive(Serialize, Deserialize)]
struct Fixture {
    writes: Vec<Write>,
    reads: Vec<Read>,
    filenames: Vec<Filename>,
}

#[derive(Serialize, Deserialize)]
struct Write {
    name: String,
    account: CoreExportAccount,
    objects: Vec<CoreExportObject>,
    unreadable: u32,
    exported_at: String,
    document: String,
}

#[derive(Serialize, Deserialize)]
struct Read {
    name: String,
    document: String,
    imported: Option<CoreAccountImport>,
    error: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Filename {
    username: String,
    day: String,
    filename: String,
}

fn account() -> CoreExportAccount {
    CoreExportAccount {
        server: "https://sealbook.example".into(),
        username: "Ada".into(),
        account_id: "11111111-1111-4111-8111-111111111111".into(),
        collection_id: "22222222-2222-4222-8222-222222222222".into(),
        device_id: "33333333-3333-4333-8333-333333333333".into(),
    }
}

fn object(id: &str, content_type: &str, payload: &str) -> CoreExportObject {
    CoreExportObject {
        id: id.into(),
        content_type: content_type.into(),
        payload: payload.into(),
    }
}

fn write(name: &str, objects: Vec<CoreExportObject>, unreadable: u32) -> Write {
    let exported_at = "2026-10-28T12:00:00Z";
    Write {
        name: name.into(),
        document: account_export_write(&account(), &objects, unreadable, exported_at),
        account: account(),
        objects,
        unreadable,
        exported_at: exported_at.into(),
    }
}

fn writes() -> Vec<Write> {
    vec![
        write("an empty vault", vec![], 0),
        write(
            "objects are sorted by content type then id",
            vec![
                object(C, NOTE, r#"{"title":"c"}"#),
                object(B, NOTE, r#"{"title":"b"}"#),
                object(A, NOTE, r#"{"title":"a"}"#),
                object(D, CONTACT, r#"{"name":"Bea"}"#),
            ],
            0,
        ),
        write(
            "a scalar payload is a payload",
            vec![
                object(A, "a", "42"),
                object(B, "a", "\"word\""),
                object(C, "a", "[1,2]"),
            ],
            0,
        ),
        write("a null payload is text", vec![object(A, "a", "null")], 0),
        write(
            "a payload that is not JSON is text, verbatim",
            vec![object(A, "a", "plain  text\nwith a break")],
            0,
        ),
        write(
            "an uppercase id is written lowercase",
            vec![object(&A.to_uppercase(), "a", "{}")],
            0,
        ),
        write(
            "unknown fields and large integers survive",
            vec![object(
                A,
                "a",
                r#"{"future":{"z":1,"a":[true,null]},"big":9007199254740993}"#,
            )],
            0,
        ),
        write(
            "a short backup says how short",
            vec![object(A, "a", "{}")],
            3,
        ),
    ]
}

fn read(name: &str, document: &str) -> Read {
    let (imported, error) = match account_export_parse(document) {
        Ok(imported) => (Some(imported), None),
        Err(CoreError::Malformed { detail }) => (None, Some(detail)),
        Err(other) => panic!("{name}: {other}"),
    };
    Read {
        name: name.into(),
        document: document.into(),
        imported,
        error,
    }
}

fn reads() -> Vec<Read> {
    let envelope = |version: &str, objects: &str| {
        format!(r#"{{"@type":"SealbookAccountExport","version":"{version}","objects":{objects}}}"#)
    };
    let mut cases = vec![
        read("not JSON", "}{"),
        read("JSON that is not an object", "\"a string\""),
        read("another document type", r#"{"@type":"SomethingElse"}"#),
        read("no version", r#"{"@type":"SealbookAccountExport"}"#),
        read("a newer major", &envelope("2.0", "[]")),
        read("a newer minor is read", &envelope("1.7", "[]")),
        read(
            "no objects",
            r#"{"@type":"SealbookAccountExport","version":"1.0"}"#,
        ),
        read("an object that is not an object", &envelope("1.0", "[7]")),
        read(
            "an id that is not a UUID",
            &envelope("1.0", r#"[{"id":"nope","contentType":"a","payload":{}}]"#),
        ),
        read(
            "an unhyphenated id",
            &envelope(
                "1.0",
                r#"[{"id":"0b9d4a521d6f4c339a3e5f8f3b1a7c01","contentType":"a","payload":{}}]"#,
            ),
        ),
        read(
            "an uppercase id is read lowercase",
            &envelope(
                "1.0",
                &format!(
                    r#"[{{"id":"{}","contentType":"a","payload":{{}}}}]"#,
                    A.to_uppercase()
                ),
            ),
        ),
        read(
            "a repeated id",
            &envelope(
                "1.0",
                &format!(
                    r#"[{{"id":"{A}","contentType":"a","payload":{{}}}},{{"id":"{A}","contentType":"a","payload":{{}}}}]"#
                ),
            ),
        ),
        read(
            "no contentType",
            &envelope("1.0", &format!(r#"[{{"id":"{A}","payload":{{}}}}]"#)),
        ),
        read(
            "neither payload nor text",
            &envelope("1.0", &format!(r#"[{{"id":"{A}","contentType":"a"}}]"#)),
        ),
        read(
            "a null payload falls back to text",
            &envelope(
                "1.0",
                &format!(r#"[{{"id":"{A}","contentType":"a","payload":null,"text":"null"}}]"#),
            ),
        ),
        read(
            "a payload and text together reads the payload",
            &envelope(
                "1.0",
                &format!(r#"[{{"id":"{A}","contentType":"a","payload":{{"k":1}},"text":"x"}}]"#),
            ),
        ),
        read(
            "the account and the unreadable count",
            &format!(
                r#"{{"@type":"SealbookAccountExport","version":"1.0","account":{{"username":"Ada","server":"https://sealbook.example"}},"unreadable":4,"objects":[{{"id":"{B}","contentType":"a","text":"raw"}}]}}"#
            ),
        ),
    ];
    for write in writes() {
        cases.push(read(
            &format!("round trip: {}", write.name),
            &write.document,
        ));
    }
    cases
}

fn filenames() -> Vec<Filename> {
    [
        "Ada",
        "Ada Lovelace",
        "  --Ada__99--  ",
        "名前",
        "",
        "A.B@c",
    ]
    .into_iter()
    .map(|username| Filename {
        username: username.into(),
        day: "2026-10-28".into(),
        filename: account_export_filename(username, "2026-10-28"),
    })
    .collect()
}

#[test]
#[ignore]
fn regenerate() {
    if std::env::var("REGENERATE_ACCOUNT_EXPORT_FIXTURE").is_err() {
        return;
    }
    let fixture = Fixture {
        writes: writes(),
        reads: reads(),
        filenames: filenames(),
    };
    let mut text = serde_json::to_string_pretty(&fixture).unwrap();
    text.push('\n');
    std::fs::write(FIXTURE, text).unwrap();
}

#[test]
fn the_fixture_is_what_core_produces() {
    let stored: Fixture = serde_json::from_str(&std::fs::read_to_string(FIXTURE).unwrap()).unwrap();
    for expected in &stored.writes {
        let document = account_export_write(
            &expected.account,
            &expected.objects,
            expected.unreadable,
            &expected.exported_at,
        );
        assert_eq!(document, expected.document, "{}", expected.name);
    }
    for expected in &stored.reads {
        let actual = read(&expected.name, &expected.document);
        assert_eq!(actual.imported, expected.imported, "{}", expected.name);
        assert_eq!(actual.error, expected.error, "{}", expected.name);
    }
    for expected in &stored.filenames {
        assert_eq!(
            account_export_filename(&expected.username, &expected.day),
            expected.filename
        );
    }
}

#[test]
fn the_fixture_pins_what_the_cases_mean() {
    let stored: Fixture = serde_json::from_str(&std::fs::read_to_string(FIXTURE).unwrap()).unwrap();
    let write = |name: &str| {
        stored
            .writes
            .iter()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("{name}"))
    };
    let read = |name: &str| {
        stored
            .reads
            .iter()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("{name}"))
    };

    let sorted: serde_json::Value =
        serde_json::from_str(&write("objects are sorted by content type then id").document)
            .unwrap();
    let order: Vec<(&str, &str)> = sorted["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| {
            (
                o["contentType"].as_str().unwrap(),
                o["id"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(order, [(NOTE, A), (NOTE, B), (NOTE, C), (CONTACT, D)]);

    let scalars: serde_json::Value =
        serde_json::from_str(&write("a scalar payload is a payload").document).unwrap();
    assert!(scalars["objects"]
        .as_array()
        .unwrap()
        .iter()
        .all(|o| o.get("payload").is_some() && o.get("text").is_none()));

    let null: serde_json::Value =
        serde_json::from_str(&write("a null payload is text").document).unwrap();
    assert_eq!(null["objects"][0]["text"], "null");
    assert!(null["objects"][0].get("payload").is_none());

    let short: serde_json::Value =
        serde_json::from_str(&write("a short backup says how short").document).unwrap();
    assert_eq!(short["unreadable"], 3);
    let whole: serde_json::Value = serde_json::from_str(&write("an empty vault").document).unwrap();
    assert!(whole.get("unreadable").is_none());

    assert_eq!(
        read("the account and the unreadable count")
            .imported
            .as_ref()
            .map(|i| (i.source.as_str(), i.unreadable)),
        Some(("Ada at https://sealbook.example", 4))
    );
    assert_eq!(
        read("an uppercase id is read lowercase")
            .imported
            .as_ref()
            .unwrap()
            .objects[0]
            .id,
        A
    );
    assert!(read("a newer minor is read").imported.is_some());
    assert!(read("a newer major").error.is_some());
    assert!(read("an unhyphenated id").error.is_some());
    assert!(read("a repeated id").error.is_some());
    for case in stored
        .reads
        .iter()
        .filter(|c| c.name.starts_with("round trip: "))
    {
        let source = stored
            .writes
            .iter()
            .find(|w| case.name == format!("round trip: {}", w.name))
            .unwrap();
        let imported = case.imported.as_ref().expect(&case.name);
        let mut expected: Vec<(String, String)> = source
            .objects
            .iter()
            .map(|o| (o.id.to_lowercase(), o.content_type.clone()))
            .collect();
        expected.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        let actual: Vec<(String, String)> = imported
            .objects
            .iter()
            .map(|o| (o.id.clone(), o.content_type.clone()))
            .collect();
        assert_eq!(actual, expected, "{}", case.name);
        assert_eq!(imported.unreadable, source.unreadable);
    }
}
