//! Bookmark and collection payloads, against the fixture the clients share.
//!
//! What is pinned is the plaintext itself, byte for byte: the server sees only
//! the content type, so nothing but this fixture catches a client writing a key
//! the others do not read. The cases are the ones the clients disagreed about:
//! whether an address is normalised, whether a title is invented, which keys a
//! collection owns, what an unnamed collection is called, and what happens to a
//! payload from a newer schema major.
//!
//! Regenerate with:
//! `REGENERATE_BOOKMARK_FIXTURE=1 cargo test -p sealbook-core --test bookmarks -- --ignored regenerate`

use sealbook_core::*;
use serde::{Deserialize, Serialize};

const FIXTURE: &str = "../sealbook-protocol/fixtures/payloads/bookmarks.json";

/// Fixed so the written payloads are reproducible: core has no clock.
const NOW: &str = "2026-10-28T12:00:00Z";

const BOOKMARK: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ROOT: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const CHILD: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

#[derive(Serialize, Deserialize)]
struct Fixture {
    now: String,
    constants: Constants,
    writes: Vec<WriteCase>,
    parses: Vec<ParseCase>,
    collection_writes: Vec<CollectionWriteCase>,
    collection_parses: Vec<CollectionParseCase>,
    tones: Vec<ToneCase>,
    refusals: Vec<RefusalCase>,
}

#[derive(Serialize, Deserialize)]
struct Constants {
    bookmark_content_type: String,
    collection_content_type: String,
    bookmark_keys: Vec<String>,
    collection_keys: Vec<String>,
    default_collection_id: String,
    default_collection_name: String,
    untitled_bookmark_title: String,
    unreadable_bookmark_title: String,
    untitled_collection_name: String,
    max_tags: usize,
}

#[derive(Serialize, Deserialize)]
struct WriteCase {
    case: String,
    draft: CoreBookmarkDraft,
    payload: String,
}

#[derive(Serialize, Deserialize)]
struct ParseCase {
    case: String,
    id: String,
    raw: String,
    bookmark: CoreBookmark,
}

#[derive(Serialize, Deserialize)]
struct CollectionWriteCase {
    case: String,
    draft: CoreBookmarkCollectionDraft,
    payload: String,
}

#[derive(Serialize, Deserialize)]
struct CollectionParseCase {
    case: String,
    id: String,
    raw: String,
    collection: CoreBookmarkCollection,
}

/// A tree of collections and the colour each id resolves to.
#[derive(Serialize, Deserialize)]
struct ToneCase {
    case: String,
    collections: Vec<CoreBookmarkCollection>,
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

fn blank() -> CoreBookmarkDraft {
    CoreBookmarkDraft {
        collection_id: default_bookmark_collection_id(),
        ..Default::default()
    }
}

fn stored_with_everything() -> String {
    serde_json::json!({
        "@type": "Bookmark",
        "version": "1.0",
        "url": "https://example.com/a",
        "title": "Example",
        "notes": "worth keeping",
        "tags": ["rust", "web"],
        "collectionId": ROOT,
        "createdAt": "2026-01-01T00:00:00Z",
        "updatedAt": "2026-02-02T00:00:00Z",
        "somethingNewer": { "from": "a later build" }
    })
    .to_string()
}

fn write_cases() -> Vec<(String, CoreBookmarkDraft)> {
    let stored = stored_with_everything();
    let parsed = bookmark_parse(BOOKMARK, &stored);
    vec![
        (
            "a bookmark written from scratch".into(),
            CoreBookmarkDraft {
                url: "https://example.com/a".into(),
                title: "Example".into(),
                ..blank()
            },
        ),
        (
            "a bare host is given a scheme, and a title is trimmed".into(),
            CoreBookmarkDraft {
                url: "  example.com/a  ".into(),
                title: "  Example  ".into(),
                ..blank()
            },
        ),
        (
            "no title is written when none was given".into(),
            CoreBookmarkDraft {
                url: "https://example.com".into(),
                ..blank()
            },
        ),
        (
            "a blank collection resolves to the default".into(),
            CoreBookmarkDraft {
                url: "https://example.com".into(),
                collection_id: "   ".into(),
                ..blank()
            },
        ),
        (
            "notes and tags, the tags trimmed and de-duplicated".into(),
            CoreBookmarkDraft {
                url: "https://example.com".into(),
                notes: "  a note  ".into(),
                tags: vec!["Rust".into(), " rust ".into(), "".into(), "web".into()],
                ..blank()
            },
        ),
        (
            "an edit keeps a key a later build added".into(),
            CoreBookmarkDraft {
                title: "Renamed".into(),
                ..parsed.draft()
            },
        ),
        (
            "an edit that clears the notes and tags".into(),
            CoreBookmarkDraft {
                notes: String::new(),
                tags: Vec::new(),
                ..parsed.draft()
            },
        ),
        (
            "an untitled bookmark saved unchanged stays untitled".into(),
            bookmark_parse(
                BOOKMARK,
                r#"{"@type":"Bookmark","url":"https://example.com","createdAt":"2026-01-01T00:00:00Z"}"#,
            )
            .draft(),
        ),
        (
            "a newer minor keeps its version and its keys".into(),
            CoreBookmarkDraft {
                title: "t".into(),
                ..bookmark_parse(
                    BOOKMARK,
                    r#"{"@type":"Bookmark","version":"1.7","url":"https://example.com","createdAt":"2026-01-01T00:00:00Z","futureKey":[1]}"#,
                )
                .draft()
            },
        ),
    ]
}

fn parse_cases() -> Vec<(String, String, String)> {
    let case = |name: &str, raw: String| (name.to_string(), BOOKMARK.to_string(), raw);
    vec![
        case(
            "the richest payload any client writes",
            stored_with_everything(),
        ),
        case("an empty object", "{}".into()),
        case(
            "a title that is only space falls back to the address",
            r#"{"url":"https://example.com","title":"   "}"#.into(),
        ),
        case(
            "a payload that is not JSON at all",
            "never a bookmark".into(),
        ),
        case("a payload that is JSON but not an object", "[1,2]".into()),
        case(
            "tags that are not all strings",
            r#"{"url":"https://example.com","tags":["a",{"x":1},3,"A","b"]}"#.into(),
        ),
        case(
            "tags that are not an array",
            r#"{"url":"https://example.com","tags":{"a":1}}"#.into(),
        ),
        case(
            "notes of the wrong type",
            r#"{"url":"https://example.com","notes":42}"#.into(),
        ),
        case(
            "a payload from a newer schema major",
            r#"{"@type":"Bookmark","version":"2.0","url":"https://example.com"}"#.into(),
        ),
    ]
}

fn collection_write_cases() -> Vec<(String, CoreBookmarkCollectionDraft)> {
    let stored = serde_json::json!({
        "@type": "BookmarkCollection",
        "version": "1.0",
        "name": "Work",
        "parentId": ROOT,
        "color": "#112233",
        "sortKey": "from a later build"
    })
    .to_string();
    let parsed = bookmark_collection_parse(CHILD, &stored);
    vec![
        (
            "a collection created from scratch".into(),
            CoreBookmarkCollectionDraft {
                name: "Work".into(),
                ..Default::default()
            },
        ),
        (
            "a name with surrounding space, under another collection".into(),
            CoreBookmarkCollectionDraft {
                name: "  Work  ".into(),
                parent_id: Some(ROOT.into()),
                ..Default::default()
            },
        ),
        (
            "a coloured top-level collection".into(),
            CoreBookmarkCollectionDraft {
                name: "Work".into(),
                color: Some("#112233".into()),
                ..Default::default()
            },
        ),
        (
            "a rename keeps the parent, the colour and a later build's key".into(),
            CoreBookmarkCollectionDraft {
                name: "Renamed".into(),
                ..parsed.draft()
            },
        ),
        (
            "moving to the top level clears the parent".into(),
            CoreBookmarkCollectionDraft {
                parent_id: None,
                ..parsed.draft()
            },
        ),
    ]
}

fn collection_parse_cases() -> Vec<(String, String, String)> {
    vec![
        (
            "a named, nested, coloured collection".into(),
            CHILD.into(),
            format!(r##"{{"name":"  Work  ","parentId":"{ROOT}","color":"#112233"}}"##),
        ),
        (
            "the default collection, unnamed".into(),
            default_bookmark_collection_id(),
            "{}".into(),
        ),
        (
            "any other collection, unnamed".into(),
            CHILD.into(),
            "not json".into(),
        ),
        (
            "an empty parent and colour read as none".into(),
            CHILD.into(),
            r#"{"name":"Work","parentId":"  ","color":""}"#.into(),
        ),
    ]
}

fn tone_cases() -> Vec<(String, Vec<CoreBookmarkCollection>, String)> {
    let parse = |id: &str, raw: String| bookmark_collection_parse(id, &raw);
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
        case(
            "a collection whose parent is gone is its own root",
            "orphan",
        ),
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
            bookmark_write(&draft, NOW).expect("writes"),
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
        assert_eq!(bookmark_parse(&id, &raw), expected.bookmark, "{case}");
    }
}

#[test]
fn every_collection_payload_is_the_one_spelling_the_fixture_holds() {
    let fixture = fixture();
    assert_eq!(
        fixture.collection_writes.len(),
        collection_write_cases().len()
    );
    for (expected, (case, draft)) in fixture
        .collection_writes
        .iter()
        .zip(collection_write_cases())
    {
        assert_eq!(expected.case, case);
        assert_eq!(expected.draft, draft, "{case}: the draft drifted");
        assert_eq!(
            bookmark_collection_write(&draft).expect("writes"),
            expected.payload,
            "{case}"
        );
    }
}

#[test]
fn every_collection_reads_back_as_the_record_the_fixture_holds() {
    let fixture = fixture();
    assert_eq!(
        fixture.collection_parses.len(),
        collection_parse_cases().len()
    );
    for (expected, (case, id, raw)) in fixture
        .collection_parses
        .iter()
        .zip(collection_parse_cases())
    {
        assert_eq!(expected.case, case);
        assert_eq!(
            bookmark_collection_parse(&id, &raw),
            expected.collection,
            "{case}"
        );
    }
}

#[test]
fn every_collection_resolves_to_the_colour_the_fixture_holds() {
    let fixture = fixture();
    assert_eq!(fixture.tones.len(), tone_cases().len());
    for (expected, (case, collections, id)) in fixture.tones.iter().zip(tone_cases()) {
        assert_eq!(expected.case, case);
        assert_eq!(
            bookmark_collection_tone(&collections, &id),
            expected.tone,
            "{case}"
        );
    }
}

#[test]
fn the_fixture_states_the_constants_the_hosts_mirror() {
    let constants = fixture().constants;
    assert_eq!(constants.bookmark_content_type, BOOKMARK_CONTENT_TYPE);
    assert_eq!(
        constants.collection_content_type,
        BOOKMARK_COLLECTION_CONTENT_TYPE
    );
    assert_eq!(constants.bookmark_keys, BOOKMARK_KEYS);
    assert_eq!(constants.collection_keys, BOOKMARK_COLLECTION_KEYS);
    assert_eq!(
        constants.default_collection_id,
        default_bookmark_collection_id()
    );
    assert_eq!(
        constants.default_collection_name,
        DEFAULT_BOOKMARK_COLLECTION_NAME
    );
    assert_eq!(constants.untitled_bookmark_title, UNTITLED_BOOKMARK_TITLE);
    assert_eq!(
        constants.unreadable_bookmark_title,
        UNREADABLE_BOOKMARK_TITLE
    );
    assert_eq!(constants.untitled_collection_name, UNTITLED_COLLECTION_NAME);
    assert_eq!(constants.max_tags, MAX_BOOKMARK_TAGS);
}

#[test]
fn a_payload_from_a_newer_schema_major_is_read_but_never_written_over() {
    let refusals = fixture().refusals;
    let future = r#"{"@type":"Bookmark","version":"2.0","url":"https://example.com"}"#;

    let bookmark = bookmark_parse(BOOKMARK, future);
    assert!(!bookmark.readable);
    let refused = bookmark_write(
        &CoreBookmarkDraft {
            raw: Some(future.into()),
            ..blank()
        },
        NOW,
    )
    .expect_err("refuses");
    assert_eq!(error_name(&refused), refusals[0].error);

    let collection = r#"{"@type":"BookmarkCollection","version":"3.1","name":"future"}"#;
    assert!(!bookmark_collection_parse(CHILD, collection).readable);
    let refused = bookmark_collection_write(&CoreBookmarkCollectionDraft {
        name: "edited".into(),
        raw: Some(collection.into()),
        ..Default::default()
    })
    .expect_err("refuses");
    assert_eq!(error_name(&refused), refusals[1].error);
}

/// The property the byte comparisons cannot state: every readable payload,
/// written from its own draft, reads back as the same bookmark.
#[test]
fn a_bookmark_written_from_what_was_read_reads_back_the_same() {
    for (case, id, raw) in parse_cases() {
        let bookmark = bookmark_parse(&id, &raw);
        if !bookmark.readable || bookmark.title == UNREADABLE_BOOKMARK_TITLE {
            continue;
        }
        let rewritten = bookmark_write(&bookmark.draft(), NOW).expect("writes");
        let again = bookmark_parse(&id, &rewritten);
        assert_eq!(again.url, normalize_url(&bookmark.url), "{case}");
        assert_eq!(again.title, bookmark.title, "{case}");
        assert_eq!(again.derived_title, bookmark.derived_title, "{case}");
        assert_eq!(again.notes, bookmark.notes, "{case}");
        assert_eq!(again.tags, bookmark.tags, "{case}");
        assert_eq!(again.collection_id, bookmark.collection_id, "{case}");
    }
}

#[test]
#[ignore = "writes the shared fixture"]
fn regenerate() {
    if std::env::var("REGENERATE_BOOKMARK_FIXTURE").is_err() {
        return;
    }
    let fixture = Fixture {
        now: NOW.into(),
        constants: Constants {
            bookmark_content_type: BOOKMARK_CONTENT_TYPE.into(),
            collection_content_type: BOOKMARK_COLLECTION_CONTENT_TYPE.into(),
            bookmark_keys: BOOKMARK_KEYS.iter().map(|key| key.to_string()).collect(),
            collection_keys: BOOKMARK_COLLECTION_KEYS
                .iter()
                .map(|key| key.to_string())
                .collect(),
            default_collection_id: default_bookmark_collection_id(),
            default_collection_name: DEFAULT_BOOKMARK_COLLECTION_NAME.into(),
            untitled_bookmark_title: UNTITLED_BOOKMARK_TITLE.into(),
            unreadable_bookmark_title: UNREADABLE_BOOKMARK_TITLE.into(),
            untitled_collection_name: UNTITLED_COLLECTION_NAME.into(),
            max_tags: MAX_BOOKMARK_TAGS,
        },
        writes: write_cases()
            .into_iter()
            .map(|(case, draft)| WriteCase {
                case,
                payload: bookmark_write(&draft, NOW).expect("writes"),
                draft,
            })
            .collect(),
        parses: parse_cases()
            .into_iter()
            .map(|(case, id, raw)| ParseCase {
                case,
                bookmark: bookmark_parse(&id, &raw),
                id,
                raw,
            })
            .collect(),
        collection_writes: collection_write_cases()
            .into_iter()
            .map(|(case, draft)| CollectionWriteCase {
                case,
                payload: bookmark_collection_write(&draft).expect("writes"),
                draft,
            })
            .collect(),
        collection_parses: collection_parse_cases()
            .into_iter()
            .map(|(case, id, raw)| CollectionParseCase {
                case,
                collection: bookmark_collection_parse(&id, &raw),
                id,
                raw,
            })
            .collect(),
        tones: tone_cases()
            .into_iter()
            .map(|(case, collections, id)| ToneCase {
                case,
                tone: bookmark_collection_tone(&collections, &id),
                collections,
                id,
            })
            .collect(),
        refusals: vec![
            RefusalCase {
                case: "editing a bookmark from a newer schema major".into(),
                error: "PayloadSchema".into(),
            },
            RefusalCase {
                case: "renaming a collection from a newer schema major".into(),
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
