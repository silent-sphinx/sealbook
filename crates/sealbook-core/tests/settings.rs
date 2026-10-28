//! Account settings payloads, against the fixture the clients share.
//!
//! What is pinned is the plaintext itself, byte for byte. The cases are the
//! ones the two hosts disagreed on: a flag from a newer build, a payload with
//! every feature off, and a toggle that must not drop what it does not know.
//!
//! Regenerate with:
//! `REGENERATE_SETTINGS_FIXTURE=1 cargo test -p sealbook-core --test settings -- --ignored regenerate`

use sealbook_core::*;
use serde::{Deserialize, Serialize};

const FIXTURE: &str = "../sealbook-protocol/fixtures/payloads/settings.json";

#[derive(Serialize, Deserialize)]
struct Fixture {
    constants: Constants,
    writes: Vec<WriteCase>,
    parses: Vec<ParseCase>,
    toggles: Vec<ToggleCase>,
    refusals: Vec<RefusalCase>,
}

#[derive(Serialize, Deserialize)]
struct Constants {
    content_type: String,
    object_id: String,
    legacy_object_id: String,
    keys: Vec<String>,
    features: Vec<String>,
    contact_modes: Vec<String>,
    default_contact_mode: String,
    accents: Vec<String>,
    default_accent: String,
}

#[derive(Serialize, Deserialize)]
struct WriteCase {
    case: String,
    draft: CoreAccountSettingsDraft,
    payload: String,
}

#[derive(Serialize, Deserialize)]
struct ParseCase {
    case: String,
    raw: String,
    settings: CoreAccountSettings,
}

#[derive(Serialize, Deserialize)]
struct ToggleCase {
    case: String,
    raw: String,
    feature: String,
    enabled: bool,
    settings: CoreAccountSettings,
    can_disable: bool,
}

#[derive(Serialize, Deserialize)]
struct RefusalCase {
    case: String,
    error: String,
}

fn flag(key: &str, enabled: bool) -> CoreFeatureFlag {
    CoreFeatureFlag {
        key: key.into(),
        enabled,
    }
}

fn draft(raw: Option<&str>) -> CoreAccountSettingsDraft {
    CoreAccountSettingsDraft {
        features: FEATURES.iter().map(|key| flag(key, true)).collect(),
        unknown_features: Vec::new(),
        contact_mode: "basic".into(),
        accent: "blue".into(),
        raw: raw.map(ToOwned::to_owned),
    }
}

fn write_cases() -> Vec<(String, CoreAccountSettingsDraft)> {
    let mut cases = Vec::new();
    let mut add =
        |name: &str, draft: CoreAccountSettingsDraft| cases.push((name.to_string(), draft));

    add("defaults", draft(None));

    let mut mixed = draft(None);
    mixed.features = vec![flag("notes", false), flag("tasks", false)];
    mixed.contact_mode = "detailed".into();
    mixed.accent = "rose".into();
    add("some features off, detailed contacts, rose", mixed);

    let mut empty = draft(None);
    empty.features = FEATURES.iter().map(|key| flag(key, false)).collect();
    add("every feature off is repaired to the first", empty);

    let mut strange = draft(None);
    strange.contact_mode = "Detailed".into();
    strange.accent = "teal".into();
    add("an unknown mode and accent are the defaults", strange);

    let mut sparse = draft(None);
    sparse.features = vec![flag("calendar", false)];
    add("a feature the draft does not name is on", sparse);

    let mut unknown = draft(Some(
        r#"{"@type":"AccountSettings","version":"1.0","features":{"contacts":true,"journal":false,"labs":"beta","depth":3},"contactMode":"basic","accent":"blue","theme":"dark"}"#,
    ));
    unknown.unknown_features = vec![flag("journal", false)];
    unknown.accent = "green".into();
    add(
        "flags of any type from a newer build survive, with other keys",
        unknown,
    );

    let mut foreign = draft(None);
    foreign.unknown_features = vec![flag("contacts", false), flag("journal", true)];
    add("an unknown flag cannot overwrite a known one", foreign);

    let mut hosted = draft(None);
    hosted.features = vec![flag("contacts", true)];
    hosted.unknown_features = vec![flag("tasks", false), flag("journal", true)];
    add(
        "a known feature the host has no screen for rides in the unknown list",
        hosted,
    );

    let mut fallback = draft(Some("not json"));
    fallback.accent = "amber".into();
    add("an unreadable stored payload is replaced", fallback);

    cases
}

fn parse_cases() -> Vec<(String, String)> {
    [
        ("empty", ""),
        ("not json", "not json"),
        ("an array", "[]"),
        ("an empty object", "{}"),
        (
            "every flag present",
            r#"{"features":{"contacts":false,"calendar":true,"notes":false,"bookmarks":true,"tasks":true},"contactMode":"detailed","accent":"purple"}"#,
        ),
        (
            "a flag that is not a boolean is on",
            r#"{"features":{"contacts":"no","calendar":0,"notes":null,"bookmarks":false}}"#,
        ),
        (
            "every feature off reads as the first on",
            r#"{"features":{"contacts":false,"calendar":false,"notes":false,"bookmarks":false,"tasks":false}}"#,
        ),
        (
            "unknown boolean flags are kept, others are not read",
            r#"{"features":{"zeta":true,"alpha":false,"labs":"beta","depth":3}}"#,
        ),
        (
            "features that is not an object",
            r#"{"features":["contacts"],"accent":"cyan"}"#,
        ),
        (
            "mode and accent that are not strings",
            r#"{"contactMode":1,"accent":["green"]}"#,
        ),
        ("an accent that is not known", r#"{"accent":"teal"}"#),
        (
            "a mode with the wrong case",
            r#"{"contactMode":"Detailed"}"#,
        ),
        (
            "a newer schema major",
            r#"{"version":"9.0","features":{"notes":false},"accent":"rose"}"#,
        ),
    ]
    .into_iter()
    .map(|(case, raw)| (case.to_string(), raw.to_string()))
    .collect()
}

fn toggle_cases() -> Vec<(String, String, String, bool)> {
    let some_off = r#"{"features":{"contacts":true,"calendar":false,"notes":false,"bookmarks":false,"tasks":false,"journal":true}}"#;
    [
        ("switch a feature off", "{}", "notes", false),
        ("switch a feature on", some_off, "calendar", true),
        (
            "the last feature cannot go off",
            some_off,
            "contacts",
            false,
        ),
        ("a feature already off stays off", some_off, "notes", false),
        ("an unknown feature changes nothing", "{}", "journal", false),
    ]
    .into_iter()
    .map(|(case, raw, feature, enabled)| {
        (
            case.to_string(),
            raw.to_string(),
            feature.to_string(),
            enabled,
        )
    })
    .collect()
}

fn fixture() -> Fixture {
    Fixture {
        constants: Constants {
            content_type: ACCOUNT_SETTINGS_CONTENT_TYPE.into(),
            object_id: ACCOUNT_SETTINGS_ID.to_string(),
            legacy_object_id: LEGACY_ACCOUNT_SETTINGS_ID.into(),
            keys: ACCOUNT_SETTINGS_KEYS
                .iter()
                .map(|k| k.to_string())
                .collect(),
            features: FEATURES.iter().map(|k| k.to_string()).collect(),
            contact_modes: CONTACT_MODES.iter().map(|k| k.to_string()).collect(),
            default_contact_mode: DEFAULT_CONTACT_MODE.into(),
            accents: ACCENTS.iter().map(|k| k.to_string()).collect(),
            default_accent: DEFAULT_ACCENT.into(),
        },
        writes: write_cases()
            .into_iter()
            .map(|(case, draft)| WriteCase {
                case,
                payload: settings_write(&draft).expect("writes"),
                draft,
            })
            .collect(),
        parses: parse_cases()
            .into_iter()
            .map(|(case, raw)| ParseCase {
                case,
                settings: settings_parse(&raw),
                raw,
            })
            .collect(),
        toggles: toggle_cases()
            .into_iter()
            .map(|(case, raw, feature, enabled)| {
                let before = settings_parse(&raw);
                ToggleCase {
                    case,
                    can_disable: can_disable_feature(&before, &feature),
                    settings: settings_with_feature(&before, &feature, enabled),
                    raw,
                    feature,
                    enabled,
                }
            })
            .collect(),
        refusals: vec![RefusalCase {
            case: "saving over a newer schema major".into(),
            error: "PayloadSchema".into(),
        }],
    }
}

#[test]
fn the_fixture_is_current() {
    let stored: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(FIXTURE).expect("fixture exists")).unwrap();
    assert_eq!(stored, serde_json::to_value(fixture()).unwrap());
}

#[test]
fn a_toggle_keeps_what_it_does_not_know() {
    let raw = r#"{"version":"1.0","features":{"journal":"beta","notes":true},"theme":"dark"}"#;
    let next = settings_with_feature(&settings_parse(raw), "notes", false);
    let written: serde_json::Value =
        serde_json::from_str(&settings_write(&next.draft()).unwrap()).unwrap();
    assert_eq!(written["features"]["journal"], "beta");
    assert_eq!(written["features"]["notes"], false);
    assert_eq!(written["theme"], "dark");
}

#[test]
fn settings_written_from_what_was_read_read_back_the_same() {
    for (case, raw) in parse_cases() {
        let before = settings_parse(&raw);
        if !before.readable {
            continue;
        }
        let written = settings_write(&before.draft()).expect(&case);
        let after = settings_parse(&written);
        assert_eq!(before.features, after.features, "{case}");
        assert_eq!(before.unknown_features, after.unknown_features, "{case}");
        assert_eq!(before.contact_mode, after.contact_mode, "{case}");
        assert_eq!(before.accent, after.accent, "{case}");
    }
}

#[test]
fn a_newer_major_is_read_but_not_written_over() {
    let read = settings_parse(r#"{"version":"9.0","features":{"notes":false}}"#);
    assert!(!read.readable);
    assert!(!read.is_enabled("notes"));
    assert!(matches!(
        settings_write(&read.draft()),
        Err(CoreError::PayloadSchema { .. })
    ));
}

#[test]
#[ignore = "writes the shared fixture"]
fn regenerate() {
    if std::env::var("REGENERATE_SETTINGS_FIXTURE").is_err() {
        return;
    }
    std::fs::write(
        FIXTURE,
        format!("{}\n", serde_json::to_string_pretty(&fixture()).unwrap()),
    )
    .unwrap();
}
