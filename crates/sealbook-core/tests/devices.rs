//! Device labels, against the fixture the clients share.
//!
//! Regenerate with:
//! `REGENERATE_DEVICES_FIXTURE=1 cargo test -p sealbook-core --test devices -- --ignored regenerate`

use sealbook_core::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const FIXTURE: &str = "../sealbook-protocol/fixtures/payloads/devices.json";

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Fixture {
    constants: Constants,
    names: Vec<NameCase>,
    user_agents: Vec<UserAgentCase>,
    android_models: Vec<AndroidCase>,
    writes: Vec<WriteCase>,
    parses: Vec<ParseCase>,
    entries: Vec<EntriesCase>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Constants {
    content_type: String,
    keys: Vec<String>,
    kinds: Vec<String>,
    kind_labels: Vec<(CoreDeviceKind, String)>,
    max_name_chars: usize,
    max_platform_chars: usize,
    unreported_detail: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct NameCase {
    device_id: Uuid,
    name: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct UserAgentCase {
    case: String,
    user_agent: String,
    browser: String,
    os: String,
    described: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct AndroidCase {
    manufacturer: String,
    model: String,
    named: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct WriteCase {
    case: String,
    labels: Vec<CoreDeviceLabelObject>,
    device_id: Uuid,
    /// `Some` is a rename, `None` an ensure.
    rename: Option<String>,
    kind: CoreDeviceKind,
    platform: String,
    /// The written payload, or `None` where nothing needs writing.
    payload: Option<String>,
    /// Whether the write reused the object id of the stored label.
    reused_object: bool,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct ParseCase {
    case: String,
    raw: String,
    label: Option<CoreDeviceLabel>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct EntriesCase {
    case: String,
    roster: Vec<Uuid>,
    labels: Vec<CoreDeviceLabelObject>,
    current: Uuid,
    entries: Vec<CoreDeviceEntry>,
    stale: Vec<String>,
}

fn id(n: u128) -> Uuid {
    Uuid::from_u128(0x5ea1_b00c_0000_4000_8000_0000_0000_0000 | n)
}

fn label(object: u128, device: Uuid, body: &str) -> CoreDeviceLabelObject {
    CoreDeviceLabelObject {
        object_id: Uuid::from_u128(object).to_string(),
        payload: body.replace("DEVICE", &device.to_string()),
    }
}

fn names() -> Vec<NameCase> {
    [
        "3ee1943d-0a63-4600-a9b0-983990be5e4b",
        "7a4cdd6a-40b8-419f-b20c-279a8d946029",
        "51e5b1fb-d44e-4ff3-a261-5e82e12675b0",
        "00000000-0000-0000-0000-000000000000",
        "ffffffff-ffff-4fff-bfff-ffffffffffff",
    ]
    .into_iter()
    .map(|raw| {
        let device_id: Uuid = raw.parse().unwrap();
        NameCase {
            device_id,
            name: device_default_name(device_id),
        }
    })
    .collect()
}

fn user_agents() -> Vec<UserAgentCase> {
    [
        ("Firefox on macOS", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0"),
        ("Chrome on Windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"),
        ("Edge on Windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0"),
        ("Safari on macOS", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"),
        ("Safari on iOS", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"),
        ("Chrome on Android", "Mozilla/5.0 (Linux; Android 15; Pixel 8a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36"),
        ("Firefox on Linux", "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"),
        ("Chrome on ChromeOS", "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"),
        ("Firefox on iPadOS", "Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/140.0 Mobile/15E148 Safari/605.1.15"),
        ("nothing recognised", "curl/8.7.1"),
        ("empty", ""),
    ]
    .into_iter()
    .map(|(case, ua)| UserAgentCase {
        case: case.into(),
        user_agent: ua.into(),
        browser: user_agent_browser(ua),
        os: user_agent_os(ua),
        described: describe_user_agent(ua),
    })
    .collect()
}

fn android_models() -> Vec<AndroidCase> {
    [
        ("Google", "Pixel 8a"),
        ("samsung", "SM-S921B"),
        ("OnePlus", "OnePlus 12"),
        ("Xiaomi", "  Redmi   Note 13 "),
        ("", "Pixel 9"),
    ]
    .into_iter()
    .map(|(manufacturer, model)| AndroidCase {
        manufacturer: manufacturer.into(),
        model: model.into(),
        named: android_model_name(manufacturer, model),
    })
    .collect()
}

type WriteInput = (
    &'static str,
    Vec<CoreDeviceLabelObject>,
    Option<&'static str>,
    CoreDeviceKind,
    &'static str,
);

fn write_cases() -> Vec<WriteCase> {
    let me = id(1);
    let stored = label(
        10,
        me,
        r#"{"@type":"DeviceLabel","version":"1.0","deviceId":"DEVICE","name":"Work laptop","kind":"web","platform":"Firefox on macOS","pinned":true}"#,
    );
    let foreign = label(
        11,
        me,
        r#"{"@type":"DeviceLabel","version":"1.2","deviceId":"DEVICE","name":"Kitchen tablet","kind":"ios","platform":"iPadOS"}"#,
    );
    let newer = label(
        12,
        me,
        r#"{"@type":"DeviceLabel","version":"9.0","deviceId":"DEVICE","name":"Future","kind":"web"}"#,
    );
    let cases: Vec<WriteInput> = vec![
        (
            "a device with no label writes one under its default name",
            vec![],
            None,
            CoreDeviceKind::Firefox,
            "macOS",
        ),
        (
            "a label that already says what the device is needs no write",
            vec![stored.clone()],
            None,
            CoreDeviceKind::Web,
            "Firefox on macOS",
        ),
        (
            "a new platform keeps the chosen name and unknown keys",
            vec![stored.clone()],
            None,
            CoreDeviceKind::Web,
            "Firefox on Linux",
        ),
        (
            "a label from a newer major is left alone",
            vec![newer.clone()],
            None,
            CoreDeviceKind::Web,
            "Chrome on Windows",
        ),
        (
            "a rename keeps the kind and platform",
            vec![stored.clone()],
            Some("  Office   iMac "),
            CoreDeviceKind::Unknown,
            "",
        ),
        (
            "a rename keeps a kind this build does not know",
            vec![foreign],
            Some("Tablet"),
            CoreDeviceKind::Unknown,
            "",
        ),
        (
            "an empty rename restores the default",
            vec![stored],
            Some("   "),
            CoreDeviceKind::Unknown,
            "",
        ),
        (
            "renaming a device that never reported writes a label with no kind",
            vec![],
            Some("Old phone"),
            CoreDeviceKind::Unknown,
            "",
        ),
        (
            "a long name is cut to the limit",
            vec![],
            Some("A name that goes on far longer than anyone would want to read"),
            CoreDeviceKind::Unknown,
            "",
        ),
    ];
    cases
        .into_iter()
        .map(|(case, labels, rename, kind, platform)| {
            let written = match rename {
                Some(name) => Some(device_label_rename(&labels, me, name).expect("renames")),
                None => device_label_ensure(&labels, me, kind, platform).expect("ensures"),
            };
            WriteCase {
                case: case.into(),
                reused_object: written
                    .as_ref()
                    .is_some_and(|w| labels.iter().any(|l| l.object_id == w.object_id)),
                payload: written.map(|w| w.payload),
                labels,
                device_id: me,
                rename: rename.map(str::to_string),
                kind,
                platform: platform.into(),
            }
        })
        .collect()
}

fn parse_cases() -> Vec<ParseCase> {
    let device = id(2);
    [
        ("a full label", r#"{"@type":"DeviceLabel","version":"1.0","deviceId":"DEVICE","name":"Swift Otter","kind":"android","platform":"Google Pixel 8a"}"#),
        ("an unknown kind reads as unknown", r#"{"@type":"DeviceLabel","version":"1.0","deviceId":"DEVICE","name":"Tab","kind":"ios"}"#),
        ("a newer major is read but marked", r#"{"@type":"DeviceLabel","version":"9.0","deviceId":"DEVICE","name":"Next"}"#),
        ("no device id is no label", r#"{"@type":"DeviceLabel","version":"1.0","name":"Orphan"}"#),
        ("not JSON", "garbage"),
    ]
    .into_iter()
    .map(|(case, raw)| {
        let raw = raw.replace("DEVICE", &device.to_string());
        ParseCase {
            case: case.into(),
            label: device_label_parse(&raw),
            raw,
        }
    })
    .collect()
}

fn entries_cases() -> Vec<EntriesCase> {
    let (me, phone, cli, gone) = (id(1), id(2), id(3), id(4));
    let labels = vec![
        label(
            20,
            me,
            r#"{"@type":"DeviceLabel","version":"1.0","deviceId":"DEVICE","name":"Desk","kind":"web","platform":"Firefox on macOS"}"#,
        ),
        label(
            21,
            phone,
            r#"{"@type":"DeviceLabel","version":"1.0","deviceId":"DEVICE","name":"Phone","kind":"android","platform":"Google Pixel 8a"}"#,
        ),
        label(
            22,
            gone,
            r#"{"@type":"DeviceLabel","version":"1.0","deviceId":"DEVICE","name":"Revoked","kind":"cli","platform":"Linux"}"#,
        ),
        label(
            19,
            phone,
            r#"{"@type":"DeviceLabel","version":"1.0","deviceId":"DEVICE","name":"Phone (race)","kind":"android"}"#,
        ),
        label(23, me, "not a label"),
    ];
    let twins = vec![
        label(
            30,
            phone,
            r#"{"@type":"DeviceLabel","version":"1.0","deviceId":"DEVICE","name":"Laptop","kind":"web"}"#,
        ),
        label(
            31,
            cli,
            r#"{"@type":"DeviceLabel","version":"1.0","deviceId":"DEVICE","name":"laptop","kind":"cli","platform":"macOS"}"#,
        ),
    ];
    [
        (
            "labelled, unlabelled, raced and revoked devices",
            vec![phone, me, cli],
            labels,
            me,
        ),
        (
            "two devices sharing a name are told apart",
            vec![me, phone, cli],
            twins,
            me,
        ),
        ("no labels at all", vec![phone, me], vec![], me),
    ]
    .into_iter()
    .map(|(case, roster, labels, current)| EntriesCase {
        case: case.into(),
        entries: device_entries(&roster, &labels, current),
        stale: stale_device_labels(&roster, &labels),
        roster,
        labels,
        current,
    })
    .collect()
}

fn fixture() -> Fixture {
    Fixture {
        constants: Constants {
            content_type: DEVICE_LABEL_CONTENT_TYPE.into(),
            keys: DEVICE_LABEL_KEYS.iter().map(|k| k.to_string()).collect(),
            kinds: DEVICE_KINDS.iter().map(|k| k.to_string()).collect(),
            kind_labels: [
                CoreDeviceKind::Web,
                CoreDeviceKind::Firefox,
                CoreDeviceKind::Android,
                CoreDeviceKind::Cli,
                CoreDeviceKind::Unknown,
            ]
            .into_iter()
            .map(|kind| (kind, device_kind_label(kind)))
            .collect(),
            max_name_chars: MAX_DEVICE_NAME_CHARS,
            max_platform_chars: MAX_DEVICE_PLATFORM_CHARS,
            unreported_detail: UNREPORTED_DEVICE_DETAIL.into(),
        },
        names: names(),
        user_agents: user_agents(),
        android_models: android_models(),
        writes: write_cases(),
        parses: parse_cases(),
        entries: entries_cases(),
    }
}

#[test]
#[ignore = "writes the shared fixture; run with REGENERATE_DEVICES_FIXTURE=1"]
fn regenerate() {
    assert!(std::env::var("REGENERATE_DEVICES_FIXTURE").is_ok());
    let text = serde_json::to_string_pretty(&fixture()).unwrap() + "\n";
    std::fs::write(FIXTURE, text).unwrap();
}

#[test]
fn the_shared_fixture_is_what_core_produces() {
    let stored: Fixture = serde_json::from_str(
        &std::fs::read_to_string(FIXTURE).expect("the fixture exists; regenerate it"),
    )
    .expect("the fixture parses");
    assert_eq!(stored, fixture());
}

#[test]
fn a_default_name_is_two_words_from_the_lists() {
    for n in 0..512u128 {
        let name = device_default_name(Uuid::from_u128(n * 7919));
        assert_eq!(name.split(' ').count(), 2, "{name}");
        assert!(name.len() <= MAX_DEVICE_NAME_CHARS);
    }
}

#[test]
fn a_new_label_takes_a_fresh_object_id_each_time() {
    let a = device_label_ensure(&[], id(1), CoreDeviceKind::Cli, "macOS")
        .unwrap()
        .unwrap();
    let b = device_label_ensure(&[], id(1), CoreDeviceKind::Cli, "macOS")
        .unwrap()
        .unwrap();
    assert_ne!(a.object_id, b.object_id);
    assert_eq!(a.payload, b.payload);
}

#[test]
fn every_written_label_is_a_device_label_payload() {
    for case in write_cases() {
        if let Some(payload) = case.payload {
            assert_eq!(
                payload_kind(DEVICE_LABEL_CONTENT_TYPE, &payload),
                CorePayloadKind::DeviceLabel
            );
            assert_eq!(payload_kind("", &payload), CorePayloadKind::DeviceLabel);
        }
    }
}
