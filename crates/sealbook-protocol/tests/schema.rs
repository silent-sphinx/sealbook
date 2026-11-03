//! The checked-in wire schema against the one the serde types generate, and
//! the shared fixtures against the schema.
//!
//! Run `REGENERATE_SCHEMA=1 cargo test -p sealbook-protocol -- --ignored
//! regenerate` to rewrite it after a deliberate wire change.

use sealbook_protocol::schema::wire_schema;
use serde_json::Value;

const WIRE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/schema/wire.json");

fn built() -> String {
    serde_json::to_string_pretty(&wire_schema()).unwrap() + "\n"
}

#[test]
#[ignore = "writes the checked-in schema; run with REGENERATE_SCHEMA=1"]
fn regenerate_the_wire_schema() {
    assert!(
        std::env::var("REGENERATE_SCHEMA").is_ok(),
        "set REGENERATE_SCHEMA=1 to confirm overwriting the checked-in schema"
    );
    std::fs::create_dir_all(concat!(env!("CARGO_MANIFEST_DIR"), "/schema")).unwrap();
    std::fs::write(WIRE, built()).unwrap();
}

#[test]
fn the_checked_in_wire_schema_is_what_the_types_generate() {
    let stored = std::fs::read_to_string(WIRE).unwrap_or_default();
    assert!(
        stored == built(),
        "schema/wire.json is stale; regenerate it: REGENERATE_SCHEMA=1"
    );
}

#[test]
fn bytes_are_described_as_base64url_strings() {
    let schema = wire_schema();
    let mac = &schema["$defs"]["RosterBody"]["properties"]["mac"];
    assert_eq!(mac["$ref"], "#/$defs/Base64Url");
    assert_eq!(schema["$defs"]["Base64Url"]["contentEncoding"], "base64url");
}

#[test]
fn every_type_that_derives_a_schema_is_in_the_bundle() {
    let schema = wire_schema();
    let sources = [
        include_str!("../src/lib.rs"),
        include_str!("../src/attachment.rs"),
        include_str!("../src/version.rs"),
    ];
    for source in sources {
        let mut lines = source.lines();
        while let Some(line) = lines.next() {
            if !line.contains("derive(schemars::JsonSchema)") {
                continue;
            }
            let name = lines
                .by_ref()
                .find_map(|line| {
                    let rest = line
                        .strip_prefix("pub struct ")
                        .or_else(|| line.strip_prefix("pub enum "))?;
                    rest.split(|c: char| !c.is_alphanumeric()).next()
                })
                .expect("a derive is followed by its type");
            assert!(
                schema["$defs"].get(name).is_some(),
                "{name} derives a schema but is not listed in schema::wire_schema"
            );
        }
    }
}

fn fixture(name: &str) -> Value {
    let path = format!("{}/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    serde_json::from_str(&text).expect("a fixture must be JSON")
}

/// The values at `path`, where `*` steps into every item of an array. A string
/// is parsed, since fixtures hold a response body as the text the server sent.
fn at(value: &Value, path: &str) -> Vec<Value> {
    let mut found = vec![value];
    for step in path.split('/') {
        found = found
            .into_iter()
            .flat_map(|value| match step {
                "*" => value
                    .as_array()
                    .expect("* steps into an array")
                    .iter()
                    .collect(),
                key => vec![&value[key]],
            })
            .collect();
    }
    found
        .into_iter()
        .map(|value| match value {
            Value::String(text) => serde_json::from_str(text).expect("a body string is JSON"),
            Value::Null => panic!("{path} is missing"),
            other => other.clone(),
        })
        .collect()
}

fn assert_valid(type_name: &str, bodies: &[Value], whence: &str) {
    let mut schema = wire_schema();
    assert!(schema["$defs"].get(type_name).is_some(), "no {type_name}");
    schema["$ref"] = format!("#/$defs/{type_name}").into();
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .expect("the wire schema compiles");
    assert!(!bodies.is_empty(), "{whence} selects nothing");
    for (index, body) in bodies.iter().enumerate() {
        let errors: Vec<String> = validator
            .iter_errors(body)
            .map(|error| format!("{} at {}", error, error.instance_path()))
            .collect();
        assert!(
            errors.is_empty(),
            "{whence}[{index}] is not a valid {type_name}: {errors:#?}"
        );
    }
}

#[test]
fn every_wire_body_in_the_shared_fixtures_meets_the_schema() {
    for (name, path, type_name) in [
        ("rosters/chain-with-revoke.json", "rosters/*", "RosterBody"),
        ("manifests/one-write.json", "devices/*", "DevicePublicKeys"),
        (
            "manifests/one-write.json",
            "manifest_response",
            "ManifestResponse",
        ),
        (
            "manifests/one-write.json",
            "buckets_response",
            "ManifestBucketsResponse",
        ),
        ("manifests/one-write.json", "write/*", "ManifestEntry"),
        ("changes/paged-walk.json", "devices/*", "DevicePublicKeys"),
        ("changes/paged-walk.json", "pages/*", "ChangesResponse"),
        (
            "pairing/handshake.json",
            "approver/device",
            "DevicePublicKeys",
        ),
        (
            "pairing/handshake.json",
            "joining/device",
            "DevicePublicKeys",
        ),
        (
            "pairing/handshake.json",
            "verified/roster_json",
            "RosterBody",
        ),
        (
            "pairing/handshake.json",
            "join_response",
            "PairJoinResponse",
        ),
        (
            "pairing/handshake.json",
            "join_refusals/*/response",
            "PairJoinResponse",
        ),
        (
            "pairing/handshake.json",
            "preview_response",
            "PairStatusResponse",
        ),
        (
            "pairing/handshake.json",
            "approve_refusals/*/response",
            "PairStatusResponse",
        ),
        ("rotation/plan.json", "devices/*", "DevicePublicKeys"),
        (
            "attachments/attachments.json",
            "sweep/rows/*",
            "AttachmentListEntry",
        ),
        ("auth/account.json", "device/device", "DevicePublicKeys"),
        ("auth/account.json", "recover_start", "RecoverStartResponse"),
        ("auth/account.json", "logins/*/body", "LoginFinishResponse"),
    ] {
        let whence = format!("{name} {path}");
        assert_valid(type_name, &at(&fixture(name), path), &whence);
    }
}

#[test]
fn pairing_polls_meet_the_schema_for_their_status() {
    let polls = fixture("pairing/handshake.json");
    for poll in polls["polls"].as_array().expect("polls") {
        let type_name = match poll["status"].as_u64() {
            Some(200) => "PairStatusResponse",
            _ => "ErrorBody",
        };
        let what = poll["what"].as_str().unwrap_or_default();
        assert_valid(type_name, &at(poll, "body"), &format!("poll {what}"));
    }
}

#[test]
fn auth_refusals_meet_the_schema_for_their_flow() {
    let account = fixture("auth/account.json");
    for refusal in account["refusals"].as_array().expect("refusals") {
        let type_name = match refusal["flow"].as_str() {
            Some("recover start accept") => "RecoverStartResponse",
            Some("login accept") => "LoginFinishResponse",
            other => panic!("no wire type for the {other:?} flow"),
        };
        let what = refusal["what"].as_str().unwrap_or_default();
        assert_valid(type_name, &at(refusal, "body"), &format!("refusal {what}"));
    }
}

#[test]
fn the_schema_rejects_a_body_serde_would_reject() {
    let mut roster = at(&fixture("rosters/chain-with-revoke.json"), "rosters/*").remove(0);
    roster["mac"] = "not base64url!".into();
    let mut schema = wire_schema();
    schema["$ref"] = "#/$defs/RosterBody".into();
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .unwrap();
    assert!(!validator.is_valid(&roster));
    roster["mac"] = "AAAA".into();
    roster["devices"][0]["device_id"] = "not-a-uuid".into();
    assert!(!validator.is_valid(&roster));
}
