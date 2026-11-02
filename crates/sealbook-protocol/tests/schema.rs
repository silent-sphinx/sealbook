//! The checked-in wire schema against the one the serde types generate.
//!
//! Run `REGENERATE_SCHEMA=1 cargo test -p sealbook-protocol -- --ignored
//! regenerate` to rewrite it after a deliberate wire change.

use sealbook_protocol::schema::wire_schema;

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
