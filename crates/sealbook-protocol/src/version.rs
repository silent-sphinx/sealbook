//! Every version number the protocol declares, and what bumping each one costs.
//!
//! These live together because they are independent: the wire generation, the
//! sealed envelope's framing and a payload's schema can each move without the
//! others, and a reader needs to know which one it is looking at. Collecting
//! them is also the only way to see that they are currently all at 1.
//!
//! Bumping one means, in each case:
//!
//! - [`PROTOCOL_VERSION`]: add the old string to [`SUPPORTED_PROTOCOL_VERSIONS`]
//!   for as long as older clients are to keep working, and mount the new routes
//!   under their own `/vN` prefix beside the existing ones.
//! - [`ENVELOPE_VERSION`]: add a reader for the new leading byte in
//!   `envelope::open_envelope` and keep the old one. Objects convert as they are
//!   rewritten, so the old reader stays until a rotation has touched every
//!   collection.
//! - [`PAYLOAD_SCHEMA_VERSION`]: bump the minor for a field that an older
//!   reader can ignore, the major only for a change that would make it
//!   misread what it does understand.

/// Wire protocol generation, reported by `GET /health/crypto`.
pub const PROTOCOL_VERSION: &str = "sealbook-v1";

/// The generations this build can talk to, newest first.
///
/// A client compares the server's reported version against this before it
/// trusts anything else the server says, so a version mismatch surfaces as
/// itself rather than as whichever field happens to decode wrongly first.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[PROTOCOL_VERSION];

pub fn speaks_protocol(reported: &str) -> bool {
    SUPPORTED_PROTOCOL_VERSIONS.contains(&reported)
}

/// Just the version field of `GET /health/crypto`.
///
/// The full profile lives in the server, which is free to add to it: a client
/// checking the generation it is talking to must not fail because the server
/// grew a field describing an algorithm this build has no opinion about.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProtocolReport {
    pub protocol: String,
}

/// Schema version written into every object payload as `version`.
///
/// Major and minor, because the two are read differently: a reader accepts any
/// minor within its own major, since the only thing a minor bump may add is a
/// field that an older reader can leave alone. Clients preserve fields they do
/// not recognise, so a minor addition survives a round trip through a build
/// that predates it.
pub const PAYLOAD_SCHEMA_VERSION: &str = "1.0";

/// Whether a payload declaring `version` can be read by this build.
///
/// An absent or unparsable version is treated as readable: payloads predating
/// the field exist, and the fields themselves are all optional, so the parse
/// degrades rather than refusing. A newer major is not readable, because that
/// is exactly the case where a field this build does understand may have
/// changed meaning.
pub fn payload_schema_readable(declared: &str) -> bool {
    let Some(major) = declared.split('.').next() else {
        return true;
    };
    match major.parse::<u32>() {
        Ok(major) => major <= payload_schema_major(),
        Err(_) => true,
    }
}

/// Serialises a payload, carrying through any field of `previous` that this
/// build does not own.
///
/// `owned` is every key this build manages, not just the ones it is writing this
/// time. The difference matters: a writer omits an empty optional field rather
/// than writing null, so deriving the set from `fields` would carry the previous
/// value of a field the caller has just cleared back in and resurrect it.
///
/// Without this, a field written by a newer client is destroyed the first time an
/// older one saves over it, which is silent data loss rather than a version error
/// anyone would see. Mirrored by `mergePayload` in `sealbook-web`.
pub fn merge_payload(
    previous: Option<&str>,
    fields: serde_json::Value,
    owned: &[&str],
) -> serde_json::Value {
    let mut merged = match carried_fields(previous, owned) {
        Some(carried) => carried,
        None => return fields,
    };
    let Some(fields) = fields.as_object() else {
        return fields;
    };
    for (key, value) in fields {
        merged.insert(key.clone(), value.clone());
    }
    serde_json::Value::Object(merged)
}

fn carried_fields(
    previous: Option<&str>,
    owned: &[&str],
) -> Option<serde_json::Map<String, serde_json::Value>> {
    let parsed = serde_json::from_str::<serde_json::Value>(previous?).ok()?;
    let object = parsed.as_object()?;
    Some(
        object
            .iter()
            .filter(|(key, _)| !owned.contains(&key.as_str()))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
}

fn payload_schema_major() -> u32 {
    PAYLOAD_SCHEMA_VERSION
        .split('.')
        .next()
        .and_then(|major| major.parse().ok())
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_build_speaks_its_own_protocol() {
        assert!(speaks_protocol(PROTOCOL_VERSION));
    }

    #[test]
    fn an_unknown_protocol_is_refused() {
        assert!(!speaks_protocol("sealbook-v2"));
        assert!(!speaks_protocol(""));
    }

    #[test]
    fn a_payload_minor_within_this_major_is_readable() {
        assert!(payload_schema_readable("1.0"));
        assert!(payload_schema_readable("1.7"));
    }

    #[test]
    fn a_newer_payload_major_is_not_readable() {
        assert!(!payload_schema_readable("2.0"));
    }

    #[test]
    fn a_payload_without_a_usable_version_is_still_readable() {
        assert!(payload_schema_readable(""));
        assert!(payload_schema_readable("not-a-version"));
    }

    const OWNED: &[&str] = &["@type", "title"];

    #[test]
    fn a_merge_carries_a_field_this_build_does_not_own() {
        let previous = r#"{"@type":"Note","title":"old","futureField":7}"#;
        let merged = merge_payload(
            Some(previous),
            serde_json::json!({ "@type": "Note", "title": "new" }),
            OWNED,
        );
        assert_eq!(merged["title"], "new");
        assert_eq!(merged["futureField"], 7);
    }

    #[test]
    fn a_merge_does_not_resurrect_an_owned_field_just_cleared() {
        let previous = r#"{"@type":"Note","title":"old"}"#;
        let merged = merge_payload(
            Some(previous),
            serde_json::json!({ "@type": "Note" }),
            OWNED,
        );
        assert!(merged.get("title").is_none());
    }

    #[test]
    fn a_merge_without_a_usable_previous_payload_writes_the_fields_alone() {
        let fields = serde_json::json!({ "a": 1 });
        for previous in [
            None,
            Some(""),
            Some("not json"),
            Some("[1,2]"),
            Some("null"),
        ] {
            assert_eq!(merge_payload(previous, fields.clone(), OWNED), fields);
        }
    }
}
