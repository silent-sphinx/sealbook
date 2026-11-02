use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Deserializer, Serializer};

/// Bytes on the wire as unpadded base64url.
///
/// A type rather than a module so that one `#[serde(with = "b64")]` serves both
/// serde, which calls the associated functions, and schemars, which takes the
/// path as the type whose schema the field has.
#[allow(non_camel_case_types)]
pub struct b64;

impl b64 {
    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }

    #[allow(dead_code)]
    pub fn encode(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    #[allow(dead_code)]
    pub fn decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
        URL_SAFE_NO_PAD.decode(s.as_bytes())
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for b64 {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Base64Url".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "contentEncoding": "base64url",
            "pattern": "^[A-Za-z0-9_-]*$",
            "description": "Bytes as unpadded base64url (RFC 4648 section 5)."
        })
    }
}
