//! The sealed envelope: the plaintext format an object is stored in.
//!
//! The server only ever sees [`SEALED_CONTENT_TYPE`], so an object's real type
//! has to travel inside the ciphertext, and this is what carries it. It lives in
//! the protocol crate rather than in one client because all three clients format
//! it, and three copies of the format is how they drifted apart.
//!
//! The type is deliberately not also bound into the AEAD's associated data.
//! Associated data is authenticated but not encrypted, and a reader needs it
//! before it can decrypt, so an AAD-bound type would have to stay in the clear.
//! Inside the sealed plaintext the AEAD authenticates it just as firmly and the
//! server learns nothing.

use serde::Deserialize;

/// The envelope version clients write.
pub const ENVELOPE_VERSION: u8 = 2;

/// What a stored plaintext turned out to be.
pub enum Unsealed {
    Envelope {
        content_type: String,
        tombstone: bool,
        payload: Vec<u8>,
    },
    /// A raw payload from before the envelope existed.
    Legacy,
    /// An envelope this build cannot read, by version or because it is damaged.
    /// Never treated as legacy: the type inside it is the authenticated one, and
    /// falling back to the server's label would be trusting the server instead.
    Unreadable,
}

const TOMBSTONE_FLAG: u8 = 1;

/// The plaintext to encrypt for a live object of `content_type`.
pub fn seal_envelope(content_type: &str, payload: &[u8]) -> Vec<u8> {
    seal_envelope_inner(content_type, payload, false)
}

/// As [`seal_envelope`], for a delete that still carries a sealed body.
pub fn seal_tombstone_envelope(content_type: &str) -> Vec<u8> {
    seal_envelope_inner(content_type, &[], true)
}

fn seal_envelope_inner(content_type: &str, payload: &[u8], tombstone: bool) -> Vec<u8> {
    let type_bytes = content_type.as_bytes();
    let mut out = Vec::with_capacity(4 + type_bytes.len() + payload.len());
    out.push(ENVELOPE_VERSION);
    out.push(if tombstone { TOMBSTONE_FLAG } else { 0 });
    // Length-prefixed so the type cannot borrow a byte from the payload.
    out.extend_from_slice(&(type_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(type_bytes);
    out.extend_from_slice(payload);
    out
}

#[derive(Deserialize)]
struct EnvelopeV1 {
    version: u8,
    #[serde(rename = "contentType")]
    content_type: String,
    #[serde(default)]
    tombstone: bool,
    payload: String,
}

pub fn open_envelope(plain: &[u8]) -> Unsealed {
    if plain.first() == Some(&ENVELOPE_VERSION) {
        return open_v2(plain);
    }
    match serde_json::from_slice::<EnvelopeV1>(plain) {
        Ok(envelope) if envelope.version == 1 => Unsealed::Envelope {
            content_type: envelope.content_type,
            tombstone: envelope.tombstone,
            payload: envelope.payload.into_bytes(),
        },
        // A JSON object that declares a version this build does not know is an
        // envelope all the same, so its payload is not readable here.
        Ok(_) => Unsealed::Unreadable,
        Err(_) => Unsealed::Legacy,
    }
}

fn open_v2(plain: &[u8]) -> Unsealed {
    if plain.len() < 4 {
        return Unsealed::Unreadable;
    }
    let type_len = u16::from_be_bytes([plain[2], plain[3]]) as usize;
    let Some(type_end) = 4usize
        .checked_add(type_len)
        .filter(|end| *end <= plain.len())
    else {
        return Unsealed::Unreadable;
    };
    let Ok(content_type) = std::str::from_utf8(&plain[4..type_end]) else {
        return Unsealed::Unreadable;
    };
    Unsealed::Envelope {
        content_type: content_type.to_string(),
        tombstone: plain[1] & TOMBSTONE_FLAG != 0,
        payload: plain[type_end..].to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOTE: &str = "application/sealbook.note+json";

    fn opened(plain: &[u8]) -> (String, bool, Vec<u8>) {
        match open_envelope(plain) {
            Unsealed::Envelope {
                content_type,
                tombstone,
                payload,
            } => (content_type, tombstone, payload),
            _ => panic!("expected an envelope"),
        }
    }

    #[test]
    fn a_v2_envelope_round_trips() {
        let sealed = seal_envelope(NOTE, br#"{"@type":"Note"}"#);
        assert_eq!(
            opened(&sealed),
            (NOTE.to_string(), false, br#"{"@type":"Note"}"#.to_vec())
        );
    }

    #[test]
    fn a_v2_payload_that_is_not_text_survives() {
        let payload = vec![0x00, 0xff, 0xfe, 0x7b];
        let sealed = seal_envelope(NOTE, &payload);
        assert_eq!(opened(&sealed).2, payload);
    }

    #[test]
    fn a_v2_tombstone_is_flagged() {
        let sealed = seal_tombstone_envelope(NOTE);
        assert_eq!(opened(&sealed), (NOTE.to_string(), true, Vec::new()));
    }

    #[test]
    fn a_web_written_v1_envelope_still_opens() {
        let plain = br#"{"version":1,"contentType":"application/sealbook.note+json","tombstone":false,"revision":7,"payload":"hi"}"#;
        assert_eq!(opened(plain), (NOTE.to_string(), false, b"hi".to_vec()));
    }

    #[test]
    fn a_raw_payload_is_legacy() {
        assert!(matches!(
            open_envelope(br#"{"@type":"Card"}"#),
            Unsealed::Legacy
        ));
    }

    #[test]
    fn an_envelope_version_this_build_does_not_know_is_not_legacy() {
        assert!(matches!(
            open_envelope(br#"{"version":9,"contentType":"x","tombstone":false,"payload":"hi"}"#),
            Unsealed::Unreadable
        ));
        assert!(matches!(open_envelope(&[2u8, 0, 0]), Unsealed::Unreadable));
        assert!(matches!(
            open_envelope(&[2u8, 0, 0xff, 0xff, b'x']),
            Unsealed::Unreadable
        ));
        assert!(matches!(
            open_envelope(&[2u8, 0, 0, 1, 0xff]),
            Unsealed::Unreadable
        ));
    }
}
