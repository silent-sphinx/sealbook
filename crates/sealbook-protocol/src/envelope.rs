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
//!
//! [`SEALED_CONTENT_TYPE`]: crate::SEALED_CONTENT_TYPE

/// The envelope version clients write, and the only one they read.
///
/// A future version adds an arm to [`open_envelope`] rather than replacing one:
/// stored objects carry the version they were written under until something
/// rewrites them.
pub const ENVELOPE_VERSION: u8 = 1;

/// What a stored plaintext turned out to be.
pub enum Unsealed {
    Envelope {
        content_type: String,
        tombstone: bool,
        payload: Vec<u8>,
    },
    /// An envelope this build cannot read, by version or because it is damaged.
    ///
    /// Never resolved by falling back to the content type the server serves: the
    /// type inside the envelope is the authenticated one, and preferring the
    /// server's label would hand it the choice of how a payload is parsed.
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

pub fn open_envelope(plain: &[u8]) -> Unsealed {
    // The leading byte is the only dispatch: a version this build does not know
    // is unreadable, not guessed at.
    match plain.first() {
        Some(&ENVELOPE_VERSION) => open_v1(plain),
        _ => Unsealed::Unreadable,
    }
}

fn open_v1(plain: &[u8]) -> Unsealed {
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
    fn an_envelope_round_trips() {
        let sealed = seal_envelope(NOTE, br#"{"@type":"Note"}"#);
        assert_eq!(
            opened(&sealed),
            (NOTE.to_string(), false, br#"{"@type":"Note"}"#.to_vec())
        );
    }

    #[test]
    fn a_payload_that_is_not_text_survives() {
        let payload = vec![0x00, 0xff, 0xfe, 0x7b];
        let sealed = seal_envelope(NOTE, &payload);
        assert_eq!(opened(&sealed).2, payload);
    }

    #[test]
    fn a_tombstone_is_flagged() {
        let sealed = seal_tombstone_envelope(NOTE);
        assert_eq!(opened(&sealed), (NOTE.to_string(), true, Vec::new()));
    }

    #[test]
    fn a_raw_payload_is_unreadable() {
        // Not an envelope at all: without a version byte there is nothing to
        // authenticate the type, so it is refused rather than read under the
        // type the server happens to serve.
        assert!(matches!(
            open_envelope(br#"{"@type":"Card"}"#),
            Unsealed::Unreadable
        ));
        assert!(matches!(open_envelope(&[]), Unsealed::Unreadable));
    }

    #[test]
    fn an_envelope_version_this_build_does_not_know_is_unreadable() {
        assert!(matches!(
            open_envelope(&[ENVELOPE_VERSION + 1, 0, 0, 0]),
            Unsealed::Unreadable
        ));
    }

    #[test]
    fn a_truncated_or_overlong_envelope_is_unreadable() {
        assert!(matches!(
            open_envelope(&[ENVELOPE_VERSION, 0, 0]),
            Unsealed::Unreadable
        ));
        assert!(matches!(
            open_envelope(&[ENVELOPE_VERSION, 0, 0xff, 0xff, b'x']),
            Unsealed::Unreadable
        ));
        assert!(matches!(
            open_envelope(&[ENVELOPE_VERSION, 0, 0, 1, 0xff]),
            Unsealed::Unreadable
        ));
    }
}
