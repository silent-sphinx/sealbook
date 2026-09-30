//! Shared request validation for the key material that pairing, recovery and
//! rotation all submit in the same shapes.

use axum::http::StatusCode;
use axum::Json;

use sealbook_crypto::{
    is_supported_recovery_ciphersuite, ED25519_PUBLIC_KEY_LEN, HPKE_AEAD_TAG_LEN,
    MLDSA65_PUBLIC_KEY_LEN, PHRASE_CIPHERSUITE, PHRASE_LOOKUP_ID_LEN, PHRASE_SCHEME,
    XWING_CIPHERSUITE, XWING_ENCAPSULATED_KEY_LEN,
};
use sealbook_protocol::{
    ErrorBody, KeyWrapBody, PhraseRecoveryBody, PutObjectRequest, RotatedObject,
    ADDRESS_BOOK_CONTENT_TYPE, CALENDAR_CONTENT_TYPE, CALENDAR_EVENT_CONTENT_TYPE,
    JSCONTACT_CONTENT_TYPE, MAX_PADDED_OBJECT_SIZE, MIN_PADDED_OBJECT_SIZE,
};

use crate::*;

/// Checks the shape and scheme of hybrid recovery-phrase material.
pub(crate) fn validate_phrase_recovery(
    phrase: &PhraseRecoveryBody,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    if phrase.scheme != PHRASE_SCHEME {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "unsupported phrase recovery scheme",
        ));
    }
    if phrase.mldsa_pk.len() != MLDSA65_PUBLIC_KEY_LEN
        || phrase.ed25519_pk.len() != ED25519_PUBLIC_KEY_LEN
        || phrase.lookup_id.len() != PHRASE_LOOKUP_ID_LEN
    {
        return Err(err(StatusCode::BAD_REQUEST, "invalid phrase recovery key"));
    }
    Ok(())
}

pub(crate) fn validate_wraps(
    device_id: &str,
    username: &str,
    wraps: &[KeyWrapBody],
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let mut device = 0;
    let mut recovery = 0;
    let mut phrase = 0;
    for wrap in wraps {
        match wrap.recipient_kind.as_str() {
            "device" => {
                if wrap.recipient_id != device_id
                    || wrap.ciphersuite != XWING_CIPHERSUITE
                    || wrap.hpke_enc.len() != XWING_ENCAPSULATED_KEY_LEN
                    || wrap.wrapped_ck.len() != 32 + HPKE_AEAD_TAG_LEN
                {
                    return Err(err(StatusCode::BAD_REQUEST, "invalid key wrap"));
                }
                device += 1;
            }
            "recovery" => {
                if !is_supported_recovery_ciphersuite(&wrap.ciphersuite)
                    || wrap.hpke_enc.len() != 24
                    || wrap.wrapped_ck.len() != 32 + HPKE_AEAD_TAG_LEN
                {
                    return Err(err(StatusCode::BAD_REQUEST, "invalid key wrap"));
                }
                recovery += 1;
            }
            "phrase" => {
                if wrap.recipient_id != username
                    || wrap.ciphersuite != PHRASE_CIPHERSUITE
                    || wrap.hpke_enc.len() != 24
                    || wrap.wrapped_ck.len() != 32 + HPKE_AEAD_TAG_LEN
                {
                    return Err(err(StatusCode::BAD_REQUEST, "invalid key wrap"));
                }
                phrase += 1;
            }
            _ => return Err(err(StatusCode::BAD_REQUEST, "invalid key wrap")),
        }
    }
    if device != 1 || recovery != 1 || phrase != 1 {
        return Err(err(StatusCode::BAD_REQUEST, "invalid key wrap"));
    }
    Ok(())
}

/// The new wraps must cover every remaining device exactly once, plus the
/// password and phrase recipients, and nothing else.
pub(crate) fn validate_rotation_wraps(
    remaining: &[String],
    username: &str,
    wraps: &[KeyWrapBody],
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let mut devices: Vec<String> = Vec::new();
    let mut recovery = 0;
    let mut phrase = 0;
    for wrap in wraps {
        match wrap.recipient_kind.as_str() {
            "device" => {
                if wrap.ciphersuite != XWING_CIPHERSUITE
                    || wrap.hpke_enc.len() != XWING_ENCAPSULATED_KEY_LEN
                    || wrap.wrapped_ck.len() != 32 + HPKE_AEAD_TAG_LEN
                {
                    return Err(err(StatusCode::BAD_REQUEST, "invalid key wrap"));
                }
                devices.push(wrap.recipient_id.clone());
            }
            "recovery" => {
                if !is_supported_recovery_ciphersuite(&wrap.ciphersuite)
                    || wrap.hpke_enc.len() != 24
                    || wrap.wrapped_ck.len() != 32 + HPKE_AEAD_TAG_LEN
                {
                    return Err(err(StatusCode::BAD_REQUEST, "invalid key wrap"));
                }
                recovery += 1;
            }
            "phrase" => {
                if wrap.recipient_id != username
                    || wrap.ciphersuite != PHRASE_CIPHERSUITE
                    || wrap.hpke_enc.len() != 24
                    || wrap.wrapped_ck.len() != 32 + HPKE_AEAD_TAG_LEN
                {
                    return Err(err(StatusCode::BAD_REQUEST, "invalid key wrap"));
                }
                phrase += 1;
            }
            _ => return Err(err(StatusCode::BAD_REQUEST, "invalid key wrap")),
        }
    }
    if recovery != 1 || phrase != 1 {
        return Err(err(StatusCode::BAD_REQUEST, "invalid key wrap"));
    }
    devices.sort();
    devices.dedup();
    let mut expected = remaining.to_vec();
    expected.sort();
    if devices != expected {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "rotation must re-wrap for exactly the remaining devices",
        ));
    }
    Ok(())
}

pub(crate) fn validate_rotated_object(
    object: &RotatedObject,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    validate_encrypted(
        &object.content_type,
        &object.nonce,
        &object.ciphertext,
        object.padded_size,
        object.tombstone,
    )
}

pub(crate) fn validate_object(
    body: &PutObjectRequest,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    validate_encrypted(
        &body.content_type,
        &body.nonce,
        &body.ciphertext,
        body.padded_size,
        body.tombstone,
    )
}

/// Shape checks every encrypted object must pass, however it arrives.
fn validate_encrypted(
    content_type: &str,
    nonce: &[u8],
    ciphertext: &[u8],
    padded_size: usize,
    tombstone: bool,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let valid_content_type = matches!(
        content_type,
        JSCONTACT_CONTENT_TYPE
            | ADDRESS_BOOK_CONTENT_TYPE
            | CALENDAR_EVENT_CONTENT_TYPE
            | CALENDAR_CONTENT_TYPE
    );
    if !valid_content_type || content_type.len() > 128 {
        return Err(err(StatusCode::BAD_REQUEST, "invalid content type"));
    }
    if tombstone && nonce.is_empty() && ciphertext.is_empty() && padded_size == 0 {
        return Ok(());
    }
    if nonce.len() != 24
        || !(MIN_PADDED_OBJECT_SIZE..=MAX_PADDED_OBJECT_SIZE).contains(&padded_size)
        || ciphertext.len() != padded_size + 16
    {
        return Err(err(StatusCode::BAD_REQUEST, "invalid encrypted object"));
    }
    Ok(())
}
