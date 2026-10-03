use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Absorbs a length-prefixed field, so that concatenating different field
/// splits cannot produce the same digest.
///
/// Every transcript in this module uses this for each field whose length can
/// vary, and plain `update` only for fields the type fixes: a `Uuid`, a `u64`, a
/// `[u8; 32]`. Keeping to that is what stops a field added next to a variable one
/// from reintroducing an ambiguity.
pub(crate) fn absorb(h: &mut Sha256, field: &[u8]) {
    h.update((field.len() as u64).to_be_bytes());
    h.update(field);
}

/// One collection-key wrap, as it appears in a rotation request.
pub struct WrapDigestEntry<'a> {
    pub recipient_kind: &'a str,
    pub recipient_id: &'a str,
    pub hpke_enc: &'a [u8],
    pub wrapped_ck: &'a [u8],
    pub ciphersuite: &'a str,
}

/// One re-encrypted object, as it appears in a rotation request.
pub struct ObjectDigestEntry<'a> {
    pub id: Uuid,
    pub revision: u64,
    pub nonce: &'a [u8],
    pub ciphertext: &'a [u8],
    pub padded_size: u64,
    pub content_type: &'a str,
    pub tombstone: bool,
}

/// Digest of the new key wraps, in the order they are sent.
pub fn key_wraps_digest(entries: &[WrapDigestEntry<'_>]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sealbook-rotation-wraps-v1");
    h.update((entries.len() as u64).to_be_bytes());
    for entry in entries {
        absorb(&mut h, entry.recipient_kind.as_bytes());
        absorb(&mut h, entry.recipient_id.as_bytes());
        absorb(&mut h, entry.hpke_enc);
        absorb(&mut h, entry.wrapped_ck);
        absorb(&mut h, entry.ciphersuite.as_bytes());
    }
    h.finalize().into()
}

/// Digest of the re-encrypted objects, in the order they are sent.
pub fn rotated_objects_digest(entries: &[ObjectDigestEntry<'_>]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sealbook-rotation-objects-v1");
    h.update((entries.len() as u64).to_be_bytes());
    for entry in entries {
        absorb(&mut h, entry.id.as_bytes());
        absorb(&mut h, &entry.revision.to_be_bytes());
        absorb(&mut h, entry.nonce);
        absorb(&mut h, entry.ciphertext);
        absorb(&mut h, &entry.padded_size.to_be_bytes());
        absorb(&mut h, entry.content_type.as_bytes());
        absorb(&mut h, &[u8::from(entry.tombstone)]);
    }
    h.finalize().into()
}

/// One object as the manifest commits to it.
#[derive(Clone)]
pub struct ManifestDigestEntry {
    pub id: Uuid,
    pub revision: u64,
    pub tombstone: bool,
    /// `SHA-256(nonce || ciphertext)`.
    pub content_digest: [u8; 32],
}

pub const MANIFEST_BUCKETS: usize = 256;
pub fn manifest_bucket_of(id: Uuid) -> u8 {
    id.as_bytes()[0]
}

pub fn manifest_bucket_digest(entries: &[ManifestDigestEntry]) -> [u8; 32] {
    let mut sorted: Vec<&ManifestDigestEntry> = entries.iter().collect();
    sorted.sort_by_key(|entry| *entry.id.as_bytes());
    let mut h = Sha256::new();
    h.update(b"sealbook-manifest-bucket-v1");
    h.update((sorted.len() as u64).to_be_bytes());
    for entry in sorted {
        absorb(&mut h, entry.id.as_bytes());
        absorb(&mut h, &entry.revision.to_be_bytes());
        absorb(&mut h, &[u8::from(entry.tombstone)]);
        absorb(&mut h, &entry.content_digest);
    }
    h.finalize().into()
}

pub fn manifest_root(buckets: &[[u8; 32]; MANIFEST_BUCKETS], object_count: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sealbook-manifest-v1");
    h.update(object_count.to_be_bytes());
    for bucket in buckets.iter() {
        h.update(bucket);
    }
    h.finalize().into()
}

/// Digest of a collection's entire contents.
pub fn manifest_digest(entries: &[ManifestDigestEntry]) -> [u8; 32] {
    let mut buckets = [[0u8; 32]; MANIFEST_BUCKETS];
    let mut grouped: Vec<Vec<&ManifestDigestEntry>> = vec![Vec::new(); MANIFEST_BUCKETS];
    for entry in entries {
        grouped[manifest_bucket_of(entry.id) as usize].push(entry);
    }
    for (bucket, members) in buckets.iter_mut().zip(grouped) {
        // An empty bucket stays all zeroes rather than being hashed, so a vault
        // with nothing in it costs nothing to describe and the root still binds
        // the count.
        if members.is_empty() {
            continue;
        }
        let owned: Vec<ManifestDigestEntry> = members.into_iter().cloned().collect();
        *bucket = manifest_bucket_digest(&owned);
    }
    manifest_root(&buckets, entries.len() as u64)
}

/// `SHA-256(nonce || ciphertext)`, the per-object commitment inside a manifest.
pub fn content_digest(nonce: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(nonce);
    h.update(ciphertext);
    h.finalize().into()
}

/// Signed by the writing device over the state of the collection after its write.
pub fn manifest_transcript(
    collection_id: Uuid,
    manifest_seq: u64,
    key_epoch: u64,
    latest_revision: u64,
    object_count: u64,
    digest: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sealbook-manifest-sig-v1");
    h.update(collection_id.as_bytes());
    h.update(manifest_seq.to_be_bytes());
    h.update(key_epoch.to_be_bytes());
    h.update(latest_revision.to_be_bytes());
    h.update(object_count.to_be_bytes());
    h.update(digest);
    h.finalize().into()
}

/// Signed by the device performing an account mutation.
pub fn account_op_transcript(
    op: &str,
    challenge_id: Uuid,
    challenge: &[u8],
    account_id: &str,
    device_id: Uuid,
    payload: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sealbook-account-op-v1");
    absorb(&mut h, op.as_bytes());
    h.update(challenge_id.as_bytes());
    absorb(&mut h, challenge);
    absorb(&mut h, account_id.as_bytes());
    h.update(device_id.as_bytes());
    h.update(payload);
    h.finalize().into()
}

/// Digest of the payload of a username change.
pub fn username_change_payload(new_username: &str, upload: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sealbook-op-username-v1");
    absorb(&mut h, new_username.as_bytes());
    absorb(&mut h, upload);
    h.finalize().into()
}

/// Digest of the payload of a password change.
///
/// This binds the new password verifier *and* the replacement recovery wrap, so a
/// caller cannot substitute key material the account holder never produced —
/// which was the way a stolen token could destroy password-based recovery.
pub fn password_change_payload(
    upload: &[u8],
    kdf_salt: &[u8],
    recovery_nonce: &[u8],
    recovery_wrapped_ck: &[u8],
    recovery_ciphersuite: &str,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sealbook-op-password-v1");
    absorb(&mut h, upload);
    absorb(&mut h, kdf_salt);
    absorb(&mut h, recovery_nonce);
    absorb(&mut h, recovery_wrapped_ck);
    absorb(&mut h, recovery_ciphersuite.as_bytes());
    h.finalize().into()
}

/// Digest of the payload of an account deletion, which carries nothing of its own.
pub fn delete_account_payload() -> [u8; 32] {
    Sha256::digest(b"sealbook-op-delete-v1").into()
}

/// Digest of the account-level recovery material a rotation installs.
///
/// A rotation replaces the password KDF salt and the entire recovery-phrase
/// verification record. Neither of those is a key wrap, so neither was covered by
/// `key_wraps_digest`, and both went into `accounts` unauthenticated. Anything
/// able to modify a rotation request body — a tampering reverse proxy, say, which
/// in `proxy` TLS mode terminates the connection clients verify — could therefore
/// substitute a `lookup_id` and phrase verification key it controls, and then
/// enrol a device of its own through the recovery flow.
///
/// `password_change_payload` already binds its replacement recovery material for
/// exactly this reason. This is the same commitment for the rotation path.
pub fn rotation_recovery_payload(
    kdf_salt: &[u8],
    phrase_mldsa_pk: &[u8],
    phrase_ed25519_pk: &[u8],
    phrase_lookup_id: &[u8],
    phrase_scheme: &str,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sealbook-rotation-recovery-v1");
    absorb(&mut h, kdf_salt);
    absorb(&mut h, phrase_mldsa_pk);
    absorb(&mut h, phrase_ed25519_pk);
    absorb(&mut h, phrase_lookup_id);
    absorb(&mut h, phrase_scheme.as_bytes());
    h.finalize().into()
}

/// Signed by the rotating device, binding the whole rotation: which device is
/// being removed, the new key epoch, every new wrap, every re-encrypted object,
/// and the recovery material the rotation installs. Without this a stolen session
/// token alone could re-key the vault.
pub fn key_rotation_transcript(
    collection_id: Uuid,
    revoked_device_id: Option<Uuid>,
    key_epoch: u64,
    wraps_digest: &[u8; 32],
    objects_digest: &[u8; 32],
    manifest_digest: &[u8; 32],
    recovery_payload: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sealbook-key-rotation-v1");
    h.update(collection_id.as_bytes());
    // A presence byte, so "rotate without revoking" cannot collide with revoking
    // some device whose id happens to be all zeroes.
    h.update([u8::from(revoked_device_id.is_some())]);
    h.update(revoked_device_id.unwrap_or(Uuid::nil()).as_bytes());
    h.update(key_epoch.to_be_bytes());
    h.update(wraps_digest);
    h.update(objects_digest);
    h.update(manifest_digest);
    h.update(recovery_payload);
    h.finalize().into()
}

/// Signed by a device over the keys it is enrolling.
///
/// The three public keys are length-prefixed. They are adjacent and all three
/// are typed as variable, so raw concatenation left the only thing fixing their
/// boundaries outside the digest: that an ML-DSA-65 key is 1952 bytes and an
/// Ed25519 key is 32, which `verify` enforces incidentally rather than this
/// transcript stating it.
pub fn enrollment_transcript(
    device_id: Uuid,
    mldsa_pk: &[u8],
    ed25519_pk: &[u8],
    xwing_hpke_pk: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sealbook-enroll-v2");
    h.update(device_id.as_bytes());
    absorb(&mut h, mldsa_pk);
    absorb(&mut h, ed25519_pk);
    absorb(&mut h, xwing_hpke_pk);
    h.finalize().into()
}

/// Signed by the approving device over the device a pairing enrols.
///
/// Length-prefixed for the same reason as `enrollment_transcript`, with one more
/// variable field after the keys.
#[allow(clippy::too_many_arguments)]
pub fn pair_grant_transcript(
    pair_id: Uuid,
    approver_device_id: Uuid,
    new_device_id: Uuid,
    mldsa_pk: &[u8],
    ed25519_pk: &[u8],
    xwing_hpke_pk: &[u8],
    confirm: &str,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sealbook-pair-v2");
    h.update(pair_id.as_bytes());
    h.update(approver_device_id.as_bytes());
    h.update(new_device_id.as_bytes());
    absorb(&mut h, mldsa_pk);
    absorb(&mut h, ed25519_pk);
    absorb(&mut h, xwing_hpke_pk);
    absorb(&mut h, confirm.as_bytes());
    h.finalize().into()
}

/// Number of base-32 characters in a pairing confirmation code.
///
/// 26 characters carry 130 bits, which keeps a second-preimage search against
/// the code above the 128-bit post-quantum target used elsewhere. The previous
/// 13-character code carried only 65 bits.
pub const PAIR_CONFIRMATION_LEN: usize = 26;

const _: () = assert!(
    PAIR_CONFIRMATION_LEN * 5 >= 128,
    "pairing confirmation code must carry at least 128 bits"
);
const _: () = assert!(
    PAIR_CONFIRMATION_LEN.div_ceil(8) * 5 <= 32,
    "pairing confirmation code must fit in a SHA-256 digest"
);

/// The code both screens show during a pairing, which the user compares.
pub fn pair_confirmation(
    pair_id: Uuid,
    device_id: Uuid,
    mldsa_pk: &[u8],
    ed25519_pk: &[u8],
    xwing_hpke_pk: &[u8],
    roster_seq: u64,
    roster_transcript: &[u8],
) -> String {
    const ALPH: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut h = Sha256::new();
    h.update(b"sealbook-pair-confirm-v2");
    h.update(pair_id.as_bytes());
    h.update(device_id.as_bytes());
    absorb(&mut h, mldsa_pk);
    absorb(&mut h, ed25519_pk);
    absorb(&mut h, xwing_hpke_pk);
    h.update(roster_seq.to_be_bytes());
    absorb(&mut h, roster_transcript);
    let digest = h.finalize();
    let mut code = String::with_capacity(PAIR_CONFIRMATION_LEN);
    for index in 0..PAIR_CONFIRMATION_LEN {
        let mut value = 0u8;
        for bit in 0..5 {
            let bit_index = index * 5 + bit;
            value |= ((digest[bit_index / 8] >> (bit_index % 8)) & 1) << bit;
        }
        code.push(ALPH[value as usize] as char);
    }
    code
}

/// Signed by the device before the server releases an OPAQUE credential
/// response, binding the opened login challenge to this OPAQUE request.
pub fn login_start_transcript(
    challenge_id: Uuid,
    username: &str,
    device_id: Uuid,
    challenge: &[u8; 32],
    opaque_request: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sealbook-login-start-v2");
    h.update(challenge_id.as_bytes());
    absorb(&mut h, username.as_bytes());
    h.update(device_id.as_bytes());
    h.update(challenge);
    absorb(&mut h, opaque_request);
    h.finalize().into()
}

pub fn login_transcript(
    login_id: Uuid,
    username: &str,
    device_id: Uuid,
    finalization: &[u8],
    challenge: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sealbook-login-v2");
    h.update(login_id.as_bytes());
    absorb(&mut h, username.as_bytes());
    h.update(device_id.as_bytes());
    absorb(&mut h, finalization);
    h.update(challenge);
    h.finalize().into()
}

/// Digest of the credentials a recovery installs.
///
/// A recovery replaces the password, because the phrase exists for the case where
/// the password is the thing that was lost. That makes the new OPAQUE record, the
/// KDF salt and the re-made password wrap of the collection key part of what the
/// phrase has to vouch for: unbound, anything able to rewrite the request body
/// could swap in a password of its own and take the account. This is
/// `password_change_payload`'s reasoning applied to the recovery path.
pub fn recovery_password_payload(
    upload: &[u8],
    kdf_salt: &[u8],
    recovery_nonce: &[u8],
    recovery_wrapped_ck: &[u8],
    recovery_ciphersuite: &str,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sealbook-recovery-password-v1");
    absorb(&mut h, upload);
    absorb(&mut h, kdf_salt);
    absorb(&mut h, recovery_nonce);
    absorb(&mut h, recovery_wrapped_ck);
    absorb(&mut h, recovery_ciphersuite.as_bytes());
    h.finalize().into()
}

/// Signed with the recovery phrase's key to enrol a device and reset the password.
///
/// Fields are length-prefixed: `username` and `challenge` both vary in length, and
/// raw concatenation let one borrow bytes from the other.
#[allow(clippy::too_many_arguments)]
pub fn phrase_recovery_transcript(
    username: &str,
    recovery_id: Uuid,
    challenge: &[u8],
    device_id: Uuid,
    mldsa_pk: &[u8],
    ed25519_pk: &[u8],
    xwing_hpke_pk: &[u8],
    password_payload: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sealbook-phrase-recovery-v2");
    absorb(&mut h, username.as_bytes());
    h.update(recovery_id.as_bytes());
    absorb(&mut h, challenge);
    h.update(device_id.as_bytes());
    absorb(&mut h, mldsa_pk);
    absorb(&mut h, ed25519_pk);
    absorb(&mut h, xwing_hpke_pk);
    h.update(password_payload);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_transcript_binds_the_password_it_installs() {
        let recovery_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let payload = |upload: &[u8], salt: &[u8]| {
            recovery_password_payload(upload, salt, b"nonce", b"wrapped", "suite")
        };
        let sign = |payload: &[u8; 32]| {
            phrase_recovery_transcript(
                "alice",
                recovery_id,
                b"challenge",
                device_id,
                b"mldsa",
                b"ed",
                b"xwing",
                payload,
            )
        };
        let base = sign(&payload(b"upload", b"salt"));
        assert_ne!(
            base,
            sign(&payload(b"other", b"salt")),
            "the new password verifier must be bound"
        );
        assert_ne!(
            base,
            sign(&payload(b"upload", b"salt2")),
            "the new kdf salt must be bound"
        );
        // Length prefixing: a byte moved across a field boundary must show up.
        assert_ne!(
            phrase_recovery_transcript(
                "alic",
                recovery_id,
                b"echallenge",
                device_id,
                b"mldsa",
                b"ed",
                b"xwing",
                &payload(b"upload", b"salt"),
            ),
            base,
        );
    }

    #[test]
    fn pair_confirmation_binds_joiner_keys_and_the_roster_anchor() {
        let pair_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let anchor = [9u8; 32];
        let first = pair_confirmation(pair_id, device_id, b"mldsa", b"ed", b"xwing", 4, &anchor);
        let keys = pair_confirmation(pair_id, device_id, b"changed", b"ed", b"xwing", 4, &anchor);
        assert_eq!(first.len(), PAIR_CONFIRMATION_LEN);
        assert_ne!(first, keys);
        // Bug #9: the roster a joining device was told to anchor on has to change
        // the code, or the user comparing two codes confirms only one direction.
        let other_roster =
            pair_confirmation(pair_id, device_id, b"mldsa", b"ed", b"xwing", 4, &[8u8; 32]);
        assert_ne!(first, other_roster);
        let other_seq =
            pair_confirmation(pair_id, device_id, b"mldsa", b"ed", b"xwing", 5, &anchor);
        assert_ne!(first, other_seq);
    }

    #[test]
    fn rotation_digests_are_order_and_boundary_sensitive() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let wrap = |kind: &'static str, id: &'static str| WrapDigestEntry {
            recipient_kind: kind,
            recipient_id: id,
            hpke_enc: b"enc",
            wrapped_ck: b"ct",
            ciphersuite: "suite",
        };
        let first = key_wraps_digest(&[wrap("device", "one"), wrap("phrase", "two")]);
        let reordered = key_wraps_digest(&[wrap("phrase", "two"), wrap("device", "one")]);
        assert_ne!(first, reordered, "wrap order must be bound");

        // Length prefixing: moving a byte across a field boundary must change
        // the digest, otherwise fields could be shifted undetectably.
        let split_a = key_wraps_digest(&[wrap("devic", "eone")]);
        let split_b = key_wraps_digest(&[wrap("device", "one")]);
        assert_ne!(split_a, split_b);

        let object = |id: Uuid, tombstone: bool| ObjectDigestEntry {
            id,
            revision: 1,
            nonce: b"nonce",
            ciphertext: b"ct",
            padded_size: 256,
            content_type: "application/jscontact+json",
            tombstone,
        };
        assert_ne!(
            rotated_objects_digest(&[object(a, false), object(b, false)]),
            rotated_objects_digest(&[object(b, false), object(a, false)]),
        );
        assert_ne!(
            rotated_objects_digest(&[object(a, false)]),
            rotated_objects_digest(&[object(a, true)]),
        );
    }

    #[test]
    fn rotation_transcript_binds_every_component() {
        let collection = Uuid::new_v4();
        let revoked = Uuid::new_v4();
        let wraps = [1u8; 32];
        let objects = [2u8; 32];
        let manifest = [3u8; 32];
        let recovery = [4u8; 32];
        let sign = |collection,
                    revoked,
                    epoch,
                    wraps: &[u8; 32],
                    objects: &[u8; 32],
                    manifest: &[u8; 32],
                    recovery: &[u8; 32]| {
            key_rotation_transcript(
                collection, revoked, epoch, wraps, objects, manifest, recovery,
            )
        };
        let base = sign(
            collection,
            Some(revoked),
            2,
            &wraps,
            &objects,
            &manifest,
            &recovery,
        );

        for (changed, why) in [
            (
                sign(
                    collection,
                    Some(revoked),
                    3,
                    &wraps,
                    &objects,
                    &manifest,
                    &recovery,
                ),
                "the key epoch must be bound",
            ),
            (
                sign(
                    collection,
                    Some(Uuid::new_v4()),
                    2,
                    &wraps,
                    &objects,
                    &manifest,
                    &recovery,
                ),
                "which device is revoked must be bound",
            ),
            (
                sign(
                    Uuid::new_v4(),
                    Some(revoked),
                    2,
                    &wraps,
                    &objects,
                    &manifest,
                    &recovery,
                ),
                "the collection must be bound",
            ),
            (
                sign(
                    collection,
                    Some(revoked),
                    2,
                    &[9u8; 32],
                    &objects,
                    &manifest,
                    &recovery,
                ),
                "the new key wraps must be bound",
            ),
            (
                sign(
                    collection,
                    Some(revoked),
                    2,
                    &wraps,
                    &[9u8; 32],
                    &manifest,
                    &recovery,
                ),
                "the re-encrypted objects must be bound",
            ),
            (
                sign(
                    collection,
                    Some(revoked),
                    2,
                    &wraps,
                    &objects,
                    &[9u8; 32],
                    &recovery,
                ),
                "the manifest must be bound into the rotation",
            ),
            (
                sign(
                    collection,
                    Some(revoked),
                    2,
                    &wraps,
                    &objects,
                    &manifest,
                    &[9u8; 32],
                ),
                "the recovery material the rotation installs must be bound",
            ),
            (
                sign(collection, None, 2, &wraps, &objects, &manifest, &recovery),
                "revoking a device must not collide with rotating without one",
            ),
        ] {
            assert_ne!(base, changed, "{why}");
        }
    }

    /// Every field of the recovery record has to move the digest, or a tampering
    /// proxy could change the one field the signature happened not to reach.
    #[test]
    fn rotation_recovery_payload_binds_every_field() {
        let base = rotation_recovery_payload(b"salt", b"mldsa", b"ed25519", b"lookup", "scheme");
        for (changed, why) in [
            (
                rotation_recovery_payload(b"SALT", b"mldsa", b"ed25519", b"lookup", "scheme"),
                "kdf salt",
            ),
            (
                rotation_recovery_payload(b"salt", b"MLDSA", b"ed25519", b"lookup", "scheme"),
                "phrase ml-dsa public key",
            ),
            (
                rotation_recovery_payload(b"salt", b"mldsa", b"ED25519", b"lookup", "scheme"),
                "phrase ed25519 public key",
            ),
            (
                rotation_recovery_payload(b"salt", b"mldsa", b"ed25519", b"LOOKUP", "scheme"),
                "phrase lookup id",
            ),
            (
                rotation_recovery_payload(b"salt", b"mldsa", b"ed25519", b"lookup", "SCHEME"),
                "phrase scheme",
            ),
        ] {
            assert_ne!(base, changed, "{why} must be bound");
        }

        // Length prefixing, so moving a byte across a field boundary is a
        // different digest rather than the same one.
        assert_ne!(
            rotation_recovery_payload(b"ab", b"c", b"d", b"e", "f"),
            rotation_recovery_payload(b"a", b"bc", b"d", b"e", "f"),
        );
    }

    /// Bug #10. Every transcript length-prefixes its variable fields, so a byte
    /// moved across a field boundary is a different digest. Of these,
    /// `enrollment_transcript` and `pair_grant_transcript` were the ones with a
    /// real ambiguity: three or four adjacent variable fields, held apart only by
    /// `verify` happening to reject a key of the wrong length. The two login
    /// transcripts interleave theirs with fixed-size fields, so they could not be
    /// shifted even before this; they are uniform now so that the next field
    /// added to one of them does not have to be the one that notices.
    #[test]
    fn every_transcript_binds_its_field_boundaries() {
        let one = Uuid::new_v4();
        let two = Uuid::new_v4();
        let three = Uuid::new_v4();
        let challenge = [7u8; 32];

        assert_ne!(
            enrollment_transcript(one, b"ab", b"c", b"d"),
            enrollment_transcript(one, b"a", b"bc", b"d"),
            "the enrolled signing keys must not be able to borrow bytes from each other"
        );
        assert_ne!(
            enrollment_transcript(one, b"a", b"bc", b"d"),
            enrollment_transcript(one, b"a", b"b", b"cd"),
            "the hpke key boundary must bind"
        );

        assert_ne!(
            pair_grant_transcript(one, two, three, b"ab", b"c", b"d", "e"),
            pair_grant_transcript(one, two, three, b"a", b"bc", b"d", "e"),
        );
        assert_ne!(
            pair_grant_transcript(one, two, three, b"a", b"b", b"cd", "e"),
            pair_grant_transcript(one, two, three, b"a", b"b", b"c", "de"),
            "the confirmation code boundary must bind"
        );

        assert_ne!(
            login_start_transcript(one, "ab", two, &challenge, b"c"),
            login_start_transcript(one, "a", two, &challenge, b"bc"),
        );
        assert_ne!(
            login_transcript(one, "ab", two, b"c", &challenge),
            login_transcript(one, "a", two, b"bc", &challenge),
        );
    }

    #[test]
    fn login_start_transcript_binds_the_opaque_request() {
        let challenge_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let challenge = [4u8; 32];
        let base = login_start_transcript(challenge_id, "ada", device_id, &challenge, b"request");
        assert_ne!(
            base,
            login_start_transcript(challenge_id, "ada", device_id, &challenge, b"tampered")
        );
        assert_ne!(
            base,
            login_start_transcript(challenge_id, "ada", device_id, &[5u8; 32], b"request")
        );
        assert_ne!(
            base,
            login_start_transcript(challenge_id, "bob", device_id, &challenge, b"request")
        );
    }

    /// The property the server's incremental path stands on: rebuilding the root
    /// from per-bucket digests must equal hashing the whole set in one pass. If
    /// these ever disagree, a client and the server disagree about the vault and
    /// every write is refused.
    #[test]
    fn the_root_from_per_bucket_digests_equals_the_whole_set_digest() {
        for count in [0usize, 1, 2, 7, 64, 500, 2_000] {
            let entries: Vec<ManifestDigestEntry> = (0..count)
                .map(|index| ManifestDigestEntry {
                    id: Uuid::new_v4(),
                    revision: index as u64 + 1,
                    tombstone: index % 5 == 0,
                    content_digest: [index as u8; 32],
                })
                .collect();

            // What a writer does: group by bucket, hash each bucket, hash the root.
            let mut buckets = [[0u8; 32]; MANIFEST_BUCKETS];
            for (index, bucket) in buckets.iter_mut().enumerate() {
                let members: Vec<ManifestDigestEntry> = entries
                    .iter()
                    .filter(|entry| manifest_bucket_of(entry.id) as usize == index)
                    .cloned()
                    .collect();
                if !members.is_empty() {
                    *bucket = manifest_bucket_digest(&members);
                }
            }

            assert_eq!(
                manifest_root(&buckets, entries.len() as u64),
                manifest_digest(&entries),
                "incremental and whole-set digests disagree at {count} entries"
            );
        }
    }

    #[test]
    fn a_write_changes_only_its_own_bucket() {
        let entries: Vec<ManifestDigestEntry> = (0..200)
            .map(|index| ManifestDigestEntry {
                id: Uuid::new_v4(),
                revision: index as u64 + 1,
                tombstone: false,
                content_digest: [index as u8; 32],
            })
            .collect();
        let bucket_of = |entries: &[ManifestDigestEntry], bucket: usize| -> [u8; 32] {
            let members: Vec<ManifestDigestEntry> = entries
                .iter()
                .filter(|entry| manifest_bucket_of(entry.id) as usize == bucket)
                .cloned()
                .collect();
            if members.is_empty() {
                [0u8; 32]
            } else {
                manifest_bucket_digest(&members)
            }
        };

        let mut changed = entries.clone();
        changed[7].revision += 1;
        let touched = manifest_bucket_of(entries[7].id) as usize;

        assert_ne!(
            manifest_digest(&entries),
            manifest_digest(&changed),
            "a revision bump must change the root"
        );
        assert_ne!(
            bucket_of(&entries, touched),
            bucket_of(&changed, touched),
            "the object's own bucket must change"
        );
        for bucket in 0..MANIFEST_BUCKETS {
            if bucket == touched {
                continue;
            }
            assert_eq!(
                bucket_of(&entries, bucket),
                bucket_of(&changed, bucket),
                "bucket {bucket} changed although nothing in it did"
            );
        }
    }

    /// An entry must not be movable to another bucket without changing the root.
    #[test]
    fn the_root_binds_which_bucket_an_entry_is_in() {
        let mut buckets = [[0u8; 32]; MANIFEST_BUCKETS];
        buckets[3] = [1u8; 32];
        let base = manifest_root(&buckets, 1);
        let mut moved = [[0u8; 32]; MANIFEST_BUCKETS];
        moved[4] = [1u8; 32];
        assert_ne!(base, manifest_root(&moved, 1), "bucket position must bind");
        assert_ne!(base, manifest_root(&buckets, 2), "the count must bind");
    }

    #[test]
    fn a_manifest_digest_commits_to_revision_and_content() {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let entry = |id: Uuid, revision: u64, tombstone: bool, byte: u8| ManifestDigestEntry {
            id,
            revision,
            tombstone,
            content_digest: [byte; 32],
        };
        let base = manifest_digest(&[entry(first, 1, false, 1), entry(second, 2, false, 2)]);

        // Order must not matter: the client and the server sort independently.
        assert_eq!(
            base,
            manifest_digest(&[entry(second, 2, false, 2), entry(first, 1, false, 1)]),
        );
        // Everything else must.
        assert_ne!(
            base,
            manifest_digest(&[entry(first, 9, false, 1), entry(second, 2, false, 2)]),
            "a rolled-back revision must change the digest"
        );
        assert_ne!(
            base,
            manifest_digest(&[entry(first, 1, false, 9), entry(second, 2, false, 2)]),
            "substituted ciphertext must change the digest"
        );
        assert_ne!(
            base,
            manifest_digest(&[entry(first, 1, true, 1), entry(second, 2, false, 2)]),
        );
        assert_ne!(
            base,
            manifest_digest(&[entry(first, 1, false, 1)]),
            "a withheld object must change the digest"
        );
    }

    #[test]
    fn account_op_transcripts_do_not_cross_over() {
        let challenge_id = Uuid::new_v4();
        let device = Uuid::new_v4();
        let challenge = [7u8; 32];
        let rename = account_op_transcript(
            "username",
            challenge_id,
            &challenge,
            "account",
            device,
            &username_change_payload("newname", b"upload"),
        );
        let delete = account_op_transcript(
            "delete",
            challenge_id,
            &challenge,
            "account",
            device,
            &delete_account_payload(),
        );
        assert_ne!(rename, delete, "operations must be distinguishable");

        // A fresh challenge must produce a fresh transcript, or a captured
        // signature could be replayed.
        assert_ne!(
            rename,
            account_op_transcript(
                "username",
                challenge_id,
                &[8u8; 32],
                "account",
                device,
                &username_change_payload("newname", b"upload"),
            )
        );
        // And the payload must be bound.
        assert_ne!(
            rename,
            account_op_transcript(
                "username",
                challenge_id,
                &challenge,
                "account",
                device,
                &username_change_payload("attacker", b"upload"),
            )
        );
    }

    #[test]
    fn a_password_change_binds_its_replacement_recovery_wrap() {
        let base = password_change_payload(b"upload", b"salt", b"nonce", b"wrapped", "suite");
        assert_ne!(
            base,
            password_change_payload(b"upload", b"salt", b"nonce", b"other", "suite"),
            "the recovery wrap must be signed, or it can be replaced with garbage"
        );
        assert_ne!(
            base,
            password_change_payload(b"upload", b"other", b"nonce", b"wrapped", "suite")
        );
    }
}
