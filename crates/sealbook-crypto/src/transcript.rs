use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Absorbs a length-prefixed field, so that concatenating different field
/// splits cannot produce the same digest.
fn absorb(h: &mut Sha256, field: &[u8]) {
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
pub struct ManifestDigestEntry {
    pub id: Uuid,
    pub revision: u64,
    pub tombstone: bool,
    /// `SHA-256(nonce || ciphertext)`.
    pub content_digest: [u8; 32],
}

/// Digest of a collection's entire contents.
///
/// Entries are sorted by object id here rather than trusting the caller's order,
/// so a client and the server always agree on the digest without having to agree
/// on an iteration order as well.
///
/// Committing to `content_digest` alongside the revision is the part that makes a
/// rollback visible. Without it a server could serve the ciphertext from an older
/// revision under the current revision number and nothing would notice.
pub fn manifest_digest(entries: &[ManifestDigestEntry]) -> [u8; 32] {
    let mut sorted: Vec<&ManifestDigestEntry> = entries.iter().collect();
    sorted.sort_by_key(|entry| *entry.id.as_bytes());
    let mut h = Sha256::new();
    h.update(b"sealbook-manifest-v1");
    h.update((sorted.len() as u64).to_be_bytes());
    for entry in sorted {
        absorb(&mut h, entry.id.as_bytes());
        absorb(&mut h, &entry.revision.to_be_bytes());
        absorb(&mut h, &[u8::from(entry.tombstone)]);
        absorb(&mut h, &entry.content_digest);
    }
    h.finalize().into()
}

/// `SHA-256(nonce || ciphertext)`, the per-object commitment inside a manifest.
pub fn content_digest(nonce: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(nonce);
    h.update(ciphertext);
    h.finalize().into()
}

/// Signed by the writing device over the state of the collection after its write.
///
/// The server verifies every scalar here against its own tables before storing
/// it, so a stored manifest is a device-signed statement of the truth rather than
/// of whatever the client claimed.
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
///
/// `op` names the operation and `payload` digests whatever that operation
/// carries, so a signature for one change cannot be replayed as another. The
/// server-issued challenge makes it fresh: a captured signature is useless once
/// the challenge is consumed.
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

pub fn enrollment_transcript(
    device_id: Uuid,
    mldsa_pk: &[u8],
    ed25519_pk: &[u8],
    xwing_hpke_pk: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sealbook-enroll-v1");
    h.update(device_id.as_bytes());
    h.update(mldsa_pk);
    h.update(ed25519_pk);
    h.update(xwing_hpke_pk);
    h.finalize().into()
}

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
    h.update(b"sealbook-pair-v1");
    h.update(pair_id.as_bytes());
    h.update(approver_device_id.as_bytes());
    h.update(new_device_id.as_bytes());
    h.update(mldsa_pk);
    h.update(ed25519_pk);
    h.update(xwing_hpke_pk);
    h.update(confirm.as_bytes());
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

pub fn pair_confirmation(
    pair_id: Uuid,
    device_id: Uuid,
    mldsa_pk: &[u8],
    ed25519_pk: &[u8],
    xwing_hpke_pk: &[u8],
) -> String {
    const ALPH: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut h = Sha256::new();
    h.update(b"sealbook-pair-confirm-v1");
    h.update(pair_id.as_bytes());
    h.update(device_id.as_bytes());
    h.update(mldsa_pk);
    h.update(ed25519_pk);
    h.update(xwing_hpke_pk);
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
    h.update(b"sealbook-login-start-v1");
    h.update(challenge_id.as_bytes());
    h.update(username.as_bytes());
    h.update(device_id.as_bytes());
    h.update(challenge);
    h.update(opaque_request);
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
    h.update(b"sealbook-login-v1");
    h.update(login_id.as_bytes());
    h.update(username.as_bytes());
    h.update(device_id.as_bytes());
    h.update(finalization);
    h.update(challenge);
    h.finalize().into()
}

pub fn phrase_recovery_transcript(
    username: &str,
    recovery_id: Uuid,
    challenge: &[u8],
    device_id: Uuid,
    mldsa_pk: &[u8],
    ed25519_pk: &[u8],
    xwing_hpke_pk: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sealbook-phrase-recovery-v1");
    h.update(username.as_bytes());
    h.update(recovery_id.as_bytes());
    h.update(challenge);
    h.update(device_id.as_bytes());
    h.update(mldsa_pk);
    h.update(ed25519_pk);
    h.update(xwing_hpke_pk);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_confirmation_binds_joiner_keys() {
        let pair_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let first = pair_confirmation(pair_id, device_id, b"mldsa", b"ed", b"xwing");
        let changed = pair_confirmation(pair_id, device_id, b"changed", b"ed", b"xwing");
        assert_eq!(first.len(), PAIR_CONFIRMATION_LEN);
        assert_ne!(first, changed);
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
