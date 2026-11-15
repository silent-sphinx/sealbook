//! The collection, roster and phrase wrap `recover/start` answers with when the
//! username and lookup id it was given do not match an account, and the roster
//! anchor `pair/join` answers with for a username that has none.
//!
//! The handler is written so that a miss and a hit are indistinguishable, which
//! a response shaped differently for the two gives away. Everything here is
//! derived from a server-held key and the request, so one lookup is always
//! answered the same way (a pairing anchor advancing over time, as a real
//! roster does) and two lookups are answered unrelatedly: a caller cannot take
//! a lookup it knows to be a miss as a baseline and compare. The
//! parts are real keys, signatures and ciphertexts rather than random bytes of
//! the right length, because an X-Wing public key and an ML-DSA signature are
//! checkable encodings that random bytes of the right length fail.

use sealbook_crypto::{
    decoy_seed, device_hpke_public_from_ikm, phrase_recovery_keys, signing_from_seeds,
    wrap_for_phrase_with_nonce, CollectionKey, CryptoError, DeviceSigningSecrets, DECOY_KEY_LEN,
    NONCE_LEN,
};
use sealbook_protocol::{DevicePublicKeys, KeyWrapBody, RosterBody, RosterSignerBody};
use uuid::{Builder, Uuid};

/// The most devices a decoy roster lists.
///
/// The count is varied with the request rather than fixed, because a fixed one
/// lets a caller who knows how many devices an account has read the answer off
/// the length of the roster.
const MAX_DECOY_DEVICES: u8 = 4;

pub(crate) struct RecoveryDecoy {
    pub(crate) collection_id: Uuid,
    pub(crate) wrap: KeyWrapBody,
    pub(crate) roster: RosterBody,
}

pub(crate) fn recovery_decoy(
    key: &[u8; DECOY_KEY_LEN],
    username: &str,
    lookup_id: &[u8],
) -> Result<RecoveryDecoy, CryptoError> {
    // The lookup id is fixed length, so where the username ends is unambiguous.
    let mut context = Vec::with_capacity(username.len() + lookup_id.len());
    context.extend_from_slice(username.as_bytes());
    context.extend_from_slice(lookup_id);
    let seed = |label: &str| decoy_seed(key, &context, label.as_bytes());

    let collection_id = decoy_uuid(&seed("collection-id")?);
    let shape = seed("shape")?;
    let count = 1 + u64::from(shape[0] % MAX_DECOY_DEVICES);
    // A roster is written for every device added, so the sequence is at least
    // the device count, and an epoch is raised by a rotation, which writes one
    // too.
    let roster_seq = count + u64::from(shape[1] % 9);
    let key_epoch = 1 + u64::from(shape[2]) % roster_seq;

    let mut devices = Vec::with_capacity(count as usize);
    let (first, signer_secrets) = decoy_device(key, &context, 0)?;
    let signer = first.device_id;
    devices.push(first);
    for index in 1..count {
        devices.push(decoy_device(key, &context, index)?.0);
    }

    let entropy = seed("phrase")?;
    let (_, phrase_public) = phrase_recovery_keys(&entropy)?;
    let ck = CollectionKey::from_bytes(seed("collection-key")?);
    let roster = RosterBody::seal(
        collection_id,
        roster_seq,
        key_epoch,
        devices,
        phrase_public.mldsa_pk,
        phrase_public.ed25519_pk,
        RosterSignerBody::Device { device_id: signer },
        &signer_secrets,
        &ck,
    )?;

    // Derived rather than random, so that repeating a lookup returns the same
    // wrap. Nothing else is ever sealed under this entropy, so the nonce is
    // used once.
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&seed("wrap-nonce")?[..NONCE_LEN]);
    let wrap = wrap_for_phrase_with_nonce(&entropy, &ck, &nonce)?;
    Ok(RecoveryDecoy {
        collection_id,
        wrap: KeyWrapBody {
            recipient_kind: "phrase".into(),
            recipient_id: username.to_string(),
            hpke_enc: wrap.nonce.to_vec(),
            wrapped_ck: wrap.ciphertext,
            ciphersuite: wrap.ciphersuite,
        },
        roster,
    })
}

/// When a pairing decoy's roster starts to change: 2026-01-01 UTC. Fixed, so
/// that every server derives the same history and a restart moves nothing.
const PAIR_DECOY_ORIGIN: i64 = 1_767_225_600;

/// A pairing decoy's roster changes at most once per window of this length.
const PAIR_DECOY_WINDOW: i64 = 30 * 24 * 60 * 60;

/// The chance, in sixths, that a pairing decoy's roster changes in a window:
/// about twice a year, a guess at how often an account adds or removes a
/// device or rotates its key.
const PAIR_DECOY_CHANGE_SIXTHS: u8 = 1;

/// The roster `pair/join` anchors a username with no account on, as a sequence
/// number and transcript, at `now` in Unix seconds.
///
/// Derived for the same reason as the recovery decoy: a real account anchors
/// every join on the same roster, so a decoy made up per request is caught by
/// joining twice. The starting sequence is spread like a recovery decoy's,
/// since a fixed one is recognised against any account that has added a
/// device. It then advances now and then, because a real account's roster
/// does, and an anchor watched for months that never moved would mark the
/// username as unused.
pub(crate) fn pairing_decoy_anchor(
    key: &[u8; DECOY_KEY_LEN],
    username: &str,
    now: i64,
) -> Result<(u64, [u8; 32]), CryptoError> {
    let seed = |context: &[u8], label: &str| decoy_seed(key, context, label.as_bytes());
    let shape = seed(username.as_bytes(), "pair-shape")?;
    let start = 1 + u64::from(shape[0] % MAX_DECOY_DEVICES) + u64::from(shape[1] % 9);

    let mut changes = 0;
    let mut window_start = PAIR_DECOY_ORIGIN;
    let mut window = 0u64;
    while window_start < now {
        let roll = seed(&with_suffix(username, window), "pair-change")?;
        let offset =
            i64::from(u32::from_be_bytes([roll[1], roll[2], roll[3], roll[4]])) % PAIR_DECOY_WINDOW;
        if roll[0] % 6 < PAIR_DECOY_CHANGE_SIXTHS && window_start + offset < now {
            changes += 1;
        }
        window_start += PAIR_DECOY_WINDOW;
        window += 1;
    }

    let roster_seq = start + changes;
    let transcript = seed(&with_suffix(username, roster_seq), "pair-transcript")?;
    Ok((roster_seq, transcript))
}

/// The username followed by a number, as a derivation context. The number is
/// fixed length, so where the username ends is unambiguous.
fn with_suffix(username: &str, number: u64) -> Vec<u8> {
    let mut context = Vec::with_capacity(username.len() + 8);
    context.extend_from_slice(username.as_bytes());
    context.extend_from_slice(&number.to_be_bytes());
    context
}

fn decoy_device(
    key: &[u8; DECOY_KEY_LEN],
    context: &[u8],
    index: u64,
) -> Result<(DevicePublicKeys, DeviceSigningSecrets), CryptoError> {
    let seed = |part: &str| decoy_seed(key, context, format!("device-{index}-{part}").as_bytes());
    let (secrets, public) = signing_from_seeds(&seed("mldsa")?, &seed("ed25519")?);
    let xwing_hpke_pk = device_hpke_public_from_ikm(&seed("hpke")?).0;
    Ok((
        DevicePublicKeys {
            device_id: decoy_uuid(&seed("id")?),
            mldsa_pk: public.mldsa_pk,
            ed25519_pk: public.ed25519_pk,
            xwing_hpke_pk,
        },
        secrets,
    ))
}

/// Version 4, which every identifier the server really holds is.
fn decoy_uuid(seed: &[u8; 32]) -> Uuid {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&seed[..16]);
    Builder::from_random_bytes(bytes).into_uuid()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealbook_crypto::{
        validate_device_hpke_public, verify, DeviceHpkePublic, DeviceSigningPublic, DualSignature,
        ED25519_PUBLIC_KEY_LEN, MLDSA65_PUBLIC_KEY_LEN, ROSTER_MAC_LEN,
    };

    const KEY: [u8; DECOY_KEY_LEN] = [3u8; DECOY_KEY_LEN];
    const LOOKUP: [u8; 32] = [9u8; 32];

    fn decoy(username: &str, lookup: &[u8]) -> RecoveryDecoy {
        recovery_decoy(&KEY, username, lookup).expect("decoy")
    }

    /// The parts a caller can check have to be real, not bytes of the right
    /// length: the signature must verify, under a key in the roster, over the
    /// roster's own transcript.
    #[test]
    fn a_decoy_roster_is_a_real_signed_roster() {
        let decoy = decoy("alice", &LOOKUP);
        let RosterSignerBody::Device { device_id } = decoy.roster.signer else {
            panic!("a decoy roster is signed by one of its devices");
        };
        let signer = decoy
            .roster
            .devices
            .iter()
            .find(|device| device.device_id == device_id)
            .expect("the signer is listed in the roster");
        verify(
            &DeviceSigningPublic {
                mldsa_pk: signer.mldsa_pk.clone(),
                ed25519_pk: signer.ed25519_pk.clone(),
            },
            &decoy.roster.to_roster().transcript(decoy.collection_id),
            &DualSignature {
                mldsa: decoy.roster.signature.mldsa.clone(),
                ed25519: decoy.roster.signature.ed25519.clone(),
            },
        )
        .expect("the decoy roster's signature verifies");
        assert_eq!(decoy.roster.mac.len(), ROSTER_MAC_LEN);
        for device in &decoy.roster.devices {
            assert_eq!(device.mldsa_pk.len(), MLDSA65_PUBLIC_KEY_LEN);
            assert_eq!(device.ed25519_pk.len(), ED25519_PUBLIC_KEY_LEN);
            validate_device_hpke_public(&DeviceHpkePublic(device.xwing_hpke_pk.clone()))
                .expect("the decoy's HPKE keys are real X-Wing keys");
            assert_eq!(device.device_id.get_version_num(), 4);
        }
        assert_eq!(decoy.collection_id.get_version_num(), 4);
    }

    /// A caller that repeats a lookup must be answered the same way, as it would
    /// be if the lookup had matched.
    #[test]
    fn a_decoy_is_stable_for_one_lookup() {
        let first = decoy("alice", &LOOKUP);
        let again = decoy("alice", &LOOKUP);
        assert_eq!(first.collection_id, again.collection_id);
        assert_eq!(first.wrap.hpke_enc, again.wrap.hpke_enc);
        assert_eq!(first.wrap.wrapped_ck, again.wrap.wrapped_ck);
        assert_eq!(first.roster.mac, again.roster.mac);
        assert_eq!(first.roster.roster_seq, again.roster.roster_seq);
    }

    /// The property a fixed decoy would not have: a caller cannot hold a lookup
    /// it knows to be a miss beside one it is asking about and compare them.
    #[test]
    fn two_lookups_get_unrelated_decoys() {
        let mine = decoy("alice", &LOOKUP);
        let other_name = decoy("bob", &LOOKUP);
        let other_lookup = decoy("alice", &[11u8; 32]);
        assert_ne!(mine.collection_id, other_name.collection_id);
        assert_ne!(mine.collection_id, other_lookup.collection_id);
        assert_ne!(mine.wrap.wrapped_ck, other_name.wrap.wrapped_ck);
        assert_ne!(mine.roster.mac, other_lookup.roster.mac);
    }

    /// The wrap is the one the username asked for, and the roster could be a
    /// real account's: a shape no real roster has is as good a tell as a missing
    /// field.
    #[test]
    fn a_decoy_could_pass_for_an_account() {
        for name in ["alice", "bob", "carol", "dave", "erin", "frank"] {
            let decoy = decoy(name, &LOOKUP);
            assert_eq!(decoy.wrap.recipient_kind, "phrase");
            assert_eq!(decoy.wrap.recipient_id, name);
            assert_eq!(decoy.wrap.hpke_enc.len(), NONCE_LEN);
            assert_eq!(decoy.roster.phrase_mldsa_pk.len(), MLDSA65_PUBLIC_KEY_LEN);
            let devices = decoy.roster.devices.len() as u64;
            assert!((1..=u64::from(MAX_DECOY_DEVICES)).contains(&devices));
            assert!(decoy.roster.roster_seq >= devices);
            assert!(decoy.roster.key_epoch >= 1);
            assert!(decoy.roster.key_epoch <= decoy.roster.roster_seq);
        }
    }

    const NAMES: [&str; 8] = [
        "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
    ];
    const DAY: i64 = 24 * 60 * 60;

    fn anchor(name: &str, now: i64) -> (u64, [u8; 32]) {
        pairing_decoy_anchor(&KEY, name, now).expect("anchor")
    }

    #[test]
    fn a_pairing_decoy_is_stable_per_username_and_varied_across_them() {
        let now = PAIR_DECOY_ORIGIN;
        let first = anchor("alice", now);
        assert_eq!(first, anchor("alice", now));
        let mut seqs = std::collections::HashSet::new();
        for name in &NAMES[1..] {
            let (seq, transcript) = anchor(name, now);
            assert_ne!(transcript, first.1);
            assert!((1..=u64::from(MAX_DECOY_DEVICES) + 8).contains(&seq));
            seqs.insert(seq);
        }
        assert!(seqs.len() > 1);
    }

    #[test]
    fn a_pairing_decoy_moves_forward_now_and_then_like_a_real_roster() {
        let start = PAIR_DECOY_ORIGIN;
        let mut moved = 0;
        for name in NAMES {
            let mut last = anchor(name, start);
            for day in 1..=(3 * 365) {
                let next = anchor(name, start + day * DAY);
                assert!(next.0 >= last.0, "{name}'s sequence went backwards");
                if next.0 == last.0 {
                    assert_eq!(next.1, last.1, "{name}'s transcript moved alone");
                } else {
                    assert_eq!(next.0, last.0 + 1, "{name} skipped a sequence");
                    assert_ne!(next.1, last.1, "{name}'s transcript stayed");
                    moved += 1;
                }
                last = next;
            }
        }
        // About two changes a year each, so eight names over three years land
        // near 48. The bounds only rule out never and constantly.
        assert!((10..=120).contains(&moved), "{moved} changes");
    }

    #[test]
    fn a_pairing_decoy_before_its_origin_is_its_starting_roster() {
        for name in NAMES {
            assert_eq!(anchor(name, 0), anchor(name, PAIR_DECOY_ORIGIN));
        }
    }
}
