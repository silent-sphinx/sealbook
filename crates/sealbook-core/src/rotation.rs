//! What replacing the collection key means for every row and every device.
//!
//! A rotation is the only write that touches the whole collection, and the only
//! operation that may leave a row out of the manifest, so what it plans is
//! decided here rather than three times over. Core says which rows are
//! re-encrypted and at which revision, which tombstones the manifest still
//! commits to, which rows are retired, and which devices keep a wrap of the new
//! key. The host mints the key, does the sealing and moves the bytes.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sealbook_crypto::{
    decrypt_object, encrypt_object, generate_kdf_salt, generate_phrase, object_aad,
    phrase_lookup_id, phrase_recovery_public, wrap_collection_key, wrap_for_device,
    wrap_for_phrase, CollectionKey, DeviceHpkePublic, EncryptedObject, PHRASE_CIPHERSUITE,
    PHRASE_SCHEME, RECOVERY_CIPHERSUITE, XWING_CIPHERSUITE,
};
use sealbook_protocol::envelope::{open_envelope, Unsealed};
use sealbook_protocol::{KeyWrapBody, PhraseRecoveryBody};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::manifest::{manifest_entry_for, CoreManifestEntry, ManifestPlan};
use crate::roster::CoreDevice;
use crate::sync::{open_row, CoreSealedRow, RowOutcome, UnreadableReason};
use crate::CoreError;

/// Why a rotation cannot be planned as asked.
///
/// Typed rather than free text because each of these is something to tell the
/// user about, and each host has its own wording for it.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[serde(tag = "refusal")]
pub enum RotationRefusal {
    #[error("cannot revoke the device you are signed in on")]
    RevokingSelf,
    #[error("that device is not in the account's roster")]
    NotInRoster,
    #[error("cannot revoke the last device")]
    LastDevice,
    #[error("this device is not in the account's roster")]
    NotEnrolled,
    /// A live row this device cannot open. Every other read counts one of these
    /// and carries on, because raising would hide every readable row behind it.
    /// A rotation cannot: it re-encrypts each row from its plaintext, so a row
    /// it cannot read is a row it would leave sealed under the retired key, and
    /// counting it would drop the object from the collection for good.
    #[error("object {object} cannot be re-sealed: {}", reason.detail())]
    Unreadable {
        #[cfg_attr(feature = "wasm", tsify(type = "string"))]
        object: Uuid,
        reason: UnreadableReason,
    },
}

/// Where the collection is when a rotation starts, as a verified read left it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RotationState {
    pub manifest_seq: u64,
    pub key_epoch: u64,
    pub latest_revision: u64,
    /// Below this revision no incremental answer can still carry a delete.
    pub tombstone_floor: u64,
}

/// One row to be re-sealed, with the revision the rotation gives it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ResealRow {
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub id: Uuid,
    /// The revision after the rotation, not the one the row was served at.
    pub revision: u64,
    pub nonce: String,
    pub ciphertext: String,
    pub padded_size: u64,
}

/// What a rotation writes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RotationPlan {
    /// Re-sealed under the new key, in the order served, at consecutive
    /// revisions from the collection's next one.
    pub reseal: Vec<ResealRow>,
    /// Tombstones the manifest still commits to, at their stored revision and
    /// digest. There is no plaintext left to re-seal, but they are still rows
    /// and the manifest commits to every row: leaving them out made the
    /// manifest short and the rotation refused on any collection that had ever
    /// had a deletion.
    pub carried: Vec<CoreManifestEntry>,
    /// Tombstones below the floor, whose rows the rotation drops instead of
    /// signing for them again, named in the request's `drop_tombstones`. The
    /// manifest is what authorises that: the server retires exactly these rows
    /// and recomputes the digest from what it then holds.
    #[cfg_attr(feature = "wasm", tsify(type = "string[]"))]
    pub retired: Vec<Uuid>,
    /// The sequence, epoch and revision the rotation's manifest is signed over.
    pub manifest: ManifestPlan,
}

/// The rows and numbers a rotation writes, from the collection as read.
///
/// Classifies by the row-level tombstone flag, which is what the manifest
/// vouches for. A sealed tombstone, which only the web client writes, is a live
/// row here and is re-sealed with its envelope untouched, so a rotation never
/// has to consult the label the server serves.
pub fn rotation_plan(
    ck_b64: &str,
    collection_id: Uuid,
    state: &RotationState,
    rows: &[CoreSealedRow],
) -> Result<RotationPlan, CoreError> {
    let first_revision = state.latest_revision + 1;
    let mut reseal = Vec::new();
    let mut carried = Vec::new();
    let mut retired = Vec::new();
    for row in rows {
        if row.tombstone {
            if row.revision < state.tombstone_floor {
                retired.push(row.id);
            } else {
                carried.push(manifest_entry_for(
                    row.id,
                    row.revision,
                    true,
                    &row.nonce,
                    &row.ciphertext,
                )?);
            }
            continue;
        }
        // Opened before anything is written, so a collection with a row this
        // device cannot read is refused whole rather than part way through.
        if let RowOutcome::Unreadable { reason } = open_row(ck_b64, collection_id, row)? {
            return Err(CoreError::Rotation {
                refusal: RotationRefusal::Unreadable {
                    object: row.id,
                    reason,
                },
            });
        }
        reseal.push(ResealRow {
            id: row.id,
            revision: first_revision + reseal.len() as u64,
            nonce: row.nonce.clone(),
            ciphertext: row.ciphertext.clone(),
            padded_size: row.padded_size,
        });
    }
    let latest_revision = match reseal.last() {
        Some(last) => last.revision,
        None => state.latest_revision,
    };
    Ok(RotationPlan {
        reseal,
        carried,
        retired,
        manifest: ManifestPlan {
            manifest_seq: state.manifest_seq + 1,
            key_epoch: state.key_epoch + 1,
            latest_revision,
        },
    })
}

/// The devices a rotation re-wraps the new key for, in roster order.
///
/// `devices` comes from the verified roster. Taken from the server's device
/// list, a device the server had added would be handed a wrap of the new key,
/// which is the whole reason the roster exists.
pub fn rotation_recipients(
    self_device_id: Uuid,
    revoke_device_id: Option<Uuid>,
    devices: &[CoreDevice],
) -> Result<Vec<CoreDevice>, CoreError> {
    let refuse = |refusal| Err(CoreError::Rotation { refusal });
    if revoke_device_id == Some(self_device_id) {
        return refuse(RotationRefusal::RevokingSelf);
    }
    if let Some(revoked) = revoke_device_id {
        if !devices.iter().any(|device| device.device_id == revoked) {
            return refuse(RotationRefusal::NotInRoster);
        }
    }
    let remaining: Vec<CoreDevice> = devices
        .iter()
        .filter(|device| Some(device.device_id) != revoke_device_id)
        .cloned()
        .collect();
    if remaining.is_empty() {
        return refuse(RotationRefusal::LastDevice);
    }
    if !remaining
        .iter()
        .any(|device| device.device_id == self_device_id)
    {
        return refuse(RotationRefusal::NotEnrolled);
    }
    Ok(remaining)
}

/// One row re-sealed under the new key, at the revision the plan gave it.
///
/// Re-sealed from the stored bytes rather than from a payload the host has
/// decoded: the envelope already carries the type, and decoding the plaintext
/// as text would rewrite any payload that is not valid UTF-8.
pub fn reseal_row(
    old_ck_b64: &str,
    new_ck_b64: &str,
    collection_id: Uuid,
    row: &ResealRow,
) -> Result<CoreSealedRow, CoreError> {
    let unreadable = |reason| CoreError::Rotation {
        refusal: RotationRefusal::Unreadable {
            object: row.id,
            reason,
        },
    };
    let old_key = CollectionKey::from_bytes(crate::roster::collection_key(old_ck_b64)?);
    let new_key = CollectionKey::from_bytes(crate::roster::collection_key(new_ck_b64)?);
    let (Ok(nonce), Ok(ciphertext)) = (
        URL_SAFE_NO_PAD.decode(&row.nonce),
        URL_SAFE_NO_PAD.decode(&row.ciphertext),
    ) else {
        return Err(unreadable(UnreadableReason::Stored));
    };
    let Ok(nonce) = <[u8; 24]>::try_from(nonce.as_slice()) else {
        return Err(unreadable(UnreadableReason::Stored));
    };
    let aad = object_aad(row.id.as_bytes(), collection_id.as_bytes());
    let encrypted = EncryptedObject {
        nonce,
        ciphertext,
        padded_size: row.padded_size as usize,
    };
    let Ok(stored) = decrypt_object(&old_key, &encrypted, &aad) else {
        return Err(unreadable(UnreadableReason::Key));
    };
    if matches!(open_envelope(&stored), Unsealed::Unreadable) {
        return Err(unreadable(UnreadableReason::Envelope));
    }
    let resealed = encrypt_object(&new_key, &stored, &aad)?;
    Ok(CoreSealedRow {
        id: row.id,
        revision: row.revision,
        // A rotation re-encrypts plaintext, and the server refuses a rotated
        // object that claims to be a tombstone.
        tombstone: false,
        nonce: URL_SAFE_NO_PAD.encode(resealed.nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(&resealed.ciphertext),
        padded_size: resealed.padded_size as u64,
    })
}

/// The manifest entry set for a rotation.
///
/// `resealed` is the plan's rows after the host sealed them under the new key,
/// in the same order. Taking the entries from the plan rather than from
/// whatever the host happens to hold is what keeps a row that was not re-sealed
/// from reaching the manifest at its old digest, which would commit to a row
/// nothing can read once the old key is retired.
pub fn rotation_entries(
    plan: &RotationPlan,
    resealed: &[CoreSealedRow],
) -> Result<Vec<CoreManifestEntry>, CoreError> {
    if resealed.len() != plan.reseal.len() {
        return Err(CoreError::misuse(format!(
            "rotation planned {} objects and sealed {}",
            plan.reseal.len(),
            resealed.len()
        )));
    }
    let mut entries = Vec::with_capacity(resealed.len() + plan.carried.len());
    for (sealed, planned) in resealed.iter().zip(&plan.reseal) {
        if sealed.id != planned.id || sealed.revision != planned.revision {
            return Err(CoreError::misuse(format!(
                "rotation sealed {} at revision {} where {} at {} was planned",
                sealed.id, sealed.revision, planned.id, planned.revision
            )));
        }
        entries.push(manifest_entry_for(
            sealed.id,
            sealed.revision,
            // A rotation re-encrypts plaintext, and the server refuses a
            // rotated object that claims to be a tombstone.
            false,
            &sealed.nonce,
            &sealed.ciphertext,
        )?);
    }
    entries.extend(plan.carried.iter().cloned());
    Ok(entries)
}

/// What a rotation installs besides the re-sealed rows, in the types the wire
/// carries.
pub struct RotationWraps {
    pub key_wraps: Vec<KeyWrapBody>,
    pub kdf_salt: Vec<u8>,
    pub phrase: String,
    pub phrase_recovery: PhraseRecoveryBody,
}

/// The new key wrapped for every recipient, then for the password, then for a
/// fresh recovery phrase.
///
/// The order is the one the rotation signature covers: the server checks the
/// digest of the list as sent, so every client builds it here and none of them
/// sequences it. Draws the salt and the phrase, and returns both for the host
/// to keep.
pub fn rotation_wraps_typed(
    new_key: &CollectionKey,
    recipients: &[CoreDevice],
    username: &str,
    password: &str,
) -> Result<RotationWraps, CoreError> {
    let salt = generate_kdf_salt();
    let recovery = wrap_collection_key(password.as_bytes(), &salt, new_key)?;
    let (phrase, entropy) = generate_phrase()?;
    let phrase_wrap = wrap_for_phrase(&entropy, new_key)?;
    let public = phrase_recovery_public(&entropy)?;

    let mut key_wraps = Vec::with_capacity(recipients.len() + 2);
    for device in recipients {
        let pk =
            URL_SAFE_NO_PAD
                .decode(&device.xwing_hpke_pk)
                .map_err(|_| CoreError::Malformed {
                    detail: "device HPKE key".into(),
                })?;
        let wrap = wrap_for_device(&DeviceHpkePublic(pk), new_key)?;
        key_wraps.push(KeyWrapBody {
            recipient_kind: "device".into(),
            recipient_id: device.device_id.to_string(),
            hpke_enc: wrap.enc,
            wrapped_ck: wrap.ciphertext,
            ciphersuite: XWING_CIPHERSUITE.into(),
        });
    }
    key_wraps.push(KeyWrapBody {
        recipient_kind: "recovery".into(),
        recipient_id: username.to_string(),
        hpke_enc: recovery.nonce.to_vec(),
        wrapped_ck: recovery.ciphertext,
        ciphersuite: RECOVERY_CIPHERSUITE.into(),
    });
    key_wraps.push(KeyWrapBody {
        recipient_kind: "phrase".into(),
        recipient_id: username.to_string(),
        hpke_enc: phrase_wrap.nonce.to_vec(),
        wrapped_ck: phrase_wrap.ciphertext,
        ciphersuite: PHRASE_CIPHERSUITE.into(),
    });
    Ok(RotationWraps {
        key_wraps,
        kdf_salt: salt.to_vec(),
        phrase,
        phrase_recovery: PhraseRecoveryBody {
            mldsa_pk: public.mldsa_pk,
            ed25519_pk: public.ed25519_pk,
            lookup_id: phrase_lookup_id(&entropy)?.to_vec(),
            scheme: PHRASE_SCHEME.to_string(),
        },
    })
}

/// One wrap of the new key, with the binary fields base64url as the hosts hold
/// them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreKeyWrap {
    pub recipient_kind: String,
    pub recipient_id: String,
    pub hpke_enc: String,
    pub wrapped_ck: String,
    pub ciphersuite: String,
}

/// [`RotationWraps`] as a host carries it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreRotationWraps {
    pub key_wraps: Vec<CoreKeyWrap>,
    pub kdf_salt: String,
    pub phrase: String,
    pub phrase_mldsa_pk: String,
    pub phrase_ed25519_pk: String,
    pub phrase_lookup_id: String,
    pub phrase_scheme: String,
}

/// [`rotation_wraps_typed`] for a host that holds the new key as base64url.
pub fn rotation_wraps(
    new_ck_b64: &str,
    recipients: &[CoreDevice],
    username: &str,
    password: &str,
) -> Result<CoreRotationWraps, CoreError> {
    let key = CollectionKey::from_bytes(crate::roster::collection_key(new_ck_b64)?);
    let wraps = rotation_wraps_typed(&key, recipients, username, password)?;
    let b64 = |bytes: &[u8]| URL_SAFE_NO_PAD.encode(bytes);
    Ok(CoreRotationWraps {
        key_wraps: wraps
            .key_wraps
            .iter()
            .map(|wrap| CoreKeyWrap {
                recipient_kind: wrap.recipient_kind.clone(),
                recipient_id: wrap.recipient_id.clone(),
                hpke_enc: b64(&wrap.hpke_enc),
                wrapped_ck: b64(&wrap.wrapped_ck),
                ciphersuite: wrap.ciphersuite.clone(),
            })
            .collect(),
        kdf_salt: b64(&wraps.kdf_salt),
        phrase: wraps.phrase,
        phrase_mldsa_pk: b64(&wraps.phrase_recovery.mldsa_pk),
        phrase_ed25519_pk: b64(&wraps.phrase_recovery.ed25519_pk),
        phrase_lookup_id: b64(&wraps.phrase_recovery.lookup_id),
        phrase_scheme: wraps.phrase_recovery.scheme,
    })
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sealbook_crypto::{encrypt_object, object_aad, CollectionKey};
    use sealbook_protocol::envelope::seal_envelope;

    use super::*;

    const KEY: [u8; 32] = [7; 32];
    const OTHER_KEY: [u8; 32] = [9; 32];

    fn collection() -> Uuid {
        Uuid::from_u128(2)
    }

    fn ck() -> String {
        URL_SAFE_NO_PAD.encode(KEY)
    }

    fn sealed_with(key: [u8; 32], id: Uuid, revision: u64) -> CoreSealedRow {
        let aad = object_aad(id.as_bytes(), collection().as_bytes());
        let plain = seal_envelope("application/sealbook.note+json", b"{}");
        let enc = encrypt_object(&CollectionKey::from_bytes(key), &plain, &aad).unwrap();
        CoreSealedRow {
            id,
            revision,
            tombstone: false,
            nonce: URL_SAFE_NO_PAD.encode(enc.nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(&enc.ciphertext),
            padded_size: enc.padded_size as u64,
        }
    }

    fn live(id: Uuid, revision: u64) -> CoreSealedRow {
        sealed_with(KEY, id, revision)
    }

    fn tombstone(id: Uuid, revision: u64) -> CoreSealedRow {
        CoreSealedRow {
            id,
            revision,
            tombstone: true,
            nonce: URL_SAFE_NO_PAD.encode([3u8; 24]),
            ciphertext: URL_SAFE_NO_PAD.encode([4u8; 48]),
            padded_size: 48,
        }
    }

    fn state() -> RotationState {
        RotationState {
            manifest_seq: 4,
            key_epoch: 2,
            latest_revision: 9,
            tombstone_floor: 5,
        }
    }

    fn plan_for(rows: &[CoreSealedRow]) -> RotationPlan {
        rotation_plan(&ck(), collection(), &state(), rows).unwrap()
    }

    #[test]
    fn live_rows_take_consecutive_revisions_from_the_collections_next_one() {
        let plan = plan_for(&[
            live(Uuid::from_u128(11), 3),
            live(Uuid::from_u128(12), 7),
            live(Uuid::from_u128(13), 9),
        ]);
        assert_eq!(
            plan.reseal
                .iter()
                .map(|row| row.revision)
                .collect::<Vec<_>>(),
            vec![10, 11, 12]
        );
        assert_eq!(plan.manifest.latest_revision, 12);
        assert_eq!(plan.manifest.key_epoch, 3);
        assert_eq!(plan.manifest.manifest_seq, 5);
    }

    #[test]
    fn a_tombstone_above_the_floor_is_carried_and_one_below_it_is_retired() {
        let kept = Uuid::from_u128(21);
        let old = Uuid::from_u128(22);
        let plan = plan_for(&[tombstone(kept, 6), tombstone(old, 4)]);
        assert_eq!(plan.retired, vec![old]);
        assert_eq!(plan.carried.len(), 1);
        let entry = &plan.carried[0];
        assert_eq!((entry.id, entry.revision, entry.tombstone), (kept, 6, true));
        // Nothing was re-sealed, so the collection's revision does not move.
        assert_eq!(plan.manifest.latest_revision, 9);
        assert!(plan.reseal.is_empty());
    }

    /// A tombstone exactly at the floor is still reachable by an incremental
    /// answer, so it is carried rather than retired.
    #[test]
    fn a_tombstone_at_the_floor_is_carried() {
        let plan = plan_for(&[tombstone(Uuid::from_u128(21), 5)]);
        assert!(plan.retired.is_empty());
        assert_eq!(plan.carried.len(), 1);
    }

    /// Retired tombstones leave no gap in the revisions the live rows take: the
    /// rotation assigns those from the collection's latest revision, not from
    /// the rows it happens to be carrying.
    #[test]
    fn a_retired_tombstone_between_two_live_rows_does_not_shift_their_revisions() {
        let plan = plan_for(&[
            live(Uuid::from_u128(11), 3),
            tombstone(Uuid::from_u128(22), 4),
            live(Uuid::from_u128(12), 7),
        ]);
        assert_eq!(
            plan.reseal
                .iter()
                .map(|row| row.revision)
                .collect::<Vec<_>>(),
            vec![10, 11]
        );
    }

    #[test]
    fn a_row_this_device_cannot_open_refuses_the_whole_rotation() {
        let bad = Uuid::from_u128(13);
        let rows = [live(Uuid::from_u128(11), 3), sealed_with(OTHER_KEY, bad, 7)];
        assert_eq!(
            rotation_plan(&ck(), collection(), &state(), &rows).unwrap_err(),
            CoreError::Rotation {
                refusal: RotationRefusal::Unreadable {
                    object: bad,
                    reason: UnreadableReason::Key,
                },
            }
        );
    }

    fn device(id: u128) -> CoreDevice {
        CoreDevice {
            device_id: Uuid::from_u128(id),
            mldsa_pk: String::new(),
            ed25519_pk: String::new(),
            xwing_hpke_pk: String::new(),
        }
    }

    fn refusal(revoke: Option<Uuid>, devices: &[CoreDevice]) -> RotationRefusal {
        match rotation_recipients(Uuid::from_u128(1), revoke, devices).unwrap_err() {
            CoreError::Rotation { refusal } => refusal,
            other => panic!("expected a rotation refusal, got {other:?}"),
        }
    }

    #[test]
    fn revoking_a_device_leaves_every_other_one_holding_a_wrap() {
        let devices = [device(1), device(2), device(3)];
        let remaining =
            rotation_recipients(Uuid::from_u128(1), Some(Uuid::from_u128(2)), &devices).unwrap();
        assert_eq!(
            remaining
                .iter()
                .map(|device| device.device_id)
                .collect::<Vec<_>>(),
            vec![Uuid::from_u128(1), Uuid::from_u128(3)]
        );
    }

    #[test]
    fn a_rotation_that_revokes_nothing_wraps_for_the_whole_roster() {
        let devices = [device(1), device(2)];
        let remaining = rotation_recipients(Uuid::from_u128(1), None, &devices).unwrap();
        assert_eq!(remaining.len(), 2);
    }

    #[test]
    fn the_signed_in_device_cannot_revoke_itself() {
        assert_eq!(
            refusal(Some(Uuid::from_u128(1)), &[device(1), device(2)]),
            RotationRefusal::RevokingSelf
        );
    }

    #[test]
    fn a_device_already_gone_from_the_roster_cannot_be_revoked() {
        assert_eq!(
            refusal(Some(Uuid::from_u128(9)), &[device(1), device(2)]),
            RotationRefusal::NotInRoster
        );
    }

    #[test]
    fn the_last_device_cannot_be_revoked() {
        assert_eq!(
            refusal(Some(Uuid::from_u128(2)), &[device(2)]),
            RotationRefusal::LastDevice
        );
    }

    /// Signed in on a device the roster does not list: the rotation would wrap
    /// the new key for everyone except the device doing it.
    #[test]
    fn a_device_not_in_the_roster_cannot_rotate() {
        assert_eq!(
            refusal(None, &[device(2), device(3)]),
            RotationRefusal::NotEnrolled
        );
    }

    #[test]
    fn the_manifest_commits_to_the_resealed_rows_and_the_carried_tombstones() {
        let first = Uuid::from_u128(11);
        let kept = Uuid::from_u128(21);
        let plan = plan_for(&[live(first, 3), tombstone(kept, 6)]);
        let resealed = [CoreSealedRow {
            id: first,
            revision: 10,
            tombstone: false,
            ..sealed_with(OTHER_KEY, first, 10)
        }];
        let entries = rotation_entries(&plan, &resealed).unwrap();
        assert_eq!(
            entries
                .iter()
                .map(|entry| (entry.id, entry.revision, entry.tombstone))
                .collect::<Vec<_>>(),
            vec![(first, 10, false), (kept, 6, true)]
        );
        // The digest is of the new ciphertext, not the one that was read.
        assert_eq!(
            entries[0].content_digest,
            manifest_entry_for(
                first,
                10,
                false,
                &resealed[0].nonce,
                &resealed[0].ciphertext
            )
            .unwrap()
            .content_digest
        );
    }

    #[test]
    fn a_rotation_that_sealed_a_different_set_than_it_planned_is_refused() {
        let first = Uuid::from_u128(11);
        let plan = plan_for(&[live(first, 3), live(Uuid::from_u128(12), 4)]);
        let short = [sealed_with(OTHER_KEY, first, 10)];
        assert!(matches!(
            rotation_entries(&plan, &short).unwrap_err(),
            CoreError::Misuse { .. }
        ));
    }

    #[test]
    fn a_rotation_that_renumbered_a_row_is_refused() {
        let first = Uuid::from_u128(11);
        let plan = plan_for(&[live(first, 3)]);
        let renumbered = [sealed_with(OTHER_KEY, first, 99)];
        assert!(matches!(
            rotation_entries(&plan, &renumbered).unwrap_err(),
            CoreError::Misuse { .. }
        ));
    }

    #[test]
    fn a_resealed_row_opens_under_the_new_key_with_its_envelope_intact() {
        let id = Uuid::from_u128(11);
        let plan = plan_for(&[live(id, 3)]);
        let new_ck = URL_SAFE_NO_PAD.encode(OTHER_KEY);
        let resealed = reseal_row(&ck(), &new_ck, collection(), &plan.reseal[0]).unwrap();
        assert_eq!((resealed.id, resealed.revision), (id, 10));
        assert!(!resealed.tombstone);
        assert_eq!(
            crate::sync::open_row(&new_ck, collection(), &resealed).unwrap(),
            RowOutcome::Object {
                content_type: "application/sealbook.note+json".into(),
                payload: "{}".into(),
            }
        );
        // The old key is retired by the rotation, and stops opening the row.
        assert!(matches!(
            crate::sync::open_row(&ck(), collection(), &resealed).unwrap(),
            RowOutcome::Unreadable { .. }
        ));
    }

    #[test]
    fn a_row_the_old_key_does_not_open_cannot_be_resealed() {
        let id = Uuid::from_u128(11);
        let plan = plan_for(&[live(id, 3)]);
        let wrong = URL_SAFE_NO_PAD.encode(OTHER_KEY);
        assert_eq!(
            reseal_row(&wrong, &ck(), collection(), &plan.reseal[0]).unwrap_err(),
            CoreError::Rotation {
                refusal: RotationRefusal::Unreadable {
                    object: id,
                    reason: UnreadableReason::Key,
                },
            }
        );
    }

    #[test]
    fn an_empty_collection_rotates_to_an_empty_manifest() {
        let plan = plan_for(&[]);
        assert!(plan.reseal.is_empty());
        assert!(plan.carried.is_empty());
        assert!(plan.retired.is_empty());
        assert_eq!(plan.manifest.latest_revision, 9);
        assert_eq!(plan.manifest.key_epoch, 3);
        assert!(rotation_entries(&plan, &[]).unwrap().is_empty());
    }

    fn enrolled(id: u128) -> (CoreDevice, sealbook_crypto::DeviceHpkeSecret) {
        let (secret, public) = sealbook_crypto::generate_device_hpke().unwrap();
        let mut entry = device(id);
        entry.xwing_hpke_pk = URL_SAFE_NO_PAD.encode(&public.0);
        (entry, secret)
    }

    #[test]
    fn wraps_go_to_each_device_then_the_password_then_the_phrase() {
        let (first, first_secret) = enrolled(1);
        let (second, _) = enrolled(2);
        let key = CollectionKey::from_bytes(KEY);
        let wraps =
            rotation_wraps_typed(&key, &[first.clone(), second.clone()], "ada", "hunter2").unwrap();
        let order: Vec<(&str, &str)> = wraps
            .key_wraps
            .iter()
            .map(|wrap| (wrap.recipient_kind.as_str(), wrap.recipient_id.as_str()))
            .collect();
        assert_eq!(
            order,
            [
                ("device", first.device_id.to_string().as_str()),
                ("device", second.device_id.to_string().as_str()),
                ("recovery", "ada"),
                ("phrase", "ada"),
            ]
        );
        assert_eq!(wraps.key_wraps[0].ciphersuite, XWING_CIPHERSUITE);
        assert_eq!(wraps.key_wraps[2].ciphersuite, RECOVERY_CIPHERSUITE);
        assert_eq!(wraps.key_wraps[3].ciphersuite, PHRASE_CIPHERSUITE);
        assert_eq!(wraps.phrase_recovery.scheme, PHRASE_SCHEME);

        let opened = sealbook_crypto::unwrap_for_device(
            &first_secret,
            &sealbook_crypto::DeviceHpkeWrap {
                enc: wraps.key_wraps[0].hpke_enc.clone(),
                ciphertext: wraps.key_wraps[0].wrapped_ck.clone(),
                ciphersuite: XWING_CIPHERSUITE,
            },
        )
        .unwrap();
        assert_eq!(opened.as_bytes(), &KEY);
    }

    #[test]
    fn the_host_form_carries_the_same_wraps_as_base64() {
        let (only, _) = enrolled(1);
        let wraps = rotation_wraps(&URL_SAFE_NO_PAD.encode(KEY), &[only], "ada", "pw").unwrap();
        assert_eq!(wraps.key_wraps.len(), 3);
        assert_eq!(wraps.phrase.split_whitespace().count(), 24);
        assert!(URL_SAFE_NO_PAD.decode(&wraps.kdf_salt).is_ok());
        assert!(URL_SAFE_NO_PAD.decode(&wraps.phrase_lookup_id).is_ok());
    }

    #[test]
    fn a_device_key_that_is_not_base64_is_refused() {
        let mut bad = device(1);
        bad.xwing_hpke_pk = "***".into();
        assert!(
            rotation_wraps_typed(&CollectionKey::from_bytes(KEY), &[bad], "ada", "pw").is_err()
        );
    }
}

/// The uniffi surface for the rotation plan above.
#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{
        CoreDevice, CoreError, CoreManifestEntry, CoreRotationWraps, CoreSealedRow, ResealRow,
        RotationPlan, RotationState,
    };
    use uuid::Uuid;

    #[uniffi::export]
    pub fn rotation_plan(
        ck_b64: String,
        collection_id: Uuid,
        state: RotationState,
        rows: Vec<CoreSealedRow>,
    ) -> Result<RotationPlan, CoreError> {
        super::rotation_plan(&ck_b64, collection_id, &state, &rows)
    }

    #[uniffi::export]
    pub fn rotation_recipients(
        self_device_id: Uuid,
        revoke_device_id: Option<Uuid>,
        devices: Vec<CoreDevice>,
    ) -> Result<Vec<CoreDevice>, CoreError> {
        super::rotation_recipients(self_device_id, revoke_device_id, &devices)
    }

    #[uniffi::export]
    pub fn rotation_wraps(
        new_ck_b64: String,
        recipients: Vec<CoreDevice>,
        username: String,
        password: String,
    ) -> Result<CoreRotationWraps, CoreError> {
        super::rotation_wraps(&new_ck_b64, &recipients, &username, &password)
    }

    #[uniffi::export]
    pub fn reseal_row(
        old_ck_b64: String,
        new_ck_b64: String,
        collection_id: Uuid,
        row: ResealRow,
    ) -> Result<CoreSealedRow, CoreError> {
        super::reseal_row(&old_ck_b64, &new_ck_b64, collection_id, &row)
    }

    #[uniffi::export]
    pub fn rotation_entries(
        plan: RotationPlan,
        resealed: Vec<CoreSealedRow>,
    ) -> Result<Vec<CoreManifestEntry>, CoreError> {
        super::rotation_entries(&plan, &resealed)
    }
}
