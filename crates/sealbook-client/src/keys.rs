//! The collection key's lifecycle: which devices hold it, when it is replaced,
//! and how a device gets back to the current one.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use uuid::Uuid;

use sealbook_crypto::{
    key_rotation_transcript, key_wraps_digest, rotated_objects_digest, rotation_phrase_payload,
    sign, unwrap_for_device, CollectionKey, DeviceHpkeSecret, DeviceHpkeWrap, DeviceSigningSecrets,
    ObjectDigestEntry, WrapBinding, WrapDigestEntry, XWING_CIPHERSUITE,
};
use sealbook_protocol::{
    CollectionKeysResponse, DevicePublicKeys, DualSignatureBody, RosterBody, RosterSignerBody,
    RotateRequest, RotatedObject, SEALED_CONTENT_TYPE,
};

use sealbook_core::{
    reseal_row_upgrading, rotation_entries, rotation_plan, rotation_recipients,
    rotation_wraps_typed, CoreDevice, CoreSealedRow, RotationState, RotationWraps,
};

use crate::{ClientError, SealbookClient};

/// The collection as core's rotation plan reads it.
///
/// The rows are base64 here rather than bytes, because the plan is one rule for
/// all four clients and the other three hold them that way.
fn sealed_rows(objects: &[sealbook_protocol::ObjectChange]) -> Vec<CoreSealedRow> {
    objects
        .iter()
        .map(|object| CoreSealedRow {
            id: object.id,
            revision: object.revision,
            tombstone: object.tombstone,
            nonce: URL_SAFE_NO_PAD.encode(&object.nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(&object.ciphertext),
            padded_size: object.padded_size as u64,
        })
        .collect()
}

/// A re-sealed row as the rotation request carries it.
fn rotated_object(row: &CoreSealedRow) -> Result<RotatedObject, ClientError> {
    let decode = |field: &str, value: &str| {
        URL_SAFE_NO_PAD.decode(value).map_err(|err| {
            ClientError::Server(format!("core returned an unreadable {field}: {err}"))
        })
    };
    Ok(RotatedObject {
        id: row.id,
        revision: row.revision,
        nonce: decode("nonce", &row.nonce)?,
        ciphertext: decode("ciphertext", &row.ciphertext)?,
        padded_size: row.padded_size as usize,
        content_type: SEALED_CONTENT_TYPE.into(),
        tombstone: row.tombstone,
    })
}

impl SealbookClient {
    /// The account's devices, from the verified roster rather than the server's
    /// unsigned device list.
    pub async fn list_devices(&self) -> Result<Vec<DevicePublicKeys>, ClientError> {
        Ok(self.verified_roster().await?.devices)
    }

    /// Revokes a device and rotates the collection key.
    ///
    /// Marking a device revoked does not take away what it already holds: it
    /// has the collection key and can decrypt anything it synced. So this
    /// mints a fresh key, re-wraps it for every remaining device plus the
    /// password and a *new* recovery phrase, and re-encrypts every object
    /// under it, all in one server-side transaction.
    ///
    /// Returns the new recovery phrase. The previous phrase stops working:
    /// re-wrapping under the old one would need the phrase itself, which the
    /// client does not hold. Callers must show this to the user.
    /// Revokes a device, rotating the collection key so it loses access to data it
    /// has already synced as well as to anything new.
    ///
    /// Returns the replacement recovery phrase, which the user must write down: a
    /// rotation cannot re-wrap for the old phrase, because no client holds it.
    pub async fn revoke_device(&mut self, device_id: Uuid) -> Result<String, ClientError> {
        self.revoke_devices(&[device_id], &mut |_| Ok(())).await
    }

    /// Revokes several devices in one rotation. The ids may come in any order.
    pub async fn revoke_devices(
        &mut self,
        device_ids: &[Uuid],
        confirm: &mut dyn FnMut(&str) -> Result<(), ClientError>,
    ) -> Result<String, ClientError> {
        let mut sorted = device_ids.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let phrase = self.rotate_confirmed(&sorted, confirm).await?;
        // The revoke has landed; a label left behind is only clutter.
        let _ = self.remove_stale_device_labels().await;
        Ok(phrase)
    }

    /// Issues a new recovery phrase and rotates the collection key onto it.
    ///
    /// Replacing the phrase without rotating would leave anyone who has ever seen
    /// the old phrase able to decrypt: the wrap they captured still opens the same
    /// key. This is also why a completed recovery rotates.
    pub async fn change_phrase(&mut self) -> Result<String, ClientError> {
        self.rotate(&[]).await
    }

    /// Replaces the collection key and re-encrypts the vault under it.
    ///
    /// One code path for every operation that has to invalidate the old key,
    /// because they all need the same work: read everything under the current key,
    /// generate a new one, re-wrap it for each device that keeps access plus the
    /// password and a fresh phrase, re-encrypt every object, and sign the lot.
    ///
    /// `revoke_device_ids` must be strictly ascending: the signed transcript
    /// hashes the list as sent and the server refuses any other order.
    pub async fn rotate(&mut self, revoke_device_ids: &[Uuid]) -> Result<String, ClientError> {
        self.rotate_confirmed(revoke_device_ids, &mut |_| Ok(()))
            .await
    }

    /// As [`Self::rotate`], showing the new recovery phrase to `confirm` before
    /// anything is posted. The rotation retires the old phrase, so a caller that
    /// makes the user prove they wrote the new one down does it here, while an
    /// abort still leaves the account as it was.
    pub async fn rotate_confirmed(
        &mut self,
        revoke_device_ids: &[Uuid],
        confirm: &mut dyn FnMut(&str) -> Result<(), ClientError>,
    ) -> Result<String, ClientError> {
        let (server, username, collection_id, self_device_id, token, secrets) = {
            let state = self.state.as_ref().ok_or(ClientError::NoState)?;
            (
                state.server.clone(),
                state.username.clone(),
                state.collection_id,
                state.device_id,
                state.session_token.clone().ok_or(ClientError::NoState)?,
                DeviceSigningSecrets {
                    mldsa_seed: state.mldsa_seed.clone(),
                    ed25519_sk: state.ed25519_sk.clone(),
                },
            )
        };
        let (manifest_seq, epoch, latest_revision, _) = self.manifest_state().await?;
        // Everything below is re-encrypted from the current key, so this session
        // has to be holding it rather than one a rotation elsewhere retired.
        self.align_key_epoch(epoch).await?;
        // Wraps go only to devices the verified roster lists. Taken from the
        // server's device list, a device the server added would be handed the key.
        // Checked before the collection is read, so a rotation that cannot start
        // does not read the whole vault first.
        let roster = self.verified_roster().await?;
        let devices: Vec<CoreDevice> = roster.devices.iter().map(CoreDevice::from).collect();
        let recipients = rotation_recipients(self_device_id, revoke_device_ids, &devices)?;
        let remaining: Vec<DevicePublicKeys> = recipients
            .iter()
            .map(DevicePublicKeys::try_from)
            .collect::<Result<_, _>>()?;

        // Read everything under the current key before replacing it. The plan is
        // what says which rows are re-sealed and at which revision, which
        // tombstones the manifest carries and which rows the rotation retires.
        let verified = self.fetch_verified_objects().await?;
        let old_ck_b64 = self.collection_key_b64()?;
        let plan = rotation_plan(
            &old_ck_b64,
            collection_id,
            &RotationState {
                manifest_seq,
                key_epoch: epoch,
                latest_revision,
                tombstone_floor: verified.tombstone_floor,
            },
            &sealed_rows(&verified.objects),
        )?;

        let new_ck = CollectionKey::generate();
        let RotationWraps {
            key_wraps,
            phrase,
            phrase_recovery,
        } = rotation_wraps_typed(
            &new_ck,
            &WrapBinding {
                collection_id,
                key_epoch: plan.manifest.key_epoch,
            },
            &recipients,
            &username,
        )?;

        let new_ck_b64 = URL_SAFE_NO_PAD.encode(new_ck.as_bytes());
        let mut objects = Vec::with_capacity(plan.reseal.len());
        let mut resealed = Vec::with_capacity(plan.reseal.len());
        let mut upgraded = 0u32;
        for row in &plan.reseal {
            let outcome = reseal_row_upgrading(&old_ck_b64, &new_ck_b64, collection_id, row)?;
            upgraded += u32::from(outcome.upgraded);
            objects.push(rotated_object(&outcome.row)?);
            resealed.push(outcome.row);
        }

        let key_epoch = plan.manifest.key_epoch;
        let manifest_entries = rotation_entries(&plan, &resealed)?;
        let manifest = self.sign_manifest(&plan.manifest, &manifest_entries)?;
        let mut manifest_digest_bytes = [0u8; 32];
        manifest_digest_bytes.copy_from_slice(&manifest.digest);

        let wrap_entries: Vec<WrapDigestEntry<'_>> = key_wraps
            .iter()
            .map(|wrap| WrapDigestEntry {
                recipient_kind: &wrap.recipient_kind,
                recipient_id: &wrap.recipient_id,
                hpke_enc: &wrap.hpke_enc,
                wrapped_ck: &wrap.wrapped_ck,
                ciphersuite: &wrap.ciphersuite,
            })
            .collect();
        let object_entries: Vec<ObjectDigestEntry<'_>> = objects
            .iter()
            .map(|object| ObjectDigestEntry {
                id: object.id,
                revision: object.revision,
                nonce: &object.nonce,
                ciphertext: &object.ciphertext,
                padded_size: object.padded_size as u64,
                content_type: &object.content_type,
                tombstone: object.tombstone,
            })
            .collect();
        let new_roster = RosterBody::seal(
            collection_id,
            roster.roster_seq + 1,
            key_epoch,
            remaining.clone(),
            phrase_recovery.mldsa_pk.clone(),
            phrase_recovery.ed25519_pk.clone(),
            RosterSignerBody::Device {
                device_id: self_device_id,
            },
            &secrets,
            &new_ck,
        )?;
        let transcript = key_rotation_transcript(
            collection_id,
            revoke_device_ids,
            key_epoch,
            &key_wraps_digest(&wrap_entries),
            &rotated_objects_digest(&object_entries),
            &manifest_digest_bytes,
            &rotation_phrase_payload(
                &phrase_recovery.mldsa_pk,
                &phrase_recovery.ed25519_pk,
                &phrase_recovery.lookup_id,
                &phrase_recovery.scheme,
            ),
        );
        let signature = sign(&secrets, &transcript)?;
        confirm(&phrase)?;

        let response: sealbook_protocol::RotateResponse = self
            .post_json(
                &format!("{server}/v2/collections/{collection_id}/rotate"),
                &RotateRequest {
                    key_epoch,
                    revoke_device_ids: revoke_device_ids.to_vec(),
                    key_wraps,
                    phrase_recovery,
                    objects,
                    manifest,
                    rotation_signature: DualSignatureBody {
                        mldsa: signature.mldsa,
                        ed25519: signature.ed25519,
                    },
                    roster: new_roster.clone(),
                    drop_tombstones: plan.retired.clone(),
                },
                Some(&token),
            )
            .await?;

        self.collection_key = Some(new_ck);
        self.key_epoch = response.key_epoch;
        // The rotation carried a manifest at this sequence, like any other write.
        self.accept_manifest_seq(plan.manifest.manifest_seq)?;
        self.pin_roster(&new_roster)?;
        self.rotation_hint = None;
        self.last_rotation_upgraded = upgraded;
        Ok(phrase)
    }

    /// The epoch the cached collection key belongs to.
    pub fn cached_key_epoch(&self) -> u64 {
        self.key_epoch
    }

    /// The collection's current key epoch, per the server.
    pub async fn server_key_epoch(&self) -> Result<u64, ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoState)?;
        let token = state.session_token.as_deref().ok_or(ClientError::NoState)?;
        let resp: CollectionKeysResponse = self
            .get_json(
                &format!(
                    "{}/v2/collections/{}/keys",
                    state.server, state.collection_id
                ),
                Some(token),
            )
            .await?;
        Ok(resp.key_epoch)
    }

    /// Re-fetches this device's collection-key wrap after a rotation.
    ///
    /// Only the device's own X-Wing secret is needed, so this does not require
    /// the password. The wrap alone proves nothing about the key, since anyone
    /// with this device's public key can seal one, so the key is adopted only
    /// once the roster for its epoch commits to it.
    pub async fn refresh_collection_key(&mut self) -> Result<u64, ClientError> {
        let (server, collection_id, device_id, token, hpke_sk) = {
            let state = self.state.as_ref().ok_or(ClientError::NoState)?;
            (
                state.server.clone(),
                state.collection_id,
                state.device_id,
                state.session_token.clone().ok_or(ClientError::NoState)?,
                state.hpke_sk.clone(),
            )
        };
        let resp: CollectionKeysResponse = self
            .get_json(
                &format!("{server}/v2/collections/{collection_id}/keys"),
                Some(&token),
            )
            .await?;
        let wrap = resp
            .key_wraps
            .iter()
            .find(|wrap| {
                wrap.recipient_kind == "device" && wrap.recipient_id == device_id.to_string()
            })
            .ok_or(ClientError::NoCollectionKey)?;
        let (key, form) = unwrap_for_device(
            &DeviceHpkeSecret::from_bytes(hpke_sk),
            &DeviceHpkeWrap {
                enc: wrap.hpke_enc.clone(),
                ciphertext: wrap.wrapped_ck.clone(),
                ciphersuite: XWING_CIPHERSUITE,
            },
            &WrapBinding {
                collection_id,
                key_epoch: resp.key_epoch,
            },
        )?;
        self.adopt_key(
            key,
            resp.key_epoch,
            form == sealbook_crypto::WrapForm::Legacy,
        )
        .await?;
        Ok(resp.key_epoch)
    }
}
