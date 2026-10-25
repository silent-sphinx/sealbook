//! The collection key's lifecycle: which devices hold it, when it is replaced,
//! and how a device gets back to the current one.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use uuid::Uuid;

use sealbook_crypto::{
    generate_kdf_salt, generate_phrase, key_rotation_transcript, key_wraps_digest,
    phrase_lookup_id, phrase_recovery_public, rotated_objects_digest, rotation_recovery_payload,
    sign, unwrap_collection_key, unwrap_for_device, wrap_collection_key, wrap_for_device,
    wrap_for_phrase, CollectionKey, DeviceHpkePublic, DeviceHpkeSecret, DeviceHpkeWrap,
    DeviceSigningSecrets, ObjectDigestEntry, RecoveryWrap, WrapDigestEntry, PHRASE_CIPHERSUITE,
    PHRASE_SCHEME, RECOVERY_CIPHERSUITE, XWING_CIPHERSUITE,
};
use sealbook_protocol::{
    CollectionKeysResponse, DevicePublicKeys, DualSignatureBody, KeyWrapBody, PhraseRecoveryBody,
    RosterBody, RosterSignerBody, RotateRequest, RotatedObject, SEALED_CONTENT_TYPE,
};

use sealbook_core::{
    reseal_row, rotation_entries, rotation_plan, rotation_recipients, CoreDevice, CoreSealedRow,
    RotationState,
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
    pub async fn revoke_device(
        &mut self,
        device_id: Uuid,
        password: &str,
    ) -> Result<String, ClientError> {
        self.rotate(Some(device_id), password).await
    }

    /// Issues a new recovery phrase and rotates the collection key onto it.
    ///
    /// Replacing the phrase without rotating would leave anyone who has ever seen
    /// the old phrase able to decrypt: the wrap they captured still opens the same
    /// key. This is also why a completed recovery rotates.
    pub async fn change_phrase(&mut self, password: &str) -> Result<String, ClientError> {
        self.rotate(None, password).await
    }

    /// Replaces the collection key and re-encrypts the vault under it.
    ///
    /// One code path for every operation that has to invalidate the old key,
    /// because they all need the same work: read everything under the current key,
    /// generate a new one, re-wrap it for each device that keeps access plus the
    /// password and a fresh phrase, re-encrypt every object, and sign the lot.
    pub async fn rotate(
        &mut self,
        revoke_device_id: Option<Uuid>,
        password: &str,
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
        let remaining: Vec<DevicePublicKeys> =
            rotation_recipients(self_device_id, revoke_device_id, &devices)?
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
        let salt = generate_kdf_salt();
        let recovery = wrap_collection_key(password.as_bytes(), &salt, &new_ck)?;
        let (phrase, phrase_entropy) = generate_phrase()?;
        let phrase_wrap = wrap_for_phrase(&phrase_entropy, &new_ck)?;

        let mut key_wraps = Vec::with_capacity(remaining.len() + 2);
        for device in &remaining {
            let wrap = wrap_for_device(&DeviceHpkePublic(device.xwing_hpke_pk.clone()), &new_ck)?;
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
            recipient_id: username.clone(),
            hpke_enc: recovery.nonce.to_vec(),
            wrapped_ck: recovery.ciphertext,
            ciphersuite: RECOVERY_CIPHERSUITE.into(),
        });
        key_wraps.push(KeyWrapBody {
            recipient_kind: "phrase".into(),
            recipient_id: username,
            hpke_enc: phrase_wrap.nonce.to_vec(),
            wrapped_ck: phrase_wrap.ciphertext,
            ciphersuite: PHRASE_CIPHERSUITE.into(),
        });

        let new_ck_b64 = URL_SAFE_NO_PAD.encode(new_ck.as_bytes());
        let mut objects = Vec::with_capacity(plan.reseal.len());
        let mut resealed = Vec::with_capacity(plan.reseal.len());
        for row in &plan.reseal {
            let sealed = reseal_row(&old_ck_b64, &new_ck_b64, collection_id, row)?;
            objects.push(rotated_object(&sealed)?);
            resealed.push(sealed);
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
        let phrase_recovery = phrase_recovery_body(&phrase_entropy)?;
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
            revoke_device_id,
            key_epoch,
            &key_wraps_digest(&wrap_entries),
            &rotated_objects_digest(&object_entries),
            &manifest_digest_bytes,
            &rotation_recovery_payload(
                &salt,
                &phrase_recovery.mldsa_pk,
                &phrase_recovery.ed25519_pk,
                &phrase_recovery.lookup_id,
                &phrase_recovery.scheme,
            ),
        );
        let signature = sign(&secrets, &transcript)?;

        let response: sealbook_protocol::RotateResponse = self
            .post_json(
                &format!("{server}/v1/collections/{collection_id}/rotate"),
                &RotateRequest {
                    key_epoch,
                    revoke_device_id,
                    kdf_salt: salt.to_vec(),
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
        if let Some(state) = self.state.as_mut() {
            state.kdf_salt = salt.to_vec();
        }
        // The rotation carried a manifest at this sequence, like any other write.
        self.accept_manifest_seq(plan.manifest.manifest_seq)?;
        self.pin_roster(&new_roster)?;
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
                    "{}/v1/collections/{}/keys",
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
    /// the password.
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
                &format!("{server}/v1/collections/{collection_id}/keys"),
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
        let key = unwrap_for_device(
            &DeviceHpkeSecret::from_bytes(hpke_sk),
            &DeviceHpkeWrap {
                enc: wrap.hpke_enc.clone(),
                ciphertext: wrap.wrapped_ck.clone(),
                ciphersuite: XWING_CIPHERSUITE,
            },
        )?;
        self.collection_key = Some(key);
        self.key_epoch = resp.key_epoch;
        Ok(resp.key_epoch)
    }
}

pub(crate) fn unwrap_ck(
    password: &[u8],
    salt: &[u8],
    hpke_sk: &[u8],
    device_id: &str,
    wraps: &[KeyWrapBody],
) -> Result<CollectionKey, ClientError> {
    let device_key = if let Some(device) = wraps
        .iter()
        .find(|w| w.recipient_kind == "device" && w.recipient_id == device_id)
    {
        let wrap = DeviceHpkeWrap {
            enc: device.hpke_enc.clone(),
            ciphertext: device.wrapped_ck.clone(),
            ciphersuite: XWING_CIPHERSUITE,
        };
        Some(unwrap_for_device(
            &DeviceHpkeSecret::from_bytes(hpke_sk.to_vec()),
            &wrap,
        )?)
    } else {
        None
    };
    if let Some(device_key) = device_key {
        return Ok(device_key);
    }
    if let Some(recovery) = wraps.iter().find(|w| w.recipient_kind == "recovery") {
        let mut nonce = [0u8; 24];
        if recovery.hpke_enc.len() != 24 {
            return Err(ClientError::Nonce);
        }
        nonce.copy_from_slice(&recovery.hpke_enc);
        let wrap = RecoveryWrap {
            nonce,
            ciphertext: recovery.wrapped_ck.clone(),
            ciphersuite: RECOVERY_CIPHERSUITE.to_string(),
        };
        let recovery_key = unwrap_collection_key(password, salt, &wrap)?;
        return Ok(recovery_key);
    }
    Err(ClientError::NoCollectionKey)
}

pub(crate) fn phrase_recovery_body(
    entropy: &[u8; sealbook_crypto::PHRASE_ENTROPY_LEN],
) -> Result<PhraseRecoveryBody, ClientError> {
    let public = phrase_recovery_public(entropy)?;
    Ok(PhraseRecoveryBody {
        mldsa_pk: public.mldsa_pk,
        ed25519_pk: public.ed25519_pk,
        lookup_id: phrase_lookup_id(entropy)?.to_vec(),
        scheme: PHRASE_SCHEME.to_string(),
    })
}
