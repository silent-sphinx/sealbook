//! The signed manifest: how a served collection is checked against what a
//! device vouched for, and how this device vouches for the next state.

use sealbook_crypto::{
    manifest_digest, manifest_transcript, sign, verify, DeviceSigningPublic, DeviceSigningSecrets,
    DualSignature, ManifestDigestEntry,
};
use sealbook_protocol::{
    DevicePublicKeys, DualSignatureBody, ManifestBody, ManifestEntry, ManifestResponse,
};

use crate::{ClientError, ManifestError, SealbookClient};

impl SealbookClient {
    pub(crate) fn signing_secrets(&self) -> Result<DeviceSigningSecrets, ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoState)?;
        Ok(DeviceSigningSecrets {
            mldsa_seed: state.mldsa_seed.clone(),
            ed25519_sk: state.ed25519_sk.clone(),
        })
    }

    fn digest_entries(entries: &[ManifestEntry]) -> Result<[u8; 32], ManifestError> {
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            if entry.content_digest.len() != 32 {
                return Err(ManifestError("entry has a malformed content digest".into()));
            }
            let mut content_digest = [0u8; 32];
            content_digest.copy_from_slice(&entry.content_digest);
            out.push(ManifestDigestEntry {
                id: entry.id,
                revision: entry.revision,
                tombstone: entry.tombstone,
                content_digest,
            });
        }
        Ok(manifest_digest(&out))
    }

    /// Checks a served manifest against the entry set it is supposed to describe.
    ///
    /// The signature says an enrolled device vouched for this shape of the
    /// collection; the digest says the shape is the one being served. Both are
    /// needed: a valid signature over a different state is exactly what a rollback
    /// looks like.
    pub(crate) fn verify_manifest(
        &self,
        manifest: &ManifestBody,
        entries: &[ManifestEntry],
        devices: &[DevicePublicKeys],
    ) -> Result<(), ManifestError> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| ManifestError("no local state to verify a manifest against".into()))?;
        if manifest.object_count != entries.len() as u64 {
            return Err(ManifestError(format!(
                "server sent {} objects but the manifest commits to {}",
                entries.len(),
                manifest.object_count
            )));
        }
        let digest = Self::digest_entries(entries)?;
        if manifest.digest != digest {
            return Err(ManifestError(
                "the objects served do not match the signed manifest; an object may have been \
                 withheld, rolled back or substituted"
                    .into(),
            ));
        }
        // The signing device is normally this one; after a pairing or a rotation it
        // may be another of the account's devices.
        let signer = devices
            .iter()
            .find(|device| device.device_id == manifest.device_id)
            .ok_or_else(|| {
                ManifestError("manifest signed by a device this account does not have".into())
            })?;
        verify(
            &DeviceSigningPublic {
                mldsa_pk: signer.mldsa_pk.clone(),
                ed25519_pk: signer.ed25519_pk.clone(),
            },
            &manifest_transcript(
                state.collection_id,
                manifest.manifest_seq,
                manifest.key_epoch,
                manifest.latest_revision,
                manifest.object_count,
                &digest,
            ),
            &DualSignature {
                mldsa: manifest.signature.mldsa.clone(),
                ed25519: manifest.signature.ed25519.clone(),
            },
        )
        .map_err(|_| ManifestError("manifest signature does not verify".into()))?;
        if manifest.manifest_seq < state.manifest_seq {
            return Err(ManifestError(format!(
                "manifest went backwards: this device has already seen sequence {} but was \
                 served {}",
                state.manifest_seq, manifest.manifest_seq
            )));
        }
        Ok(())
    }

    /// The collection's manifest and entry set, verified.
    ///
    /// Returns `(manifest_seq, key_epoch, latest_revision, entries)`. A collection
    /// that has never been written by a v3 client has no manifest; that is accepted
    /// once, and only while this device has never seen one, so a server cannot
    /// pretend a vault is unmanifested to hide its contents.
    pub(crate) async fn manifest_state(
        &self,
    ) -> Result<(u64, u64, u64, Vec<ManifestEntry>), ClientError> {
        let (server, collection_id, token) = {
            let state = self.state.as_ref().ok_or(ClientError::NoState)?;
            (
                state.server.clone(),
                state.collection_id,
                state.session_token.clone().ok_or(ClientError::NoState)?,
            )
        };
        let response: ManifestResponse = self
            .get_json(
                &format!("{server}/v1/collections/{collection_id}/manifest"),
                Some(&token),
            )
            .await?;
        match response.manifest {
            Some(manifest) => {
                let devices = self.list_devices().await?;
                self.verify_manifest(&manifest, &response.entries, &devices)?;
                Ok((
                    manifest.manifest_seq,
                    manifest.key_epoch,
                    manifest.latest_revision,
                    response.entries,
                ))
            }
            None => {
                let state = self.state.as_ref().ok_or(ClientError::NoState)?;
                if state.manifest_seq > 0 {
                    return Err(ManifestError(format!(
                        "server has no manifest, but this device has seen sequence {}",
                        state.manifest_seq
                    ))
                    .into());
                }
                let epoch = self.server_key_epoch().await?;
                let latest = response
                    .entries
                    .iter()
                    .map(|entry| entry.revision)
                    .max()
                    .unwrap_or(0);
                Ok((0, epoch, latest, response.entries))
            }
        }
    }

    pub(crate) fn sign_manifest(
        &self,
        seq: u64,
        key_epoch: u64,
        latest_revision: u64,
        entries: &[ManifestEntry],
    ) -> Result<ManifestBody, ClientError> {
        let (collection_id, device_id) = {
            let state = self.state.as_ref().ok_or(ClientError::NoState)?;
            (state.collection_id, state.device_id)
        };
        let digest = Self::digest_entries(entries)?;
        let signature = sign(
            &self.signing_secrets()?,
            &manifest_transcript(
                collection_id,
                seq,
                key_epoch,
                latest_revision,
                entries.len() as u64,
                &digest,
            ),
        )?;
        Ok(ManifestBody {
            manifest_seq: seq,
            key_epoch,
            latest_revision,
            object_count: entries.len() as u64,
            digest: digest.to_vec(),
            device_id,
            signature: DualSignatureBody {
                mldsa: signature.mldsa,
                ed25519: signature.ed25519,
            },
        })
    }
}
