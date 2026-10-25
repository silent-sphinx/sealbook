//! The signed manifest: how a served collection is checked against what a
//! device vouched for, and how this device vouches for the next state.

use uuid::Uuid;

use sealbook_crypto::{
    manifest_bucket_digest, manifest_bucket_of, manifest_digest, manifest_root,
    manifest_transcript, sign, verify, DeviceSigningPublic, DeviceSigningSecrets, DualSignature,
    ManifestDigestEntry, MANIFEST_BUCKETS,
};
use sealbook_protocol::{
    bucket_query, DevicePublicKeys, DualSignatureBody, ManifestBody, ManifestBucketsResponse,
    ManifestEntry, ManifestResponse,
};

use crate::{ClientError, ManifestError, SealbookClient};

/// The collection as one write needs to see it.
///
/// A write changes one bucket per object, so it needs those buckets' entries and
/// the remaining digests, not the whole collection. `apply` does the update and
/// returns what the next manifest has to commit to.
pub(crate) struct BucketedManifest {
    pub(crate) seq: u64,
    pub(crate) key_epoch: u64,
    pub(crate) latest_revision: u64,
    buckets: [[u8; 32]; MANIFEST_BUCKETS],
    object_count: u64,
    /// The buckets whose entries are held, ascending. An entry outside them
    /// cannot be folded in, because its bucket's digest cannot be recomputed
    /// from entries this client was not served.
    held: Vec<u8>,
    entries: Vec<ManifestEntry>,
}

impl BucketedManifest {
    /// Folds the written entries in, and returns the object count and root the
    /// manifest for the collection after that write must carry.
    ///
    /// The server recomputes both from its own rows, so these have to be derived
    /// the same way: replace each entry in its bucket, rehash the buckets that
    /// changed, rehash the root over all 256.
    pub(crate) fn apply(
        mut self,
        written: &[ManifestEntry],
    ) -> Result<(u64, [u8; 32]), ManifestError> {
        let mut fresh = 0u64;
        let mut touched: Vec<u8> = Vec::with_capacity(written.len());
        for entry in written {
            let bucket = manifest_bucket_of(entry.id);
            if !self.held.contains(&bucket) {
                return Err(ManifestError(
                    "a write was folded into a bucket this device did not fetch".into(),
                ));
            }
            touched.push(bucket);
            match self.entries.iter_mut().find(|held| held.id == entry.id) {
                Some(held) => *held = entry.clone(),
                None => {
                    self.entries.push(entry.clone());
                    fresh += 1;
                }
            }
        }
        touched.sort_unstable();
        touched.dedup();
        for bucket in touched {
            let members: Vec<ManifestEntry> = self
                .entries
                .iter()
                .filter(|entry| manifest_bucket_of(entry.id) == bucket)
                .cloned()
                .collect();
            self.buckets[bucket as usize] = if members.is_empty() {
                [0u8; 32]
            } else {
                manifest_bucket_digest(&SealbookClient::digest_inputs(&members)?)
            };
        }
        let object_count = self.object_count + fresh;
        Ok((object_count, manifest_root(&self.buckets, object_count)))
    }
}

impl SealbookClient {
    pub(crate) fn signing_secrets(&self) -> Result<DeviceSigningSecrets, ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoState)?;
        Ok(DeviceSigningSecrets {
            mldsa_seed: state.mldsa_seed.clone(),
            ed25519_sk: state.ed25519_sk.clone(),
        })
    }

    fn digest_entries(entries: &[ManifestEntry]) -> Result<[u8; 32], ManifestError> {
        Ok(manifest_digest(&Self::digest_inputs(entries)?))
    }

    fn digest_inputs(entries: &[ManifestEntry]) -> Result<Vec<ManifestDigestEntry>, ManifestError> {
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
        Ok(out)
    }

    pub(crate) fn accept_manifest_seq(&mut self, seq: u64) -> Result<(), ClientError> {
        let state = self.state.as_mut().ok_or(ClientError::NoState)?;
        state.manifest_seq = state.manifest_seq.max(seq);
        Ok(())
    }

    /// Checks a served manifest against the entry set it is supposed to describe,
    /// and pins its sequence number.
    pub(crate) fn verify_manifest(
        &mut self,
        manifest: &ManifestBody,
        entries: &[ManifestEntry],
        devices: &[DevicePublicKeys],
    ) -> Result<(), ManifestError> {
        let (collection_id, pinned_seq) = {
            let state = self.state.as_ref().ok_or_else(|| {
                ManifestError("no local state to verify a manifest against".into())
            })?;
            (state.collection_id, state.manifest_seq)
        };
        if manifest.manifest_seq < pinned_seq {
            return Err(ManifestError(format!(
                "manifest went backwards: this device has already seen sequence {} but was \
                 served {}",
                pinned_seq, manifest.manifest_seq
            )));
        }
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
                collection_id,
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
        // Verified, so this is now the oldest manifest this device will accept.
        if let Some(state) = self.state.as_mut() {
            state.manifest_seq = state.manifest_seq.max(manifest.manifest_seq);
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
        &mut self,
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

    /// The collection's manifest and the buckets these objects fall in, verified.
    ///
    /// Two checks together are what the single whole-collection digest check used
    /// to be. The served entries of each bucket must hash to that bucket's digest,
    /// which catches an object withheld from or substituted within a bucket. The
    /// digests with the count must produce the root the signature covers, which
    /// catches an edited digest and pins the buckets that were not served.
    pub(crate) async fn manifest_bucket_state(
        &mut self,
        object_ids: &[Uuid],
    ) -> Result<BucketedManifest, ClientError> {
        let (server, collection_id, token) = {
            let state = self.state.as_ref().ok_or(ClientError::NoState)?;
            (
                state.server.clone(),
                state.collection_id,
                state.session_token.clone().ok_or(ClientError::NoState)?,
            )
        };
        let mut wanted: Vec<u8> = object_ids.iter().copied().map(manifest_bucket_of).collect();
        wanted.sort_unstable();
        wanted.dedup();
        let response: ManifestBucketsResponse = self
            .get_json(
                &format!(
                    "{server}/v1/collections/{collection_id}/manifest/buckets?buckets={}",
                    bucket_query(&wanted)
                ),
                Some(&token),
            )
            .await?;
        // Both lists are sorted and deduplicated, so this is the whole check that
        // every bucket asked for was answered for.
        if response.served != wanted {
            return Err(ManifestError("server answered for other buckets".into()).into());
        }
        let buckets = Self::buckets_from_blob(&response.buckets)?;
        // Each served bucket's entries must be what its digest commits to.
        for bucket in &wanted {
            let members: Vec<ManifestEntry> = response
                .entries
                .iter()
                .filter(|entry| manifest_bucket_of(entry.id) == *bucket)
                .cloned()
                .collect();
            if Self::digest_entries_bucket(&members)? != buckets[*bucket as usize] {
                return Err(ManifestError(
                    "the entries served for this bucket do not match its digest; an object may \
                     have been withheld, rolled back or substituted"
                        .into(),
                )
                .into());
            }
        }
        for entry in &response.entries {
            if !wanted.contains(&manifest_bucket_of(entry.id)) {
                return Err(ManifestError("server put an entry in the wrong bucket".into()).into());
            }
        }

        let (seq, key_epoch, latest_revision) = match &response.manifest {
            Some(manifest) => {
                if manifest.object_count != response.object_count {
                    return Err(ManifestError(format!(
                        "server says {} objects but the manifest commits to {}",
                        response.object_count, manifest.object_count
                    ))
                    .into());
                }
                let root = manifest_root(&buckets, response.object_count);
                self.verify_manifest_root(manifest, &root).await?;
                (
                    manifest.manifest_seq,
                    manifest.key_epoch,
                    manifest.latest_revision,
                )
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
                (0, epoch, latest)
            }
        };

        Ok(BucketedManifest {
            seq,
            key_epoch,
            latest_revision,
            buckets,
            object_count: response.object_count,
            held: wanted,
            entries: response.entries,
        })
    }

    fn buckets_from_blob(blob: &[u8]) -> Result<[[u8; 32]; MANIFEST_BUCKETS], ManifestError> {
        if blob.len() != MANIFEST_BUCKETS * 32 {
            return Err(ManifestError(format!(
                "expected {} bytes of bucket digests, got {}",
                MANIFEST_BUCKETS * 32,
                blob.len()
            )));
        }
        let mut buckets = [[0u8; 32]; MANIFEST_BUCKETS];
        for (bucket, chunk) in buckets.iter_mut().zip(blob.chunks(32)) {
            bucket.copy_from_slice(chunk);
        }
        Ok(buckets)
    }

    /// One bucket's digest, or all zeroes for an empty bucket, matching how the
    /// root is built.
    fn digest_entries_bucket(entries: &[ManifestEntry]) -> Result<[u8; 32], ManifestError> {
        if entries.is_empty() {
            return Ok([0u8; 32]);
        }
        Ok(manifest_bucket_digest(&Self::digest_inputs(entries)?))
    }

    /// Checks a served manifest against a root derived from the bucket digests,
    /// and pins its sequence number.
    async fn verify_manifest_root(
        &mut self,
        manifest: &ManifestBody,
        root: &[u8; 32],
    ) -> Result<(), ClientError> {
        let (collection_id, pinned_seq) = {
            let state = self.state.as_ref().ok_or(ClientError::NoState)?;
            (state.collection_id, state.manifest_seq)
        };
        if manifest.manifest_seq < pinned_seq {
            return Err(ManifestError(format!(
                "manifest went backwards: this device has already seen sequence {} but was \
                 served {}",
                pinned_seq, manifest.manifest_seq
            ))
            .into());
        }
        if manifest.digest != root {
            return Err(ManifestError(
                "the bucket digests served do not match the signed manifest; an object may \
                 have been withheld, rolled back or substituted"
                    .into(),
            )
            .into());
        }
        let devices = self
            .roster_for(manifest.key_epoch, manifest.device_id)
            .await?;
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
                collection_id,
                manifest.manifest_seq,
                manifest.key_epoch,
                manifest.latest_revision,
                manifest.object_count,
                root,
            ),
            &DualSignature {
                mldsa: manifest.signature.mldsa.clone(),
                ed25519: manifest.signature.ed25519.clone(),
            },
        )
        .map_err(|_| ManifestError("manifest signature does not verify".into()))?;
        if let Some(state) = self.state.as_mut() {
            state.manifest_seq = state.manifest_seq.max(manifest.manifest_seq);
        }
        Ok(())
    }

    /// The verified roster, reused across writes.
    ///
    /// Refetched when the epoch has moved, which is what a revocation looks like
    /// from here since every revocation rotates, or when the signer is one the
    /// cache does not hold, which is what a pairing elsewhere looks like.
    async fn roster_for(
        &mut self,
        key_epoch: u64,
        signer: Uuid,
    ) -> Result<Vec<DevicePublicKeys>, ClientError> {
        if let Some((cached, devices)) = &self.roster_cache {
            if sealbook_core::roster_answers_for(Some(cached), Some(key_epoch), Some(signer)) {
                return Ok(devices.clone());
            }
        }
        let verified = self.verified_roster_core().await?;
        let roster: sealbook_protocol::RosterBody = serde_json::from_str(&verified.roster_json)
            .map_err(|err| ClientError::Server(err.to_string()))?;
        self.roster_cache = Some((verified.roster, roster.devices.clone()));
        Ok(roster.devices)
    }

    /// Signs a manifest whose digest has already been derived, for the write path
    /// that never holds the whole entry set.
    pub(crate) fn sign_manifest_root(
        &self,
        seq: u64,
        key_epoch: u64,
        latest_revision: u64,
        object_count: u64,
        root: &[u8; 32],
    ) -> Result<ManifestBody, ClientError> {
        let (collection_id, device_id) = {
            let state = self.state.as_ref().ok_or(ClientError::NoState)?;
            (state.collection_id, state.device_id)
        };
        let signature = sign(
            &self.signing_secrets()?,
            &manifest_transcript(
                collection_id,
                seq,
                key_epoch,
                latest_revision,
                object_count,
                root,
            ),
        )?;
        Ok(ManifestBody {
            manifest_seq: seq,
            key_epoch,
            latest_revision,
            object_count,
            digest: root.to_vec(),
            device_id,
            signature: DualSignatureBody {
                mldsa: signature.mldsa,
                ed25519: signature.ed25519,
            },
        })
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
