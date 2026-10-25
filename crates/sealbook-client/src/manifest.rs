//! The signed manifest as the CLI fetches it.
//!
//! Every decision here is `sealbook_core::manifest`; this module is the reqwest
//! shell around it, plus the conversion to and from `LocalState`. The roster the
//! signature is checked against is fetched here, because core names the epoch
//! and the signer but cannot go and get them.

use sealbook_core::{
    core_entries, manifest_absence_ok, manifest_accept, manifest_buckets_accept,
    manifest_buckets_from_whole, manifest_buckets_request, manifest_request, manifest_signer,
    manifest_verify, wire_entries, AppliedManifest, BucketedManifest, BucketsOutcome, CoreDevice,
    ManifestContext, ManifestOutcome, ManifestPlan, ManifestSigner,
};
use sealbook_crypto::DeviceSigningSecrets;
use sealbook_protocol::{ManifestBody, ManifestEntry};
use uuid::Uuid;

use crate::{ClientError, SealbookClient};

impl SealbookClient {
    pub(crate) fn manifest_context(&self) -> Result<ManifestContext, ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoState)?;
        Ok(ManifestContext {
            collection_id: state.collection_id,
            device_id: state.device_id,
            manifest_seq: state.manifest_seq,
        })
    }

    pub(crate) fn signing_secrets(&self) -> Result<DeviceSigningSecrets, ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoState)?;
        Ok(DeviceSigningSecrets {
            mldsa_seed: state.mldsa_seed.clone(),
            ed25519_sk: state.ed25519_sk.clone(),
        })
    }

    pub(crate) fn accept_manifest_seq(&mut self, seq: u64) -> Result<(), ClientError> {
        let state = self.state.as_mut().ok_or(ClientError::NoState)?;
        state.manifest_seq = sealbook_core::accept_manifest_seq(state.manifest_seq, seq);
        Ok(())
    }

    /// The collection's manifest and entry set, verified.
    ///
    /// Returns `(manifest_seq, key_epoch, latest_revision, entries)`. A
    /// collection that has never been written by a manifest-signing client has
    /// no manifest, and the epoch to sign the next write under is then the
    /// server's current one rather than a signed one.
    pub(crate) async fn manifest_state(
        &mut self,
    ) -> Result<(u64, u64, u64, Vec<ManifestEntry>), ClientError> {
        let context = self.manifest_context()?;
        let body = self.fetch(&manifest_request(&context)).await?;
        let devices = self.devices_for(manifest_signer(&body.body)?).await?;
        match manifest_accept(&context, &body, &devices)? {
            ManifestOutcome::Signed { plan, entries } => {
                self.accept_manifest_seq(plan.manifest_seq)?;
                Ok((
                    plan.manifest_seq,
                    plan.key_epoch,
                    plan.latest_revision,
                    wire_entries(&entries)?,
                ))
            }
            ManifestOutcome::Unmanifested {
                latest_revision,
                entries,
            } => Ok((
                0,
                self.server_key_epoch().await?,
                latest_revision,
                wire_entries(&entries)?,
            )),
        }
    }

    /// The collection's manifest and the buckets these objects fall in,
    /// verified.
    pub(crate) async fn manifest_bucket_state(
        &mut self,
        object_ids: &[Uuid],
    ) -> Result<BucketedManifest, ClientError> {
        let context = self.manifest_context()?;
        let request = manifest_buckets_request(&context, object_ids);
        let body = self.fetch(&request).await?;
        let devices = self.devices_for(manifest_signer(&body.body)?).await?;
        match manifest_buckets_accept(&context, object_ids, &body, &devices)? {
            BucketsOutcome::Signed { held } => {
                self.accept_manifest_seq(held.plan.manifest_seq)?;
                Ok(held)
            }
            BucketsOutcome::Unmanifested => {
                // A bucket answer carries no revision for the entries it did not
                // serve, so the collection's next revision cannot be chosen from
                // it. One extra request, on a path nothing takes once anything
                // has written a manifest.
                let (manifest_seq, key_epoch, latest_revision, entries) =
                    self.manifest_state().await?;
                Ok(manifest_buckets_from_whole(
                    &ManifestPlan {
                        manifest_seq,
                        key_epoch,
                        latest_revision,
                    },
                    &core_entries(&entries),
                )?)
            }
        }
    }

    /// Checks a manifest served alongside pages of objects against the entry
    /// set those pages produced, and pins its sequence.
    pub(crate) async fn verify_manifest(
        &mut self,
        manifest_json: &str,
        entries: &[ManifestEntry],
    ) -> Result<(), ClientError> {
        let context = self.manifest_context()?;
        let manifest: ManifestBody = serde_json::from_str(manifest_json)
            .map_err(|err| ClientError::Server(format!("unreadable manifest: {err}")))?;
        let devices = self
            .devices_for(Some(ManifestSigner {
                key_epoch: manifest.key_epoch,
                device_id: manifest.device_id,
            }))
            .await?;
        let plan = manifest_verify(&context, manifest_json, &core_entries(entries), &devices)?;
        self.accept_manifest_seq(plan.manifest_seq)?;
        Ok(())
    }

    /// The rule for a server that served objects with no manifest at all.
    pub(crate) fn manifest_absence_ok(&self) -> Result<(), ClientError> {
        Ok(manifest_absence_ok(&self.manifest_context()?)?)
    }

    pub(crate) fn sign_manifest(
        &self,
        plan: &ManifestPlan,
        entries: &[ManifestEntry],
    ) -> Result<ManifestBody, ClientError> {
        Ok(sealbook_core::manifest_sign(
            &self.signing_secrets()?,
            &self.manifest_context()?,
            plan,
            &core_entries(entries),
        )?
        .wire()?)
    }

    pub(crate) fn sign_manifest_root(
        &self,
        plan: &ManifestPlan,
        applied: &AppliedManifest,
    ) -> Result<ManifestBody, ClientError> {
        Ok(sealbook_core::manifest_sign_root(
            &self.signing_secrets()?,
            &self.manifest_context()?,
            plan,
            applied,
        )?
        .wire()?)
    }

    /// The verified roster a manifest signature is checked against, reused
    /// across writes.
    ///
    /// Refetched when the epoch has moved, which is what a revocation looks
    /// like from here since every revocation rotates, or when the signer is one
    /// the cache does not hold, which is what a pairing elsewhere looks like.
    async fn devices_for(
        &mut self,
        signer: Option<ManifestSigner>,
    ) -> Result<Vec<CoreDevice>, ClientError> {
        // No manifest means no signature to check, and so no roster to fetch.
        let Some(signer) = signer else {
            return Ok(Vec::new());
        };
        if let Some(cached) = &self.roster_cache {
            if sealbook_core::roster_answers_for(
                Some(cached),
                Some(signer.key_epoch),
                Some(signer.device_id),
            ) {
                return Ok(cached.devices.clone());
            }
        }
        let verified = self.verified_roster_core().await?;
        let devices = verified.roster.devices.clone();
        self.roster_cache = Some(verified.roster);
        Ok(devices)
    }

    pub(crate) async fn fetch(
        &self,
        request: &sealbook_core::HttpRequest,
    ) -> Result<sealbook_core::HttpResponse, ClientError> {
        let token = {
            let state = self.state.as_ref().ok_or(ClientError::NoState)?;
            state.session_token.clone().ok_or(ClientError::NoState)?
        };
        self.send(request, Some(&token)).await
    }
}
