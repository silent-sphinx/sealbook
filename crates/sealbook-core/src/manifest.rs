//! Manifest decisions: what to ask for, whether what came back is the
//! collection a device vouched for, and what the next manifest commits to.
//!
//! The roster is the host's to fetch, because the manifest names the epoch and
//! the signer it must be checked against and that is only known once the
//! response has been read. So a verify here is two calls: [`manifest_signer`]
//! says who to look up, and the accept takes the devices that came back.
//!
//! As in [`crate::roster`], the host has already raised anything that is not a
//! success, so the status check is a guard rather than the error path.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sealbook_crypto::{
    manifest_bucket_digest, manifest_bucket_of, manifest_digest, manifest_root,
    manifest_transcript, sign, verify, DeviceSigningPublic, DeviceSigningSecrets, DualSignature,
    ManifestDigestEntry, MANIFEST_BUCKETS,
};
use sealbook_protocol::{
    bucket_query, DualSignatureBody, ManifestBody, ManifestBucketsResponse, ManifestEntry,
    ManifestResponse,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{CoreDevice, CoreError, HttpRequest, HttpResponse, Method};

/// Just what a manifest decision reads out of the persisted state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ManifestContext {
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub collection_id: Uuid,
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub device_id: Uuid,
    /// Highest sequence this device has accepted. 0 means none.
    pub manifest_seq: u64,
}

/// What a manifest says about the collection, apart from its contents.
///
/// The three numbers travel together everywhere: a read returns them, a write
/// derives the next from them, and a signature covers them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ManifestPlan {
    pub manifest_seq: u64,
    pub key_epoch: u64,
    pub latest_revision: u64,
}

/// One object as the manifest commits to it, with the digest base64 as all
/// three clients already hold it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreManifestEntry {
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub id: Uuid,
    pub revision: u64,
    pub tombstone: bool,
    /// base64 of `SHA-256(nonce || ciphertext)`.
    pub content_digest: String,
}

/// The key epoch and device a served manifest must be checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ManifestSigner {
    pub key_epoch: u64,
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub device_id: Uuid,
}

/// A manifest this device has signed, in the shape the server expects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SignedManifest {
    pub plan: ManifestPlan,
    pub object_count: u64,
    pub digest: String,
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub device_id: Uuid,
    pub mldsa: String,
    pub ed25519: String,
    /// The wire form, for the host that embeds it in a write body it builds
    /// itself rather than reassembling the fields above.
    pub manifest_json: String,
}

/// A verified whole-collection manifest, or the absence of one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum ManifestOutcome {
    Signed {
        plan: ManifestPlan,
        entries: Vec<CoreManifestEntry>,
    },
    /// A collection no manifest-writing client has written yet. Accepted only
    /// while this device has never seen a manifest, which core has checked, so
    /// a server cannot pretend one away. The key epoch is the host's to supply:
    /// there is no signed one to read.
    Unmanifested {
        latest_revision: u64,
        entries: Vec<CoreManifestEntry>,
    },
}

/// The collection as one write needs to see it.
///
/// A write changes one bucket per object, so it needs those buckets' entries
/// and the remaining digests rather than the whole collection.
/// [`manifest_apply`] folds the write in and says what the next manifest must
/// commit to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct BucketedManifest {
    pub plan: ManifestPlan,
    pub object_count: u64,
    /// The 256 bucket digests concatenated, 32 bytes each, base64.
    pub buckets: String,
    /// The buckets whose entries are held, ascending. An entry outside them
    /// cannot be folded in, because its bucket's digest cannot be recomputed
    /// from entries this client was not served.
    pub held: Vec<u8>,
    pub entries: Vec<CoreManifestEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum BucketsOutcome {
    Signed { held: BucketedManifest },
    /// No manifest yet. A bucket answer carries no revision for the entries it
    /// did not serve, so the collection's next revision cannot be chosen from
    /// it: the host reads the whole set and calls
    /// [`manifest_buckets_from_whole`]. One extra request, on a path nothing
    /// takes once anything has written a manifest.
    Unmanifested,
}

/// What the manifest after a write has to carry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AppliedManifest {
    pub object_count: u64,
    pub root: String,
}

impl SignedManifest {
    /// The wire type, for a host that builds its request body in Rust.
    pub fn wire(&self) -> Result<ManifestBody, CoreError> {
        Ok(serde_json::from_str(&self.manifest_json)?)
    }
}

/// The request that fetches the manifest with every entry it commits to.
pub fn manifest_request(context: &ManifestContext) -> HttpRequest {
    get(format!(
        "/v1/collections/{}/manifest",
        context.collection_id
    ))
}

/// The request that fetches the manifest with only the buckets these objects
/// fall in.
pub fn manifest_buckets_request(context: &ManifestContext, ids: &[Uuid]) -> HttpRequest {
    get(format!(
        "/v1/collections/{}/manifest/buckets?buckets={}",
        context.collection_id,
        bucket_query(&buckets_of(ids))
    ))
}

/// The epoch and device a served manifest must be checked against, so the host
/// can fetch the roster before accepting it.
///
/// `None` is a collection with no manifest, which needs no roster. Reads either
/// response shape, since both carry the manifest under the same name.
pub fn manifest_signer(body: &[u8]) -> Result<Option<ManifestSigner>, CoreError> {
    #[derive(Deserialize)]
    struct Served {
        manifest: Option<ManifestBody>,
    }
    let served: Served = serde_json::from_slice(body).map_err(unreadable)?;
    Ok(served.manifest.map(|manifest| ManifestSigner {
        key_epoch: manifest.key_epoch,
        device_id: manifest.device_id,
    }))
}

/// Checks a served manifest against the entry set it is supposed to describe.
///
/// The signature says an enrolled device vouched for this shape of the
/// collection; the digest says the shape is the one being served. A valid
/// signature over a different state is what a rollback looks like, so both are
/// required. Does not move the pin; [`accept_manifest_seq`] does.
pub fn manifest_accept(
    context: &ManifestContext,
    response: &HttpResponse,
    devices: &[CoreDevice],
) -> Result<ManifestOutcome, CoreError> {
    let served: ManifestResponse = read_body(response)?;
    let entries = project(&served.entries);
    let Some(manifest) = served.manifest else {
        return unmanifested(context, entries);
    };
    let plan = against_entries(context, &manifest, &served.entries, devices)?;
    Ok(ManifestOutcome::Signed { plan, entries })
}

/// Checks a manifest against an entry set the host derived itself.
///
/// For the read path, where the manifest arrives alongside pages of objects
/// rather than with the entry set it commits to.
pub fn manifest_verify(
    context: &ManifestContext,
    manifest_json: &str,
    entries: &[CoreManifestEntry],
    devices: &[CoreDevice],
) -> Result<ManifestPlan, CoreError> {
    let manifest: ManifestBody = serde_json::from_str(manifest_json).map_err(unreadable)?;
    against_entries(context, &manifest, &unproject(entries)?, devices)
}

/// The rule for a server that served no manifest at all.
///
/// A collection nothing has written a manifest for is a real state, but only
/// for a device that has never seen one: otherwise a server could hide a vault
/// by claiming it was never written.
pub fn manifest_absence_ok(context: &ManifestContext) -> Result<(), CoreError> {
    if context.manifest_seq > 0 {
        return Err(CoreError::manifest(format!(
            "server has no manifest, but this device has seen sequence {}",
            context.manifest_seq
        )));
    }
    Ok(())
}

/// Checks a bucketed manifest answer and returns what a write needs from it.
///
/// Two checks together are what the single whole-collection digest check used
/// to be. The served entries of each bucket must hash to that bucket's digest,
/// which catches an object withheld from or substituted within a bucket. The
/// digests with the count must produce the root the signature covers, which
/// catches an edited digest and pins the buckets that were not served.
pub fn manifest_buckets_accept(
    context: &ManifestContext,
    ids: &[Uuid],
    response: &HttpResponse,
    devices: &[CoreDevice],
) -> Result<BucketsOutcome, CoreError> {
    let served: ManifestBucketsResponse = read_body(response)?;
    let wanted = buckets_of(ids);
    // Both lists are sorted and deduplicated, so this is the whole check that
    // every bucket asked for was answered for.
    if served.served != wanted {
        return Err(CoreError::manifest("server answered for other buckets"));
    }
    let buckets = buckets_from_blob(&served.buckets)?;
    for bucket in &wanted {
        let members = in_bucket(&served.entries, *bucket);
        if bucket_digest(&members)? != buckets[*bucket as usize] {
            return Err(CoreError::manifest(
                "the entries served for this bucket do not match its digest; an object may have \
                 been withheld, rolled back or substituted",
            ));
        }
    }
    for entry in &served.entries {
        if !wanted.contains(&manifest_bucket_of(entry.id)) {
            return Err(CoreError::manifest("server put an entry in the wrong bucket"));
        }
    }
    let Some(manifest) = served.manifest else {
        // Still core's rule to apply, even though the host reads again: a
        // server may not drop the manifest for a device that has seen one.
        unmanifested(context, Vec::new())?;
        return Ok(BucketsOutcome::Unmanifested);
    };
    not_backwards(context, &manifest)?;
    if manifest.object_count != served.object_count {
        return Err(CoreError::manifest(format!(
            "server says {} objects but the manifest commits to {}",
            served.object_count, manifest.object_count
        )));
    }
    let root = manifest_root(&buckets, served.object_count);
    if manifest.digest != root {
        return Err(CoreError::manifest(
            "the bucket digests served do not match the signed manifest; an object may have been \
             withheld, rolled back or substituted",
        ));
    }
    check_signature(context, &manifest, &root, devices)?;
    Ok(BucketsOutcome::Signed {
        held: BucketedManifest {
            plan: plan_of(&manifest),
            object_count: served.object_count,
            buckets: encode(&served.buckets),
            held: wanted,
            entries: project(&served.entries),
        },
    })
}

/// The bucketed view of a collection whose every entry is in hand.
///
/// For the manifestless write path, where the whole set had to be read anyway.
pub fn manifest_buckets_from_whole(
    plan: &ManifestPlan,
    entries: &[CoreManifestEntry],
) -> Result<BucketedManifest, CoreError> {
    let mut grouped: Vec<Vec<ManifestEntry>> = vec![Vec::new(); MANIFEST_BUCKETS];
    for entry in unproject(entries)? {
        grouped[manifest_bucket_of(entry.id) as usize].push(entry);
    }
    let mut buckets = [[0u8; 32]; MANIFEST_BUCKETS];
    for (digest, members) in buckets.iter_mut().zip(grouped) {
        *digest = bucket_digest(&members)?;
    }
    Ok(BucketedManifest {
        plan: *plan,
        object_count: entries.len() as u64,
        buckets: encode(&buckets.concat()),
        held: (0..=u8::MAX).collect(),
        entries: entries.to_vec(),
    })
}

/// Folds written entries in, and returns the object count and root the manifest
/// for the collection after that write must carry.
///
/// The server recomputes both from its own rows, so these have to be derived
/// the same way: replace each entry in its bucket, rehash the buckets that
/// changed, rehash the root over all 256.
pub fn manifest_apply(
    held: &BucketedManifest,
    written: &[CoreManifestEntry],
) -> Result<AppliedManifest, CoreError> {
    let mut buckets = buckets_from_blob(&decode(&held.buckets, "manifest bucket digests")?)?;
    let mut entries = unproject(&held.entries)?;
    let mut fresh = 0u64;
    let mut touched: Vec<u8> = Vec::with_capacity(written.len());
    for entry in unproject(written)? {
        let bucket = manifest_bucket_of(entry.id);
        if !held.held.contains(&bucket) {
            return Err(CoreError::manifest(
                "a write was folded into a bucket this device did not fetch",
            ));
        }
        touched.push(bucket);
        match entries.iter_mut().find(|held| held.id == entry.id) {
            Some(held) => *held = entry,
            None => {
                entries.push(entry);
                fresh += 1;
            }
        }
    }
    touched.sort_unstable();
    touched.dedup();
    for bucket in touched {
        buckets[bucket as usize] = bucket_digest(&in_bucket(&entries, bucket))?;
    }
    let object_count = held.object_count + fresh;
    Ok(AppliedManifest {
        object_count,
        root: encode(&manifest_root(&buckets, object_count)),
    })
}

/// Signs a manifest over an entry set, for the caller that holds all of it.
pub fn manifest_sign(
    secrets: &DeviceSigningSecrets,
    context: &ManifestContext,
    plan: &ManifestPlan,
    entries: &[CoreManifestEntry],
) -> Result<SignedManifest, CoreError> {
    let wire = unproject(entries)?;
    let digest = manifest_digest(&digest_inputs(&wire)?);
    signed(secrets, context, plan, entries.len() as u64, &digest)
}

/// Signs a manifest over a root already derived from the bucket digests, for
/// the write path that never holds the whole entry set.
///
/// The root comes from [`manifest_apply`], so the signature covers the same
/// value a signature over every entry would.
pub fn manifest_sign_root(
    secrets: &DeviceSigningSecrets,
    context: &ManifestContext,
    plan: &ManifestPlan,
    applied: &AppliedManifest,
) -> Result<SignedManifest, CoreError> {
    let root = digest32(&applied.root, "manifest root")?;
    signed(secrets, context, plan, applied.object_count, &root)
}

/// The sequence to persist once a manifest has been verified.
///
/// A high-water mark, never a move backwards: the server is the only source of
/// manifests, so it can freeze a device at a real past state but not rewind it.
pub fn accept_manifest_seq(current: u64, seq: u64) -> u64 {
    current.max(seq)
}

/// A served entry set in core's shape, for a host that holds the wire type.
pub fn core_entries(entries: &[ManifestEntry]) -> Vec<CoreManifestEntry> {
    project(entries)
}

/// The reverse of [`core_entries`], for a host that builds its request body in
/// Rust.
pub fn wire_entries(entries: &[CoreManifestEntry]) -> Result<Vec<ManifestEntry>, CoreError> {
    unproject(entries)
}

/// The manifest entry a sealed object produces.
pub fn manifest_entry_for(
    id: Uuid,
    revision: u64,
    tombstone: bool,
    nonce_b64: &str,
    ciphertext_b64: &str,
) -> Result<CoreManifestEntry, CoreError> {
    let nonce = decode(nonce_b64, "object nonce")?;
    let ciphertext = decode(ciphertext_b64, "object ciphertext")?;
    Ok(CoreManifestEntry {
        id,
        revision,
        tombstone,
        content_digest: encode(&sealbook_crypto::content_digest(&nonce, &ciphertext)),
    })
}

fn signed(
    secrets: &DeviceSigningSecrets,
    context: &ManifestContext,
    plan: &ManifestPlan,
    object_count: u64,
    digest: &[u8; 32],
) -> Result<SignedManifest, CoreError> {
    let signature = sign(
        secrets,
        &manifest_transcript(
            context.collection_id,
            plan.manifest_seq,
            plan.key_epoch,
            plan.latest_revision,
            object_count,
            digest,
        ),
    )?;
    let body = ManifestBody {
        manifest_seq: plan.manifest_seq,
        key_epoch: plan.key_epoch,
        latest_revision: plan.latest_revision,
        object_count,
        digest: digest.to_vec(),
        device_id: context.device_id,
        signature: DualSignatureBody {
            mldsa: signature.mldsa.clone(),
            ed25519: signature.ed25519.clone(),
        },
    };
    Ok(SignedManifest {
        plan: *plan,
        object_count,
        digest: encode(digest),
        device_id: context.device_id,
        mldsa: encode(&signature.mldsa),
        ed25519: encode(&signature.ed25519),
        manifest_json: serde_json::to_string(&body)?,
    })
}

/// The two checks a manifest over a known entry set must pass, plus the
/// freshness rule.
fn against_entries(
    context: &ManifestContext,
    manifest: &ManifestBody,
    entries: &[ManifestEntry],
    devices: &[CoreDevice],
) -> Result<ManifestPlan, CoreError> {
    not_backwards(context, manifest)?;
    if manifest.object_count != entries.len() as u64 {
        return Err(CoreError::manifest(format!(
            "server sent {} objects but the manifest commits to {}",
            entries.len(),
            manifest.object_count
        )));
    }
    let digest = manifest_digest(&digest_inputs(entries)?);
    if manifest.digest != digest {
        return Err(CoreError::manifest(
            "the objects served do not match the signed manifest; an object may have been \
             withheld, rolled back or substituted",
        ));
    }
    check_signature(context, manifest, &digest, devices)?;
    Ok(plan_of(manifest))
}

fn check_signature(
    context: &ManifestContext,
    manifest: &ManifestBody,
    digest: &[u8; 32],
    devices: &[CoreDevice],
) -> Result<(), CoreError> {
    let signer = devices
        .iter()
        .find(|device| device.device_id == manifest.device_id)
        .ok_or_else(|| {
            CoreError::manifest("manifest signed by a device this account does not have")
        })?;
    verify(
        &DeviceSigningPublic {
            mldsa_pk: decode(&signer.mldsa_pk, "signer ML-DSA key")?,
            ed25519_pk: decode(&signer.ed25519_pk, "signer Ed25519 key")?,
        },
        &manifest_transcript(
            context.collection_id,
            manifest.manifest_seq,
            manifest.key_epoch,
            manifest.latest_revision,
            manifest.object_count,
            digest,
        ),
        &DualSignature {
            mldsa: manifest.signature.mldsa.clone(),
            ed25519: manifest.signature.ed25519.clone(),
        },
    )
    .map_err(|_| CoreError::manifest("manifest signature does not verify"))
}

fn not_backwards(context: &ManifestContext, manifest: &ManifestBody) -> Result<(), CoreError> {
    if manifest.manifest_seq < context.manifest_seq {
        return Err(CoreError::manifest(format!(
            "manifest went backwards: this device has already seen sequence {} but was served {}",
            context.manifest_seq, manifest.manifest_seq
        )));
    }
    Ok(())
}

fn unmanifested(
    context: &ManifestContext,
    entries: Vec<CoreManifestEntry>,
) -> Result<ManifestOutcome, CoreError> {
    manifest_absence_ok(context)?;
    let latest_revision = entries.iter().map(|entry| entry.revision).max().unwrap_or(0);
    Ok(ManifestOutcome::Unmanifested {
        latest_revision,
        entries,
    })
}

fn plan_of(manifest: &ManifestBody) -> ManifestPlan {
    ManifestPlan {
        manifest_seq: manifest.manifest_seq,
        key_epoch: manifest.key_epoch,
        latest_revision: manifest.latest_revision,
    }
}

fn buckets_of(ids: &[Uuid]) -> Vec<u8> {
    let mut wanted: Vec<u8> = ids.iter().copied().map(manifest_bucket_of).collect();
    wanted.sort_unstable();
    wanted.dedup();
    wanted
}

fn in_bucket(entries: &[ManifestEntry], bucket: u8) -> Vec<ManifestEntry> {
    entries
        .iter()
        .filter(|entry| manifest_bucket_of(entry.id) == bucket)
        .cloned()
        .collect()
}

/// One bucket's digest, or all zeroes for an empty bucket, matching how the
/// root is built.
fn bucket_digest(entries: &[ManifestEntry]) -> Result<[u8; 32], CoreError> {
    if entries.is_empty() {
        return Ok([0u8; 32]);
    }
    Ok(manifest_bucket_digest(&digest_inputs(entries)?))
}

fn digest_inputs(entries: &[ManifestEntry]) -> Result<Vec<ManifestDigestEntry>, CoreError> {
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry.content_digest.len() != 32 {
            return Err(CoreError::manifest("entry has a malformed content digest"));
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

fn buckets_from_blob(blob: &[u8]) -> Result<[[u8; 32]; MANIFEST_BUCKETS], CoreError> {
    if blob.len() != MANIFEST_BUCKETS * 32 {
        return Err(CoreError::manifest(format!(
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

fn project(entries: &[ManifestEntry]) -> Vec<CoreManifestEntry> {
    entries
        .iter()
        .map(|entry| CoreManifestEntry {
            id: entry.id,
            revision: entry.revision,
            tombstone: entry.tombstone,
            content_digest: encode(&entry.content_digest),
        })
        .collect()
}

fn unproject(entries: &[CoreManifestEntry]) -> Result<Vec<ManifestEntry>, CoreError> {
    entries
        .iter()
        .map(|entry| {
            Ok(ManifestEntry {
                id: entry.id,
                revision: entry.revision,
                tombstone: entry.tombstone,
                content_digest: digest32(&entry.content_digest, "entry content digest")?.to_vec(),
            })
        })
        .collect()
}

fn read_body<T: serde::de::DeserializeOwned>(response: &HttpResponse) -> Result<T, CoreError> {
    if response.status != 200 {
        return Err(CoreError::Server {
            detail: format!("the manifest request returned HTTP {}", response.status),
        });
    }
    serde_json::from_slice(&response.body).map_err(unreadable)
}

fn get(path: String) -> HttpRequest {
    HttpRequest {
        method: Method::Get,
        path,
        headers: Vec::new(),
        body: Vec::new(),
    }
}

fn unreadable(err: serde_json::Error) -> CoreError {
    CoreError::malformed(format!("the manifest response is unreadable: {err}"))
}

fn digest32(text: &str, what: &str) -> Result<[u8; 32], CoreError> {
    let bytes = decode(text, what)?;
    if bytes.len() != 32 {
        return Err(CoreError::manifest(format!("{what} is not 32 bytes")));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode(text: &str, what: &str) -> Result<Vec<u8>, CoreError> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|err| CoreError::malformed(format!("{what} is not base64: {err}")))
}

/// The uniffi surface for the decisions above.
///
/// Takes the device's signing secrets as base64 because that is how Kotlin
/// holds them, and the response body alone because the host's transport has
/// already raised anything that is not a success.
#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{
        AppliedManifest, BucketedManifest, BucketsOutcome, CoreError, CoreManifestEntry,
        HttpRequest, ManifestContext, ManifestOutcome, ManifestPlan, ManifestSigner, SignedManifest,
    };
    use crate::{CoreDevice, HttpResponse};
    use sealbook_crypto::DeviceSigningSecrets;
    use uuid::Uuid;

    fn ok(body: String) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: body.into_bytes(),
        }
    }

    fn secrets(mldsa_seed_b64: &str, ed25519_sk_b64: &str) -> Result<DeviceSigningSecrets, CoreError> {
        Ok(DeviceSigningSecrets {
            mldsa_seed: super::decode(mldsa_seed_b64, "ML-DSA seed")?,
            ed25519_sk: super::decode(ed25519_sk_b64, "Ed25519 secret key")?,
        })
    }

    #[uniffi::export]
    pub fn manifest_request(context: ManifestContext) -> HttpRequest {
        super::manifest_request(&context)
    }

    #[uniffi::export]
    pub fn manifest_buckets_request(context: ManifestContext, ids: Vec<Uuid>) -> HttpRequest {
        super::manifest_buckets_request(&context, &ids)
    }

    #[uniffi::export]
    pub fn manifest_signer(body: String) -> Result<Option<ManifestSigner>, CoreError> {
        super::manifest_signer(body.as_bytes())
    }

    #[uniffi::export]
    pub fn manifest_accept(
        context: ManifestContext,
        body: String,
        devices: Vec<CoreDevice>,
    ) -> Result<ManifestOutcome, CoreError> {
        super::manifest_accept(&context, &ok(body), &devices)
    }

    #[uniffi::export]
    pub fn manifest_buckets_accept(
        context: ManifestContext,
        ids: Vec<Uuid>,
        body: String,
        devices: Vec<CoreDevice>,
    ) -> Result<BucketsOutcome, CoreError> {
        super::manifest_buckets_accept(&context, &ids, &ok(body), &devices)
    }

    #[uniffi::export]
    pub fn manifest_buckets_from_whole(
        plan: ManifestPlan,
        entries: Vec<CoreManifestEntry>,
    ) -> Result<BucketedManifest, CoreError> {
        super::manifest_buckets_from_whole(&plan, &entries)
    }

    #[uniffi::export]
    pub fn manifest_apply(
        held: BucketedManifest,
        written: Vec<CoreManifestEntry>,
    ) -> Result<AppliedManifest, CoreError> {
        super::manifest_apply(&held, &written)
    }

    #[uniffi::export]
    pub fn manifest_sign(
        mldsa_seed_b64: String,
        ed25519_sk_b64: String,
        context: ManifestContext,
        plan: ManifestPlan,
        entries: Vec<CoreManifestEntry>,
    ) -> Result<SignedManifest, CoreError> {
        super::manifest_sign(
            &secrets(&mldsa_seed_b64, &ed25519_sk_b64)?,
            &context,
            &plan,
            &entries,
        )
    }

    #[uniffi::export]
    pub fn manifest_sign_root(
        mldsa_seed_b64: String,
        ed25519_sk_b64: String,
        context: ManifestContext,
        plan: ManifestPlan,
        applied: AppliedManifest,
    ) -> Result<SignedManifest, CoreError> {
        super::manifest_sign_root(
            &secrets(&mldsa_seed_b64, &ed25519_sk_b64)?,
            &context,
            &plan,
            &applied,
        )
    }

    #[uniffi::export]
    pub fn manifest_verify(
        context: ManifestContext,
        manifest_json: String,
        entries: Vec<CoreManifestEntry>,
        devices: Vec<CoreDevice>,
    ) -> Result<ManifestPlan, CoreError> {
        super::manifest_verify(&context, &manifest_json, &entries, &devices)
    }

    #[uniffi::export]
    pub fn manifest_absence_ok(context: ManifestContext) -> Result<(), CoreError> {
        super::manifest_absence_ok(&context)
    }

    #[uniffi::export]
    pub fn accept_manifest_seq(current: u64, seq: u64) -> u64 {
        super::accept_manifest_seq(current, seq)
    }

    #[uniffi::export]
    pub fn manifest_entry_for(
        id: Uuid,
        revision: u64,
        tombstone: bool,
        nonce_b64: String,
        ciphertext_b64: String,
    ) -> Result<CoreManifestEntry, CoreError> {
        super::manifest_entry_for(id, revision, tombstone, &nonce_b64, &ciphertext_b64)
    }
}
