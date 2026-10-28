//! Chunking an attachment, sealing each chunk, and verifying a download.
//!
//! An attachment's bytes never join the sealed-object set: they are split into
//! chunks, each sealed under a key of its own that lives inside the owning
//! record's plaintext, and stored under a path of their own. A key rotation
//! therefore never rewrites a chunk and the eager sync never pulls one.
//!
//! The bytes stay in the host. A 4 MB chunk carried as a field of a boundary
//! record would cross the wasm boundary element by element, so the sealed and
//! opened buffers are function arguments and returns, which both bindings carry
//! as a native byte array. Everything else here is a decision: the plan, the
//! paths, the nonce header, the limits, the hash and what makes a download
//! acceptable.
//!
//! The content hash is what a download is checked against: per-chunk SHA-256
//! digests rolled into one value with the chunk count folded in last, so a
//! withheld, reordered, truncated or substituted chunk changes the result. Core
//! takes the digests rather than holding a running hasher, which keeps every
//! function here pure and leaves the host nothing to free.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sealbook_crypto::{
    attachment_chunk_aad, decrypt_chunk, encrypt_chunk, AttachmentHasher, AttachmentKey,
    EncryptedChunk, ATTACHMENT_KEY_LEN, NONCE_LEN,
};
use sealbook_protocol::{
    AttachmentListEntry, AttachmentMetaResponse, CommitAttachmentResponse, CreateAttachmentRequest,
    CreateAttachmentResponse, ListAttachmentsResponse, ATTACHMENT_CHUNK_SIZE,
    ATTACHMENT_STATE_COMMITTED, ATTACHMENT_STATE_PENDING, MAX_ATTACHMENT_SIZE,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::http::{Header, HttpRequest, Method};
use crate::CoreError;

/// The header a chunk's nonce travels in, on the way up and on the way back.
pub const NONCE_HEADER: &str = "x-sealbook-nonce";

/// How long an unreferenced attachment is left alone before a sweep removes it.
///
/// An upload creates the row before the owning record is written, so a sweep
/// running in that window would delete an attachment that is about to be
/// referenced. The grace period is what makes the two orders safe.
pub const ORPHAN_GRACE_SECS: i64 = 48 * 60 * 60;

/// Why an attachment cannot be uploaded or trusted.
///
/// Typed rather than free text because each of these is something to tell the
/// user about, and each host has its own wording for it.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[serde(tag = "refusal")]
pub enum AttachmentRefusal {
    /// Refused here rather than sent: the server rejects a zero-length
    /// attachment, and both clients used to send one chunk for no bytes and
    /// surface the resulting mismatch as a protocol error.
    #[error("there is nothing to upload")]
    Empty,
    #[error("that file is {size} bytes, over the {max} byte limit")]
    TooLarge { size: u64, max: u64 },
    /// The record's own chunk count is the one the AAD of every chunk was sealed
    /// over, so a server naming a different one is serving another attachment.
    #[error("the server holds {served} chunks for this attachment, not {expected}")]
    ChunkCount { expected: u32, served: u32 },
    #[error("this attachment is {served}, not {expected}")]
    State { expected: String, served: String },
    #[error("an attachment chunk arrived without its {header} header", header = NONCE_HEADER)]
    MissingNonce,
    #[error("an attachment key is not {len} bytes", len = ATTACHMENT_KEY_LEN)]
    Key,
}

/// What an upload is going to do, decided before any of it is sent.
///
/// The id and the key are drawn here so that one generator serves every host,
/// and both are returned for the owning record to keep: the key is the only way
/// back to the bytes and nothing re-derives it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AttachmentPlan {
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub attachment_id: Uuid,
    /// Base64url of the 32-byte attachment key, as the owning record stores it.
    pub key: String,
    pub chunk_size: u32,
    pub chunk_count: u32,
    pub total_plaintext_size: u64,
}

/// One chunk's slice of the plaintext the host is holding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ChunkRange {
    pub index: u32,
    pub start: u64,
    pub end: u64,
}

/// The ceilings and shapes a host needs to police its own input.
///
/// `max_size` is the protocol's. A host that wants a lower one of its own, as
/// the web does because it assembles a download in memory, applies it before
/// calling [`attachment_plan`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AttachmentLimits {
    pub max_size: u64,
    pub chunk_size: u32,
    pub nonce_header: String,
    pub nonce_len: u32,
    pub orphan_grace_secs: i64,
}

/// An attachment as the listing serves it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AttachmentRow {
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub attachment_id: Uuid,
    pub state: String,
    pub created_at: i64,
}

/// Where a sweep has reached, and which cursors it has already been given.
///
/// `seen` is what stops a server whose cursor does not advance from being paged
/// forever. The CLI had no such guard.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SweepCursor {
    #[cfg_attr(feature = "wasm", tsify(type = "string | undefined"))]
    pub after: Option<Uuid>,
    #[cfg_attr(feature = "wasm", tsify(type = "string[]"))]
    #[serde(default)]
    pub seen: Vec<Uuid>,
}

/// One page of a sweep. `next` is `None` when the listing is exhausted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SweepPage {
    pub rows: Vec<AttachmentRow>,
    pub next: Option<SweepCursor>,
}

/// The protocol's limits and the nonce header contract.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn attachment_limits() -> AttachmentLimits {
    AttachmentLimits {
        max_size: MAX_ATTACHMENT_SIZE as u64,
        chunk_size: ATTACHMENT_CHUNK_SIZE as u32,
        nonce_header: NONCE_HEADER.to_string(),
        nonce_len: NONCE_LEN as u32,
        orphan_grace_secs: ORPHAN_GRACE_SECS,
    }
}

/// Decides an upload: a fresh id and key, and how the plaintext is cut up.
///
/// The chunk count is `total / chunk_size` rounded up, with no floor of one: the
/// server derives the same number the same way and refuses a count that does not
/// match, so an empty attachment is refused here instead of becoming a protocol
/// error nobody can act on.
pub fn attachment_plan(total_plaintext_size: u64) -> Result<AttachmentPlan, CoreError> {
    if total_plaintext_size == 0 {
        return Err(refuse(AttachmentRefusal::Empty));
    }
    if total_plaintext_size > MAX_ATTACHMENT_SIZE as u64 {
        return Err(refuse(AttachmentRefusal::TooLarge {
            size: total_plaintext_size,
            max: MAX_ATTACHMENT_SIZE as u64,
        }));
    }
    let chunk_size = ATTACHMENT_CHUNK_SIZE as u64;
    Ok(AttachmentPlan {
        attachment_id: Uuid::new_v4(),
        key: encode(AttachmentKey::generate().as_bytes()),
        chunk_size: chunk_size as u32,
        chunk_count: total_plaintext_size.div_ceil(chunk_size) as u32,
        total_plaintext_size,
    })
}

/// The slices of plaintext a plan's chunks are taken from, in order.
pub fn attachment_ranges(plan: &AttachmentPlan) -> Vec<ChunkRange> {
    let chunk_size = plan.chunk_size as u64;
    (0..plan.chunk_count)
        .map(|index| {
            let start = index as u64 * chunk_size;
            ChunkRange {
                index,
                start,
                end: (start + chunk_size).min(plan.total_plaintext_size),
            }
        })
        .collect()
}

/// Reserves the attachment, which is what the chunk uploads are checked against.
pub fn attachment_create_request(collection_id: Uuid, plan: &AttachmentPlan) -> HttpRequest {
    json_request(
        Method::Post,
        attachment_base(collection_id),
        &CreateAttachmentRequest {
            attachment_id: plan.attachment_id,
            total_plaintext_size: plan.total_plaintext_size,
            chunk_size: plan.chunk_size,
            chunk_count: plan.chunk_count,
        },
    )
}

/// Checks the reservation landed, and on the attachment this plan is for.
pub fn attachment_create_accept(plan: &AttachmentPlan, body: &str) -> Result<(), CoreError> {
    let served: CreateAttachmentResponse = serde_json::from_str(body)?;
    expect_id(plan.attachment_id, served.attachment_id)?;
    expect_state(ATTACHMENT_STATE_PENDING, &served.state)
}

/// Where one chunk is put and fetched.
pub fn attachment_chunk_path(collection_id: Uuid, attachment_id: Uuid, index: u32) -> String {
    format!(
        "{}/{attachment_id}/chunks/{index}",
        attachment_base(collection_id)
    )
}

/// Seals one chunk, returning its nonce followed by its ciphertext.
///
/// The two travel apart on the wire, the nonce in [`NONCE_HEADER`] and the
/// ciphertext as the body, so the caller splits the first
/// [`AttachmentLimits::nonce_len`] bytes off. They are returned together because
/// a second call would seal under a second nonce.
///
/// The AAD binds the attachment, the collection and this chunk's place in the
/// set, which is what stops a chunk being replayed under another attachment's
/// key or served in another position.
pub fn seal_attachment_chunk(
    key_b64: &str,
    attachment_id: Uuid,
    collection_id: Uuid,
    index: u32,
    chunk_count: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let aad = chunk_aad(attachment_id, collection_id, index, chunk_count);
    let sealed = encrypt_chunk(&key(key_b64)?, plaintext, &aad)?;
    let mut out = Vec::with_capacity(sealed.nonce.len() + sealed.ciphertext.len());
    out.extend_from_slice(&sealed.nonce);
    out.extend_from_slice(&sealed.ciphertext);
    Ok(out)
}

/// Opens one chunk. A chunk that will not open is a tampered or corrupt
/// download, never a condition to retry.
#[allow(clippy::too_many_arguments)]
pub fn open_attachment_chunk(
    key_b64: &str,
    attachment_id: Uuid,
    collection_id: Uuid,
    index: u32,
    chunk_count: u32,
    nonce_b64: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(nonce_b64)
        .map_err(|_| CoreError::Nonce)?;
    let nonce = <[u8; NONCE_LEN]>::try_from(bytes.as_slice()).map_err(|_| CoreError::Nonce)?;
    let aad = chunk_aad(attachment_id, collection_id, index, chunk_count);
    decrypt_chunk(
        &key(key_b64)?,
        &EncryptedChunk {
            nonce,
            ciphertext: ciphertext.to_vec(),
        },
        &aad,
    )
    .map_err(|_| CoreError::AttachmentIntegrity {
        object: attachment_id,
    })
}

/// The nonce a chunk response carried, or the refusal for one that carried none.
pub fn attachment_chunk_nonce(header: Option<String>) -> Result<String, CoreError> {
    header
        .filter(|value| !value.is_empty())
        .ok_or_else(|| refuse(AttachmentRefusal::MissingNonce))
}

/// Seals the attachment, after which the server serves its chunks and stops
/// accepting new ones.
pub fn attachment_commit_request(collection_id: Uuid, attachment_id: Uuid) -> HttpRequest {
    json_request(
        Method::Post,
        format!("{}/{attachment_id}/commit", attachment_base(collection_id)),
        &serde_json::json!({}),
    )
}

/// Checks the commit took, so an upload does not report success over an
/// attachment the server still holds as pending.
pub fn attachment_commit_accept(attachment_id: Uuid, body: &str) -> Result<(), CoreError> {
    let served: CommitAttachmentResponse = serde_json::from_str(body)?;
    expect_id(attachment_id, served.attachment_id)?;
    expect_state(ATTACHMENT_STATE_COMMITTED, &served.state)
}

pub fn attachment_meta_request(collection_id: Uuid, attachment_id: Uuid) -> HttpRequest {
    empty_request(
        Method::Get,
        format!("{}/{attachment_id}", attachment_base(collection_id)),
    )
}

/// Whether the server is holding the attachment this record references.
///
/// The record's chunk count is the trusted one: it came out of sealed plaintext
/// and every chunk's AAD was built over it. A server naming another count is
/// offering a different set of chunks, which is refused before a byte is
/// fetched rather than discovered as an integrity failure at the end.
pub fn attachment_meta_accept(
    attachment_id: Uuid,
    chunk_count: u32,
    body: &str,
) -> Result<AttachmentMetaResponse, CoreError> {
    let served: AttachmentMetaResponse = serde_json::from_str(body)?;
    expect_id(attachment_id, served.attachment_id)?;
    expect_state(ATTACHMENT_STATE_COMMITTED, &served.state)?;
    if served.chunk_count != chunk_count {
        return Err(refuse(AttachmentRefusal::ChunkCount {
            expected: chunk_count,
            served: served.chunk_count,
        }));
    }
    Ok(served)
}

pub fn attachment_delete_request(collection_id: Uuid, attachment_id: Uuid) -> HttpRequest {
    empty_request(
        Method::Delete,
        format!("{}/{attachment_id}", attachment_base(collection_id)),
    )
}

/// One chunk's plaintext digest, base64url, to be rolled up by
/// [`attachment_content_hash`].
pub fn attachment_chunk_digest(plaintext: &[u8]) -> String {
    encode(&AttachmentHasher::chunk_digest(plaintext))
}

/// The value the owning record commits to, rolled from every chunk's digest in
/// order.
///
/// Taking the digests rather than the plaintexts means neither core nor the
/// host holds the whole file to compute it, and the same function serves the
/// upload that produces the hash and the download that checks it.
pub fn attachment_content_hash(digests: &[String]) -> Result<String, CoreError> {
    let mut hasher = AttachmentHasher::new();
    for digest in digests {
        hasher.update_digest(&decode_digest(digest)?);
    }
    Ok(encode(&hasher.finalize()))
}

/// Checks a download reproduced what the record committed to.
pub fn attachment_verify(
    attachment_id: Uuid,
    expected_hash_b64: &str,
    digests: &[String],
) -> Result<(), CoreError> {
    let integrity = || CoreError::AttachmentIntegrity {
        object: attachment_id,
    };
    if attachment_content_hash(digests).map_err(|_| integrity())? != expected_hash_b64 {
        return Err(integrity());
    }
    Ok(())
}

/// A sweep of the whole listing, from the beginning.
pub fn sweep_start() -> SweepCursor {
    SweepCursor {
        after: None,
        seen: Vec::new(),
    }
}

pub fn sweep_request(collection_id: Uuid, cursor: &SweepCursor) -> HttpRequest {
    let base = attachment_base(collection_id);
    empty_request(
        Method::Get,
        match cursor.after {
            Some(after) => format!("{base}?after={after}"),
            None => base,
        },
    )
}

/// One page of the listing, and where to ask next.
///
/// A cursor the sweep has already followed ends the walk: the pages so far are
/// swept rather than the whole pass failing, which is the same choice the row
/// loop makes when one delete fails.
pub fn sweep_page(cursor: &SweepCursor, body: &str) -> Result<SweepPage, CoreError> {
    let page: ListAttachmentsResponse = serde_json::from_str(body)?;
    let rows = page.attachments.into_iter().map(row).collect();
    let next = page
        .next_after
        .filter(|id| !cursor.seen.contains(id))
        .map(|after| {
            let mut seen = cursor.seen.clone();
            seen.push(after);
            SweepCursor {
                after: Some(after),
                seen,
            }
        });
    Ok(SweepPage { rows, next })
}

/// Which listed attachments are safe to delete.
///
/// `now_secs` is the host's clock: core has none. An attachment no record
/// references is only an orphan once it is older than [`ORPHAN_GRACE_SECS`],
/// because an upload creates the row before the record that will reference it.
pub fn sweep_orphans(rows: &[AttachmentRow], referenced: &[Uuid], now_secs: i64) -> Vec<Uuid> {
    rows.iter()
        .filter(|row| !referenced.contains(&row.attachment_id))
        .filter(|row| now_secs.saturating_sub(row.created_at) > ORPHAN_GRACE_SECS)
        .map(|row| row.attachment_id)
        .collect()
}

fn attachment_base(collection_id: Uuid) -> String {
    format!("/v1/collections/{collection_id}/attachments")
}

fn chunk_aad(attachment_id: Uuid, collection_id: Uuid, index: u32, chunk_count: u32) -> Vec<u8> {
    attachment_chunk_aad(
        attachment_id.as_bytes(),
        collection_id.as_bytes(),
        index,
        chunk_count,
    )
}

fn key(key_b64: &str) -> Result<AttachmentKey, CoreError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(key_b64)
        .map_err(|_| refuse(AttachmentRefusal::Key))?;
    Ok(AttachmentKey::from_bytes(
        <[u8; ATTACHMENT_KEY_LEN]>::try_from(bytes.as_slice())
            .map_err(|_| refuse(AttachmentRefusal::Key))?,
    ))
}

fn row(entry: AttachmentListEntry) -> AttachmentRow {
    AttachmentRow {
        attachment_id: entry.attachment_id,
        state: entry.state,
        created_at: entry.created_at,
    }
}

fn expect_id(expected: Uuid, served: Uuid) -> Result<(), CoreError> {
    if expected != served {
        return Err(CoreError::malformed(format!(
            "the server answered about attachment {served}, not {expected}"
        )));
    }
    Ok(())
}

fn expect_state(expected: &str, served: &str) -> Result<(), CoreError> {
    if served != expected {
        return Err(refuse(AttachmentRefusal::State {
            expected: expected.to_string(),
            served: served.to_string(),
        }));
    }
    Ok(())
}

fn decode_digest(digest_b64: &str) -> Result<[u8; 32], CoreError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(digest_b64)
        .map_err(|err| CoreError::malformed(format!("unreadable chunk digest: {err}")))?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| CoreError::malformed("a chunk digest is not 32 bytes"))
}

fn json_request<T: Serialize>(method: Method, path: String, body: &T) -> HttpRequest {
    HttpRequest {
        method,
        path,
        headers: vec![Header {
            name: "content-type".into(),
            value: "application/json".into(),
        }],
        body: serde_json::to_vec(body).unwrap_or_default(),
    }
}

fn empty_request(method: Method, path: String) -> HttpRequest {
    HttpRequest {
        method,
        path,
        headers: Vec::new(),
        body: Vec::new(),
    }
}

fn refuse(refusal: AttachmentRefusal) -> CoreError {
    CoreError::Attachment { refusal }
}

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Everything above, in the shapes the bindings can carry.
#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{
        AttachmentPlan, AttachmentRow, ChunkRange, CoreError, HttpRequest, SweepCursor, SweepPage,
    };
    use sealbook_protocol::AttachmentMetaResponse;
    use uuid::Uuid;

    #[uniffi::export(name = "attachment_plan")]
    pub fn plan(total_plaintext_size: u64) -> Result<AttachmentPlan, CoreError> {
        super::attachment_plan(total_plaintext_size)
    }

    #[uniffi::export(name = "attachment_ranges")]
    pub fn ranges(plan: AttachmentPlan) -> Vec<ChunkRange> {
        super::attachment_ranges(&plan)
    }

    #[uniffi::export(name = "attachment_create_request")]
    pub fn create_request(collection_id: Uuid, plan: AttachmentPlan) -> HttpRequest {
        super::attachment_create_request(collection_id, &plan)
    }

    #[uniffi::export(name = "attachment_create_accept")]
    pub fn create_accept(plan: AttachmentPlan, body: String) -> Result<(), CoreError> {
        super::attachment_create_accept(&plan, &body)
    }

    #[uniffi::export(name = "attachment_chunk_path")]
    pub fn chunk_path(collection_id: Uuid, attachment_id: Uuid, index: u32) -> String {
        super::attachment_chunk_path(collection_id, attachment_id, index)
    }

    #[uniffi::export(name = "seal_attachment_chunk")]
    pub fn seal(
        key_b64: String,
        attachment_id: Uuid,
        collection_id: Uuid,
        index: u32,
        chunk_count: u32,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, CoreError> {
        super::seal_attachment_chunk(
            &key_b64,
            attachment_id,
            collection_id,
            index,
            chunk_count,
            &plaintext,
        )
    }

    #[uniffi::export(name = "open_attachment_chunk")]
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        key_b64: String,
        attachment_id: Uuid,
        collection_id: Uuid,
        index: u32,
        chunk_count: u32,
        nonce_b64: String,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, CoreError> {
        super::open_attachment_chunk(
            &key_b64,
            attachment_id,
            collection_id,
            index,
            chunk_count,
            &nonce_b64,
            &ciphertext,
        )
    }

    #[uniffi::export(name = "attachment_chunk_nonce")]
    pub fn chunk_nonce(header: Option<String>) -> Result<String, CoreError> {
        super::attachment_chunk_nonce(header)
    }

    #[uniffi::export(name = "attachment_commit_request")]
    pub fn commit_request(collection_id: Uuid, attachment_id: Uuid) -> HttpRequest {
        super::attachment_commit_request(collection_id, attachment_id)
    }

    #[uniffi::export(name = "attachment_commit_accept")]
    pub fn commit_accept(attachment_id: Uuid, body: String) -> Result<(), CoreError> {
        super::attachment_commit_accept(attachment_id, &body)
    }

    #[uniffi::export(name = "attachment_meta_request")]
    pub fn meta_request(collection_id: Uuid, attachment_id: Uuid) -> HttpRequest {
        super::attachment_meta_request(collection_id, attachment_id)
    }

    #[uniffi::export(name = "attachment_meta_accept")]
    pub fn meta_accept(
        attachment_id: Uuid,
        chunk_count: u32,
        body: String,
    ) -> Result<AttachmentMeta, CoreError> {
        super::attachment_meta_accept(attachment_id, chunk_count, &body).map(meta)
    }

    #[uniffi::export(name = "attachment_delete_request")]
    pub fn delete_request(collection_id: Uuid, attachment_id: Uuid) -> HttpRequest {
        super::attachment_delete_request(collection_id, attachment_id)
    }

    #[uniffi::export(name = "attachment_chunk_digest")]
    pub fn chunk_digest(plaintext: Vec<u8>) -> String {
        super::attachment_chunk_digest(&plaintext)
    }

    #[uniffi::export(name = "attachment_content_hash")]
    pub fn content_hash(digests: Vec<String>) -> Result<String, CoreError> {
        super::attachment_content_hash(&digests)
    }

    #[uniffi::export(name = "attachment_verify")]
    pub fn verify(
        attachment_id: Uuid,
        expected_hash_b64: String,
        digests: Vec<String>,
    ) -> Result<(), CoreError> {
        super::attachment_verify(attachment_id, &expected_hash_b64, &digests)
    }

    #[uniffi::export(name = "attachment_sweep_start")]
    pub fn sweep_start() -> SweepCursor {
        super::sweep_start()
    }

    #[uniffi::export(name = "attachment_sweep_request")]
    pub fn sweep_request(collection_id: Uuid, cursor: SweepCursor) -> HttpRequest {
        super::sweep_request(collection_id, &cursor)
    }

    #[uniffi::export(name = "attachment_sweep_page")]
    pub fn sweep_page(cursor: SweepCursor, body: String) -> Result<SweepPage, CoreError> {
        super::sweep_page(&cursor, &body)
    }

    #[uniffi::export(name = "attachment_sweep_orphans")]
    pub fn sweep_orphans(
        rows: Vec<AttachmentRow>,
        referenced: Vec<Uuid>,
        now_secs: i64,
    ) -> Vec<Uuid> {
        super::sweep_orphans(&rows, &referenced, now_secs)
    }

    /// `AttachmentMetaResponse` in a shape uniffi can carry.
    #[derive(uniffi::Record)]
    pub struct AttachmentMeta {
        pub attachment_id: Uuid,
        pub state: String,
        pub chunk_size: u32,
        pub chunk_count: u32,
        pub total_ciphertext_size: u64,
        pub created_at: i64,
    }

    fn meta(served: AttachmentMetaResponse) -> AttachmentMeta {
        AttachmentMeta {
            attachment_id: served.attachment_id,
            state: served.state,
            chunk_size: served.chunk_size,
            chunk_count: served.chunk_count,
            total_ciphertext_size: served.total_ciphertext_size,
            created_at: served.created_at,
        }
    }
}
