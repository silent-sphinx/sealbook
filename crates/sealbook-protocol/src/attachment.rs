//! Wire types for note photo attachments.
//!
//! Attachments live outside the sealed-object set: their ciphertext is chunked
//! and stored on its own path, never committed to a manifest, never re-encrypted
//! on key rotation, and never pulled by the eager `/changes` sync. The owning
//! note carries only a small reference (the attachment key, a content hash and
//! the chunking parameters) inside its ordinary sealed JSON payload. These types
//! describe the create/upload/commit/download/delete exchange for that path.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Plaintext bytes per attachment chunk.
///
/// An attachment is first padded to `sealbook_crypto::padme_len` of its size, then
/// sliced into chunks of this size; every chunk but the last is exactly this
/// long, and the last is zero-filled up to the padded total. Each chunk is
/// sealed independently with `sealbook_crypto::encrypt_chunk`. The value trades
/// upload round trips against per-request size: at 4 MiB a 200 MiB photo is
/// about 50 chunks. What the server learns of the length is the padded total,
/// which Padme keeps to within about 12 percent.
pub const ATTACHMENT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Largest plaintext a single attachment may carry, before padding.
///
/// Not a padding bucket and need not be a power of two. It bounds one photo, not
/// a whole account; the per-account ceiling is the server's attachment quota,
/// which counts the padded ciphertext.
pub const MAX_ATTACHMENT_SIZE: usize = 200 * 1024 * 1024;

/// Largest padded attachment the server accepts: the plaintext ceiling plus the
/// most Padme adds, an eighth.
pub const MAX_PADDED_ATTACHMENT_SIZE: usize = MAX_ATTACHMENT_SIZE + MAX_ATTACHMENT_SIZE / 8;

/// AEAD tag bytes added to each sealed chunk, used to size the upload body limit
/// and the server's per-chunk ciphertext check.
pub const ATTACHMENT_CHUNK_TAG_LEN: usize = 16;

/// Declares an attachment before its chunks are uploaded.
///
/// The server reserves quota from the declared parameters and refuses the whole
/// attachment up front if it would not fit, so a client does not stream tens of
/// megabytes only to be rejected at commit. Re-declaring an id already `pending`
/// is a no-op, which is what lets an interrupted upload resume.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CreateAttachmentRequest {
    pub attachment_id: Uuid,
    pub chunk_size: u32,
    pub chunk_count: u32,
    /// The device's authorisation for this create.
    pub auth: AttachmentOpAuth,
}

/// A device's signature over one attachment create, commit or delete.
///
/// The challenge comes from `POST /v2/attachments/challenge` and is single use.
/// A session token alone cannot create, commit or delete an attachment: the
/// signature is over the operation, the collection and the attachment, made with
/// the device's own signing keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct AttachmentOpAuth {
    pub challenge_id: Uuid,
    #[serde(with = "crate::b64")]
    pub challenge: Vec<u8>,
    pub signature: crate::DualSignatureBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CreateAttachmentResponse {
    pub attachment_id: Uuid,
    pub state: String,
}

/// An attachment's stored shape, without any chunk bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct AttachmentMetaResponse {
    pub attachment_id: Uuid,
    pub state: String,
    pub chunk_size: u32,
    pub chunk_count: u32,
    pub total_ciphertext_size: u64,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CommitAttachmentResponse {
    pub attachment_id: Uuid,
    pub state: String,
}

/// One entry of the attachment listing the client uses to sweep orphans.
///
/// Deliberately id and age only: the server is content-blind and cannot know
/// which attachments a note still references, so the sweep is driven entirely by
/// the client cross-referencing these ids against its decrypted notes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct AttachmentListEntry {
    pub attachment_id: Uuid,
    pub state: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ListAttachmentsResponse {
    pub attachments: Vec<AttachmentListEntry>,
    /// Set to the last id when a page was capped, to continue with `after`.
    pub next_after: Option<Uuid>,
}

/// State strings an attachment row can hold.
pub const ATTACHMENT_STATE_PENDING: &str = "pending";
pub const ATTACHMENT_STATE_COMMITTED: &str = "committed";
