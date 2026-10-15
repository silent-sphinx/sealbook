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
/// A whole attachment is sliced into chunks of this size (the final chunk may be
/// shorter) and each is sealed independently with `sealbook_crypto::encrypt_chunk`.
/// The value trades upload round trips against per-request size and the
/// granularity at which the server can infer an attachment's length: at 4 MiB a
/// 200 MiB photo is 50 chunks and its size leaks only to within 4 MiB.
pub const ATTACHMENT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Largest plaintext a single attachment may carry.
///
/// Unlike `MAX_PADDED_OBJECT_SIZE`, this is not a padding bucket and need not be
/// a power of two: attachment chunks are never padded. It bounds one photo, not
/// a whole account; the per-account ceiling is the server's attachment quota.
pub const MAX_ATTACHMENT_SIZE: usize = 200 * 1024 * 1024;

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
pub struct CreateAttachmentRequest {
    pub attachment_id: Uuid,
    pub total_plaintext_size: u64,
    pub chunk_size: u32,
    pub chunk_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAttachmentResponse {
    pub attachment_id: Uuid,
    pub state: String,
}

/// An attachment's stored shape, without any chunk bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentMetaResponse {
    pub attachment_id: Uuid,
    pub state: String,
    pub chunk_size: u32,
    pub chunk_count: u32,
    pub total_ciphertext_size: u64,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct AttachmentListEntry {
    pub attachment_id: Uuid,
    pub state: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListAttachmentsResponse {
    pub attachments: Vec<AttachmentListEntry>,
    /// Set to the last id when a page was capped, to continue with `after`.
    pub next_after: Option<Uuid>,
}

/// State strings an attachment row can hold.
pub const ATTACHMENT_STATE_PENDING: &str = "pending";
pub const ATTACHMENT_STATE_COMMITTED: &str = "committed";
