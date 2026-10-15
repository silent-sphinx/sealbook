//! Client-side attachment upload and download.
//!
//! An attachment is chunked, each chunk sealed under a per-attachment key, and
//! the chunks uploaded to a storage path of their own — never the sealed-object
//! set, so they are not re-encrypted on rotation nor pulled by the eager sync.
//! The owning note carries only the small reference this module produces: the
//! attachment key, the rolled-up content hash, and the chunking parameters.
//!
//! Download is lazy and verified: chunks are fetched on demand and the content
//! hash recomputed across them, so a withheld, reordered, truncated or
//! substituted chunk is caught rather than rendered.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use uuid::Uuid;

use sealbook_crypto::{
    attachment_chunk_aad, decrypt_chunk, encrypt_chunk, AttachmentHasher, AttachmentKey,
    EncryptedChunk, NONCE_LEN,
};
use sealbook_protocol::{
    AttachmentListEntry, AttachmentMetaResponse, CommitAttachmentResponse,
    CreateAttachmentRequest, CreateAttachmentResponse, ListAttachmentsResponse,
    ATTACHMENT_CHUNK_SIZE,
};

use crate::{ClientError, SealbookClient};

/// What an upload hands back for the owning note to store.
///
/// Everything a later download needs: the key to open the chunks, the hash to
/// verify them against, and the chunking the server was told. The bytes
/// themselves live only on the server.
#[derive(Debug, Clone)]
pub struct UploadedAttachment {
    pub attachment_id: Uuid,
    /// Base64url of the 32-byte attachment key, as stored in the note JSON.
    pub key_b64: String,
    /// Base64url of the rolled-up content hash.
    pub content_hash_b64: String,
    pub chunk_size: u32,
    pub chunk_count: u32,
    pub total_plaintext_size: u64,
}

impl SealbookClient {
    fn attachment_target(&self) -> Result<(String, Uuid, String), ClientError> {
        let local = self.state.as_ref().ok_or(ClientError::NoState)?;
        Ok((
            local.server.clone(),
            local.collection_id,
            local.session_token.clone().ok_or(ClientError::NoState)?,
        ))
    }

    /// Chunks `data`, seals each chunk under a fresh key, uploads them, and
    /// commits the attachment. Returns the reference the note must keep.
    ///
    /// The whole payload is held in memory, which the per-attachment size ceiling
    /// bounds; a caller streaming a file larger than that should chunk at the file
    /// boundary instead. Chunk size is `ATTACHMENT_CHUNK_SIZE`.
    pub async fn upload_attachment(
        &mut self,
        data: &[u8],
    ) -> Result<UploadedAttachment, ClientError> {
        let (server, collection_id, token) = self.attachment_target()?;
        let attachment_id = Uuid::new_v4();
        let key = AttachmentKey::generate();
        let chunk_size = ATTACHMENT_CHUNK_SIZE;
        let total = data.len() as u64;
        let chunk_count = total.div_ceil(chunk_size as u64).max(1) as u32;

        self.post_json::<_, CreateAttachmentResponse>(
            &format!("{server}/v1/collections/{collection_id}/attachments"),
            &CreateAttachmentRequest {
                attachment_id,
                total_plaintext_size: total,
                chunk_size: chunk_size as u32,
                chunk_count,
            },
            Some(&token),
        )
        .await?;

        let mut hasher = AttachmentHasher::new();
        for index in 0..chunk_count {
            let start = index as usize * chunk_size;
            let end = (start + chunk_size).min(data.len());
            let plaintext = &data[start..end];
            hasher.update(plaintext);
            let aad = attachment_chunk_aad(
                attachment_id.as_bytes(),
                collection_id.as_bytes(),
                index,
                chunk_count,
            );
            let sealed = encrypt_chunk(&key, plaintext, &aad)?;
            let mut body = Vec::with_capacity(sealed.ciphertext.len());
            body.extend_from_slice(&sealed.ciphertext);
            self.put_bytes(
                &format!(
                    "{server}/v1/collections/{collection_id}/attachments/{attachment_id}/chunks/{index}"
                ),
                &URL_SAFE_NO_PAD.encode(sealed.nonce),
                body,
                &token,
            )
            .await?;
        }

        self.post_json::<_, CommitAttachmentResponse>(
            &format!(
                "{server}/v1/collections/{collection_id}/attachments/{attachment_id}/commit"
            ),
            &serde_json::json!({}),
            Some(&token),
        )
        .await?;

        Ok(UploadedAttachment {
            attachment_id,
            key_b64: URL_SAFE_NO_PAD.encode(key.as_bytes()),
            content_hash_b64: URL_SAFE_NO_PAD.encode(hasher.finalize()),
            chunk_size: chunk_size as u32,
            chunk_count,
            total_plaintext_size: total,
        })
    }

    /// Fetches and decrypts every chunk of an attachment, verifying the result
    /// against the note's committed content hash before returning it.
    pub async fn download_attachment(
        &self,
        reference: &UploadedAttachment,
    ) -> Result<Vec<u8>, ClientError> {
        let (server, collection_id, token) = self.attachment_target()?;
        let key_bytes = URL_SAFE_NO_PAD
            .decode(&reference.key_b64)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or(ClientError::AttachmentIntegrity(reference.attachment_id))?;
        let key = AttachmentKey::from_bytes(key_bytes);

        let mut out = Vec::new();
        let mut hasher = AttachmentHasher::new();
        for index in 0..reference.chunk_count {
            let (nonce_b64, ciphertext) = self
                .get_bytes(
                    &format!(
                        "{server}/v1/collections/{collection_id}/attachments/{}/chunks/{index}",
                        reference.attachment_id
                    ),
                    &token,
                )
                .await?;
            let nonce = URL_SAFE_NO_PAD
                .decode(&nonce_b64)
                .ok()
                .filter(|bytes| bytes.len() == NONCE_LEN)
                .ok_or(ClientError::AttachmentIntegrity(reference.attachment_id))?;
            let mut nonce_arr = [0u8; NONCE_LEN];
            nonce_arr.copy_from_slice(&nonce);
            let aad = attachment_chunk_aad(
                reference.attachment_id.as_bytes(),
                collection_id.as_bytes(),
                index,
                reference.chunk_count,
            );
            let plaintext = decrypt_chunk(
                &key,
                &EncryptedChunk {
                    nonce: nonce_arr,
                    ciphertext,
                },
                &aad,
            )
            .map_err(|_| ClientError::AttachmentIntegrity(reference.attachment_id))?;
            hasher.update(&plaintext);
            out.extend_from_slice(&plaintext);
        }

        let expected = URL_SAFE_NO_PAD
            .decode(&reference.content_hash_b64)
            .ok()
            .ok_or(ClientError::AttachmentIntegrity(reference.attachment_id))?;
        if hasher.finalize().as_slice() != expected.as_slice() {
            return Err(ClientError::AttachmentIntegrity(reference.attachment_id));
        }
        Ok(out)
    }

    pub async fn get_attachment_meta(
        &self,
        attachment_id: Uuid,
    ) -> Result<AttachmentMetaResponse, ClientError> {
        let (server, collection_id, token) = self.attachment_target()?;
        self.get_json(
            &format!(
                "{server}/v1/collections/{collection_id}/attachments/{attachment_id}"
            ),
            Some(&token),
        )
        .await
    }

    pub async fn delete_attachment(&self, attachment_id: Uuid) -> Result<(), ClientError> {
        let (server, collection_id, token) = self.attachment_target()?;
        self.delete_no_body(
            &format!(
                "{server}/v1/collections/{collection_id}/attachments/{attachment_id}"
            ),
            &token,
        )
        .await
    }

    /// Every attachment id the server holds for this collection, paged through.
    /// The caller cross-references these against its notes to find orphans.
    pub async fn list_attachments(&self) -> Result<Vec<AttachmentListEntry>, ClientError> {
        let (server, collection_id, token) = self.attachment_target()?;
        let mut all = Vec::new();
        let mut after: Option<Uuid> = None;
        loop {
            let url = match after {
                Some(id) => format!(
                    "{server}/v1/collections/{collection_id}/attachments?after={id}"
                ),
                None => format!("{server}/v1/collections/{collection_id}/attachments"),
            };
            let page: ListAttachmentsResponse = self.get_json(&url, Some(&token)).await?;
            all.extend(page.attachments);
            match page.next_after {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        Ok(all)
    }
}
