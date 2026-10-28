//! Client-side attachment upload and download.
//!
//! Every decision is core's: how a file becomes chunks, what each round sends,
//! which nonce header a chunk travels under, whether the server is holding the
//! attachment the record references, and whether the chunks that arrived
//! reproduce the hash it committed to. This module moves bytes.
//!
//! The bytes are the reason the chunk rounds do not go through `send`: a sealed
//! chunk is multi-megabyte binary, so it is PUT and GET directly while core
//! supplies the path and the header name.

use uuid::Uuid;

use sealbook_core::AttachmentRow;

use crate::{ClientError, SealbookClient};

/// What an upload hands back for the owning record to store.
///
/// Everything a later download needs: the key to open the chunks, the hash to
/// verify them against, and the chunking the server was told. The bytes
/// themselves live only on the server.
#[derive(Debug, Clone)]
pub struct UploadedAttachment {
    pub attachment_id: Uuid,
    /// Base64url of the 32-byte attachment key, as stored in the record.
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

    /// Chunks `data`, seals each chunk, uploads them, and commits the
    /// attachment. Returns the reference the record must keep.
    ///
    /// The whole payload is held in memory, which the per-attachment ceiling
    /// bounds; a caller streaming a file larger than that should chunk at the
    /// file boundary instead.
    ///
    /// A failure part way through deletes the reservation rather than leaving a
    /// pending row for the sweep to find two days later.
    pub async fn upload_attachment(
        &mut self,
        data: &[u8],
    ) -> Result<UploadedAttachment, ClientError> {
        let (server, collection_id, token) = self.attachment_target()?;
        let plan = sealbook_core::attachment_plan(data.len() as u64)?;
        let create = sealbook_core::attachment_create_request(collection_id, &plan);
        let created = self.send(&create, Some(&token)).await?;
        sealbook_core::attachment_create_accept(&plan, &text(&created.body))?;

        match self
            .upload_chunks(&server, collection_id, &plan, data, &token)
            .await
        {
            Ok(content_hash_b64) => Ok(UploadedAttachment {
                attachment_id: plan.attachment_id,
                key_b64: plan.key,
                content_hash_b64,
                chunk_size: plan.chunk_size,
                chunk_count: plan.chunk_count,
                total_plaintext_size: plan.total_plaintext_size,
            }),
            Err(err) => {
                // The orphan sweep is the backstop if this also fails.
                let _ = self.delete_attachment(plan.attachment_id).await;
                Err(err)
            }
        }
    }

    async fn upload_chunks(
        &self,
        server: &str,
        collection_id: Uuid,
        plan: &sealbook_core::AttachmentPlan,
        data: &[u8],
        token: &str,
    ) -> Result<String, ClientError> {
        let nonce_len = sealbook_core::attachment_limits().nonce_len as usize;
        let mut digests = Vec::with_capacity(plan.chunk_count as usize);
        for range in sealbook_core::attachment_ranges(plan) {
            let plaintext = &data[range.start as usize..range.end as usize];
            digests.push(sealbook_core::attachment_chunk_digest(plaintext));
            let sealed = sealbook_core::seal_attachment_chunk(
                &plan.key,
                plan.attachment_id,
                collection_id,
                range.index,
                plan.chunk_count,
                plaintext,
            )?;
            let (nonce, ciphertext) = sealed.split_at(nonce_len);
            self.put_bytes(
                &format!(
                    "{server}{}",
                    sealbook_core::attachment_chunk_path(
                        collection_id,
                        plan.attachment_id,
                        range.index
                    )
                ),
                &encode(nonce),
                ciphertext.to_vec(),
                token,
            )
            .await?;
        }

        let commit = sealbook_core::attachment_commit_request(collection_id, plan.attachment_id);
        let committed = self.send(&commit, Some(token)).await?;
        sealbook_core::attachment_commit_accept(plan.attachment_id, &text(&committed.body))?;
        Ok(sealbook_core::attachment_content_hash(&digests)?)
    }

    /// Fetches and decrypts every chunk, verifying the result against the
    /// record's committed content hash before returning it.
    pub async fn download_attachment(
        &self,
        reference: &UploadedAttachment,
    ) -> Result<Vec<u8>, ClientError> {
        let (server, collection_id, token) = self.attachment_target()?;
        let mut out = Vec::with_capacity(reference.total_plaintext_size as usize);
        let mut digests = Vec::with_capacity(reference.chunk_count as usize);
        for index in 0..reference.chunk_count {
            let (nonce, ciphertext) = self
                .get_bytes(
                    &format!(
                        "{server}{}",
                        sealbook_core::attachment_chunk_path(
                            collection_id,
                            reference.attachment_id,
                            index
                        )
                    ),
                    &token,
                )
                .await?;
            let plaintext = sealbook_core::open_attachment_chunk(
                &reference.key_b64,
                reference.attachment_id,
                collection_id,
                index,
                reference.chunk_count,
                &sealbook_core::attachment_chunk_nonce(Some(nonce))?,
                &ciphertext,
            )?;
            digests.push(sealbook_core::attachment_chunk_digest(&plaintext));
            out.extend_from_slice(&plaintext);
        }
        sealbook_core::attachment_verify(
            reference.attachment_id,
            &reference.content_hash_b64,
            &digests,
        )?;
        Ok(out)
    }

    /// The server's own record of an attachment, checked against the chunk count
    /// the caller's reference carries.
    pub async fn get_attachment_meta(
        &self,
        attachment_id: Uuid,
        chunk_count: u32,
    ) -> Result<sealbook_protocol::AttachmentMetaResponse, ClientError> {
        let (_, collection_id, token) = self.attachment_target()?;
        let request = sealbook_core::attachment_meta_request(collection_id, attachment_id);
        let served = self.send(&request, Some(&token)).await?;
        Ok(sealbook_core::attachment_meta_accept(
            attachment_id,
            chunk_count,
            &text(&served.body),
        )?)
    }

    pub async fn delete_attachment(&self, attachment_id: Uuid) -> Result<(), ClientError> {
        let (_, collection_id, token) = self.attachment_target()?;
        let request = sealbook_core::attachment_delete_request(collection_id, attachment_id);
        self.send(&request, Some(&token)).await?;
        Ok(())
    }

    /// Every attachment the server holds for this collection, paged through.
    ///
    /// The walk ends on a cursor it has already followed, so a server whose
    /// cursor does not advance cannot page this forever.
    pub async fn list_attachments(&self) -> Result<Vec<AttachmentRow>, ClientError> {
        let (_, collection_id, token) = self.attachment_target()?;
        let mut cursor = sealbook_core::sweep_start();
        let mut all = Vec::new();
        loop {
            let request = sealbook_core::sweep_request(collection_id, &cursor);
            let served = self.send(&request, Some(&token)).await?;
            let page = sealbook_core::sweep_page(&cursor, &text(&served.body))?;
            all.extend(page.rows);
            match page.next {
                Some(next) => cursor = next,
                None => break,
            }
        }
        Ok(all)
    }

    /// Deletes the attachments no record references any more.
    ///
    /// The server is content-blind and cannot know which attachments are still
    /// referenced, so the caller passes the ids its own decrypted records name.
    /// `now_secs` is the clock core does not have.
    pub async fn sweep_orphaned_attachments(
        &self,
        referenced: &[Uuid],
        now_secs: i64,
    ) -> Result<usize, ClientError> {
        let rows = self.list_attachments().await?;
        let mut removed = 0;
        for id in sealbook_core::sweep_orphans(&rows, referenced, now_secs) {
            // Leave it for the next sweep rather than failing the whole pass.
            if self.delete_attachment(id).await.is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }
}

fn text(body: &[u8]) -> String {
    String::from_utf8_lossy(body).into_owned()
}

fn encode(bytes: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}
