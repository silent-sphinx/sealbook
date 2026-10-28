//! Binary attachment storage: chunked upload, lazy download, and the quota and
//! sweep that bound it.
//!
//! Attachments sit apart from the sealed-object store on purpose. Their
//! ciphertext is chunked and stored in `attachment_chunks`, never committed to a
//! manifest, never re-encrypted by a key rotation, and never pulled by the eager
//! `/changes` feed. The owning note carries only a small reference — the
//! attachment key, a content hash, the chunking parameters — inside its ordinary
//! sealed JSON. That split is what lets a multi-hundred-megabyte photo store
//! exist without every sync decrypting it and every device revocation resending
//! it.
//!
//! Because nothing audits an attachment id that used to exist, these tables keep
//! no revision log and no tombstones: a delete physically removes the rows in one
//! transaction. The quota lives in `attachment_totals`, reserved at create time
//! from the declared size (an upper bound) and reconciled to the actual stored
//! bytes at commit.

use axum::body::Bytes;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use sealbook_protocol::{
    AttachmentListEntry, AttachmentMetaResponse, CommitAttachmentResponse, CreateAttachmentRequest,
    CreateAttachmentResponse, ErrorBody, ListAttachmentsResponse, ATTACHMENT_CHUNK_SIZE,
    ATTACHMENT_CHUNK_TAG_LEN, ATTACHMENT_STATE_COMMITTED, ATTACHMENT_STATE_PENDING,
    MAX_ATTACHMENT_SIZE,
};

use crate::session::require_session;
use crate::*;

/// Header carrying a chunk's base64url nonce, since the chunk body itself is the
/// raw ciphertext.
const NONCE_HEADER: &str = "x-sealbook-nonce";

/// Attachment operations an account may run per minute. Generous: a large photo
/// is tens of chunk PUTs, and a client may upload several at once.
const ATTACHMENT_OPS_PER_MINUTE: usize = 6_000;

/// Longest a `pending` attachment lives before the sweep reclaims it.
///
/// An upload that was interrupted leaves chunks and reserved quota behind; this
/// is the abandoned-multipart cleanup. Long enough that a slow but live upload is
/// never cut off.
const PENDING_TTL_SECS: i64 = 24 * 60 * 60;

/// Most attachment ids one listing page returns.
const LIST_PAGE_LIMIT: usize = 500;

/// Whether the session owns the collection, as a plain existence check. Unlike
/// the object path this needs no key epoch: attachment ciphertext is sealed under
/// its own key, outside the collection-key epoch entirely.
async fn owns_collection(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    account_id: &str,
    collection_id: Uuid,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let found: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM collections WHERE id = ? AND account_id = ?")
            .bind(collection_id.to_string())
            .bind(account_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    found
        .map(|_| ())
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "collection"))
}

async fn rate_limit(state: &Shared, account_id: &str) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    if !state
        .limiter
        .allow_account(
            "attachments",
            account_id,
            ATTACHMENT_OPS_PER_MINUTE,
            Duration::from_secs(60),
        )
        .await
    {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    Ok(())
}

pub(crate) async fn create_attachment(
    State(state): State<Shared>,
    AxumPath(collection_id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(body): Json<CreateAttachmentRequest>,
) -> Result<Json<CreateAttachmentResponse>, (StatusCode, Json<ErrorBody>)> {
    let session = require_session(&state, &headers).await?;
    rate_limit(&state, &session.account_id).await?;

    if body.total_plaintext_size == 0 || body.chunk_size == 0 || body.chunk_count == 0 {
        return Err(err(StatusCode::BAD_REQUEST, "empty attachment"));
    }
    if body.total_plaintext_size > MAX_ATTACHMENT_SIZE as u64 {
        return Err(err(StatusCode::PAYLOAD_TOO_LARGE, "attachment too large"));
    }
    if body.chunk_size as usize > ATTACHMENT_CHUNK_SIZE {
        return Err(err(StatusCode::BAD_REQUEST, "chunk size too large"));
    }
    // The declared chunking must be the one and only tiling of the declared size,
    // so the completeness check at commit (count of stored chunks) is meaningful.
    let expected_chunks = body.total_plaintext_size.div_ceil(body.chunk_size as u64);
    if expected_chunks != body.chunk_count as u64 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "chunk count does not match size",
        ));
    }

    // An upper-bound reservation: every chunk at full size plus its AEAD tag. The
    // final, shorter chunk makes this a slight over-estimate, reconciled at commit.
    let reserved =
        body.chunk_count as i64 * (body.chunk_size as i64 + ATTACHMENT_CHUNK_TAG_LEN as i64);

    let mut tx = state
        .db
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    owns_collection(&mut tx, &session.account_id, collection_id).await?;

    let existing: Option<String> = sqlx::query_scalar(
        "SELECT state FROM attachments
         WHERE account_id = ? AND collection_id = ? AND attachment_id = ?",
    )
    .bind(&session.account_id)
    .bind(collection_id.to_string())
    .bind(body.attachment_id.to_string())
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    // A re-declare of the same id is idempotent, which is what lets an interrupted
    // upload resume without double-charging the quota.
    if let Some(state_str) = existing {
        tx.commit()
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
        return Ok(Json(CreateAttachmentResponse {
            attachment_id: body.attachment_id,
            state: state_str,
        }));
    }

    let (bytes, count): (i64, i64) = sqlx::query_as(
        "SELECT attachment_bytes, attachment_count FROM attachment_totals WHERE account_id = ?",
    )
    .bind(&session.account_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
    .unwrap_or((0, 0));
    if bytes + reserved > state.limits.max_attachment_bytes
        || count + 1 > state.limits.max_attachment_count
    {
        return Err(err(
            StatusCode::INSUFFICIENT_STORAGE,
            "account attachment quota exceeded",
        ));
    }

    sqlx::query(
        "INSERT INTO attachments
         (account_id, collection_id, attachment_id, state, chunk_size, chunk_count,
          total_plaintext_size, total_ciphertext_size, created_at, committed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
    )
    .bind(&session.account_id)
    .bind(collection_id.to_string())
    .bind(body.attachment_id.to_string())
    .bind(ATTACHMENT_STATE_PENDING)
    .bind(body.chunk_size as i64)
    .bind(body.chunk_count as i64)
    .bind(body.total_plaintext_size as i64)
    .bind(reserved)
    .bind(now())
    .execute(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    bump_totals(&mut tx, &session.account_id, reserved, 1).await?;

    tx.commit()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(Json(CreateAttachmentResponse {
        attachment_id: body.attachment_id,
        state: ATTACHMENT_STATE_PENDING.to_string(),
    }))
}

/// Applies a signed delta to an account's attachment totals, creating the row on
/// first use and clamping at zero so a reconciliation can never drive it negative.
async fn bump_totals(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    account_id: &str,
    bytes_delta: i64,
    count_delta: i64,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    // Numbered params so the raw delta reaches the UPDATE clause. Clamping in the
    // VALUES list would make `excluded` carry the clamped value, and a negative
    // delta (a delete or a downward reconcile) would then add zero instead of
    // subtracting. The MAX(0, ..) on the stored column still floors the result.
    sqlx::query(
        "INSERT INTO attachment_totals (account_id, attachment_bytes, attachment_count)
         VALUES (?1, MAX(0, ?2), MAX(0, ?3))
         ON CONFLICT(account_id) DO UPDATE SET
            attachment_bytes = MAX(0, attachment_bytes + ?2),
            attachment_count = MAX(0, attachment_count + ?3)",
    )
    .bind(account_id)
    .bind(bytes_delta)
    .bind(count_delta)
    .execute(&mut **tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(())
}

pub(crate) async fn upload_chunk(
    State(state): State<Shared>,
    AxumPath((collection_id, attachment_id, index)): AxumPath<(Uuid, Uuid, u32)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, (StatusCode, Json<ErrorBody>)> {
    let session = require_session(&state, &headers).await?;
    rate_limit(&state, &session.account_id).await?;

    let nonce = headers
        .get(NONCE_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing or malformed nonce header"))?;
    if nonce.len() != sealbook_crypto::NONCE_LEN {
        return Err(err(StatusCode::BAD_REQUEST, "wrong nonce length"));
    }

    let mut tx = state
        .db
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    let row: Option<(String, i64, i64)> = sqlx::query_as(
        "SELECT state, chunk_size, chunk_count FROM attachments
         WHERE account_id = ? AND collection_id = ? AND attachment_id = ?",
    )
    .bind(&session.account_id)
    .bind(collection_id.to_string())
    .bind(attachment_id.to_string())
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let (state_str, chunk_size, chunk_count) =
        row.ok_or_else(|| err(StatusCode::NOT_FOUND, "attachment"))?;
    if state_str != ATTACHMENT_STATE_PENDING {
        return Err(err(StatusCode::CONFLICT, "attachment already committed"));
    }
    if index as i64 >= chunk_count {
        return Err(err(StatusCode::BAD_REQUEST, "chunk index out of range"));
    }
    // One sealed chunk is at most its plaintext plus the AEAD tag. A larger body
    // than the declared chunking allows is a client bug or an attempt to smuggle
    // bytes past the reservation.
    if body.len() as i64 > chunk_size + ATTACHMENT_CHUNK_TAG_LEN as i64 {
        return Err(err(StatusCode::BAD_REQUEST, "chunk larger than declared"));
    }
    if body.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "empty chunk"));
    }

    // Overwrite-safe, so a retry after a dropped connection simply re-sends.
    sqlx::query(
        "INSERT INTO attachment_chunks
         (account_id, collection_id, attachment_id, chunk_index, nonce, ciphertext)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(account_id, collection_id, attachment_id, chunk_index) DO UPDATE SET
            nonce = excluded.nonce,
            ciphertext = excluded.ciphertext",
    )
    .bind(&session.account_id)
    .bind(collection_id.to_string())
    .bind(attachment_id.to_string())
    .bind(index as i64)
    .bind(&nonce)
    .bind(body.as_ref())
    .execute(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    tx.commit()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn commit_attachment(
    State(state): State<Shared>,
    AxumPath((collection_id, attachment_id)): AxumPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<CommitAttachmentResponse>, (StatusCode, Json<ErrorBody>)> {
    let session = require_session(&state, &headers).await?;
    rate_limit(&state, &session.account_id).await?;

    let mut tx = state
        .db
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    let row: Option<(String, i64, i64)> = sqlx::query_as(
        "SELECT state, chunk_count, total_ciphertext_size FROM attachments
         WHERE account_id = ? AND collection_id = ? AND attachment_id = ?",
    )
    .bind(&session.account_id)
    .bind(collection_id.to_string())
    .bind(attachment_id.to_string())
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let (state_str, chunk_count, reserved) =
        row.ok_or_else(|| err(StatusCode::NOT_FOUND, "attachment"))?;
    if state_str == ATTACHMENT_STATE_COMMITTED {
        // Committing twice is idempotent: the first commit already did the work.
        tx.commit()
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
        return Ok(Json(CommitAttachmentResponse {
            attachment_id,
            state: ATTACHMENT_STATE_COMMITTED.to_string(),
        }));
    }

    // The server cannot read plaintext, so completeness is all it can enforce:
    // every declared chunk index must be present. Content integrity is the
    // client's rolled-up hash, checked on download.
    let (present, actual): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(LENGTH(ciphertext)), 0) FROM attachment_chunks
         WHERE account_id = ? AND collection_id = ? AND attachment_id = ?",
    )
    .bind(&session.account_id)
    .bind(collection_id.to_string())
    .bind(attachment_id.to_string())
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    if present != chunk_count {
        return Err(err(StatusCode::CONFLICT, "attachment is missing chunks"));
    }

    sqlx::query(
        "UPDATE attachments SET state = ?, total_ciphertext_size = ?, committed_at = ?
         WHERE account_id = ? AND collection_id = ? AND attachment_id = ?",
    )
    .bind(ATTACHMENT_STATE_COMMITTED)
    .bind(actual)
    .bind(now())
    .bind(&session.account_id)
    .bind(collection_id.to_string())
    .bind(attachment_id.to_string())
    .execute(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    // Reconcile the reservation to the bytes actually stored (the final chunk is
    // usually shorter than a full one).
    bump_totals(&mut tx, &session.account_id, actual - reserved, 0).await?;

    tx.commit()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(Json(CommitAttachmentResponse {
        attachment_id,
        state: ATTACHMENT_STATE_COMMITTED.to_string(),
    }))
}

pub(crate) async fn get_attachment_meta(
    State(state): State<Shared>,
    AxumPath((collection_id, attachment_id)): AxumPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<AttachmentMetaResponse>, (StatusCode, Json<ErrorBody>)> {
    let session = require_session(&state, &headers).await?;

    let row: Option<(String, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT state, chunk_size, chunk_count, total_ciphertext_size, created_at
         FROM attachments
         WHERE account_id = ? AND collection_id = ? AND attachment_id = ?",
    )
    .bind(&session.account_id)
    .bind(collection_id.to_string())
    .bind(attachment_id.to_string())
    .fetch_optional(&state.db)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let (state_str, chunk_size, chunk_count, total_ciphertext_size, created_at) =
        row.ok_or_else(|| err(StatusCode::NOT_FOUND, "attachment"))?;
    Ok(Json(AttachmentMetaResponse {
        attachment_id,
        state: state_str,
        chunk_size: chunk_size as u32,
        chunk_count: chunk_count as u32,
        total_ciphertext_size: total_ciphertext_size as u64,
        created_at,
    }))
}

pub(crate) async fn download_chunk(
    State(state): State<Shared>,
    AxumPath((collection_id, attachment_id, index)): AxumPath<(Uuid, Uuid, u32)>,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, Json<ErrorBody>)> {
    let session = require_session(&state, &headers).await?;

    // Only a committed attachment is served, so a second device never sees a
    // half-uploaded one mid-write. This join of state and chunk also means an
    // id the session does not own is simply not found.
    let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT c.nonce, c.ciphertext
         FROM attachment_chunks c
         JOIN attachments a ON a.account_id = c.account_id
            AND a.collection_id = c.collection_id
            AND a.attachment_id = c.attachment_id
         WHERE c.account_id = ? AND c.collection_id = ? AND c.attachment_id = ?
            AND c.chunk_index = ? AND a.state = ?",
    )
    .bind(&session.account_id)
    .bind(collection_id.to_string())
    .bind(attachment_id.to_string())
    .bind(index as i64)
    .bind(ATTACHMENT_STATE_COMMITTED)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let (nonce, ciphertext) = row.ok_or_else(|| err(StatusCode::NOT_FOUND, "chunk"))?;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(NONCE_HEADER, URL_SAFE_NO_PAD.encode(&nonce))
        .body(axum::body::Body::from(ciphertext))
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "response"))
}

pub(crate) async fn delete_attachment(
    State(state): State<Shared>,
    AxumPath((collection_id, attachment_id)): AxumPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, Json<ErrorBody>)> {
    let session = require_session(&state, &headers).await?;
    rate_limit(&state, &session.account_id).await?;

    let mut tx = state
        .db
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    let reserved: Option<i64> = sqlx::query_scalar(
        "SELECT total_ciphertext_size FROM attachments
         WHERE account_id = ? AND collection_id = ? AND attachment_id = ?",
    )
    .bind(&session.account_id)
    .bind(collection_id.to_string())
    .bind(attachment_id.to_string())
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    // Idempotent: deleting an absent attachment is a success, so a client that
    // retries after a dropped response is not stuck.
    let Some(reserved) = reserved else {
        tx.commit()
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
        return Ok(StatusCode::NO_CONTENT);
    };

    // The chunk rows go by the foreign-key cascade when the attachment row does.
    sqlx::query(
        "DELETE FROM attachments
         WHERE account_id = ? AND collection_id = ? AND attachment_id = ?",
    )
    .bind(&session.account_id)
    .bind(collection_id.to_string())
    .bind(attachment_id.to_string())
    .execute(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    bump_totals(&mut tx, &session.account_id, -reserved, -1).await?;

    tx.commit()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub(crate) struct ListQuery {
    after: Option<Uuid>,
}

pub(crate) async fn list_attachments(
    State(state): State<Shared>,
    AxumPath(collection_id): AxumPath<Uuid>,
    Query(query): Query<ListQuery>,
    headers: HeaderMap,
) -> Result<Json<ListAttachmentsResponse>, (StatusCode, Json<ErrorBody>)> {
    let session = require_session(&state, &headers).await?;

    // Ids and age only. The server is content-blind, so it cannot know which
    // attachments a note still references: the orphan sweep is the client's,
    // driven by cross-referencing this list against its decrypted notes.
    let after = query.after.map(|id| id.to_string()).unwrap_or_default();
    let rows = sqlx::query(
        "SELECT attachment_id, state, created_at FROM attachments
         WHERE account_id = ? AND collection_id = ? AND attachment_id > ?
         ORDER BY attachment_id ASC
         LIMIT ?",
    )
    .bind(&session.account_id)
    .bind(collection_id.to_string())
    .bind(after)
    .bind(LIST_PAGE_LIMIT as i64 + 1)
    .fetch_all(&state.db)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    let mut attachments: Vec<AttachmentListEntry> = rows
        .iter()
        .filter_map(|row| {
            let id: String = row.get("attachment_id");
            Some(AttachmentListEntry {
                attachment_id: Uuid::parse_str(&id).ok()?,
                state: row.get("state"),
                created_at: row.get("created_at"),
            })
        })
        .collect();

    let next_after = if attachments.len() > LIST_PAGE_LIMIT {
        attachments.truncate(LIST_PAGE_LIMIT);
        attachments.last().map(|entry| entry.attachment_id)
    } else {
        None
    };

    Ok(Json(ListAttachmentsResponse {
        attachments,
        next_after,
    }))
}

/// Deletes `pending` attachments older than `PENDING_TTL_SECS`, releasing their
/// reserved quota. The reservation per account is recomputed from what remains
/// rather than decremented per row, so a crash mid-sweep cannot drift the total.
pub async fn sweep_pending_attachments(db: &Pool<Sqlite>) -> Result<u64, sqlx::Error> {
    let cutoff = now().saturating_sub(PENDING_TTL_SECS);
    let mut tx = db.begin_with("BEGIN IMMEDIATE").await?;

    // The accounts about to lose a pending attachment, so their totals can be
    // recomputed afterwards.
    let touched: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT account_id FROM attachments
         WHERE state = ? AND created_at < ?",
    )
    .bind(ATTACHMENT_STATE_PENDING)
    .bind(cutoff)
    .fetch_all(&mut *tx)
    .await?;

    let deleted = sqlx::query("DELETE FROM attachments WHERE state = ? AND created_at < ?")
        .bind(ATTACHMENT_STATE_PENDING)
        .bind(cutoff)
        .execute(&mut *tx)
        .await?
        .rows_affected();

    for account_id in &touched {
        sqlx::query(
            "INSERT INTO attachment_totals (account_id, attachment_bytes, attachment_count)
             VALUES (
                ?,
                COALESCE((SELECT SUM(total_ciphertext_size) FROM attachments WHERE account_id = ?), 0),
                COALESCE((SELECT COUNT(*) FROM attachments WHERE account_id = ?), 0)
             )
             ON CONFLICT(account_id) DO UPDATE SET
                attachment_bytes = COALESCE(
                    (SELECT SUM(total_ciphertext_size) FROM attachments WHERE account_id = attachment_totals.account_id), 0),
                attachment_count = COALESCE(
                    (SELECT COUNT(*) FROM attachments WHERE account_id = attachment_totals.account_id), 0)",
        )
        .bind(account_id)
        .bind(account_id)
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(deleted)
}
