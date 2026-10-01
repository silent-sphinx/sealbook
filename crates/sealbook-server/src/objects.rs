//! The encrypted object store: writes, the change feed clients sync from,
//! and the wrapped collection keys.

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use sqlx::Row;
use uuid::Uuid;

use sealbook_crypto::content_digest;
use sealbook_protocol::{
    ChangesQuery, ChangesResponse, CollectionKeysResponse, ErrorBody, KeyWrapBody,
    ManifestResponse, ObjectChange, PutObjectRequest, PutObjectResponse, DEFAULT_CHANGES_LIMIT,
    MAX_CHANGES_LIMIT,
};

use crate::manifest;
use crate::session::require_session;
use crate::validate::validate_object;
use crate::*;

pub(crate) async fn put_object(
    State(state): State<Shared>,
    AxumPath(collection_id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(body): Json<PutObjectRequest>,
) -> Result<Json<PutObjectResponse>, (StatusCode, Json<ErrorBody>)> {
    let session = require_session(&state, &headers).await?;
    // Authenticated routes were unmetered, so a stolen token could write until the
    // disk filled. High enough that a first full sync of a large vault is not
    // throttled, low enough to bound what one token can do in a minute.
    if !state
        .limiter
        .allow_account(
            "put-object",
            &session.account_id,
            1_200,
            Duration::from_secs(60),
        )
        .await
    {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    validate_object(&body)?;
    let collection =
        sqlx::query("SELECT key_epoch FROM collections WHERE id = ? AND account_id = ?")
            .bind(collection_id.to_string())
            .bind(&session.account_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let Some(collection) = collection else {
        return Err(err(StatusCode::NOT_FOUND, "collection"));
    };
    let key_epoch: i64 = collection.get("key_epoch");

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let seq = sqlx::query("SELECT next_revision FROM revision_seq WHERE account_id = ?")
        .bind(&session.account_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let revision: i64 = seq.get("next_revision");
    // The revision is chosen by the client, because the manifest it signs commits
    // to it. A mismatch means another device wrote first.
    if body.revision != revision as u64 {
        return Err(err(StatusCode::CONFLICT, "stale revision"));
    }

    // Quota is checked against the state this write would produce.
    let Limits {
        max_objects,
        max_bytes,
        ..
    } = state.limits;

    let usage = sqlx::query(
        "SELECT COUNT(*) AS objects, COALESCE(SUM(padded_size), 0) AS bytes,
                COALESCE(SUM(CASE WHEN id = ? AND collection_id = ? THEN padded_size ELSE 0 END), 0)
                    AS replaced,
                COALESCE(SUM(CASE WHEN id = ? AND collection_id = ? THEN 1 ELSE 0 END), 0)
                    AS present
         FROM objects WHERE account_id = ?",
    )
    .bind(body.id.to_string())
    .bind(collection_id.to_string())
    .bind(body.id.to_string())
    .bind(collection_id.to_string())
    .bind(&session.account_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let existing_objects: i64 = usage.get("objects");
    let existing_bytes: i64 = usage.get("bytes");
    let replaced: i64 = usage.get("replaced");
    let is_new = usage.get::<i64, _>("present") == 0;
    let objects_after = existing_objects + i64::from(is_new);
    let bytes_after = existing_bytes - replaced + body.padded_size as i64;
    if objects_after > max_objects || bytes_after > max_bytes {
        return Err(err(
            StatusCode::INSUFFICIENT_STORAGE,
            "account storage quota exceeded",
        ));
    }
    // The vault also has to stay small enough to rotate. A rotation re-encrypts
    // everything in one request, so a vault that outgrows that body cannot be
    // rotated — and every operation that has to invalidate the collection key
    // goes through a rotation. Refusing the write is the only failure mode that
    // does not end with a revoked device still holding a working key.
    if !state.limits.rotation_fits(objects_after, bytes_after) {
        return Err(err(
            StatusCode::INSUFFICIENT_STORAGE,
            "account storage quota exceeded: the vault would grow past what one \
             key rotation can carry, and revoking a device would stop working",
        ));
    }

    sqlx::query("UPDATE revision_seq SET next_revision = ? WHERE account_id = ?")
        .bind(revision + 1)
        .bind(&session.account_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    let digest = content_digest(&body.nonce, &body.ciphertext).to_vec();
    sqlx::query(
        "INSERT INTO objects (id, collection_id, account_id, revision, tombstone, ciphertext, nonce, padded_size, content_type, content_digest)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(account_id, collection_id, id) DO UPDATE SET
            revision = excluded.revision,
            tombstone = excluded.tombstone,
            ciphertext = excluded.ciphertext,
            nonce = excluded.nonce,
            padded_size = excluded.padded_size,
            content_type = excluded.content_type,
            content_digest = excluded.content_digest",
    )
    .bind(body.id.to_string())
    .bind(collection_id.to_string())
    .bind(&session.account_id)
    .bind(revision)
    .bind(if body.tombstone { 1 } else { 0 })
    .bind(&body.ciphertext)
    .bind(&body.nonce)
    .bind(body.padded_size as i64)
    .bind(&body.content_type)
    .bind(&digest)
    .execute(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    sqlx::query(
        "INSERT INTO object_revisions
         (account_id, revision, collection_id, object_id, tombstone, ciphertext, nonce, padded_size, content_type, content_digest, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&session.account_id)
    .bind(revision)
    .bind(collection_id.to_string())
    .bind(body.id.to_string())
    .bind(if body.tombstone { 1 } else { 0 })
    .bind(&body.ciphertext)
    .bind(&body.nonce)
    .bind(body.padded_size as i64)
    .bind(&body.content_type)
    .bind(&digest)
    .bind(now())
    .execute(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    manifest::verify_and_store(
        &mut tx,
        manifest::Expected {
            collection_id: &collection_id.to_string(),
            account_id: &session.account_id,
            device_id: &session.device_id,
            key_epoch,
            latest_revision: revision,
        },
        &body.manifest,
    )
    .await?;

    tx.commit()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    Ok(Json(PutObjectResponse {
        revision: revision as u64,
    }))
}

/// The collection's signed manifest and the entries it commits to.
///
/// A client with no local state starts here: verify the signature against an
/// enrolled device's public key, check the digest over these entries, and the
/// entry set can then be trusted as the collection's true shape.
pub(crate) async fn collection_manifest(
    State(state): State<Shared>,
    AxumPath(collection_id): AxumPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<ManifestResponse>, (StatusCode, Json<ErrorBody>)> {
    let session = require_session(&state, &headers).await?;
    let owned = sqlx::query("SELECT id FROM collections WHERE id = ? AND account_id = ?")
        .bind(collection_id.to_string())
        .bind(&session.account_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    if owned.is_none() {
        return Err(err(StatusCode::NOT_FOUND, "collection"));
    }
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let entries =
        manifest::entries(&mut tx, &session.account_id, &collection_id.to_string()).await?;
    tx.commit()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(Json(ManifestResponse {
        manifest: manifest::load(&state.db, &collection_id.to_string()).await?,
        entries,
    }))
}

pub(crate) async fn changes(
    State(state): State<Shared>,
    AxumPath(collection_id): AxumPath<Uuid>,
    Query(query): Query<ChangesQuery>,
    headers: HeaderMap,
) -> Result<Json<ChangesResponse>, (StatusCode, Json<ErrorBody>)> {
    let session = require_session(&state, &headers).await?;
    let after = query.after.unwrap_or(0) as i64;
    // One row over the page, so "is there more" needs no second query.
    let limit = query
        .limit
        .unwrap_or(DEFAULT_CHANGES_LIMIT)
        .clamp(1, MAX_CHANGES_LIMIT);
    let probe = limit as i64 + 1;

    // Superseded revisions are pruned after a retention window, so an incremental
    // request can name a watermark whose successors no longer exist. Serving the
    // remaining tail would silently skip the writes in between, so the client is
    // told to restart as a snapshot walk instead.
    //
    // A snapshot walk pages through live objects rather than the log, so it needs
    // nothing retained and cannot be interrupted by a sweep mid-walk. Tombstones
    // are rows in `objects`, so it is a complete description, not just a current
    // one.
    let snapshot = query.snapshot.unwrap_or(false);
    let latest_assigned: i64 =
        sqlx::query_scalar("SELECT next_revision - 1 FROM revision_seq WHERE account_id = ?")
            .bind(&session.account_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
            .unwrap_or(0);
    let key_epoch: i64 =
        sqlx::query_scalar("SELECT key_epoch FROM collections WHERE id = ? AND account_id = ?")
            .bind(collection_id.to_string())
            .bind(&session.account_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "collection"))?;

    // Can the log bridge the gap between what the client has and now?
    let needs_resync = !snapshot && after > 0 && after < latest_assigned && {
        let floor: Option<i64> =
            sqlx::query_scalar("SELECT MIN(revision) FROM object_revisions WHERE account_id = ?")
                .bind(&session.account_id)
                .fetch_optional(&state.db)
                .await
                .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
                .flatten();
        match floor {
            Some(floor) => after + 1 < floor,
            None => true,
        }
    };
    if needs_resync {
        // Deliberately empty. Saying "restart from the beginning as a snapshot" in
        // one round trip is unambiguous; serving a partial snapshot from the
        // client's stale watermark would look like an answer and quietly omit
        // everything below it.
        return Ok(Json(ChangesResponse {
            latest_revision: latest_assigned as u64,
            key_epoch: key_epoch as u64,
            objects: Vec::new(),
            has_more: false,
            manifest: manifest::load(&state.db, &collection_id.to_string()).await?,
            resync: true,
        }));
    }

    let rows = if snapshot || after == 0 {
        // `revision > ?` so a paged walk advances. Revisions start at 1, so
        // `after = 0` still selects everything.
        sqlx::query(
            "SELECT id AS object_id, revision, tombstone, nonce, ciphertext,
                padded_size, content_type
             FROM objects
             WHERE account_id = ? AND collection_id = ? AND revision > ?
             ORDER BY revision ASC
             LIMIT ?",
        )
        .bind(&session.account_id)
        .bind(collection_id.to_string())
        .bind(after)
        .bind(probe)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query(
            "SELECT r.object_id, r.revision, r.tombstone, r.nonce, r.ciphertext,
                r.padded_size, r.content_type
             FROM object_revisions r
             WHERE r.account_id = ? AND r.collection_id = ? AND r.revision > ?
             ORDER BY r.revision ASC
             LIMIT ?",
        )
        .bind(&session.account_id)
        .bind(collection_id.to_string())
        .bind(after)
        .bind(probe)
        .fetch_all(&state.db)
        .await
    }
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    let has_more = rows.len() > limit;
    let mut latest = after as u64;
    let mut objects = Vec::new();
    for row in rows.into_iter().take(limit) {
        let revision: i64 = row.get("revision");
        latest = latest.max(revision as u64);
        let tombstone: i64 = row.get("tombstone");
        let id: String = row.get("object_id");
        objects.push(ObjectChange {
            id: Uuid::parse_str(&id).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?,
            revision: revision as u64,
            tombstone: tombstone != 0,
            nonce: row.get("nonce"),
            ciphertext: row.get("ciphertext"),
            padded_size: row.get::<i64, _>("padded_size") as usize,
            content_type: row.get("content_type"),
        });
    }
    Ok(Json(ChangesResponse {
        latest_revision: latest,
        key_epoch: key_epoch as u64,
        objects,
        has_more,
        manifest: manifest::load(&state.db, &collection_id.to_string()).await?,
        // A snapshot walk is itself the resync.
        resync: snapshot,
    }))
}

/// Returns the calling device's current collection-key wrap.
///
/// A client whose cached key is stale after a rotation fetches its new wrap
/// here; unwrapping needs only the device's own X-Wing secret, so this works
/// without re-prompting for the password.
pub(crate) async fn collection_keys(
    State(state): State<Shared>,
    AxumPath(collection_id): AxumPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<CollectionKeysResponse>, (StatusCode, Json<ErrorBody>)> {
    let session = require_session(&state, &headers).await?;
    let collection =
        sqlx::query("SELECT key_epoch FROM collections WHERE id = ? AND account_id = ?")
            .bind(collection_id.to_string())
            .bind(&session.account_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "collection"))?;
    let rows = sqlx::query(
        "SELECT recipient_kind, recipient_id, hpke_enc, wrapped_ck, ciphersuite
         FROM key_wraps
         WHERE collection_id = ? AND recipient_kind = 'device' AND recipient_id = ?",
    )
    .bind(collection_id.to_string())
    .bind(&session.device_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(Json(CollectionKeysResponse {
        key_epoch: collection.get::<i64, _>("key_epoch") as u64,
        key_wraps: rows.into_iter().map(row_to_key_wrap).collect(),
    }))
}

pub(crate) fn row_to_key_wrap(row: sqlx::sqlite::SqliteRow) -> KeyWrapBody {
    KeyWrapBody {
        recipient_kind: row.get("recipient_kind"),
        recipient_id: row.get("recipient_id"),
        hpke_enc: row.get("hpke_enc"),
        wrapped_ck: row.get("wrapped_ck"),
        ciphersuite: row.get("ciphersuite"),
    }
}
