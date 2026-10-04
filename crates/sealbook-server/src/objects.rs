//! The encrypted object store: writes, the change feed clients sync from,
//! and the wrapped collection keys.

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use sqlx::Row;
use uuid::Uuid;

use sealbook_crypto::content_digest;
use sealbook_protocol::{
    parse_bucket_query, ChangesQuery, ChangesResponse, CollectionKeysResponse, ErrorBody,
    KeyWrapBody, ManifestBucketQuery, ManifestBucketsResponse, ManifestResponse, ObjectChange,
    PutObjectRequest, PutObjectResponse, PutObjectsRequest, PutObjectsResponse,
    DEFAULT_CHANGES_LIMIT, MAX_CHANGES_LIMIT,
};

use crate::manifest;
use crate::session::require_session;
use crate::validate::{validate_batch, validate_object};
use crate::*;

const WRITES_PER_MINUTE: usize = 1_200;

/// Most ciphertext bytes one `changes` page may carry.
///
/// `limit` was the only thing deciding how large an answer could get, and an
/// object may be `MAX_PADDED_OBJECT_SIZE`, so a page of 2,000 could read the
/// whole of a quota-sized vault out of the rows and base64 expand it beside
/// itself. A page always carries at least one object, so a vault whose next
/// object is larger than this still advances rather than stalling.
const MAX_CHANGES_BYTES: i64 = 8 * 1024 * 1024;

/// What a write would leave the account holding.
struct Totals {
    objects: i64,
    bytes: i64,
    tombstones: i64,
}

fn check_quota(limits: &Limits, totals: &Totals) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let Limits {
        max_objects,
        max_bytes,
        ..
    } = *limits;

    let live = totals.objects - totals.tombstones;
    if live > max_objects || totals.bytes > max_bytes {
        return Err(err(
            StatusCode::INSUFFICIENT_STORAGE,
            "account storage quota exceeded",
        ));
    }

    if totals.tombstones > max_objects {
        return Err(err(
            StatusCode::INSUFFICIENT_STORAGE,
            "account storage quota exceeded: too many deleted objects. Rotating the \
             collection key retires the ones no device can still be told about.",
        ));
    }

    if !limits.rotation_fits(live, totals.bytes, totals.tombstones) {
        return Err(err(
            StatusCode::INSUFFICIENT_STORAGE,
            "account storage quota exceeded: the vault would grow past what one \
             key rotation can carry, and revoking a device would stop working",
        ));
    }
    Ok(())
}

/// The padded size and tombstone flag of the row this write replaces, if any.
async fn replaced_object(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    account_id: &str,
    collection_id: &str,
    object_id: Uuid,
) -> Result<Option<(i64, i64)>, (StatusCode, Json<ErrorBody>)> {
    sqlx::query_as(
        "SELECT padded_size, tombstone FROM objects
         WHERE account_id = ? AND collection_id = ? AND id = ?",
    )
    .bind(account_id)
    .bind(collection_id)
    .bind(object_id.to_string())
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))
}

/// One object's live row and its entry in the revision log.
///
/// Both tables or neither: the live state is what a snapshot walk serves and the
/// log is what an incremental one serves, so a write that landed in one and not
/// the other would give two devices different collections.
#[allow(clippy::too_many_arguments)]
async fn store_object(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    account_id: &str,
    collection_id: &str,
    object_id: Uuid,
    revision: i64,
    tombstone: bool,
    nonce: &[u8],
    ciphertext: &[u8],
    padded_size: usize,
    content_type: &str,
    digest: &[u8],
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
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
    .bind(object_id.to_string())
    .bind(collection_id)
    .bind(account_id)
    .bind(revision)
    .bind(i64::from(tombstone))
    .bind(ciphertext)
    .bind(nonce)
    .bind(padded_size as i64)
    .bind(content_type)
    .bind(digest)
    .execute(&mut **tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    sqlx::query(
        "INSERT INTO object_revisions
         (account_id, revision, collection_id, object_id, tombstone, ciphertext, nonce, padded_size, content_type, content_digest, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(account_id)
    .bind(revision)
    .bind(collection_id)
    .bind(object_id.to_string())
    .bind(i64::from(tombstone))
    .bind(ciphertext)
    .bind(nonce)
    .bind(padded_size as i64)
    .bind(content_type)
    .bind(digest)
    .bind(now())
    .execute(&mut **tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(())
}

/// The collection's key epoch, or a 404 if the session does not own it.
async fn owned_collection_epoch(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    account_id: &str,
    collection_id: Uuid,
) -> Result<i64, (StatusCode, Json<ErrorBody>)> {
    sqlx::query_scalar::<_, i64>(
        "SELECT key_epoch FROM collections WHERE id = ? AND account_id = ?",
    )
    .bind(collection_id.to_string())
    .bind(account_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "collection"))
}

pub(crate) async fn put_object(
    State(state): State<Shared>,
    AxumPath(collection_id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(body): Json<PutObjectRequest>,
) -> Result<Json<PutObjectResponse>, (StatusCode, Json<ErrorBody>)> {
    let session = require_session(&state, &headers).await?;
    crate::recovery::require_rotation_not_owed(&state, &session.account_id).await?;
    if !state
        .limiter
        .allow_account(
            "put-object",
            &session.account_id,
            WRITES_PER_MINUTE,
            Duration::from_secs(60),
        )
        .await
    {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    validate_object(&body)?;

    let mut tx = state
        .db
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    let collection = collection_id.to_string();
    let key_epoch = owned_collection_epoch(&mut tx, &session.account_id, collection_id).await?;

    let seq = sqlx::query(
        "SELECT next_revision, object_count, byte_total, tombstone_count FROM revision_seq
         WHERE account_id = ?",
    )
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
    let replaced = replaced_object(&mut tx, &session.account_id, &collection, body.id).await?;
    let is_new = replaced.is_none();
    let (replaced_bytes, replaced_tombstone) = replaced.unwrap_or((0, 0));
    let totals = Totals {
        objects: seq.get::<i64, _>("object_count") + i64::from(is_new),
        bytes: seq.get::<i64, _>("byte_total") - replaced_bytes + body.padded_size as i64,
        tombstones: seq.get::<i64, _>("tombstone_count") - replaced_tombstone
            + i64::from(body.tombstone),
    };
    check_quota(&state.limits, &totals)?;

    sqlx::query(
        "UPDATE revision_seq SET next_revision = ?, object_count = ?, byte_total = ?,
             tombstone_count = ?
         WHERE account_id = ?",
    )
    .bind(revision + 1)
    .bind(totals.objects)
    .bind(totals.bytes)
    .bind(totals.tombstones)
    .bind(&session.account_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    let digest = content_digest(&body.nonce, &body.ciphertext).to_vec();
    store_object(
        &mut tx,
        &session.account_id,
        &collection,
        body.id,
        revision,
        body.tombstone,
        &body.nonce,
        &body.ciphertext,
        body.padded_size,
        &body.content_type,
        &digest,
    )
    .await?;

    // Folds the write into the bucket digests, so the manifest check below reads
    // a digest instead of recomputing one over the whole collection.
    manifest::record_object_writes(
        &mut tx,
        &session.account_id,
        &collection,
        &[(body.id, is_new)],
    )
    .await?;

    manifest::verify_and_store(
        &mut tx,
        manifest::Expected {
            collection_id: &collection,
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

pub(crate) async fn put_objects(
    State(state): State<Shared>,
    AxumPath(collection_id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(body): Json<PutObjectsRequest>,
) -> Result<Json<PutObjectsResponse>, (StatusCode, Json<ErrorBody>)> {
    let session = require_session(&state, &headers).await?;
    crate::recovery::require_rotation_not_owed(&state, &session.account_id).await?;
    // Shape-checked before the limiter, so a malformed batch cannot be charged
    // for an object count it was never going to be allowed to write.
    validate_batch(&body.objects)?;
    // Charged per object against the same bucket a single write uses: a batch is
    // a cheaper way to send the same number of objects, not a way to send more.
    if !state
        .limiter
        .allow_account_cost(
            "put-object",
            &session.account_id,
            body.objects.len(),
            WRITES_PER_MINUTE,
            Duration::from_secs(60),
        )
        .await
    {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }

    // Hashed before the transaction opens, for the reason `rotate` gives: a batch
    // is up to 256 objects of SHA-256, and under `BEGIN IMMEDIATE` that would
    // stall every other writer for as long as it takes.
    let digests: Vec<Vec<u8>> = body
        .objects
        .iter()
        .map(|object| content_digest(&object.nonce, &object.ciphertext).to_vec())
        .collect();

    let mut tx = state
        .db
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    let collection = collection_id.to_string();
    let key_epoch = owned_collection_epoch(&mut tx, &session.account_id, collection_id).await?;

    let seq = sqlx::query(
        "SELECT next_revision, object_count, byte_total, tombstone_count FROM revision_seq
         WHERE account_id = ?",
    )
    .bind(&session.account_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let first_revision: i64 = seq.get("next_revision");
    // Revisions are chosen by the client, because the manifest it signs commits to
    // each one, and must run consecutively from the collection's next revision in
    // the order sent. A mismatch means another device wrote first.
    for (index, object) in body.objects.iter().enumerate() {
        if object.revision != first_revision as u64 + index as u64 {
            return Err(err(StatusCode::CONFLICT, "stale revision"));
        }
    }
    let latest_revision = first_revision + body.objects.len() as i64 - 1;

    // Quota is checked once against the state the whole batch would produce, so a
    // batch that would end over the ceiling is refused entire rather than part
    // applied. Ids are unique within a batch, so no object here replaces another
    // of its own and each replacement is read from the pre-batch rows.
    let mut totals = Totals {
        objects: seq.get("object_count"),
        bytes: seq.get("byte_total"),
        tombstones: seq.get("tombstone_count"),
    };
    let mut written: Vec<(Uuid, bool)> = Vec::with_capacity(body.objects.len());
    for object in &body.objects {
        let replaced =
            replaced_object(&mut tx, &session.account_id, &collection, object.id).await?;
        let is_new = replaced.is_none();
        let (replaced_bytes, replaced_tombstone) = replaced.unwrap_or((0, 0));
        totals.objects += i64::from(is_new);
        totals.bytes += object.padded_size as i64 - replaced_bytes;
        totals.tombstones += i64::from(object.tombstone) - replaced_tombstone;
        written.push((object.id, is_new));
    }
    check_quota(&state.limits, &totals)?;

    sqlx::query(
        "UPDATE revision_seq SET next_revision = ?, object_count = ?, byte_total = ?,
             tombstone_count = ?
         WHERE account_id = ?",
    )
    .bind(latest_revision + 1)
    .bind(totals.objects)
    .bind(totals.bytes)
    .bind(totals.tombstones)
    .bind(&session.account_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    for ((index, object), digest) in body.objects.iter().enumerate().zip(&digests) {
        store_object(
            &mut tx,
            &session.account_id,
            &collection,
            object.id,
            first_revision + index as i64,
            object.tombstone,
            &object.nonce,
            &object.ciphertext,
            object.padded_size,
            &object.content_type,
            digest,
        )
        .await?;
    }

    // One pass over the buckets the batch touched, each rebuilt once however many
    // of these objects share it.
    manifest::record_object_writes(&mut tx, &session.account_id, &collection, &written).await?;

    manifest::verify_and_store(
        &mut tx,
        manifest::Expected {
            collection_id: &collection,
            account_id: &session.account_id,
            device_id: &session.device_id,
            key_epoch,
            latest_revision,
        },
        &body.manifest,
    )
    .await?;

    tx.commit()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    Ok(Json(PutObjectsResponse {
        first_revision: first_revision as u64,
        latest_revision: latest_revision as u64,
    }))
}

/// The collection's signed manifest and the entries it commits to.
pub(crate) async fn collection_manifest(
    State(state): State<Shared>,
    AxumPath(collection_id): AxumPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<ManifestResponse>, (StatusCode, Json<ErrorBody>)> {
    let session = require_session(&state, &headers).await?;
    require_read_budget(&state, "manifest", &session.account_id).await?;
    let owned = sqlx::query("SELECT id FROM collections WHERE id = ? AND account_id = ?")
        .bind(collection_id.to_string())
        .bind(&session.account_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    if owned.is_none() {
        return Err(err(StatusCode::NOT_FOUND, "collection"));
    }
    // The entries and the manifest that commits to them must come from one
    // snapshot. Read apart, a write landing in between returns the new manifest
    // beside the old entries, and the client's digest check — the whole point of
    // this endpoint — fails exactly as it would against a server withholding an
    // object.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let entries =
        manifest::entries(&mut tx, &session.account_id, &collection_id.to_string()).await?;
    let manifest = manifest::load(&mut *tx, &collection_id.to_string()).await?;
    tx.commit()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(Json(ManifestResponse { manifest, entries }))
}

/// The manifest in the shape a write needs: the bucket digests, and the entries
/// of the buckets that write touches.
///
/// `collection_manifest` serves every entry in the collection, which made a write
/// cost bytes proportional to the whole vault. This is the same guarantee for a
/// fraction of the traffic, because the root is a hash of the 256 bucket digests
/// and a write changes one of them per object.
pub(crate) async fn collection_manifest_buckets(
    State(state): State<Shared>,
    AxumPath(collection_id): AxumPath<Uuid>,
    Query(query): Query<ManifestBucketQuery>,
    headers: HeaderMap,
) -> Result<Json<ManifestBucketsResponse>, (StatusCode, Json<ErrorBody>)> {
    let session = require_session(&state, &headers).await?;
    require_read_budget(&state, "manifest", &session.account_id).await?;
    let owned = sqlx::query("SELECT id FROM collections WHERE id = ? AND account_id = ?")
        .bind(collection_id.to_string())
        .bind(&session.account_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    if owned.is_none() {
        return Err(err(StatusCode::NOT_FOUND, "collection"));
    }
    // Deduplicated and sorted by the parser, so a caller naming one bucket many
    // times pays for one range scan and the echo back is canonical.
    let served = match query.buckets.as_deref() {
        Some(buckets) => parse_bucket_query(buckets)
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "invalid bucket list"))?,
        None => Vec::new(),
    };
    // One snapshot for the digests, the buckets and the manifest, for the reason
    // `collection_manifest` gives: read apart, a write landing in between serves
    // a new manifest beside an old bucket and the client's check fails exactly as
    // it would against a server withholding an object.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let collection = collection_id.to_string();
    let (buckets, object_count) =
        manifest::bucket_state(&mut tx, &session.account_id, &collection).await?;
    let entries =
        manifest::entries_in_buckets(&mut tx, &session.account_id, &collection, &served).await?;
    let manifest = manifest::load(&mut *tx, &collection).await?;
    tx.commit()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(Json(ManifestBucketsResponse {
        manifest,
        buckets,
        object_count: object_count as u64,
        served,
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
    require_read_budget(&state, "changes", &session.account_id).await?;
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

    // One snapshot for the whole answer. Read from the pool one statement at a
    // time, the watermark, the epoch, the rows and the manifest could each come
    // from a different commit, so a write landing mid-handler produced a reply
    // that described no state the vault was ever in.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let latest_assigned: i64 =
        sqlx::query_scalar("SELECT next_revision - 1 FROM revision_seq WHERE account_id = ?")
            .bind(&session.account_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
            .unwrap_or(0);
    let key_epoch: i64 =
        sqlx::query_scalar("SELECT key_epoch FROM collections WHERE id = ? AND account_id = ?")
            .bind(collection_id.to_string())
            .bind(&session.account_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "collection"))?;

    // The oldest revision the log still holds, which is both what decides a
    // resync below and which tombstones a rotation may retire. An empty log
    // bridges nothing, so the floor sits above every revision assigned.
    let log_floor: i64 =
        sqlx::query_scalar("SELECT MIN(revision) FROM object_revisions WHERE account_id = ?")
            .bind(&session.account_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
            .flatten()
            .unwrap_or(latest_assigned + 1);

    // Can the log bridge the gap between what the client has and now?
    let needs_resync = !snapshot && after > 0 && after < latest_assigned && after + 1 < log_floor;
    if needs_resync {
        // Deliberately empty. Saying "restart from the beginning as a snapshot" in
        // one round trip is unambiguous; serving a partial snapshot from the
        // client's stale watermark would look like an answer and quietly omit
        // everything below it.
        let manifest = manifest::load(&mut *tx, &collection_id.to_string()).await?;
        tx.commit()
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
        return Ok(Json(ChangesResponse {
            latest_revision: latest_assigned as u64,
            key_epoch: key_epoch as u64,
            objects: Vec::new(),
            has_more: false,
            manifest,
            resync: true,
            tombstone_floor: log_floor as u64,
        }));
    }

    // The sizes of the candidate rows, without their ciphertext, so the byte
    // ceiling bounds what the page reads rather than only what it returns.
    // `revision > ?` so a paged walk advances; revisions start at 1, so
    // `after = 0` still selects everything.
    let sizes: Vec<i64> = if snapshot || after == 0 {
        sqlx::query_scalar(
            "SELECT padded_size FROM objects
             WHERE account_id = ? AND collection_id = ? AND revision > ?
             ORDER BY revision ASC
             LIMIT ?",
        )
    } else {
        sqlx::query_scalar(
            "SELECT r.padded_size FROM object_revisions r
             WHERE r.account_id = ? AND r.collection_id = ? AND r.revision > ?
             ORDER BY r.revision ASC
             LIMIT ?",
        )
    }
    .bind(&session.account_id)
    .bind(collection_id.to_string())
    .bind(after)
    .bind(probe)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    // The longest prefix that fits the ceiling, and never shorter than one
    // object.
    let mut page = 0usize;
    let mut page_bytes = 0i64;
    for padded in sizes.iter().take(limit) {
        if page > 0 && page_bytes + padded > MAX_CHANGES_BYTES {
            break;
        }
        page_bytes += padded;
        page += 1;
    }
    let has_more = sizes.len() > page;

    let rows = if page == 0 {
        Vec::new()
    } else if snapshot || after == 0 {
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
        .bind(page as i64)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
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
        .bind(page as i64)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
    };

    let mut latest = after as u64;
    let mut objects = Vec::new();
    for row in rows {
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
    let manifest = manifest::load(&mut *tx, &collection_id.to_string()).await?;
    tx.commit()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(Json(ChangesResponse {
        latest_revision: latest,
        key_epoch: key_epoch as u64,
        objects,
        has_more,
        manifest,
        // A snapshot walk is itself the resync.
        resync: snapshot,
        tombstone_floor: log_floor as u64,
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
    require_read_budget(&state, "keys", &session.account_id).await?;
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
