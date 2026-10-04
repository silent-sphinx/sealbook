//! Device inventory and revocation. Revoking rotates the collection key and
//! re-wraps it for every device that keeps access.

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use sqlx::Row;
use tracing::info;
use uuid::Uuid;

use sealbook_crypto::{
    content_digest, key_rotation_transcript, key_wraps_digest, rotated_objects_digest,
    rotation_recovery_payload, verify, DeviceSigningPublic, DualSignature, ObjectDigestEntry,
    WrapDigestEntry,
};
use sealbook_protocol::{DevicePublicKeys, ErrorBody, RotateRequest, RotateResponse};

use crate::manifest;
use crate::roster;
use crate::session::{require_recent_session, require_session};
use crate::validate::{validate_phrase_recovery, validate_rotated_object, validate_rotation_wraps};
use crate::*;

pub(crate) async fn list_devices(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> Result<Json<Vec<DevicePublicKeys>>, (StatusCode, Json<ErrorBody>)> {
    let session = require_session(&state, &headers).await?;
    require_read_budget(&state, "devices", &session.account_id).await?;
    let rows = sqlx::query(
        "SELECT id, mldsa_pk, ed25519_pk, xwing_hpke_pk FROM devices
         WHERE account_id = ? AND revoked_at IS NULL ORDER BY created_at ASC",
    )
    .bind(&session.account_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let devices = rows
        .into_iter()
        .filter_map(|row| {
            Some(DevicePublicKeys {
                device_id: Uuid::parse_str(&row.get::<String, _>("id")).ok()?,
                mldsa_pk: row.get("mldsa_pk"),
                ed25519_pk: row.get("ed25519_pk"),
                xwing_hpke_pk: row.get("xwing_hpke_pk"),
            })
        })
        .collect();
    Ok(Json(devices))
}

/// Replaces the collection key, re-wrapping it and re-encrypting every object.
///
/// One endpoint serves every operation that has to invalidate the old key, because
/// they all need the same work done and only a client can do it: revoking a device
/// that already holds the key, changing the recovery phrase, and finishing a
/// recovery — where the phrase that was just used, and anyone who has ever seen it,
/// must stop being able to decrypt.
///
/// Marking a device revoked without this would leave it able to decrypt everything
/// it had ever synced; leaving the key alone on a phrase change would leave an old
/// phrase holder able to do the same.
pub(crate) async fn rotate(
    State(state): State<Shared>,
    AxumPath(collection_id): AxumPath<Uuid>,
    headers: HeaderMap,
    Json(body): Json<RotateRequest>,
) -> Result<Json<RotateResponse>, (StatusCode, Json<ErrorBody>)> {
    let session = require_recent_session(&state, &headers).await?;
    // A rotation rewrites the whole vault, so it is the most expensive request the
    // server serves. A real account revokes a device or changes a phrase now and
    // then; anything faster is a loop or an attack.
    if !state
        .limiter
        .allow_account("rotate", &session.account_id, 5, Duration::from_secs(300))
        .await
    {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    if body
        .revoke_device_id
        .is_some_and(|device| device.to_string() == session.device_id)
    {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "cannot revoke the device performing the rotation",
        ));
    }
    validate_phrase_recovery(&body.phrase_recovery)?;
    if body.kdf_salt.len() != 16 {
        return Err(err(StatusCode::BAD_REQUEST, "invalid kdf salt"));
    }

    // Everything that depends only on the request body is done before the
    // transaction opens, because all of it hashes the whole body: the object
    // digest the transcript covers, and the per-object content digests the rows
    // store. At the byte quota that is hundreds of milliseconds of
    // SHA-256, and under the write lock it would stall every other writer for
    // that long.
    let mut supplied: Vec<String> = Vec::with_capacity(body.objects.len());
    for object in &body.objects {
        validate_rotated_object(object)?;
        // A rotation re-encrypts the live objects, and the `UPDATE` below does
        // not carry `tombstone`, so a rotated object claiming to be a tombstone
        // left `objects` saying the object is live and `object_revisions` saying
        // it was deleted. Devices on the change feed would then drop an object
        // that a snapshot walk still serves, and neither manifest digest covers
        // the other's view, so nothing downstream could catch it.
        if object.tombstone {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "a rotation re-encrypts live objects; a tombstone has no plaintext \
                 to re-encrypt and must be left out",
            ));
        }
        supplied.push(object.id.to_string());
    }
    let content_digests: Vec<Vec<u8>> = body
        .objects
        .iter()
        .map(|object| content_digest(&object.nonce, &object.ciphertext).to_vec())
        .collect();
    let wrap_entries: Vec<WrapDigestEntry<'_>> = body
        .key_wraps
        .iter()
        .map(|wrap| WrapDigestEntry {
            recipient_kind: &wrap.recipient_kind,
            recipient_id: &wrap.recipient_id,
            hpke_enc: &wrap.hpke_enc,
            wrapped_ck: &wrap.wrapped_ck,
            ciphersuite: &wrap.ciphersuite,
        })
        .collect();
    let object_entries: Vec<ObjectDigestEntry<'_>> = body
        .objects
        .iter()
        .map(|object| ObjectDigestEntry {
            id: object.id,
            revision: object.revision,
            nonce: &object.nonce,
            ciphertext: &object.ciphertext,
            padded_size: object.padded_size as u64,
            content_type: &object.content_type,
            tombstone: object.tombstone,
        })
        .collect();
    let mut manifest_digest = [0u8; 32];
    if body.manifest.digest.len() != 32 {
        return Err(err(StatusCode::BAD_REQUEST, "invalid manifest digest"));
    }
    manifest_digest.copy_from_slice(&body.manifest.digest);
    // The salt and phrase record this rotation is about to write into `accounts`
    // are signed too, so a modified request body cannot install recovery material
    // the account holder never produced.
    let recovery_payload = rotation_recovery_payload(
        &body.kdf_salt,
        &body.phrase_recovery.mldsa_pk,
        &body.phrase_recovery.ed25519_pk,
        &body.phrase_recovery.lookup_id,
        &body.phrase_recovery.scheme,
    );
    let transcript = key_rotation_transcript(
        collection_id,
        body.revoke_device_id,
        body.key_epoch,
        &key_wraps_digest(&wrap_entries),
        &rotated_objects_digest(&object_entries),
        &manifest_digest,
        &recovery_payload,
    );

    // Everything this rotation checks against the vault, and everything it then
    // writes, runs in one `BEGIN IMMEDIATE` transaction. Read from the pool first
    // and committed afterwards, as they were, each check described a vault that
    // could already have moved: a write landing in between invalidated the
    // revision run, the live object set and the epoch this request was built
    // against, and the rotation's first write then failed with an unretryable
    // `SQLITE_BUSY_SNAPSHOT` rather than a conflict the client could act on.
    let mut tx = state
        .db
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    let collection =
        sqlx::query("SELECT id, key_epoch FROM collections WHERE id = ? AND account_id = ?")
            .bind(collection_id.to_string())
            .bind(&session.account_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "collection"))?;
    let collection_id_text: String = collection.get("id");
    let current_epoch: i64 = collection.get("key_epoch");
    // Reject replays and concurrent rotations: the epoch must advance by one.
    if body.key_epoch != (current_epoch as u64) + 1 {
        return Err(err(StatusCode::CONFLICT, "stale key epoch"));
    }

    if let Some(device_id) = body.revoke_device_id {
        let target = sqlx::query(
            "SELECT id FROM devices WHERE id = ? AND account_id = ? AND revoked_at IS NULL",
        )
        .bind(device_id.to_string())
        .bind(&session.account_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
        if target.is_none() {
            return Err(err(StatusCode::NOT_FOUND, "device"));
        }
    }

    // Every device that keeps access must get a wrap of the new key.
    let revoked = body
        .revoke_device_id
        .map(|device| device.to_string())
        .unwrap_or_default();
    let remaining: Vec<String> = sqlx::query(
        "SELECT id FROM devices
         WHERE account_id = ? AND revoked_at IS NULL AND id != ?
         ORDER BY created_at ASC",
    )
    .bind(&session.account_id)
    .bind(&revoked)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
    .into_iter()
    .map(|row| row.get::<String, _>("id"))
    .collect();
    if remaining.is_empty() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "cannot revoke the last device",
        ));
    }

    let account = sqlx::query("SELECT username FROM accounts WHERE id = ?")
        .bind(&session.account_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::NOT_FOUND, "account not found"))?;
    let username: String = account.get("username");
    validate_rotation_wraps(&remaining, &username, &body.key_wraps)?;

    // The rotation must cover exactly the live objects: no silent drops, and
    // nothing left behind under the old key.
    let existing: Vec<String> = sqlx::query(
        "SELECT id FROM objects
         WHERE account_id = ? AND collection_id = ? AND tombstone = 0",
    )
    .bind(&session.account_id)
    .bind(&collection_id_text)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
    .into_iter()
    .map(|row| row.get::<String, _>("id"))
    .collect();
    let mut expected_sorted = existing.clone();
    expected_sorted.sort();
    let mut supplied_sorted = supplied.clone();
    supplied_sorted.sort();
    supplied_sorted.dedup();
    if supplied_sorted.len() != supplied.len() || supplied_sorted != expected_sorted {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "rotation must re-encrypt exactly the current objects",
        ));
    }

    // Revisions are chosen by the client so that the manifest can commit to them,
    // and must run consecutively from the collection's next revision.
    let first_revision: i64 =
        sqlx::query_scalar("SELECT next_revision FROM revision_seq WHERE account_id = ?")
            .bind(&session.account_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    let log_floor: i64 =
        sqlx::query_scalar("SELECT MIN(revision) FROM object_revisions WHERE account_id = ?")
            .bind(&session.account_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
            .flatten()
            .unwrap_or(first_revision);
    // A set, not a list: a vault at the tombstone ceiling holds as many of these
    // as it has objects, and a membership scan per id would be quadratic in that.
    let retirable: std::collections::HashSet<String> = sqlx::query(
        "SELECT id FROM objects
         WHERE account_id = ? AND collection_id = ? AND tombstone = 1 AND revision < ?",
    )
    .bind(&session.account_id)
    .bind(&collection_id_text)
    .bind(log_floor)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
    .into_iter()
    .map(|row| row.get::<String, _>("id"))
    .collect();
    let mut dropped: Vec<String> = body
        .drop_tombstones
        .iter()
        .map(|id| id.to_string())
        .collect();
    let before_dedup = dropped.len();
    dropped.sort();
    dropped.dedup();
    if dropped.len() != before_dedup || !dropped.iter().all(|id| retirable.contains(id)) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "a rotation may only retire tombstones below the collection's tombstone floor,              each named once",
        ));
    }
    for (index, object) in body.objects.iter().enumerate() {
        if object.revision != (first_revision as u64) + index as u64 {
            return Err(err(
                StatusCode::CONFLICT,
                "rotation revisions must run consecutively from the next revision",
            ));
        }
    }

    // Bind the whole rotation to the device performing it.
    let signer = sqlx::query(
        "SELECT mldsa_pk, ed25519_pk FROM devices WHERE id = ? AND account_id = ? AND revoked_at IS NULL",
    )
    .bind(&session.device_id)
    .bind(&session.account_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
    .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid token"))?;
    verify(
        &DeviceSigningPublic {
            mldsa_pk: signer.get("mldsa_pk"),
            ed25519_pk: signer.get("ed25519_pk"),
        },
        &transcript,
        &DualSignature {
            mldsa: body.rotation_signature.mldsa.clone(),
            ed25519: body.rotation_signature.ed25519.clone(),
        },
    )
    .map_err(|_| err(StatusCode::BAD_REQUEST, "rotation signature"))?;

    if let Some(device_id) = body.revoke_device_id {
        let updated = sqlx::query(
            "UPDATE devices SET revoked_at = ?
             WHERE id = ? AND account_id = ? AND revoked_at IS NULL",
        )
        .bind(now())
        .bind(device_id.to_string())
        .bind(&session.account_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
        if updated.rows_affected() == 0 {
            return Err(err(StatusCode::NOT_FOUND, "device"));
        }
        sqlx::query("DELETE FROM sessions WHERE account_id = ? AND device_id = ?")
            .bind(&session.account_id)
            .bind(device_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    }

    // Drop every old wrap, including a revoked device's, and install the new
    // ones. Leaving an old wrap behind would defeat the rotation.
    sqlx::query("DELETE FROM key_wraps WHERE collection_id = ?")
        .bind(&collection_id_text)
        .execute(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    for wrap in &body.key_wraps {
        sqlx::query(
            "INSERT INTO key_wraps (collection_id, recipient_kind, recipient_id, hpke_enc, wrapped_ck, ciphersuite)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&collection_id_text)
        .bind(&wrap.recipient_kind)
        .bind(&wrap.recipient_id)
        .bind(&wrap.hpke_enc)
        .bind(&wrap.wrapped_ck)
        .bind(&wrap.ciphersuite)
        .execute(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    }

    sqlx::query(
        "UPDATE accounts
         SET kdf_salt = ?, phrase_mldsa_pk = ?, phrase_ed25519_pk = ?,
             phrase_lookup_id = ?, phrase_scheme = ?
         WHERE id = ?",
    )
    .bind(&body.kdf_salt)
    .bind(&body.phrase_recovery.mldsa_pk)
    .bind(&body.phrase_recovery.ed25519_pk)
    .bind(&body.phrase_recovery.lookup_id)
    .bind(&body.phrase_recovery.scheme)
    .bind(&session.account_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    for id in &dropped {
        sqlx::query("DELETE FROM objects WHERE account_id = ? AND collection_id = ? AND id = ?")
            .bind(&session.account_id)
            .bind(&collection_id_text)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    }

    let mut revision = first_revision;
    for (object, digest) in body.objects.iter().zip(&content_digests) {
        sqlx::query(
            "UPDATE objects
             SET revision = ?, ciphertext = ?, nonce = ?, padded_size = ?, content_type = ?,
                 content_digest = ?
             WHERE account_id = ? AND collection_id = ? AND id = ?",
        )
        .bind(revision)
        .bind(&object.ciphertext)
        .bind(&object.nonce)
        .bind(object.padded_size as i64)
        .bind(&object.content_type)
        .bind(digest)
        .bind(&session.account_id)
        .bind(&collection_id_text)
        .bind(object.id.to_string())
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
        .bind(&collection_id_text)
        .bind(object.id.to_string())
        .bind(i64::from(object.tombstone))
        .bind(&object.ciphertext)
        .bind(&object.nonce)
        .bind(object.padded_size as i64)
        .bind(&object.content_type)
        .bind(digest)
        .bind(now())
        .execute(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
        revision += 1;
    }
    // A rotation re-encrypts exactly the live objects and cannot tombstone one,
    // so the live count cannot change here, but retiring tombstones drops rows
    // and padding can put each object in a different size bucket. All three are
    // re-derived from the rows rather than adjusted, which also heals any drift a
    // past bug left behind. The index covers every column read, so this is one
    // index-only pass.
    let totals: (i64, i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(padded_size), 0), COALESCE(SUM(tombstone), 0)
         FROM objects WHERE account_id = ?",
    )
    .bind(&session.account_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let (object_count, byte_total, tombstone_count) = totals;
    sqlx::query(
        "UPDATE revision_seq
             SET next_revision = ?, object_count = ?, byte_total = ?, tombstone_count = ?
         WHERE account_id = ?",
    )
    .bind(revision)
    .bind(object_count)
    .bind(byte_total)
    .bind(tombstone_count)
    .bind(&session.account_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    // A rotation is exactly what an unfinished recovery owes: a new collection
    // key, a new phrase, and every object re-encrypted. Whatever prompted it, it
    // settles the debt.
    sqlx::query("UPDATE accounts SET recovery_pending = 0 WHERE id = ?")
        .bind(&session.account_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    sqlx::query("UPDATE collections SET key_epoch = ? WHERE id = ?")
        .bind(body.key_epoch as i64)
        .bind(&collection_id_text)
        .execute(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    // A rotation rewrites every live object, so the buckets are rebuilt in one
    // pass rather than one at a time. That pass also re-derives the count, so a
    // rotation repairs the state as well as updating it.
    manifest::rebuild_digest_state(&mut tx, &session.account_id, &collection_id_text).await?;

    manifest::verify_and_store(
        &mut tx,
        manifest::Expected {
            collection_id: &collection_id_text,
            account_id: &session.account_id,
            device_id: &session.device_id,
            key_epoch: body.key_epoch as i64,
            latest_revision: revision.saturating_sub(1),
        },
        &body.manifest,
    )
    .await?;

    roster::verify_and_store(
        &mut tx,
        roster::Expected {
            collection_id: &collection_id_text,
            account_id: &session.account_id,
            signer: roster::Signer::Device(&session.device_id),
            genesis: false,
        },
        &body.roster,
    )
    .await?;

    tx.commit()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    info!(
        revoked = ?body.revoke_device_id,
        epoch = body.key_epoch,
        "collection key rotated"
    );
    Ok(Json(RotateResponse {
        key_epoch: body.key_epoch,
        latest_revision: revision.saturating_sub(1) as u64,
    }))
}
