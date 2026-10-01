//! The signed object manifest.
//!
//! Per-object encryption keeps the server from *reading* a collection, but on its
//! own it does not stop the server from lying about the collection's shape: it can
//! withhold an object, serve the ciphertext of an older revision under the current
//! revision number, or drop a row entirely, and a client has no way to tell.
//!
//! A manifest closes that. Every write carries a device signature over the state
//! of the collection *after* the write — each object's id, revision, tombstone flag
//! and a digest of its ciphertext. Before storing it the server recomputes every
//! one of those values from its own tables and rejects anything that does not
//! match, so a stored manifest is a device-signed statement of the truth rather
//! than of whatever the client claimed. A reader re-derives the digest from what it
//! was served and compares.
//!
//! What this does not give: a server can still serve the *latest* manifest it holds
//! for ever, freezing a client at a real past state. Detecting that needs freshness
//! from somewhere other than the server.

use axum::http::StatusCode;
use axum::Json;
use sqlx::{Row, Sqlite, Transaction};
use uuid::Uuid;

use sealbook_crypto::{
    manifest_digest, manifest_transcript, verify, DeviceSigningPublic, DualSignature,
    ManifestDigestEntry,
};
use sealbook_protocol::{ErrorBody, ManifestBody, ManifestEntry};

use crate::err;

/// What the server expects the incoming manifest to describe.
pub(crate) struct Expected<'a> {
    pub(crate) collection_id: &'a str,
    pub(crate) account_id: &'a str,
    /// The device whose session is making the request. The manifest must be
    /// signed by it, so a manifest cannot be attributed to another device.
    pub(crate) device_id: &'a str,
    pub(crate) key_epoch: i64,
    /// The highest revision assigned by this write.
    pub(crate) latest_revision: i64,
}

/// The manifest sequence a collection is currently at, or 0 if it has none.
pub(crate) async fn current_seq(
    tx: &mut Transaction<'_, Sqlite>,
    collection_id: &str,
) -> Result<i64, (StatusCode, Json<ErrorBody>)> {
    sqlx::query_scalar::<_, i64>("SELECT manifest_seq FROM manifests WHERE collection_id = ?")
        .bind(collection_id)
        .fetch_optional(&mut **tx)
        .await
        .map(|seq| seq.unwrap_or(0))
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))
}

/// Reads the collection's contents as the manifest commits to them.
pub(crate) async fn entries(
    tx: &mut Transaction<'_, Sqlite>,
    account_id: &str,
    collection_id: &str,
) -> Result<Vec<ManifestEntry>, (StatusCode, Json<ErrorBody>)> {
    let rows = sqlx::query(
        "SELECT id, revision, tombstone, content_digest FROM objects
         WHERE account_id = ? AND collection_id = ?",
    )
    .bind(account_id)
    .bind(collection_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let id: String = row.get("id");
        out.push(ManifestEntry {
            id: Uuid::parse_str(&id).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?,
            revision: row.get::<i64, _>("revision") as u64,
            tombstone: row.get::<i64, _>("tombstone") != 0,
            content_digest: row.get("content_digest"),
        });
    }
    Ok(out)
}

pub(crate) fn digest_of(entries: &[ManifestEntry]) -> Result<[u8; 32], ()> {
    let mut digest_entries = Vec::with_capacity(entries.len());
    for entry in entries {
        let mut content_digest = [0u8; 32];
        if entry.content_digest.len() != 32 {
            return Err(());
        }
        content_digest.copy_from_slice(&entry.content_digest);
        digest_entries.push(ManifestDigestEntry {
            id: entry.id,
            revision: entry.revision,
            tombstone: entry.tombstone,
            content_digest,
        });
    }
    Ok(manifest_digest(&digest_entries))
}

/// Checks a submitted manifest against the server's own view and stores it.
///
/// Called inside the same transaction as the write it describes, after that write
/// has been applied, so the entries read here are the post-write state.
pub(crate) async fn verify_and_store(
    tx: &mut Transaction<'_, Sqlite>,
    expected: Expected<'_>,
    body: &ManifestBody,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    if body.device_id.to_string() != expected.device_id {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "manifest must be signed by the device making the request",
        ));
    }
    let seq = current_seq(tx, expected.collection_id).await?;
    if body.manifest_seq != (seq as u64) + 1 {
        // Concurrent writers land here: refetch the manifest and retry.
        return Err(err(StatusCode::CONFLICT, "stale manifest sequence"));
    }
    if body.key_epoch != expected.key_epoch as u64 {
        return Err(err(StatusCode::CONFLICT, "stale manifest key epoch"));
    }
    if body.latest_revision != expected.latest_revision as u64 {
        return Err(err(StatusCode::BAD_REQUEST, "manifest revision mismatch"));
    }

    let entries = entries(tx, expected.account_id, expected.collection_id).await?;
    if body.object_count != entries.len() as u64 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "manifest object count mismatch",
        ));
    }
    let digest = digest_of(&entries).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    if body.digest != digest {
        // The client signed something other than what the server now holds. Both
        // sides having to agree is the point: it means a stored manifest can be
        // handed to any other device as a true description of the collection.
        return Err(err(StatusCode::BAD_REQUEST, "manifest digest mismatch"));
    }

    let device = sqlx::query(
        "SELECT mldsa_pk, ed25519_pk FROM devices
         WHERE id = ? AND account_id = ? AND revoked_at IS NULL",
    )
    .bind(expected.device_id)
    .bind(expected.account_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
    .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid token"))?;
    let collection_uuid = Uuid::parse_str(expected.collection_id)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let transcript = manifest_transcript(
        collection_uuid,
        body.manifest_seq,
        body.key_epoch,
        body.latest_revision,
        body.object_count,
        &digest,
    );
    verify(
        &DeviceSigningPublic {
            mldsa_pk: device.get("mldsa_pk"),
            ed25519_pk: device.get("ed25519_pk"),
        },
        &transcript,
        &DualSignature {
            mldsa: body.signature.mldsa.clone(),
            ed25519: body.signature.ed25519.clone(),
        },
    )
    .map_err(|_| err(StatusCode::BAD_REQUEST, "manifest signature"))?;

    sqlx::query(
        "INSERT INTO manifests
         (collection_id, manifest_seq, key_epoch, latest_revision, object_count, digest,
          device_id, mldsa_sig, ed25519_sig, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(collection_id) DO UPDATE SET
            manifest_seq = excluded.manifest_seq,
            key_epoch = excluded.key_epoch,
            latest_revision = excluded.latest_revision,
            object_count = excluded.object_count,
            digest = excluded.digest,
            device_id = excluded.device_id,
            mldsa_sig = excluded.mldsa_sig,
            ed25519_sig = excluded.ed25519_sig,
            updated_at = excluded.updated_at",
    )
    .bind(expected.collection_id)
    .bind(body.manifest_seq as i64)
    .bind(body.key_epoch as i64)
    .bind(body.latest_revision as i64)
    .bind(body.object_count as i64)
    .bind(digest.to_vec())
    .bind(expected.device_id)
    .bind(&body.signature.mldsa)
    .bind(&body.signature.ed25519)
    .bind(crate::now())
    .execute(&mut **tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(())
}

/// The collection's stored manifest, for serving to clients.
///
/// Generic over the executor so that a caller which has already read the entries
/// inside a transaction can read the manifest from that same snapshot. A manifest
/// loaded from a later one describes a collection the caller is not about to
/// return, and the digest comparison it exists for then fails.
pub(crate) async fn load<'e, E>(
    db: E,
    collection_id: &str,
) -> Result<Option<ManifestBody>, (StatusCode, Json<ErrorBody>)>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let row = sqlx::query(
        "SELECT manifest_seq, key_epoch, latest_revision, object_count, digest, device_id,
                mldsa_sig, ed25519_sig
         FROM manifests WHERE collection_id = ?",
    )
    .bind(collection_id)
    .fetch_optional(db)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let device_id: String = row.get("device_id");
    Ok(Some(ManifestBody {
        manifest_seq: row.get::<i64, _>("manifest_seq") as u64,
        key_epoch: row.get::<i64, _>("key_epoch") as u64,
        latest_revision: row.get::<i64, _>("latest_revision") as u64,
        object_count: row.get::<i64, _>("object_count") as u64,
        digest: row.get("digest"),
        device_id: Uuid::parse_str(&device_id)
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?,
        signature: sealbook_protocol::DualSignatureBody {
            mldsa: row.get("mldsa_sig"),
            ed25519: row.get("ed25519_sig"),
        },
    }))
}
