//! Adding a second device: the pairing handshake and device enrolment.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use sqlx::{Row, Sqlite};
use uuid::Uuid;

use sealbook_crypto::{
    enrollment_transcript, generate_pair_code, pair_confirmation, pair_grant_transcript,
    validate_device_hpke_public, verify, DeviceHpkePublic, DeviceSigningPublic, DualSignature,
    HPKE_AEAD_TAG_LEN, XWING_CIPHERSUITE, XWING_ENCAPSULATED_KEY_LEN,
};
use sealbook_protocol::{
    valid_username, DevicePublicKeys, DualSignatureBody, ErrorBody, KeyWrapBody,
    PairApproveRequest, PairJoinRequest, PairJoinResponse, PairStatusResponse,
};

use crate::session::require_session;
use crate::*;

pub(crate) fn pair_id_for_key(key: &str, pending: &HashMap<Uuid, PendingPair>) -> Option<Uuid> {
    if let Ok(pair_id) = Uuid::parse_str(key.trim()) {
        return pending.contains_key(&pair_id).then_some(pair_id);
    }
    let normalized = key.split_whitespace().collect::<Vec<_>>().join(" ");
    pending
        .iter()
        .find(|(_, pair)| pair.pair_code == normalized)
        .map(|(pair_id, _)| *pair_id)
}

/// The fields of a `PendingPair` that an approval needs once the pairing lock has
/// been released, so the code below reads the same as it did under the lock.
struct PairView<'a> {
    device: &'a DevicePublicKeys,
    enrollment_signature: &'a DualSignatureBody,
    username: &'a str,
    confirm: &'a str,
}

pub(crate) fn verify_enroll(
    device: &DevicePublicKeys,
    sig: &DualSignatureBody,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    validate_device_hpke_public(&DeviceHpkePublic(device.xwing_hpke_pk.clone()))
        .map_err(|_| err(StatusCode::BAD_REQUEST, "xwing public key"))?;
    let enroll = enrollment_transcript(
        device.device_id,
        &device.mldsa_pk,
        &device.ed25519_pk,
        &device.xwing_hpke_pk,
    );
    let public = DeviceSigningPublic {
        mldsa_pk: device.mldsa_pk.clone(),
        ed25519_pk: device.ed25519_pk.clone(),
    };
    let signature = DualSignature {
        mldsa: sig.mldsa.clone(),
        ed25519: sig.ed25519.clone(),
    };
    verify(&public, &enroll, &signature)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "enrollment signature"))
}

/// Most devices one account may have enrolled at once.
///
/// Every enrolled device gets a wrap of the collection key in every rotation, and
/// a rotation carries the whole vault in one request, so an unbounded device list
/// makes rotation — and therefore revocation — progressively more expensive. It is
/// also the shape an attacker who has a session token would use to quietly keep a
/// foothold. Revoking a device frees its slot.
const MAX_DEVICES_PER_ACCOUNT: i64 = 16;

pub(crate) async fn insert_device(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    account_id: &str,
    collection_id: &str,
    device: &DevicePublicKeys,
    wrap: &KeyWrapBody,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    // Counted inside the caller's transaction, so two simultaneous enrolments
    // cannot both see room for the last slot.
    let enrolled: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM devices WHERE account_id = ? AND revoked_at IS NULL",
    )
    .bind(account_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    if enrolled >= MAX_DEVICES_PER_ACCOUNT {
        return Err(err(
            StatusCode::CONFLICT,
            "this account already has the maximum number of devices; revoke one first",
        ));
    }
    if wrap.recipient_kind != "device"
        || wrap.recipient_id != device.device_id.to_string()
        || wrap.ciphersuite != XWING_CIPHERSUITE
        || wrap.hpke_enc.len() != XWING_ENCAPSULATED_KEY_LEN
        || wrap.wrapped_ck.len() != 32 + HPKE_AEAD_TAG_LEN
    {
        return Err(err(StatusCode::BAD_REQUEST, "invalid key wrap"));
    }
    sqlx::query(
        "INSERT INTO devices (id, account_id, mldsa_pk, ed25519_pk, xwing_hpke_pk, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(device.device_id.to_string())
    .bind(account_id)
    .bind(&device.mldsa_pk)
    .bind(&device.ed25519_pk)
    .bind(&device.xwing_hpke_pk)
    .bind(now())
    .execute(&mut **tx)
    .await
    .map_err(|_| err(StatusCode::CONFLICT, "device exists"))?;
    sqlx::query(
        "INSERT INTO key_wraps (collection_id, recipient_kind, recipient_id, hpke_enc, wrapped_ck, ciphersuite)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(collection_id)
    .bind(&wrap.recipient_kind)
    .bind(&wrap.recipient_id)
    .bind(&wrap.hpke_enc)
    .bind(&wrap.wrapped_ck)
    .bind(&wrap.ciphersuite)
    .execute(&mut **tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(())
}

pub(crate) async fn pair_join(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PairJoinRequest>,
) -> Result<Json<PairJoinResponse>, (StatusCode, Json<ErrorBody>)> {
    if !valid_username(&body.username) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid username"));
    }
    if !state
        .limiter
        .allow_endpoint(
            "pair",
            &body.username,
            Some(state.trusted_proxies.client_ip(addr.ip(), &headers)),
        )
        .await
    {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    verify_enroll(&body.device, &body.enrollment_signature)?;
    let account = sqlx::query("SELECT id FROM accounts WHERE username = ?")
        .bind(&body.username)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let pair_id = Uuid::new_v4();
    let pair_code = generate_pair_code();
    let confirm = pair_confirmation(
        pair_id,
        body.device.device_id,
        &body.device.mldsa_pk,
        &body.device.ed25519_pk,
        &body.device.xwing_hpke_pk,
    );
    let mut pending = state.pending_pairs.lock().await;
    admit(&mut pending, Duration::from_secs(180), |entry| {
        entry.created
    });
    pending.insert(
        pair_id,
        PendingPair {
            username: body.username,
            account_id: account.map(|r| r.get("id")),
            device: body.device,
            enrollment_signature: body.enrollment_signature,
            confirm: confirm.clone(),
            pair_code: pair_code.clone(),
            created: Instant::now(),
            approved: false,
        },
    );
    Ok(Json(PairJoinResponse {
        pair_id,
        pair_code,
        confirm,
    }))
}

pub(crate) async fn pair_status(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    AxumPath(pair_key): AxumPath<String>,
    headers: HeaderMap,
) -> Result<Json<PairStatusResponse>, (StatusCode, Json<ErrorBody>)> {
    // Unauthenticated, and it takes the pairing lock to scan every pending pair,
    // so it was the one endpoint anybody could hammer for free. A joining device
    // polls this every second or two while it waits for approval, so the bound is
    // per address and generous rather than tight.
    if !state
        .limiter
        .allow(
            &format!(
                "ip:pair-status:{}",
                state.trusted_proxies.client_ip(addr.ip(), &headers)
            ),
            120,
            Duration::from_secs(60),
        )
        .await
    {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    // Resolved before the pairing lock is taken, not under it. A joining device
    // polls this every second or two, so a database round trip held under the one
    // lock every pairing request needs made each poller wait on every other.
    let caller = require_session(&state, &headers).await.ok();
    let mut pending = state.pending_pairs.lock().await;
    pending.retain(|_, p| p.created.elapsed() < Duration::from_secs(180));
    let pair_id = pair_id_for_key(&pair_key, &pending)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "expired"))?;
    let pair = pending
        .get(&pair_id)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "expired"))?;
    let status = if pair.approved { "ready" } else { "pending" };
    if let Some(session) = caller {
        if pair.account_id.as_deref() == Some(session.account_id.as_str()) {
            return Ok(Json(PairStatusResponse {
                pair_id,
                status: status.into(),
                confirm: pair.confirm.clone(),
                username: Some(pair.username.clone()),
                device: Some(pair.device.clone()),
            }));
        }
    }
    Ok(Json(PairStatusResponse {
        pair_id,
        status: status.into(),
        confirm: pair.confirm.clone(),
        username: None,
        device: None,
    }))
}

pub(crate) async fn pair_approve(
    State(state): State<Shared>,
    AxumPath(pair_key): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<PairApproveRequest>,
) -> Result<Json<PairStatusResponse>, (StatusCode, Json<ErrorBody>)> {
    let session = require_session(&state, &headers).await?;
    // The pairing lock is taken twice, for as long as each of two in-memory
    // lookups needs, and is not held across the dual signature verifications or
    // the enrolling transaction below. Held across those, as it was, one approval
    // stalled every `pair_status` poll on the server.
    let (pair_id, pair_device, pair_enrollment_signature, pair_username, pair_confirm) = {
        let mut pending = state.pending_pairs.lock().await;
        pending.retain(|_, p| p.created.elapsed() < Duration::from_secs(180));
        let pair_id = pair_id_for_key(&pair_key, &pending)
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "expired"))?;
        let pair = pending
            .get(&pair_id)
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "expired"))?;
        if pair.account_id.as_deref() != Some(session.account_id.as_str()) {
            return Err(err(StatusCode::NOT_FOUND, "expired"));
        }
        let expected_confirm = pair_confirmation(
            pair_id,
            pair.device.device_id,
            &pair.device.mldsa_pk,
            &pair.device.ed25519_pk,
            &pair.device.xwing_hpke_pk,
        );
        if pair.confirm != expected_confirm {
            return Err(err(StatusCode::BAD_REQUEST, "pair confirmation"));
        }
        if body.confirmation.trim() != expected_confirm {
            return Err(err(StatusCode::BAD_REQUEST, "pair confirmation"));
        }
        if pair.approved {
            return Ok(Json(PairStatusResponse {
                pair_id,
                status: "ready".into(),
                confirm: pair.confirm.clone(),
                username: Some(pair.username.clone()),
                device: Some(pair.device.clone()),
            }));
        }
        (
            pair_id,
            pair.device.clone(),
            pair.enrollment_signature.clone(),
            pair.username.clone(),
            pair.confirm.clone(),
        )
    };
    let pair = PairView {
        device: &pair_device,
        enrollment_signature: &pair_enrollment_signature,
        username: &pair_username,
        confirm: &pair_confirm,
    };
    verify_enroll(pair.device, pair.enrollment_signature)?;
    let approver = sqlx::query(
        "SELECT mldsa_pk, ed25519_pk FROM devices WHERE id = ? AND account_id = ? AND revoked_at IS NULL",
    )
    .bind(&session.device_id)
    .bind(&session.account_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
    .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid token"))?;
    let grant_t = pair_grant_transcript(
        pair_id,
        Uuid::parse_str(&session.device_id).unwrap(),
        pair.device.device_id,
        &pair.device.mldsa_pk,
        &pair.device.ed25519_pk,
        &pair.device.xwing_hpke_pk,
        pair.confirm,
    );
    let public = DeviceSigningPublic {
        mldsa_pk: approver.get("mldsa_pk"),
        ed25519_pk: approver.get("ed25519_pk"),
    };
    let grant = DualSignature {
        mldsa: body.grant.mldsa.clone(),
        ed25519: body.grant.ed25519.clone(),
    };
    verify(&public, &grant_t, &grant)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "grant signature"))?;

    let collection = sqlx::query("SELECT id FROM collections WHERE account_id = ?")
        .bind(&session.account_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let collection_id: String = collection.get("id");
    let mut tx = state
        .db
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    insert_device(
        &mut tx,
        &session.account_id,
        &collection_id,
        pair.device,
        &body.wrap,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    // Re-acquired to record the approval. The entry can have expired while the
    // enrolment ran; the device is enrolled either way, and the joining device
    // learns that from its next poll finding nothing rather than from a stale
    // "pending".
    if let Some(entry) = state.pending_pairs.lock().await.get_mut(&pair_id) {
        entry.approved = true;
    }
    Ok(Json(PairStatusResponse {
        pair_id,
        status: "ready".into(),
        confirm: pair.confirm.to_string(),
        username: Some(pair.username.to_string()),
        device: Some(pair.device.clone()),
    }))
}
