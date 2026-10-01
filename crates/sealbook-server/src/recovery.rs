//! Recovering an account from its recovery phrase onto a new device.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use sqlx::Row;
use uuid::Uuid;

use sealbook_crypto::{
    ct_eq, generate_login_challenge, phrase_recovery_transcript, verify_phrase_recovery,
    DeviceSigningPublic, DualSignature, PHRASE_LOOKUP_ID_LEN,
};
use sealbook_protocol::{
    valid_username, ErrorBody, KeyWrapBody, RecoverFinishRequest, RecoverFinishResponse,
    RecoverStartRequest, RecoverStartResponse,
};

use crate::pairing::{insert_device, verify_enroll};
use crate::*;

pub(crate) async fn recover_start(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RecoverStartRequest>,
) -> Result<Json<RecoverStartResponse>, (StatusCode, Json<ErrorBody>)> {
    if !valid_username(&body.username) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid username"));
    }
    if !state
        .limiter
        .allow_endpoint(
            "recover-start",
            &body.username,
            Some(state.trusted_proxies.client_ip(addr.ip(), &headers)),
        )
        .await
    {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    if body.lookup_id.len() != PHRASE_LOOKUP_ID_LEN {
        return Err(err(StatusCode::BAD_REQUEST, "invalid phrase lookup id"));
    }
    let row = sqlx::query(
        "SELECT c.id, w.hpke_enc, w.wrapped_ck, w.ciphersuite
         FROM accounts a
         JOIN collections c ON c.account_id = a.id
         JOIN key_wraps w ON w.collection_id = c.id AND w.recipient_kind = 'phrase'
         WHERE a.username = ? AND a.phrase_lookup_id = ?",
    )
    .bind(&body.username)
    .bind(&body.lookup_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let wrap = row
        .map(|r| KeyWrapBody {
            recipient_kind: "phrase".into(),
            recipient_id: body.username.clone(),
            hpke_enc: r.get("hpke_enc"),
            wrapped_ck: r.get("wrapped_ck"),
            ciphersuite: r.get("ciphersuite"),
        })
        .unwrap_or_else(|| state.dummy_phrase_wrap.clone());
    let recovery_id = Uuid::new_v4();
    let challenge = generate_login_challenge();
    let mut pending = state.pending_recoveries.lock().await;
    admit(&mut pending, Duration::from_secs(120), |entry| {
        entry.created
    });
    pending.insert(
        recovery_id,
        PendingRecovery {
            username: body.username,
            challenge,
            created: Instant::now(),
        },
    );
    Ok(Json(RecoverStartResponse {
        wrap,
        recovery_id,
        challenge: challenge.to_vec(),
    }))
}

pub(crate) async fn recover_finish(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RecoverFinishRequest>,
) -> Result<Json<RecoverFinishResponse>, (StatusCode, Json<ErrorBody>)> {
    if !valid_username(&body.username) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid username"));
    }
    if !state
        .limiter
        .allow_endpoint(
            "recover-finish",
            &body.username,
            Some(state.trusted_proxies.client_ip(addr.ip(), &headers)),
        )
        .await
    {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    let pending = state
        .pending_recoveries
        .lock()
        .await
        .remove(&body.recovery_id)
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid recovery"))?;
    if pending.created.elapsed() > Duration::from_secs(120)
        || pending.username != body.username
        || body.challenge.len() != 32
        || !ct_eq(&body.challenge, &pending.challenge)
    {
        return Err(err(StatusCode::UNAUTHORIZED, "invalid recovery"));
    }
    verify_enroll(&body.device, &body.enrollment_signature)?;
    let account = sqlx::query(
        "SELECT id, phrase_mldsa_pk, phrase_ed25519_pk FROM accounts WHERE username = ?",
    )
    .bind(&body.username)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    // Verify against a dummy key for unknown accounts so the work done, and the
    // error returned, are the same either way.
    let recovery_pk = account
        .as_ref()
        .and_then(|row| {
            let mldsa_pk: Option<Vec<u8>> = row.get("phrase_mldsa_pk");
            let ed25519_pk: Option<Vec<u8>> = row.get("phrase_ed25519_pk");
            Some(DeviceSigningPublic {
                mldsa_pk: mldsa_pk?,
                ed25519_pk: ed25519_pk?,
            })
        })
        .unwrap_or_else(|| state.dummy_phrase_recovery_pk.clone());
    let transcript = phrase_recovery_transcript(
        &body.username,
        body.recovery_id,
        &body.challenge,
        body.device.device_id,
        &body.device.mldsa_pk,
        &body.device.ed25519_pk,
        &body.device.xwing_hpke_pk,
    );
    let proof = DualSignature {
        mldsa: body.phrase_proof.mldsa.clone(),
        ed25519: body.phrase_proof.ed25519.clone(),
    };
    let proof_ok = verify_phrase_recovery(&recovery_pk, &transcript, &proof).is_ok();
    let Some(account) = account else {
        return Err(err(StatusCode::UNAUTHORIZED, "invalid credentials"));
    };
    if !proof_ok {
        return Err(err(StatusCode::UNAUTHORIZED, "invalid credentials"));
    }
    let account_id: String = account.get("id");
    let collection =
        sqlx::query("SELECT id FROM collections WHERE account_id = ?")
            .bind(&account_id)
            .fetch_one(&state.db)
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let collection_id: String = collection.get("id");
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    insert_device(
        &mut tx,
        &account_id,
        &collection_id,
        &body.device,
        &body.wrap,
    )
    .await?;
    sqlx::query("DELETE FROM sessions WHERE account_id = ?")
        .bind(&account_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    tx.commit()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(Json(RecoverFinishResponse {
        account_id: Uuid::parse_str(&account_id).unwrap(),
        collection_id: Uuid::parse_str(&collection_id).unwrap(),
    }))
}
