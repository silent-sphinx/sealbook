//! Account-level changes: username, password, recovery phrase, and deletion.

use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use sqlx::Row;
use uuid::Uuid;

use sealbook_crypto::opaque::{server_register_finish, server_register_start};
use sealbook_crypto::{
    account_op_transcript, ct_eq, delete_account_payload, generate_login_challenge,
    is_supported_recovery_ciphersuite, password_change_payload, username_change_payload, verify,
    DeviceSigningPublic, DualSignature, HPKE_AEAD_TAG_LEN,
};
use sealbook_protocol::{
    valid_username, AccountChallengeResponse, ChangePasswordRequest, ChangePasswordStartRequest,
    ChangePasswordStartResponse, ChangeUsernameRequest, DeleteAccountRequest, DualSignatureBody,
    ErrorBody, SimpleStatusResponse,
};

use crate::session::{require_recent_session, Session};
use crate::*;

/// Issues a nonce for an account mutation.
///
/// Account changes are authorised by a device signature over a transcript that
/// includes this challenge. A bearer token on its own is no longer enough to
/// rename the account, replace its password verifier, or delete it — which it was,
/// for any token less than five minutes old.
pub(crate) async fn account_challenge(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> Result<Json<AccountChallengeResponse>, (StatusCode, Json<ErrorBody>)> {
    let session = require_recent_session(&state, &headers).await?;
    // Every account mutation starts here, so metering this one endpoint bounds all
    // of them. Renaming, re-keying or deleting an account is a deliberate act; a
    // token making a dozen attempts a minute is not one.
    if !state
        .limiter
        .allow_account(
            "account-op",
            &session.account_id,
            10,
            Duration::from_secs(300),
        )
        .await
    {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    let challenge = generate_login_challenge();
    let challenge_id = Uuid::new_v4();
    let mut pending = state.pending_account_ops.lock().await;
    admit(&mut pending, Duration::from_secs(120), |entry| {
        entry.created
    });
    pending.insert(
        challenge_id,
        PendingAccountOp {
            account_id: session.account_id,
            device_id: session.device_id,
            challenge,
            created: Instant::now(),
        },
    );
    Ok(Json(AccountChallengeResponse {
        challenge_id,
        challenge: challenge.to_vec(),
    }))
}

/// Consumes an account-operation challenge and checks the device signature over it.
///
/// Single use: the challenge is removed whether or not verification succeeds, so a
/// failed attempt cannot be retried against the same nonce.
async fn authorise_account_op(
    state: &AppState,
    session: &Session,
    op: &str,
    challenge_id: Uuid,
    challenge: &[u8],
    payload: &[u8; 32],
    signature: &DualSignatureBody,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let pending = state
        .pending_account_ops
        .lock()
        .await
        .remove(&challenge_id)
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid account challenge"))?;
    if pending.created.elapsed() > Duration::from_secs(120)
        || pending.account_id != session.account_id
        || pending.device_id != session.device_id
        || challenge.len() != 32
        || !ct_eq(challenge, &pending.challenge)
    {
        return Err(err(StatusCode::UNAUTHORIZED, "invalid account challenge"));
    }
    verify_device_signature(
        state,
        session,
        op,
        challenge_id,
        challenge,
        payload,
        signature,
    )
    .await
}

/// Verifies that the session's device signed this operation.
async fn verify_device_signature(
    state: &AppState,
    session: &Session,
    op: &str,
    challenge_id: Uuid,
    challenge: &[u8],
    payload: &[u8; 32],
    signature: &DualSignatureBody,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let device = sqlx::query(
        "SELECT mldsa_pk, ed25519_pk FROM devices
         WHERE id = ? AND account_id = ? AND revoked_at IS NULL",
    )
    .bind(&session.device_id)
    .bind(&session.account_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
    .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid token"))?;
    let device_uuid = Uuid::parse_str(&session.device_id)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let transcript = account_op_transcript(
        op,
        challenge_id,
        challenge,
        &session.account_id,
        device_uuid,
        payload,
    );
    verify(
        &DeviceSigningPublic {
            mldsa_pk: device.get("mldsa_pk"),
            ed25519_pk: device.get("ed25519_pk"),
        },
        &transcript,
        &DualSignature {
            mldsa: signature.mldsa.clone(),
            ed25519: signature.ed25519.clone(),
        },
    )
    .map_err(|_| err(StatusCode::UNAUTHORIZED, "invalid operation signature"))
}

pub(crate) async fn change_username(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<ChangeUsernameRequest>,
) -> Result<Json<SimpleStatusResponse>, (StatusCode, Json<ErrorBody>)> {
    let session = require_recent_session(&state, &headers).await?;
    if !valid_username(&body.new_username) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid username"));
    }
    authorise_account_op(
        &state,
        &session,
        "username",
        body.challenge_id,
        &body.challenge,
        &username_change_payload(&body.new_username, &body.upload),
        &body.signature,
    )
    .await?;
    let record = server_register_finish(&body.upload)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "opaque finish"))?;

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    sqlx::query("UPDATE accounts SET username = ?, opaque_record = ? WHERE id = ?")
        .bind(&body.new_username)
        .bind(&record)
        .bind(&session.account_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(db_err) = &e {
                if db_err.is_unique_violation() {
                    return err(StatusCode::CONFLICT, "username taken");
                }
            }
            err(StatusCode::INTERNAL_SERVER_ERROR, "db")
        })?;

    sqlx::query(
        "UPDATE key_wraps SET recipient_id = ? 
         WHERE recipient_kind IN ('phrase', 'recovery') 
           AND collection_id IN (SELECT id FROM collections WHERE account_id = ?)",
    )
    .bind(&body.new_username)
    .bind(&session.account_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    tx.commit()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    sqlx::query("DELETE FROM sessions WHERE account_id = ?")
        .bind(&session.account_id)
        .execute(&state.db)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(Json(SimpleStatusResponse {
        status: "ok".into(),
    }))
}

pub(crate) async fn change_password_start(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<ChangePasswordStartRequest>,
) -> Result<Json<ChangePasswordStartResponse>, (StatusCode, Json<ErrorBody>)> {
    let session = require_recent_session(&state, &headers).await?;
    // Carries its own challenge rather than going through `account_challenge`, so
    // it needs its own bound. An OPAQUE registration start is real server work.
    if !state
        .limiter
        .allow_account(
            "password-change",
            &session.account_id,
            10,
            Duration::from_secs(300),
        )
        .await
    {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    let account = sqlx::query("SELECT username FROM accounts WHERE id = ?")
        .bind(&session.account_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| err(StatusCode::NOT_FOUND, "account not found"))?;
    let username: String = account.get("username");
    let response = server_register_start(&state.opaque, &body.request, username.as_bytes())
        .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    let password_change_id = Uuid::new_v4();
    // The transaction doubles as the account-operation challenge, so changing a
    // password stays two round trips rather than three.
    let challenge = generate_login_challenge();
    let mut pending = state.pending_password_changes.lock().await;
    admit(&mut pending, Duration::from_secs(300), |entry| {
        entry.created
    });
    pending.insert(
        password_change_id,
        PendingPasswordChange {
            account_id: session.account_id,
            device_id: session.device_id,
            challenge,
            created: Instant::now(),
        },
    );
    Ok(Json(ChangePasswordStartResponse {
        password_change_id,
        response,
        challenge: challenge.to_vec(),
    }))
}

pub(crate) async fn change_password(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<Json<SimpleStatusResponse>, (StatusCode, Json<ErrorBody>)> {
    let session = require_recent_session(&state, &headers).await?;
    let pending = state
        .pending_password_changes
        .lock()
        .await
        .remove(&body.password_change_id)
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid password change"))?;
    if pending.created.elapsed() > Duration::from_secs(300)
        || pending.account_id != session.account_id
        || pending.device_id != session.device_id
        || body.challenge.len() != 32
        || !ct_eq(&body.challenge, &pending.challenge)
    {
        return Err(err(StatusCode::UNAUTHORIZED, "invalid password change"));
    }
    // The signature covers the replacement recovery wrap as well as the new
    // verifier, so a caller cannot substitute key material the account holder
    // never produced — which is how a stolen token could destroy password-based
    // recovery while looking like a legitimate password change.
    verify_device_signature(
        &state,
        &session,
        "password",
        body.password_change_id,
        &body.challenge,
        &password_change_payload(
            &body.upload,
            &body.kdf_salt,
            &body.recovery_nonce,
            &body.recovery_wrapped_ck,
            &body.recovery_ciphersuite,
        ),
        &body.signature,
    )
    .await?;
    if body.kdf_salt.len() != 16 {
        return Err(err(StatusCode::BAD_REQUEST, "invalid kdf salt"));
    }
    if !is_supported_recovery_ciphersuite(&body.recovery_ciphersuite)
        || body.recovery_nonce.len() != 24
        || body.recovery_wrapped_ck.len() != 32 + HPKE_AEAD_TAG_LEN
    {
        return Err(err(StatusCode::BAD_REQUEST, "invalid ciphersuite"));
    }
    let record = server_register_finish(&body.upload)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "opaque finish"))?;

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    let account = sqlx::query("SELECT username FROM accounts WHERE id = ?")
        .bind(&session.account_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::NOT_FOUND, "account not found"))?;
    let username: String = account.get("username");

    let collection =
        sqlx::query("SELECT id FROM collections WHERE account_id = ? AND kind = 'contacts'")
            .bind(&session.account_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "collection not found"))?;
    let collection_id: String = collection.get("id");

    sqlx::query("UPDATE accounts SET opaque_record = ?, kdf_salt = ? WHERE id = ?")
        .bind(&record)
        .bind(&body.kdf_salt)
        .bind(&session.account_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    sqlx::query("DELETE FROM key_wraps WHERE collection_id = ? AND recipient_kind = 'recovery'")
        .bind(&collection_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    sqlx::query(
        "INSERT INTO key_wraps (collection_id, recipient_kind, recipient_id, hpke_enc, wrapped_ck, ciphersuite)
         VALUES (?, 'recovery', ?, ?, ?, ?)",
    )
    .bind(&collection_id)
    .bind(&username)
    .bind(&body.recovery_nonce)
    .bind(&body.recovery_wrapped_ck)
    .bind(&body.recovery_ciphersuite)
    .execute(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    sqlx::query("DELETE FROM sessions WHERE account_id = ?")
        .bind(&session.account_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    tx.commit()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    Ok(Json(SimpleStatusResponse {
        status: "ok".into(),
    }))
}

pub(crate) async fn delete_account(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<DeleteAccountRequest>,
) -> Result<Json<SimpleStatusResponse>, (StatusCode, Json<ErrorBody>)> {
    let session = require_recent_session(&state, &headers).await?;
    authorise_account_op(
        &state,
        &session,
        "delete",
        body.challenge_id,
        &body.challenge,
        &delete_account_payload(),
        &body.signature,
    )
    .await?;

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    // Keyed on the account alone. Selecting through `objects` left behind any
    // revision whose object row had gone, which is exactly what deleting an
    // account must not do.
    sqlx::query("DELETE FROM object_revisions WHERE account_id = ?")
        .bind(&session.account_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    sqlx::query(
        "DELETE FROM objects WHERE collection_id IN (
             SELECT id FROM collections WHERE account_id = ?
         )",
    )
    .bind(&session.account_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    sqlx::query(
        "DELETE FROM key_wraps WHERE collection_id IN (
             SELECT id FROM collections WHERE account_id = ?
         )",
    )
    .bind(&session.account_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    sqlx::query("DELETE FROM revision_seq WHERE account_id = ?")
        .bind(&session.account_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    sqlx::query(
        "DELETE FROM manifests WHERE collection_id IN (
             SELECT id FROM collections WHERE account_id = ?
         )",
    )
    .bind(&session.account_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    sqlx::query("DELETE FROM collections WHERE account_id = ?")
        .bind(&session.account_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    sqlx::query("DELETE FROM sessions WHERE account_id = ?")
        .bind(&session.account_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    sqlx::query("DELETE FROM devices WHERE account_id = ?")
        .bind(&session.account_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    sqlx::query("DELETE FROM accounts WHERE id = ?")
        .bind(&session.account_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    tx.commit()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    Ok(Json(SimpleStatusResponse {
        status: "ok".into(),
    }))
}
