//! Bearer-token sessions: the guards every authenticated route calls, and
//! the route that revokes the caller's own session.

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::Json;
use sha2::{Digest, Sha256};
use sqlx::Row;

use sealbook_protocol::{ErrorBody, SimpleStatusResponse};

use crate::*;

pub(crate) struct Session {
    pub(crate) account_id: String,
    pub(crate) device_id: String,
    pub(crate) created_at: i64,
}

pub(crate) async fn require_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Session, (StatusCode, Json<ErrorBody>)> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "missing token"))?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "missing token"))?;
    let hash = Sha256::digest(token.as_bytes()).to_vec();
    let row = sqlx::query(
        "SELECT s.account_id, s.device_id, s.expires_at, s.created_at
         FROM sessions s
         JOIN devices d ON d.id = s.device_id AND d.account_id = s.account_id
         WHERE s.token_hash = ? AND d.revoked_at IS NULL",
    )
    .bind(&hash)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
    .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid token"))?;
    let expires_at: i64 = row.get("expires_at");
    if expires_at < now() {
        return Err(err(StatusCode::UNAUTHORIZED, "expired token"));
    }
    Ok(Session {
        account_id: row.get("account_id"),
        device_id: row.get("device_id"),
        created_at: row.get("created_at"),
    })
}

pub(crate) async fn require_recent_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Session, (StatusCode, Json<ErrorBody>)> {
    let session = require_session(state, headers).await?;
    if now().saturating_sub(session.created_at) > 300 {
        return Err(err(StatusCode::UNAUTHORIZED, "recent login required"));
    }
    Ok(session)
}

pub(crate) async fn revoke_session(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> Result<Json<SimpleStatusResponse>, (StatusCode, Json<ErrorBody>)> {
    let session = require_session(&state, &headers).await?;
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "missing token"))?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "missing token"))?;
    let token_hash = Sha256::digest(token.as_bytes()).to_vec();
    sqlx::query("DELETE FROM sessions WHERE token_hash = ? AND account_id = ? AND device_id = ?")
        .bind(token_hash)
        .bind(session.account_id)
        .bind(session.device_id)
        .execute(&state.db)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(Json(SimpleStatusResponse {
        status: "ok".into(),
    }))
}
