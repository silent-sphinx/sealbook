//! OPAQUE registration and the three-message login exchange.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use sha2::{Digest, Sha256};
use sqlx::Row;
use tracing::info;
use uuid::Uuid;
use zeroize::Zeroize;

use sealbook_crypto::opaque::{
    server_login_finish, server_login_start, server_register_finish, server_register_start,
};
use sealbook_crypto::{
    ct_eq, enrollment_transcript, generate_login_challenge, hybrid_session_key,
    login_start_transcript, login_transcript, seal_login_challenge, validate_device_hpke_public,
    verify, DeviceHpkePublic, DeviceSigningPublic, DualSignature,
};
use sealbook_protocol::{
    valid_username, ErrorBody, KeyWrapBody, LoginChallengeRequest, LoginChallengeResponse,
    LoginFinishRequest, LoginFinishResponse, LoginStartRequest, LoginStartResponse,
    RegisterFinishRequest, RegisterFinishResponse, RegisterStartRequest, RegisterStartResponse,
};

use crate::manifest;
use crate::validate::{validate_phrase_recovery, validate_wraps};
use crate::*;

pub(crate) async fn register_start(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RegisterStartRequest>,
) -> Result<Json<RegisterStartResponse>, (StatusCode, Json<ErrorBody>)> {
    if !valid_username(&body.username) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid username"));
    }
    if !state
        .limiter
        .allow_endpoint(
            "register",
            &body.username,
            Some(state.trusted_proxies.client_ip(addr.ip(), &headers)),
        )
        .await
    {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    let existing = sqlx::query("SELECT id FROM accounts WHERE username = ?")
        .bind(&body.username)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    if existing.is_some() {
        return Err(err(StatusCode::CONFLICT, "username taken"));
    }
    let response = server_register_start(&state.opaque, &body.request, body.username.as_bytes())
        .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(Json(RegisterStartResponse { response }))
}

pub(crate) async fn register_finish(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RegisterFinishRequest>,
) -> Result<Json<RegisterFinishResponse>, (StatusCode, Json<ErrorBody>)> {
    if !valid_username(&body.username) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid username"));
    }
    if !state
        .limiter
        .allow_endpoint(
            "register",
            &body.username,
            Some(state.trusted_proxies.client_ip(addr.ip(), &headers)),
        )
        .await
    {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    let record = server_register_finish(&body.upload)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    if body.kdf_salt.len() != 16 {
        return Err(err(StatusCode::BAD_REQUEST, "invalid kdf salt"));
    }
    let enroll = enrollment_transcript(
        body.device.device_id,
        &body.device.mldsa_pk,
        &body.device.ed25519_pk,
        &body.device.xwing_hpke_pk,
    );
    let public = DeviceSigningPublic {
        mldsa_pk: body.device.mldsa_pk.clone(),
        ed25519_pk: body.device.ed25519_pk.clone(),
    };
    validate_device_hpke_public(&DeviceHpkePublic(body.device.xwing_hpke_pk.clone()))
        .map_err(|_| err(StatusCode::BAD_REQUEST, "xwing public key"))?;
    let sig = DualSignature {
        mldsa: body.enrollment_signature.mldsa.clone(),
        ed25519: body.enrollment_signature.ed25519.clone(),
    };
    verify(&public, &enroll, &sig)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "enrollment signature"))?;
    validate_phrase_recovery(&body.phrase_recovery)?;
    validate_wraps(
        &body.device.device_id.to_string(),
        &body.username,
        &body.key_wraps,
    )?;

    let account_id = Uuid::new_v4();
    // Client-chosen, so the device could sign the initial manifest over it.
    let collection_id = body.collection_id;
    let ts = now();

    let mut tx = state
        .db
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    sqlx::query(
        "INSERT INTO accounts
             (id, username, opaque_record, kdf_salt, created_at,
              phrase_mldsa_pk, phrase_ed25519_pk, phrase_lookup_id, phrase_scheme)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(account_id.to_string())
    .bind(&body.username)
    .bind(&record)
    .bind(&body.kdf_salt)
    .bind(ts)
    .bind(&body.phrase_recovery.mldsa_pk)
    .bind(&body.phrase_recovery.ed25519_pk)
    .bind(&body.phrase_recovery.lookup_id)
    .bind(&body.phrase_recovery.scheme)
    .execute(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::CONFLICT, "username taken"))?;

    sqlx::query(
        "INSERT INTO devices (id, account_id, mldsa_pk, ed25519_pk, xwing_hpke_pk, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(body.device.device_id.to_string())
    .bind(account_id.to_string())
    .bind(&body.device.mldsa_pk)
    .bind(&body.device.ed25519_pk)
    .bind(&body.device.xwing_hpke_pk)
    .bind(ts)
    .execute(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    sqlx::query(
        "INSERT INTO collections (id, account_id, kind, created_at) VALUES (?, ?, 'vault', ?)",
    )
    .bind(collection_id.to_string())
    .bind(account_id.to_string())
    .bind(ts)
    .execute(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::CONFLICT, "collection exists"))?;

    sqlx::query("INSERT INTO revision_seq (account_id, next_revision) VALUES (?, 1)")
        .bind(account_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    for wrap in &body.key_wraps {
        sqlx::query(
            "INSERT INTO key_wraps (collection_id, recipient_kind, recipient_id, hpke_enc, wrapped_ck, ciphersuite)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(collection_id.to_string())
        .bind(&wrap.recipient_kind)
        .bind(&wrap.recipient_id)
        .bind(&wrap.hpke_enc)
        .bind(&wrap.wrapped_ck)
        .bind(&wrap.ciphersuite)
        .execute(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    }

    // Creates the bucket state for the new, empty collection, so the manifest
    // check below has something to read and every later write is incremental.
    manifest::rebuild_digest_state(&mut tx, &account_id.to_string(), &collection_id.to_string())
        .await?;

    // An account has a signed manifest from the moment it exists, so a client is
    // never asked to accept an unsigned "your vault is empty" from the server.
    manifest::verify_and_store(
        &mut tx,
        manifest::Expected {
            collection_id: &collection_id.to_string(),
            account_id: &account_id.to_string(),
            device_id: &body.device.device_id.to_string(),
            key_epoch: 1,
            latest_revision: 0,
        },
        &body.manifest,
    )
    .await?;

    tx.commit()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    info!(%account_id, "registered");
    Ok(Json(RegisterFinishResponse {
        account_id,
        collection_id,
    }))
}

/// Step 1 of login: issue a challenge sealed to the device's X-Wing key.
///
/// Unknown usernames and devices get a challenge sealed to a persistent dummy
/// key, so the response shape reveals nothing. No OPAQUE state is created here.
pub(crate) async fn login_challenge(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginChallengeRequest>,
) -> Result<Json<LoginChallengeResponse>, (StatusCode, Json<ErrorBody>)> {
    if !valid_username(&body.username) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid username"));
    }
    // A separate bucket from `login`, so that splitting login into two requests
    // does not halve the number of login attempts a user gets per minute.
    if !state
        .limiter
        .allow_endpoint(
            "login-challenge",
            &body.username,
            Some(state.trusted_proxies.client_ip(addr.ip(), &headers)),
        )
        .await
    {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    let hpke_row = sqlx::query(
        "SELECT d.xwing_hpke_pk FROM devices d
         JOIN accounts a ON a.id = d.account_id
         WHERE a.username = ? AND d.id = ? AND d.revoked_at IS NULL",
    )
    .bind(&body.username)
    .bind(body.device_id.to_string())
    .fetch_optional(&state.db)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let hpke_pk = hpke_row
        .map(|r| DeviceHpkePublic(r.get("xwing_hpke_pk")))
        .unwrap_or_else(|| state.dummy_hpke_pk.clone());
    let challenge = generate_login_challenge();
    let wrap = seal_login_challenge(&hpke_pk, &challenge)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "challenge"))?;

    let challenge_id = Uuid::new_v4();
    let mut pending = state.pending_challenges.lock().await;
    admit(&mut pending, Duration::from_secs(120), |entry| {
        entry.created
    });
    pending.insert(
        challenge_id,
        PendingChallenge {
            username: body.username,
            device_id: body.device_id,
            challenge,
            created: Instant::now(),
        },
    );
    Ok(Json(LoginChallengeResponse {
        challenge_id,
        challenge_enc: wrap.enc,
        challenge_ct: wrap.ciphertext,
    }))
}

/// Step 2 of login: check the device proof, then release the OPAQUE response.
///
/// Nothing derived from the password record leaves the server until the caller
/// has opened the X-Wing challenge and signed it with the device's ML-DSA-65
/// and Ed25519 keys. That is what stops an attacker from harvesting an OPRF
/// evaluation for an arbitrary username and attacking the password offline.
pub(crate) async fn login_start(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginStartRequest>,
) -> Result<Json<LoginStartResponse>, (StatusCode, Json<ErrorBody>)> {
    if !valid_username(&body.username) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid username"));
    }
    if !state
        .limiter
        .allow_endpoint(
            "login",
            &body.username,
            Some(state.trusted_proxies.client_ip(addr.ip(), &headers)),
        )
        .await
    {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    let mut pending_challenge = state
        .pending_challenges
        .lock()
        .await
        .remove(&body.challenge_id)
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid credentials"))?;
    if pending_challenge.created.elapsed() > Duration::from_secs(120)
        || pending_challenge.username != body.username
        || pending_challenge.device_id != body.device_id
        || body.challenge.len() != 32
        || !ct_eq(&body.challenge, &pending_challenge.challenge)
    {
        pending_challenge.challenge.zeroize();
        return Err(err(StatusCode::UNAUTHORIZED, "invalid credentials"));
    }
    let mut challenge = [0u8; 32];
    challenge.copy_from_slice(&body.challenge);
    pending_challenge.challenge.zeroize();

    // The device must exist and be signed for before any OPAQUE work happens.
    let device = sqlx::query(
        "SELECT d.mldsa_pk, d.ed25519_pk FROM devices d
         JOIN accounts a ON a.id = d.account_id
         WHERE a.username = ? AND d.id = ? AND d.revoked_at IS NULL",
    )
    .bind(&body.username)
    .bind(body.device_id.to_string())
    .fetch_optional(&state.db)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
    .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid credentials"))?;
    let public = DeviceSigningPublic {
        mldsa_pk: device.get("mldsa_pk"),
        ed25519_pk: device.get("ed25519_pk"),
    };
    let transcript = login_start_transcript(
        body.challenge_id,
        &body.username,
        body.device_id,
        &challenge,
        &body.request,
    );
    let signature = DualSignature {
        mldsa: body.device_signature.mldsa.clone(),
        ed25519: body.device_signature.ed25519.clone(),
    };
    verify(&public, &transcript, &signature)
        .map_err(|_| err(StatusCode::UNAUTHORIZED, "invalid credentials"))?;

    let row = sqlx::query("SELECT opaque_record FROM accounts WHERE username = ?")
        .bind(&body.username)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let record: Vec<u8> = row
        .map(|r| r.get("opaque_record"))
        .unwrap_or_else(|| state.dummy_record.clone());
    let (response, login_state) = server_login_start(
        &state.opaque,
        &record,
        &body.request,
        body.username.as_bytes(),
    )
    .map_err(|_| err(StatusCode::UNAUTHORIZED, "invalid credentials"))?;

    let login_id = Uuid::new_v4();
    let mut pending = state.pending_logins.lock().await;
    admit(&mut pending, Duration::from_secs(120), |entry| {
        entry.created
    });
    pending.insert(
        login_id,
        PendingLogin {
            state: login_state,
            created: Instant::now(),
            username: body.username,
            device_id: body.device_id,
            challenge,
        },
    );
    challenge.zeroize();
    Ok(Json(LoginStartResponse { login_id, response }))
}

pub(crate) async fn login_finish(
    State(state): State<Shared>,
    Json(body): Json<LoginFinishRequest>,
) -> Result<Json<LoginFinishResponse>, (StatusCode, Json<ErrorBody>)> {
    let mut pending = state
        .pending_logins
        .lock()
        .await
        .remove(&body.login_id)
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid credentials"))?;
    if pending.created.elapsed() > Duration::from_secs(120)
        || pending.username != body.username
        || pending.device_id != body.device_id
    {
        return Err(err(StatusCode::UNAUTHORIZED, "invalid credentials"));
    }
    // The challenge was verified in `login_start`; it is replayed from server
    // state here only to bind the transcript and derive the session token.
    let mut challenge = pending.challenge;
    let mut session_key = server_login_finish(pending.state, &body.finalization)
        .map_err(|_| err(StatusCode::UNAUTHORIZED, "invalid credentials"))?;
    let mut token_bytes = hybrid_session_key(&session_key, &challenge)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "session"))?;
    session_key.zeroize();
    pending.challenge.zeroize();

    let account = sqlx::query("SELECT id, kdf_salt FROM accounts WHERE username = ?")
        .bind(&body.username)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid credentials"))?;
    let account_id: String = account.get("id");
    let kdf_salt: Vec<u8> = account.get("kdf_salt");

    let device = sqlx::query("SELECT id, mldsa_pk, ed25519_pk FROM devices WHERE id = ? AND account_id = ? AND revoked_at IS NULL")
        .bind(body.device_id.to_string())
        .bind(&account_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid credentials"))?;
    let device_id: String = device.get("id");
    let public = DeviceSigningPublic {
        mldsa_pk: device.get("mldsa_pk"),
        ed25519_pk: device.get("ed25519_pk"),
    };
    let transcript = login_transcript(
        body.login_id,
        &body.username,
        body.device_id,
        &body.finalization,
        &challenge,
    );
    let sig = DualSignature {
        mldsa: body.device_signature.mldsa.clone(),
        ed25519: body.device_signature.ed25519.clone(),
    };
    verify(&public, &transcript, &sig)
        .map_err(|_| err(StatusCode::UNAUTHORIZED, "invalid credentials"))?;

    let collection = sqlx::query("SELECT id, key_epoch FROM collections WHERE account_id = ?")
        .bind(&account_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let collection_id: String = collection.get("id");
    let key_epoch: i64 = collection.get("key_epoch");

    let wraps = sqlx::query(
        "SELECT recipient_kind, recipient_id, hpke_enc, wrapped_ck, ciphersuite
         FROM key_wraps WHERE collection_id = ?",
    )
    .bind(&collection_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    let key_wraps = wraps
        .into_iter()
        .map(|row| KeyWrapBody {
            recipient_kind: row.get("recipient_kind"),
            recipient_id: row.get("recipient_id"),
            hpke_enc: row.get("hpke_enc"),
            wrapped_ck: row.get("wrapped_ck"),
            ciphersuite: row.get("ciphersuite"),
        })
        .collect();

    let token = hex::encode(token_bytes);
    token_bytes.zeroize();
    challenge.zeroize();
    let token_hash = Sha256::digest(token.as_bytes()).to_vec();
    let expires = now() + 86400;
    sqlx::query(
        "INSERT INTO sessions (token_hash, account_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&token_hash)
    .bind(&account_id)
    .bind(&device_id)
    .bind(expires)
    .bind(now())
    .execute(&state.db)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    Ok(Json(LoginFinishResponse {
        account_id: Uuid::parse_str(&account_id).unwrap(),
        collection_id: Uuid::parse_str(&collection_id).unwrap(),
        session_token: token,
        kdf_salt,
        key_wraps,
        key_epoch: key_epoch as u64,
    }))
}
