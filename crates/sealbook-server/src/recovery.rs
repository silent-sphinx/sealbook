//! Recovering an account from its recovery phrase onto a new device.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use sqlx::Row;
use uuid::Uuid;

use sealbook_crypto::opaque::{server_register_finish, server_register_start};
use sealbook_crypto::{
    ct_eq, generate_login_challenge, is_supported_recovery_ciphersuite, phrase_recovery_transcript,
    recovery_password_payload, verify_phrase_recovery, DeviceSigningPublic, DualSignature,
    HPKE_AEAD_TAG_LEN, KDF_SALT_LEN, NONCE_LEN, PHRASE_LOOKUP_ID_LEN,
};
use sealbook_protocol::{
    valid_username, ErrorBody, KeyWrapBody, RecoverFinishRequest, RecoverFinishResponse,
    RecoverStartRequest, RecoverStartResponse,
};

use crate::pairing::{insert_device, verify_enroll};
use crate::roster;
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
    let collection_id: Option<String> = row.as_ref().map(|r| r.get("id"));
    // Served without the phrase key, which is never handed out before a proof.
    // The recovering device derives it from the phrase and the roster's MAC and
    // signature bind it, so nothing is lost by leaving it out.
    let roster = match &collection_id {
        Some(id) => roster::latest(&state.db, id).await?.map(|mut roster| {
            roster.phrase_mldsa_pk.clear();
            roster.phrase_ed25519_pk.clear();
            roster
        }),
        None => None,
    };
    let collection_id = collection_id.and_then(|id| Uuid::parse_str(&id).ok());
    // Begin the password reset. Evaluated against the account's own username so
    // the record this produces is usable for login, and against a fixed dummy
    // name when there is no such account, so the two cases cost the same and look
    // the same. Nothing here is derived from the existing password.
    let opaque_name: &[u8] = if collection_id.is_some() {
        body.username.as_bytes()
    } else {
        b"\x00sealbook-dummy"
    };
    let opaque_response = server_register_start(&state.opaque, &body.opaque_request, opaque_name)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "invalid credentials"))?;
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
        roster,
        collection_id,
        opaque_response,
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
    if body.kdf_salt.len() != KDF_SALT_LEN {
        return Err(err(StatusCode::BAD_REQUEST, "invalid kdf salt"));
    }
    if !is_supported_recovery_ciphersuite(&body.recovery_ciphersuite)
        || body.recovery_nonce.len() != NONCE_LEN
        || body.recovery_wrapped_ck.len() != 32 + HPKE_AEAD_TAG_LEN
    {
        return Err(err(StatusCode::BAD_REQUEST, "invalid ciphersuite"));
    }
    let transcript = phrase_recovery_transcript(
        &body.username,
        body.recovery_id,
        &body.challenge,
        body.device.device_id,
        &body.device.mldsa_pk,
        &body.device.ed25519_pk,
        &body.device.xwing_hpke_pk,
        &recovery_password_payload(
            &body.upload,
            &body.kdf_salt,
            &body.recovery_nonce,
            &body.recovery_wrapped_ck,
            &body.recovery_ciphersuite,
        ),
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
    let collection = sqlx::query("SELECT id FROM collections WHERE account_id = ?")
        .bind(&account_id)
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
        &account_id,
        &collection_id,
        &body.device,
        &body.wrap,
    )
    .await?;
    roster::verify_and_store(
        &mut tx,
        roster::Expected {
            collection_id: &collection_id,
            account_id: &account_id,
            signer: roster::Signer::Phrase,
            genesis: false,
        },
        &body.roster,
    )
    .await?;
    // The phrase proved itself, so the password it asks for takes effect. This is
    // what makes the phrase a recovery credential rather than a second factor on
    // top of a password the user may no longer have.
    let record = server_register_finish(&body.upload)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "opaque finish"))?;
    sqlx::query("UPDATE accounts SET opaque_record = ?, kdf_salt = ? WHERE id = ?")
        .bind(&record)
        .bind(&body.kdf_salt)
        .bind(&account_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    // The password wrap of the collection key was made under the old password, so
    // it is replaced with the one the client re-made under the new one. Left
    // alone, the account would have a password that logs in but cannot decrypt.
    sqlx::query(
        "UPDATE key_wraps SET hpke_enc = ?, wrapped_ck = ?, ciphersuite = ?
         WHERE collection_id = ? AND recipient_kind = 'recovery'",
    )
    .bind(&body.recovery_nonce)
    .bind(&body.recovery_wrapped_ck)
    .bind(&body.recovery_ciphersuite)
    .bind(&collection_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    // The phrase that was just used still unwraps the current collection key, and
    // so does every other copy of it. Only a client can rotate, so the debt is
    // recorded here and `rotate` is what clears it; until then this account is
    // held to it by `require_rotation_not_owed`.
    sqlx::query("UPDATE accounts SET recovery_pending = ? WHERE id = ?")
        .bind(now())
        .bind(&account_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
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

/// Whether a recovery has left this account owing a key rotation.
pub(crate) async fn rotation_owed<'e, E>(
    db: E,
    account_id: &str,
) -> Result<bool, (StatusCode, Json<ErrorBody>)>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let pending: i64 = sqlx::query_scalar("SELECT recovery_pending FROM accounts WHERE id = ?")
        .bind(account_id)
        .fetch_optional(db)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
        .unwrap_or(0);
    Ok(pending != 0)
}

/// Refuses an operation while a recovery's rotation is still outstanding.
///
/// A recovery enrols a device without replacing the collection key, so until the
/// rotation lands the phrase just used — and any other copy of it — still opens
/// the vault. Letting the account carry on as normal is what turned "the client
/// crashed before it rotated" into a phrase that stayed valid for ever.
///
/// Reading is deliberately still allowed: a rotation has to re-encrypt every
/// object, so it has to be able to read them first.
pub(crate) async fn require_rotation_not_owed(
    state: &AppState,
    account_id: &str,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    if rotation_owed(&state.db, account_id).await? {
        return Err(err(
            StatusCode::CONFLICT,
            "this account has an unfinished recovery: the collection key must be rotated \
             before it can be used again, which issues a new recovery phrase",
        ));
    }
    Ok(())
}
