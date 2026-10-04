//! The signed device roster: the history a client verifies the device set against.
//!
//! The server cannot sign a roster, and that is the point: a client that took the
//! device list on the server's word would wrap the next collection key for any
//! device the server chose to list. What the server does is refuse to store a
//! roster that does not describe its own post-operation state exactly, so the
//! signed history and the `devices` table never disagree for an honest server.

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use sqlx::{Row, Sqlite, Transaction};
use uuid::Uuid;

use sealbook_crypto::{verify_roster_step, ROSTER_MAC_LEN};
use sealbook_protocol::{ErrorBody, RosterBody, RosterQuery, RosterResponse, RosterSignerBody};

use crate::session::require_session;
use crate::*;

/// A device's id and its three public keys, compared as one value.
type DeviceKeys = (String, Vec<u8>, Vec<u8>, Vec<u8>);

/// Who must have signed the roster an operation submits.
pub(crate) enum Signer<'a> {
    /// A device: the registering device for a genesis, otherwise the session's.
    Device(&'a str),
    /// The recovery phrase key, for a recovery.
    Phrase,
}

pub(crate) struct Expected<'a> {
    pub(crate) collection_id: &'a str,
    pub(crate) account_id: &'a str,
    pub(crate) signer: Signer<'a>,
    /// Only registration may store a first roster.
    pub(crate) genesis: bool,
}

fn decode(body: &str) -> Result<RosterBody, (StatusCode, Json<ErrorBody>)> {
    serde_json::from_str(body).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))
}

/// The collection's newest roster.
pub(crate) async fn latest<'e, E>(
    db: E,
    collection_id: &str,
) -> Result<Option<RosterBody>, (StatusCode, Json<ErrorBody>)>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let body: Option<String> = sqlx::query_scalar(
        "SELECT body FROM device_rosters WHERE collection_id = ?
         ORDER BY roster_seq DESC LIMIT 1",
    )
    .bind(collection_id)
    .fetch_optional(db)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    body.as_deref().map(decode).transpose()
}

/// Checks a submitted roster against the server's own view and stores it.
///
/// Called inside the transaction that changes the device set, after the change,
/// so the devices, phrase key and epoch read here are the ones the roster must
/// describe.
pub(crate) async fn verify_and_store(
    tx: &mut Transaction<'_, Sqlite>,
    expected: Expected<'_>,
    body: &RosterBody,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let previous = latest(&mut **tx, expected.collection_id).await?;
    match (&previous, expected.genesis) {
        (None, false) => {
            return Err(err(
                StatusCode::CONFLICT,
                "this account has no device roster",
            ))
        }
        (Some(_), true) => return Err(err(StatusCode::CONFLICT, "roster already exists")),
        _ => {}
    }
    let next_seq = previous.as_ref().map_or(1, |roster| roster.roster_seq + 1);
    if body.roster_seq != next_seq {
        // A pairing and a rotation racing each other land here.
        return Err(err(StatusCode::CONFLICT, "stale roster sequence"));
    }

    let signer_ok = match (&expected.signer, &body.signer) {
        (Signer::Device(expected), RosterSignerBody::Device { device_id }) => {
            device_id.to_string() == *expected
        }
        (Signer::Phrase, RosterSignerBody::Phrase) => true,
        _ => false,
    };
    if !signer_ok {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "roster must be signed by the party making this change",
        ));
    }
    if body.mac.len() != ROSTER_MAC_LEN {
        return Err(err(StatusCode::BAD_REQUEST, "invalid roster mac"));
    }

    let key_epoch: i64 = sqlx::query_scalar("SELECT key_epoch FROM collections WHERE id = ?")
        .bind(expected.collection_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    if body.key_epoch != key_epoch as u64 {
        return Err(err(StatusCode::CONFLICT, "stale roster key epoch"));
    }

    let account =
        sqlx::query("SELECT phrase_mldsa_pk, phrase_ed25519_pk FROM accounts WHERE id = ?")
            .bind(expected.account_id)
            .fetch_one(&mut **tx)
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let phrase_mldsa_pk: Vec<u8> = account.get("phrase_mldsa_pk");
    let phrase_ed25519_pk: Vec<u8> = account.get("phrase_ed25519_pk");
    if body.phrase_mldsa_pk != phrase_mldsa_pk || body.phrase_ed25519_pk != phrase_ed25519_pk {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "roster phrase key does not match the account",
        ));
    }

    let rows = sqlx::query(
        "SELECT id, mldsa_pk, ed25519_pk, xwing_hpke_pk FROM devices
         WHERE account_id = ? AND revoked_at IS NULL",
    )
    .bind(expected.account_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let mut actual: Vec<DeviceKeys> = rows
        .into_iter()
        .map(|row| {
            (
                row.get("id"),
                row.get("mldsa_pk"),
                row.get("ed25519_pk"),
                row.get("xwing_hpke_pk"),
            )
        })
        .collect();
    actual.sort();
    let mut listed: Vec<DeviceKeys> = body
        .devices
        .iter()
        .map(|device| {
            (
                device.device_id.to_string(),
                device.mldsa_pk.clone(),
                device.ed25519_pk.clone(),
                device.xwing_hpke_pk.clone(),
            )
        })
        .collect();
    listed.sort();
    if listed != actual {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "roster does not list exactly the account's devices",
        ));
    }

    let collection_uuid = Uuid::parse_str(expected.collection_id)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let previous_roster = previous.as_ref().map(RosterBody::to_roster);
    verify_roster_step(collection_uuid, previous_roster.as_ref(), &body.to_roster())
        .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;

    let encoded =
        serde_json::to_string(body).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    sqlx::query("INSERT INTO device_rosters (collection_id, roster_seq, body) VALUES (?, ?, ?)")
        .bind(expected.collection_id)
        .bind(body.roster_seq as i64)
        .bind(encoded)
        .execute(&mut **tx)
        .await
        .map_err(|_| err(StatusCode::CONFLICT, "stale roster sequence"))?;
    Ok(())
}

/// The roster history from `from` on, or only the newest roster without it.
pub(crate) async fn collection_roster(
    State(state): State<Shared>,
    AxumPath(collection_id): AxumPath<Uuid>,
    Query(query): Query<RosterQuery>,
    headers: HeaderMap,
) -> Result<Json<RosterResponse>, (StatusCode, Json<ErrorBody>)> {
    let session = require_session(&state, &headers).await?;
    require_read_budget(&state, "roster", &session.account_id).await?;
    let owned = sqlx::query("SELECT id FROM collections WHERE id = ? AND account_id = ?")
        .bind(collection_id.to_string())
        .bind(&session.account_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    if owned.is_none() {
        return Err(err(StatusCode::NOT_FOUND, "collection"));
    }
    let rosters = match query.from {
        None => latest(&state.db, &collection_id.to_string())
            .await?
            .into_iter()
            .collect(),
        Some(from) => {
            let bodies: Vec<String> = sqlx::query_scalar(
                "SELECT body FROM device_rosters
                 WHERE collection_id = ? AND roster_seq >= ?
                 ORDER BY roster_seq ASC",
            )
            .bind(collection_id.to_string())
            .bind(from as i64)
            .fetch_all(&state.db)
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
            bodies
                .iter()
                .map(|body| decode(body))
                .collect::<Result<Vec<_>, _>>()?
        }
    };
    Ok(Json(RosterResponse { rosters }))
}
