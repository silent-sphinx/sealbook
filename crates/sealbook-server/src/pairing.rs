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
    enrollment_transcript, pair_grant_transcript, validate_device_hpke_public, verify,
    DeviceHpkePublic, DeviceSigningPublic, DualSignature, HPKE_AEAD_TAG_LEN, NONCE_LEN,
    PAIR_NAMEPLATE_WORDS, PAIR_SID_LEN, XWING_CIPHERSUITE, XWING_ENCAPSULATED_KEY_LEN,
};
use sealbook_protocol::{
    valid_username, DevicePublicKeys, DualSignatureBody, ErrorBody, KeyWrapBody,
    PairApproveRequest, PairConfirmRequest, PairJoinRequest, PairJoinResponse, PairRespondRequest,
    PairStatusResponse,
};

use crate::roster;
use crate::session::require_session;
use crate::*;

/// How a request names a pairing: the joining device by the pair id it was
/// given, the approving device by the nameplate the user typed.
pub(crate) enum PairKey {
    Joiner(Uuid),
    Approver(String),
}

impl PairKey {
    fn parse(key: &str) -> Self {
        match Uuid::parse_str(key.trim()) {
            Ok(pair_id) => Self::Joiner(pair_id),
            Err(_) => Self::Approver(key.trim().to_ascii_lowercase()),
        }
    }
}

/// The live pairing a key names, if any.
pub(crate) fn pair_id_for_key(key: &PairKey, pending: &HashMap<Uuid, PendingPair>) -> Option<Uuid> {
    match key {
        PairKey::Joiner(pair_id) => pending.contains_key(pair_id).then_some(*pair_id),
        PairKey::Approver(nameplate) => pending
            .iter()
            .find(|(_, pair)| &pair.nameplate == nameplate)
            .map(|(pair_id, _)| *pair_id),
    }
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

/// Whether this enrolment is refused at `MAX_DEVICES_PER_ACCOUNT`.
pub(crate) enum DeviceCap {
    /// A pairing. The session approving it can free a slot by revoking.
    Enforced,
    /// A phrase recovery, which cannot be refused: the only way to free a slot
    /// is a revocation, which needs a session, which needs the password this
    /// request exists to replace. Enforcing the cap here loses the account for
    /// good, while exempting it costs one device on an account that already
    /// owes a rotation before it can be used again.
    PhraseExempt,
}

pub(crate) async fn insert_device(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    account_id: &str,
    collection_id: &str,
    device: &DevicePublicKeys,
    wrap: &KeyWrapBody,
    cap: DeviceCap,
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
        match cap {
            DeviceCap::Enforced => {
                return Err(err(
                    StatusCode::CONFLICT,
                    "this account already has the maximum number of devices; revoke one first",
                ))
            }
            DeviceCap::PhraseExempt => tracing::warn!(
                enrolled,
                "a recovery enrolled a device past the device cap; revoke the devices no \
                 longer in use, since every one of them is wrapped in each rotation"
            ),
        }
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

/// The CPace share length: one encoded ristretto255 element.
const SHARE_LEN: usize = 32;
/// The longest sealed message a pairing relays. The joining device's reply
/// carries a short description; the approving device's pin is 40 bytes.
const MAX_SEALED_LEN: usize = 512;
/// The longest nameplate: three of the longest list words and two hyphens.
const MAX_NAMEPLATE_LEN: usize = 3 * 8 + 2;

/// A nameplate is three lowercase words, hyphen-joined. It is all the server
/// ever sees of the code.
fn valid_nameplate(nameplate: &str) -> bool {
    nameplate.len() <= MAX_NAMEPLATE_LEN
        && nameplate.split('-').count() == PAIR_NAMEPLATE_WORDS
        && nameplate
            .split('-')
            .all(|word| !word.is_empty() && word.bytes().all(|b| b.is_ascii_lowercase()))
}

fn pair_status_name(pair: &PendingPair) -> &'static str {
    if pair.approved {
        "ready"
    } else if pair.hello.is_some() {
        "confirmed"
    } else if pair.approver_share.is_some() {
        "responded"
    } else {
        "pending"
    }
}

/// The pairing as the approving device sees it: the joining device's half.
fn approver_view(pair_id: Uuid, pair: &PendingPair) -> PairStatusResponse {
    PairStatusResponse {
        pair_id,
        status: pair_status_name(pair).into(),
        username: Some(pair.username.clone()),
        device: Some(pair.device.clone()),
        sid: pair.sid.clone(),
        joiner_share: pair.joiner_share.clone(),
        approver_share: Vec::new(),
        hello: pair.hello.clone().unwrap_or_default(),
        sealed_pin: Vec::new(),
    }
}

/// The pairing as the joining device sees it: the approving device's half. It
/// carries nothing that names the account or the device.
fn joiner_view(pair_id: Uuid, pair: &PendingPair) -> PairStatusResponse {
    PairStatusResponse {
        pair_id,
        status: pair_status_name(pair).into(),
        username: None,
        device: None,
        sid: Vec::new(),
        joiner_share: Vec::new(),
        approver_share: pair.approver_share.clone().unwrap_or_default(),
        hello: Vec::new(),
        sealed_pin: pair.sealed_pin.clone().unwrap_or_default(),
    }
}

fn gone() -> (StatusCode, Json<ErrorBody>) {
    err(StatusCode::NOT_FOUND, "expired")
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
    let source = state.trusted_proxies.client_ip(addr.ip(), &headers);
    // Per address only. No proof exists yet to charge a per-username ceiling
    // after, and charged before one, it let anyone who knew a username hold
    // pairing closed for it (audit finding 5). The code's secret words are what
    // stop a stranger's device being approved.
    if !state
        .limiter
        .allow_address("pair", &body.username, Some(source))
        .await
    {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    if !valid_nameplate(&body.nameplate)
        || body.sid.len() != PAIR_SID_LEN
        || body.share.len() != SHARE_LEN
    {
        return Err(err(StatusCode::BAD_REQUEST, "invalid pairing request"));
    }
    verify_enroll(&body.device, &body.enrollment_signature)?;
    // Looked up for the approval's sake only. Nothing in the answer depends on
    // it, so a join cannot tell whether the username has an account: one with
    // none simply has no device that can ever see the pairing.
    let account_id: Option<String> =
        sqlx::query_scalar("SELECT id FROM accounts WHERE username = ?")
            .bind(&body.username)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let pair_id = Uuid::new_v4();
    let mut pending = state.pending_pairs.lock().await;
    admit_pair(&mut pending);
    // The joining device picked the nameplate, so on the rare collision it
    // picks another code rather than share a lookup with someone else's pairing.
    if pending
        .values()
        .any(|pair| pair.nameplate == body.nameplate)
    {
        return Err(err(StatusCode::CONFLICT, "pairing code in use"));
    }
    pending.insert(
        pair_id,
        PendingPair {
            username: body.username,
            account_id,
            source,
            device: body.device,
            enrollment_signature: body.enrollment_signature,
            nameplate: body.nameplate,
            sid: body.sid,
            joiner_share: body.share,
            approver_share: None,
            responder: None,
            hello: None,
            sealed_pin: None,
            created: Instant::now(),
            approved: false,
        },
    );
    Ok(Json(PairJoinResponse { pair_id }))
}

pub(crate) async fn pair_status(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    AxumPath(pair_key): AxumPath<String>,
    headers: HeaderMap,
) -> Result<Json<PairStatusResponse>, (StatusCode, Json<ErrorBody>)> {
    // Unauthenticated for the joining device, and it takes the pairing lock to
    // scan every pending pair, so it is bound per address. Both devices poll this
    // every second while they wait, so the bound is generous rather than tight.
    if !state
        .limiter
        .allow(
            &format!(
                "ip:pair-status:{}",
                state.trusted_proxies.client_ip(addr.ip(), &headers)
            ),
            240,
            Duration::from_secs(60),
        )
        .await
    {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    let key = PairKey::parse(&pair_key);
    // Resolved before the pairing lock is taken, not under it, so one poller's
    // database round trip does not hold up every other.
    let caller = match key {
        PairKey::Approver(_) => require_session(&state, &headers).await.ok(),
        PairKey::Joiner(_) => None,
    };
    let mut pending = state.pending_pairs.lock().await;
    pending.retain(|_, p| p.created.elapsed() < PAIR_TTL);
    let pair_id = pair_id_for_key(&key, &pending).ok_or_else(gone)?;
    let pair = pending.get(&pair_id).ok_or_else(gone)?;
    match key {
        PairKey::Joiner(_) => Ok(Json(joiner_view(pair_id, pair))),
        // A nameplate is three words anyone could guess at, so a pairing is only
        // shown to a device on the account it is joining.
        PairKey::Approver(_) => match caller {
            Some(session) if pair.account_id.as_deref() == Some(session.account_id.as_str()) => {
                Ok(Json(approver_view(pair_id, pair)))
            }
            _ => Err(gone()),
        },
    }
}

/// Records the approving device's CPace share. Once per pairing, by a device on
/// the account, which from then on is the only one that may approve it.
pub(crate) async fn pair_respond(
    State(state): State<Shared>,
    AxumPath(pair_key): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<PairRespondRequest>,
) -> Result<Json<PairStatusResponse>, (StatusCode, Json<ErrorBody>)> {
    let session = require_session(&state, &headers).await?;
    // Handing the current collection key to another device while a phrase that
    // opens it may be in someone else's hands would widen the exposure, so the
    // pairing is refused before the code is spent rather than at the approval.
    crate::recovery::require_rotation_not_owed(&state, &session.account_id).await?;
    if body.share.len() != SHARE_LEN {
        return Err(err(StatusCode::BAD_REQUEST, "invalid pairing share"));
    }
    let key = PairKey::parse(&pair_key);
    if !matches!(key, PairKey::Approver(_)) {
        return Err(gone());
    }
    let mut pending = state.pending_pairs.lock().await;
    pending.retain(|_, p| p.created.elapsed() < PAIR_TTL);
    let pair_id = pair_id_for_key(&key, &pending).ok_or_else(gone)?;
    let pair = pending.get_mut(&pair_id).ok_or_else(gone)?;
    if pair.account_id.as_deref() != Some(session.account_id.as_str()) {
        return Err(gone());
    }
    if pair.approver_share.is_some() {
        return Err(err(
            StatusCode::CONFLICT,
            "this pairing has already been answered",
        ));
    }
    pair.approver_share = Some(body.share);
    pair.responder = Some(session.device_id.clone());
    Ok(Json(approver_view(pair_id, pair)))
}

/// Records the joining device's sealed reply. Once per pairing, by pair id: the
/// joining device has no session, and the pair id is what it was given.
pub(crate) async fn pair_confirm(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    AxumPath(pair_key): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<PairConfirmRequest>,
) -> Result<Json<PairStatusResponse>, (StatusCode, Json<ErrorBody>)> {
    if !state
        .limiter
        .allow(
            &format!(
                "ip:pair-confirm:{}",
                state.trusted_proxies.client_ip(addr.ip(), &headers)
            ),
            30,
            Duration::from_secs(60),
        )
        .await
    {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    if body.hello.len() < NONCE_LEN || body.hello.len() > MAX_SEALED_LEN {
        return Err(err(StatusCode::BAD_REQUEST, "invalid pairing reply"));
    }
    let key = PairKey::parse(&pair_key);
    if !matches!(key, PairKey::Joiner(_)) {
        return Err(gone());
    }
    let mut pending = state.pending_pairs.lock().await;
    pending.retain(|_, p| p.created.elapsed() < PAIR_TTL);
    let pair_id = pair_id_for_key(&key, &pending).ok_or_else(gone)?;
    let pair = pending.get_mut(&pair_id).ok_or_else(gone)?;
    if pair.approver_share.is_none() || pair.hello.is_some() {
        return Err(err(
            StatusCode::CONFLICT,
            "this pairing is not waiting for a reply",
        ));
    }
    pair.hello = Some(body.hello);
    Ok(Json(joiner_view(pair_id, pair)))
}

/// Drops a pairing the approving device has given up on, which is what it does
/// when the joining device's reply does not open: the code is spent.
pub(crate) async fn pair_cancel(
    State(state): State<Shared>,
    AxumPath(pair_key): AxumPath<String>,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, Json<ErrorBody>)> {
    let session = require_session(&state, &headers).await?;
    let key = PairKey::parse(&pair_key);
    if !matches!(key, PairKey::Approver(_)) {
        return Err(gone());
    }
    let mut pending = state.pending_pairs.lock().await;
    let Some(pair_id) = pair_id_for_key(&key, &pending) else {
        return Ok(StatusCode::NO_CONTENT);
    };
    let ours = pending.get(&pair_id).is_some_and(|pair| {
        pair.account_id.as_deref() == Some(session.account_id.as_str()) && !pair.approved
    });
    if ours {
        pending.remove(&pair_id);
    }
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn pair_approve(
    State(state): State<Shared>,
    AxumPath(pair_key): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<PairApproveRequest>,
) -> Result<Json<PairStatusResponse>, (StatusCode, Json<ErrorBody>)> {
    let session = require_session(&state, &headers).await?;
    crate::recovery::require_rotation_not_owed(&state, &session.account_id).await?;
    if body.sealed_pin.len() < NONCE_LEN || body.sealed_pin.len() > MAX_SEALED_LEN {
        return Err(err(StatusCode::BAD_REQUEST, "invalid sealed pin"));
    }
    let key = PairKey::parse(&pair_key);
    if !matches!(key, PairKey::Approver(_)) {
        return Err(gone());
    }
    // The pairing lock is taken twice, for as long as each of two in-memory
    // lookups needs, and is not held across the dual signature verifications or
    // the enrolling transaction below, which would stall every poll.
    let (pair_id, pair) = {
        let mut pending = state.pending_pairs.lock().await;
        pending.retain(|_, p| p.created.elapsed() < PAIR_TTL);
        let pair_id = pair_id_for_key(&key, &pending).ok_or_else(gone)?;
        let pair = pending.get(&pair_id).ok_or_else(gone)?;
        if pair.account_id.as_deref() != Some(session.account_id.as_str()) {
            return Err(gone());
        }
        if pair.approved {
            return Ok(Json(approver_view(pair_id, pair)));
        }
        if pair.responder.as_deref() != Some(session.device_id.as_str()) {
            return Err(err(
                StatusCode::CONFLICT,
                "this pairing was answered by another device",
            ));
        }
        if pair.hello.is_none() {
            return Err(err(
                StatusCode::CONFLICT,
                "the new device has not replied to this pairing yet",
            ));
        }
        (
            pair_id,
            (
                pair.device.clone(),
                pair.enrollment_signature.clone(),
                pair.sid.clone(),
                pair.joiner_share.clone(),
                pair.approver_share.clone().unwrap_or_default(),
            ),
        )
    };
    let (device, enrollment_signature, sid, joiner_share, approver_share) = pair;
    verify_enroll(&device, &enrollment_signature)?;
    let approver = sqlx::query(
        "SELECT mldsa_pk, ed25519_pk FROM devices WHERE id = ? AND account_id = ? AND revoked_at IS NULL",
    )
    .bind(&session.device_id)
    .bind(&session.account_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?
    .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid token"))?;
    let approver_id = Uuid::parse_str(&session.device_id)
        .map_err(|_| err(StatusCode::UNAUTHORIZED, "invalid token"))?;
    let grant_t = pair_grant_transcript(
        pair_id,
        approver_id,
        device.device_id,
        &device.mldsa_pk,
        &device.ed25519_pk,
        &device.xwing_hpke_pk,
        &sid,
        &joiner_share,
        &approver_share,
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
        &device,
        &body.wrap,
        DeviceCap::Enforced,
    )
    .await?;
    // The approver signs on the roster it verified just now, so a rotation or
    // another pairing landing in between is a stale sequence here, and the
    // approval is made again from the newer roster.
    roster::verify_and_store(
        &mut tx,
        roster::Expected {
            collection_id: &collection_id,
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
    // Re-acquired to record the approval and hand the joining device its pin.
    // The entry can have expired while the enrolment ran; the device is
    // enrolled either way, and the joining device learns that from its next
    // poll finding nothing, after which it pairs again.
    let mut pending = state.pending_pairs.lock().await;
    match pending.get_mut(&pair_id) {
        Some(entry) => {
            entry.approved = true;
            entry.sealed_pin = Some(body.sealed_pin);
            Ok(Json(approver_view(pair_id, entry)))
        }
        None => Err(gone()),
    }
}
