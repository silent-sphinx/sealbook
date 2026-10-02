use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::middleware::from_fn;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use sqlx::{Pool, Sqlite};
use tokio::sync::Mutex;
use tracing::info;
use uuid::Uuid;

use sealbook_crypto::opaque::{OpaqueServerLogin, OpaqueServerSetup};
use sealbook_crypto::{
    dummy_phrase_wrap, DeviceHpkePublic, DeviceSigningPublic, PHRASE_CIPHERSUITE,
};
use sealbook_protocol::{DevicePublicKeys, DualSignatureBody, ErrorBody, KeyWrapBody};

pub mod healthcheck;
mod manifest;
mod rate_limit;
pub mod tls;

mod account;
mod auth;
mod client_ip;
mod db;
mod devices;
mod http;
mod objects;
mod pairing;
mod recovery;
mod roster;
mod session;
mod validate;

use account::*;
use auth::*;
use client_ip::TrustedProxies;
use db::*;
use devices::*;
use http::*;
use objects::*;
use pairing::*;
use rate_limit::RateLimiter;
use recovery::*;
use session::*;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;

/// A login challenge that has been issued but not yet opened by the device.
struct PendingChallenge {
    username: String,
    device_id: Uuid,
    challenge: [u8; 32],
    created: Instant,
}

struct PendingLogin {
    state: OpaqueServerLogin,
    created: Instant,
    username: String,
    device_id: Uuid,
    challenge: [u8; 32],
}

struct PendingPair {
    username: String,
    account_id: Option<String>,
    device: DevicePublicKeys,
    enrollment_signature: DualSignatureBody,
    confirm: String,
    pair_code: String,
    created: Instant,
    approved: bool,
}

struct PendingRecovery {
    username: String,
    challenge: [u8; 32],
    created: Instant,
}

struct PendingPasswordChange {
    account_id: String,
    device_id: String,
    challenge: [u8; 32],
    created: Instant,
}

/// A challenge issued for an account mutation, pending its signed request.
struct PendingAccountOp {
    account_id: String,
    device_id: String,
    challenge: [u8; 32],
    created: Instant,
}

/// Per-account storage ceilings, so one account cannot fill the volume.
///
/// Enforced on writes only: a rotation replaces objects rather than adding them,
/// and refusing one would leave a revoked device holding a key that still works.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_objects: i64,
    pub max_bytes: i64,
    /// Largest rotation request body this server will accept, and therefore the
    /// real ceiling on a vault's size — see `rotation_body_estimate`.
    pub max_rotation_body: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_objects: 50_000,
            // Sized so that a vault at *both* ceilings at once, 50,000 objects
            // totalling this many padded bytes, still fits in one rotation body,
            // which `the_default_quota_can_be_rotated` checks.
            //
            // Raised from 32 MiB for notes, which are the first content type that
            // is routinely large: at the 4 MiB per-object ceiling the old quota
            // was 8 objects deep, and hitting it blocks *every* write, contacts
            // included, not just the oversized one.
            max_bytes: 128 * 1024 * 1024,
            // Two of these may be buffered and JSON-parsed whole at once
            // (`MAX_CONCURRENT_ROTATIONS`), so this is the server's peak memory
            // and not a free number to raise. It tracks `max_bytes`: the estimate
            // for a vault at both ceilings is roughly 187 MiB, and
            // `rotatable_bytes_ceiling` must stay above `max_bytes` or writes are
            // refused before the quota is reached.
            max_rotation_body: 256 * 1024 * 1024,
        }
    }
}

impl Limits {
    fn from_env() -> Self {
        fn read(name: &str, default: i64) -> i64 {
            std::env::var(name)
                .ok()
                .and_then(|value| value.parse::<i64>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(default)
        }
        let defaults = Self::default();
        Self {
            max_objects: read("SEALBOOK_MAX_OBJECTS", defaults.max_objects),
            max_bytes: read("SEALBOOK_MAX_BYTES", defaults.max_bytes),
            max_rotation_body: read(
                "SEALBOOK_MAX_ROTATION_BODY",
                defaults.max_rotation_body as i64,
            ) as usize,
        }
    }

    /// Whether a vault of this shape could still be rotated.
    ///
    /// Checked on every write, so that a vault can never grow into a state where
    /// revoking a device is impossible.
    fn rotation_fits(&self, objects: i64, padded_bytes: i64) -> bool {
        rotation_body_estimate(objects, padded_bytes) <= self.max_rotation_body as i64
    }

    /// The largest vault, in padded bytes, that can still be rotated. Logged at
    /// startup so an operator sees the effective ceiling rather than inferring it.
    fn rotatable_bytes_ceiling(&self) -> i64 {
        let budget = (self.max_rotation_body as i64).saturating_sub(ROTATION_ENVELOPE);
        (budget.max(0) * 3 / 4).saturating_sub(16)
    }
}

/// Fixed cost of a rotation body: the new key wraps for every device, the phrase
/// recovery record, and the signed manifest. Generous, so it covers a fully
/// populated device list.
const ROTATION_ENVELOPE: i64 = 128 * 1024;

/// JSON scaffolding per rotated object: the field names, the object id, nonce,
/// revision, padded size, content type and tombstone flag. Rounded up.
const ROTATION_PER_OBJECT_OVERHEAD: i64 = 320;

/// Bytes of JSON a rotation request would carry for a vault of this shape.
///
/// A rotation re-encrypts the entire vault in one request body, so a vault that
/// has outgrown `max_rotation_body` cannot be rotated — and a rotation that
/// cannot be sent means a revoked device keeps a collection key that still opens
/// everything it ever synced. That is the failure this projection exists to stop:
/// checking it on every write turns a silently failed revocation later into a
/// refused write now.
///
/// Deliberately an over-estimate. Each object's ciphertext is its padded
/// plaintext plus a 16-byte AEAD tag, which base64url expands by four thirds.
pub(crate) fn rotation_body_estimate(objects: i64, padded_bytes: i64) -> i64 {
    let ciphertext = padded_bytes.saturating_add(objects.saturating_mul(16));
    let encoded = ciphertext.saturating_mul(4).saturating_add(2) / 3;
    ROTATION_ENVELOPE
        .saturating_add(objects.saturating_mul(ROTATION_PER_OBJECT_OVERHEAD))
        .saturating_add(encoded)
}

struct AppState {
    db: Pool<Sqlite>,
    limits: Limits,
    opaque: OpaqueServerSetup,
    dummy_record: Vec<u8>,
    dummy_hpke_pk: DeviceHpkePublic,
    dummy_phrase_wrap: KeyWrapBody,
    dummy_phrase_recovery_pk: DeviceSigningPublic,
    pending_challenges: Mutex<HashMap<Uuid, PendingChallenge>>,
    pending_logins: Mutex<HashMap<Uuid, PendingLogin>>,
    pending_pairs: Mutex<HashMap<Uuid, PendingPair>>,
    pending_recoveries: Mutex<HashMap<Uuid, PendingRecovery>>,
    pending_password_changes: Mutex<HashMap<Uuid, PendingPasswordChange>>,
    pending_account_ops: Mutex<HashMap<Uuid, PendingAccountOp>>,
    limiter: RateLimiter,
    trusted_proxies: TrustedProxies,
}

type Shared = Arc<AppState>;

pub async fn app(db_path: &str) -> anyhow::Result<Router> {
    app_with_limits(db_path, Limits::from_env()).await
}

/// Builds the app with explicit storage limits, rather than reading the
/// environment. Tests use this so that one test's quota cannot affect another's.
pub async fn app_with_limits(db_path: &str, limits: Limits) -> anyhow::Result<Router> {
    let db = open_migrated(db_path).await?;
    verify_db_integrity(&db).await?;
    let opaque = load_or_create_setup(&db).await?;
    let dummy_record = load_or_create_dummy(&db, &opaque).await?;
    let dummy_hpke_pk = load_or_create_dummy_hpke(&db).await?;
    let dummy_phrase = dummy_phrase_wrap()?;
    let dummy_phrase_wrap = KeyWrapBody {
        recipient_kind: "phrase".into(),
        recipient_id: "dummy".into(),
        hpke_enc: dummy_phrase.nonce.to_vec(),
        wrapped_ck: dummy_phrase.ciphertext,
        ciphersuite: PHRASE_CIPHERSUITE.into(),
    };
    let dummy_phrase_recovery_pk = load_or_create_dummy_phrase_pk(&db).await?;
    let state = Arc::new(AppState {
        db,
        limits,
        opaque,
        dummy_record,
        dummy_hpke_pk,
        dummy_phrase_wrap,
        dummy_phrase_recovery_pk,
        pending_challenges: Mutex::new(HashMap::new()),
        pending_logins: Mutex::new(HashMap::new()),
        pending_pairs: Mutex::new(HashMap::new()),
        pending_recoveries: Mutex::new(HashMap::new()),
        pending_password_changes: Mutex::new(HashMap::new()),
        pending_account_ops: Mutex::new(HashMap::new()),
        limiter: RateLimiter::new(),
        trusted_proxies: TrustedProxies::from_env(),
    });
    spawn_session_sweeper(state.clone());
    Ok(router(state.clone()).with_state(state))
}

/// Interval between sweeps of the sessions table.
const SESSION_SWEEP_INTERVAL: Duration = Duration::from_secs(900);

/// Deletes sessions whose expiry has passed.
///
/// Expiry is already enforced when a token is presented, so this is purely
/// housekeeping: without it, every session a user simply walked away from stays
/// in the table forever.
pub(crate) async fn sweep_expired_sessions(db: &Pool<Sqlite>) -> Result<u64, sqlx::Error> {
    let deleted = sqlx::query("DELETE FROM sessions WHERE expires_at < ?")
        .bind(now())
        .execute(db)
        .await?
        .rows_affected();
    Ok(deleted)
}

/// How long a superseded object revision is kept.
///
/// The change feed replays revisions so a client can catch up incrementally, so
/// the log has to outlive any gap a client might realistically have. Beyond that
/// it is dead weight: every write and every rotation appends another full copy of
/// the ciphertext, nothing read it, and the storage quota counts only the live
/// `objects` table — so a long-lived vault's disk use was unbounded and invisible.
///
/// A client that has been away longer than this is not stranded: `changes` says so
/// and serves the full current state instead, which is complete because tombstones
/// live in `objects` rather than only in the log.
fn revision_retention() -> Duration {
    const DEFAULT_DAYS: u64 = 30;
    let days = std::env::var("SEALBOOK_REVISION_RETENTION_DAYS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|days| *days > 0)
        .unwrap_or(DEFAULT_DAYS);
    Duration::from_secs(days.saturating_mul(86_400))
}

/// Rows deleted per statement by the retention sweeps.
///
/// One unbounded `DELETE` holds the write lock for as long as it takes and grows
/// the WAL by everything it touches, which on the first sweep after a backlog
/// means blocking every write in the process. Batching gives other writers the
/// lock back between statements.
const PRUNE_BATCH: i64 = 2_000;

/// Bytes charged per retained revision on top of its padded size: the AEAD tag,
/// the row header, the ids and the index entry. Deliberately an over-estimate,
/// like `rotation_body_estimate`.
const REVISION_ROW_OVERHEAD: i64 = 64;

/// Deletes superseded object revisions older than the retention window.
///
/// The newest revision of each account is kept whatever its age, so that a
/// caught-up client still gets an empty incremental answer rather than being sent
/// round a full resync every time it polls an idle vault.
pub async fn prune_old_revisions(
    db: &Pool<Sqlite>,
    retention: Duration,
) -> Result<u64, sqlx::Error> {
    let cutoff = now().saturating_sub(retention.as_secs() as i64);
    let mut total = 0;
    loop {
        let deleted = sqlx::query(
            "DELETE FROM object_revisions WHERE rowid IN (
                 SELECT r.rowid FROM object_revisions r
                 WHERE r.created_at < ?
                   AND r.revision < COALESCE(
                       (SELECT s.next_revision - 1 FROM revision_seq s
                         WHERE s.account_id = r.account_id),
                       0)
                 LIMIT ?)",
        )
        .bind(cutoff)
        .bind(PRUNE_BATCH)
        .execute(db)
        .await?
        .rows_affected();
        total += deleted;
        if deleted < PRUNE_BATCH as u64 {
            return Ok(total);
        }
    }
}

/// Deletes an account's oldest retained revisions once its log outgrows `budget`.
///
/// The storage quota counts only the live `objects` table, so before this the
/// revision log was bounded by the retention window and the write rate and by
/// nothing else: at the rates the limiter permits, one account on a 128 MiB quota
/// could append terabytes a day and every byte stayed for thirty days. Age was
/// capping how long a revision lived, not how many there were.
///
/// Dropping the oldest first raises an away client's chance of being told to
/// resync, which is a supported answer and the same one the age sweep already
/// produces. The newest revision of each account is kept regardless, so a
/// caught-up client is never sent round a resync by this.
pub async fn prune_oversized_revision_logs(
    db: &Pool<Sqlite>,
    budget: i64,
) -> Result<u64, sqlx::Error> {
    let mut total = 0;
    loop {
        // The running total is per account, newest revision first, so `running`
        // is what the log would cost if it were kept back to this row. Every row
        // past the budget goes, oldest first.
        //
        // Both correlated references are qualified: unqualified, `account_id`
        // inside the subquery resolves against `revision_seq` itself, which
        // silently compares every row to one arbitrary account's watermark.
        let deleted = sqlx::query(
            "DELETE FROM object_revisions WHERE rowid IN (
                 SELECT r.rowid FROM (
                     SELECT rowid AS rowid, account_id AS account_id,
                            revision AS revision,
                            SUM(padded_size + ?) OVER (
                                PARTITION BY account_id ORDER BY revision DESC
                                ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
                            ) AS running
                     FROM object_revisions) AS r
                 WHERE r.running > ?
                   AND r.revision < COALESCE(
                       (SELECT s.next_revision - 1 FROM revision_seq s
                         WHERE s.account_id = r.account_id),
                       0)
                 ORDER BY r.running DESC
                 LIMIT ?)",
        )
        .bind(REVISION_ROW_OVERHEAD)
        .bind(budget)
        .bind(PRUNE_BATCH)
        .execute(db)
        .await?
        .rows_affected();
        total += deleted;
        if deleted < PRUNE_BATCH as u64 {
            return Ok(total);
        }
    }
}

fn spawn_session_sweeper(state: Shared) {
    tokio::spawn(async move {
        let retention = revision_retention();
        loop {
            match sweep_expired_sessions(&state.db).await {
                Ok(deleted) if deleted > 0 => {
                    info!(deleted, "swept expired sessions");
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(%error, "sweeping expired sessions failed");
                }
            }
            match prune_old_revisions(&state.db, retention).await {
                Ok(deleted) if deleted > 0 => {
                    info!(deleted, "pruned superseded object revisions");
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(%error, "pruning object revisions failed");
                }
            }
            // The log gets the same byte budget as the live vault, so an account's
            // total footprint stays within about twice its quota however fast it
            // writes, instead of being bounded only by the retention window.
            match prune_oversized_revision_logs(&state.db, state.limits.max_bytes).await {
                Ok(deleted) if deleted > 0 => {
                    info!(deleted, "pruned revision logs past their byte budget");
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(%error, "pruning oversized revision logs failed");
                }
            }
            tokio::time::sleep(SESSION_SWEEP_INTERVAL).await;
        }
    });
}

/// Whether the server is running in production mode, which tightens defaults
/// that are deliberately permissive during development.
pub(crate) fn is_production() -> bool {
    std::env::var("SEALBOOK_ENV")
        .map(|value| value.eq_ignore_ascii_case("production"))
        .unwrap_or(false)
}

pub async fn serve(db_path: &str, bind: &str) -> anyhow::Result<()> {
    tls::install_crypto_provider();
    let tls_dir = std::env::var("SEALBOOK_TLS_DIR").unwrap_or_else(|_| "tls".into());
    let production = is_production();
    let tls_mode = tls::TlsMode::from_env(production)?;
    let material = tls::load_for_mode(Path::new(&tls_dir), tls_mode)?;
    let pq_supported = tls::preferred_kx_is_pq();
    info!(
        pq_required = true,
        pq_supported,
        tls_mode = tls_mode.as_str(),
        "TLS PQ policy initialized"
    );
    // A pinning client needs the certificate itself, not just a promise that one
    // exists, so make the fingerprint available to compare against.
    if tls_mode.clients_pin() {
        info!(
            fingerprint = %tls::fingerprint(&material.cert_der),
            "clients must pin this certificate (sha256)"
        );
    }
    // The rotation budget is the real ceiling on a vault, so say what it works out
    // to rather than leaving an operator to infer it from three separate numbers.
    let limits = Limits::from_env();
    info!(
        max_objects = limits.max_objects,
        max_bytes = limits.max_bytes,
        max_rotation_body = limits.max_rotation_body,
        rotatable_bytes = limits.rotatable_bytes_ceiling(),
        "storage limits"
    );
    if limits.max_bytes > limits.rotatable_bytes_ceiling() {
        tracing::warn!(
            max_bytes = limits.max_bytes,
            rotatable_bytes = limits.rotatable_bytes_ceiling(),
            "SEALBOOK_MAX_BYTES is larger than one key rotation can carry, so writes will be \
             refused before the quota is reached; raise SEALBOOK_MAX_ROTATION_BODY to match, \
             remembering that it is buffered in memory"
        );
    }

    let trusted_proxy_count = TrustedProxies::from_env().len();
    // Rate limits are keyed on the peer address, which behind a proxy is the
    // proxy for every request. Saying the deployment has one while leaving the
    // header untrusted is the combination that silently shares one bucket.
    if tls_mode == tls::TlsMode::Proxy && trusted_proxy_count == 0 {
        tracing::warn!(
            "SEALBOOK_TLS_MODE=proxy but SEALBOOK_TRUSTED_PROXIES is unset; every request \
             will be attributed to the proxy and the whole deployment will share one rate limit"
        );
    }
    // Export the certificate for pinning only where asked. Previously this was
    // written into the working directory on every start, which is surprising
    // and can scatter stale copies that clients then pin to.
    if let Some(export) = std::env::var_os("SEALBOOK_CERT_EXPORT") {
        let export = Path::new(&export);
        std::fs::write(export, &material.cert_pem)
            .with_context(|| format!("write {}", export.display()))?;
        info!(path = %export.display(), "exported server certificate");
    } else if !production {
        // Development convenience: the CLI pins ./cert.pem by default.
        let cwd_cert = Path::new("cert.pem");
        if !cwd_cert.exists() {
            std::fs::write(cwd_cert, &material.cert_pem)?;
        }
    }
    if trusted_proxy_count > 0 {
        info!(
            count = trusted_proxy_count,
            "trusting X-Forwarded-For from configured proxies"
        );
    }
    let app = app(db_path).await?;
    let addr: SocketAddr = bind.parse().context("bind address")?;
    info!("sealbook listening on https://{bind} (TLS 1.3, X25519MLKEM768 preferred)");
    let handle = axum_server::Handle::new();
    tokio::spawn(shutdown_on_signal(handle.clone()));
    axum_server::bind_rustls(
        addr,
        axum_server::tls_rustls::RustlsConfig::from_config(material.server_config),
    )
    .handle(handle)
    .serve(app.into_make_service_with_connect_info::<SocketAddr>())
    .await?;
    info!("shutdown complete");
    Ok(())
}

/// How long in-flight requests get to finish once a shutdown signal arrives.
///
/// Long enough for a key rotation to commit, since that is the one request that
/// carries real work; short enough that a container stop does not hang.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(20);

/// Stops accepting connections on SIGTERM or ctrl-c, then drains.
///
/// Without this the process is killed mid-request on every `docker stop`, restart
/// and redeploy. SQLite's WAL and `synchronous=Full` mean that does not corrupt
/// the database, but it does abort whatever a client was in the middle of.
async fn shutdown_on_signal(handle: axum_server::Handle<SocketAddr>) {
    wait_for_shutdown_signal().await;
    info!(
        grace_seconds = SHUTDOWN_GRACE.as_secs(),
        "shutdown signal received, draining"
    );
    handle.graceful_shutdown(Some(SHUTDOWN_GRACE));
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    match signal(SignalKind::terminate()) {
        Ok(mut terminate) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
        }
        Err(error) => {
            // Falling through to an immediate shutdown would be worse than not
            // handling SIGTERM at all, so wait on ctrl-c alone.
            tracing::warn!(%error, "cannot listen for SIGTERM; only ctrl-c will drain");
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

/// Largest request body accepted on a route that has no override.
///
/// Everything except object writes and key rotation is small and fixed-shape,
/// so a tight limit here is free.
const MAX_BODY: usize = 256 * 1024;

/// Largest request body for a single object write.
///
/// One object is at most `MAX_PADDED_OBJECT_SIZE` of padded plaintext plus a
/// 16-byte tag, which base64url expands by a third: 8 MiB becomes 11,184,832
/// bytes. The write also carries a signed `ManifestBody`, whose ML-DSA-65
/// signature is another few KiB once encoded. Twelve MiB covers both with about
/// a tenth to spare, and `the_object_body_limit_covers_a_maximum_object` holds
/// the two constants together.
///
/// Unlike the rotation route this one has no concurrency limit, so this figure
/// is also the server's memory cost per write in flight.
const MAX_OBJECT_BODY: usize = 12 * 1024 * 1024;

/// How many rotations may be in flight at once.
///
/// A rotation body is buffered and JSON-parsed whole, so peak memory is a few
/// multiples of `Limits::max_rotation_body` per concurrent request. Without a
/// bound, a handful of concurrent rotations is an out-of-memory kill; with one,
/// the cost of the largest route on the server is a number an operator can
/// reason about.
const MAX_CONCURRENT_ROTATIONS: usize = 2;

/// How long a small, fixed-shape request gets before it is abandoned.
///
/// Everything but an object write and a rotation is a handful of kilobytes and a
/// few queries, so anything still running after this is a client that has stalled
/// or a query that has gone wrong. Without a timeout anywhere, a stalled request
/// holds a connection and a database handle until the process restarts.
const SMALL_TIMEOUT: Duration = Duration::from_secs(30);

/// An object write is up to `MAX_OBJECT_BODY`, which takes a while on a slow
/// uplink. Still generous at 12 MiB: it only requires 100 KB/s to finish.
const OBJECT_TIMEOUT: Duration = Duration::from_secs(120);

/// A rotation carries the whole vault and may queue behind another, so it gets
/// the most patience. Still bounded: a rotation that has not finished by now is
/// not going to.
const ROTATION_TIMEOUT: Duration = Duration::from_secs(600);

fn router(state: Shared) -> Router<Shared> {
    // The three route groups differ in how much they may carry and how long they
    // may take, so each gets its own budget rather than one number that has to be
    // generous enough for a rotation and therefore useless for everything else.
    let small = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/health/crypto", get(crypto_profile))
        .route("/v1/opaque/register/start", post(register_start))
        .route("/v1/opaque/register/finish", post(register_finish))
        .route("/v1/opaque/login/challenge", post(login_challenge))
        .route("/v1/opaque/login/start", post(login_start))
        .route("/v1/opaque/login/finish", post(login_finish))
        .route("/v1/collections/{id}/changes", get(changes))
        .route("/v1/collections/{id}/keys", get(collection_keys))
        .route("/v1/collections/{id}/manifest", get(collection_manifest))
        .route(
            "/v1/collections/{id}/roster",
            get(roster::collection_roster),
        )
        .route("/v1/pair/join", post(pair_join))
        .route("/v1/pair/{id}", get(pair_status))
        .route("/v1/pair/{id}/approve", post(pair_approve))
        .route("/v1/recover/start", post(recover_start))
        .route("/v1/recover/finish", post(recover_finish))
        .route("/v1/account/challenge", post(account_challenge))
        .route("/v1/account/username", post(change_username))
        .route("/v1/account/password/start", post(change_password_start))
        .route("/v1/account/password", post(change_password))
        .route("/v1/session", delete(revoke_session))
        .route("/v1/account/devices", get(list_devices))
        .route("/v1/account", delete(delete_account))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            SMALL_TIMEOUT,
        ));

    let objects = Router::new()
        .route("/v1/collections/{id}/objects", put(put_object))
        .layer(DefaultBodyLimit::max(MAX_OBJECT_BODY))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            OBJECT_TIMEOUT,
        ));

    // A rotation carries the entire vault re-encrypted under the new collection
    // key, because only a client can do that work (see `rotate`). The body limit
    // is the operator's, not a constant, and `put_object` refuses any write that
    // would push the vault past what fits — so a rotation is never the request
    // that discovers the vault has grown too large.
    //
    // The concurrency limit sits outside the body limit, so requests over the
    // limit wait before their bodies are buffered rather than after. That is what
    // bounds peak memory: at most `MAX_CONCURRENT_ROTATIONS` bodies exist at once,
    // however many clients ask at the same time.
    let rotation = Router::new()
        .route("/v1/collections/{id}/rotate", post(rotate))
        .layer(DefaultBodyLimit::max(state.limits.max_rotation_body))
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_ROTATIONS))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            ROTATION_TIMEOUT,
        ));

    small
        .merge(objects)
        .merge(rotation)
        .layer(from_fn(security_headers))
        .layer(cors_layer())
}

/// Most entries any one pending-handshake table holds.
const MAX_PENDING: usize = 10_000;

/// Expires stale entries and, if the table is still full, drops the oldest to
/// make room for the newcomer.
///
/// These tables used to refuse the newcomer once full. The cap is global, so that
/// turned a flood of handshakes into a lockout for every other user of the server
/// — a `429` on login for people who had done nothing. Evicting the oldest keeps
/// the cost with whoever is displaced, and a displaced handshake only has to start
/// again.
pub(crate) fn admit<K, V>(
    pending: &mut HashMap<K, V>,
    ttl: Duration,
    created: impl Fn(&V) -> Instant,
) where
    K: std::hash::Hash + Eq + Clone,
{
    pending.retain(|_, entry| created(entry).elapsed() < ttl);
    while pending.len() >= MAX_PENDING {
        let Some(oldest) = pending
            .iter()
            .min_by_key(|(_, entry)| created(entry))
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        pending.remove(&oldest);
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
}

fn err(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ErrorBody>) {
    (status, Json(ErrorBody { error: msg.into() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default quota has to be one that can actually be rotated. It was not:
    /// a 1 GiB vault needed roughly a 1.4 GiB rotation body against a 32 MiB
    /// limit, so an account near its quota failed every revocation with `413` and
    /// the revoked device kept a working collection key.
    #[test]
    fn the_default_quota_can_be_rotated() {
        let limits = Limits::default();
        assert!(
            limits.rotation_fits(limits.max_objects, limits.max_bytes),
            "a vault at the default quota must still fit in one rotation: \
             {} bytes needed, {} allowed",
            rotation_body_estimate(limits.max_objects, limits.max_bytes),
            limits.max_rotation_body
        );
        // And the object quota is reachable rather than decorative: the smallest
        // legal object is 256 padded bytes.
        let smallest = limits.max_objects * sealbook_protocol::MIN_PADDED_OBJECT_SIZE as i64;
        assert!(
            limits.rotation_fits(limits.max_objects, smallest),
            "max_objects must be reachable with minimum-size objects"
        );
    }

    #[test]
    fn a_vault_past_the_rotation_budget_does_not_fit() {
        let limits = Limits::default();
        assert!(!limits.rotation_fits(limits.max_objects, limits.max_bytes * 4));
    }

    /// The pairing `MAX_OBJECT_BODY` claims in prose, checked. Nothing held these
    /// two together before, which is how the ceiling once sat at 16 MiB behind a
    /// 256 KiB route limit.
    #[test]
    fn the_object_body_limit_covers_a_maximum_object() {
        let encoded = (sealbook_protocol::MAX_PADDED_OBJECT_SIZE + 16).div_ceil(3) * 4;
        assert!(
            MAX_OBJECT_BODY > encoded + 64 * 1024,
            "a maximum object encodes to {encoded} bytes, which {MAX_OBJECT_BODY} \
             does not cover with room for a signed manifest"
        );
    }

    /// Base64 is four bytes out for every three in, so the estimate has to be
    /// above the raw ciphertext or the check it guards is worthless.
    #[test]
    fn the_rotation_estimate_covers_base64_expansion() {
        let raw = 3 * 1024 * 1024;
        let estimate = rotation_body_estimate(1, raw);
        assert!(
            estimate > raw * 4 / 3,
            "estimate {estimate} does not cover {raw} bytes of base64"
        );
    }

    #[tokio::test]
    async fn a_full_pending_table_evicts_the_oldest_rather_than_the_newcomer() {
        #[derive(Debug)]
        struct Entry {
            created: Instant,
            tag: usize,
        }
        let mut pending: HashMap<usize, Entry> = HashMap::new();
        // Fill past capacity, oldest first.
        let base = Instant::now();
        for tag in 0..MAX_PENDING + 16 {
            admit(&mut pending, Duration::from_secs(120), |entry| {
                entry.created
            });
            pending.insert(
                tag,
                Entry {
                    created: base + Duration::from_millis(tag as u64),
                    tag,
                },
            );
        }
        assert!(pending.len() <= MAX_PENDING);
        // The newest arrivals survived; something old was displaced instead of the
        // newcomer being turned away, which is what used to happen and which
        // returned `429` to every other user of the server.
        let newest = MAX_PENDING + 15;
        assert!(
            pending.contains_key(&newest),
            "the newest entry must have been admitted"
        );
        assert!(
            pending.values().all(|entry| entry.tag > 0),
            "the oldest entries should have been the ones evicted"
        );
    }

    #[cfg(test)]
    async fn seed_account(db: &Pool<Sqlite>, account: &str, device: &str, collection: &str) {
        sqlx::query(
            "INSERT INTO accounts (id, username, opaque_record, kdf_salt, created_at)
             VALUES (?, ?, X'', X'', 0)",
        )
        .bind(account)
        .bind(account)
        .execute(db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO devices (id, account_id, mldsa_pk, ed25519_pk, xwing_hpke_pk, created_at)
             VALUES (?, ?, X'', X'', X'', 0)",
        )
        .bind(device)
        .bind(account)
        .execute(db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO collections (id, account_id, kind, created_at) VALUES (?, ?, 'vault', 0)",
        )
        .bind(collection)
        .bind(account)
        .execute(db)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn pruning_caps_a_revision_log_that_outgrows_its_byte_budget() {
        let dir = std::env::temp_dir().join(format!("sealbook-budget-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_file = dir.join("sealbook.db");
        let db_path = db_file.to_str().unwrap().to_string();
        let _ = app(&db_path).await.unwrap();
        let db = sqlx::SqlitePool::connect(&format!("sqlite://{}", db_file.display()))
            .await
            .unwrap();

        seed_account(&db, "one", "device-one", "collection-one").await;
        seed_account(&db, "two", "device-two", "collection-two").await;
        for account in ["one", "two"] {
            sqlx::query("INSERT INTO revision_seq (account_id, next_revision) VALUES (?, 6)")
                .bind(account)
                .execute(&db)
                .await
                .unwrap();
            // Five revisions of 1,000 padded bytes each, all brand new, so the age
            // sweep would keep every one of them.
            for revision in 1..=5 {
                sqlx::query(
                    "INSERT INTO object_revisions
                     (account_id, revision, collection_id, object_id, tombstone,
                      padded_size, created_at)
                     VALUES (?, ?, 'collection', 'object', 0, 1000, ?)",
                )
                .bind(account)
                .bind(revision)
                .bind(now())
                .execute(&db)
                .await
                .unwrap();
            }
        }

        // Room for two rows of 1,000 + 64 bytes, not three.
        let deleted = prune_oversized_revision_logs(&db, 2 * (1000 + 64))
            .await
            .unwrap();
        assert_eq!(deleted, 6, "three rows per account should have gone");

        for account in ["one", "two"] {
            let kept: Vec<i64> = sqlx::query_scalar(
                "SELECT revision FROM object_revisions WHERE account_id = ?
                 ORDER BY revision",
            )
            .bind(account)
            .fetch_all(&db)
            .await
            .unwrap();
            assert_eq!(
                kept,
                vec![4, 5],
                "account {account} kept the wrong revisions"
            );
        }

        db.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A budget smaller than a single revision must still not take the newest one,
    /// or a caught-up client is sent round a resync on every poll.
    #[tokio::test]
    async fn the_byte_budget_never_drops_an_account_s_newest_revision() {
        let dir = std::env::temp_dir().join(format!("sealbook-budget-min-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_file = dir.join("sealbook.db");
        let db_path = db_file.to_str().unwrap().to_string();
        let _ = app(&db_path).await.unwrap();
        let db = sqlx::SqlitePool::connect(&format!("sqlite://{}", db_file.display()))
            .await
            .unwrap();

        seed_account(&db, "account", "device", "collection").await;
        sqlx::query("INSERT INTO revision_seq (account_id, next_revision) VALUES ('account', 3)")
            .execute(&db)
            .await
            .unwrap();
        for revision in 1..=2 {
            sqlx::query(
                "INSERT INTO object_revisions
                 (account_id, revision, collection_id, object_id, tombstone,
                  padded_size, created_at)
                 VALUES ('account', ?, 'collection', 'object', 0, 4096, ?)",
            )
            .bind(revision)
            .bind(now())
            .execute(&db)
            .await
            .unwrap();
        }

        prune_oversized_revision_logs(&db, 1).await.unwrap();

        let kept: Vec<i64> =
            sqlx::query_scalar("SELECT revision FROM object_revisions ORDER BY revision")
                .fetch_all(&db)
                .await
                .unwrap();
        assert_eq!(kept, vec![2], "the newest revision must survive any budget");

        db.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pruning_drops_aged_revisions_but_keeps_the_newest() {
        let dir = std::env::temp_dir().join(format!("sealbook-prune-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_file = dir.join("sealbook.db");
        let db_path = db_file.to_str().unwrap().to_string();
        let _ = app(&db_path).await.unwrap();
        let db = sqlx::SqlitePool::connect(&format!("sqlite://{}", db_file.display()))
            .await
            .unwrap();

        seed_account(&db, "account", "device", "collection").await;
        sqlx::query("INSERT INTO revision_seq (account_id, next_revision) VALUES ('account', 4)")
            .execute(&db)
            .await
            .unwrap();
        // Revisions 1 and 2 are old and superseded; 3 is the newest the account has
        // assigned, so it survives whatever its age.
        for (revision, created) in [(1, 0), (2, 0), (3, 0)] {
            sqlx::query(
                "INSERT INTO object_revisions
                 (account_id, revision, collection_id, object_id, tombstone, created_at)
                 VALUES ('account', ?, 'collection', 'object', 0, ?)",
            )
            .bind(revision)
            .bind(created)
            .execute(&db)
            .await
            .unwrap();
        }

        let deleted = prune_old_revisions(&db, Duration::from_secs(86_400))
            .await
            .unwrap();
        assert_eq!(deleted, 2, "only the superseded revisions should go");
        let remaining: Vec<i64> =
            sqlx::query_scalar("SELECT revision FROM object_revisions ORDER BY revision")
                .fetch_all(&db)
                .await
                .unwrap();
        assert_eq!(
            remaining,
            vec![3],
            "the newest revision must survive, so a caught-up client is not sent \
             round a full resync on every poll"
        );

        // A fresh revision inside the window is left alone.
        sqlx::query(
            "INSERT INTO object_revisions
             (account_id, revision, collection_id, object_id, tombstone, created_at)
             VALUES ('account', 4, 'collection', 'object', 0, ?)",
        )
        .bind(now())
        .execute(&db)
        .await
        .unwrap();
        sqlx::query("UPDATE revision_seq SET next_revision = 6 WHERE account_id = 'account'")
            .execute(&db)
            .await
            .unwrap();
        assert_eq!(
            prune_old_revisions(&db, Duration::from_secs(86_400))
                .await
                .unwrap(),
            1,
            "revision 3 is now superseded and aged out; 4 is still fresh"
        );

        db.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn the_sweeper_removes_only_expired_sessions() {
        let dir = std::env::temp_dir().join(format!("sealbook-sweep-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_file = dir.join("sealbook.db");
        let db_path = db_file.to_str().unwrap().to_string();

        // app() builds the schema; then talk to the same file directly.
        let _ = app(&db_path).await.unwrap();
        let db = sqlx::SqlitePool::connect(&format!("sqlite://{}", db_file.display()))
            .await
            .unwrap();

        seed_account(&db, "account", "device", "collection").await;
        for (token, expires) in [
            (b"live".as_slice(), now() + 3600),
            (b"dead".as_slice(), now() - 1),
        ] {
            sqlx::query(
                "INSERT INTO sessions (token_hash, account_id, device_id, expires_at, created_at)
                 VALUES (?, 'account', 'device', ?, 0)",
            )
            .bind(token)
            .bind(expires)
            .execute(&db)
            .await
            .unwrap();
        }

        let deleted = sweep_expired_sessions(&db).await.unwrap();
        assert_eq!(deleted, 1, "only the expired session should go");

        let remaining: Vec<Vec<u8>> = sqlx::query_scalar("SELECT token_hash FROM sessions")
            .fetch_all(&db)
            .await
            .unwrap();
        assert_eq!(remaining, vec![b"live".to_vec()]);

        db.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
