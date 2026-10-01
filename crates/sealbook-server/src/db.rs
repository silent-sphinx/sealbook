//! Database lifecycle: opening the pool, the schema migrations, and the
//! one-time server secrets that are generated on first start.

use std::fs::OpenOptions;
use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Pool, Row, Sqlite};

use sealbook_crypto::opaque::{
    deserialize_server_setup, dummy_server_record, new_server_setup, serialize_server_setup,
    OpaqueServerSetup,
};
use sealbook_crypto::{
    dummy_phrase_recovery_public, generate_device_hpke, DeviceHpkePublic, DeviceSigningPublic,
    ED25519_PUBLIC_KEY_LEN, MLDSA65_PUBLIC_KEY_LEN,
};

pub(crate) async fn open_db(path: &str) -> anyhow::Result<Pool<Sqlite>> {
    let db_path = Path::new(path);
    if let Some(parent) = db_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    if !db_path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(db_path)?;
        }
        #[cfg(not(unix))]
        {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(db_path)?;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(db_path, std::fs::Permissions::from_mode(0o600))?;
    }
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full)
        .busy_timeout(Duration::from_secs(5))
        .foreign_keys(true);
    SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .with_context(|| format!("open sqlite {path}"))
}

/// Schema version this build expects.
///
/// Stored in SQLite's `user_version` header field, which is transactional, so a
/// migration and the version bump that records it commit together or not at all.
/// Bump this and add a step to `migrate` when the schema changes.
pub(crate) const SCHEMA_VERSION: i64 = 1;

/// Brings the database up to `SCHEMA_VERSION`.
///
/// Each step runs at most once per database. A database from a newer build is
/// refused rather than opened hopefully, since this build would silently ignore
/// columns it does not know about.
pub(crate) async fn migrate(db: &Pool<Sqlite>) -> anyhow::Result<()> {
    let version = schema_version(db).await?;
    if version > SCHEMA_VERSION {
        anyhow::bail!(
            "database is at schema version {version} but this build of \
             sealbook-server understands only {SCHEMA_VERSION}; run a newer build \
             against it rather than downgrading"
        );
    }
    if version < 1 {
        migrate_to_v1(db).await?;
    }
    Ok(())
}

pub(crate) async fn schema_version(db: &Pool<Sqlite>) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar::<_, i64>("PRAGMA user_version")
        .fetch_one(db)
        .await?)
}

/// The schema, as one step.
///
/// Sealbook has had exactly one released protocol, so there is no earlier shape to
/// upgrade from and no back-fill to run: a database is either current or brand new.
async fn migrate_to_v1(db: &Pool<Sqlite>) -> anyhow::Result<()> {
    let mut tx = db.begin().await?;
    {
        let db = &mut *tx;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS meta (
                k TEXT PRIMARY KEY,
                v BLOB NOT NULL
            )",
        )
        .execute(&mut *db)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                opaque_record BLOB NOT NULL,
                kdf_salt BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                phrase_mldsa_pk BLOB,
                phrase_ed25519_pk BLOB,
                phrase_lookup_id BLOB,
                phrase_scheme TEXT
            )",
        )
        .execute(&mut *db)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL,
                mldsa_pk BLOB NOT NULL,
                ed25519_pk BLOB NOT NULL,
                xwing_hpke_pk BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                revoked_at INTEGER
            )",
        )
        .execute(&mut *db)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS sessions (
                token_hash BLOB PRIMARY KEY,
                account_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL DEFAULT 0
            )",
        )
        .execute(&mut *db)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS collections (
                id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                key_epoch INTEGER NOT NULL DEFAULT 1
            )",
        )
        .execute(&mut *db)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS key_wraps (
                collection_id TEXT NOT NULL,
                recipient_kind TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                hpke_enc BLOB NOT NULL,
                wrapped_ck BLOB NOT NULL,
                ciphersuite TEXT NOT NULL,
                PRIMARY KEY (collection_id, recipient_kind, recipient_id)
            )",
        )
        .execute(&mut *db)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS objects (
                id TEXT NOT NULL,
                collection_id TEXT NOT NULL,
                account_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                tombstone INTEGER NOT NULL DEFAULT 0,
                ciphertext BLOB NOT NULL,
                nonce BLOB NOT NULL,
                padded_size INTEGER NOT NULL,
                content_type TEXT NOT NULL,
                content_digest BLOB NOT NULL DEFAULT X'',
                PRIMARY KEY (account_id, collection_id, id)
            )",
        )
        .execute(&mut *db)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS object_revisions (
                account_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                collection_id TEXT NOT NULL,
                object_id TEXT NOT NULL,
                tombstone INTEGER NOT NULL,
                ciphertext BLOB NOT NULL DEFAULT X'',
                nonce BLOB NOT NULL DEFAULT X'',
                padded_size INTEGER NOT NULL DEFAULT 0,
                content_type TEXT NOT NULL DEFAULT 'application/jscontact+json',
                content_digest BLOB NOT NULL DEFAULT X'',
                created_at INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (account_id, revision)
            )",
        )
        .execute(&mut *db)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS revision_seq (
                account_id TEXT PRIMARY KEY,
                next_revision INTEGER NOT NULL
            )",
        )
        .execute(&mut *db)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS manifests (
                collection_id TEXT PRIMARY KEY,
                manifest_seq INTEGER NOT NULL,
                key_epoch INTEGER NOT NULL,
                latest_revision INTEGER NOT NULL,
                object_count INTEGER NOT NULL,
                digest BLOB NOT NULL,
                device_id TEXT NOT NULL,
                mldsa_sig BLOB NOT NULL,
                ed25519_sig BLOB NOT NULL,
                updated_at INTEGER NOT NULL
            )",
        )
        .execute(&mut *db)
        .await?;

        // The change feed pages on (account_id, revision); the retention sweep
        // scans created_at. Without these, both are full scans of the largest
        // table in the database.
        for statement in [
            "CREATE INDEX IF NOT EXISTS object_revisions_account_revision
                 ON object_revisions (account_id, revision)",
            "CREATE INDEX IF NOT EXISTS object_revisions_created_at
                 ON object_revisions (created_at)",
            "CREATE INDEX IF NOT EXISTS objects_account_collection
                 ON objects (account_id, collection_id)",
            "CREATE INDEX IF NOT EXISTS sessions_expires_at ON sessions (expires_at)",
            "CREATE INDEX IF NOT EXISTS devices_account ON devices (account_id)",
        ] {
            sqlx::query(statement).execute(&mut *db).await?;
        }

        sqlx::query("PRAGMA user_version = 1")
            .execute(&mut *db)
            .await?;
    }
    tx.commit().await?;
    tracing::info!(version = 1, "database schema created");
    Ok(())
}

/// Refuses to start on a corrupt database.
///
/// `quick_check` by default: it finds the corruption that matters — a damaged
/// page, a broken index — without the full row-by-row pass, which is O(database)
/// and was making startup time grow with the vault. Set
/// `SEALBOOK_FULL_INTEGRITY_CHECK=1` to do the exhaustive one, which is worth it
/// after a crash or a restore.
pub(crate) async fn verify_db_integrity(db: &Pool<Sqlite>) -> anyhow::Result<()> {
    let full = std::env::var("SEALBOOK_FULL_INTEGRITY_CHECK")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let pragma = if full {
        "PRAGMA integrity_check"
    } else {
        "PRAGMA quick_check"
    };
    let result: String = sqlx::query_scalar(pragma).fetch_one(db).await?;
    if result != "ok" {
        anyhow::bail!("sqlite {pragma} failed: {result}");
    }
    Ok(())
}

pub(crate) async fn load_or_create_setup(db: &Pool<Sqlite>) -> anyhow::Result<OpaqueServerSetup> {
    let row = sqlx::query("SELECT v FROM meta WHERE k = 'opaque_setup'")
        .fetch_optional(db)
        .await?;
    if let Some(row) = row {
        let bytes: Vec<u8> = row.get("v");
        return Ok(deserialize_server_setup(&bytes)?);
    }
    let setup = new_server_setup();
    let bytes = serialize_server_setup(&setup);
    sqlx::query("INSERT INTO meta (k, v) VALUES ('opaque_setup', ?)")
        .bind(&bytes)
        .execute(db)
        .await?;
    Ok(setup)
}

pub(crate) async fn load_or_create_dummy(
    db: &Pool<Sqlite>,
    setup: &OpaqueServerSetup,
) -> anyhow::Result<Vec<u8>> {
    let row = sqlx::query("SELECT v FROM meta WHERE k = 'opaque_dummy'")
        .fetch_optional(db)
        .await?;
    if let Some(row) = row {
        let bytes: Vec<u8> = row.get("v");
        return Ok(bytes);
    }
    let dummy = dummy_server_record(setup)?;
    sqlx::query("INSERT INTO meta (k, v) VALUES ('opaque_dummy', ?)")
        .bind(&dummy)
        .execute(db)
        .await?;
    Ok(dummy)
}

pub(crate) async fn load_or_create_dummy_hpke(
    db: &Pool<Sqlite>,
) -> anyhow::Result<DeviceHpkePublic> {
    let row = sqlx::query("SELECT v FROM meta WHERE k = 'dummy_hpke_pk'")
        .fetch_optional(db)
        .await?;
    if let Some(row) = row {
        let bytes: Vec<u8> = row.get("v");
        return Ok(DeviceHpkePublic(bytes));
    }
    let (_sk, pk) = generate_device_hpke()?;
    sqlx::query("INSERT INTO meta (k, v) VALUES ('dummy_hpke_pk', ?)")
        .bind(&pk.0)
        .execute(db)
        .await?;
    Ok(pk)
}

/// A stable recovery public key for accounts that do not exist, so that a
/// recovery attempt against an unknown username does the same verification work
/// as one against a real account.
pub(crate) async fn load_or_create_dummy_phrase_pk(
    db: &Pool<Sqlite>,
) -> anyhow::Result<DeviceSigningPublic> {
    let row = sqlx::query("SELECT v FROM meta WHERE k = 'dummy_phrase_recovery_pk'")
        .fetch_optional(db)
        .await?;
    let bytes: Vec<u8> = match row {
        Some(row) => row.get("v"),
        None => {
            let public = dummy_phrase_recovery_public()?;
            let mut bytes = public.mldsa_pk.clone();
            bytes.extend_from_slice(&public.ed25519_pk);
            sqlx::query("INSERT INTO meta (k, v) VALUES ('dummy_phrase_recovery_pk', ?)")
                .bind(&bytes)
                .execute(db)
                .await?;
            bytes
        }
    };
    if bytes.len() != MLDSA65_PUBLIC_KEY_LEN + ED25519_PUBLIC_KEY_LEN {
        anyhow::bail!("stored dummy phrase recovery key has the wrong length");
    }
    let (mldsa_pk, ed25519_pk) = bytes.split_at(MLDSA65_PUBLIC_KEY_LEN);
    Ok(DeviceSigningPublic {
        mldsa_pk: mldsa_pk.to_vec(),
        ed25519_pk: ed25519_pk.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn temp_db() -> (std::path::PathBuf, Pool<Sqlite>) {
        let dir = std::env::temp_dir().join(format!("sealbook-db-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sealbook.db");
        let db = open_db(path.to_str().unwrap()).await.unwrap();
        (dir, db)
    }

    #[tokio::test]
    async fn migration_records_its_version() {
        let (dir, db) = temp_db().await;
        assert_eq!(schema_version(&db).await.unwrap(), 0, "a new file is at 0");
        migrate(&db).await.unwrap();
        assert_eq!(schema_version(&db).await.unwrap(), SCHEMA_VERSION);
        db.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn migrating_an_already_current_database_changes_nothing() {
        let (dir, db) = temp_db().await;
        migrate(&db).await.unwrap();
        sqlx::query(
            "INSERT INTO objects
             (id, collection_id, account_id, revision, tombstone, ciphertext, nonce,
              padded_size, content_type, content_digest)
             VALUES ('object-one', 'collection', 'account', 1, 0, X'00', X'01', 256,
                     'application/jscontact+json', X'02')",
        )
        .execute(&db)
        .await
        .unwrap();

        // Starting again must not touch what is already there. Before the schema was
        // versioned, every start re-read and re-wrote the whole objects table.
        migrate(&db).await.unwrap();

        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM objects")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(rows, 1);
        assert_eq!(schema_version(&db).await.unwrap(), SCHEMA_VERSION);

        db.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_database_from_a_newer_build_is_refused() {
        let (dir, db) = temp_db().await;
        migrate(&db).await.unwrap();
        sqlx::query(&format!("PRAGMA user_version = {}", SCHEMA_VERSION + 1))
            .execute(&db)
            .await
            .unwrap();

        let error = migrate(&db).await.expect_err("should refuse to open");
        assert!(
            error.to_string().contains("newer"),
            "unhelpful error: {error}"
        );

        db.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Every index the hot paths rely on. Without them the change feed and the
    /// revision sweep are full scans of the biggest table there is.
    #[tokio::test]
    async fn the_schema_carries_the_indexes_the_hot_queries_need() {
        let (dir, db) = temp_db().await;
        migrate(&db).await.unwrap();
        let indexes: Vec<String> =
            sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'index'")
                .fetch_all(&db)
                .await
                .unwrap();
        for expected in [
            "object_revisions_account_revision",
            "object_revisions_created_at",
            "objects_account_collection",
            "sessions_expires_at",
            "devices_account",
        ] {
            assert!(
                indexes.iter().any(|name| name == expected),
                "missing index {expected}; have {indexes:?}"
            );
        }
        db.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn the_schema_carries_every_table_the_server_writes_to() {
        let (dir, db) = temp_db().await;
        migrate(&db).await.unwrap();
        let tables: Vec<String> =
            sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table'")
                .fetch_all(&db)
                .await
                .unwrap();
        for expected in [
            "meta",
            "accounts",
            "devices",
            "sessions",
            "collections",
            "key_wraps",
            "objects",
            "object_revisions",
            "revision_seq",
            "manifests",
        ] {
            assert!(
                tables.iter().any(|name| name == expected),
                "missing table {expected}; have {tables:?}"
            );
        }
        db.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }
}
