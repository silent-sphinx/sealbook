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

/// Opens `path`, brings it to `SCHEMA_VERSION`, and returns a pool for serving.
pub(crate) async fn open_migrated(path: &str) -> anyhow::Result<Pool<Sqlite>> {
    let migrating = open_db(path).await?;
    let result = migrate(&migrating).await;
    migrating.close().await;
    result?;
    open_db(path).await
}

/// Schema version this build expects.
///
/// Stored in SQLite's `user_version` header field, which is transactional, so a
/// migration and the version bump that records it commit together or not at all.
/// Bump this and add a step to `migrate` when the schema changes.
pub(crate) const SCHEMA_VERSION: i64 = 2;

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
    if version < 2 {
        migrate_to_v2(db).await?;
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
                revoked_at INTEGER,
                FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
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
                created_at INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE,
                FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
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
                key_epoch INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
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
                PRIMARY KEY (collection_id, recipient_kind, recipient_id),
                FOREIGN KEY (collection_id) REFERENCES collections (id) ON DELETE CASCADE
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
                PRIMARY KEY (account_id, collection_id, id),
                FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE,
                FOREIGN KEY (collection_id) REFERENCES collections (id) ON DELETE CASCADE
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
                PRIMARY KEY (account_id, revision),
                FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
            )",
        )
        .execute(&mut *db)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS revision_seq (
                account_id TEXT PRIMARY KEY,
                next_revision INTEGER NOT NULL,
                object_count INTEGER NOT NULL DEFAULT 0,
                byte_total INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
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
                updated_at INTEGER NOT NULL,
                FOREIGN KEY (collection_id) REFERENCES collections (id) ON DELETE CASCADE
            )",
        )
        .execute(&mut *db)
        .await?;

        // The retention sweep scans created_at, which nothing else indexes.
        // The change feed pages on (account_id, revision), which is already
        // `object_revisions`' primary key, so the implicit index serves it and an
        // explicit copy would only be a second b-tree to maintain.
        for statement in [
            "CREATE INDEX IF NOT EXISTS object_revisions_created_at
                 ON object_revisions (created_at)",
            // Covers both scans every PUT runs: the account's `padded_size` for the
            // quota check and the collection's `content_digest` for the manifest.
            //
            // `revision` sits ahead of `id` so the same index also orders the
            // snapshot walk. Without that the walk sorts the whole collection,
            // ciphertexts and all, through a temp b-tree on every page it serves,
            // rather than reading just the page it was asked for.
            "CREATE INDEX IF NOT EXISTS objects_account_meta
                 ON objects (account_id, collection_id, revision, id, tombstone,
                             padded_size, content_digest)",
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

/// The indexes the two foreign-key cascades need, and the tombstone counter the
/// quota needs in order to tell a deleted object from a live one.
///
/// A `FOREIGN KEY ... ON DELETE CASCADE` is only as fast as the child table's
/// index on the referencing column. Neither `sessions.account_id` nor
/// `objects.collection_id` leads an index in v1, so deleting one account scanned
/// every session and every object in the database, and so did the account-wide
/// session delete that a password change, a rename and a recovery each run.
async fn migrate_to_v2(db: &Pool<Sqlite>) -> anyhow::Result<()> {
    let mut tx = db.begin().await?;
    {
        let db = &mut *tx;
        for statement in [
            // One index per referencing column, because the two cascades arrive
            // from opposite directions: `accounts` knows only an account id,
            // `devices` only a device id, and a composite can lead on just one of
            // them. `sessions_account` also serves the account-wide session
            // delete that a password change, a rename and a recovery each run.
            "CREATE INDEX IF NOT EXISTS sessions_account ON sessions (account_id)",
            "CREATE INDEX IF NOT EXISTS sessions_device ON sessions (device_id)",
            // `objects`' primary key leads on `account_id`, so the cascade from
            // `collections`, which knows only a collection id, could not use it.
            "CREATE INDEX IF NOT EXISTS objects_collection
                 ON objects (collection_id)",
        ] {
            sqlx::query(statement).execute(&mut *db).await?;
        }

        sqlx::query(
            "ALTER TABLE revision_seq
                 ADD COLUMN tombstone_count INTEGER NOT NULL DEFAULT 0",
        )
        .execute(&mut *db)
        .await?;
        // Back-filled from the rows themselves, so an existing vault starts
        // counting from the truth rather than from zero.
        sqlx::query(
            "UPDATE revision_seq
                 SET tombstone_count = COALESCE(
                     (SELECT COUNT(*) FROM objects o
                       WHERE o.account_id = revision_seq.account_id
                         AND o.tombstone = 1),
                     0)",
        )
        .execute(&mut *db)
        .await?;

        sqlx::query("PRAGMA user_version = 2")
            .execute(&mut *db)
            .await?;
    }
    tx.commit().await?;
    tracing::info!(version = 2, "database schema migrated");
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
        // The object hangs off a real account and collection, because the schema
        // now enforces that it must.
        sqlx::query(
            "INSERT INTO accounts (id, username, opaque_record, kdf_salt, created_at)
             VALUES ('account', 'account', X'', X'', 0)",
        )
        .execute(&db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO collections (id, account_id, kind, created_at)
             VALUES ('collection', 'account', 'vault', 0)",
        )
        .execute(&db)
        .await
        .unwrap();
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
            "object_revisions_created_at",
            "objects_account_meta",
            "sessions_expires_at",
            "devices_account",
            "sessions_account",
            "sessions_device",
            "objects_collection",
        ] {
            assert!(
                indexes.iter().any(|name| name == expected),
                "missing index {expected}; have {indexes:?}"
            );
        }
        db.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The two queries every PUT runs must be answerable from the index alone.
    #[tokio::test]
    async fn the_per_write_scans_of_objects_never_touch_a_table_row() {
        let dir = std::env::temp_dir().join(format!("sealbook-db-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sealbook.db");
        let db = open_migrated(path.to_str().unwrap()).await.unwrap();

        let quota = "SELECT COUNT(*), COALESCE(SUM(padded_size), 0),
                 COALESCE(SUM(CASE WHEN id = 'o' AND collection_id = 'c'
                                   THEN padded_size ELSE 0 END), 0),
                 COALESCE(SUM(CASE WHEN id = 'o' AND collection_id = 'c'
                                   THEN 1 ELSE 0 END), 0)
             FROM objects WHERE account_id = 'a'";
        let manifest = "SELECT id, revision, tombstone, content_digest FROM objects
             WHERE account_id = 'a' AND collection_id = 'c'";

        for (label, query) in [("quota", quota), ("manifest entries", manifest)] {
            let plan: Vec<String> = sqlx::query(&format!("EXPLAIN QUERY PLAN {query}"))
                .fetch_all(&db)
                .await
                .unwrap()
                .iter()
                .map(|row| row.get::<String, _>("detail"))
                .collect();
            assert!(
                plan.iter()
                    .any(|step| step.contains("COVERING INDEX objects_account_meta")),
                "the {label} scan is not index-only: {plan:?}"
            );
        }

        db.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The walk selects `ciphertext`, so a sort means spooling every object in the
    /// collection through a temp b-tree to hand back one page, on every page.
    #[tokio::test]
    async fn the_snapshot_walk_reads_its_page_in_revision_order() {
        let dir = std::env::temp_dir().join(format!("sealbook-db-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sealbook.db");
        let db = open_migrated(path.to_str().unwrap()).await.unwrap();

        let plan: Vec<String> = sqlx::query(
            "EXPLAIN QUERY PLAN
             SELECT id AS object_id, revision, tombstone, nonce, ciphertext,
                    padded_size, content_type
             FROM objects
             WHERE account_id = 'a' AND collection_id = 'c' AND revision > 0
             ORDER BY revision ASC
             LIMIT 51",
        )
        .fetch_all(&db)
        .await
        .unwrap()
        .iter()
        .map(|row| row.get::<String, _>("detail"))
        .collect();

        assert!(
            !plan.iter().any(|step| step.contains("TEMP B-TREE")),
            "the snapshot walk sorts the collection to serve one page: {plan:?}"
        );
        assert!(
            plan.iter()
                .any(|step| step.contains("objects_account_meta") && step.contains("revision>")),
            "the snapshot walk does not seek on revision: {plan:?}"
        );

        db.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The change feed must still seek, now that no explicit index duplicates
    /// `object_revisions`' primary key.
    #[tokio::test]
    async fn the_change_feed_seeks_on_the_primary_key() {
        let dir = std::env::temp_dir().join(format!("sealbook-db-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sealbook.db");
        let db = open_migrated(path.to_str().unwrap()).await.unwrap();

        let feed = "SELECT r.object_id, r.revision, r.tombstone, r.nonce, r.ciphertext,
                    r.padded_size, r.content_type
             FROM object_revisions r
             WHERE r.account_id = 'a' AND r.collection_id = 'c' AND r.revision > 3
             ORDER BY r.revision ASC
             LIMIT 51";
        let floor = "SELECT MIN(revision) FROM object_revisions WHERE account_id = 'a'";

        for (label, query) in [("change feed", feed), ("resync floor", floor)] {
            let plan: Vec<String> = sqlx::query(&format!("EXPLAIN QUERY PLAN {query}"))
                .fetch_all(&db)
                .await
                .unwrap()
                .iter()
                .map(|row| row.get::<String, _>("detail"))
                .collect();
            assert!(
                plan.iter().any(|step| step.contains("SEARCH")
                    && step.contains("sqlite_autoindex_object_revisions_1")),
                "the {label} no longer seeks on the primary key: {plan:?}"
            );
            assert!(
                !plan.iter().any(|step| step.contains("TEMP B-TREE")),
                "the {label} sorts: {plan:?}"
            );
        }

        db.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Both foreign-key cascades have to seek. Without an index on the
    /// referencing column, deleting one account scans every session and every
    /// object in the database, not just that account's.
    #[tokio::test]
    async fn the_cascading_deletes_never_scan_a_child_table() {
        let dir = std::env::temp_dir().join(format!("sealbook-db-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sealbook.db");
        let db = open_migrated(path.to_str().unwrap()).await.unwrap();

        for (label, query) in [
            ("the account cascade", "DELETE FROM accounts WHERE id = 'a'"),
            (
                "the collection cascade",
                "DELETE FROM collections WHERE id = 'c'",
            ),
            ("the device cascade", "DELETE FROM devices WHERE id = 'd'"),
            (
                "an account's session revoke",
                "DELETE FROM sessions WHERE account_id = 'a'",
            ),
        ] {
            let plan: Vec<String> = sqlx::query(&format!("EXPLAIN QUERY PLAN {query}"))
                .fetch_all(&db)
                .await
                .unwrap()
                .iter()
                .map(|row| row.get::<String, _>("detail"))
                .collect();
            assert!(
                !plan.iter().any(|step| step.contains("SCAN")),
                "{label} scans a child table: {plan:?}"
            );
        }

        db.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    /// An existing vault's tombstone counter has to start from the rows it
    /// already holds, not from zero, or the quota under-counts for ever.
    #[tokio::test]
    async fn the_tombstone_counter_is_back_filled_from_the_objects() {
        let (dir, db) = temp_db().await;
        migrate_to_v1(&db).await.unwrap();
        sqlx::query(
            "INSERT INTO accounts (id, username, opaque_record, kdf_salt, created_at)
             VALUES ('account', 'account', X'', X'', 0)",
        )
        .execute(&db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO collections (id, account_id, kind, created_at)
             VALUES ('collection', 'account', 'vault', 0)",
        )
        .execute(&db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO revision_seq (account_id, next_revision) VALUES ('account', 4)")
            .execute(&db)
            .await
            .unwrap();
        for (id, tombstone) in [("live", 0), ("gone-one", 1), ("gone-two", 1)] {
            sqlx::query(
                "INSERT INTO objects
                 (id, collection_id, account_id, revision, tombstone, ciphertext, nonce,
                  padded_size, content_type, content_digest)
                 VALUES (?, 'collection', 'account', 1, ?, X'', X'', 0,
                         'application/jscontact+json', X'')",
            )
            .bind(id)
            .bind(tombstone)
            .execute(&db)
            .await
            .unwrap();
        }

        migrate(&db).await.unwrap();

        let counted: i64 = sqlx::query_scalar("SELECT tombstone_count FROM revision_seq")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(counted, 2, "the two tombstones were not counted");
        assert_eq!(schema_version(&db).await.unwrap(), SCHEMA_VERSION);

        db.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The write paths take the write lock before they read, so two writers
    /// serialise instead of one of them failing after it has already read.
    ///
    /// A deferred `BEGIN` takes its read snapshot on the first `SELECT` and asks
    /// for the write lock only at the first write. If another connection commits
    /// in between, that write returns `SQLITE_BUSY_SNAPSHOT`, which the busy
    /// handler is never consulted about — so `busy_timeout` cannot absorb it and
    /// the request fails. Both halves are asserted here, because the contrast is
    /// the whole reason the write paths pass `BEGIN IMMEDIATE`.
    #[tokio::test]
    async fn writers_serialise_on_an_immediate_transaction() {
        let dir = std::env::temp_dir().join(format!("sealbook-db-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sealbook.db");
        let db = open_migrated(path.to_str().unwrap()).await.unwrap();
        sqlx::query(
            "INSERT INTO accounts (id, username, opaque_record, kdf_salt, created_at)
             VALUES ('account', 'account', X'', X'', 0)",
        )
        .execute(&db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO revision_seq (account_id, next_revision) VALUES ('account', 1)")
            .execute(&db)
            .await
            .unwrap();

        // What the deferred transaction the handlers used to open would do.
        let mut deferred = db.begin().await.unwrap();
        let read: i64 =
            sqlx::query_scalar("SELECT next_revision FROM revision_seq WHERE account_id = ?")
                .bind("account")
                .fetch_one(&mut *deferred)
                .await
                .unwrap();
        assert_eq!(read, 1);
        sqlx::query("UPDATE revision_seq SET next_revision = 2 WHERE account_id = 'account'")
            .execute(&db)
            .await
            .unwrap();
        let conflict =
            sqlx::query("UPDATE revision_seq SET next_revision = 2 WHERE account_id = 'account'")
                .execute(&mut *deferred)
                .await;
        assert!(
            conflict.is_err(),
            "a deferred writer that read a stale revision must not be able to write it"
        );
        drop(deferred);

        // What they do now: the second writer waits for the lock, then reads the
        // revision the first one committed rather than a stale one.
        let mut first = db.begin_with("BEGIN IMMEDIATE").await.unwrap();
        let second = tokio::spawn({
            let db = db.clone();
            async move {
                let mut tx = db.begin_with("BEGIN IMMEDIATE").await.expect("begin");
                let seen: i64 = sqlx::query_scalar(
                    "SELECT next_revision FROM revision_seq WHERE account_id = ?",
                )
                .bind("account")
                .fetch_one(&mut *tx)
                .await
                .expect("read");
                sqlx::query("UPDATE revision_seq SET next_revision = ? WHERE account_id = ?")
                    .bind(seen + 1)
                    .bind("account")
                    .execute(&mut *tx)
                    .await
                    .expect("write");
                tx.commit().await.expect("commit");
                seen
            }
        });
        // Long enough that the spawned writer is waiting on the lock, not racing
        // to take it first.
        tokio::time::sleep(Duration::from_millis(100)).await;
        sqlx::query("UPDATE revision_seq SET next_revision = 10 WHERE account_id = 'account'")
            .execute(&mut *first)
            .await
            .unwrap();
        first.commit().await.unwrap();

        let seen = second.await.unwrap();
        assert_eq!(seen, 10, "the second writer read a stale revision");
        let final_revision: i64 =
            sqlx::query_scalar("SELECT next_revision FROM revision_seq WHERE account_id = ?")
                .bind("account")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(final_revision, 11, "the second write was lost");

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
