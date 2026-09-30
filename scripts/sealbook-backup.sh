#!/usr/bin/env bash
#
# Backs up a Sealbook data directory: the SQLite database and the TLS material,
# which have to be kept together — the database is useless to a pinned client
# without the certificate it was served with.
#
# Uses SQLite's online backup, so it is safe to run against a live server. A
# plain file copy is not: newer committed pages may still be in the WAL.
#
# Usage:
#   sealbook-backup.sh <data-dir> <backup-dir> [keep]
#
# Example (cron, daily, keeping 14):
#   0 4 * * * /opt/sealbook/scripts/sealbook-backup.sh /sealbook /sealbook-backups 14
#
# Exits non-zero on any failure, including a failed integrity check, so a cron
# mail or a monitoring wrapper actually tells you when backups stop working.

set -euo pipefail

DATA_DIR=${1:-}
BACKUP_DIR=${2:-}
KEEP=${3:-14}

if [[ -z $DATA_DIR || -z $BACKUP_DIR ]]; then
    sed -n '2,20p' "$0" >&2
    exit 2
fi

command -v sqlite3 >/dev/null || { echo "sqlite3 is required" >&2; exit 2; }

DB=$DATA_DIR/sealbook.db
TLS=$DATA_DIR/tls
[[ -f $DB ]] || { echo "no database at $DB" >&2; exit 1; }

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
TARGET=$BACKUP_DIR/sealbook-$STAMP
PARTIAL=$TARGET.partial

# Build under a .partial name and rename at the end, so an interrupted run never
# leaves something that looks like a usable backup.
rm -rf "$PARTIAL"
mkdir -p "$PARTIAL"
chmod 700 "$PARTIAL"

sqlite3 "$DB" ".backup '$PARTIAL/sealbook.db'"
chmod 600 "$PARTIAL/sealbook.db"

# Fold the WAL into the copy so the backup is one self-contained file. Without
# this, every later read of the copy leaves -wal and -shm files beside it, and a
# backup whose sidecars can be separated from it is a backup that can lose
# writes. The server switches the file back to WAL when it opens it.
sqlite3 "$PARTIAL/sealbook.db" 'PRAGMA journal_mode=delete;' >/dev/null

INTEGRITY=$(sqlite3 "$PARTIAL/sealbook.db" 'PRAGMA integrity_check')
if [[ $INTEGRITY != ok ]]; then
    echo "integrity check failed on the copy: $INTEGRITY" >&2
    exit 1
fi

if [[ -d $TLS ]]; then
    cp -a "$TLS" "$PARTIAL/tls"
else
    echo "warning: no TLS directory at $TLS; clients pinning this server's certificate will not be able to use this backup" >&2
fi

rm -f "$PARTIAL/sealbook.db-wal" "$PARTIAL/sealbook.db-shm"

mv "$PARTIAL" "$TARGET"
echo "backed up to $TARGET"

# Prune oldest first, and only ever completed backups.
if [[ $KEEP -gt 0 ]]; then
    mapfile -t EXISTING < <(find "$BACKUP_DIR" -maxdepth 1 -type d -name 'sealbook-*' ! -name '*.partial' | sort)
    COUNT=${#EXISTING[@]}
    if (( COUNT > KEEP )); then
        for (( i = 0; i < COUNT - KEEP; i++ )); do
            rm -rf "${EXISTING[i]}"
            echo "pruned ${EXISTING[i]}"
        done
    fi
fi
