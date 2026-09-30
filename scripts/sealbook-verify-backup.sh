#!/usr/bin/env bash
#
# Verifies a backup by actually using it: copies it to a scratch directory,
# starts a real server against it on a spare port, and probes that server.
#
# This catches what an integrity check cannot — a database that opens but whose
# schema this build refuses, or missing TLS material — which is the failure mode
# that matters, because you only find out during a restore otherwise.
#
# Usage:
#   sealbook-verify-backup.sh <backup-dir> [sealbook-server-binary] [port]
#
# What it does not check: that a specific account can log in and read its data.
# That needs a password, so do it by hand once after this passes — point a client
# at https://127.0.0.1:<port> while the temporary server is up.

set -euo pipefail

BACKUP=${1:-}
BINARY=${2:-$(command -v sealbook-server || echo ./target/release/sealbook-server)}
PORT=${3:-18443}

if [[ -z $BACKUP ]]; then
    sed -n '2,18p' "$0" >&2
    exit 2
fi
[[ -f $BACKUP/sealbook.db ]] || { echo "no database in $BACKUP" >&2; exit 1; }
[[ -x $BINARY ]] || { echo "no sealbook-server binary at $BINARY" >&2; exit 2; }

SCRATCH=$(mktemp -d)
SERVER_PID=""
cleanup() {
    [[ -n $SERVER_PID ]] && kill "$SERVER_PID" 2>/dev/null || true
    [[ -n $SERVER_PID ]] && wait "$SERVER_PID" 2>/dev/null || true
    rm -rf "$SCRATCH"
}
trap cleanup EXIT

cp -a "$BACKUP/sealbook.db" "$SCRATCH/sealbook.db"
[[ -d $BACKUP/tls ]] && cp -a "$BACKUP/tls" "$SCRATCH/tls"

echo "starting a temporary server against the restored copy on 127.0.0.1:$PORT"
(
    cd "$SCRATCH"
    SEALBOOK_DATA_DIR=$SCRATCH SEALBOOK_BIND=127.0.0.1:$PORT \
        "$BINARY" >"$SCRATCH/server.log" 2>&1
) &
SERVER_PID=$!

for _ in $(seq 1 40); do
    if SEALBOOK_BIND=127.0.0.1:$PORT "$BINARY" --health-check 2>/dev/null; then
        echo "restore verified: the server started against this backup and answered /health"
        exit 0
    fi
    kill -0 "$SERVER_PID" 2>/dev/null || break
    sleep 0.5
done

echo "restore FAILED; server output follows" >&2
cat "$SCRATCH/server.log" >&2
exit 1
