#!/usr/bin/env bash
# Runs the live-server scenario (fixtures/live/scenario.json) through the wasm
# build under Node and through Android's native library under a JVM, both
# against one real sealbook-server over its post-quantum TLS.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
web="${SEALBOOK_WEB_DIR:-$root/../sealbook-web}"
app="${SEALBOOK_APP_DIR:-$root/../sealbook-app}"
port="${SEALBOOK_E2E_PORT:-18943}"

cargo build -q -p sealbook-server --manifest-path "$root/Cargo.toml"

data="$(mktemp -d)"
SEALBOOK_BIND="127.0.0.1:$port" SEALBOOK_DATA_DIR="$data" \
  "$root/target/debug/sealbook-server" >"$data/server.log" 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null || true; rm -rf "$data"' EXIT

for _ in $(seq 1 60); do
  [ -f "$data/tls/cert.pem" ] && grep -q "listening on" "$data/server.log" && break
  sleep 0.5
done
grep -q "listening on" "$data/server.log" || { cat "$data/server.log"; exit 1; }

export SEALBOOK_E2E_SERVER="https://127.0.0.1:$port"
export SEALBOOK_E2E_CERT="$data/tls/cert.pem"
export NODE_EXTRA_CA_CERTS="$SEALBOOK_E2E_CERT"

(cd "$web" && ALLOW_UNPINNED_SEALBOOK=1 npx vitest run src/test/liveServer.test.ts)
(cd "$app" && ./gradlew testDebugUnitTest --offline -q --rerun \
  --tests com.sealbook.app.LiveServerTest)
