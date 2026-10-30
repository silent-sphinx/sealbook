#!/usr/bin/env bash
# Scans host source for payload logic that belongs in sealbook-core.
#
# Usage: scripts/check-host-boundaries.sh [--strict] HOST_SRC_DIR...
#
# Rules:
#   seal   sealing or opening an object outside the one wrapper per host
#   type   a literal "@type" key in host code, which means the host builds or
#          sniffs a payload shape instead of asking core
#
# Findings are printed and counted. The exit status is 0 unless --strict is
# given and a finding is not listed in EXCEPTIONS below.
set -uo pipefail

STRICT=0
if [[ "${1:-}" == "--strict" ]]; then
  STRICT=1
  shift
fi
[[ $# -gt 0 ]] || { echo "usage: $0 [--strict] HOST_SRC_DIR..." >&2; exit 2; }

SEAL_WRAPPERS='lib/wasm\.ts|lib/clientCore\.ts|api/VaultClient\.kt'
EXCLUDE='/uniffi/|/pkg/|/test/|\.test\.|Test\.kt'
# path-suffix:rule pairs that are reviewed and allowed
EXCEPTIONS=(
  "lib/bookmarkExport.ts:type"
  "lib/taskExport.ts:type"
)

findings=()
scan() {
  local rule="$1" pattern="$2" dir="$3"
  while IFS= read -r hit; do
    findings+=("$rule:$hit")
  done < <(grep -rnE --include='*.ts' --include='*.tsx' --include='*.kt' "$pattern" "$dir" |
    grep -vE "$EXCLUDE")
}

for dir in "$@"; do
  scan type '"@type"|@type\\"' "$dir"
  while IFS= read -r hit; do
    grep -qE "$SEAL_WRAPPERS" <<<"${hit%%:*}" || findings+=("seal:$hit")
  done < <(grep -rnE --include='*.ts' --include='*.tsx' --include='*.kt' \
    '\b(seal_object|open_object|sealObject|openObject)\(' "$dir" | grep -vE "$EXCLUDE")
done

failed=0
for finding in "${findings[@]+"${findings[@]}"}"; do
  rule="${finding%%:*}"
  path="${finding#*:}"
  path="${path%%:*}"
  excepted=0
  for pair in "${EXCEPTIONS[@]}"; do
    [[ "$rule" == "${pair##*:}" && "$path" == *"${pair%%:*}" ]] && excepted=1
  done
  if ((excepted)); then
    echo "allowed  $finding"
  else
    echo "finding  $finding"
    failed=$((failed + 1))
  fi
done

echo "$failed finding(s) outside the exceptions"
((STRICT && failed > 0)) && exit 1
exit 0
