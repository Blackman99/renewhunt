#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${ROOT}/renewhunt"
if [[ ! -x "$BIN" ]]; then
  (cd "$ROOT" && go build -o renewhunt ./cmd/renewhunt)
fi

echo "== scan testdata (expect exit 1 / BLOCKED) =="
set +e
"$BIN" scan "$ROOT/testdata"
code=$?
set -e
if [[ "$code" -ne 1 ]]; then
  echo "expected exit 1 on BLOCKED fixtures, got $code" >&2
  exit 1
fi

echo "== json output =="
set +e
json="$("$BIN" scan -json "$ROOT/testdata/bad" 2>/dev/null)"
set -e
echo "$json" | grep -q BLOCKED

echo "== clients (smoke) =="
"$BIN" clients >/dev/null

echo "== timers (smoke) =="
"$BIN" timers >/dev/null

echo "== version =="
"$BIN" -version | grep -q renewhunt

echo "e2e ok"
