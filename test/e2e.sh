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

echo "== cert-manager fix suggestion =="
set +e
cm="$("$BIN" scan -json "$ROOT/testdata/cert-manager" 2>/dev/null)"
set -e
echo "$cm" | grep -q '"suggestion": "renewBeforePercentage: 33"'

echo "== live: no host is a usage error (exit 2) =="
set +e
"$BIN" live >/dev/null 2>&1
code=$?
set -e
[[ "$code" -eq 2 ]] || { echo "expected exit 2, got $code" >&2; exit 1; }

echo "== live: unreachable host is BLOCKED (exit 1) =="
set +e
out="$("$BIN" live -timeout 3s 127.0.0.1:1)"
code=$?
set -e
echo "$out"
[[ "$code" -eq 1 ]] || { echo "expected exit 1, got $code" >&2; exit 1; }
echo "$out" | grep -q BLOCKED

echo "== live -ari: unreachable host still BLOCKED, no ARI lookup without a cert (exit 1) =="
set +e
out="$("$BIN" live -ari -json -timeout 3s 127.0.0.1:1)"
code=$?
set -e
[[ "$code" -eq 1 ]] || { echo "expected exit 1, got $code" >&2; exit 1; }
if echo "$out" | grep -q '"ari"'; then echo "unexpected ari block for failed handshake" >&2; exit 1; fi

echo "== default command with -check-live merges live section =="
set +e
all="$("$BIN" -json -check-live 127.0.0.1:1 "$ROOT/testdata/good")"
set -e
echo "$all" | grep -q '"live"'

echo "== clients (smoke) =="
"$BIN" clients >/dev/null

echo "== timers (smoke) =="
"$BIN" timers >/dev/null

echo "== version =="
"$BIN" -version | grep -q renewhunt

echo "e2e ok"
