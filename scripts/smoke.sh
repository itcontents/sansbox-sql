#!/usr/bin/env bash
# Quick smoke test against a running API.
set -euo pipefail

HOST="${SANDBOX_API_HOST:-127.0.0.1}"
PORT="${SANDBOX_API_PORT:-8080}"
BASE="http://${HOST}:${PORT}"

echo "[smoke] GET ${BASE}/healthz"
curl -fsS "${BASE}/healthz" | python3 -m json.tool

echo
echo "[smoke] GET ${BASE}/readyz"
curl -sS "${BASE}/readyz" | python3 -m json.tool || true

echo
echo "[smoke] unauthenticated POST should 401"
code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE}/instance" \
  -H 'Content-Type: application/json' \
  -d '{"ticket":"smoke","dbs":["db_a"]}')"
[[ "${code}" == "401" ]] || { echo "expected 401, got ${code}" >&2; exit 1; }
echo "  -> 401 OK"

echo
echo "[smoke] all good."