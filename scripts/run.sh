#!/usr/bin/env bash
# Launch the sqldb-sandbox API.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

if [[ ! -f .env ]]; then
  echo ".env missing; run scripts/bootstrap.sh first" >&2
  exit 1
fi

HOST="${SANDBOX_API_HOST:-127.0.0.1}"
PORT="${SANDBOX_API_PORT:-8080}"
WORKERS="${SANDBOX_API_WORKERS:-1}"

echo "[run] starting uvicorn on ${HOST}:${PORT} (workers=${WORKERS})"
exec python3 -m uvicorn api.main:app \
  --host "${HOST}" --port "${PORT}" --workers "${WORKERS}" \
  --proxy-headers --forwarded-allow-ips='*' \
  --log-level info