#!/usr/bin/env bash
# Backup the SQLite state DB via the safe online `.backup` command.
# Wire to cron (hourly) — keeps WAL-consistent snapshots even while the
# API is writing.
#
# Cron entry:
#   0 * * * * /opt/sqldb-sandbox-setup/scripts/backup-state.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1090
source "${REPO_ROOT}/.env"

DB="${SANDBOX_STATE_DB:-/var/lib/sandboxes/state.db}"
BACKUP_DIR="${SANDBOX_BACKUP_DIR:-/var/lib/sandboxes/backups}"
RETENTION_HOURS="${SANDBOX_BACKUP_RETENTION_HOURS:-168}"  # 7 days

mkdir -p "${BACKUP_DIR}"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
tmp="${BACKUP_DIR}/state-${stamp}.db.partial"

# sqlite3 .backup flushes the WAL and produces a consistent snapshot
# without briefly blocking writers.
sqlite3 "${DB}" ".backup '${tmp}'"
mv "${tmp}" "${BACKUP_DIR}/state-${stamp}.db"

# Append-WAL files alongside (defensive: allows point-in-time recovery
# if a backup races with a writer; tiny).
if [[ -f "${DB}-wal" ]]; then
  cp -p "${DB}-wal" "${BACKUP_DIR}/state-${stamp}-wal"
fi

# Retention: prune hourly snapshots older than RETENTION_HOURS.
find "${BACKUP_DIR}" -name 'state-*.db*' -type f -mmin "+$((RETENTION_HOURS * 60))" -delete

echo "[$(date -Iseconds)] backed up to ${BACKUP_DIR}/state-${stamp}.db"
