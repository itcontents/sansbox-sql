from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id                    TEXT PRIMARY KEY,
    ticket                TEXT NOT NULL,
    date                  TEXT NOT NULL,
    dbs_json              TEXT NOT NULL,
    creds_enc             BLOB NOT NULL,
    host                  TEXT NOT NULL,
    mysql_host            TEXT NOT NULL,
    port                  INTEGER NOT NULL,
    container_name        TEXT NOT NULL,
    compose_path          TEXT NOT NULL,
    tls_dir               TEXT NOT NULL,
    log_dir               TEXT NOT NULL,
    created_at            INTEGER NOT NULL,
    expires_at            INTEGER NOT NULL,
    max_extended_until    INTEGER NOT NULL,
    ttl_extended          INTEGER NOT NULL DEFAULT 0,
    status                TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_status_expires ON sessions(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_ticket ON sessions(ticket);
"""

STATUS_STARTING = "starting"
STATUS_READY = "ready"
STATUS_EXPIRED = "expired"
STATUS_NUKED = "nuked"
STATUS_ERROR = "error"

_VALID_STATUSES = {STATUS_STARTING, STATUS_READY, STATUS_EXPIRED, STATUS_NUKED, STATUS_ERROR}


class SessionStore:
    """Thread-safe SQLite-backed session store."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(db_path),
            check_same_thread=False,
            isolation_level=None,  # autocommit; we use explicit BEGIN where needed
            timeout=30.0,           # SQLITE_BUSY -> wait up to 30s
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def create(self, record: dict[str, Any]) -> None:
        required = {
            "id",
            "ticket",
            "date",
            "dbs_json",
            "creds_enc",
            "host",
            "mysql_host",
            "port",
            "container_name",
            "compose_path",
            "tls_dir",
            "log_dir",
            "created_at",
            "expires_at",
            "max_extended_until",
            "status",
        }
        missing = required - record.keys()
        if missing:
            raise ValueError(f"record missing fields: {sorted(missing)}")
        if record["status"] not in _VALID_STATUSES:
            raise ValueError(f"invalid status: {record['status']}")

        cols = ", ".join(required)
        placeholders = ", ".join("?" for _ in required)
        values = tuple(record[k] for k in required)
        with self._tx() as conn:
            conn.execute(
                f"INSERT INTO sessions ({cols}) VALUES ({placeholders})",
                values,
            )

    def reserve_session(
        self,
        *,
        record_factory,
        port_allocator,
    ) -> dict[str, Any]:
        """Atomically allocate a free port and INSERT a new session row.

        Held under a single BEGIN IMMEDIATE transaction so two concurrent
        creates cannot pick the same host port. SQLite serializes the
        write-lock so the second caller simply waits, then sees the first
        caller's row in `used_ports()`.

        `record_factory(port: int) -> dict` populates all required columns;
        `port_allocator(used_ports: set[int]) -> int` is `allocate_port`.
        """
        required = {
            "id", "ticket", "date", "dbs_json", "creds_enc",
            "host", "mysql_host", "port", "container_name",
            "compose_path", "tls_dir", "log_dir",
            "created_at", "expires_at", "max_extended_until",
            "status",
        }
        with self._tx() as conn:
            rows = conn.execute(
                "SELECT port FROM sessions WHERE status IN (?, ?, ?)",
                (STATUS_STARTING, STATUS_READY, STATUS_EXPIRED),
            ).fetchall()
            used = {int(r[0]) for r in rows}
            port = port_allocator(used)
            record = record_factory(port)
            missing = required - record.keys()
            if missing:
                raise ValueError(f"record missing fields: {sorted(missing)}")
            if record["status"] not in _VALID_STATUSES:
                raise ValueError(f"invalid status: {record['status']}")

            cols = ", ".join(required)
            placeholders = ", ".join("?" for _ in required)
            values = tuple(record[k] for k in required)
            conn.execute(
                f"INSERT INTO sessions ({cols}) VALUES ({placeholders})",
                values,
            )
            return record

    def get(self, sid: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM sessions WHERE id = ?", (sid,)
            ).fetchone()
        return dict(row) if row else None

    def list_all(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM sessions ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def list_by_status(self, status: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM sessions WHERE status = ? ORDER BY created_at DESC",
                (status,),
            ).fetchall()
        return [dict(r) for r in rows]

    def used_ports(self) -> set[int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT port FROM sessions WHERE status IN (?, ?, ?)",
                (STATUS_STARTING, STATUS_READY, STATUS_EXPIRED),
            ).fetchall()
        return {int(r["port"]) for r in rows}

    def claim_expired(self, now: int) -> list[dict[str, Any]]:
        """Atomically mark ready OR already-expired sessions past expires_at as 'expired' and return them.

        Re-claiming sessions that are already in 'expired' status lets the reaper
        retry sessions whose previous teardown attempt failed.
        """
        with self._tx() as conn:
            rows = conn.execute(
                "SELECT * FROM sessions WHERE status IN (?, ?) AND expires_at < ?",
                (STATUS_READY, STATUS_EXPIRED, now),
            ).fetchall()
            if not rows:
                return []
            ids = [r["id"] for r in rows]
            qmarks = ", ".join("?" for _ in ids)
            conn.execute(
                f"UPDATE sessions SET status = ? WHERE id IN ({qmarks})",
                (STATUS_EXPIRED, *ids),
            )
        return [dict(r) for r in rows]

    def set_status(self, sid: str, status: str) -> None:
        if status not in _VALID_STATUSES:
            raise ValueError(f"invalid status: {status}")
        with self._tx() as conn:
            conn.execute(
                "UPDATE sessions SET status = ? WHERE id = ?", (status, sid)
            )

    def update_to_ready(
        self,
        sid: str,
        *,
        creds_enc: bytes,
        expires_at: int,
        max_extended_until: int,
    ) -> bool:
        """Transition a `starting` row to `ready` with the real creds blob + TTL.

        Idempotent: returns False if the row is no longer in `starting` (e.g.
        the reaper already cleaned it up, or another worker beat us to it).
        """
        with self._tx() as conn:
            cur = conn.execute(
                "UPDATE sessions "
                "SET status = ?, creds_enc = ?, expires_at = ?, max_extended_until = ? "
                "WHERE id = ? AND status = ?",
                (STATUS_READY, creds_enc, expires_at, max_extended_until, sid, STATUS_STARTING),
            )
            return cur.rowcount > 0

    def claim_stuck(self, now: int, *, grace_seconds: int = 300) -> list[dict[str, Any]]:
        """Claim rows in `starting` or `error` past their grace window.

        These are orphans: either the API process died mid-create (row was
        inserted early as a placeholder) or the create raised and an error
        path left a row in `error`. Either way the container must be nuked.

        Returns the claimed records; their status is left untouched here so
        the caller (reaper) can attempt `down_session`, then mark `nuked`
        once it actually tore down.
        """
        cutoff = now - grace_seconds
        with self._tx() as conn:
            rows = conn.execute(
                "SELECT * FROM sessions "
                "WHERE status IN (?, ?) AND created_at < ?",
                (STATUS_STARTING, STATUS_ERROR, cutoff),
            ).fetchall()
            return [dict(r) for r in rows] if rows else []

    def mark_nuked(self, sid: str) -> None:
        with self._tx() as conn:
            conn.execute(
                "UPDATE sessions SET status = ? WHERE id = ? AND status NOT IN (?, ?)",
                (STATUS_NUKED, sid, STATUS_NUKED, STATUS_EXPIRED),
            )

    def update_ttl(self, sid: str, new_expires_at: int, ttl_extended: int) -> bool:
        with self._tx() as conn:
            cur = conn.execute(
                "UPDATE sessions SET expires_at = ?, ttl_extended = ? WHERE id = ?",
                (new_expires_at, ttl_extended, sid),
            )
        return cur.rowcount > 0

    def update_port(self, sid: str, port: int) -> None:
        with self._tx() as conn:
            conn.execute("UPDATE sessions SET port = ? WHERE id = ?", (port, sid))

    def delete(self, sid: str) -> bool:
        with self._tx() as conn:
            cur = conn.execute("DELETE FROM sessions WHERE id = ?", (sid,))
        return cur.rowcount > 0