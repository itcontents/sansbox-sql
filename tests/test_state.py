from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest

from api.state import (
    STATUS_EXPIRED,
    STATUS_NUKED,
    STATUS_READY,
    STATUS_STARTING,
    SessionStore,
)


def _tmp_db(tmp_path: Path) -> SessionStore:
    return SessionStore(tmp_path / "state.db")


def _record(sid: str = "abc", **overrides) -> dict:
    base = dict(
        id=sid,
        ticket="10215",
        date="2026-06-29",
        dbs_json='["db_a"]',
        creds_enc=b"\x00\x01\x02",
        host="api.test",
        mysql_host="1.2.3.4",
        port=33060,
        container_name="sandbox-abc",
        compose_path="/var/lib/sandboxes/composes/abc/compose.yml",
        tls_dir="/var/lib/sandboxes/tls/abc",
        log_dir="/var/log/sandboxes/10215-2026-06-29/abc",
        created_at=1_700_000_000,
        expires_at=1_700_021_600,
        max_extended_until=1_700_028_800,
        status=STATUS_READY,
    )
    base.update(overrides)
    return base


def test_create_and_get(tmp_path: Path):
    s = _tmp_db(tmp_path)
    try:
        rec = _record()
        s.create(rec)
        got = s.get(rec["id"])
        assert got is not None
        assert got["ticket"] == "10215"
        assert got["creds_enc"] == b"\x00\x01\x02"
    finally:
        s.close()


def test_create_rejects_missing_field(tmp_path: Path):
    s = _tmp_db(tmp_path)
    try:
        rec = _record()
        rec.pop("ticket")
        with pytest.raises(ValueError):
            s.create(rec)
    finally:
        s.close()


def test_create_rejects_invalid_status(tmp_path: Path):
    s = _tmp_db(tmp_path)
    try:
        rec = _record(status="bogus")
        with pytest.raises(ValueError):
            s.create(rec)
    finally:
        s.close()


def test_get_missing_returns_none(tmp_path: Path):
    s = _tmp_db(tmp_path)
    try:
        assert s.get("nope") is None
    finally:
        s.close()


def test_set_status(tmp_path: Path):
    s = _tmp_db(tmp_path)
    try:
        s.create(_record())
        s.set_status("abc", STATUS_NUKED)
        assert s.get("abc")["status"] == STATUS_NUKED
    finally:
        s.close()


def test_used_ports(tmp_path: Path):
    s = _tmp_db(tmp_path)
    try:
        s.create(_record(sid="a", port=33060, status=STATUS_READY))
        s.create(_record(sid="b", port=33061, status=STATUS_STARTING))
        s.create(_record(sid="c", port=33062, status=STATUS_NUKED))
        ports = s.used_ports()
        assert ports == {33060, 33061}
    finally:
        s.close()


def test_claim_expired_marks_and_returns(tmp_path: Path):
    s = _tmp_db(tmp_path)
    try:
        now = 1_700_021_700
        s.create(_record(sid="old1", expires_at=now - 10, status=STATUS_READY))
        s.create(_record(sid="old2", expires_at=now - 1, status=STATUS_READY))
        s.create(_record(sid="fresh", expires_at=now + 1000, status=STATUS_READY))
        claimed = s.claim_expired(now)
        ids = sorted(r["id"] for r in claimed)
        assert ids == ["old1", "old2"]
        assert s.get("old1")["status"] == STATUS_EXPIRED
        assert s.get("old2")["status"] == STATUS_EXPIRED
        assert s.get("fresh")["status"] == STATUS_READY
    finally:
        s.close()


def test_update_ttl(tmp_path: Path):
    s = _tmp_db(tmp_path)
    try:
        s.create(_record())
        ok = s.update_ttl("abc", 1_700_028_000, 1)
        assert ok is True
        assert s.get("abc")["expires_at"] == 1_700_028_000
        assert s.get("abc")["ttl_extended"] == 1
    finally:
        s.close()


def test_list_by_status(tmp_path: Path):
    s = _tmp_db(tmp_path)
    try:
        s.create(_record(sid="a", status=STATUS_READY))
        s.create(_record(sid="b", status=STATUS_NUKED))
        s.create(_record(sid="c", status=STATUS_READY))
        ready = s.list_by_status(STATUS_READY)
        assert {r["id"] for r in ready} == {"a", "c"}
    finally:
        s.close()


def test_concurrent_writes_do_not_corrupt(tmp_path: Path):
    import threading

    s = _tmp_db(tmp_path)
    try:
        errors: list[Exception] = []

        def writer(i: int) -> None:
            try:
                s.create(_record(sid=f"s{i}", port=33060 + i, status=STATUS_READY))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        assert len(s.list_all()) == 20
    finally:
        s.close()


def test_delete(tmp_path: Path):
    s = _tmp_db(tmp_path)
    try:
        s.create(_record())
        assert s.delete("abc") is True
        assert s.delete("abc") is False
        assert s.get("abc") is None
    finally:
        s.close()


def test_update_to_ready_only_from_starting(tmp_path: Path):
    s = SessionStore(tmp_path / "state.db")
    try:
        s.create({
            "id": "sid-1", "ticket": "t", "date": "2026-06-30",
            "dbs_json": "[]", "creds_enc": b"\x00",
            "host": "h", "mysql_host": "1.2.3.4", "port": 33451,
            "container_name": "c",
            "compose_path": "/tmp/c.yml", "tls_dir": "/tmp/t", "log_dir": "/tmp/l",
            "created_at": 100, "expires_at": 160, "max_extended_until": 200,
            "status": "starting",
        })
        ok = s.update_to_ready("sid-1", creds_enc=b"ENC", expires_at=500, max_extended_until=600)
        assert ok is True
        row = s.get("sid-1")
        assert row["status"] == "ready"
        assert row["creds_enc"] == b"ENC"
        assert row["expires_at"] == 500
    finally:
        s.close()


def test_update_to_ready_ignored_when_status_already_changed(tmp_path: Path):
    s = SessionStore(tmp_path / "state.db")
    try:
        s.create({
            "id": "sid-2", "ticket": "t", "date": "2026-06-30",
            "dbs_json": "[]", "creds_enc": b"\x00",
            "host": "h", "mysql_host": "1.2.3.4", "port": 33451,
            "container_name": "c",
            "compose_path": "/tmp/c.yml", "tls_dir": "/tmp/t", "log_dir": "/tmp/l",
            "created_at": 100, "expires_at": 160, "max_extended_until": 200,
            "status": "starting",
        })
        # Reaper already nuked it
        s.set_status("sid-2", "nuked")
        ok = s.update_to_ready("sid-2", creds_enc=b"NEW", expires_at=999, max_extended_until=1000)
        assert ok is False
        row = s.get("sid-2")
        assert row["status"] == "nuked"
        assert row["creds_enc"] == b"\x00"  # untouched
    finally:
        s.close()


def test_claim_stuck_picks_old_starting_and_error(tmp_path: Path):
    s = SessionStore(tmp_path / "state.db")
    try:
        for sid, status, created in [
            ("old_starting", "starting", 100),
            ("old_error",    "error",    100),
            ("new_starting", "starting", 9_999_999),  # still fresh
            ("ready_old",    "ready",    100),         # not in starting/error
        ]:
            s.create({
                "id": sid, "ticket": "t", "date": "d",
                "dbs_json": "[]", "creds_enc": b"\x00",
                "host": "h", "mysql_host": "1.2.3.4", "port": 1,
                "container_name": "c",
                "compose_path": "/tmp/x.yml", "tls_dir": "/tmp/t", "log_dir": "/tmp/l",
                "created_at": created, "expires_at": created + 60, "max_extended_until": created + 200,
                "status": status,
            })
        stuck = [r["id"] for r in s.claim_stuck(now=10_000, grace_seconds=60)]
        assert sorted(stuck) == ["old_error", "old_starting"]
    finally:
        s.close()


def test_mark_nuked_skips_already_terminal(tmp_path: Path):
    s = SessionStore(tmp_path / "state.db")
    try:
        s.create({
            "id": "sid-x", "ticket": "t", "date": "d",
            "dbs_json": "[]", "creds_enc": b"\x00",
            "host": "h", "mysql_host": "1.2.3.4", "port": 1,
            "container_name": "c",
            "compose_path": "/tmp/x.yml", "tls_dir": "/tmp/t", "log_dir": "/tmp/l",
            "created_at": 0, "expires_at": 60, "max_extended_until": 200,
            "status": "nuked",
        })
        s.mark_nuked("sid-x")  # no-op, already nuked
        assert s.get("sid-x")["status"] == "nuked"
    finally:
        s.close()


def test_reserve_session_is_atomic(tmp_path: Path):
    """Concurrent reserve_session calls must never pick the same port."""
    import threading
    from api.docker_ops import allocate_port
    s = SessionStore(tmp_path / "state.db")
    try:
        s.create({
            "id": "pre", "ticket": "t", "date": "d",
            "dbs_json": "[]", "creds_enc": b"\x00",
            "host": "h", "mysql_host": "1.2.3.4", "port": 33061,
            "container_name": "c",
            "compose_path": "/tmp/x.yml", "tls_dir": "/tmp/t", "log_dir": "/tmp/l",
            "created_at": 0, "expires_at": 60, "max_extended_until": 200,
            "status": "ready",
        })

        settings = type("S", (), {"port_range": range(33070, 33080)})()

        N = 8
        barrier = threading.Barrier(N)
        results: list[dict] = []
        results_lock = threading.Lock()

        def worker(i: int):
            barrier.wait()
            def fac(port):
                return {
                    "id": f"new-{i}", "ticket": "t", "date": "d",
                    "dbs_json": "[]", "creds_enc": b"\x00",
                    "host": "h", "mysql_host": "1.2.3.4", "port": port,
                    "container_name": "c",
                    "compose_path": "/tmp/x.yml", "tls_dir": "/tmp/t", "log_dir": "/tmp/l",
                    "created_at": 0, "expires_at": 60, "max_extended_until": 200,
                    "ttl_extended": 0,
                    "status": "starting",
                }
            rec = s.reserve_session(
                record_factory=fac,
                port_allocator=lambda used: allocate_port(used, settings),
            )
            with results_lock:
                results.append(rec)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
        for t in threads: t.start()
        for t in threads: t.join()

        ports = [r["port"] for r in results]
        assert len(set(ports)) == N, f"port collision: {ports}"
        assert all(33070 <= p <= 33079 for p in ports)
        # Pre-existing row's port must be in the no-go set.
        assert 33061 not in ports
    finally:
        s.close()