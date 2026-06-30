from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import pytest

from api.reaper import reap_loop, reap_once
from api.state import (
    STATUS_ERROR,
    STATUS_EXPIRED,
    STATUS_NUKED,
    STATUS_READY,
    STATUS_STARTING,
    SessionStore,
)


def _record(sid: str = "abc", **overrides) -> dict:
    base = dict(
        id=sid,
        ticket="10215",
        date="2026-06-29",
        dbs_json='["db_a"]',
        creds_enc=b"x",
        host="api.test",
        mysql_host="1.2.3.4",
        port=33060,
        container_name=f"sandbox-{sid}",
        compose_path=f"/tmp/{sid}/docker-compose.yml",
        tls_dir=f"/tmp/{sid}/tls",
        log_dir=f"/var/log/sandboxes/10215-2026-06-29/{sid}",
        created_at=1_700_000_000,
        expires_at=1_700_021_600,
        max_extended_until=1_700_028_800,
        status=STATUS_READY,
    )
    base.update(overrides)
    return base


def _tmp_store(tmp_path: Path) -> SessionStore:
    return SessionStore(tmp_path / "state.db")


def test_reap_once_nukes_expired(tmp_path: Path):
    s = _tmp_store(tmp_path)
    try:
        now = 1_700_021_700
        s.create(_record(sid="old", expires_at=now - 10))
        s.create(_record(sid="alive", expires_at=now + 1000))
        down_calls: list[Path] = []

        def fake_down(p):
            down_calls.append(p)
            Path(p).parent.mkdir(parents=True, exist_ok=True)
            Path(p).write_text("compose")

        nuked = reap_once(store=s, down_session=fake_down, now=now)
        assert [r["id"] for r in nuked] == ["old"]
        assert s.get("old")["status"] == STATUS_NUKED
        assert s.get("alive")["status"] == STATUS_READY
        assert len(down_calls) == 1
        assert down_calls[0].name == "docker-compose.yml"
    finally:
        s.close()


def test_reap_once_handles_empty(tmp_path: Path):
    s = _tmp_store(tmp_path)
    try:
        nuked = reap_once(store=s, down_session=lambda p: None, now=1_700_021_700)
        assert nuked == []
    finally:
        s.close()


def test_reap_once_continues_on_down_failure(tmp_path: Path):
    s = _tmp_store(tmp_path)
    try:
        now = 1_700_021_700
        s.create(_record(sid="a", expires_at=now - 1))
        s.create(_record(sid="b", expires_at=now - 2))

        def flaky(p):
            if "a" in str(p):
                raise RuntimeError("docker daemon down")

        nuked = reap_once(store=s, down_session=flaky, now=now)
        assert [r["id"] for r in nuked] == ["b"]
        assert s.get("a")["status"] == STATUS_EXPIRED
        assert s.get("b")["status"] == STATUS_NUKED
    finally:
        s.close()


def test_reap_once_nukes_orphan_stuck_sessions(tmp_path: Path):
    """`starting`/`error` rows past their grace window get nuked, with -v."""
    s = _tmp_store(tmp_path)
    try:
        now = 1_700_021_700
        s.create(_record(sid="orphan1", status=STATUS_STARTING, created_at=now - 3600))
        s.create(_record(sid="orphan2", status=STATUS_ERROR,    created_at=now - 3600))
        s.create(_record(sid="fresh",    status=STATUS_STARTING, created_at=now - 5))

        down_calls: list[tuple] = []

        def fake_down(compose_path, **kwargs):
            down_calls.append((str(compose_path), kwargs.get("remove_volumes", False)))

        nuked = reap_once(
            store=s,
            down_session=fake_down,
            now=now,
            stuck_grace_seconds=60,
            down_with_volumes=True,
        )
        ids = {r["id"] for r in nuked}
        assert ids == {"orphan1", "orphan2"}
        # Orphan teardown always passes remove_volumes=True
        assert all(kwargs is True for _, kwargs in down_calls), down_calls
        # 'fresh' untouched
        assert s.get("fresh")["status"] == STATUS_STARTING
        # Orphans nuked
        for sid in ("orphan1", "orphan2"):
            assert s.get(sid)["status"] == STATUS_NUKED
    finally:
        s.close()


def test_reap_loop_calls_reap_once_periodically(tmp_path: Path):
    s = _tmp_store(tmp_path)
    try:
        s.create(_record(sid="x", expires_at=1))
        s.create(_record(sid="y", expires_at=int(time.time()) + 3600))

        calls = {"n": 0}
        stop_event = asyncio.Event()

        def fake_down(p):
            calls["n"] += 1

        async def main():
            task = asyncio.create_task(
                reap_loop(
                    store=s,
                    down_session=fake_down,
                    interval_seconds=1,
                    stop=stop_event.wait,
                )
            )
            await asyncio.sleep(2.2)
            stop_event.set()
            await asyncio.wait_for(task, timeout=3)

        asyncio.run(main())
        assert calls["n"] >= 1
        assert s.get("x")["status"] == STATUS_NUKED
    finally:
        s.close()


def test_reap_loop_swallowed_exception_keeps_running(tmp_path: Path):
    s = _tmp_store(tmp_path)
    try:
        s.create(_record(sid="boom", expires_at=1))

        calls = {"n": 0}
        stop_event = asyncio.Event()

        def fake_down(p):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("transient")

        async def main():
            task = asyncio.create_task(
                reap_loop(
                    store=s,
                    down_session=fake_down,
                    interval_seconds=1,
                    stop=stop_event.wait,
                )
            )
            await asyncio.sleep(2.2)
            stop_event.set()
            await asyncio.wait_for(task, timeout=3)

        asyncio.run(main())
        assert calls["n"] >= 2
    finally:
        s.close()