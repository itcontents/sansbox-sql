from __future__ import annotations

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Awaitable, Callable

from api.state import STATUS_EXPIRED, STATUS_NUKED, SessionStore


log = logging.getLogger("sandbox.reaper")


def _teardown(call: Callable[[Path, ...], None], compose_path: Path, **kwargs):
    """Run `call(compose_path, **kwargs)`, handling the legacy signature
    that doesn't accept `remove_volumes`. Returns whether teardown succeeded.
    """
    # Orphan cleanup: if the compose file is gone (create crashed before
    # writing it, or it was removed on teardown), there is nothing to do.
    if not compose_path.exists():
        return True
    try:
        call(compose_path, **kwargs)
        return True
    except TypeError:
        # Mock / older signature without the kwarg.
        try:
            call(compose_path)
            return True
        except Exception as exc:
            log.exception("reaper: down_session (legacy) failed: %s", exc)
            return False
    except Exception as exc:
        log.exception("reaper: down_session failed: %s", exc)
        return False


def reap_once(
    *,
    store: SessionStore,
    down_session: Callable[[Path], None],
    now: int | None = None,
    stuck_grace_seconds: int = 300,
    down_with_volumes: bool = False,
    parallel_workers: int = 4,
) -> list[dict]:
    """Claim and nuke every session that should be gone.

    Two buckets:
    - ready/expired past their TTL  → standard teardown (no `-v`)
    - starting/error past a grace   → orphans from crashed/half-failed creates

    Teardowns run on a small thread pool so the reaper keeps up when many
    sessions expire in the same tick. Returns the list of nuked records.
    """
    now = now if now is not None else int(time.time())
    nuked: list[dict] = []

    expired = store.claim_expired(now)
    stuck = store.claim_stuck(now, grace_seconds=stuck_grace_seconds)

    if not expired and not stuck:
        return []

    # Phase 1: dispatch teardowns concurrently. `down_session` itself shell-outs
    # to docker, which serialises internally — workers > 4 doesn't help.
    pool = ThreadPoolExecutor(max_workers=max(1, parallel_workers))

    def teardown(rec: dict, remove_volumes: bool) -> tuple[dict, bool]:
        compose_path = Path(rec["compose_path"])
        ok = _teardown(down_session, compose_path, remove_volumes=remove_volumes)
        return rec, ok

    futures = []
    for rec in expired:
        futures.append(pool.submit(teardown, rec, False))
    for rec in stuck:
        futures.append(pool.submit(teardown, rec, down_with_volumes))

    # Phase 2: serialise state writes (sqlite is happy serial).
    for fut in futures:
        rec, ok = fut.result()
        if not ok:
            continue
        sid = rec["id"]
        was_stuck = rec["status"] in (STATUS_EXPIRED, "starting", "error") and rec in stuck
        # The records from `expired` are already in 'expired' (claim_expired
        # transitions ready→expired atomically).
        if was_stuck:
            store.mark_nuked(sid)
            log.warning(
                "reaper: nuked stuck session=%s status=%s ticket=%s compose=%s "
                "(create likely failed or process crashed)",
                sid, rec.get("status"), rec.get("ticket"),
                rec["compose_path"],
            )
        else:
            store.set_status(sid, STATUS_NUKED)
            log.info(
                "reaper: nuked expired session=%s ticket=%s compose=%s",
                sid, rec.get("ticket"), rec["compose_path"],
            )
        nuked.append(rec)

    pool.shutdown(wait=True)
    return nuked


async def reap_loop(
    *,
    store: SessionStore,
    down_session: Callable[[Path], None],
    interval_seconds: int,
    stop: Callable[[], Awaitable[None]] | None = None,
) -> None:
    """Long-lived background loop. Returns when `stop()` is awaited or cancelled."""
    stop_event = asyncio.Event()
    if stop is not None:
        async def _bridge():
            await stop()
            stop_event.set()
        asyncio.create_task(_bridge())

    while not stop_event.is_set():
        try:
            reap_once(store=store, down_session=down_session)
        except Exception:
            log.exception("reaper: iteration failed")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            break