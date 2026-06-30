from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Path as PathParam, Request, Response, status
from fastapi.responses import JSONResponse, PlainTextResponse

from api import auth, docker_ops, mysql_ops, ssh_tunnel, tls_ops
from api.config import Settings, get_settings, reset_settings_cache
from api.crypto import fernet_from_key
from api.models import (
    CreateSessionRequest,
    CreateSessionResponse,
    DatabaseInfo,
    DeleteResponse,
    ResetTTLResponse,
    SessionView,
    TicketClosedRequest,
    TicketClosedResponse,
)
from api.reaper import reap_loop
from api.service import CreateSessionError, SessionService
from api.state import SessionStore


log = logging.getLogger("sandbox.main")


@dataclass
class AppContext:
    settings: Settings
    store: SessionStore
    service: SessionService


def _build_service(settings: Settings, store: SessionStore) -> SessionService:
    return SessionService(
        settings=settings,
        store=store,
        fernet=fernet_from_key(settings.sandbox_fernet_key),
        open_tunnel=ssh_tunnel.open_tunnel,
        dump_db=mysql_ops.dump_db,
        restore_db=mysql_ops.restore_db,
        apply_grants=mysql_ops.apply_grants,
        wait_ready=mysql_ops.wait_ready,
        up_session=docker_ops.up_session,
        down_session=docker_ops.down_session,
        replace_port_in_compose=docker_ops.replace_port_in_compose,
        render_compose=docker_ops.render_compose,
        render_mysqld_cnf=docker_ops.render_mysqld_cnf,
        render_grant_sql=docker_ops.render_grant_sql,
        generate_session_tls=tls_ops.generate_session_tls,
        wait_healthy=docker_ops.wait_healthy,
        make_session_paths=docker_ops.make_session_paths,
        allocate_port=docker_ops.allocate_port,
        gen_root_password=docker_ops.gen_root_password,
    )


def _build_context(settings: Settings) -> AppContext:
    store = SessionStore(settings.sandbox_state_db)
    service = _build_service(settings, store)
    return AppContext(settings=settings, store=store, service=service)


def create_app(ctx: AppContext | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if ctx is None:
            settings = get_settings()
            app_ctx = _build_context(settings)
        else:
            app_ctx = ctx
        app.state.ctx = app_ctx

        stop = asyncio.Event()
        app.state.reaper_stop = stop

        task = asyncio.create_task(
            reap_loop(
                store=app_ctx.store,
                down_session=docker_ops.down_session,
                interval_seconds=app_ctx.settings.sandbox_reaper_interval_seconds,
                stop=stop.wait,
            )
        )
        app.state.reaper_task = task
        log.info("sandbox api started; reaper interval=%ds",
                 app_ctx.settings.sandbox_reaper_interval_seconds)
        try:
            yield
        finally:
            stop.set()
            try:
                await asyncio.wait_for(task, timeout=5)
            except asyncio.TimeoutError:
                task.cancel()
            app_ctx.store.close()
            log.info("sandbox api stopped")

    app = FastAPI(title="sqldb-sandbox", lifespan=lifespan)

    def _ctx(request: Request) -> AppContext:
        return request.app.state.ctx

    @app.get("/healthz", response_class=JSONResponse)
    def healthz():
        """Shallow liveness — process is up. No external deps probed."""
        return {"status": "ok"}

    @app.get("/readyz", response_class=JSONResponse)
    def readyz(app_ctx: AppContext = Depends(_ctx)):
        """Deep readiness — verifies the dependencies we need to create a session."""
        checks: dict[str, tuple[str, str]] = {}
        # SQLite store reachable
        try:
            app_ctx.store.list_all()
            checks["sqlite"] = ("ok", "")
        except Exception as exc:
            checks["sqlite"] = ("fail", str(exc)[:200])
        # Docker daemon reachable
        try:
            import shutil
            if not shutil.which("docker"):
                checks["docker_binary"] = ("fail", "docker binary not on PATH")
            else:
                import subprocess
                p = subprocess.run(
                    ["docker", "info", "--format", "{{.ServerVersion}}"],
                    check=False, capture_output=True, timeout=5,
                )
                if p.returncode == 0:
                    checks["docker"] = ("ok", p.stdout.decode().strip())
                else:
                    checks["docker"] = ("fail", p.stderr.decode(errors='replace')[:200])
        except Exception as exc:
            checks["docker"] = ("fail", str(exc)[:200])
        # mysql / mysqldump / mysqladmin on PATH
        for bin in ("mysqldump", "mysql", "mysqladmin"):
            import shutil as _sh
            checks[f"bin_{bin}"] = ("ok", "") if _sh.which(bin) else ("fail", "not on PATH")

        all_ok = all(c[0] == "ok" for c in checks.values())
        return JSONResponse(
            status_code=200 if all_ok else 503,
            content={"status": "ok" if all_ok else "degraded", "checks": checks},
        )

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics(app_ctx: AppContext = Depends(_ctx)):
        """Tiny Prometheus-style metrics. No auth — operator can firewall."""
        from collections import Counter
        rows = app_ctx.store.list_all()
        by_status = Counter(r["status"] for r in rows)
        total = len(rows)
        oldest_unused = min(
            ((now - r["created_at"]) for r in rows if r["status"] == "ready"),
            default=0,
        )
        import time as _t
        now = int(_t.time())
        body = (
            "# HELP sqldb_sandbox_sessions_total Total sessions in store\n"
            "# TYPE sqldb_sandbox_sessions_total gauge\n"
            f"sqldb_sandbox_sessions_total {total}\n"
            "# HELP sqldb_sandbox_sessions_by_status Sessions by status\n"
            "# TYPE sqldb_sandbox_sessions_by_status gauge\n"
        )
        for status, n in by_status.items():
            body += f'sqldb_sandbox_sessions_by_status{{status="{status}"}} {n}\n'
        body += (
            "# HELP sqldb_sandbox_oldest_ready_seconds Age of oldest ready session\n"
            "# TYPE sqldb_sandbox_oldest_ready_seconds gauge\n"
            f"sqldb_sandbox_oldest_ready_seconds {oldest_unused}\n"
        )
        return Response(content=body, media_type="text/plain; version=0.0.4")

    _CATEGORY_TO_HTTP = {
        "validation": status.HTTP_422_UNPROCESSABLE_ENTITY,
        "port": status.HTTP_503_SERVICE_UNAVAILABLE,
        "ssh": status.HTTP_502_BAD_GATEWAY,
        "dump": status.HTTP_502_BAD_GATEWAY,
        "container": status.HTTP_502_BAD_GATEWAY,
        "restore": status.HTTP_502_BAD_GATEWAY,
        "grant": status.HTTP_502_BAD_GATEWAY,
        "internal": status.HTTP_500_INTERNAL_SERVER_ERROR,
    }

    # Generic, public-safe messages keyed by category. The full exception
    # text (which can include hostname/IP/path details from upstream stderr)
    # is logged server-side and never returned to clients.
    _PUBLIC_MESSAGES = {
        "port": "no free sandbox ports; retry later",
        "ssh": "could not reach the bastion",
        "dump": "prod dump failed",
        "container": "container startup failed",
        "restore": "restore failed",
        "grant": "applying permissions failed",
        "internal": "internal error",
    }

    @app.post("/instance", response_model=CreateSessionResponse, status_code=201,
              dependencies=[Depends(auth.enforce_cf_access), Depends(auth.enforce_api_key)])
    def create_instance(req: CreateSessionRequest, app_ctx: AppContext = Depends(_ctx)):
        try:
            data = app_ctx.service.create(req.ticket, req.dbs)
        except CreateSessionError as exc:
            http_code = _CATEGORY_TO_HTTP.get(exc.category, status.HTTP_500_INTERNAL_SERVER_ERROR)
            log.warning(
                "create failed sid=%s category=%s message=%s",
                exc.sid, exc.category, exc,
            )
            return JSONResponse(
                status_code=http_code,
                content={
                    "detail": _PUBLIC_MESSAGES.get(exc.category, "internal error"),
                    "category": exc.category,
                    "session_id": exc.sid,
                    "hint": "see server logs for the full error",
                },
            )
        except Exception:
            log.exception("create failed (unclassified)")
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "internal error", "category": "internal"},
            )
        return CreateSessionResponse(
            session_id=data["session_id"],
            api_host=data["api_host"],
            mysql_host=data["mysql_host"],
            mysql_port=data["mysql_port"],
            expires_at=data["expires_at"],
            max_extended_until=data["max_extended_until"],
            ca_url=data["ca_url"],
            databases=data["databases"],
        )

    @app.get("/session/{session_id}", response_model=SessionView,
             dependencies=[Depends(auth.enforce_cf_access), Depends(auth.enforce_api_key)])
    def get_session(session_id: str = PathParam(..., min_length=8),
                    app_ctx: AppContext = Depends(_ctx)):
        view = app_ctx.service.view(session_id)
        if view is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "session not found")
        return SessionView(
            session_id=view["session_id"],
            ticket=view["ticket"],
            status=view["status"],
            api_host=view["api_host"],
            mysql_host=view["mysql_host"],
            mysql_port=view["mysql_port"],
            expires_at=view["expires_at"],
            max_extended_until=view["max_extended_until"],
            ttl_extended=view["ttl_extended"],
            ca_url=view["ca_url"],
            databases=[DatabaseInfo(**d) for d in view["databases"]],
        )

    @app.post("/session/{session_id}/reset-ttl", response_model=ResetTTLResponse,
              dependencies=[Depends(auth.enforce_cf_access), Depends(auth.enforce_api_key)])
    def reset_ttl(session_id: str = PathParam(..., min_length=8),
                  app_ctx: AppContext = Depends(_ctx)):
        try:
            res = app_ctx.service.reset_ttl(session_id)
        except KeyError:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "session not found")
        except PermissionError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc))
        return ResetTTLResponse(**res)

    @app.delete("/session/{session_id}", response_model=DeleteResponse,
                dependencies=[Depends(auth.enforce_cf_access), Depends(auth.enforce_api_key)])
    def delete_session(session_id: str = PathParam(..., min_length=8),
                       app_ctx: AppContext = Depends(_ctx)):
        try:
            app_ctx.service.nuke(session_id)
        except KeyError:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "session not found")
        return DeleteResponse(session_id=session_id, status="nuked")

    @app.get("/session-tls/{session_id}/ca.pem",
             dependencies=[Depends(auth.enforce_cf_access), Depends(auth.enforce_api_key)],
             response_class=PlainTextResponse)
    def get_ca(session_id: str = PathParam(..., min_length=8),
               app_ctx: AppContext = Depends(_ctx)):
        try:
            pem = app_ctx.service.ca_pem(session_id)
        except KeyError:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "session not found")
        except FileNotFoundError:
            raise HTTPException(status.HTTP_410_GONE, "tls material missing")
        return Response(content=pem, media_type="application/x-pem-file")

    @app.post("/webhook/ticket-closed", response_model=TicketClosedResponse)
    def ticket_closed(
        req: TicketClosedRequest,
        app_ctx: AppContext = Depends(_ctx),
        _body: bytes = Depends(auth.require_webhook_signature),
    ):
        try:
            status_value = app_ctx.service.nuke_by_ticket(req.ticket, req.session_id)
        except KeyError:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                "session not found or does not belong to that ticket",
            )
        log.info("ticket-closed webhook: ticket=%s sid=%s status=%s",
                 req.ticket, req.session_id, status_value)
        return TicketClosedResponse(
            ticket=req.ticket,
            session_id=req.session_id,
            status=status_value,
        )

    return app


app = create_app()


def reset_for_tests() -> None:
    reset_settings_cache()