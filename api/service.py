from __future__ import annotations

import json
import logging
import secrets
import shutil
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from cryptography.fernet import Fernet

from api.config import Settings
from api.crypto import decrypt_creds, encrypt_creds, gen_password
from api.docker_ops import DockerOpsError
from api.models import DBSpec, DatabaseInfo
from api.mysql_ops import MySQLOpsError
from api.ssh_tunnel import TunnelError
from api.state import STATUS_ERROR, STATUS_NUKED, STATUS_READY, STATUS_STARTING, SessionStore


log = logging.getLogger("sandbox.service")


class CreateSessionError(Exception):
    """Failure during POST /instance.

    `category` is one of:
    - "validation"   : bad request shape (shouldn't reach here — pydantic catches)
    - "ssh"          : cannot reach or authenticate the bastion
    - "dump"         : `mysqldump` against prod failed
    - "container"    : docker compose / container startup failed
    - "restore"      : pipe-restore into the sandbox mysql failed
    - "grant"        : applying per-DB grants failed
    - "port"         : port range exhausted / bind conflict
    - "internal"     : bug or unexpected infra failure
    """

    def __init__(self, *, category: str, sid: str, message: str):
        self.category = category
        self.sid = sid
        super().__init__(message)


def _classify_failure(exc: BaseException) -> tuple[str, str]:
    """Map a low-level exception to a (category, user_message) pair."""
    if isinstance(exc, TunnelError):
        return "ssh", f"SSH tunnel failed: {exc}"
    if isinstance(exc, MySQLOpsError):
        msg = str(exc).lower()
        if "mysqldump" in msg:
            return "dump", f"prod dump failed: {exc}"
        if "create database" in msg:
            return "restore", f"create database failed: {exc}"
        return "restore", f"mysql restore failed: {exc}"
    if isinstance(exc, DockerOpsError):
        msg = str(exc).lower()
        if "port" in msg:
            return "port", f"container port error: {exc}"
        return "container", f"container error: {exc}"
    return "internal", f"unexpected error: {exc}"


DumpFn = Callable[..., object]
RestoreFn = Callable[..., None]
CloneFn = Callable[..., None]
ApplyGrantsFn = Callable[..., None]
WaitReadyFn = Callable[..., None]
SetGeneralLogFn = Callable[..., None]
UpFn = Callable[[Path], None]
DownFn = Callable[[Path], None]
ReplacePortFn = Callable[[Path, str, int], None]
RenderComposeFn = Callable[..., Path]
RenderCnfFn = Callable[..., Path]
RenderGrantsFn = Callable[..., str]
GenerateTLSFn = Callable[..., object]
WaitHealthyFn = Callable[..., None]
MakePathsFn = Callable[..., object]
AllocatePortFn = Callable[..., int]
GenPasswordFn = Callable[[], str]
OpenTunnelFn = Callable[..., object]


@dataclass
class SessionService:
    settings: Settings
    store: SessionStore
    fernet: Fernet

    open_tunnel: OpenTunnelFn
    dump_db: DumpFn
    restore_db: RestoreFn
    clone_db: CloneFn
    apply_grants: ApplyGrantsFn
    wait_ready: WaitReadyFn
    set_general_log: SetGeneralLogFn
    up_session: UpFn
    down_session: DownFn
    replace_port_in_compose: ReplacePortFn
    render_compose: RenderComposeFn
    render_mysqld_cnf: RenderCnfFn
    render_grant_sql: RenderGrantsFn
    generate_session_tls: GenerateTLSFn
    wait_healthy: WaitHealthyFn
    make_session_paths: MakePathsFn
    allocate_port: AllocatePortFn
    gen_root_password: GenPasswordFn

    def encrypt_creds(self, creds: dict) -> bytes:
        return encrypt_creds(creds, self.fernet)

    def decrypt_creds(self, token: bytes) -> dict:
        return decrypt_creds(token, self.fernet)

    def create(self, ticket: str, dbs: list[DBSpec]) -> dict:
        sid = str(uuid.uuid4())
        now = int(time.time())
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        paths = self.make_session_paths(
            sid=sid, ticket=ticket, date_str=date_str, settings=self.settings
        )

        # Atomically: read used_ports + allocate + INSERT, all under one
        # BEGIN IMMEDIATE. Two concurrent /instance requests cannot pick the
        # same host port.
        def _factory(host_port: int) -> dict:
            return {
                "id": sid,
                "ticket": ticket,
                "date": date_str,
                "dbs_json": json.dumps([s.model_dump() for s in dbs]),
                "creds_enc": b"\x00",
                "host": self.settings.sandbox_public_host,
                "mysql_host": self.settings.sandbox_mysql_host,
                "port": host_port,
                "container_name": f"sandbox-{sid}",
                "compose_path": str(paths.compose_path),
                "tls_dir": str(paths.tls_dir),
                "log_dir": str(paths.log_dir),
                "created_at": now,
                # Placeholder row while create is in progress. The reaper uses
                # `expires_at` as the stuck-create deadline, so give slow dumps
                # enough room before treating the session as orphaned.
                "expires_at": now + 3600,
                "max_extended_until": now,
                "ttl_extended": 0,
                "status": STATUS_STARTING,
            }

        try:
            placeholder = self.store.reserve_session(
                record_factory=_factory,
                port_allocator=lambda used: self.allocate_port(used, self.settings),
            )
        except DockerOpsError as exc:
            shutil.rmtree(paths.session_dir, ignore_errors=True)
            shutil.rmtree(paths.tls_dir, ignore_errors=True)
            shutil.rmtree(paths.log_dir, ignore_errors=True)
            raise CreateSessionError(
                category="port", sid=sid, message=str(exc)
            ) from exc

        host_port = placeholder["port"]
        container_name = placeholder["container_name"]
        try:
            return self._do_create(
                sid=sid,
                ticket=ticket,
                dbs=dbs,
                paths=paths,
                host_port=host_port,
                container_name=container_name,
                created_at=now,
                placeholder=placeholder,
            )
        except BaseException as exc:
            category, msg = _classify_failure(exc)
            log.exception(
                "create failed sid=%s ticket=%s category=%s", sid, ticket, category,
            )
            self._cleanup_failed_create(sid, paths, container_name)
            try:
                self.store.set_status(sid, STATUS_ERROR)
            except Exception:
                log.exception("set_status(error) failed for sid=%s", sid)
            if isinstance(exc, CreateSessionError):
                raise
            raise CreateSessionError(category=category, sid=sid, message=msg) from exc
        container_name = placeholder["container_name"]
        try:
            return self._do_create(
                sid=sid,
                ticket=ticket,
                dbs=dbs,
                paths=paths,
                host_port=host_port,
                container_name=container_name,
                created_at=now,
                placeholder=placeholder,
            )
        except BaseException as exc:
            category, msg = _classify_failure(exc)
            log.exception(
                "create failed sid=%s ticket=%s category=%s", sid, ticket, category,
            )
            self._cleanup_failed_create(sid, paths, container_name)
            try:
                self.store.set_status(sid, STATUS_ERROR)
            except Exception:
                log.exception("set_status(error) failed for sid=%s", sid)
            if isinstance(exc, CreateSessionError):
                raise
            raise CreateSessionError(category=category, sid=sid, message=msg) from exc

    def _do_create(
        self,
        *,
        sid: str,
        ticket: str,
        dbs: list[DBSpec],
        paths,
        host_port: int,
        container_name: str,
        created_at: int,
        placeholder: dict,
    ) -> dict:
        db_creds: list[dict] = []
        grants: list[dict] = []
        for spec in dbs:
            user = f"u_{spec.name}_{secrets.token_hex(4)}"
            password = gen_password(24)
            db_creds.append(
                {"name": spec.name, "user": user, "password": password, "tables": spec.table_list}
            )
            grants.append({"db": spec.name, "user": user, "password": password})
        root_password = self.gen_root_password()

        self.generate_session_tls(
            sid,
            paths.tls_dir,
            container_hostname=container_name,
            mysql_host_ip=self.settings.sandbox_mysql_host,
        )

        # Per-session CA cert used by every client call into this sandbox.
        # The server is configured with require-secure-transport=ON, so
        # passing --ssl-mode=REQUIRED here is mandatory.
        tls_ca_path = paths.tls_dir / "ca.pem"

        self.render_compose(
            paths=paths,
            sid=sid,
            container_name=container_name,
            mysql_image=self.settings.sandbox_mysql_image,
            bind_host="127.0.0.1",
            host_port=host_port,
            root_password=root_password,
        )
        self.render_mysqld_cnf(paths=paths)

        self.up_session(paths.compose_path)
        self.wait_healthy(container_name, timeout_seconds=600)
        self.wait_ready(
            host="127.0.0.1",
            port=host_port,
            user="root",
            password=root_password,
            timeout_seconds=60,
            ssl_ca=tls_ca_path,
        )
        try:
            self.set_general_log(
                False,
                host="127.0.0.1",
                port=host_port,
                user="root",
                password=root_password,
                ssl_ca=tls_ca_path,
            )
        except Exception:
            log.exception("set_general_log(False) failed; audit log will include dump")
        with self.open_tunnel(
            ssh_host=self.settings.prod_ssh_host,
            ssh_port=self.settings.prod_ssh_port,
            ssh_user=self.settings.prod_ssh_user,
            ssh_key=self.settings.prod_ssh_key,
            remote_host=self.settings.prod_mysql_host,
            remote_port=self.settings.prod_mysql_port,
            bind_host=self.settings.sandbox_tunnel_bind_host,
        ) as tunnel:
            for spec in dbs:
                self.clone_db(
                    tunnel=tunnel,
                    source_db=spec.name,
                    source_user=self.settings.prod_mysql_user,
                    source_password=self.settings.prod_mysql_password,
                    target_host="127.0.0.1",
                    target_port=host_port,
                    target_user="root",
                    target_password=root_password,
                    target_db=spec.name,
                    host=tunnel.local_host,
                    tables=spec.table_list or (),
                    ssl_ca=tls_ca_path,
                )
        try:
            self.set_general_log(
                True,
                host="127.0.0.1",
                port=host_port,
                user="root",
                password=root_password,
                ssl_ca=tls_ca_path,
            )
        except Exception:
            log.exception("set_general_log(True) failed; dev queries may not be audited")
        self.apply_grants(
            host="127.0.0.1",
            port=host_port,
            user="root",
            password=root_password,
            sql_statements=[self.render_grant_sql(grants=grants)],
            ssl_ca=tls_ca_path,
        )

        # Re-render the compose file with the public bind host — clean re-render
        # rather than sed-mutating, so a future template change can't silently
        # match the wrong line.
        self.render_compose(
            paths=paths,
            sid=sid,
            container_name=container_name,
            mysql_image=self.settings.sandbox_mysql_image,
            bind_host="0.0.0.0",
            host_port=host_port,
            root_password=root_password,
        )
        self.down_session(paths.compose_path, remove_volumes=False)
        self.up_session(paths.compose_path)
        self.wait_healthy(container_name, timeout_seconds=300)

        expires_at = created_at + self.settings.sandbox_ttl_default_seconds
        max_extended_until = created_at + self.settings.sandbox_ttl_max_seconds

        creds_blob = self.encrypt_creds(
            {"dbs": db_creds, "root_password": root_password}
        )
        # Only flip status='starting' → 'ready'. If a parallel process already
        # nuked the row, treat as failure rather than resurrecting.
        if not self.store.update_to_ready(
            sid,
            creds_enc=creds_blob,
            expires_at=expires_at,
            max_extended_until=max_extended_until,
        ):
            log.warning(
                "update_to_ready lost the race for sid=%s; tearing down", sid,
            )
            try:
                self.down_session(paths.compose_path, remove_volumes=True)
            except Exception:
                log.exception("late cleanup down_session failed sid=%s", sid)
            raise CreateSessionError(
                category="internal",
                sid=sid,
                message="session row vanished during create",
            )

        log.info(
            "session created sid=%s ticket=%s port=%d db_count=%d",
            sid, ticket, host_port, len(dbs),
        )

        return {
            "session_id": sid,
            "api_host": self.settings.sandbox_public_host,
            "mysql_host": self.settings.sandbox_mysql_host,
            "mysql_port": host_port,
            "expires_at": datetime.fromtimestamp(expires_at, tz=timezone.utc),
            "max_extended_until": datetime.fromtimestamp(
                max_extended_until, tz=timezone.utc
            ),
            "ca_url": f"https://{self.settings.sandbox_public_host}/session-tls/{sid}/ca.pem",
            "databases": [
                DatabaseInfo(
                    name=d["name"], user=d["user"], password=d["password"], tables=d.get("tables")
                )
                for d in db_creds
            ],
        }

    def _cleanup_failed_create(self, sid: str, paths, container_name: str) -> None:
        """Best-effort cleanup after a failed /instance. Never raises."""
        try:
            self.down_session(paths.compose_path, remove_volumes=True)
        except Exception:
            log.exception("cleanup: down_session failed for sid=%s", sid)
        try:
            shutil.rmtree(paths.session_dir, ignore_errors=True)
            shutil.rmtree(paths.tls_dir, ignore_errors=True)
            # Keep paths.log_dir on purpose: container stdout from the failed
            # run can be useful for postmortem.
        except Exception:
            log.exception("cleanup: rmtree failed for sid=%s", sid)

    def view(self, sid: str) -> dict | None:
        record = self.store.get(sid)
        if record is None:
            return None
        creds = self.decrypt_creds(record["creds_enc"])
        return {
            "session_id": record["id"],
            "ticket": record["ticket"],
            "status": record["status"],
            "api_host": record["host"],
            "mysql_host": record["mysql_host"],
            "mysql_port": record["port"],
            "expires_at": datetime.fromtimestamp(record["expires_at"], tz=timezone.utc),
            "max_extended_until": datetime.fromtimestamp(
                record["max_extended_until"], tz=timezone.utc
            ),
            "ttl_extended": bool(record["ttl_extended"]),
            "ca_url": f"https://{record['host']}/session-tls/{record['id']}/ca.pem",
            "databases": creds["dbs"],
        }

    def reset_ttl(self, sid: str) -> dict:
        record = self.store.get(sid)
        if record is None:
            raise KeyError(sid)
        if record["status"] not in (STATUS_READY,):
            raise PermissionError(f"cannot reset ttl for status={record['status']}")
        if record["ttl_extended"]:
            raise PermissionError("ttl already extended once")
        now = int(time.time())
        if now >= record["max_extended_until"]:
            raise PermissionError("max ttl already reached")
        new_expires_at = min(
            record["max_extended_until"],
            record["expires_at"] + self.settings.sandbox_ttl_reset_add_seconds,
        )
        self.store.update_ttl(sid, new_expires_at, 1)
        return {
            "session_id": sid,
            "expires_at": datetime.fromtimestamp(new_expires_at, tz=timezone.utc),
            "max_extended_until": datetime.fromtimestamp(
                record["max_extended_until"], tz=timezone.utc
            ),
            "reset_used": True,
        }

    def nuke(self, sid: str) -> None:
        record = self.store.get(sid)
        if record is None:
            raise KeyError(sid)
        try:
            self.down_session(Path(record["compose_path"]))
        except Exception:
            log.exception("nuke: down_session failed for %s", sid)
        self.store.set_status(sid, STATUS_NUKED)

    def nuke_by_ticket(self, ticket: str, sid: str) -> str:
        """Nuke a session tied to a specific ticket. Idempotent.

        Returns:
            "nuked"          if the session was active and is now nuked.
            "already_nuked"  if the session was already nuked (no-op).

        Raises:
            KeyError if the session does not exist or the session_id does not
            belong to the given ticket.
        """
        record = self.store.get(sid)
        if record is None:
            raise KeyError(sid)
        if record["ticket"] != ticket:
            raise KeyError(sid)
        if record["status"] == STATUS_NUKED:
            return "already_nuked"
        try:
            self.down_session(Path(record["compose_path"]))
        except Exception:
            log.exception("nuke_by_ticket: down_session failed for %s", sid)
        self.store.set_status(sid, STATUS_NUKED)
        return "nuked"

    def ca_pem(self, sid: str) -> bytes:
        record = self.store.get(sid)
        if record is None:
            raise KeyError(sid)
        ca = Path(record["tls_dir"]) / "ca.pem"
        if not ca.exists():
            raise FileNotFoundError(str(ca))
        return ca.read_bytes()
