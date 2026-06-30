from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Iterable, Sequence

from api.ssh_tunnel import Tunnel


class MySQLOpsError(Exception):
    pass


@dataclass
class DumpResult:
    db: str
    sql_bytes: bytes


def _resolve_binary(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise MySQLOpsError(f"required binary not found on PATH: {name}")
    return path


def _mysql_env(password: str | None) -> dict[str, str]:
    """Minimal child env. Password (when present) is delivered via MYSQL_PWD so
    it never appears on the child's argv (which is world-readable via
    /proc/<pid>/cmdline). It does appear in /proc/<pid>/environ, which is
    mode 0400 and readable only by the process owner / root.

    `--ssl-mode=DISABLED` is also added unconditionally so future code that
    moves the tunnel listener off-loopback fails loudly.
    """
    env = {
        "PATH": os.environ.get(
            "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": os.environ.get("HOME", "/root"),
    }
    if password is not None:
        env["MYSQL_PWD"] = password
    return env


def dump_db(
    *,
    tunnel: Tunnel,
    db: str,
    user: str,
    password: str,
    host: str | None = None,
    tables: Sequence[str] = (),
    extra_args: Sequence[str] = (),
) -> DumpResult:
    """Run `mysqldump` against prod via the SSH tunnel.

    Returns the SQL bytes (suitable to pipe into `mysql` on the sandbox).

    If `tables` is non-empty, only those tables are dumped (partial dump).
    The dump never includes `CREATE DATABASE`; the caller is responsible for
    ensuring the target DB exists on the sandbox before restoring.

    `host` is the local IP `mysqldump` connects to. Defaults to whatever IP
    the tunnel's local forward listener is bound to.
    """
    mysqldump = _resolve_binary("mysqldump")
    host_arg = host if host is not None else tunnel.local_host
    cmd = [
        mysqldump,
        "--single-transaction",
        "--quick",
        "--routines",
        "--triggers",
        "--events",
        "--no-tablespaces",
        "--no-create-db",
        "--ssl-mode=DISABLED",
        f"--host={host_arg}",
        f"--port={tunnel.local_port}",
        f"--user={user}",
        *extra_args,
        db,
        *tables,
    ]
    proc = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        timeout=1800,
        env=_mysql_env(password),
    )
    if proc.returncode != 0:
        raise MySQLOpsError(
            f"mysqldump {db}"
            + (f" tables={list(tables)}" if tables else "")
            + f" failed (rc={proc.returncode}): {proc.stderr.decode(errors='replace')[:2000]}"
        )
    return DumpResult(db=db, sql_bytes=proc.stdout)


def restore_db(
    *,
    host: str,
    port: int,
    user: str,
    password: str,
    db: str,
    sql_bytes: bytes,
) -> None:
    """Ensure `db` exists, then pipe `sql_bytes` into `mysql`.

    `CREATE DATABASE IF NOT EXISTS` is prepended so this works for both full
    dumps (whose own CREATE DATABASE IF NOT EXISTS becomes a no-op) and
    partial/table-only dumps (which omit CREATE DATABASE entirely).
    """
    _ensure_database(host=host, port=port, user=user, password=password, db=db)
    mysql = _resolve_binary("mysql")
    cmd = [
        mysql,
        f"--host={host}",
        f"--port={port}",
        f"--user={user}",
        db,
    ]
    proc = subprocess.run(
        cmd,
        input=sql_bytes,
        check=False,
        capture_output=True,
        timeout=1800,
        env=_mysql_env(password),
    )
    if proc.returncode != 0:
        raise MySQLOpsError(
            f"mysql restore {db} failed (rc={proc.returncode}): {proc.stderr.decode(errors='replace')[:2000]}"
        )


def _ensure_database(*, host: str, port: int, user: str, password: str, db: str) -> None:
    mysql = _resolve_binary("mysql")
    stmt = f"CREATE DATABASE IF NOT EXISTS `{db}` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci"
    cmd = [
        mysql,
        f"--host={host}",
        f"--port={port}",
        f"--user={user}",
        "-e",
        stmt,
    ]
    proc = subprocess.run(
        cmd, check=False, capture_output=True, timeout=30, env=_mysql_env(password),
    )
    if proc.returncode != 0:
        raise MySQLOpsError(
            f"CREATE DATABASE {db} failed (rc={proc.returncode}): {proc.stderr.decode(errors='replace')[:500]}"
        )


def apply_grants(
    *,
    host: str,
    port: int,
    user: str,
    password: str,
    sql_statements: Iterable[str],
) -> None:
    """Run a sequence of SQL statements against the target MySQL."""
    mysql = _resolve_binary("mysql")
    sql = "\n".join(sql_statements).encode("utf-8")
    cmd = [
        mysql,
        f"--host={host}",
        f"--port={port}",
        f"--user={user}",
    ]
    proc = subprocess.run(
        cmd,
        input=sql,
        check=False,
        capture_output=True,
        timeout=60,
        env=_mysql_env(password),
    )
    if proc.returncode != 0:
        raise MySQLOpsError(
            f"mysql grants failed (rc={proc.returncode}): {proc.stderr.decode(errors='replace')[:2000]}"
        )


def wait_ready(
    *,
    host: str,
    port: int,
    user: str,
    password: str,
    timeout_seconds: int = 60,
) -> None:
    """Poll `mysqladmin ping` until MySQL responds or we time out."""
    mysqladmin = _resolve_binary("mysqladmin")
    cmd = [
        mysqladmin,
        "ping",
        f"--host={host}",
        f"--port={port}",
        f"--user={user}",
    ]
    deadline = time.monotonic() + timeout_seconds
    last_err = "no attempt yet"
    while time.monotonic() < deadline:
        proc = subprocess.run(
            cmd, check=False, capture_output=True, timeout=5, env=_mysql_env(password),
        )
        if proc.returncode == 0:
            return
        last_err = proc.stderr.decode(errors="replace").strip()
        time.sleep(1)
    raise MySQLOpsError(
        f"mysql at {host}:{port} did not become ready in {timeout_seconds}s; last error: {last_err}"
    )
