from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Iterable, Sequence

from api.ssh_tunnel import Tunnel


class MySQLOpsError(Exception):
    pass


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


def _mysqldump_cmd(
    *,
    tunnel: Tunnel,
    db: str,
    user: str,
    host: str | None = None,
    tables: Sequence[str] = (),
    extra_args: Sequence[str] = (),
) -> list[str]:
    mysqldump = _resolve_binary("mysqldump")
    host_arg = host if host is not None else tunnel.local_host
    return [
        mysqldump,
        "--single-transaction",
        "--quick",
        "--routines",
        "--triggers",
        "--events",
        "--no-tablespaces",
        "--no-create-db",
        "--column-statistics=0",
        "--ssl-mode=DISABLED",
        f"--host={host_arg}",
        f"--port={tunnel.local_port}",
        f"--user={user}",
        *extra_args,
        db,
        *tables,
    ]


def _mysql_restore_cmd(
    *, host: str, port: int, user: str, db: str, ssl_ca: Path | None = None
) -> list[str]:
    mysql = _resolve_binary("mysql")
    cmd = [
        mysql,
        f"--host={host}",
        f"--port={port}",
        f"--user={user}",
    ]
    if ssl_ca is not None:
        cmd.extend(["--ssl-mode=REQUIRED", f"--ssl-ca={ssl_ca}"])
    cmd.append(db)
    return cmd


def dump_db(
    *,
    tunnel: Tunnel,
    db: str,
    user: str,
    password: str,
    host: str | None = None,
    tables: Sequence[str] = (),
    extra_args: Sequence[str] = (),
) -> bytes:
    """Run `mysqldump` against prod via the SSH tunnel.

    Returns the SQL bytes (suitable to pipe into `mysql` on the sandbox).

    If `tables` is non-empty, only those tables are dumped (partial dump).
    The dump never includes `CREATE DATABASE`; the caller is responsible for
    ensuring the target DB exists on the sandbox before restoring.

    `host` is the local IP `mysqldump` connects to. Defaults to whatever IP
    the tunnel's local forward listener is bound to.
    """
    cmd = _mysqldump_cmd(
        tunnel=tunnel,
        db=db,
        user=user,
        host=host,
        tables=tables,
        extra_args=extra_args,
    )
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
    return proc.stdout


def clone_db(
    *,
    tunnel: Tunnel,
    source_db: str,
    source_user: str,
    source_password: str,
    target_host: str,
    target_port: int,
    target_user: str,
    target_password: str,
    target_db: str,
    host: str | None = None,
    tables: Sequence[str] = (),
    extra_args: Sequence[str] = (),
    timeout_seconds: int = 7200,
    ssl_ca: Path | None = None,
) -> None:
    """Stream `mysqldump` directly into `mysql` on the sandbox.

    This avoids writing the full dump to disk or holding it in Python memory,
    which is materially faster for large databases.

    `ssl_ca` is the per-session CA cert path. When set, the restore side uses
    `--ssl-mode=REQUIRED --ssl-ca=<path>` to authenticate the sandbox MySQL
    against the per-session CA. The dump side talks over SSH so it uses
    `--ssl-mode=DISABLED` (in-transit security is provided by the tunnel).
    """
    _ensure_database(
        host=target_host,
        port=target_port,
        user=target_user,
        password=target_password,
        db=target_db,
        ssl_ca=ssl_ca,
    )
    dump_cmd = _mysqldump_cmd(
        tunnel=tunnel,
        db=source_db,
        user=source_user,
        host=host,
        tables=tables,
        extra_args=extra_args,
    )
    restore_cmd = _mysql_restore_cmd(
        host=target_host,
        port=target_port,
        user=target_user,
        db=target_db,
        ssl_ca=ssl_ca,
    )

    dump_proc = subprocess.Popen(
        dump_cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_mysql_env(source_password),
    )
    assert dump_proc.stdout is not None
    dump_stderr_fp = dump_proc.stderr
    restore_proc = subprocess.Popen(
        restore_cmd,
        stdin=dump_proc.stdout,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=_mysql_env(target_password),
    )
    dump_proc.stdout.close()

    try:
        _, restore_stderr = restore_proc.communicate(timeout=timeout_seconds)
        dump_rc = dump_proc.wait(timeout=30)
    except subprocess.TimeoutExpired as exc:
        dump_proc.kill()
        restore_proc.kill()
        dump_proc.wait()
        restore_proc.wait()
        raise MySQLOpsError(
            f"streaming clone {source_db}->{target_db} exceeded {timeout_seconds}s"
        ) from exc

    dump_stderr = b""
    if dump_stderr_fp is not None:
        dump_stderr = dump_stderr_fp.read()
        dump_stderr_fp.close()
    restore_stderr = restore_stderr or b""

    dump_text = dump_stderr.decode(errors="replace")[:2000]
    restore_text = restore_stderr.decode(errors="replace")[:2000]

    # Surface whichever side failed; if both did, report both so we can tell
    # whether it's a dump-side mysqldump failure or a restore-side TLS/auth
    # failure masquerading as a SIGPIPE upstream.
    dump_failed = dump_rc != 0
    restore_failed = restore_proc.returncode != 0
    if dump_failed or restore_failed:
        parts: list[str] = []
        if restore_failed:
            parts.append(
                f"mysql restore {target_db} failed (rc={restore_proc.returncode}): {restore_text}"
            )
        if dump_failed:
            parts.append(
                f"mysqldump {source_db}"
                + (f" tables={list(tables)}" if tables else "")
                + f" failed (rc={dump_rc}): {dump_text}"
            )
        raise MySQLOpsError("; ".join(parts))


def restore_db(
    *,
    host: str,
    port: int,
    user: str,
    password: str,
    db: str,
    sql_bytes: bytes,
    ssl_ca: Path | None = None,
) -> None:
    """Ensure `db` exists, then pipe `sql_bytes` into `mysql`.

    `CREATE DATABASE IF NOT EXISTS` is prepended so this works for both full
    dumps (whose own CREATE DATABASE IF NOT EXISTS becomes a no-op) and
    partial/table-only dumps (which omit CREATE DATABASE entirely).
    """
    _ensure_database(
        host=host, port=port, user=user, password=password, db=db, ssl_ca=ssl_ca,
    )
    cmd = _mysql_restore_cmd(
        host=host, port=port, user=user, db=db, ssl_ca=ssl_ca,
    )
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


def _ensure_database(
    *,
    host: str,
    port: int,
    user: str,
    password: str,
    db: str,
    ssl_ca: Path | None = None,
) -> None:
    mysql = _resolve_binary("mysql")
    stmt = f"CREATE DATABASE IF NOT EXISTS `{db}` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci"
    cmd = [
        mysql,
        f"--host={host}",
        f"--port={port}",
        f"--user={user}",
    ]
    if ssl_ca is not None:
        cmd.extend(["--ssl-mode=REQUIRED", f"--ssl-ca={ssl_ca}"])
    cmd.extend(["-e", stmt])
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
    ssl_ca: Path | None = None,
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
    if ssl_ca is not None:
        cmd.extend(["--ssl-mode=REQUIRED", f"--ssl-ca={ssl_ca}"])
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
    ssl_ca: Path | None = None,
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
    if ssl_ca is not None:
        cmd.extend(["--ssl-mode=REQUIRED", f"--ssl-ca={ssl_ca}"])
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
