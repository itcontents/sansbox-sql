from __future__ import annotations

import re
import secrets
import socket
import string
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from jinja2 import Environment, FileSystemLoader, select_autoescape

from api.config import Settings


TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
_ENV = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(disabled_extensions=("j2",)),
    keep_trailing_newline=True,
)


class DockerOpsError(Exception):
    pass


@dataclass
class SessionPaths:
    session_dir: Path
    compose_path: Path
    cnf_path: Path
    tls_dir: Path
    log_dir: Path


def allocate_port(used: Iterable[int], settings: Settings) -> int:
    used_set = set(used)
    for p in settings.port_range:
        if p not in used_set:
            return p
    raise DockerOpsError("no free ports in configured range")


def make_session_paths(
    *,
    sid: str,
    ticket: str,
    date_str: str,
    settings: Settings,
) -> SessionPaths:
    compose_dir = settings.sandbox_compose_dir / sid
    compose_dir.mkdir(parents=True, exist_ok=True)
    log_dir = settings.sandbox_log_dir / f"{ticket}-{date_str}" / sid
    log_dir.mkdir(parents=True, exist_ok=True)
    tls_dir = settings.sandbox_tls_dir / sid
    tls_dir.mkdir(parents=True, exist_ok=True)
    return SessionPaths(
        session_dir=compose_dir,
        compose_path=compose_dir / "docker-compose.yml",
        cnf_path=compose_dir / "mysqld.cnf",
        tls_dir=tls_dir,
        log_dir=log_dir,
    )


def render_compose(
    *,
    paths: SessionPaths,
    sid: str,
    container_name: str,
    mysql_image: str,
    bind_host: str,
    host_port: int,
    root_password: str,
) -> Path:
    template = _ENV.get_template("docker-compose.yml.j2")
    rendered = template.render(
        container_name=container_name,
        mysql_image=mysql_image,
        sid=sid,
        bind_host=bind_host,
        host_port=host_port,
        root_password=root_password,
        log_dir=str(paths.log_dir),
        tls_dir=str(paths.tls_dir),
        cnf_path=str(paths.cnf_path),
    )
    paths.compose_path.write_text(rendered)
    paths.compose_path.chmod(0o640)
    return paths.compose_path


def render_mysqld_cnf(*, paths: SessionPaths) -> Path:
    template = _ENV.get_template("mysqld.cnf.j2")
    paths.cnf_path.write_text(template.render())
    paths.cnf_path.chmod(0o644)
    return paths.cnf_path


def render_grant_sql(
    *,
    grants: list[dict[str, str]],
) -> str:
    template = _ENV.get_template("grant_user.sql.j2")
    return template.render(grants=grants)


def gen_root_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(32))


def compose(*, compose_path: Path, args: list[str], timeout: int = 600) -> subprocess.CompletedProcess:
    cmd = ["docker", "compose", "-f", str(compose_path), *args]
    proc = subprocess.run(cmd, check=False, capture_output=True, timeout=timeout)
    return proc


def up_session(compose_path: Path, timeout: int = 600) -> None:
    proc = compose(compose_path=compose_path, args=["up", "-d"], timeout=timeout)
    if proc.returncode != 0:
        raise DockerOpsError(
            f"docker compose up failed (rc={proc.returncode}): {proc.stderr.decode(errors='replace')[:2000]}"
        )


def down_session(compose_path: Path, *, remove_volumes: bool = True, timeout: int = 120) -> None:
    args = ["down", "-v"] if remove_volumes else ["down"]
    proc = compose(compose_path=compose_path, args=args, timeout=timeout)
    if proc.returncode != 0:
        raise DockerOpsError(
            f"docker compose down failed (rc={proc.returncode}): {proc.stderr.decode(errors='replace')[:2000]}"
        )


def wait_healthy(container_name: str, timeout_seconds: int = 120) -> None:
    """Block until the container is ready for connections.

    Tries the docker `healthy` status if available, then falls back to a
    TCP connect against the published `127.0.0.1:$host_port`. The TCP probe
    is the authoritative signal because docker healthchecks are not always
    reliable in deployments where the API user has restricted socket access.
    """
    import socket
    import time

    deadline = time.monotonic() + timeout_seconds
    last_status = "unknown"
    last_tcp = "unknown"
    while time.monotonic() < deadline:
        proc = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{.State.Health.Status}}",
                container_name,
            ],
            check=False,
            capture_output=True,
            timeout=5,
        )
        if proc.returncode == 0:
            last_status = proc.stdout.decode().strip()
            if last_status == "healthy":
                # Confirm TCP is actually accepting on the published port.
                port = _read_published_port(container_name)
                if port and _tcp_open("127.0.0.1", port, timeout=2):
                    return
                last_status = last_status or "healthy-but-no-port"

        # Fallback: read the published host port and probe TCP directly.
        port = _read_published_port(container_name)
        if port and _tcp_open("127.0.0.1", port, timeout=2):
            return
        last_tcp = f"port={port}"

        time.sleep(2)

    raise DockerOpsError(
        f"container {container_name} did not become ready in {timeout_seconds}s; "
        f"last docker status: {last_status}; tcp probe: {last_tcp}"
    )


def _tcp_open(host: str, port: int, *, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.error):
        return False


def _read_published_port(container_name: str) -> int | None:
    """Return the host-side port bound to the container's 3306/tcp, if any.

    Uses the JSON inspect format and parses locally because Go templates
    misbehave when iterating nested port bindings.
    """
    proc = subprocess.run(
        ["docker", "inspect", container_name],
        check=False,
        capture_output=True,
        timeout=5,
    )
    if proc.returncode != 0:
        return None
    try:
        import json
        data = json.loads(proc.stdout)
        bindings = data[0].get("NetworkSettings", {}).get("Ports", {}).get("3306/tcp")
        if bindings:
            host_port = bindings[0].get("HostPort")
            if host_port and str(host_port).isdigit():
                return int(host_port)
        host_cfg = (
            data[0].get("HostConfig", {}).get("PortBindings", {}).get("3306/tcp")
        )
        if host_cfg:
            host_port = host_cfg[0].get("HostPort")
            if host_port and str(host_port).isdigit():
                return int(host_port)
    except Exception:
        return None
    return None


def replace_port_in_compose(compose_path: Path, new_bind_host: str, new_host_port: int) -> None:
    """Deprecated: kept for backward compat. Render the compose file twice
    (once private, once public) instead of mutating after the fact.
    """
    text = compose_path.read_text()
    pattern = re.compile(r'-\s*"\$\{[^}]*\}|-\s*"[0-9.]+:\d+:3306"|-\s*"127\.0\.0\.1:\d+:3306"')
    new_line = f'      - "{new_bind_host}:{new_host_port}:3306"'
    new_text, n = pattern.subn(new_line, text)
    if n == 0:
        new_text2 = text.replace("- \"127.0.0.1", f'- "{new_bind_host}', 1)
        if new_text2 == text:
            raise DockerOpsError(f"could not find port mapping in compose: {compose_path}")
        new_text = new_text2
    compose_path.write_text(new_text)
    compose_path.chmod(0o640)