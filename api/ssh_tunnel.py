from __future__ import annotations

import os
import socket
import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


class TunnelError(Exception):
    pass


@dataclass
class Tunnel:
    """A local TCP forward to (remote_host:remote_port) over an SSH `-L` subprocess.

    The SSH process is the source of truth — when it dies, the forward is gone.
    We do not try to introspect or restart it.
    """

    local_port: int
    local_host: str
    _proc: subprocess.Popen

    def close(self) -> None:
        proc = self._proc
        if proc.poll() is None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
            except Exception:
                pass


def _wait_listening(host: str, port: int, *, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            try:
                s.connect((host, port))
                return True
            except OSError:
                time.sleep(0.1)
    return False


def _pick_local_port() -> int:
    """Bind an ephemeral port on 127.0.0.1 to discover a free number, then release.
    Using port=0 lets the kernel pick. We close immediately; the tunnel will
    race to re-bind the same number. Acceptable for our low-concurrency use.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _known_hosts_file(ssh_user: str) -> Path:
    """Use the calling user's known_hosts (the API runs as `sandbox`).
    Falls back to /dev/null which forces strict checking to fail loudly.
    """
    sudo_user = os.environ.get("SUDO_USER") or os.environ.get("USER") or ssh_user
    candidate = Path("/home") / sudo_user / ".ssh" / "known_hosts"
    if candidate.exists():
        return candidate
    # /home/lytadmin/.ssh/known_hosts is the alternative when running as lytadmin.
    fallback = Path("/home/lytadmin/.ssh/known_hosts")
    if fallback.exists():
        return fallback
    return Path("/dev/null")


@contextmanager
def open_tunnel(
    *,
    ssh_host: str,
    ssh_port: int,
    ssh_user: str,
    ssh_key: Path,
    remote_host: str,
    remote_port: int,
    bind_host: str = "127.0.0.1",
) -> Iterator[Tunnel]:
    """Open a local <bind_host>:<random> forward to <remote_host>:<remote_port>
    by spawning `ssh -N -L`. The forward stays up until the context exits.

    Replaces the previous paramiko `direct-tcpip` implementation, which wedged
    intermittently (the channel accepted connections but stopped forwarding
    bytes after the first idle period, with no exception or close event).
    OpenSSH's `-L` forward is well-tested and handles keepalives + half-close
    detection correctly.
    """
    ssh_key = Path(ssh_key)
    if not ssh_key.exists():
        raise TunnelError(f"ssh key not found: {ssh_key}")

    local_port = _pick_local_port()
    known_hosts = _known_hosts_file(ssh_user)

    cmd = [
        "ssh",
        "-N",
        "-T",
        "-x",
        "-a",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
        "-o", "TCPKeepAlive=yes",
        "-i", str(ssh_key),
        "-p", str(ssh_port),
        "-L", f"{bind_host}:{local_port}:{remote_host}:{remote_port}",
        f"{ssh_user}@{ssh_host}",
    ]

    stderr_log = Path("/var/log/sandboxes") / "ssh-tunnel.err.log"
    stderr_log.parent.mkdir(parents=True, exist_ok=True)
    log_fp = open(stderr_log, "ab", buffering=0)

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=log_fp,
        start_new_session=True,
    )

    try:
        if not _wait_listening(bind_host, local_port, timeout=10.0):
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            raise TunnelError(
                f"ssh -L forward did not become ready within 10s "
                f"(host={ssh_host}:{ssh_port} user={ssh_user} "
                f"forward={bind_host}:{local_port}->{remote_host}:{remote_port}); "
                f"see {stderr_log}"
            )

        # If ssh died between the listen check and yield, propagate that.
        if proc.poll() is not None:
            raise TunnelError(
                f"ssh -L exited prematurely (rc={proc.returncode}); see {stderr_log}"
            )

        tunnel = Tunnel(local_port=local_port, local_host=bind_host, _proc=proc)
        try:
            yield tunnel
        finally:
            tunnel.close()
            log_fp.close()
    except Exception:
        try:
            log_fp.close()
        except Exception:
            pass
        raise