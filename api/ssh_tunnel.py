from __future__ import annotations

import socket
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import paramiko


class TunnelError(Exception):
    pass


@dataclass
class Tunnel:
    local_port: int
    local_host: str
    _server_sock: socket.socket
    _client: paramiko.SSHClient
    _stop_event: threading.Event
    _serve_thread: threading.Thread

    def close(self) -> None:
        self._stop_event.set()
        try:
            self._server_sock.close()
        except OSError:
            pass
        try:
            self._client.close()
        except Exception:
            pass
        self._serve_thread.join(timeout=2)


def _pump(src, dst) -> None:
    try:
        while True:
            data = src.recv(8192)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        for s in (src, dst):
            try:
                s.close()
            except Exception:
                pass


def _serve_connections(
    server_sock: socket.socket,
    client: paramiko.SSHClient,
    remote_host: str,
    remote_port: int,
    stop_event: threading.Event,
) -> None:
    server_sock.settimeout(0.5)
    while not stop_event.is_set():
        try:
            conn, _ = server_sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            transport = client.get_transport()
            if transport is None:
                conn.close()
                continue
            channel = transport.open_channel(
                "direct-tcpip",
                (remote_host, remote_port),
                conn.getpeername(),
            )
        except Exception:
            try:
                conn.close()
            except OSError:
                pass
            continue
        threading.Thread(target=_pump, args=(conn, channel), daemon=True).start()
        threading.Thread(target=_pump, args=(channel, conn), daemon=True).start()


def _load_private_key(path: Path) -> paramiko.PKey:
    path = Path(path)
    for loader in (
        paramiko.Ed25519Key.from_private_key_file,
        paramiko.RSAKey.from_private_key_file,
        paramiko.ECDSAKey.from_private_key_file,
    ):
        try:
            return loader(str(path))
        except paramiko.PasswordRequiredException:
            raise
        except Exception:
            continue
    raise TunnelError(f"could not load SSH key: {path}")


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
    """Open a local <bind_host>:<random> forward to <remote_host>:<remote_port> over SSH.

    `bind_host` selects which local IP the SSH local-forward listener binds
    to (defaults to 127.0.0.1). `mysqldump` is invoked with `--host=<bind_host>`
    so it can reach the listener.

    The tunnel is torn down when the context manager exits.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())

    pkey = _load_private_key(ssh_key)

    try:
        client.connect(
            hostname=ssh_host,
            port=ssh_port,
            username=ssh_user,
            pkey=pkey,
            allow_agent=False,
            look_for_keys=False,
            timeout=15,
        )
    except Exception as exc:
        raise TunnelError(f"ssh connect failed: {exc}") from exc

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((bind_host, 0))
    server_sock.listen(8)
    local_addr = server_sock.getsockname()
    local_host, local_port = local_addr[0], local_addr[1]

    stop_event = threading.Event()
    serve_thread = threading.Thread(
        target=_serve_connections,
        args=(server_sock, client, remote_host, remote_port, stop_event),
        daemon=True,
    )
    serve_thread.start()

    tunnel = Tunnel(
        local_port=local_port,
        local_host=local_host,
        _server_sock=server_sock,
        _client=client,
        _stop_event=stop_event,
        _serve_thread=serve_thread,
    )
    try:
        yield tunnel
    finally:
        tunnel.close()