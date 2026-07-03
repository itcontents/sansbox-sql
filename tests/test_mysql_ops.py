from __future__ import annotations

import socket
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from api.mysql_ops import (
    MySQLOpsError,
    apply_grants,
    clone_db,
    dump_db,
    restore_db,
    wait_ready,
)
from api.ssh_tunnel import Tunnel, open_tunnel


class _FakeChannel:
    def __init__(self, sink: list[bytes], done: threading.Event) -> None:
        self._sink = sink
        self._done = done

    def recv(self, n: int) -> bytes:
        if self._done.is_set() and not self._sink:
            return b""
        while not self._sink and not self._done.is_set():
            time.sleep(0.01)
        return self._sink.pop(0) if self._sink else b""

    def sendall(self, data: bytes) -> None:
        self._sink.append(data)

    def close(self) -> None:
        self._done.set()


class _FakeTransport:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def open_channel(self, kind, dest, src):
        self.calls.append((kind, dest, src))
        sink: list[bytes] = []
        done = threading.Event()
        return _FakeChannel(sink, done)


class _FakeSSHClient:
    def __init__(self) -> None:
        self._transport = _FakeTransport()
        self.closed = False

    def set_missing_host_key_policy(self, policy) -> None:
        pass

    def connect(self, **kwargs) -> None:
        pass

    def get_transport(self):
        return self._transport

    def close(self) -> None:
        self.closed = True


def _run_echo_server(port_holder: list[int], stop_event: threading.Event) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port_holder.append(srv.getsockname()[1])
    srv.settimeout(0.3)
    while not stop_event.is_set():
        try:
            c, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            c.sendall(b"PONG\n")
        finally:
            c.close()
    srv.close()


def _make_tunnel(monkeypatch, tmp_path: Path) -> Tunnel:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "id_ed25519"
    key_path.write_bytes(pem)
    key_path.chmod(0o600)

    fake = _FakeSSHClient()
    monkeypatch.setattr("api.ssh_tunnel.paramiko.SSHClient", lambda: fake)
    cm = open_tunnel(
        ssh_host="x",
        ssh_port=22,
        ssh_user="u",
        ssh_key=key_path,
        remote_host="r",
        remote_port=3306,
    )
    t = cm.__enter__()
    t._cm = cm  # type: ignore[attr-defined]
    return t


def test_tunnel_local_port_is_open(monkeypatch, tmp_path: Path):
    t = _make_tunnel(monkeypatch, tmp_path)
    try:
        s = socket.socket()
        s.connect(("127.0.0.1", t.local_port))
        s.close()
    finally:
        t._cm.__exit__(None, None, None)  # type: ignore[attr-defined]


def test_dump_db_calls_mysqldump_with_local_port(monkeypatch, tmp_path: Path):
    captured: dict = {}

    class FakeRun:
        returncode = 0
        stdout = b"-- dump --"
        stderr = b""

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["input"] = kwargs.get("input")
        captured["capture"] = kwargs.get("capture_output")
        return FakeRun()

    t = _make_tunnel(monkeypatch, tmp_path)
    try:
        with patch("api.mysql_ops.subprocess.run", side_effect=fake_run), patch(
            "api.mysql_ops._resolve_binary", return_value="/usr/bin/mysqldump"
        ):
            res = dump_db(
                tunnel=t,
                db="db_a",
                user="dumper",
                password="pw",
            )
        assert res == b"-- dump --"
        assert "--port=" + str(t.local_port) in captured["cmd"]
        assert "--host=127.0.0.1" in captured["cmd"]
        assert "mysqldump" in captured["cmd"][0]
    finally:
        t._cm.__exit__(None, None, None)  # type: ignore[attr-defined]


def test_dump_db_raises_on_failure(monkeypatch, tmp_path: Path):
    class FakeRun:
        returncode = 1
        stdout = b""
        stderr = b"ERROR 1045"

    t = _make_tunnel(monkeypatch, tmp_path)
    try:
        with patch("api.mysql_ops.subprocess.run", return_value=FakeRun()), patch(
            "api.mysql_ops._resolve_binary", return_value="/usr/bin/mysqldump"
        ):
            with pytest.raises(MySQLOpsError):
                dump_db(tunnel=t, db="db_a", user="u", password="p")
    finally:
        t._cm.__exit__(None, None, None)  # type: ignore[attr-defined]


def test_restore_db_pipes_sql(monkeypatch):
    captured: list = []

    class FakePopen:
        returncode = 0
        stdout = b""
        stderr = b""

    def fake_run(cmd, **kwargs):
        captured.append({"cmd": cmd, "input": kwargs.get("input")})
        return FakePopen()

    with patch("api.mysql_ops.subprocess.run", side_effect=fake_run), patch(
        "api.mysql_ops._resolve_binary", return_value="/usr/bin/mysql"
    ):
        restore_db(
            host="sandbox", port=33451, user="root", password="r",
            db="db_a", sql_bytes=b"CREATE TABLE x;",
        )
    assert len(captured) == 2, captured
    # First call: CREATE DATABASE IF NOT EXISTS
    assert captured[0]["cmd"][0] == "/usr/bin/mysql"
    assert "-e" in captured[0]["cmd"]
    assert "CREATE DATABASE IF NOT EXISTS `db_a`" in " ".join(captured[0]["cmd"])
    # Second call: pipes the dump
    assert captured[1]["cmd"][0] == "/usr/bin/mysql"
    assert captured[1]["input"] == b"CREATE TABLE x;"
    assert "--host=sandbox" in captured[1]["cmd"]


def test_clone_db_streams_dump_directly_into_restore(monkeypatch, tmp_path: Path):
    captured: list[dict] = []

    class FakeStream:
        def read(self):
            return b""

        def close(self):
            return None

    class FakePopen:
        def __init__(self, cmd, **kwargs):
            self.cmd = cmd
            self.kwargs = kwargs
            self.returncode = 0
            self.stdout = FakeStream() if "mysqldump" in cmd[0] else None
            self.stderr = FakeStream()

        def communicate(self, timeout=None):
            captured.append({"cmd": self.cmd, "kwargs": self.kwargs, "timeout": timeout})
            return (b"", b"")

        def wait(self, timeout=None):
            captured.append({"cmd": self.cmd, "kwargs": self.kwargs, "timeout": timeout})
            return self.returncode

        def kill(self):
            self.returncode = -9

    def fake_popen(cmd, **kwargs):
        return FakePopen(cmd, **kwargs)

    t = _make_tunnel(monkeypatch, tmp_path)
    try:
        with patch("api.mysql_ops.subprocess.Popen", side_effect=fake_popen), patch(
            "api.mysql_ops._resolve_binary",
            side_effect=lambda name: f"/usr/bin/{name}",
        ), patch("api.mysql_ops._ensure_database") as ensure:
            clone_db(
                tunnel=t,
                source_db="db_a",
                source_user="dumper",
                source_password="prodpw",
                target_host="127.0.0.1",
                target_port=33451,
                target_user="root",
                target_password="rootpw",
                target_db="db_a",
            )
        ensure.assert_called_once()
        assert any("mysqldump" in rec["cmd"][0] for rec in captured)
        assert any("mysql" in rec["cmd"][0] for rec in captured)
    finally:
        t._cm.__exit__(None, None, None)  # type: ignore[attr-defined]


def test_clone_db_passes_ssl_ca_to_restore_side(monkeypatch, tmp_path: Path):
    captured: list[dict] = []

    class FakeStream:
        def read(self):
            return b""

        def close(self):
            return None

    class FakePopen:
        def __init__(self, cmd, **kwargs):
            self.cmd = cmd
            self.kwargs = kwargs
            self.returncode = 0
            self.stdout = FakeStream() if "mysqldump" in cmd[0] else None
            self.stderr = FakeStream()

        def communicate(self, timeout=None):
            captured.append({"cmd": self.cmd})
            return (b"", b"")

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            self.returncode = -9

    t = _make_tunnel(monkeypatch, tmp_path)
    try:
        with patch("api.mysql_ops.subprocess.Popen", side_effect=lambda *a, **kw: FakePopen(*a, **kw)), patch(
            "api.mysql_ops._resolve_binary",
            side_effect=lambda name: f"/usr/bin/{name}",
        ), patch("api.mysql_ops._ensure_database") as ensure:
            clone_db(
                tunnel=t,
                source_db="db_a",
                source_user="dumper",
                source_password="prodpw",
                target_host="127.0.0.1",
                target_port=33451,
                target_user="root",
                target_password="rootpw",
                target_db="db_a",
                ssl_ca=tmp_path / "ca.pem",
            )
        # The dump-side mysql call (i.e. the *restore* binary) must carry
        # --ssl-mode=REQUIRED --ssl-ca=<path>.
        mysql_calls = [rec["cmd"] for rec in captured if "/usr/bin/mysql" == rec["cmd"][0]]
        assert mysql_calls, "no mysql restore call captured"
        joined = " ".join(mysql_calls[0])
        assert "--ssl-mode=REQUIRED" in joined
        assert "--ssl-ca=" + str(tmp_path / "ca.pem") in joined
        # And _ensure_database got ssl_ca plumbed in as well.
        _, kwargs = ensure.call_args
        assert kwargs["ssl_ca"] == tmp_path / "ca.pem"
    finally:
        t._cm.__exit__(None, None, None)  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "call",
    [
        ("dump_db", lambda fake_run: _invoke_dump(fake_run)),
        ("restore_db", lambda fake_run: _invoke_restore(fake_run)),
        ("_ensure_database", lambda fake_run: _invoke_ensure(fake_run)),
        ("apply_grants", lambda fake_run: _invoke_grants(fake_run)),
        ("wait_ready_ping", lambda fake_run: _invoke_wait(fake_run)),
    ],
)
def test_password_never_on_argv(call, monkeypatch, tmp_path):
    """Regression: production / per-session passwords must NOT appear in argv."""
    name, invoke = call
    captured: list = []

    class FakePopen:
        returncode = 0
        stdout = b"-- ok --"
        stderr = b""

    def fake_run(cmd, **kwargs):
        captured.append({"cmd": cmd, "env": kwargs.get("env")})
        return FakePopen()

    with patch("api.mysql_ops.subprocess.run", side_effect=fake_run), patch(
        "api.mysql_ops._resolve_binary", return_value="/usr/bin/dummy"
    ):
        invoke(fake_run)

    assert captured, f"no subprocess.run captured for {name}"
    argv_str = " ".join(str(x) for x in captured[0]["cmd"])
    assert "--password=SECRET-PROD-PASSWORD" not in argv_str, \
        f"{name} leaked password to argv: {argv_str}"
    assert "SECRET-PROD-PASSWORD" not in argv_str
    # If the env path is taken, verify MYSQL_PWD is set there instead.
    env = captured[0]["env"] or {}
    # _mysql_env always returns at least PATH/LANG/HOME. If password was
    # passed to the call, MYSQL_PWD must be present.
    if "MYSQL_PWD" in env:
        assert env["MYSQL_PWD"] == "SECRET-PROD-PASSWORD"


def _invoke_dump(_):
    from api.mysql_ops import dump_db
    t = type("T", (), {"local_port": 0, "local_host": "127.0.0.1"})()
    dump_db(tunnel=t, db="x", user="u", password="SECRET-PROD-PASSWORD")


def _invoke_restore(_):
    from api.mysql_ops import restore_db
    restore_db(host="x", port=1, user="u", password="SECRET-PROD-PASSWORD",
               db="x", sql_bytes=b";")


def _invoke_ensure(_):
    from api.mysql_ops import _ensure_database
    _ensure_database(host="x", port=1, user="u", password="SECRET-PROD-PASSWORD", db="x")


def _invoke_grants(_):
    from api.mysql_ops import apply_grants
    apply_grants(host="x", port=1, user="u", password="SECRET-PROD-PASSWORD",
                 sql_statements=["SELECT 1"])


def _invoke_wait(_):
    from api.mysql_ops import wait_ready
    # Want only one subprocess call; let ping succeed immediately
    wait_ready(host="x", port=1, user="u", password="SECRET-PROD-PASSWORD", timeout_seconds=2)


def test_dump_db_uses_no_create_db_flag(monkeypatch, tmp_path):
    captured: dict = {}

    class FakePopen:
        returncode = 0
        stdout = b"-- dump --"
        stderr = b""

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return FakePopen()

    t = _make_tunnel(monkeypatch, tmp_path)
    try:
        with patch("api.mysql_ops.subprocess.run", side_effect=fake_run), patch(
            "api.mysql_ops._resolve_binary", return_value="/usr/bin/mysqldump"
        ):
            dump_db(tunnel=t, db="db_a", user="dumper", password="pw")
        assert "--no-create-db" in captured["cmd"]
    finally:
        t._cm.__exit__(None, None, None)  # type: ignore[attr-defined]


def test_dump_db_passes_tables_as_positional_args(monkeypatch, tmp_path):
    captured: dict = {}

    class FakePopen:
        returncode = 0
        stdout = b"-- partial --"
        stderr = b""

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return FakePopen()

    t = _make_tunnel(monkeypatch, tmp_path)
    try:
        with patch("api.mysql_ops.subprocess.run", side_effect=fake_run), patch(
            "api.mysql_ops._resolve_binary", return_value="/usr/bin/mysqldump"
        ):
            res = dump_db(
                tunnel=t, db="db_a", user="dumper", password="pw",
                tables=["orders", "users"],
            )
        # tables come after the db name as positional args
        assert res == b"-- partial --"
        idx_db = captured["cmd"].index("db_a")
        assert captured["cmd"][idx_db + 1] == "orders"
        assert captured["cmd"][idx_db + 2] == "users"
        assert "--no-create-db" in captured["cmd"]
    finally:
        t._cm.__exit__(None, None, None)  # type: ignore[attr-defined]


def test_ensure_database_creates_with_if_not_exists(monkeypatch):
    captured: dict = {}

    class FakePopen:
        returncode = 0
        stdout = b""
        stderr = b""

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return FakePopen()

    from api.mysql_ops import _ensure_database

    with patch("api.mysql_ops.subprocess.run", side_effect=fake_run), patch(
        "api.mysql_ops._resolve_binary", return_value="/usr/bin/mysql"
    ):
        _ensure_database(host="h", port=1, user="root", password="p", db="db_a")
    assert captured["cmd"][0] == "/usr/bin/mysql"
    assert "-e" in captured["cmd"]
    assert "CREATE DATABASE IF NOT EXISTS" in " ".join(captured["cmd"])


def test_apply_grants_joins_statements(monkeypatch):
    captured: dict = {}

    class FakePopen:
        returncode = 0
        stdout = b""
        stderr = b""

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["input"] = kwargs.get("input")
        return FakePopen()

    with patch("api.mysql_ops.subprocess.run", side_effect=fake_run), patch(
        "api.mysql_ops._resolve_binary", return_value="/usr/bin/mysql"
    ):
        apply_grants(
            host="h", port=1, user="root", password="r",
            sql_statements=["CREATE USER 'a'@'%'", "GRANT ALL ON db.* TO 'a'@'%'"],
        )
    assert captured["input"] == b"CREATE USER 'a'@'%'\nGRANT ALL ON db.* TO 'a'@'%'"


def test_wait_ready_succeeds_after_pings(monkeypatch):
    calls = {"n": 0}

    class FakePopen:
        returncode = 0
        stdout = b"mysqld is alive"
        stderr = b""

        def __init__(self) -> None:
            calls["n"] += 1

    with patch("api.mysql_ops.subprocess.run", return_value=FakePopen()), patch(
        "api.mysql_ops._resolve_binary", return_value="/usr/bin/mysqladmin"
    ):
        wait_ready(host="h", port=1, user="r", password="p", timeout_seconds=3)
    assert calls["n"] >= 1


def test_dump_db_uses_tunnel_local_host_by_default(monkeypatch, tmp_path):
    captured: dict = {}

    class FakePopen:
        returncode = 0
        stdout = b"-- dump --"
        stderr = b""

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return FakePopen()

    t = _make_tunnel(monkeypatch, tmp_path)
    try:
        # The fake _FakeTunnel in test_endpoints mirrors the real one; here we
        # patch the tunnel object directly to set local_host.
        import dataclasses
        t.local_host = "10.0.0.5"
        with patch("api.mysql_ops.subprocess.run", side_effect=fake_run), patch(
            "api.mysql_ops._resolve_binary", return_value="/usr/bin/mysqldump"
        ):
            dump_db(tunnel=t, db="db_a", user="u", password="p")
        assert "--host=10.0.0.5" in captured["cmd"]
    finally:
        t._cm.__exit__(None, None, None)  # type: ignore[attr-defined]


def test_dump_db_host_kwarg_overrides_tunnel_host(monkeypatch, tmp_path):
    captured: dict = {}

    class FakePopen:
        returncode = 0
        stdout = b"-- dump --"
        stderr = b""

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return FakePopen()

    t = _make_tunnel(monkeypatch, tmp_path)
    try:
        with patch("api.mysql_ops.subprocess.run", side_effect=fake_run), patch(
            "api.mysql_ops._resolve_binary", return_value="/usr/bin/mysqldump"
        ):
            dump_db(tunnel=t, db="db_a", user="u", password="p", host="192.168.0.50")
        assert "--host=192.168.0.50" in captured["cmd"]
    finally:
        t._cm.__exit__(None, None, None)  # type: ignore[attr-defined]


def test_open_tunnel_binds_to_specified_host(monkeypatch, tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "id_ed25519"
    key_path.write_bytes(pem)
    key_path.chmod(0o600)

    fake = _FakeSSHClient()
    monkeypatch.setattr("api.ssh_tunnel.paramiko.SSHClient", lambda: fake)
    cm = open_tunnel(
        ssh_host="x", ssh_port=22, ssh_user="u", ssh_key=key_path,
        remote_host="r", remote_port=3306, bind_host="127.0.0.1",
    )
    with cm as t:
        assert t.local_host == "127.0.0.1"
        assert t.local_port > 0


def test_wait_ready_times_out(monkeypatch):
    class FakePopen:
        returncode = 1
        stdout = b""
        stderr = b"connect refused"

    with patch("api.mysql_ops.subprocess.run", return_value=FakePopen()), patch(
        "api.mysql_ops._resolve_binary", return_value="/usr/bin/mysqladmin"
    ):
        with pytest.raises(MySQLOpsError):
            wait_ready(host="h", port=1, user="r", password="p", timeout_seconds=1)
