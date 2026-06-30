from __future__ import annotations

import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from api.config import Settings
from api.docker_ops import (
    DockerOpsError,
    allocate_port,
    down_session,
    gen_root_password,
    make_session_paths,
    render_compose,
    render_grant_sql,
    render_mysqld_cnf,
    replace_port_in_compose,
    up_session,
)


def _build_settings(tmp_path: Path) -> Settings:
    base = dict(
        SANDBOX_API_KEY="k",
        SANDBOX_WEBHOOK_SECRET="w",
        SANDBOX_CF_ACCESS_AUD="aud",
        SANDBOX_CF_ACCESS_CERTS_URL="https://x/certs",
        SANDBOX_FERNET_KEY="ZmRldnRlc3RrZXktZmRldnRlc3RrZXktZmRldnRlc3RrZXkxMjM0NTY3OA==",
        SANDBOX_PUBLIC_HOST="api.test",
        SANDBOX_MYSQL_HOST="1.2.3.4",
        PROD_SSH_HOST="ssh",
        PROD_MYSQL_HOST="m",
        PROD_MYSQL_USER="u",
        PROD_MYSQL_PASSWORD="p",
        SANDBOX_STATE_DB=str(tmp_path / "state.db"),
        SANDBOX_COMPOSE_DIR=str(tmp_path / "composes"),
        SANDBOX_TLS_DIR=str(tmp_path / "tls"),
        SANDBOX_LOG_DIR=str(tmp_path / "logs"),
    )
    return Settings(_env_file=None, **base)  # type: ignore[arg-type]


def test_allocate_port_skips_used():
    s = _build_settings(Path("/tmp"))
    assert allocate_port([], s) == 33060
    assert allocate_port([33060], s) == 33061
    assert allocate_port([33060, 33061, 33062], s) == 33063


def test_allocate_port_exhausted(tmp_path: Path):
    s = Settings(_env_file=None, **dict(  # type: ignore[arg-type]
        SANDBOX_API_KEY="k", SANDBOX_WEBHOOK_SECRET="w",
        SANDBOX_CF_ACCESS_AUD="a", SANDBOX_CF_ACCESS_CERTS_URL="https://x/c",
        SANDBOX_FERNET_KEY="ZmRldnRlc3RrZXktZmRldnRlc3RrZXktZmRldnRlc3RrZXkxMjM0NTY3OA==",
        SANDBOX_PUBLIC_HOST="api.test", SANDBOX_MYSQL_HOST="1.2.3.4",
        PROD_SSH_HOST="x", PROD_MYSQL_HOST="y", PROD_MYSQL_USER="u", PROD_MYSQL_PASSWORD="p",
        SANDBOX_PORT_RANGE_START=33060, SANDBOX_PORT_RANGE_END=33060,
    ))
    with pytest.raises(DockerOpsError):
        allocate_port([33060], s)


def test_gen_root_password_length_and_charset():
    p = gen_root_password()
    assert len(p) == 32
    assert all(c.isalnum() for c in p)


def test_make_session_paths_creates_dirs(tmp_path: Path):
    s = _build_settings(tmp_path)
    p = make_session_paths(sid="abc", ticket="10215", date_str="2026-06-29", settings=s)
    assert p.session_dir.is_dir()
    assert p.log_dir.is_dir()
    assert p.tls_dir.is_dir()


def test_render_compose_has_container_and_port(tmp_path: Path):
    s = _build_settings(tmp_path)
    p = make_session_paths(sid="abc", ticket="10215", date_str="2026-06-29", settings=s)
    cp = render_compose(
        paths=p, sid="abc", container_name="sandbox-abc",
        mysql_image="mysql:8.4", bind_host="127.0.0.1",
        host_port=33060, root_password="rootpw",
    )
    text = cp.read_text()
    assert "container_name: sandbox-abc" in text
    assert "127.0.0.1:33060:3306" in text
    assert "MYSQL_ROOT_PASSWORD: \"rootpw\"" in text
    assert "no-new-privileges" in text
    assert "cpus: 1.0" in text
    assert "mem_limit: 2g" in text
    mode = cp.stat().st_mode & 0o777
    assert mode == 0o640


def test_render_mysqld_cnf(tmp_path: Path):
    s = _build_settings(tmp_path)
    p = make_session_paths(sid="abc", ticket="1", date_str="2026-01-01", settings=s)
    cnf = render_mysqld_cnf(paths=p)
    text = cnf.read_text()
    assert "require-secure-transport = ON" in text
    assert "ssl-ca = /etc/mysql/tls/ca.pem" in text


def test_render_grant_sql_for_one_db():
    sql = render_grant_sql(
        grants=[{"db": "db_a", "user": "u_db_a", "password": "pw1"}]
    )
    assert "CREATE USER IF NOT EXISTS 'u_db_a'@'%'" in sql
    assert "GRANT SELECT, INSERT" in sql
    assert "ON `db_a`.* TO 'u_db_a'@'%'" in sql
    assert "REQUIRE SSL" in sql
    assert "FLUSH PRIVILEGES" in sql


def test_render_grant_sql_for_multiple_dbs():
    sql = render_grant_sql(
        grants=[
            {"db": "db_a", "user": "u_a", "password": "p1"},
            {"db": "db_b", "user": "u_b", "password": "p2"},
        ]
    )
    assert sql.count("CREATE USER") == 2
    assert sql.count("FLUSH PRIVILEGES") == 2


def test_replace_port_in_compose(tmp_path: Path):
    s = _build_settings(tmp_path)
    p = make_session_paths(sid="abc", ticket="1", date_str="2026-01-01", settings=s)
    cp = render_compose(
        paths=p, sid="abc", container_name="sandbox-abc",
        mysql_image="mysql:8.4", bind_host="127.0.0.1",
        host_port=33060, root_password="r",
    )
    replace_port_in_compose(cp, "0.0.0.0", 33060)
    text = cp.read_text()
    assert "0.0.0.0:33060:3306" in text
    assert "127.0.0.1:33060:3306" not in text


def test_up_session_invokes_docker(tmp_path: Path):
    s = _build_settings(tmp_path)
    p = make_session_paths(sid="abc", ticket="1", date_str="2026-01-01", settings=s)
    cp = render_compose(
        paths=p, sid="abc", container_name="sandbox-abc",
        mysql_image="mysql:8.4", bind_host="127.0.0.1",
        host_port=33060, root_password="r",
    )
    captured = {}

    class FakeProc:
        returncode = 0
        stdout = b""
        stderr = b""

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return FakeProc()

    with patch("api.docker_ops.subprocess.run", side_effect=fake_run):
        up_session(cp)
    assert captured["cmd"][0] == "docker"
    assert captured["cmd"][1] == "compose"
    assert captured["cmd"][2] == "-f"
    assert "up" in captured["cmd"]
    assert "-d" in captured["cmd"]


def test_up_session_raises_on_failure(tmp_path: Path):
    s = _build_settings(tmp_path)
    p = make_session_paths(sid="abc", ticket="1", date_str="2026-01-01", settings=s)
    cp = render_compose(
        paths=p, sid="abc", container_name="sandbox-abc",
        mysql_image="mysql:8.4", bind_host="127.0.0.1",
        host_port=33060, root_password="r",
    )

    class FakeProc:
        returncode = 1
        stderr = b"image not found"

    with patch("api.docker_ops.subprocess.run", return_value=FakeProc()):
        with pytest.raises(DockerOpsError):
            up_session(cp)


def test_down_session_with_volumes(tmp_path: Path):
    s = _build_settings(tmp_path)
    p = make_session_paths(sid="abc", ticket="1", date_str="2026-01-01", settings=s)
    cp = render_compose(
        paths=p, sid="abc", container_name="sandbox-abc",
        mysql_image="mysql:8.4", bind_host="127.0.0.1",
        host_port=33060, root_password="r",
    )
    captured: list = []

    class FakeProc:
        returncode = 0
        stdout = b""
        stderr = b""

    def fake_run(cmd, **kw):
        captured.append(cmd)
        return FakeProc()

    with patch("api.docker_ops.subprocess.run", side_effect=fake_run):
        down_session(cp, remove_volumes=True)
        down_session(cp, remove_volumes=False)
    assert len(captured) == 2
    assert "-v" in captured[0]
    assert "-v" not in captured[1]
    assert "down" in captured[0] and "down" in captured[1]