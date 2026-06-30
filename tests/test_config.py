from __future__ import annotations

from pathlib import Path

import pytest

from api.config import Settings, get_settings, reset_settings_cache


def _build(**overrides):
    base = dict(
        SANDBOX_API_KEY="k",
        SANDBOX_WEBHOOK_SECRET="w",
        SANDBOX_CF_ACCESS_AUD="aud",
        SANDBOX_CF_ACCESS_CERTS_URL="https://x/certs",
        SANDBOX_FERNET_KEY="ZmRldnRlc3RrZXktZmRldnRlc3RrZXktZmRldnRlc3RrZXkxMjM0NTY3OA==",
        SANDBOX_PUBLIC_HOST="api.x",
        SANDBOX_MYSQL_HOST="1.2.3.4",
        PROD_SSH_HOST="ssh.x",
        PROD_MYSQL_HOST="mysql.x",
        PROD_MYSQL_USER="u",
        PROD_MYSQL_PASSWORD="p",
    )
    base.update(overrides)
    return Settings(_env_file=None, **base)  # type: ignore[arg-type]


def test_minimal_load():
    s = _build()
    assert s.sandbox_api_key == "k"
    assert s.sandbox_public_host == "api.x"
    assert s.sandbox_port_range_start == 33060
    assert s.sandbox_port_range_end == 33999
    assert s.sandbox_ttl_default_seconds == 21600
    assert s.sandbox_ttl_max_seconds == 28800
    assert s.sandbox_tunnel_bind_host == "127.0.0.1"


def test_tunnel_bind_host_overridable():
    s = _build(SANDBOX_TUNNEL_BIND_HOST="10.0.0.5")
    assert s.sandbox_tunnel_bind_host == "10.0.0.5"


def test_port_range_property():
    s = _build()
    assert s.port_range.start == 33060
    assert s.port_range.stop == 34000


def test_invalid_port_range_rejected():
    with pytest.raises(Exception):
        _build(SANDBOX_PORT_RANGE_START=35000, SANDBOX_PORT_RANGE_END=34000)


def test_invalid_ttl_order_rejected():
    with pytest.raises(Exception):
        _build(SANDBOX_TTL_DEFAULT_SECONDS=10000, SANDBOX_TTL_MAX_SECONDS=20000)
    with pytest.raises(Exception):
        _build(SANDBOX_TTL_MIN_SECONDS=20000, SANDBOX_TTL_DEFAULT_SECONDS=30000)


def test_paths_are_pathlib():
    s = _build()
    assert isinstance(s.sandbox_state_db, Path)
    assert isinstance(s.sandbox_compose_dir, Path)


def test_get_settings_cached(monkeypatch):
    reset_settings_cache()
    monkeypatch.setenv("SANDBOX_API_KEY", "k1")
    s1 = get_settings()
    monkeypatch.setenv("SANDBOX_API_KEY", "k2")
    s2 = get_settings()
    assert s1 is s2
    reset_settings_cache()