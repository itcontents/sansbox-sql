from __future__ import annotations

import base64
import json
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import MagicMock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from api.config import Settings, reset_settings_cache
from api.crypto import fernet_from_key
from api.main import AppContext, create_app
from api.service import SessionService
from api.state import SessionStore
from api.auth import reset_jwks_cache_for_tests


KID = "test-kid"
AUD = "test-aud"

_RSA: dict = {}
_JWKS_URL: dict = {}


def _b64url_uint(n: int) -> str:
    blen = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(blen, "big")).rstrip(b"=").decode()


@pytest.fixture(scope="module", autouse=True)
def _setup_jwks():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key()
    _RSA["private"] = private
    jwks = {
        "keys": [
            {
                "kid": KID,
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": _b64url_uint(public.public_numbers().n),
                "e": _b64url_uint(public.public_numbers().e),
            }
        ]
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/certs":
                body = json.dumps(jwks).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args, **kwargs):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    _JWKS_URL["value"] = f"http://127.0.0.1:{port}/certs"

    import socket
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                break
        except OSError:
            time.sleep(0.05)

    reset_jwks_cache_for_tests()
    yield
    srv.shutdown()


def _mint_jwt(*, aud: str = AUD, exp_offset: int = 300) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "iss": "https://test",
            "sub": "user-1",
            "aud": aud,
            "iat": now,
            "exp": now + exp_offset,
            "email": "dev@example.com",
        },
        _RSA["private"],
        algorithm="RS256",
        headers={"kid": KID},
    )


def _settings(tmp_path: Path) -> Settings:
    base = dict(
        SANDBOX_API_KEY="the-key",
        SANDBOX_WEBHOOK_SECRET="the-secret",
        SANDBOX_CF_ACCESS_AUD=AUD,
        SANDBOX_CF_ACCESS_CERTS_URL=_JWKS_URL["value"],
        SANDBOX_FERNET_KEY=Fernet.generate_key().decode(),
        SANDBOX_PUBLIC_HOST="api-test.local",
        SANDBOX_MYSQL_HOST="203.0.113.10",
        SANDBOX_STATE_DB=str(tmp_path / "state.db"),
        SANDBOX_COMPOSE_DIR=str(tmp_path / "composes"),
        SANDBOX_TLS_DIR=str(tmp_path / "tls"),
        SANDBOX_LOG_DIR=str(tmp_path / "logs"),
        PROD_SSH_HOST="bastion",
        PROD_SSH_PORT="22",
        PROD_SSH_USER="sandbox",
        PROD_SSH_KEY="/tmp/nonexistent",
        PROD_MYSQL_HOST="prod-mysql",
        PROD_MYSQL_PORT="3306",
        PROD_MYSQL_USER="dumper",
        PROD_MYSQL_PASSWORD="x",
        SANDBOX_TTL_MIN_SECONDS="60",
        SANDBOX_TTL_DEFAULT_SECONDS="3600",
        SANDBOX_TTL_MAX_SECONDS="7200",
        SANDBOX_REAPER_INTERVAL_SECONDS="3600",
    )
    s = Settings(_env_file=None, **base)  # type: ignore[arg-type]
    print(f"DEBUG test settings certs_url={s.sandbox_cf_access_certs_url} jwks_dict={_JWKS_URL['value']}", flush=True)
    return s


class _FakeTunnel:
    def __init__(self, port: int = 33060, host: str = "127.0.0.1") -> None:
        self.local_port = port
        self.local_host = host

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _build_mocked_service(settings: Settings, store: SessionStore) -> SessionService:
    fake_dump = MagicMock(return_value=b"-- fake dump --")
    fake_clone = MagicMock()

    @contextmanager
    def fake_tunnel(**kw):
        yield _FakeTunnel()

    return SessionService(
        settings=settings,
        store=store,
        fernet=fernet_from_key(settings.sandbox_fernet_key),
        open_tunnel=fake_tunnel,
        dump_db=fake_dump,
        restore_db=MagicMock(),
        clone_db=fake_clone,
        apply_grants=MagicMock(),
        wait_ready=MagicMock(),
        up_session=MagicMock(),
        down_session=MagicMock(),
        replace_port_in_compose=MagicMock(),
        render_compose=MagicMock(return_value=Path("/tmp/fake-compose.yml")),
        render_mysqld_cnf=MagicMock(return_value=Path("/tmp/fake.cnf")),
        render_grant_sql=MagicMock(return_value="-- fake grant sql --"),
        generate_session_tls=MagicMock(),
        wait_healthy=MagicMock(),
        make_session_paths=MagicMock(
            return_value=MagicMock(
                session_dir=Path("/tmp/fake"),
                compose_path=Path("/tmp/fake/compose.yml"),
                cnf_path=Path("/tmp/fake/cnf"),
                tls_dir=Path("/tmp/fake/tls"),
                log_dir=Path("/tmp/fake/log"),
            )
        ),
        allocate_port=MagicMock(return_value=33451),
        gen_root_password=MagicMock(return_value="rootpw123456789012345678901234ab"),
    )


@pytest.fixture
def app_ctx(tmp_path: Path, monkeypatch):
    settings = _settings(tmp_path)
    for k, v in settings.model_dump(by_alias=True).items():
        monkeypatch.setenv(k, str(v))
    reset_settings_cache()
    reset_jwks_cache_for_tests()
    store = SessionStore(settings.sandbox_state_db)
    service = _build_mocked_service(settings, store)
    ctx = AppContext(settings=settings, store=store, service=service)
    app = create_app(ctx=ctx)
    with TestClient(app) as client:
        yield client, ctx
    store.close()


def _auth_headers() -> dict:
    return {
        "Cf-Access-Jwt-Assertion": _mint_jwt(),
        "X-API-Key": "the-key",
    }


def test_healthz_no_auth(app_ctx):
    client, _ = app_ctx
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_readyz_reports_dependency_status(app_ctx):
    client, _ = app_ctx
    r = client.get("/readyz")
    # Without a docker daemon / mysql client in the test env, we'll likely
    # be degraded. The endpoint MUST still return a payload.
    assert r.status_code in (200, 503)
    body = r.json()
    assert "checks" in body
    assert "sqlite" in body["checks"]


def test_metrics_text_plain(app_ctx):
    client, _ = app_ctx
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]
    assert "sqldb_sandbox_sessions_total" in r.text


def test_create_instance_requires_auth(app_ctx):
    client, _ = app_ctx
    r = client.post("/instance", json={"ticket": "10215", "dbs": ["db_a"]})
    assert r.status_code == 401


def test_create_instance_returns_full_response(app_ctx):
    client, ctx = app_ctx
    r = client.post(
        "/instance",
        json={"ticket": "10215", "dbs": ["db_a", "db_b"]},
        headers=_auth_headers(),
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["api_host"] == "api-test.local"
    assert body["mysql_host"] == "203.0.113.10"
    assert body["mysql_port"] == 33451
    assert body["ca_url"].endswith(f"/session-tls/{body['session_id']}/ca.pem")
    db_names = sorted(d["name"] for d in body["databases"])
    assert db_names == ["db_a", "db_b"]
    for d in body["databases"]:
        assert d["user"].startswith("u_")
        assert len(d["password"]) >= 24


def test_create_instance_validates_ticket(app_ctx):
    client, _ = app_ctx
    r = client.post(
        "/instance",
        json={"ticket": "!!!", "dbs": ["db_a"]},
        headers=_auth_headers(),
    )
    assert r.status_code == 422


def test_create_instance_validates_unique_dbs(app_ctx):
    client, _ = app_ctx
    r = client.post(
        "/instance",
        json={"ticket": "10215", "dbs": ["db_a", "db_a"]},
        headers=_auth_headers(),
    )
    assert r.status_code == 422


def test_create_instance_partial_tables(app_ctx):
    client, ctx = app_ctx
    r = client.post(
        "/instance",
        json={
            "ticket": "10215",
            "dbs": [
                {"name": "db_a", "tables": ["orders", "users"]},
                {"name": "db_b", "tables": "all"},
            ],
        },
        headers=_auth_headers(),
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert len(body["databases"]) == 2
    dbs_by_name = {d["name"]: d for d in body["databases"]}
    assert sorted(dbs_by_name["db_a"]["tables"]) == ["orders", "users"]
    # "all" normalises to None (full DB)
    assert dbs_by_name["db_b"]["tables"] is None

    # The mocked dump_db should have been called with the table list for db_a
    dump_mock = ctx.service.dump_db
    kwargs_by_db = {c.kwargs["db"]: c.kwargs for c in dump_mock.call_args_list}
    assert sorted(kwargs_by_db["db_a"]["tables"]) == ["orders", "users"]
    assert kwargs_by_db["db_b"]["tables"] == ()


def test_create_instance_invalid_table_name_rejected(app_ctx):
    client, _ = app_ctx
    r = client.post(
        "/instance",
        json={"ticket": "10215", "dbs": [{"name": "db_a", "tables": ["good", "bad;DROP"]}]},
        headers=_auth_headers(),
    )
    assert r.status_code == 422


def test_create_instance_empty_tables_list_rejected(app_ctx):
    client, _ = app_ctx
    r = client.post(
        "/instance",
        json={"ticket": "10215", "dbs": [{"name": "db_a", "tables": []}]},
        headers=_auth_headers(),
    )
    assert r.status_code == 422


def test_create_instance_legacy_string_form_still_works(app_ctx):
    client, ctx = app_ctx
    r = client.post(
        "/instance",
        json={"ticket": "10215", "dbs": ["db_a", "db_b"]},
        headers=_auth_headers(),
    )
    assert r.status_code == 201, r.text
    body = r.json()
    for d in body["databases"]:
        assert d["tables"] is None


def test_get_session_returns_creds(app_ctx):
    client, _ = app_ctx
    create = client.post(
        "/instance",
        json={"ticket": "10215", "dbs": ["db_a"]},
        headers=_auth_headers(),
    ).json()
    sid = create["session_id"]
    r = client.get(f"/session/{sid}", headers=_auth_headers())
    assert r.status_code == 200
    body = r.json()
    assert body["session_id"] == sid
    assert body["status"] == "ready"
    assert body["databases"][0]["name"] == "db_a"
    assert body["databases"][0]["password"] == create["databases"][0]["password"]


def test_get_session_missing_404(app_ctx):
    client, _ = app_ctx
    r = client.get("/session/00000000-0000-0000-0000-000000000000", headers=_auth_headers())
    assert r.status_code == 404


def test_reset_ttl_extends_and_blocks_second(app_ctx):
    client, _ = app_ctx
    sid = client.post(
        "/instance",
        json={"ticket": "t1", "dbs": ["db_a"]},
        headers=_auth_headers(),
    ).json()["session_id"]

    r1 = client.post(f"/session/{sid}/reset-ttl", headers=_auth_headers())
    assert r1.status_code == 200, r1.text
    body1 = r1.json()
    assert body1["reset_used"] is True
    assert datetime.fromisoformat(body1["expires_at"].replace("Z", "+00:00")) > datetime.fromtimestamp(0, tz=timezone.utc)

    r2 = client.post(f"/session/{sid}/reset-ttl", headers=_auth_headers())
    assert r2.status_code == 409


def test_reset_ttl_unknown_session_404(app_ctx):
    client, _ = app_ctx
    r = client.post("/session/00000000-0000-0000-0000-000000000000/reset-ttl",
                    headers=_auth_headers())
    assert r.status_code == 404


def test_delete_session_nukes(app_ctx):
    client, ctx = app_ctx
    sid = client.post(
        "/instance",
        json={"ticket": "t1", "dbs": ["db_a"]},
        headers=_auth_headers(),
    ).json()["session_id"]
    r = client.delete(f"/session/{sid}", headers=_auth_headers())
    assert r.status_code == 200
    assert r.json() == {"session_id": sid, "status": "nuked"}
    assert ctx.service.down_session.called


def test_delete_unknown_session_404(app_ctx):
    client, _ = app_ctx
    r = client.delete("/session/00000000-0000-0000-0000-000000000000",
                      headers=_auth_headers())
    assert r.status_code == 404


def test_get_ca_returns_pem(app_ctx, tmp_path):
    client, ctx = app_ctx
    sid = client.post(
        "/instance",
        json={"ticket": "t1", "dbs": ["db_a"]},
        headers=_auth_headers(),
    ).json()["session_id"]

    pem_path = tmp_path / "ca-test.pem"
    pem_path.write_text("-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n")
    record = ctx.store.get(sid)
    Path(record["tls_dir"]).mkdir(parents=True, exist_ok=True)
    (Path(record["tls_dir"]) / "ca.pem").write_text(pem_path.read_text())

    r = client.get(f"/session-tls/{sid}/ca.pem", headers=_auth_headers())
    assert r.status_code == 200
    assert "BEGIN CERTIFICATE" in r.text


def test_get_ca_unknown_session_404(app_ctx):
    client, _ = app_ctx
    r = client.get("/session-tls/00000000-0000-0000-0000-000000000000/ca.pem",
                   headers=_auth_headers())
    assert r.status_code == 404


def test_create_records_are_encrypted_at_rest(app_ctx):
    client, ctx = app_ctx
    sid = client.post(
        "/instance",
        json={"ticket": "t1", "dbs": ["db_a"]},
        headers=_auth_headers(),
    ).json()["session_id"]
    record = ctx.store.get(sid)
    assert b"db_a" not in record["creds_enc"]
    assert b"u_db_a" not in record["creds_enc"]
    plaintext = ctx.service.decrypt_creds(record["creds_enc"])
    assert plaintext["dbs"][0]["name"] == "db_a"


def _webhook_headers(body: bytes) -> dict:
    import hashlib, hmac as _hmac
    sig = "sha256=" + _hmac.new(b"the-secret", body, hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-Sandbox-Signature": sig,
    }


def test_webhook_ticket_closed_nukes_session(app_ctx):
    client, ctx = app_ctx
    sid = client.post(
        "/instance",
        json={"ticket": "10215", "dbs": ["db_a"]},
        headers=_auth_headers(),
    ).json()["session_id"]

    import json as _json
    body = _json.dumps({"ticket": "10215", "session_id": sid}).encode()
    r = client.post(
        "/webhook/ticket-closed",
        content=body,
        headers=_webhook_headers(body),
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "nuked"
    assert ctx.service.down_session.called
    assert ctx.store.get(sid)["status"] == "nuked"


def test_webhook_ticket_closed_idempotent_on_second_call(app_ctx):
    client, ctx = app_ctx
    sid = client.post(
        "/instance",
        json={"ticket": "10215", "dbs": ["db_a"]},
        headers=_auth_headers(),
    ).json()["session_id"]

    import json as _json
    body = _json.dumps({"ticket": "10215", "session_id": sid}).encode()
    headers = _webhook_headers(body)
    r1 = client.post("/webhook/ticket-closed", content=body, headers=headers)
    assert r1.status_code == 200
    assert r1.json()["status"] == "nuked"

    r2 = client.post("/webhook/ticket-closed", content=body, headers=headers)
    assert r2.status_code == 200
    assert r2.json()["status"] == "already_nuked"


def test_webhook_ticket_closed_rejects_ticket_mismatch(app_ctx):
    client, ctx = app_ctx
    sid = client.post(
        "/instance",
        json={"ticket": "10215", "dbs": ["db_a"]},
        headers=_auth_headers(),
    ).json()["session_id"]

    import json as _json
    body = _json.dumps({"ticket": "OTHER-9999", "session_id": sid}).encode()
    r = client.post(
        "/webhook/ticket-closed",
        content=body,
        headers=_webhook_headers(body),
    )
    assert r.status_code == 404
    assert ctx.store.get(sid)["status"] == "ready"


def test_webhook_ticket_closed_unknown_session_404(app_ctx):
    import json as _json
    body = _json.dumps({
        "ticket": "10215",
        "session_id": "00000000-0000-0000-0000-000000000000",
    }).encode()
    client, _ = app_ctx
    r = client.post(
        "/webhook/ticket-closed",
        content=body,
        headers=_webhook_headers(body),
    )
    assert r.status_code == 404


def test_webhook_ticket_closed_requires_signature(app_ctx):
    client, _ = app_ctx
    r = client.post(
        "/webhook/ticket-closed",
        json={"ticket": "10215", "session_id": "x"},
    )
    assert r.status_code == 401


def test_webhook_ticket_closed_rejects_bad_signature(app_ctx):
    client, _ = app_ctx
    import json as _json
    body = _json.dumps({"ticket": "10215", "session_id": "x"}).encode()
    r = client.post(
        "/webhook/ticket-closed",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Sandbox-Signature": "sha256=deadbeef",
        },
    )
    assert r.status_code == 401


def test_webhook_ticket_closed_does_not_require_cf_or_api_key(app_ctx):
    """Webhook must work without CF Access JWT or X-API-Key."""
    client, ctx = app_ctx
    sid = client.post(
        "/instance",
        json={"ticket": "10215", "dbs": ["db_a"]},
        headers=_auth_headers(),
    ).json()["session_id"]
    import json as _json
    body = _json.dumps({"ticket": "10215", "session_id": sid}).encode()
    headers = _webhook_headers(body)
    assert "Cf-Access-Jwt-Assertion" not in headers
    assert "X-API-Key" not in headers
    r = client.post("/webhook/ticket-closed", content=body, headers=headers)
    assert r.status_code == 200


# ---------- failure-handling tests ----------

def test_create_instance_dump_failure_returns_502(app_ctx):
    """mysqldump failure is a 'dump' category → HTTP 502, container torn down.

    Body must NOT echo upstream stderr verbatim (H1 fix).
    """
    import api.mysql_ops as mo
    client, ctx = app_ctx

    real_dump = ctx.service.dump_db

    def boom(**kwargs):
        raise mo.MySQLOpsError(
            "mysqldump db_a failed (rc=1): error 1045 (secret-bastion.example.com "
            "internal path /var/lib/sandboxes/composes/abc)"
        )

    ctx.service.dump_db = boom
    try:
        r = client.post(
            "/instance",
            json={"ticket": "10215", "dbs": ["db_a"]},
            headers=_auth_headers(),
        )
    finally:
        ctx.service.dump_db = real_dump

    assert r.status_code == 502, r.text
    body = r.json()
    assert body["category"] == "dump"
    assert body["session_id"]
    # Generic public message; no upstream detail leaked.
    assert body["detail"] == "prod dump failed"
    assert "secret-bastion" not in r.text
    assert "1045" not in r.text

    rec = ctx.store.get(body["session_id"])
    assert rec["status"] == "error"
    ctx.service.down_session.assert_called()


def test_create_instance_ssh_failure_returns_502(app_ctx):
    """Bastion unreachable → 'ssh' category → 502."""
    from api.service import CreateSessionError
    from api.ssh_tunnel import TunnelError
    from contextlib import contextmanager

    client, ctx = app_ctx

    real = ctx.service.open_tunnel

    @contextmanager
    def boom_tunnel(**kw):
        raise TunnelError("ssh connect failed: banner exchange timeout")
        yield  # unreachable, generator

    ctx.service.open_tunnel = boom_tunnel
    try:
        r = client.post(
            "/instance",
            json={"ticket": "10215", "dbs": ["db_a"]},
            headers=_auth_headers(),
        )
    finally:
        ctx.service.open_tunnel = real

    assert r.status_code == 502, r.text
    assert r.json()["category"] == "ssh"
    assert ctx.service.down_session.assert_called  # best-effort cleanup ran


def test_create_instance_port_exhaustion_returns_503(app_ctx):
    """allocate_port exhaustion → 'port' category → 503."""
    from api.service import CreateSessionError
    from api.docker_ops import DockerOpsError
    client, ctx = app_ctx

    real_alloc = ctx.service.allocate_port

    def boom_alloc(used, settings):
        raise DockerOpsError("no free ports in configured range")

    ctx.service.allocate_port = boom_alloc
    try:
        r = client.post(
            "/instance",
            json={"ticket": "10215", "dbs": ["db_a"]},
            headers=_auth_headers(),
        )
    finally:
        ctx.service.allocate_port = real_alloc

    assert r.status_code == 503, r.text
    assert r.json()["category"] == "port"


def test_create_instance_persists_placeholder_before_work(app_ctx):
    """A row exists in the store immediately after the call enters service.

    Even if the work fails partway, an operator can query the failed session.
    """
    from api.mysql_ops import MySQLOpsError
    client, ctx = app_ctx
    seen_in_store: list[str] = []

    real_clone = ctx.service.clone_db

    def boom(**kwargs):
        # As soon as clone starts, the placeholder row MUST exist.
        sids = [r["id"] for r in ctx.store.list_all()]
        seen_in_store.extend(sids)
        raise MySQLOpsError("mysqldump boom")

    ctx.service.clone_db = boom
    try:
        client.post("/instance", json={"ticket": "t", "dbs": ["db_a"]}, headers=_auth_headers())
    finally:
        ctx.service.clone_db = real_clone

    assert seen_in_store, "no placeholder row was persisted before clone ran"
    # And the row went to 'error' after failure.
    assert any(
        ctx.store.get(s)["status"] == "error" for s in seen_in_store if s
    )
