from __future__ import annotations

import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from api.auth import (
    CF_JWT_HEADER,
    WEBHOOK_SIGNATURE_HEADER,
    enforce_api_key,
    enforce_cf_access,
    reset_jwks_cache_for_tests,
    require_webhook_signature,
    verify_webhook_signature,
    webhook_signature_for,
)
from api.config import get_settings, reset_settings_cache


KID = "test-key-1"
ISSUER = "https://test.cloudflareaccess.com"
AUD = "test-aud"

_RSA_KEYS: dict = {}
_JWKS_URL: dict = {}


def _b64url_uint(n: int) -> str:
    blen = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(blen, "big")).rstrip(b"=").decode()


def _setup_rsa() -> None:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key()
    _RSA_KEYS["private"] = private
    _RSA_KEYS["pub_n"] = public.public_numbers().n
    _RSA_KEYS["pub_e"] = public.public_numbers().e


def _setup_jwks_server() -> None:
    jwks = {
        "keys": [
            {
                "kid": KID,
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": _b64url_uint(_RSA_KEYS["pub_n"]),
                "e": _b64url_uint(_RSA_KEYS["pub_e"]),
            }
        ]
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/certs":
                body = json.dumps(jwks).encode("utf-8")
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

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _JWKS_URL["value"] = f"http://127.0.0.1:{port}/certs"
    _JWKS_URL["_server"] = server
    _JWKS_URL["_thread"] = thread


_setup_rsa()
_setup_jwks_server()


def _mint_jwt(*, aud: str = AUD, exp_offset: int = 300, email: str = "dev@example.com", kid: str = KID) -> str:
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "sub": "sub-123",
        "aud": aud,
        "iat": now,
        "exp": now + exp_offset,
        "email": email,
    }
    return jwt.encode(payload, _RSA_KEYS["private"], algorithm="RS256", headers={"kid": kid})


@pytest.fixture
def cfg(monkeypatch):
    monkeypatch.setenv("SANDBOX_API_KEY", "the-key")
    monkeypatch.setenv("SANDBOX_WEBHOOK_SECRET", "the-secret")
    monkeypatch.setenv("SANDBOX_CF_ACCESS_AUD", AUD)
    monkeypatch.setenv("SANDBOX_CF_ACCESS_CERTS_URL", _JWKS_URL["value"])
    monkeypatch.setenv(
        "SANDBOX_FERNET_KEY", "ZmRldnRlc3RrZXktZmRldnRlc3RrZXktZmRldnRlc3RrZXkxMjM0NTY3OA=="
    )
    monkeypatch.setenv("SANDBOX_PUBLIC_HOST", "api.test")
    monkeypatch.setenv("SANDBOX_MYSQL_HOST", "1.2.3.4")
    monkeypatch.setenv("PROD_SSH_HOST", "x")
    monkeypatch.setenv("PROD_MYSQL_HOST", "y")
    monkeypatch.setenv("PROD_MYSQL_USER", "u")
    monkeypatch.setenv("PROD_MYSQL_PASSWORD", "p")
    reset_settings_cache()
    reset_jwks_cache_for_tests()
    yield
    reset_settings_cache()


def _build_app():
    app = FastAPI()

    @app.get("/protected")
    def protected(
        _identity=Depends(enforce_cf_access),
        _key=Depends(enforce_api_key),
    ):
        return {"ok": True}

    @app.post("/webhook")
    async def hook(_body: bytes = Depends(require_webhook_signature)):
        return {"ok": True}

    return app


def test_cf_jwt_valid_and_api_key(cfg):
    app = _build_app()
    client = TestClient(app)
    tok = _mint_jwt()
    r = client.get(
        "/protected",
        headers={CF_JWT_HEADER: tok, "X-API-Key": "the-key"},
    )
    assert r.status_code == 200, r.text


def test_cf_jwt_missing_returns_401(cfg):
    app = _build_app()
    client = TestClient(app)
    r = client.get("/protected", headers={"X-API-Key": "the-key"})
    assert r.status_code == 401


def test_cf_jwt_expired_returns_401(cfg):
    app = _build_app()
    client = TestClient(app)
    tok = _mint_jwt(exp_offset=-10)
    r = client.get(
        "/protected",
        headers={CF_JWT_HEADER: tok, "X-API-Key": "the-key"},
    )
    assert r.status_code == 401
    assert "expired" in r.json()["detail"].lower()


def test_cf_jwt_wrong_audience_returns_401(cfg):
    app = _build_app()
    client = TestClient(app)
    tok = _mint_jwt(aud="wrong-aud")
    r = client.get(
        "/protected",
        headers={CF_JWT_HEADER: tok, "X-API-Key": "the-key"},
    )
    assert r.status_code == 401


def test_cf_jwt_bad_signature_returns_401(cfg):
    app = _build_app()
    client = TestClient(app)
    bad = jwt.encode(
        {"aud": AUD, "exp": int(time.time()) + 60, "iat": int(time.time())},
        "not-a-real-key-32-bytes-padding-padding",
        algorithm="HS256",
    )
    r = client.get(
        "/protected",
        headers={CF_JWT_HEADER: bad, "X-API-Key": "the-key"},
    )
    assert r.status_code == 401


def test_api_key_missing_returns_401(cfg):
    app = _build_app()
    client = TestClient(app)
    tok = _mint_jwt()
    r = client.get("/protected", headers={CF_JWT_HEADER: tok})
    assert r.status_code == 401
    assert "api key" in r.json()["detail"].lower()


def test_api_key_wrong_returns_401(cfg):
    app = _build_app()
    client = TestClient(app)
    tok = _mint_jwt()
    r = client.get(
        "/protected",
        headers={CF_JWT_HEADER: tok, "X-API-Key": "wrong"},
    )
    assert r.status_code == 401


def test_webhook_signature_valid(cfg):
    app = _build_app()
    client = TestClient(app)
    body = b'{"ticket":"10215"}'
    sig = webhook_signature_for("the-secret", body)
    r = client.post(
        "/webhook",
        content=body,
        headers={"Content-Type": "application/json", WEBHOOK_SIGNATURE_HEADER: sig},
    )
    assert r.status_code == 200


def test_webhook_signature_bad(cfg):
    app = _build_app()
    client = TestClient(app)
    r = client.post(
        "/webhook",
        content=b"{}",
        headers={
            "Content-Type": "application/json",
            WEBHOOK_SIGNATURE_HEADER: "sha256=deadbeef",
        },
    )
    assert r.status_code == 401


def test_webhook_signature_missing(cfg):
    app = _build_app()
    client = TestClient(app)
    r = client.post("/webhook", content=b"{}")
    assert r.status_code == 401


def test_verify_webhook_signature_helper(cfg):
    s = get_settings()
    body = b"abc"
    sig = webhook_signature_for("the-secret", body)
    assert verify_webhook_signature("the-secret", body, sig) is True
    assert verify_webhook_signature("the-secret", body, "") is False
    assert verify_webhook_signature("the-secret", body, "sha256=00") is False


def test_test_mode_bypasses_cf_jwt_and_api_key(monkeypatch):
    monkeypatch.setenv("SANDBOX_API_KEY", "k")
    monkeypatch.setenv("SANDBOX_WEBHOOK_SECRET", "w")
    monkeypatch.setenv("SANDBOX_CF_ACCESS_AUD", "a")
    monkeypatch.setenv("SANDBOX_CF_ACCESS_CERTS_URL", _JWKS_URL["value"])
    monkeypatch.setenv(
        "SANDBOX_FERNET_KEY", "ZmRldnRlc3RrZXktZmRldnRlc3RrZXktZmRldnRlc3RrZXkxMjM0NTY3OA=="
    )
    monkeypatch.setenv("SANDBOX_PUBLIC_HOST", "api.test")
    monkeypatch.setenv("SANDBOX_MYSQL_HOST", "1.2.3.4")
    monkeypatch.setenv("PROD_SSH_HOST", "x")
    monkeypatch.setenv("PROD_MYSQL_HOST", "y")
    monkeypatch.setenv("PROD_MYSQL_USER", "u")
    monkeypatch.setenv("PROD_MYSQL_PASSWORD", "p")
    monkeypatch.setenv("SANDBOX_TEST_MODE", "1")
    reset_settings_cache()
    reset_jwks_cache_for_tests()
    try:
        app = _build_app()
        client = TestClient(app)
        r = client.get("/protected")
        assert r.status_code == 200, r.text

        r = client.post("/webhook", content=b"{}")
        assert r.status_code == 200
    finally:
        monkeypatch.delenv("SANDBOX_TEST_MODE")
        reset_settings_cache()