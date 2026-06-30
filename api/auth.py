from __future__ import annotations

import hashlib
import hmac
import threading
import time
from dataclasses import dataclass
from typing import Any

import jwt
from fastapi import Depends, Header, HTTPException, Request, status
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError

from api.config import Settings, get_settings
from api.crypto import constant_time_eq


CF_JWT_HEADER = "Cf-Access-Jwt-Assertion"
API_KEY_HEADER = "X-API-Key"
WEBHOOK_SIGNATURE_HEADER = "X-Sandbox-Signature"

_JWKS_CACHE_TTL_SECONDS = 3600


@dataclass
class AccessIdentity:
    email: str | None
    sub: str | None
    raw: dict[str, Any]


class _JWKSCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._client: PyJWKClient | None = None
        self._url: str | None = None
        self._fetched_at: float = 0.0

    def get(self, url: str) -> PyJWKClient:
        with self._lock:
            now = time.monotonic()
            stale = (now - self._fetched_at) > _JWKS_CACHE_TTL_SECONDS
            if self._client is None or self._url != url or stale:
                self._client = PyJWKClient(url, cache_keys=True, lifespan=_JWKS_CACHE_TTL_SECONDS)
                self._url = url
                self._fetched_at = now
            return self._client

    def invalidate(self) -> None:
        with self._lock:
            self._client = None
            self._url = None
            self._fetched_at = 0.0


_jwks_cache = _JWKSCache()


def _decode_cf_jwt(token: str, settings: Settings) -> AccessIdentity:
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing Cf-Access-Jwt-Assertion",
        )
    try:
        client = _jwks_cache.get(settings.sandbox_cf_access_certs_url)
        signing_key = client.get_signing_key_from_jwt(token).key
        payload = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=settings.sandbox_cf_access_aud,
            options={"require": ["exp", "iat"]},
        )
    except PyJWKClientConnectionError as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"cf access jwks unreachable: {exc}",
        )
    except PyJWKClientError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"cf access token invalid: {exc}")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "cf access token expired")
    except jwt.InvalidAudienceError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "cf access token audience mismatch")
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"cf access token invalid: {exc}")

    return AccessIdentity(
        email=payload.get("email"),
        sub=payload.get("sub"),
        raw=payload,
    )


def enforce_cf_access(
    request: Request,
    cf_jwt: str | None = Header(default=None, alias=CF_JWT_HEADER),
    settings: Settings = Depends(get_settings),
) -> AccessIdentity:
    if not settings.cf_access_enabled:
        request.state.cf_identity = AccessIdentity(email=None, sub=None, raw={})
        return request.state.cf_identity
    if settings.sandbox_test_mode:
        request.state.cf_identity = AccessIdentity(
            email="test@local", sub="test", raw={}
        )
        return request.state.cf_identity
    identity = _decode_cf_jwt(cf_jwt or "", settings)
    request.state.cf_identity = identity
    return identity


def enforce_api_key(
    api_key: str | None = Header(default=None, alias=API_KEY_HEADER),
    settings: Settings = Depends(get_settings),
) -> None:
    if settings.sandbox_test_mode:
        return
    if not api_key or not constant_time_eq(api_key, settings.sandbox_api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing API key",
        )


def webhook_signature_for(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def verify_webhook_signature(secret: str, body: bytes, header: str | None) -> bool:
    if not header:
        return False
    return constant_time_eq(webhook_signature_for(secret, body), header)


async def require_webhook_signature(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> bytes:
    """Read the request body (only happens when this dependency runs), verify
    the HMAC signature, return the body so downstream code can parse it.

    Replaces the old global body-capture middleware; the body is now read
    exactly once, only on the webhook route.
    """
    if settings.sandbox_test_mode:
        return b""
    body = await request.body()
    sig = request.headers.get(WEBHOOK_SIGNATURE_HEADER)
    if not verify_webhook_signature(settings.sandbox_webhook_secret, body, sig):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing webhook signature",
        )
    return body


def reset_jwks_cache_for_tests() -> None:
    _jwks_cache.invalidate()