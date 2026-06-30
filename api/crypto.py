from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


def gen_password(nbytes: int = 24) -> str:
    """URL-safe random password.

    24 bytes → ~32 chars after base64.
    """
    return secrets.token_urlsafe(nbytes)


def fernet_from_key(key: str) -> Fernet:
    if isinstance(key, str):
        kb = key.encode("utf-8")
    else:
        kb = key
    try:
        return Fernet(kb)
    except (ValueError, TypeError) as exc:
        raise ValueError("SANDBOX_FERNET_KEY is not a valid Fernet key") from exc


def encrypt_creds(creds: dict[str, Any], fernet: Fernet) -> bytes:
    payload = json.dumps(creds, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return fernet.encrypt(payload)


def decrypt_creds(token: bytes, fernet: Fernet) -> dict[str, Any]:
    try:
        raw = fernet.decrypt(token)
    except InvalidToken as exc:
        raise ValueError("Invalid Fernet token (key mismatch or corruption)") from exc
    return json.loads(raw.decode("utf-8"))


def constant_time_eq(a: str | bytes, b: str | bytes) -> bool:
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hmac.compare_digest(a, b)


def webhook_signature(secret: str, body: bytes) -> str:
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def verify_webhook_signature(secret: str, body: bytes, header: str) -> bool:
    if not header:
        return False
    expected = webhook_signature(secret, body)
    return constant_time_eq(expected, header)