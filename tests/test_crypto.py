from __future__ import annotations

import base64

import pytest

from api.crypto import (
    constant_time_eq,
    decrypt_creds,
    encrypt_creds,
    fernet_from_key,
    gen_password,
    verify_webhook_signature,
    webhook_signature,
)
from cryptography.fernet import Fernet


def test_gen_password_length_and_uniqueness():
    a = gen_password(24)
    b = gen_password(24)
    assert a != b
    assert len(a) >= 32


def test_fernet_from_key_valid_and_invalid():
    key = Fernet.generate_key().decode()
    assert isinstance(fernet_from_key(key), Fernet)
    with pytest.raises(ValueError):
        fernet_from_key("not-a-fernet-key")


def test_encrypt_decrypt_roundtrip():
    key = Fernet.generate_key().decode()
    f = fernet_from_key(key)
    creds = {"db_a": {"user": "u1", "password": "p1"}, "db_b": {"user": "u2"}}
    token = encrypt_creds(creds, f)
    assert isinstance(token, bytes)
    assert decrypt_creds(token, f) == creds


def test_decrypt_with_wrong_key_raises():
    f1 = Fernet(Fernet.generate_key())
    f2 = Fernet(Fernet.generate_key())
    token = encrypt_creds({"x": 1}, f1)
    with pytest.raises(ValueError):
        decrypt_creds(token, f2)


def test_constant_time_eq():
    assert constant_time_eq("abc", "abc")
    assert not constant_time_eq("abc", "abd")
    assert not constant_time_eq("abc", "abcd")
    assert constant_time_eq(b"abc", "abc")


def test_webhook_signature_roundtrip():
    body = b'{"hello":"world"}'
    sig = webhook_signature("secret", body)
    assert sig.startswith("sha256=")
    assert verify_webhook_signature("secret", body, sig)
    assert not verify_webhook_signature("secret", body, sig + "x")
    assert not verify_webhook_signature("other", body, sig)
    assert not verify_webhook_signature("secret", body, "")


def test_fernet_from_key_accepts_bytes():
    key = Fernet.generate_key()
    assert isinstance(fernet_from_key(key), Fernet)


def test_fernet_key_base64_padded_works():
    padded = base64.urlsafe_b64encode(b"x" * 32).decode()
    assert isinstance(fernet_from_key(padded), Fernet)