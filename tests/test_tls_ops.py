from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from api.tls_ops import generate_session_tls


def _load_pem(path: Path):
    if path.suffix == ".key":
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    return x509.load_pem_x509_certificate(path.read_bytes())


def test_generates_all_files(tmp_path: Path):
    out = tmp_path / "tls"
    m = generate_session_tls(
        "abc123",
        out,
        container_hostname="sandbox-abc123",
        mysql_host_ip="1.2.3.4",
    )
    for p in (
        m.ca_cert_path,
        m.ca_key_path,
        m.server_cert_path,
        m.server_key_path,
        m.client_cert_path,
        m.client_key_path,
    ):
        assert p.exists(), p
        assert p.stat().st_size > 0


def test_ca_is_self_signed_and_a_ca(tmp_path: Path):
    m = generate_session_tls("s1", tmp_path / "tls", container_hostname="x")
    ca_cert = _load_pem(m.ca_cert_path)
    assert ca_cert.subject == ca_cert.issuer
    bc = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True


def test_server_cert_signed_by_ca(tmp_path: Path):
    m = generate_session_tls(
        "s1",
        tmp_path / "tls",
        container_hostname="sandbox-s1",
        mysql_host_ip="10.0.0.5",
    )
    ca = _load_pem(m.ca_cert_path)
    server = _load_pem(m.server_cert_path)
    assert server.issuer == ca.subject
    san = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns = [v for v in san if isinstance(v, x509.DNSName)]
    ip  = [v for v in san if isinstance(v, x509.IPAddress)]
    assert any(v.value == "sandbox-s1" for v in dns)
    assert any(str(v.value) == "10.0.0.5" for v in ip)
    eku = server.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
    assert ExtendedKeyUsageOID.CLIENT_AUTH not in eku


def test_client_cert_signed_by_ca_and_has_client_auth(tmp_path: Path):
    m = generate_session_tls("s1", tmp_path / "tls", container_hostname="x")
    ca = _load_pem(m.ca_cert_path)
    client = _load_pem(m.client_cert_path)
    assert client.issuer == ca.subject
    eku = client.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
    assert ExtendedKeyUsageOID.SERVER_AUTH not in eku


def test_server_cert_validity_window(tmp_path: Path):
    m = generate_session_tls("s1", tmp_path / "tls", container_hostname="x")
    cert = _load_pem(m.server_cert_path)
    now = datetime.now(timezone.utc)
    assert cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def test_key_files_are_600(tmp_path: Path):
    m = generate_session_tls("s1", tmp_path / "tls", container_hostname="x")
    for kp in (m.ca_key_path, m.server_key_path, m.client_key_path):
        mode = kp.stat().st_mode & 0o777
        assert mode == 0o600, f"{kp} mode={oct(mode)}"


def test_cert_files_are_644(tmp_path: Path):
    m = generate_session_tls("s1", tmp_path / "tls", container_hostname="x")
    for cp in (m.ca_cert_path, m.server_cert_path, m.client_cert_path):
        mode = cp.stat().st_mode & 0o777
        assert mode == 0o644, f"{cp} mode={oct(mode)}"


def test_overwrite_replaces_files(tmp_path: Path):
    out = tmp_path / "tls"
    m1 = generate_session_tls("s1", out, container_hostname="x")
    first_ca = _load_pem(m1.ca_cert_path).public_bytes(serialization.Encoding.PEM)
    m2 = generate_session_tls("s1", out, container_hostname="x")
    second_ca = _load_pem(m2.ca_cert_path).public_bytes(serialization.Encoding.PEM)
    assert first_ca != second_ca