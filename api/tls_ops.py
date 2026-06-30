from __future__ import annotations

import datetime
import logging
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


log = logging.getLogger("sandbox.tls_ops")


CERT_VALIDITY_DAYS = 365


@dataclass(frozen=True)
class TLSMaterial:
    ca_cert_path: Path
    ca_key_path: Path
    server_cert_path: Path
    server_key_path: Path
    client_cert_path: Path
    client_key_path: Path


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        cert.public_bytes(encoding=serialization.Encoding.PEM)
    )
    path.chmod(0o644)


def _build_ca(common_name: str) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = _key()
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=CERT_VALIDITY_DAYS * 2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _sign_leaf(
    *,
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    common_name: str,
    sans_dns: Iterable[str] = (),
    sans_ip: Iterable[str] = (),
    server_auth: bool,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = _key()
    now = datetime.datetime.now(datetime.timezone.utc)

    san_entries: list[x509.GeneralName] = []
    for dns in sans_dns:
        san_entries.append(x509.DNSName(dns))
    for ip in sans_ip:
        try:
            san_entries.append(x509.IPAddress(IPv4Address(ip)))
        except ValueError:
            log.warning(
                "ignoring invalid IPv4 SAN entry: %r (devs will not be able to "
                "verify --ssl-verify-server-cert against this IP)", ip,
            )

    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=CERT_VALIDITY_DAYS))
        .add_extension(
            x509.SubjectAlternativeName(san_entries) if san_entries else x509.SubjectAlternativeName([]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )

    if server_auth:
        # Server cert: SERVER_AUTH only. Dev clients authenticate via the
        # per-DB user+password + the CA pin, not via a client cert.
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    else:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )

    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
    )
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
        critical=False,
    )

    cert = builder.sign(ca_key, hashes.SHA256())
    return cert, key


def generate_session_tls(
    sid: str,
    out_dir: Path,
    *,
    container_hostname: str,
    mysql_host_ip: str | None = None,
) -> TLSMaterial:
    """Generate CA + server + client certs for one session."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    ca_cert_path = out_dir / "ca.pem"
    ca_key_path = out_dir / "ca.key"
    server_cert_path = out_dir / "server-cert.pem"
    server_key_path = out_dir / "server-key.pem"
    client_cert_path = out_dir / "client-cert.pem"
    client_key_path = out_dir / "client-key.pem"

    ca_cert, ca_key = _build_ca(f"sandbox-ca-{sid}")
    _write_cert(ca_cert_path, ca_cert)
    _write_key(ca_key_path, ca_key)

    sans_dns = [container_hostname]
    sans_ip = [mysql_host_ip] if mysql_host_ip else []
    server_cert, server_key = _sign_leaf(
        ca_cert=ca_cert,
        ca_key=ca_key,
        common_name=container_hostname,
        sans_dns=sans_dns,
        sans_ip=sans_ip,
        server_auth=True,
    )
    _write_cert(server_cert_path, server_cert)
    _write_key(server_key_path, server_key)

    client_cert, client_key = _sign_leaf(
        ca_cert=ca_cert,
        ca_key=ca_key,
        common_name=f"sandbox-client-{sid}",
        sans_dns=[f"client.{sid}.sandbox"],
        sans_ip=[],
        server_auth=False,
    )
    _write_cert(client_cert_path, client_cert)
    _write_key(client_key_path, client_key)

    return TLSMaterial(
        ca_cert_path=ca_cert_path,
        ca_key_path=ca_key_path,
        server_cert_path=server_cert_path,
        server_key_path=server_key_path,
        client_cert_path=client_cert_path,
        client_key_path=client_key_path,
    )


def read_ca_pem(path: Path) -> bytes:
    return Path(path).read_bytes()