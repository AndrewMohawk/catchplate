"""One-shot offline outer TLS material for the private Basic-client fixture.

Run only in the renderer's bounded network-none setup container, after the
unchanged initializer and baseline have created the public inner MITM CA. The
inner private key is never opened. Root signing material is never persisted.
The renderer mounts only the outer leaf/key into the edge and only public CA
files into the client. Existing or partial outputs are retained and refused.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import signal
import socket
import stat

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


RUNTIME_ROOT = Path("/fixture-runtime")
INNER_CA_FILE = Path("/inner-ca.pem")
PROXY_HOST = "proxy.operator-basic.example.test"
PROXY_HOSTNAMES = (PROXY_HOST, "serverware-gmail-proxy.example.com")
_DIRECTORIES = frozenset({"app-data", "gate-data", "upstream-data", "service-secrets"})
_MARKER = ".private-fixture.json"
_OWNER = (10001, 10001)


def require(condition: bool) -> None:
    if not condition:
        raise ValueError("private Basic fixture setup refused")


def _read_public_file(path, maximum, *, dir_fd=None, mode=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and (info.st_uid, info.st_gid) == _OWNER and 0 < info.st_size <= maximum
            and not stat.S_IMODE(info.st_mode) & 0o022)
        if mode is not None:
            require(stat.S_IMODE(info.st_mode) == mode)
        value = source.read(maximum + 1)
        require(len(value) == info.st_size and len(value) <= maximum)
        return value


def _inner_root():
    raw = _read_public_file(INNER_CA_FILE, 16384)
    certificate = x509.load_pem_x509_certificate(raw)
    require(raw == certificate.public_bytes(serialization.Encoding.PEM))
    constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
    usage = certificate.extensions.get_extension_for_class(x509.KeyUsage)
    key = certificate.public_key()
    require(certificate.subject == certificate.issuer and constraints.critical and constraints.value.ca
        and usage.critical and usage.value.key_cert_sign and isinstance(key, ec.EllipticCurvePublicKey)
        and isinstance(key.curve, ec.SECP256R1) and isinstance(certificate.signature_hash_algorithm, hashes.SHA256))
    key.verify(certificate.signature, certificate.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
    now = dt.datetime.now(dt.timezone.utc)
    require(certificate.not_valid_before.replace(tzinfo=dt.timezone.utc) <= now
        < certificate.not_valid_after.replace(tzinfo=dt.timezone.utc))
    return certificate, raw


def _fresh_directory(parent_fd, name):
    os.mkdir(name, mode=0o700, dir_fd=parent_fd)
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    os.fchmod(descriptor, 0o700)
    return descriptor


def _write(directory_fd, name, value):
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o400, dir_fd=directory_fd)
    with os.fdopen(descriptor, "wb") as output:
        output.write(value)
        output.flush()
        os.fchmod(output.fileno(), 0o400)
        os.fchown(output.fileno(), *_OWNER)
        os.fsync(output.fileno())


def prepare(runtime_root=RUNTIME_ROOT, inner_ca_file=INNER_CA_FILE, *, proxy_hostname=PROXY_HOST):
    require(type(proxy_hostname) is str and proxy_hostname in PROXY_HOSTNAMES)
    require(runtime_root == RUNTIME_ROOT and inner_ca_file == INNER_CA_FILE and os.geteuid() == 0)
    require({name for _, name in socket.if_nameindex()} == {"lo"})
    os.umask(0o077)
    root_fd = os.open(RUNTIME_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    output_fds = []
    try:
        require(stat.S_IMODE(os.fstat(root_fd).st_mode) == 0o700)
        require(set(os.listdir(root_fd)) == _DIRECTORIES | {_MARKER})
        for name in _DIRECTORIES:
            info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                and (info.st_uid, info.st_gid) == _OWNER)
        marker = json.loads(_read_public_file(_MARKER, 1024, dir_fd=root_fd, mode=0o400))
        require(isinstance(marker, dict) and set(marker) == {"schema", "syntheticOnly"}
            and marker["schema"] == "serverware.privateOperatorAuditFixture/v1" and marker["syntheticOnly"] is True)
        inner, inner_pem = _inner_root()

        # These exclusive mkdir operations are the durable one-shot claim.
        # Do not delete or complete partial output after any failure.
        pki_fd = _fresh_directory(root_fd, "basic-pki")
        output_fds.append(pki_fd)
        work_fd = _fresh_directory(root_fd, "client-work")
        output_fds.append(work_fd)
        now = dt.datetime.now(dt.timezone.utc)
        root_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Isolated Proxy Basic Outer CA")])
        outer = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
            .sign(root_key, hashes.SHA256()))
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, proxy_hostname)]))
            .issuer_name(name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(proxy_hostname)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
            .sign(root_key, hashes.SHA256()))
        outer_pem = outer.public_bytes(serialization.Encoding.PEM)
        inner_fingerprint, outer_fingerprint = (cert.fingerprint(hashes.SHA256()) for cert in (inner, outer))
        require(inner_fingerprint != outer_fingerprint and inner.subject != outer.subject
            and inner.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            != outer.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
        roots = outer_pem + inner_pem
        require(roots.count(b"-----BEGIN CERTIFICATE-----") == 2
            and roots.count(b"-----END CERTIFICATE-----") == 2)
        _write(pki_fd, "outer-ca.pem", outer_pem)
        _write(pki_fd, "outer-cert.pem", leaf.public_bytes(serialization.Encoding.PEM))
        _write(pki_fd, "outer-key.pem", leaf_key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        _write(pki_fd, "inner-ca.pem", inner_pem)
        _write(pki_fd, "requests-ca.pem", roots)
        require(set(os.listdir(pki_fd)) == {"outer-ca.pem", "outer-cert.pem", "outer-key.pem", "inner-ca.pem", "requests-ca.pem"})
        require(not os.listdir(work_fd))
        for descriptor in output_fds:
            os.fchown(descriptor, *_OWNER)
            os.fsync(descriptor)
        os.fsync(root_fd)
        print(json.dumps({"schema": "serverware.proxyBasicFixturePki/v1", "syntheticOnly": True,
            "proxyHostname": proxy_hostname, "innerCaSha256": "sha256:" + inner_fingerprint.hex(),
            "outerCaSha256": "sha256:" + outer_fingerprint.hex(),
            "outerLeafSha256": "sha256:" + leaf.fingerprint(hashes.SHA256()).hex(),
            "requestsRootCount": 2, "rootPrivateKeyPersisted": False}, sort_keys=True))
    finally:
        for descriptor in output_fds:
            os.close(descriptor)
        os.close(root_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root", required=True, choices=(str(RUNTIME_ROOT),))
    parser.add_argument("--inner-ca-file", required=True, choices=(str(INNER_CA_FILE),))
    parser.add_argument("--proxy-hostname", choices=PROXY_HOSTNAMES, default=PROXY_HOST)
    args = parser.parse_args()
    signal.alarm(20)
    try:
        prepare(Path(args.runtime_root), Path(args.inner_ca_file), proxy_hostname=args.proxy_hostname)
    except Exception:
        raise SystemExit("Private Basic fixture setup refused; any partial output is retained. Do not retry.") from None
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    main()
