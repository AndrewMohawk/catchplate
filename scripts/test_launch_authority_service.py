#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import datetime as dt
import http.client
import json
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import launch_authority_relay as relay
import launch_authority_service as service
import launch_authorization as protocol


ROOT = Path(__file__).resolve().parents[1]
NOW = 1_800_000_000


def digest(character: str) -> str:
    return "sha256:" + character * 64


DEFAULT_RELAY_CERTIFICATE_SHA256 = digest("c")


def binding(
    token: str,
    *,
    sequence: int,
    epoch: int,
    audience: str = "prod.us-east-1.primary",
    identity: str = digest("9"),
) -> dict[str, Any]:
    return {
        "deploymentAudience": audience,
        "deploymentIdentitySha256": identity,
        "releaseSequence": sequence,
        "rollbackEpoch": epoch,
        "manifestSha256": digest(token),
        "releaseProvenanceSha256": digest(token),
        "provenanceDigest": digest(token),
        "sourceTreeDigest": digest(token),
        "launcherSha256": digest(token),
        "reproducibleBuildVerificationSha256": digest(token),
    }


def registry_entry(
    token: str,
    *,
    sequence: int,
    epoch: int,
    enabled: bool = True,
    revoked: bool = False,
    relay_certificate_sha256: str = DEFAULT_RELAY_CERTIFICATE_SHA256,
) -> dict[str, Any]:
    return {
        **binding(token, sequence=sequence, epoch=epoch),
        "relayClientCertificateSha256": relay_certificate_sha256,
        "enabled": enabled,
        "revoked": revoked,
    }


def request_for(
    entry: dict[str, Any],
    *,
    nonce: str,
    boot: str = "8",
) -> dict[str, Any]:
    return {
        "apiVersion": protocol.REQUEST_API_VERSION,
        "kind": protocol.REQUEST_KIND,
        "launcherNonce": nonce * 64,
        "bootIdSha256": digest(boot),
        **{field: entry[field] for field in service._ENTRY_BINDING_FIELDS},
    }


def canonical_request(entry: dict[str, Any], *, nonce: str, boot: str = "8") -> bytes:
    return protocol.canonical_json_bytes(request_for(entry, nonce=nonce, boot=boot))


def write_bytes(path: Path, value: bytes, mode: int) -> Path:
    path.write_bytes(value)
    path.chmod(mode)
    return path


def issue_authorization(
    engine: service.LaunchAuthority,
    raw: bytes,
    *,
    now: int = NOW,
    peer_certificate_sha256: str = DEFAULT_RELAY_CERTIFICATE_SHA256,
) -> bytes:
    return engine.issue(
        raw,
        peer_certificate_sha256=peer_certificate_sha256,
        now_unix_seconds=now,
    )


class TestPKI:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.ca_certificate = self._ca_certificate(self.ca_key, "Serverware Test CA")
        self.server_key = ec.generate_private_key(ec.SECP256R1())
        self.server_certificate = self._leaf_certificate(
            self.server_key,
            common_name="localhost",
            extended_usage=ExtendedKeyUsageOID.SERVER_AUTH,
            san=x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        )
        self.client_key = ec.generate_private_key(ec.SECP256R1())
        self.client_certificate = self._leaf_certificate(
            self.client_key,
            common_name="serverware-launch-relay",
            extended_usage=ExtendedKeyUsageOID.CLIENT_AUTH,
            san=None,
        )
        self.alternate_client_key = ec.generate_private_key(ec.SECP256R1())
        self.alternate_client_certificate = self._leaf_certificate(
            self.alternate_client_key,
            common_name="serverware-other-launch-relay",
            extended_usage=ExtendedKeyUsageOID.CLIENT_AUTH,
            san=None,
        )
        self.other_ca_key = ec.generate_private_key(ec.SECP256R1())
        self.other_ca_certificate = self._ca_certificate(
            self.other_ca_key, "Untrusted Test CA"
        )

        self.ca_path = self._write_certificate("ca.pem", self.ca_certificate)
        self.server_certificate_path = self._write_certificate(
            "server.pem", self.server_certificate
        )
        self.server_key_path = self._write_key("server-key.pem", self.server_key)
        self.client_certificate_path = self._write_certificate(
            "client.pem", self.client_certificate
        )
        self.client_key_path = self._write_key("client-key.pem", self.client_key)
        self.alternate_client_certificate_path = self._write_certificate(
            "alternate-client.pem", self.alternate_client_certificate
        )
        self.alternate_client_key_path = self._write_key(
            "alternate-client-key.pem", self.alternate_client_key
        )
        self.other_ca_path = self._write_certificate(
            "other-ca.pem", self.other_ca_certificate
        )

    @staticmethod
    def _ca_certificate(
        key: ec.EllipticCurvePrivateKey, common_name: str
    ) -> x509.Certificate:
        now = dt.datetime.now(dt.timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=2))
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
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )

    def _leaf_certificate(
        self,
        key: ec.EllipticCurvePrivateKey,
        *,
        common_name: str,
        extended_usage: x509.ObjectIdentifier,
        san: x509.SubjectAlternativeName | None,
    ) -> x509.Certificate:
        now = dt.datetime.now(dt.timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
            )
            .issuer_name(self.ca_certificate.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(x509.ExtendedKeyUsage([extended_usage]), critical=False)
        )
        if san is not None:
            builder = builder.add_extension(san, critical=False)
        return builder.sign(self.ca_key, hashes.SHA256())

    def _write_certificate(self, name: str, certificate: x509.Certificate) -> Path:
        return write_bytes(
            self.root / name,
            certificate.public_bytes(serialization.Encoding.PEM),
            0o644,
        )

    def _write_key(self, name: str, key: ec.EllipticCurvePrivateKey) -> Path:
        return write_bytes(
            self.root / name,
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            0o600,
        )

    @staticmethod
    def certificate_sha256(certificate: x509.Certificate) -> str:
        return service.der_certificate_sha256(
            certificate.public_bytes(serialization.Encoding.DER)
        )

    def client_context(
        self,
        *,
        include_certificate: bool = True,
        alternate_certificate: bool = False,
        ca_path: Path | None = None,
    ) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(ca_path or self.ca_path))
        if include_certificate:
            certificate_path = (
                self.alternate_client_certificate_path
                if alternate_certificate
                else self.client_certificate_path
            )
            key_path = (
                self.alternate_client_key_path
                if alternate_certificate
                else self.client_key_path
            )
            context.load_cert_chain(str(certificate_path), str(key_path))
        return context


class AuthorityFixture:
    def __init__(
        self,
        root: Path,
        *,
        relay_certificate_sha256: str = DEFAULT_RELAY_CERTIFICATE_SHA256,
    ) -> None:
        self.root = root
        self.entries = [
            registry_entry(
                token,
                sequence=sequence,
                epoch=epoch,
                enabled=enabled,
                revoked=revoked,
                relay_certificate_sha256=relay_certificate_sha256,
            )
            for token, sequence, epoch, enabled, revoked in (
                ("a", 1, 0, True, False),
                ("b", 1, 0, True, False),
                ("b", 2, 0, True, False),
                ("a", 3, 0, True, False),
                ("a", 3, 1, True, False),
                ("c", 4, 0, True, False),
                ("c", 4, 1, True, False),
                ("c", 4, 2, True, False),
                ("d", 5, 1, True, False),
                ("b", 2, 2, True, False),
                ("e", 10, 1, False, False),
                ("f", 11, 1, True, True),
            )
        ]
        self.registry_document = {
            "apiVersion": service.REGISTRY_API_VERSION,
            "generation": 1,
            "kind": service.REGISTRY_KIND,
            "releases": self.entries,
        }
        self.registry_path = write_bytes(
            root / "release-registry.json",
            protocol.canonical_json_bytes(self.registry_document),
            0o600,
        )
        self.authority_private_key = Ed25519PrivateKey.generate()
        self.authority_key_path = write_bytes(
            root / "launch-authority-key.pem",
            self.authority_private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            0o600,
        )
        self.authority_spki = self.authority_private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.authority_key_id = protocol.spki_key_id(self.authority_spki)
        self.ledger_path = root / "launch-authority.sqlite3"
        service.LaunchAuthorityLedger(self.ledger_path, initialize=True)

    def engine(self) -> service.LaunchAuthority:
        return service.LaunchAuthority(
            registry_path=self.registry_path,
            ledger=service.LaunchAuthorityLedger(self.ledger_path),
            signing_key=service.load_authority_signing_key(
                self.authority_key_path,
                expected_key_id=self.authority_key_id,
            ),
        )

    def entry(
        self,
        token: str,
        *,
        sequence: int,
        epoch: int,
        enabled: bool | None = None,
        revoked: bool | None = None,
    ) -> dict[str, Any]:
        matches = [
            item
            for item in self.entries
            if item["manifestSha256"] == digest(token)
            and item["releaseSequence"] == sequence
            and item["rollbackEpoch"] == epoch
            and (enabled is None or item["enabled"] is enabled)
            and (revoked is None or item["revoked"] is revoked)
        ]
        if len(matches) != 1:
            raise AssertionError(
                f"entry lookup was ambiguous: {token} {sequence} {epoch}"
            )
        return matches[0]


class RunningServer:
    def __init__(self, server: ThreadingHTTPServer) -> None:
        self.server = server
        self.thread = threading.Thread(
            target=server.serve_forever,
            name="launch-authority-test-server",
            daemon=True,
        )

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def __enter__(self) -> RunningServer:
        self.thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise AssertionError("test HTTPS server did not stop")


def authority_server(
    engine: service.LaunchAuthority,
    pki: TestPKI,
    *,
    allowed_source_cidrs: tuple[str, ...] = ("127.0.0.1/32", "::1/128"),
    max_handshakes: int = service.DEFAULT_MAX_HANDSHAKES,
    max_handshakes_per_ip: int = service.DEFAULT_MAX_HANDSHAKES_PER_IP,
    max_issuance_workers: int = service.DEFAULT_MAX_ISSUANCE_WORKERS,
    max_issuance_workers_per_ip: int = (service.DEFAULT_MAX_ISSUANCE_WORKERS_PER_IP),
    handshake_deadline_seconds: float = service.DEFAULT_HANDSHAKE_DEADLINE_SECONDS,
    connection_deadline_seconds: float = service.DEFAULT_CONNECTION_DEADLINE_SECONDS,
) -> service.LaunchAuthorityHTTPServer:
    return service.create_https_server(
        ("127.0.0.1", 0),
        authority=engine,
        server_certificate=pki.server_certificate_path,
        server_private_key=pki.server_key_path,
        client_ca_certificate=pki.ca_path,
        allowed_source_cidrs=allowed_source_cidrs,
        max_handshakes=max_handshakes,
        max_handshakes_per_ip=max_handshakes_per_ip,
        max_issuance_workers=max_issuance_workers,
        max_issuance_workers_per_ip=max_issuance_workers_per_ip,
        handshake_deadline_seconds=handshake_deadline_seconds,
        connection_deadline_seconds=connection_deadline_seconds,
    )


def https_request(
    port: int,
    context: ssl.SSLContext,
    *,
    body: bytes,
    method: str = "POST",
    path: str = service.AUTHORIZATION_PATH,
    content_type: str = service.REQUEST_CONTENT_TYPE,
    timeout: float = 2.0,
) -> tuple[int, list[tuple[str, str]], bytes]:
    connection = http.client.HTTPSConnection(
        "localhost", port, context=context, timeout=timeout
    )
    try:
        connection.request(
            method,
            path,
            body=body,
            headers={"Content-Type": content_type, "Content-Length": str(len(body))},
        )
        response = connection.getresponse()
        response_body = response.read()
        return response.status, response.getheaders(), response_body
    finally:
        connection.close()


class ScriptedAuthorityServer:
    def __init__(
        self,
        pki: TestPKI,
        *,
        status: int = 200,
        content_type: str = relay.RESPONSE_CONTENT_TYPE,
        body: bytes,
        delay_seconds: float = 0.0,
        body_chunk_delay_seconds: float = 0.0,
        body_chunk_size: int = 16,
        include_length: bool = True,
    ) -> None:
        self.received: list[bytes] = []
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                fixture.received.append(self.rfile.read(length))
                if delay_seconds:
                    time.sleep(delay_seconds)
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                if include_length:
                    self.send_header("Content-Length", str(len(body)))
                if 300 <= status < 400:
                    self.send_header("Location", "https://elsewhere.invalid/")
                self.send_header("Connection", "close")
                self.end_headers()
                try:
                    if body_chunk_delay_seconds:
                        for offset in range(0, len(body), body_chunk_size):
                            self.wfile.write(body[offset : offset + body_chunk_size])
                            self.wfile.flush()
                            time.sleep(body_chunk_delay_seconds)
                    else:
                        self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, _format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(
            str(pki.server_certificate_path), str(pki.server_key_path)
        )
        context.load_verify_locations(cafile=str(pki.ca_path))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        self.running = RunningServer(server)

    @property
    def port(self) -> int:
        return self.running.port

    def __enter__(self) -> ScriptedAuthorityServer:
        self.running.__enter__()
        return self

    def __exit__(self, *args: object) -> None:
        self.running.__exit__(*args)


class LaunchAuthorityEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.fixture = AuthorityFixture(self.root)
        self.engine = self.fixture.engine()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_authority_error(self, code: str, raw: bytes) -> service.AuthorityError:
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(self.engine, raw)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_valid_issuance_is_signed_registry_bound_and_persisted(self) -> None:
        entry = self.fixture.entry("a", sequence=1, epoch=0)
        raw = canonical_request(entry, nonce="1")
        response = issue_authorization(self.engine, raw)
        request = protocol.require_canonical_json_bytes(raw)
        verified = protocol.verify_launch_authorization(
            response,
            authority_public_key_spki_der=self.fixture.authority_spki,
            expected_request_sha256=protocol.launch_authorization_request_sha256(
                request
            ),
            expected_authority_key_id=self.fixture.authority_key_id,
            now_unix_seconds=NOW + 1,
        )
        self.assertEqual(verified.issued_at_unix_seconds, NOW)
        self.assertEqual(verified.expires_at_unix_seconds, NOW + 30)
        self.assertEqual(
            self.engine.ledger.counts(),
            {
                "authorizations": 1,
                "deployment_high_water": 1,
                "seen_release_tuples": 1,
                "registry_state": 1,
                "revoked_release_bindings": 1,
            },
        )

    def test_identical_retry_is_byte_identical_and_nonce_collision_fails(self) -> None:
        entry = self.fixture.entry("a", sequence=1, epoch=0)
        raw = canonical_request(entry, nonce="2")
        first = issue_authorization(self.engine, raw)
        retry = issue_authorization(self.engine, raw, now=NOW + 1000)
        self.assertEqual(first, retry)
        collision = canonical_request(entry, nonce="2", boot="7")
        self.assert_authority_error("NONCE_COLLISION", collision)
        self.assertEqual(self.engine.ledger.counts()["authorizations"], 1)

    def test_release_and_retry_are_bound_to_exact_relay_certificate(self) -> None:
        entry = self.fixture.entry("a", sequence=1, epoch=0)
        raw = canonical_request(entry, nonce="2")
        wrong_certificate = digest("d")
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(
                self.engine,
                raw,
                peer_certificate_sha256=wrong_certificate,
            )
        self.assertEqual(caught.exception.code, "RELAY_CLIENT_CERTIFICATE_MISMATCH")
        issued = issue_authorization(self.engine, raw)
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(
                self.engine,
                raw,
                now=NOW + 100,
                peer_certificate_sha256=wrong_certificate,
            )
        self.assertEqual(caught.exception.code, "RELAY_CLIENT_CERTIFICATE_MISMATCH")
        self.assertEqual(issue_authorization(self.engine, raw, now=NOW + 100), issued)

    def test_registry_generation_revocation_and_corruption_block_retry(self) -> None:
        entry = self.fixture.entry("a", sequence=1, epoch=0)
        first_raw = canonical_request(entry, nonce="3")
        issue_authorization(self.engine, first_raw)

        reused_generation = deepcopy(self.fixture.registry_document)
        reused_generation["releases"][0]["enabled"] = False
        write_bytes(
            self.fixture.registry_path,
            protocol.canonical_json_bytes(reused_generation),
            0o600,
        )
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(self.engine, first_raw)
        self.assertEqual(caught.exception.code, "REGISTRY_GENERATION_CONFLICT")

        disabled = deepcopy(self.fixture.registry_document)
        disabled["generation"] = 2
        disabled["releases"][0]["enabled"] = False
        write_bytes(
            self.fixture.registry_path,
            protocol.canonical_json_bytes(disabled),
            0o600,
        )
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(self.engine, first_raw)
        self.assertEqual(caught.exception.code, "RELEASE_DISABLED")
        self.assertEqual(self.engine.ledger.registry_generation(), 2)

        write_bytes(
            self.fixture.registry_path,
            protocol.canonical_json_bytes(self.fixture.registry_document),
            0o600,
        )
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(self.engine, first_raw)
        self.assertEqual(caught.exception.code, "REGISTRY_GENERATION_ROLLBACK")

        revoked = deepcopy(self.fixture.registry_document)
        revoked["generation"] = 3
        revoked["releases"][0]["revoked"] = True
        write_bytes(
            self.fixture.registry_path,
            protocol.canonical_json_bytes(revoked),
            0o600,
        )
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(self.engine, first_raw)
        self.assertEqual(caught.exception.code, "RELEASE_REVOKED")
        self.assertEqual(self.engine.ledger.registry_generation(), 3)

        resurrected = deepcopy(self.fixture.registry_document)
        resurrected["generation"] = 4
        write_bytes(
            self.fixture.registry_path,
            protocol.canonical_json_bytes(resurrected),
            0o600,
        )
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(self.engine, first_raw)
        self.assertEqual(caught.exception.code, "REGISTRY_REVOKED_BINDING_RESURRECTION")
        self.assertEqual(self.engine.ledger.registry_generation(), 3)

        write_bytes(self.fixture.registry_path, b"{}", 0o600)
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(self.engine, first_raw)
        self.assertEqual(caught.exception.code, "REGISTRY_UNAVAILABLE")

    def test_disabled_binding_may_be_reenabled_by_higher_generation(self) -> None:
        entry = self.fixture.entry("a", sequence=1, epoch=0)
        raw = canonical_request(entry, nonce="4")
        original = issue_authorization(self.engine, raw)

        disabled = deepcopy(self.fixture.registry_document)
        disabled["generation"] = 2
        disabled["releases"][0]["enabled"] = False
        write_bytes(
            self.fixture.registry_path,
            protocol.canonical_json_bytes(disabled),
            0o600,
        )
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(self.engine, raw)
        self.assertEqual(caught.exception.code, "RELEASE_DISABLED")

        reenabled = deepcopy(self.fixture.registry_document)
        reenabled["generation"] = 3
        write_bytes(
            self.fixture.registry_path,
            protocol.canonical_json_bytes(reenabled),
            0o600,
        )
        self.assertEqual(issue_authorization(self.engine, raw), original)

    def test_registry_reload_fails_closed_on_unstable_path(self) -> None:
        enrolled = self.fixture.entry("a", sequence=1, epoch=0)
        replacement = write_bytes(
            self.root / "replacement-registry.json",
            self.fixture.registry_path.read_bytes(),
            0o600,
        )
        self.fixture.registry_path.unlink()
        self.fixture.registry_path.symlink_to(replacement)
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(self.engine, canonical_request(enrolled, nonce="6"))
        self.assertEqual(caught.exception.code, "REGISTRY_UNAVAILABLE")

    def test_ledger_requires_one_time_initialization_and_missing_restart_fails(
        self,
    ) -> None:
        one_time_path = self.root / "one-time.sqlite3"
        with self.assertRaisesRegex(
            service.AuthorityConfigurationError, "initialize it explicitly"
        ):
            service.LaunchAuthorityLedger(one_time_path)
        self.assertEqual(service.main(["--initialize-ledger", str(one_time_path)]), 0)
        service.LaunchAuthorityLedger(one_time_path)
        self.assertEqual(service.main(["--initialize-ledger", str(one_time_path)]), 2)

        self.fixture.ledger_path.unlink()
        with self.assertRaisesRegex(
            service.AuthorityConfigurationError, "initialize it explicitly"
        ):
            self.fixture.engine()

    def test_ledger_initialization_failure_is_atomic_and_normalized(self) -> None:
        failed_path = self.root / "failed-initialization.sqlite3"
        with (
            mock.patch.object(
                service.LaunchAuthorityLedger,
                "_create_schema",
                side_effect=sqlite3.OperationalError("injected schema failure"),
            ),
            self.assertRaisesRegex(
                service.AuthorityConfigurationError, "setup failed closed"
            ),
        ):
            service.LaunchAuthorityLedger(failed_path, initialize=True)
        self.assertFalse(failed_path.exists())
        self.assertFalse(Path(str(failed_path) + "-wal").exists())
        self.assertFalse(Path(str(failed_path) + "-shm").exists())

        initialized_path = self.root / "atomic-initialization.sqlite3"
        ledger = service.LaunchAuthorityLedger(initialized_path, initialize=True)
        self.assertEqual(ledger.counts()["registry_state"], 0)
        connection = ledger.connect()
        try:
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0],
                service.LEDGER_SCHEMA_VERSION,
            )
            self.assertFalse(connection.in_transaction)
        finally:
            connection.close()

    def test_ledger_unlink_during_issuance_fails_before_envelope_release(self) -> None:
        raw = canonical_request(self.fixture.entry("a", sequence=1, epoch=0), nonce="a")
        original_sign = protocol.sign_launch_authorization

        def unlink_after_sign(*args: Any, **kwargs: Any) -> dict[str, Any]:
            envelope = original_sign(*args, **kwargs)
            self.fixture.ledger_path.unlink()
            return envelope

        with (
            mock.patch.object(
                protocol,
                "sign_launch_authorization",
                side_effect=unlink_after_sign,
            ),
            self.assertRaises(service.AuthorityError) as caught,
        ):
            issue_authorization(self.engine, raw)
        self.assertEqual(caught.exception.code, "LEDGER_UNAVAILABLE")

    def test_ledger_session_detects_pathname_inode_replacement(self) -> None:
        replacement = self.root / "replacement-ledger.sqlite3"
        shutil.copy2(self.fixture.ledger_path, replacement)
        replacement.chmod(0o600)
        session = self.engine.ledger.open_session()
        try:
            replacement.replace(self.fixture.ledger_path)
            with self.assertRaisesRegex(
                service.AuthorityConfigurationError, "pathname was replaced"
            ):
                session.assert_path_identity()
        finally:
            session.connection.close()

    def test_old_ledger_restore_demonstrates_external_checkpoint_requirement(
        self,
    ) -> None:
        first = self.fixture.entry("a", sequence=1, epoch=0)
        raw = canonical_request(first, nonce="7")
        original = issue_authorization(self.engine, raw)
        snapshot = self.root / "old-ledger-snapshot.sqlite3"
        shutil.copy2(self.fixture.ledger_path, snapshot)
        snapshot.chmod(0o600)
        old_registry = self.fixture.registry_path.read_bytes()

        revoked = deepcopy(self.fixture.registry_document)
        revoked["generation"] = 2
        revoked["releases"][0]["revoked"] = True
        write_bytes(
            self.fixture.registry_path,
            protocol.canonical_json_bytes(revoked),
            0o600,
        )
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(self.engine, raw)
        self.assertEqual(caught.exception.code, "RELEASE_REVOKED")
        self.assertEqual(self.engine.ledger.registry_generation(), 2)

        for suffix in ("-wal", "-shm"):
            Path(str(self.fixture.ledger_path) + suffix).unlink(missing_ok=True)
        snapshot.replace(self.fixture.ledger_path)
        write_bytes(self.fixture.registry_path, old_registry, 0o600)
        restored = self.fixture.engine()
        self.assertEqual(issue_authorization(restored, raw), original)
        self.assertIn(
            "external monotonic anti-rollback checkpoint",
            service.EXTERNAL_ANTI_ROLLBACK_REQUIREMENT,
        )

    def test_unknown_disabled_and_revoked_releases_fail_closed(self) -> None:
        disabled = self.fixture.entry("e", sequence=10, epoch=1, enabled=False)
        revoked = self.fixture.entry("f", sequence=11, epoch=1, revoked=True)
        self.assert_authority_error(
            "RELEASE_DISABLED", canonical_request(disabled, nonce="3")
        )
        self.assert_authority_error(
            "RELEASE_REVOKED", canonical_request(revoked, nonce="4")
        )
        unknown = registry_entry("0", sequence=99, epoch=9)
        self.assert_authority_error(
            "UNKNOWN_RELEASE", canonical_request(unknown, nonce="5")
        )
        self.assertEqual(self.engine.ledger.counts()["authorizations"], 0)

    def test_registry_match_binds_every_release_field(self) -> None:
        enrolled = self.fixture.entry("a", sequence=1, epoch=0)
        mutations: dict[str, Any] = {
            "deploymentAudience": "prod.us-west-2.secondary",
            "deploymentIdentitySha256": digest("0"),
            "releaseSequence": 99,
            "rollbackEpoch": 9,
            "manifestSha256": digest("0"),
            "releaseProvenanceSha256": digest("0"),
            "provenanceDigest": digest("0"),
            "sourceTreeDigest": digest("0"),
            "launcherSha256": digest("0"),
            "reproducibleBuildVerificationSha256": digest("0"),
        }
        for index, (field, value) in enumerate(mutations.items()):
            request = request_for(enrolled, nonce=f"{index:x}")
            request[field] = value
            with (
                self.subTest(field=field),
                self.assertRaises(service.AuthorityError) as caught,
            ):
                issue_authorization(self.engine, protocol.canonical_json_bytes(request))
            self.assertEqual(caught.exception.code, "UNKNOWN_RELEASE")

    def test_sequence_tuple_and_rollback_high_water_state_machine(self) -> None:
        def issue(token: str, sequence: int, epoch: int, nonce: str) -> bytes:
            return issue_authorization(
                self.engine,
                canonical_request(
                    self.fixture.entry(token, sequence=sequence, epoch=epoch),
                    nonce=nonce,
                ),
            )

        issue("a", 1, 0, "1")
        with self.assertRaisesRegex(
            service.AuthorityError, "equal release sequence"
        ) as caught:
            issue("b", 1, 0, "2")
        self.assertEqual(caught.exception.code, "SEQUENCE_TUPLE_MISMATCH")
        issue("b", 2, 0, "3")
        with self.assertRaises(service.AuthorityError) as caught:
            issue("a", 1, 0, "1")
        self.assertEqual(caught.exception.code, "SEQUENCE_ROLLBACK")
        with self.assertRaises(service.AuthorityError) as caught:
            issue("a", 3, 0, "4")
        self.assertEqual(caught.exception.code, "ROLLBACK_EPOCH_REQUIRED")
        issue("a", 3, 1, "5")
        with self.assertRaises(service.AuthorityError) as caught:
            issue("c", 4, 0, "6")
        self.assertEqual(caught.exception.code, "ROLLBACK_EPOCH_ROLLBACK")
        issue("c", 4, 1, "7")
        with self.assertRaises(service.AuthorityError) as caught:
            issue("c", 4, 2, "8")
        self.assertEqual(caught.exception.code, "SEQUENCE_TUPLE_MISMATCH")
        with self.assertRaises(service.AuthorityError) as caught:
            issue("b", 2, 2, "9")
        self.assertEqual(caught.exception.code, "SEQUENCE_ROLLBACK")
        issue("d", 5, 1, "a")
        issue("d", 5, 1, "b")
        self.assertEqual(
            self.engine.ledger.counts(),
            {
                "authorizations": 6,
                "deployment_high_water": 1,
                "seen_release_tuples": 4,
                "registry_state": 1,
                "revoked_release_bindings": 1,
            },
        )

    def test_restart_preserves_retry_bytes_and_high_water(self) -> None:
        current = self.fixture.entry("c", sequence=4, epoch=1)
        raw = canonical_request(current, nonce="c")
        first = issue_authorization(self.engine, raw)
        restarted = self.fixture.engine()
        self.assertEqual(issue_authorization(restarted, raw, now=NOW + 500), first)
        old = canonical_request(self.fixture.entry("b", sequence=2, epoch=2), nonce="d")
        with self.assertRaises(service.AuthorityError) as caught:
            issue_authorization(restarted, old, now=NOW + 500)
        self.assertEqual(caught.exception.code, "SEQUENCE_ROLLBACK")

    def test_concurrent_identical_issuance_commits_once(self) -> None:
        entry = self.fixture.entry("a", sequence=1, epoch=0)
        raw = canonical_request(entry, nonce="e")
        barrier = threading.Barrier(12)

        def issue_once() -> bytes:
            barrier.wait(timeout=5)
            return issue_authorization(self.engine, raw)

        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
            results = list(executor.map(lambda _index: issue_once(), range(12)))
        self.assertTrue(all(value == results[0] for value in results))
        self.assertEqual(self.engine.ledger.counts()["authorizations"], 1)

    def test_registry_is_closed_strict_and_cannot_enroll_caller_urls(self) -> None:
        duplicate_key = (
            b'{"apiVersion":"'
            + service.REGISTRY_API_VERSION.encode("ascii")
            + b'","apiVersion":"x","kind":"'
            + service.REGISTRY_KIND.encode("ascii")
            + b'","releases":[]}'
        )
        with self.assertRaises(service.AuthorityConfigurationError):
            service.ReleaseRegistry.from_bytes(duplicate_key)

        with self.assertRaisesRegex(
            service.AuthorityConfigurationError, "canonical compact"
        ):
            service.ReleaseRegistry.from_bytes(
                json.dumps(self.fixture.registry_document, indent=2).encode("ascii")
            )

        invalid_generation = deepcopy(self.fixture.registry_document)
        invalid_generation["generation"] = 0
        with self.assertRaisesRegex(
            service.AuthorityConfigurationError, "positive safe integer"
        ):
            service.ReleaseRegistry.from_bytes(
                protocol.canonical_json_bytes(invalid_generation)
            )

        open_registry = deepcopy(self.fixture.registry_document)
        open_registry["releaseRegistryUrl"] = "https://caller.invalid/releases"
        with self.assertRaises(service.AuthorityConfigurationError):
            service.ReleaseRegistry.from_bytes(
                protocol.canonical_json_bytes(open_registry)
            )

        open_entry = deepcopy(self.fixture.registry_document)
        open_entry["releases"][0]["provenanceUrl"] = "https://caller.invalid/provenance"
        with self.assertRaises(service.AuthorityConfigurationError):
            service.ReleaseRegistry.from_bytes(
                protocol.canonical_json_bytes(open_entry)
            )

        duplicate_entry = deepcopy(self.fixture.registry_document)
        duplicate_entry["releases"].append(deepcopy(duplicate_entry["releases"][0]))
        with self.assertRaises(service.AuthorityConfigurationError):
            service.ReleaseRegistry.from_bytes(
                protocol.canonical_json_bytes(duplicate_entry)
            )

        missing_certificate_binding = deepcopy(self.fixture.registry_document)
        del missing_certificate_binding["releases"][0]["relayClientCertificateSha256"]
        with self.assertRaises(service.AuthorityConfigurationError):
            service.ReleaseRegistry.from_bytes(
                protocol.canonical_json_bytes(missing_certificate_binding)
            )

        invalid_certificate_binding = deepcopy(self.fixture.registry_document)
        invalid_certificate_binding["releases"][0]["relayClientCertificateSha256"] = (
            "SHA256:invalid"
        )
        with self.assertRaisesRegex(
            service.AuthorityConfigurationError, "relay client certificate digest"
        ):
            service.ReleaseRegistry.from_bytes(
                protocol.canonical_json_bytes(invalid_certificate_binding)
            )

    def test_private_key_requires_matching_owner_only_regular_pkcs8(self) -> None:
        valid = service.load_authority_signing_key(
            self.fixture.authority_key_path,
            expected_key_id=self.fixture.authority_key_id,
        )
        self.assertEqual(valid.key_id, self.fixture.authority_key_id)
        with self.assertRaisesRegex(
            service.AuthorityConfigurationError, "configured key ID"
        ):
            service.load_authority_signing_key(
                self.fixture.authority_key_path, expected_key_id=digest("0")
            )
        with self.assertRaisesRegex(
            service.AuthorityConfigurationError, "lowercase hex"
        ):
            service.load_authority_signing_key(
                self.fixture.authority_key_path, expected_key_id="not-a-key-id"
            )

        self.fixture.authority_key_path.chmod(0o644)
        with self.assertRaisesRegex(
            service.AuthorityConfigurationError, "0400 or 0600"
        ):
            service.load_authority_signing_key(
                self.fixture.authority_key_path,
                expected_key_id=self.fixture.authority_key_id,
            )
        self.fixture.authority_key_path.chmod(0o600)

        symlink = self.root / "authority-key-link.pem"
        symlink.symlink_to(self.fixture.authority_key_path)
        with self.assertRaisesRegex(service.AuthorityConfigurationError, "non-symlink"):
            service.load_authority_signing_key(
                symlink, expected_key_id=self.fixture.authority_key_id
            )

        ec_key = ec.generate_private_key(ec.SECP256R1())
        wrong_algorithm = write_bytes(
            self.root / "ec-key.pem",
            ec_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            0o600,
        )
        with self.assertRaisesRegex(service.AuthorityConfigurationError, "Ed25519"):
            service.load_authority_signing_key(
                wrong_algorithm, expected_key_id=self.fixture.authority_key_id
            )

        noncanonical = write_bytes(
            self.root / "noncanonical-key.pem",
            self.fixture.authority_key_path.read_bytes() + b"\n",
            0o600,
        )
        with self.assertRaisesRegex(service.AuthorityConfigurationError, "canonical"):
            service.load_authority_signing_key(
                noncanonical, expected_key_id=self.fixture.authority_key_id
            )


class HTTPSAndRelayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.pki = TestPKI(self.root)
        self.client_certificate_sha256 = self.pki.certificate_sha256(
            self.pki.client_certificate
        )
        self.fixture = AuthorityFixture(
            self.root,
            relay_certificate_sha256=self.client_certificate_sha256,
        )
        self.engine = self.fixture.engine()
        self.entry = self.fixture.entry("a", sequence=1, epoch=0)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def relay_configuration(
        self, port: int, *, timeout: float = 2.0
    ) -> relay.RelayConfiguration:
        return relay.RelayConfiguration(
            authority_url=f"https://localhost:{port}{relay.AUTHORIZATION_PATH}",
            server_name="localhost",
            ca_certificate=self.pki.ca_path,
            client_certificate=self.pki.client_certificate_path,
            client_private_key=self.pki.client_key_path,
            timeout_seconds=timeout,
        )

    def test_https_endpoint_requires_mtls_and_exact_canonical_post(self) -> None:
        raw = canonical_request(self.entry, nonce="1")
        with RunningServer(authority_server(self.engine, self.pki)) as running:
            status, headers, body = https_request(
                running.port, self.pki.client_context(), body=raw
            )
            self.assertEqual(status, 200)
            self.assertEqual(
                [value for name, value in headers if name.lower() == "content-type"],
                [service.RESPONSE_CONTENT_TYPE],
            )
            self.assertEqual(protocol.canonical_json_bytes(json.loads(body)), body)

            status, _headers, error = https_request(
                running.port,
                self.pki.client_context(alternate_certificate=True),
                body=canonical_request(self.entry, nonce="9"),
            )
            self.assertEqual(status, 403)
            self.assertEqual(
                json.loads(error)["code"],
                "RELAY_CLIENT_CERTIFICATE_MISMATCH",
            )

            status, _headers, error = https_request(
                running.port,
                self.pki.client_context(),
                body=json.dumps(json.loads(raw), indent=2).encode("ascii"),
            )
            self.assertEqual(status, 400)
            self.assertEqual(json.loads(error)["code"], "INVALID_REQUEST")

            status, _headers, error = https_request(
                running.port,
                self.pki.client_context(),
                body=canonical_request(self.entry, nonce="2"),
                content_type="application/json",
            )
            self.assertEqual(status, 415)
            self.assertEqual(json.loads(error)["code"], "CONTENT_TYPE_INVALID")

            status, headers, _error = https_request(
                running.port,
                self.pki.client_context(),
                body=b"",
                method="GET",
            )
            self.assertEqual(status, 405)
            self.assertFalse(any(name.lower() == "location" for name, _ in headers))

            with self.assertRaises((ssl.SSLError, OSError, http.client.HTTPException)):
                https_request(
                    running.port,
                    self.pki.client_context(include_certificate=False),
                    body=canonical_request(self.entry, nonce="3"),
                )
            with self.assertRaises((ssl.SSLError, OSError, http.client.HTTPException)):
                https_request(
                    running.port,
                    self.pki.client_context(ca_path=self.pki.other_ca_path),
                    body=canonical_request(self.entry, nonce="4"),
                )

    def test_partial_tls_uses_handshake_capacity_not_issuance_capacity(self) -> None:
        server = authority_server(
            self.engine,
            self.pki,
            max_handshakes=2,
            max_handshakes_per_ip=2,
            max_issuance_workers=1,
            max_issuance_workers_per_ip=1,
            handshake_deadline_seconds=0.2,
            connection_deadline_seconds=0.5,
        )
        with RunningServer(server) as running:
            partial_tls = socket.create_connection(("127.0.0.1", running.port))
            partial_tls.sendall(b"\x16\x03")
            worker_deadline = time.monotonic() + 1
            while server.active_handshakes != 1:
                self.assertLess(time.monotonic(), worker_deadline)
                time.sleep(0.005)
            self.assertEqual(server.active_issuance_workers, 0)

            status, _headers, _body = https_request(
                running.port,
                self.pki.client_context(),
                body=canonical_request(self.entry, nonce="a"),
                timeout=0.5,
            )
            self.assertEqual(status, 200)
            self.assertEqual(server.peak_issuance_workers, 1)
            self.assertGreaterEqual(server.peak_handshakes, 1)
            time.sleep(0.25)
            partial_tls.close()
            self.assertEqual(server.active_handshakes, 0)
            self.assertEqual(server.active_issuance_workers, 0)

    def test_source_allowlist_precedes_slots_and_is_required_at_startup(self) -> None:
        for invalid in (
            (),
            ("127.0.0.1/24",),
            ("127.0.0.1/32", "127.0.0.1/32"),
            ("127.0.0.1",),
        ):
            with (
                self.subTest(cidrs=invalid),
                self.assertRaises(service.AuthorityConfigurationError),
            ):
                authority_server(
                    self.engine,
                    self.pki,
                    allowed_source_cidrs=invalid,
                )

        server = authority_server(
            self.engine,
            self.pki,
            allowed_source_cidrs=("127.0.0.1/32", "::1/128"),
            max_handshakes=1,
            max_handshakes_per_ip=1,
            max_issuance_workers=1,
            max_issuance_workers_per_ip=1,
        )
        client, rejected = socket.socketpair()
        try:
            server.process_request(rejected, ("192.0.2.1", 12345))
            self.assertEqual(server.rejected_source_count, 1)
            self.assertEqual(server.active_handshakes, 0)
            self.assertEqual(server.active_issuance_workers, 0)
        finally:
            client.close()
            rejected.close()
            server.server_close()
        self.assertIn(
            "upstream firewall/routing policy", service.NETWORK_ADMISSION_BOUNDARY
        )

    def test_per_ip_handshake_limit_rejects_excess_partial_tls(self) -> None:
        server = authority_server(
            self.engine,
            self.pki,
            max_handshakes=2,
            max_handshakes_per_ip=1,
            max_issuance_workers=1,
            max_issuance_workers_per_ip=1,
            handshake_deadline_seconds=0.2,
            connection_deadline_seconds=0.5,
        )
        with RunningServer(server) as running:
            first = socket.create_connection(("127.0.0.1", running.port))
            first.sendall(b"\x16\x03")
            worker_deadline = time.monotonic() + 1
            while server.active_handshakes != 1:
                self.assertLess(time.monotonic(), worker_deadline)
                time.sleep(0.005)
            second = socket.create_connection(("127.0.0.1", running.port))
            second.sendall(b"\x16\x03")
            second.settimeout(0.5)
            with self.assertRaises(OSError):
                if second.recv(1) == b"":
                    raise OSError("excess per-IP handshake was closed")
            self.assertEqual(server.active_handshakes, 1)
            self.assertEqual(server.active_issuance_workers, 0)
            first.close()
            second.close()
            time.sleep(0.25)
            self.assertEqual(server.active_handshakes, 0)

    def test_authority_absolute_deadline_covers_headers_body_and_response(
        self,
    ) -> None:
        server = authority_server(
            self.engine,
            self.pki,
            max_issuance_workers=1,
            max_issuance_workers_per_ip=1,
            handshake_deadline_seconds=0.2,
            connection_deadline_seconds=0.25,
        )
        with RunningServer(server) as running:
            tls_socket = self.pki.client_context().wrap_socket(
                socket.create_connection(("127.0.0.1", running.port)),
                server_hostname="localhost",
            )
            partial_body = canonical_request(self.entry, nonce="c")
            headers = (
                f"POST {service.AUTHORIZATION_PATH} HTTP/1.1\r\n"
                f"Host: localhost\r\n"
                f"Content-Type: {service.REQUEST_CONTENT_TYPE}\r\n"
                f"Content-Length: {len(partial_body)}\r\n\r\n"
            ).encode("ascii")
            tls_socket.sendall(headers + partial_body[:1])
            with self.assertRaises((ssl.SSLError, OSError, http.client.HTTPException)):
                https_request(
                    running.port,
                    self.pki.client_context(),
                    body=canonical_request(self.entry, nonce="f"),
                    timeout=0.5,
                )
            time.sleep(0.3)
            tls_socket.settimeout(0.2)
            with self.assertRaises((OSError, ssl.SSLError)):
                if tls_socket.recv(1) == b"":
                    raise OSError("authority closed the expired connection")
            tls_socket.close()

            original_issue = self.engine.issue

            def slow_issue(*args: Any, **kwargs: Any) -> bytes:
                time.sleep(0.3)
                return original_issue(*args, **kwargs)

            with mock.patch.object(self.engine, "issue", side_effect=slow_issue):
                with self.assertRaises(
                    (ssl.SSLError, OSError, http.client.HTTPException)
                ):
                    https_request(
                        running.port,
                        self.pki.client_context(),
                        body=canonical_request(self.entry, nonce="d"),
                        timeout=1,
                    )
            worker_deadline = time.monotonic() + 1
            while server.active_issuance_workers:
                self.assertLess(time.monotonic(), worker_deadline)
                time.sleep(0.01)
            self.assertEqual(server.peak_issuance_workers, 1)

    def test_relay_forwards_exact_bytes_over_tls13_mtls(self) -> None:
        raw = canonical_request(self.entry, nonce="5")
        with RunningServer(authority_server(self.engine, self.pki)) as running:
            configuration = self.relay_configuration(running.port)
            with mock.patch.object(
                relay.socket,
                "getaddrinfo",
                side_effect=AssertionError("per-launch DNS resolution is forbidden"),
            ):
                response = relay.forward_authorization_request(raw, configuration)
        self.assertEqual(
            response,
            issue_authorization(
                self.engine,
                raw,
                peer_certificate_sha256=self.pki.certificate_sha256(
                    self.pki.client_certificate
                ),
            ),
        )
        protocol.validate_launch_authorization(
            protocol.require_canonical_json_bytes(response)
        )

    def test_relay_rejects_redirect_status_content_type_and_noncanonical_response(
        self,
    ) -> None:
        raw = canonical_request(self.entry, nonce="6")
        valid_response = issue_authorization(
            self.engine,
            raw,
            peer_certificate_sha256=self.pki.certificate_sha256(
                self.pki.client_certificate
            ),
        )
        cases = (
            (302, relay.RESPONSE_CONTENT_TYPE, valid_response, "REMOTE_STATUS_INVALID"),
            (503, relay.RESPONSE_CONTENT_TYPE, valid_response, "REMOTE_STATUS_INVALID"),
            (
                200,
                "application/octet-stream",
                valid_response,
                "REMOTE_CONTENT_TYPE_INVALID",
            ),
            (
                200,
                relay.RESPONSE_CONTENT_TYPE,
                json.dumps(json.loads(valid_response), indent=2).encode("ascii"),
                "REMOTE_RESPONSE_INVALID",
            ),
        )
        for status, content_type, body, code in cases:
            with (
                self.subTest(status=status, content_type=content_type),
                ScriptedAuthorityServer(
                    self.pki, status=status, content_type=content_type, body=body
                ) as scripted,
            ):
                with self.assertRaises(relay.RelayError) as caught:
                    relay.forward_authorization_request(
                        raw, self.relay_configuration(scripted.port)
                    )
                self.assertEqual(caught.exception.code, code)

    def test_relay_preserves_request_and_response_bytes_and_enforces_timeout(
        self,
    ) -> None:
        raw = canonical_request(self.entry, nonce="7")
        response = issue_authorization(
            self.engine,
            raw,
            peer_certificate_sha256=self.pki.certificate_sha256(
                self.pki.client_certificate
            ),
        )
        with ScriptedAuthorityServer(self.pki, body=response) as scripted:
            returned = relay.forward_authorization_request(
                raw, self.relay_configuration(scripted.port)
            )
            self.assertEqual(scripted.received, [raw])
            self.assertEqual(returned, response)

        with ScriptedAuthorityServer(
            self.pki, body=response, delay_seconds=0.25
        ) as scripted:
            with self.assertRaises(relay.RelayError) as caught:
                relay.forward_authorization_request(
                    raw, self.relay_configuration(scripted.port, timeout=0.05)
                )
            self.assertEqual(caught.exception.code, "REMOTE_DEADLINE_EXCEEDED")

        with ScriptedAuthorityServer(
            self.pki,
            body=response,
            body_chunk_delay_seconds=0.02,
            body_chunk_size=32,
        ) as scripted:
            started = time.monotonic()
            with self.assertRaises(relay.RelayError) as caught:
                relay.forward_authorization_request(
                    raw, self.relay_configuration(scripted.port, timeout=0.1)
                )
            self.assertEqual(caught.exception.code, "REMOTE_DEADLINE_EXCEEDED")
            self.assertLess(time.monotonic() - started, 0.3)

    def test_relay_configuration_has_pinned_https_identity_and_secure_client_key(
        self,
    ) -> None:
        with self.assertRaises(relay.RelayConfigurationError):
            relay.RelayConfiguration(
                authority_url=f"http://localhost:443{relay.AUTHORIZATION_PATH}",
                server_name="localhost",
                ca_certificate=self.pki.ca_path,
                client_certificate=self.pki.client_certificate_path,
                client_private_key=self.pki.client_key_path,
            )
        with self.assertRaisesRegex(relay.RelayConfigurationError, "exactly match"):
            relay.RelayConfiguration(
                authority_url=f"https://localhost:443{relay.AUTHORIZATION_PATH}",
                server_name="authority.example",
                ca_certificate=self.pki.ca_path,
                client_certificate=self.pki.client_certificate_path,
                client_private_key=self.pki.client_key_path,
            )
        self.pki.client_key_path.chmod(0o644)
        with self.assertRaisesRegex(relay.RelayConfigurationError, "0400 or 0600"):
            self.relay_configuration(443)

    def test_tls_material_rejects_untrusted_or_symlinked_ancestors(self) -> None:
        real_directory = self.root / "real-tls"
        real_directory.mkdir(mode=0o700)
        copied_ca = real_directory / "ca.pem"
        copied_server_certificate = real_directory / "server.pem"
        shutil.copy2(self.pki.ca_path, copied_ca)
        shutil.copy2(self.pki.server_certificate_path, copied_server_certificate)
        alias = self.root / "tls-alias"
        alias.symlink_to(real_directory, target_is_directory=True)

        with self.assertRaisesRegex(
            relay.RelayConfigurationError, "ancestor must be a real directory"
        ):
            relay.RelayConfiguration(
                authority_url=(f"https://localhost:443{relay.AUTHORIZATION_PATH}"),
                server_name="localhost",
                ca_certificate=alias / "ca.pem",
                client_certificate=self.pki.client_certificate_path,
                client_private_key=self.pki.client_key_path,
            )
        with self.assertRaisesRegex(
            service.AuthorityConfigurationError,
            "ancestor must be a real directory",
        ):
            service.create_https_server(
                ("127.0.0.1", 0),
                authority=self.engine,
                server_certificate=alias / "server.pem",
                server_private_key=self.pki.server_key_path,
                client_ca_certificate=self.pki.ca_path,
                allowed_source_cidrs=("127.0.0.1/32",),
            )

        writable_directory = self.root / "writable-tls"
        writable_directory.mkdir(mode=0o700)
        writable_directory.chmod(0o777)
        writable_ca = writable_directory / "ca.pem"
        shutil.copy2(self.pki.ca_path, writable_ca)
        with self.assertRaisesRegex(
            relay.RelayConfigurationError, "ancestor is not trusted"
        ):
            relay.RelayConfiguration(
                authority_url=(f"https://localhost:443{relay.AUTHORIZATION_PATH}"),
                server_name="localhost",
                ca_certificate=writable_ca,
                client_certificate=self.pki.client_certificate_path,
                client_private_key=self.pki.client_key_path,
            )

    def test_tls_material_is_stable_across_python_ssl_path_loads(self) -> None:
        service_reader = service._read_stable_regular_file
        service_certificate_reads = 0

        def unstable_service_reader(*args: Any, **kwargs: Any) -> bytes:
            nonlocal service_certificate_reads
            value = service_reader(*args, **kwargs)
            if kwargs["label"] == "authority TLS server certificate":
                service_certificate_reads += 1
                if service_certificate_reads == 2:
                    return value + b"\n"
            return value

        with (
            mock.patch.object(
                service,
                "_read_stable_regular_file",
                side_effect=unstable_service_reader,
            ),
            self.assertRaisesRegex(
                service.AuthorityConfigurationError,
                "changed while the TLS context was created",
            ),
        ):
            service.create_https_server(
                ("127.0.0.1", 0),
                authority=self.engine,
                server_certificate=self.pki.server_certificate_path,
                server_private_key=self.pki.server_key_path,
                client_ca_certificate=self.pki.ca_path,
                allowed_source_cidrs=("127.0.0.1/32",),
            )

        configuration = self.relay_configuration(443)
        relay_reader = relay._read_stable_regular_file
        relay_ca_reads = 0

        def unstable_relay_reader(*args: Any, **kwargs: Any) -> bytes:
            nonlocal relay_ca_reads
            value = relay_reader(*args, **kwargs)
            if kwargs["label"] == "authority CA certificate":
                relay_ca_reads += 1
                if relay_ca_reads == 2:
                    return value + b"\n"
            return value

        with (
            mock.patch.object(
                relay,
                "_read_stable_regular_file",
                side_effect=unstable_relay_reader,
            ),
            self.assertRaisesRegex(
                relay.RelayConfigurationError,
                "changed while the TLS context was created",
            ),
        ):
            configuration.tls_context()

    def test_seqpacket_framing_size_and_single_packet_byte_preservation(self) -> None:
        packet_type = getattr(socket, "SOCK_SEQPACKET", socket.SOCK_DGRAM)
        try:
            probe = socket.socketpair(socket.AF_UNIX, packet_type)
        except OSError:
            packet_type = socket.SOCK_DGRAM
            probe = socket.socketpair(socket.AF_UNIX, packet_type)
        probe[0].close()
        probe[1].close()
        configuration = self.relay_configuration(443)
        raw = canonical_request(self.entry, nonce="8")
        response = issue_authorization(
            self.engine,
            raw,
            peer_certificate_sha256=self.pki.certificate_sha256(
                self.pki.client_certificate
            ),
        )
        client, server = socket.socketpair(socket.AF_UNIX, packet_type)
        try:
            worker_error: list[BaseException] = []

            def worker() -> None:
                try:
                    relay.serve_connection(
                        server,
                        configuration,
                        forwarder=lambda value, _configuration: (
                            response if value == raw else b""
                        ),
                        enforce_root_peer=False,
                    )
                except BaseException as exc:
                    worker_error.append(exc)

            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            self.assertEqual(client.send(raw), len(raw))
            self.assertEqual(client.recv(relay.MAX_PACKET_BYTES), response)
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(worker_error, [])
        finally:
            client.close()
            server.close()

    def test_relay_worker_pool_is_concurrent_and_strictly_bounded(self) -> None:
        packet_type = getattr(socket, "SOCK_SEQPACKET", socket.SOCK_DGRAM)
        try:
            probe = socket.socketpair(socket.AF_UNIX, packet_type)
        except OSError:
            packet_type = socket.SOCK_DGRAM
            probe = socket.socketpair(socket.AF_UNIX, packet_type)
        probe[0].close()
        probe[1].close()

        raw = canonical_request(self.entry, nonce="e")
        response = issue_authorization(
            self.engine,
            raw,
            peer_certificate_sha256=self.client_certificate_sha256,
        )
        pool = relay.BoundedRelayWorkerPool(max_workers=2)
        entered = threading.Barrier(3)
        release = threading.Event()

        def blocking_forwarder(
            value: bytes, _configuration: relay.RelayConfiguration
        ) -> bytes:
            self.assertEqual(value, raw)
            entered.wait(timeout=2)
            self.assertTrue(release.wait(timeout=2))
            return response

        pairs = [socket.socketpair(socket.AF_UNIX, packet_type) for _index in range(3)]
        try:
            configuration = self.relay_configuration(443)
            for client, server_socket in pairs[:2]:
                self.assertTrue(
                    pool.submit(
                        server_socket,
                        configuration,
                        forwarder=blocking_forwarder,
                        enforce_root_peer=False,
                    )
                )
                self.assertEqual(client.send(raw), len(raw))
            entered.wait(timeout=2)
            self.assertEqual(pool.active_workers, 2)
            self.assertEqual(pool.peak_workers, 2)
            self.assertFalse(
                pool.submit(
                    pairs[2][1],
                    configuration,
                    forwarder=blocking_forwarder,
                    enforce_root_peer=False,
                )
            )
            release.set()
            for client, _server_socket in pairs[:2]:
                self.assertEqual(client.recv(relay.MAX_PACKET_BYTES), response)
            self.assertTrue(pool.wait_for_idle(2))
            self.assertEqual(pool.peak_workers, 2)
        finally:
            release.set()
            for client, server_socket in pairs:
                client.close()
                server_socket.close()

        class OversizedPacket:
            def recvmsg(self, _size: int) -> tuple[bytes, list[Any], int, None]:
                return b"x" * (relay.MAX_PACKET_BYTES + 1), [], 0, None

        with self.assertRaises(relay.RelayError) as caught:
            relay.receive_packet(OversizedPacket())  # type: ignore[arg-type]
        self.assertEqual(caught.exception.code, "FRAME_INVALID")

        client, server = socket.socketpair(socket.AF_UNIX, packet_type)
        try:
            server.settimeout(0.03)
            with self.assertRaises(relay.RelayError) as caught:
                relay.receive_packet(server)
            self.assertEqual(caught.exception.code, "LOCAL_RECEIVE_FAILED")
        finally:
            client.close()
            server.close()

    def test_systemd_units_pin_root_seqpacket_and_harden_relay(self) -> None:
        socket_unit = (
            ROOT / "ops/systemd/serverware-launch-authority-relay.socket"
        ).read_text(encoding="utf-8")
        service_unit = (
            ROOT / "ops/systemd/serverware-launch-authority-relay.service"
        ).read_text(encoding="utf-8")
        for expected in (
            "ListenSequentialPacket=/run/serverware/launch-authority.sock",
            "SocketMode=0600",
            "SocketUser=root",
            "SocketGroup=root",
            "DirectoryMode=0711",
        ):
            self.assertIn(expected, socket_unit)
        for expected in (
            "User=serverware-launch-authority-relay",
            "Group=serverware-launch-authority-relay",
            "UMask=0077",
            "EnvironmentFile=/etc/serverware/launch-authority-relay.env",
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateDevices=yes",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "MemoryDenyWriteExecute=yes",
            "/usr/bin/python3 -I ",
            "client private key must be owned by this account with mode 0400 or 0600",
            "SO_PEERCRED",
            "TimeoutStartSec=10s",
        ):
            self.assertIn(expected, service_unit)
        self.assertNotIn("User=root", service_unit)
        self.assertNotIn("Group=root", service_unit)
        self.assertNotIn("/bin/sh", service_unit)
        self.assertNotIn("authority-public-key", service_unit)
        self.assertNotIn("authority-signing-key", service_unit)
        self.assertNotIn("SSL_CERT_FILE=", service_unit)

    def test_entry_points_resolve_protocol_sibling_under_isolated_python(self) -> None:
        for relative_path in (
            "scripts/launch_authority_service.py",
            "scripts/launch_authority_relay.py",
        ):
            result = subprocess.run(
                [sys.executable, "-I", str(ROOT / relative_path), "--help"],
                cwd=self.root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
                check=False,
            )
            with self.subTest(path=relative_path):
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("usage:", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
