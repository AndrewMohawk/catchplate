#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.oauth_provider_simulator import OAuthProviderSimulator  # noqa: E402


ADMIN_TOKEN = "browser-oauth-admin-token"
CREDENTIAL_LEASE_TOKEN = "browser-oauth-credential-lease-token"
AUDIT_TOKEN = "browser-oauth-audit-ingest-token"
GRANT_CONSUME_TOKEN = "browser-oauth-grant-consume-token"
RATE_LIMIT_CONSUME_TOKEN = "browser-oauth-rate-limit-consume-token"
RELEASE_AUTHORIZATION_TOKEN = "browser-oauth-release-authorization-token"
MANAGEMENT_TOKEN = "browser-oauth-management-token"
GOOGLE_NAME = "Browser Gmail OAuth"
X_NAME = "Browser X OAuth"
X_JIT_ROUTE_ID = "browser.x.post.one-per-day.jit"
NPM_JIT_ROUTE_ID = "browser.npm.common-writes.jit"
NPM_CREDENTIAL_ID = "cred-demo-bearer"
NPM_PACKAGE_NAME = "@scope/serverware-browser"
NPM_PACKAGE_PATH = "@scope%2fserverware-browser"
NPM_PACKAGE_VERSION = "1.2.3"
NPM_REMAINING_VERSION = "1.2.2"
NPM_REVISION = "42-deadbeef"
NPM_TOKEN_KEY = "token-key-browser-001"
NPM_FIXTURE_BEARER = "demo-token-from-vault"
GOOGLE_SCOPES = [
    "openid",
    "email",
    "https://www.googleapis.com/auth/gmail.readonly",
]
X_SCOPES = ["tweet.read", "tweet.write", "users.read", "offline.access"]
OAUTH_COOKIE_PREFIX = "__Host-serverware-oauth-"
DEFAULT_TIMEOUT_MS = 20_000
MAX_EVIDENCE_FILE_BYTES = 32 * 1024 * 1024


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _reserve_https_socket() -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    listener.set_inheritable(False)
    return listener


def _reserve_loopback_port() -> int:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])
    finally:
        listener.close()


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _write_mitm_ca(work_dir: Path) -> tuple[Path, Path]:
    work_dir.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Serverware browser Rust gate CA")]
    )
    now = dt.datetime.now(dt.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
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
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = work_dir / "decision-gate-mitm-ca.pem"
    key_path = work_dir / "decision-gate-mitm-ca-key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.chmod(0o644)
    key_path.chmod(0o600)
    return cert_path, key_path


def _configure_environment(
    data_dir: Path,
    public_url: str,
    simulator: OAuthProviderSimulator,
    data_plane_digest: str,
) -> None:
    service_tokens = {
        CREDENTIAL_LEASE_TOKEN,
        AUDIT_TOKEN,
        GRANT_CONSUME_TOKEN,
        RATE_LIMIT_CONSUME_TOKEN,
        RELEASE_AUTHORIZATION_TOKEN,
        MANAGEMENT_TOKEN,
    }
    _require(len(service_tokens) == 6, "data-plane service tokens must be distinct")
    values = {
        "SERVERWARE_DATA_DIR": str(data_dir),
        "SERVERWARE_RELEASE_CHANNEL": "dev",
        "SERVERWARE_PUBLIC_URL": public_url,
        "SERVERWARE_WEB_TLS_CERT_FILE": str(simulator.server_cert_path),
        "SERVERWARE_WEB_TLS_KEY_FILE": str(simulator.server_key_path),
        "SERVERWARE_ADMIN_TOKEN": ADMIN_TOKEN,
        "SERVERWARE_ADMIN_USER": "user:demo",
        "SERVERWARE_ADMIN_ROLES": (
            "admin,approver,auditor,policy_author,policy_publisher,credential_owner,"
            "attestation_operator,attestation_reviewer"
        ),
        "SERVERWARE_DEV_AUTHENTICATOR": "1",
        "SERVERWARE_KEY_RELEASE_REQUIRED": "0",
        "SERVERWARE_METADATA_STORE_BACKEND": "sqlite",
        "SERVERWARE_AUDIT_STORE_BACKEND": "sqlite",
        "SERVERWARE_GRANT_STORE_BACKEND": "sqlite",
        "SERVERWARE_OIDC_ENABLED": "0",
        "SERVERWARE_OIDC_BROWSER_LOGIN_ENABLED": "0",
        "SERVERWARE_CONTROL_PLANE_TWO_PERSON_REQUIRED": "1",
        "SERVERWARE_CONTROL_PLANE_TWO_PERSON_ACTIONS": "credential.oauth.activate",
        "SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED": "0",
        "SERVERWARE_CONTROL_PLANE_MUTATION_REQUIRE_HARDWARE_ATTESTATION": "0",
        "SERVERWARE_POLICY_PUBLISH_DRY_RUN_REQUIRED": "1",
        "SERVERWARE_POLICY_CANARY_REQUIRED": "0",
        "SERVERWARE_POLICY_CANARY_MIN_OBSERVATION_SECONDS": "0",
        "SERVERWARE_POLICY_CANARY_MIN_AUDIT_EVENTS": "0",
        "SERVERWARE_POLICY_CANARY_MAX_DENIALS": "0",
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_ID": simulator.GOOGLE_CLIENT_ID,
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET": simulator.GOOGLE_CLIENT_SECRET,
        "SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI": f"{public_url}/api/oauth/callback/google",
        "SERVERWARE_X_OAUTH_CLIENT_ID": simulator.X_CLIENT_ID,
        "SERVERWARE_X_OAUTH_CLIENT_SECRET": simulator.X_CLIENT_SECRET,
        "SERVERWARE_X_OAUTH_REDIRECT_URI": f"{public_url}/api/oauth/callback/x",
        "SERVERWARE_WEBAUTHN_RP_ID": "serverware.test",
        "SERVERWARE_WEBAUTHN_ORIGIN": public_url,
        "SERVERWARE_DATA_PLANE_INSTANCE_ID": (
            "spiffe://test.serverware/decision-gate/browser-oauth"
        ),
        "SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN": CREDENTIAL_LEASE_TOKEN,
        "SERVERWARE_DATA_PLANE_AUDIT_TOKEN": AUDIT_TOKEN,
        "SERVERWARE_DATA_PLANE_GRANT_CONSUME_TOKEN": GRANT_CONSUME_TOKEN,
        "SERVERWARE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN": RATE_LIMIT_CONSUME_TOKEN,
        "SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN": (
            RELEASE_AUTHORIZATION_TOKEN
        ),
        "SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN": MANAGEMENT_TOKEN,
        "SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "1",
        "SERVERWARE_RELEASE_AUTHORIZATION_RESERVATION_TTL_SECONDS": "30",
        "SERVERWARE_RELEASE_AUTHORIZATION_DISPATCH_TTL_SECONDS": "30",
        "SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST": data_plane_digest,
        "SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED": "0",
        "SERVERWARE_AUDIT_ANCHOR_URL": "",
        "SERVERWARE_DECISION_GATE_BASE": "",
        "SSL_CERT_FILE": str(simulator.ca_cert_path),
        "NO_PROXY": "serverware.test,127.0.0.1,localhost",
        "no_proxy": "serverware.test,127.0.0.1,localhost",
    }
    for name in (
        "SERVERWARE_METADATA_STORE_POSTGRES_DSN",
        "SERVERWARE_AUDIT_STORE_POSTGRES_DSN",
        "SERVERWARE_GRANT_STORE_POSTGRES_DSN",
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE",
        "SERVERWARE_X_OAUTH_CLIENT_SECRET_FILE",
        "SERVERWARE_TWITTER_OAUTH_CLIENT_ID",
        "SERVERWARE_TWITTER_OAUTH_CLIENT_SECRET",
        "SERVERWARE_TWITTER_OAUTH_REDIRECT_URI",
    ):
        os.environ.pop(name, None)
    os.environ.update(values)


class _DecisionGateProcess:
    def __init__(
        self,
        *,
        binary: Path,
        response_proof_fixture: Path,
        data_dir: Path,
        portal_url: str,
        simulator: OAuthProviderSimulator,
    ) -> None:
        self.binary = binary
        self.response_proof_fixture = response_proof_fixture
        self.data_dir = data_dir
        self.portal_url = portal_url.replace("serverware.test", "127.0.0.1")
        self.simulator = simulator
        self.proxy_port = _reserve_loopback_port()
        self.management_port = _reserve_loopback_port()
        self.ca_cert_path, self.ca_key_path = _write_mitm_ca(
            data_dir / "browser-rust-gate"
        )
        self.log_path = data_dir / "browser-rust-gate.log"
        self._log_handle: Any = None
        self._process: subprocess.Popen[bytes] | None = None

    @property
    def health_url(self) -> str:
        return f"http://127.0.0.1:{self.management_port}/healthz"

    def start(self) -> None:
        _require(self.binary.is_file(), f"decision gate binary is missing: {self.binary}")
        _require(
            os.access(self.binary, os.X_OK),
            f"decision gate binary is not executable: {self.binary}",
        )
        _require(
            self.response_proof_fixture.is_file(),
            f"response proof fixture is missing: {self.response_proof_fixture}",
        )
        _require(
            os.access(self.response_proof_fixture, os.X_OK),
            f"response proof fixture is not executable: {self.response_proof_fixture}",
        )
        env = os.environ.copy()
        env.update(
            {
                "SERVERWARE_POLICY_BUNDLE": str(self.data_dir / "policy-bundle.json"),
                "SERVERWARE_POLICY_TRUST_ROOT_ATTESTATION_URL": (
                    f"{self.portal_url}/attestation"
                ),
                "SERVERWARE_CONTROL_PLANE_CA_BUNDLE": str(
                    self.simulator.ca_cert_path
                ),
                "SERVERWARE_CONTROL_PLANE_CREDENTIAL_LEASE_URL": (
                    f"{self.portal_url}/api/data-plane/credential-leases"
                ),
                "SERVERWARE_CONTROL_PLANE_AUDIT_URL": (
                    f"{self.portal_url}/api/data-plane/audit"
                ),
                "SERVERWARE_CONTROL_PLANE_RELEASE_AUTHORIZATION_BASE_URL": (
                    f"{self.portal_url}/api/data-plane/release-authorizations"
                ),
                "SERVERWARE_ALLOW_INSECURE_DEV_CREDENTIAL_LEASES": "1",
                "SERVERWARE_RELEASE_CHANNEL": "dev",
                "SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "1",
                "SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN": (
                    CREDENTIAL_LEASE_TOKEN
                ),
                "SERVERWARE_DATA_PLANE_AUDIT_TOKEN": AUDIT_TOKEN,
                "SERVERWARE_DATA_PLANE_GRANT_CONSUME_TOKEN": GRANT_CONSUME_TOKEN,
                "SERVERWARE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN": (
                    RATE_LIMIT_CONSUME_TOKEN
                ),
                "SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN": (
                    RELEASE_AUTHORIZATION_TOKEN
                ),
                "SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN": MANAGEMENT_TOKEN,
                "SERVERWARE_DATA_PLANE_INSTANCE_ID": (
                    "spiffe://test.serverware/decision-gate/browser-oauth"
                ),
                "SERVERWARE_DATA_PLANE_RESPONSE_PROOF_ATTESTATION_COMMAND": str(
                    self.response_proof_fixture
                ),
                "SERVERWARE_MITM_CA_CERT": str(self.ca_cert_path),
                "SERVERWARE_MITM_CA_KEY": str(self.ca_key_path),
                "SERVERWARE_UPSTREAM_CA_BUNDLE": str(self.simulator.ca_cert_path),
                "SERVERWARE_POLICY_POLL_SECONDS": "0.05",
                "SERVERWARE_CREDENTIAL_LEASE_POLL_SECONDS": "0.05",
                "SERVERWARE_DECISION_GATE_HOST": "127.0.0.1",
                "SERVERWARE_DECISION_GATE_PORT": str(self.proxy_port),
                "SERVERWARE_DECISION_GATE_MANAGEMENT_HOST": "127.0.0.1",
                "SERVERWARE_DECISION_GATE_MANAGEMENT_PORT": str(
                    self.management_port
                ),
                "SSL_CERT_FILE": str(self.simulator.ca_cert_path),
                "NO_PROXY": "serverware.test,127.0.0.1,localhost",
                "no_proxy": "serverware.test,127.0.0.1,localhost",
            }
        )
        self._log_handle = self.log_path.open("wb")
        self._process = subprocess.Popen(
            [str(self.binary)],
            cwd=ROOT,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    def _failure_detail(self) -> str:
        if self._log_handle is not None:
            self._log_handle.flush()
        if not self.log_path.exists():
            return ""
        return self.log_path.read_text(encoding="utf-8", errors="replace")[-4000:]

    def wait_ready(
        self,
        *,
        policy_hash: str,
        binary_digest: str,
        require_hot_generation: bool = False,
        timeout_seconds: float = 30,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        last: Any = None
        while time.monotonic() < deadline:
            if self._process is None:
                raise AssertionError("decision gate was not started")
            if self._process.poll() is not None:
                raise AssertionError(
                    "decision gate exited before readiness: " + self._failure_detail()
                )
            try:
                request = Request(self.health_url, headers={"Cache-Control": "no-store"})
                with urlopen(request, timeout=2) as response:
                    last = json.loads(response.read(1024 * 1024))
            except Exception as exc:
                last = {"health_error": str(exc)}
                time.sleep(0.1)
                continue
            release = last.get("release_authorization") or {}
            audit = last.get("audit") or {}
            base_ready = (
                last.get("ok") is True
                and last.get("policy_hash") == policy_hash
                and last.get("data_plane_binary_digest") == binary_digest
                and last.get("policy_trust_root_source") == "attested-control-plane"
                and last.get("jit_grant_store") == "atomic_release_authorization"
                and last.get("shared_rate_limit_store") is True
                and release.get("enabled") is True
                and release.get("mode") == "reserve_dispatch_complete"
                and last.get("connect_preflight") is True
                and last.get("connect_mitm_interceptor") is True
                and audit.get("enabled") is True
                and audit.get("dropped") == 0
                and audit.get("required_failed") == 0
                and (last.get("policy_reload") or {}).get("failed") == 0
            )
            generation_ready = (
                last.get("credential_generations_ready") is True
                and (
                    not require_hot_generation
                    or (
                        int(last.get("credential_generation_hot_scopes") or 0) >= 1
                        and int(last.get("credential_generations") or 0) >= 1
                    )
                )
            )
            if base_ready and generation_ready:
                return last
            time.sleep(0.1)
        raise AssertionError(
            f"decision gate did not reach exact readiness: {last!r}; "
            f"log={self._failure_detail()}"
        )

    def close(self) -> None:
        process = self._process
        self._process = None
        try:
            if process is not None and process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
            if process is not None:
                _require(
                    process.poll() is not None,
                    "decision gate process remained alive after cleanup",
                )
        finally:
            if self._log_handle is not None:
                self._log_handle.close()
                self._log_handle = None


def _certificate_spki_sha256(cert_path: Path) -> str:
    certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    spki = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


def _assert_simulator_contract(simulator: OAuthProviderSimulator) -> None:
    _require(
        simulator.redirect_base_url.startswith("https://serverware.test:"),
        "simulator did not retain the configured HTTPS callback origin",
    )
    certificate = x509.load_pem_x509_certificate(
        simulator.server_cert_path.read_bytes()
    )
    san = certificate.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value
    dns_names = set(san.get_values_for_type(x509.DNSName))
    ip_addresses = {str(value) for value in san.get_values_for_type(x509.IPAddress)}
    _require(
        "serverware.test" in dns_names,
        "simulator certificate lacks serverware.test SAN",
    )
    _require("localhost" in dns_names, "simulator certificate lost its localhost SAN")
    _require(
        "127.0.0.1" in ip_addresses, "simulator certificate lost its loopback IP SAN"
    )


def _assert_redirect_validation(work_dir: Path) -> None:
    default = OAuthProviderSimulator(work_dir / "default-contract")
    _require(
        default.redirect_base_url == "https://serverware.test",
        "simulator default redirect origin changed",
    )
    invalid_origins = (
        "http://serverware.test",
        "https://serverware.test/path",
        "https://serverware.test?query=1",
        "https://user@serverware.test",
        "https://serverware.test#fragment",
        "https://serverware.test:70000",
        " https://serverware.test",
        "https://serverware.test.",
    )
    for index, origin in enumerate(invalid_origins):
        try:
            OAuthProviderSimulator(
                work_dir / f"invalid-{index}", redirect_base_url=origin
            )
        except ValueError:
            continue
        raise AssertionError(
            f"simulator accepted an unsafe redirect origin: {origin!r}"
        )


def _npm_publish_document() -> dict[str, Any]:
    tarball = b"serverware-browser-npm-fixture-v1"
    integrity = "sha512-" + base64.b64encode(
        hashlib.sha512(tarball).digest()
    ).decode("ascii")
    return {
        "_id": NPM_PACKAGE_NAME,
        "name": NPM_PACKAGE_NAME,
        "dist-tags": {"latest": NPM_PACKAGE_VERSION},
        "versions": {
            NPM_PACKAGE_VERSION: {
                "name": NPM_PACKAGE_NAME,
                "version": NPM_PACKAGE_VERSION,
                "dist": {"integrity": integrity},
            }
        },
        "_attachments": {
            f"serverware-browser-{NPM_PACKAGE_VERSION}.tgz": {
                "content_type": "application/octet-stream",
                "data": base64.b64encode(tarball).decode("ascii"),
                "length": len(tarball),
            }
        },
    }


def _npm_unpublish_document() -> dict[str, Any]:
    return {
        "_id": NPM_PACKAGE_NAME,
        "_rev": NPM_REVISION,
        "name": NPM_PACKAGE_NAME,
        "dist-tags": {"latest": NPM_REMAINING_VERSION},
        "versions": {
            NPM_REMAINING_VERSION: {
                "name": NPM_PACKAGE_NAME,
                "version": NPM_REMAINING_VERSION,
            }
        },
    }


def _npm_metadata_document() -> dict[str, Any]:
    return {
        "_id": NPM_PACKAGE_NAME,
        "_rev": NPM_REVISION,
        "name": NPM_PACKAGE_NAME,
        "dist-tags": {"latest": NPM_PACKAGE_VERSION},
        "versions": {
            NPM_PACKAGE_VERSION: {
                "name": NPM_PACKAGE_NAME,
                "version": NPM_PACKAGE_VERSION,
                "deprecated": "Use the supported replacement package",
            }
        },
    }


class _NpmRegistryFixture:
    def __init__(self, simulator: OAuthProviderSimulator) -> None:
        self._lock = threading.Lock()
        self._events: list[dict[str, Any]] = []
        self._counts = {
            "npm.publish": 0,
            "npm.unpublish": 0,
            "npm.distTagWrite": 0,
            "npm.tokenWrite": 0,
            "npm.metadataWrite": 0,
            "npm.tokenCreate": 0,
            "rejected": 0,
        }
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:  # noqa: N802
                fixture._handle(self)

            def do_POST(self) -> None:  # noqa: N802
                fixture._handle(self)

            def do_PUT(self) -> None:  # noqa: N802
                fixture._handle(self)

            def do_DELETE(self) -> None:  # noqa: N802
                fixture._handle(self)

            def log_message(self, _format: str, *_args: Any) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(
            certfile=str(simulator.server_cert_path),
            keyfile=str(simulator.server_key_path),
        )
        self._server.socket = context.wrap_socket(
            self._server.socket,
            server_side=True,
        )
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="serverware-browser-npm-registry",
            daemon=True,
        )
        self._started = False

    @staticmethod
    def _strict_body(handler: BaseHTTPRequestHandler) -> bytes:
        transfer_encoding = handler.headers.get("Transfer-Encoding")
        if transfer_encoding:
            raise ValueError("transfer_encoding_denied")
        raw_length = handler.headers.get("Content-Length")
        if raw_length is None:
            return b""
        if not raw_length.isdigit():
            raise ValueError("content_length_invalid")
        length = int(raw_length)
        if length > 16 * 1024 * 1024:
            raise ValueError("body_too_large")
        body = handler.rfile.read(length)
        if len(body) != length:
            raise ValueError("body_truncated")
        return body

    @staticmethod
    def _json_body(body: bytes) -> Any:
        if not body:
            return None
        return json.loads(body.decode("utf-8"))

    @staticmethod
    def _response_for(operation: str) -> dict[str, Any]:
        if operation == "npm.publish":
            return {
                "package": NPM_PACKAGE_NAME,
                "version": NPM_PACKAGE_VERSION,
                "published": True,
            }
        if operation == "npm.unpublish":
            return {
                "ok": True,
                "package": NPM_PACKAGE_NAME,
                "revision": NPM_REVISION,
                "unpublished": True,
            }
        if operation == "npm.distTagWrite":
            return {
                "ok": True,
                "package": NPM_PACKAGE_NAME,
                "version": NPM_PACKAGE_VERSION,
                "tag": "latest",
                "dist_tag_written": True,
            }
        if operation == "npm.tokenWrite":
            return {"ok": True, "token_revoked": True}
        if operation == "npm.metadataWrite":
            return {
                "ok": True,
                "package": NPM_PACKAGE_NAME,
                "metadata_updated": True,
            }
        raise ValueError("unsupported_fixture_operation")

    @staticmethod
    def _classify(method: str, path: str, body: Any) -> str:
        package_path = f"/{NPM_PACKAGE_PATH}"
        if method == "PUT" and path == package_path:
            if body == _npm_publish_document():
                return "npm.publish"
            if body == _npm_metadata_document():
                return "npm.metadataWrite"
        if (
            method == "PUT"
            and path == f"{package_path}/-rev/{NPM_REVISION}"
            and body == _npm_unpublish_document()
        ):
            return "npm.unpublish"
        if (
            method == "PUT"
            and path
            == f"/-/package/{NPM_PACKAGE_PATH}/dist-tags/latest"
            and body == NPM_PACKAGE_VERSION
        ):
            return "npm.distTagWrite"
        if (
            method == "DELETE"
            and path == f"/-/npm/v1/tokens/token/{NPM_TOKEN_KEY}"
            and body is None
        ):
            return "npm.tokenWrite"
        if method == "POST" and path == "/-/npm/v1/tokens":
            return "npm.tokenCreate"
        raise ValueError("fixture_request_unclassified")

    def _send_json(
        self,
        handler: BaseHTTPRequestHandler,
        status: int,
        payload: dict[str, Any],
    ) -> None:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.wfile.write(body)
        handler.close_connection = True

    def _handle(self, handler: BaseHTTPRequestHandler) -> None:
        method = handler.command.upper()
        path = urlsplit(handler.path).path
        operation: str | None = None
        body_sha256: str | None = None
        try:
            body_bytes = self._strict_body(handler)
            body_sha256 = "sha256:" + hashlib.sha256(body_bytes).hexdigest()
            body = self._json_body(body_bytes)
            authorization = handler.headers.get("Authorization")
            if authorization != f"Bearer {NPM_FIXTURE_BEARER}":
                raise PermissionError("credential_injection_missing")
            operation = self._classify(method, path, body)
            if operation == "npm.tokenCreate":
                with self._lock:
                    self._counts[operation] += 1
                    self._events.append(
                        {
                            "operation": operation,
                            "method": method,
                            "path": path,
                            "bodySha256": body_sha256,
                            "authorizationPresent": True,
                            "authorizationScheme": "Bearer",
                            "unexpected": True,
                        }
                    )
                self._send_json(
                    handler,
                    500,
                    {"error": "token_creation_must_not_reach_registry"},
                )
                return
            response = self._response_for(operation)
            with self._lock:
                self._counts[operation] += 1
                self._events.append(
                    {
                        "operation": operation,
                        "method": method,
                        "path": path,
                        "bodySha256": body_sha256,
                        "authorizationPresent": True,
                        "authorizationScheme": "Bearer",
                    }
                )
            self._send_json(handler, 200, response)
        except PermissionError as exc:
            with self._lock:
                self._counts["rejected"] += 1
                self._events.append(
                    {
                        "operation": operation,
                        "method": method,
                        "path": path,
                        "bodySha256": body_sha256,
                        "authorizationPresent": False,
                        "reason": str(exc),
                    }
                )
            self._send_json(handler, 401, {"error": "registry_credential_required"})
        except Exception as exc:
            with self._lock:
                self._counts["rejected"] += 1
                self._events.append(
                    {
                        "operation": operation,
                        "method": method,
                        "path": path,
                        "bodySha256": body_sha256,
                        "reason": str(exc),
                    }
                )
            self._send_json(handler, 400, {"error": "registry_fixture_rejected"})

    def start(self) -> None:
        self._thread.start()
        self._started = True

    def observations(self) -> dict[str, Any]:
        with self._lock:
            return json.loads(
                json.dumps(
                    {"counts": self._counts, "events": self._events},
                    sort_keys=True,
                )
            )

    def close(self) -> None:
        if not self._started:
            self._server.server_close()
            return
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=10)
        _require(not self._thread.is_alive(), "npm registry fixture did not stop")
        self._started = False


class _UvicornThread:
    def __init__(
        self, app: Any, listener: socket.socket, simulator: OAuthProviderSimulator
    ) -> None:
        try:
            import uvicorn
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "uvicorn is unavailable; run this script with the repository requirements.lock"
            ) from exc
        self._listener = listener
        self._error: BaseException | None = None
        self._server = uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=int(listener.getsockname()[1]),
                ssl_certfile=str(simulator.server_cert_path),
                ssl_keyfile=str(simulator.server_key_path),
                log_level="warning",
                access_log=False,
                proxy_headers=False,
                server_header=False,
                lifespan="on",
            )
        )
        self._thread = threading.Thread(
            target=self._run,
            name="serverware-browser-oauth-portal",
            daemon=True,
        )

    def _run(self) -> None:
        try:
            self._server.run(sockets=[self._listener])
        except BaseException as exc:  # pragma: no cover - surfaced to the caller
            self._error = exc

    def start(self) -> None:
        self._thread.start()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self._server.started:
                return
            if self._error is not None:
                raise RuntimeError(
                    "HTTPS portal failed during startup"
                ) from self._error
            if not self._thread.is_alive():
                raise RuntimeError("HTTPS portal stopped before startup completed")
            time.sleep(0.05)
        raise TimeoutError("HTTPS portal did not become ready")

    def close(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=20)
        if self._thread.is_alive():
            self._server.force_exit = True
            self._thread.join(timeout=5)
        if self._thread.is_alive():
            raise RuntimeError("HTTPS portal did not stop")
        if self._error is not None:
            raise RuntimeError("HTTPS portal failed") from self._error


def _api_result(
    page: Any,
    path: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return page.evaluate(
        """
        async ({path, method, payload}) => {
          const token = document.querySelector('#admin-token')?.value || '';
          const response = await fetch(path, {
            method,
            headers: {
              'Content-Type': 'application/json',
              'X-Serverware-Admin-Token': token,
              'Authorization': `Bearer ${token}`
            },
            body: method === 'GET' ? undefined : JSON.stringify(payload || {}),
            credentials: 'same-origin',
            cache: 'no-store'
          });
          const text = await response.text();
          return {status: response.status, text};
        }
        """,
        {"path": path, "method": method, "payload": payload or {}},
    )


def _api_json(page: Any, path: str) -> Any:
    result = _api_result(page, path)
    if result["status"] != 200:
        raise AssertionError(
            f"GET {path} returned HTTP {result['status']}: {result['text'][:500]}"
        )
    return json.loads(result["text"])


def _api_post_json(page: Any, path: str, payload: dict[str, Any] | None = None) -> Any:
    result = _api_result(page, path, method="POST", payload=payload)
    if result["status"] != 200:
        raise AssertionError(
            f"POST {path} returned HTTP {result['status']}: {result['text'][:500]}"
        )
    return json.loads(result["text"])


def _wait_for_api(
    page: Any,
    path: str,
    predicate: Callable[[Any], bool],
    *,
    timeout_seconds: float = 20,
) -> Any:
    deadline = time.monotonic() + timeout_seconds
    last: Any = None
    while time.monotonic() < deadline:
        last = _api_json(page, path)
        if predicate(last):
            return last
        time.sleep(0.1)
    raise AssertionError(f"GET {path} did not reach the expected state: {last!r}")


def _credential_by_name(bootstrap: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [
        item for item in bootstrap.get("credentials", []) if item.get("name") == name
    ]
    _require(len(matches) == 1, f"expected exactly one credential named {name!r}")
    return matches[0]


def _assert_public_credential(
    credential: dict[str, Any],
    *,
    provider: str,
    subject: str,
    account: str,
    scopes: list[str],
) -> None:
    metadata = credential.get("metadata") or {}
    _require(
        credential.get("kind") == "oauth2", f"{provider} credential kind is not oauth2"
    )
    _require(
        metadata.get("oauth") is True, f"{provider} credential is not managed OAuth"
    )
    _require(
        metadata.get("provider_id") == provider,
        f"{provider} credential provider mismatch",
    )
    _require(
        metadata.get("provider_subject") == subject,
        f"{provider} credential subject was not callback-verified",
    )
    _require(
        metadata.get("provider_account") == account,
        f"{provider} credential account was not callback-verified",
    )
    _require(
        metadata.get("provider_identity_verified") is True,
        f"{provider} credential identity is not marked verified",
    )
    _require(
        set(metadata.get("scopes") or []) == set(scopes),
        f"{provider} credential granted scopes mismatch",
    )
    forbidden_keys = {
        "secret",
        "encrypted_secret",
        "ciphertext",
        "access_token",
        "refresh_token",
        "client_secret",
        "code_verifier",
    }

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            overlap = forbidden_keys.intersection(value)
            _require(
                not overlap,
                f"public credential exposed secret-bearing keys: {sorted(overlap)}",
            )
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(credential)


def _wait_for_portal(
    page: Any, public_url: str, *, expected_url: str | None = None
) -> None:
    expected = expected_url or (public_url + "/")
    page.wait_for_url(
        re.compile(rf"^{re.escape(expected)}(?:\?.*)?$"), timeout=DEFAULT_TIMEOUT_MS
    )
    page.locator("#oauth-form").wait_for(state="visible", timeout=DEFAULT_TIMEOUT_MS)
    page.wait_for_function(
        """
        () => document.querySelector('#operator-auth-status')?.textContent === 'Token session'
          && document.querySelectorAll('#oauth-provider option').length === 2
        """,
        timeout=DEFAULT_TIMEOUT_MS,
    )


def _assert_refresh_preserves_live_oauth_form(page: Any) -> None:
    original = page.evaluate(
        """
        () => ({
          provider: document.querySelector('#oauth-provider')?.value || '',
          name: document.querySelector('#oauth-credential-name')?.value || '',
          scopes: document.querySelector('#oauth-scopes')?.value || '',
          metadata: document.querySelector('#oauth-metadata')?.value || '{}'
        })
        """
    )
    page.evaluate(
        """
        () => {
          const originalFetch = window.fetch.bind(window);
          let release;
          const barrier = new Promise((resolve) => { release = resolve; });
          window.__oauthRefreshRaceStarted = false;
          window.__oauthRefreshRaceDone = false;
          window.__oauthRefreshRaceRelease = release;
          window.fetch = (input, init) => {
            const raw = typeof input === 'string' ? input : input.url;
            const url = new URL(raw, window.location.href);
            if (!window.__oauthRefreshRaceStarted && url.pathname === '/api/bootstrap') {
              window.__oauthRefreshRaceStarted = true;
              return barrier.then(() => originalFetch(input, init));
            }
            return originalFetch(input, init);
          };
          window.__oauthRefreshRacePromise = (async () => {
            if (refreshInFlight) await refreshInFlight;
            await refresh();
          })().finally(() => {
            window.fetch = originalFetch;
            window.__oauthRefreshRaceDone = true;
          });
        }
        """
    )
    try:
        page.wait_for_function(
            "() => window.__oauthRefreshRaceStarted === true",
            timeout=DEFAULT_TIMEOUT_MS,
        )
        page.locator("#oauth-provider").select_option("x")
        page.locator("#oauth-credential-name").fill("Refresh race probe")
        page.locator("#oauth-scopes").fill("\n".join(X_SCOPES))
        page.locator("#oauth-metadata").fill('{"probe":"refresh-race"}')
        page.evaluate("window.__oauthRefreshRaceRelease()")
        page.wait_for_function(
            "() => window.__oauthRefreshRaceDone === true",
            timeout=DEFAULT_TIMEOUT_MS,
        )
        submitted = page.evaluate(
            """
            () => {
              const form = new FormData(document.querySelector('#oauth-form'));
              return {provider: form.get('provider'), scopes: form.get('scopes')};
            }
            """
        )
        _require(
            submitted == {"provider": "x", "scopes": "\n".join(X_SCOPES)},
            f"in-flight refresh replaced live OAuth form values: {submitted}",
        )
    finally:
        page.evaluate("window.__oauthRefreshRaceRelease?.()")
        page.wait_for_function(
            "() => window.__oauthRefreshRaceDone === true",
            timeout=DEFAULT_TIMEOUT_MS,
        )
        page.locator("#oauth-provider").select_option(original["provider"])
        page.locator("#oauth-credential-name").fill(original["name"])
        page.locator("#oauth-scopes").fill(original["scopes"])
        page.locator("#oauth-metadata").fill(original["metadata"])


def _assert_no_oauth_cookies(context: Any) -> None:
    cookies = context.cookies()
    residue = [
        item["name"] for item in cookies if item["name"].startswith(OAUTH_COOKIE_PREFIX)
    ]
    _require(
        not residue, f"OAuth state cookies survived callback consumption: {residue}"
    )


def _assert_no_horizontal_overflow(page: Any, *, label: str) -> None:
    dimensions = page.evaluate(
        """
        () => ({
          viewportWidth: window.innerWidth,
          documentWidth: document.documentElement.scrollWidth,
          bodyWidth: document.body.scrollWidth
        })
        """
    )
    maximum = max(dimensions["documentWidth"], dimensions["bodyWidth"])
    _require(
        maximum <= dimensions["viewportWidth"] + 1,
        f"{label} portal overflows horizontally: {dimensions}",
    )


def _assert_control_within_viewport(page: Any, locator: Any, *, label: str) -> None:
    box = locator.bounding_box()
    viewport = page.viewport_size
    _require(box is not None and viewport is not None, f"{label} has no rendered bounds")
    _require(
        box["x"] >= -1
        and box["y"] >= -1
        and box["x"] + box["width"] <= viewport["width"] + 1,
        f"{label} is outside the viewport: box={box}, viewport={viewport}",
    )


def _approval_diagnostics(page: Any, approval_id: str) -> dict[str, Any]:
    return page.evaluate(
        """
        (id) => ({
          url: window.location.href,
          stateReview: state.approvalReview,
          stateApproval: (state.approvals || []).find((item) => item.id === id) || null,
          status: document.querySelector('#operator-status')?.textContent || '',
          reviewText: document.querySelector('#approval-review')?.textContent || '',
          actionsText: document.querySelector('#approval-review-actions')?.textContent || '',
          actionsHidden: document.querySelector('#approval-review-actions')?.hidden,
          activeElement: document.activeElement?.id || ''
        })
        """,
        approval_id,
    )


def _install_dev_webauthn_shim(context: Any) -> None:
    context.add_init_script(
        r"""
        (() => {
          const toBase64Url = (value) => {
            const bytes = new Uint8Array(value);
            let raw = '';
            for (const byte of bytes) raw += String.fromCharCode(byte);
            return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
          };
          const fromBase64Url = (value) => {
            const padded = value + '='.repeat((4 - value.length % 4) % 4);
            const raw = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
            return Uint8Array.from(raw, (char) => char.charCodeAt(0)).buffer;
          };
          if (!window.PublicKeyCredential) {
            Object.defineProperty(window, 'PublicKeyCredential', {
              configurable: true,
              value: function PublicKeyCredential() {}
            });
          }
          const credentials = navigator.credentials;
          if (!credentials) return;
          const nativeGet = typeof credentials.get === 'function'
            ? credentials.get.bind(credentials)
            : null;
          Object.defineProperty(credentials, 'get', {
            configurable: true,
            value: async (options = {}) => {
              if (!options.publicKey) {
                if (nativeGet) return nativeGet(options);
                throw new Error('Credential request did not include publicKey options');
              }
              const token = document.querySelector('#admin-token')?.value || '';
              const response = await fetch('/api/dev/webauthn/assertion', {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'X-Serverware-Admin-Token': token,
                  'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({challenge: toBase64Url(options.publicKey.challenge)}),
                credentials: 'same-origin',
                cache: 'no-store'
              });
              const text = await response.text();
              if (!response.ok) {
                throw new Error(`Dev WebAuthn assertion failed with ${response.status}: ${text.slice(0, 300)}`);
              }
              const assertion = JSON.parse(text);
              return {
                id: assertion.id,
                rawId: fromBase64Url(assertion.rawId),
                type: assertion.type,
                response: Object.fromEntries(
                  Object.entries(assertion.response || {}).map(
                    ([key, value]) => [key, fromBase64Url(value)]
                  )
                ),
                getClientExtensionResults: () => ({})
              };
            }
          });
          window.__serverwareDevWebAuthnShim = true;
        })();
        """
    )


def _assert_single_approval_decision(
    page: Any,
    browser_observations: list[dict[str, Any]],
    approval_id: str,
    decision: str,
    *,
    reason: str | None = None,
    expected_request_count: int = 1,
    expected_denied_count: int = 0,
) -> dict[str, Any]:
    expected_status = "approved" if decision == "approve" else "denied"
    endpoint = f"/api/approvals/{approval_id}/{decision}"
    decision_requests = [
        item
        for item in browser_observations
        if item.get("type") == "request"
        and item.get("method") == "POST"
        and endpoint in item.get("url", "")
    ]
    decision_responses = [
        item
        for item in browser_observations
        if item.get("type") == "response" and endpoint in item.get("url", "")
    ]
    approvals = _api_json(page, "/api/approvals")
    matches = [item for item in approvals if item.get("id") == approval_id]
    from serverware import db

    audit_events = [
        item
        for item in db.list_audit_events(limit=500)
        if item.get("event_type") == f"approval.{expected_status}"
        and (item.get("event") or {}).get("approval_request_id") == approval_id
    ]
    diagnostics = {
        "decisionRequests": decision_requests,
        "decisionResponses": decision_responses,
        "approvalRecords": matches,
        "auditEvents": audit_events,
        "review": _approval_diagnostics(page, approval_id),
    }
    _require(
        len(decision_requests) == expected_request_count,
        f"{decision} issued an unexpected number of decision requests: {diagnostics}",
    )
    _require(
        sum(item.get("status") == 200 for item in decision_responses) == 1
        and sum(item.get("status") == 403 for item in decision_responses)
        == expected_denied_count,
        f"{decision} response statuses did not preserve fail-closed review: {diagnostics}",
    )
    _require(
        len(matches) == 1 and matches[0].get("status") == expected_status,
        f"{decision} from review did not persist exactly one {expected_status} status: {diagnostics}",
    )
    _require(
        len(audit_events) == 1,
        f"{decision} from review did not append exactly one audit decision: {diagnostics}",
    )
    if reason is not None:
        _require(
            matches[0].get("decision_note") == reason
            and (audit_events[0].get("event") or {}).get("note") == reason,
            f"review denial did not preserve its exact reason: {diagnostics}",
        )
    return matches[0]


def _assert_stripe_uses_manual_credential_flow(
    page: Any, browser_observations: list[dict[str, Any]]
) -> None:
    oauth_requests_before = sum(
        1
        for item in browser_observations
        if item.get("type") == "request" and "/api/oauth/" in item.get("url", "")
    )
    oauth_state_before = page.evaluate(
        """
        () => ({
          provider: document.querySelector('#oauth-provider')?.value || '',
          draft: sessionStorage.getItem('serverware.oauthDraft'),
          setupSessionId: state.oauthSetupSessionId
        })
        """
    )
    credential_form_before = {
        "name": page.locator("#credential-name").input_value(),
        "kind": page.locator("#credential-kind").input_value(),
        "metadata": page.locator("#credential-metadata").input_value(),
    }

    page.locator("#setup-template").select_option("stripe_payment_intent_jit")
    page.locator("#setup-principal").select_option("agent:demo")
    # The setup action records a durable run against an active route before it opens
    # the credential form. Reuse a seeded route only for this UI-path assertion.
    page.locator("#setup-route-id").fill("demo.echo")
    page.wait_for_function(
        """
        () => document.querySelector('#setup-template')?.value === 'stripe_payment_intent_jit'
          && document.querySelector('#setup-connect-button')?.textContent === 'Add credential'
        """,
        timeout=DEFAULT_TIMEOUT_MS,
    )

    setup_credential = page.locator("#setup-credential")
    unrelated_bearer = setup_credential.locator(
        "option[value='cred-demo-bearer']"
    )
    _require(
        unrelated_bearer.count() == 1 and unrelated_bearer.is_disabled(),
        "Stripe setup did not reject the unrelated seeded bearer credential",
    )
    _require(
        setup_credential.input_value() == "",
        "Stripe setup silently selected an unrelated bearer credential",
    )
    _require(
        page.locator("#oauth-provider option[value='stripe']").count() == 0,
        "Stripe was incorrectly exposed as an OAuth provider",
    )
    add_credential = page.get_by_role("button", name="Add credential", exact=True)
    _require(add_credential.is_enabled(), "Stripe manual credential action is disabled")
    add_credential.click()
    page.wait_for_function(
        """
        () => {
          try {
            const metadata = JSON.parse(document.querySelector('#credential-metadata')?.value || '{}');
            return document.querySelector('#credential-kind')?.value === 'bearer'
              && metadata.provider === 'stripe'
              && new URL(window.location.href).searchParams.has('setup');
          } catch (_) {
            return false;
          }
        }
        """,
        timeout=DEFAULT_TIMEOUT_MS,
    )
    _require(
        page.locator("#credential-name").input_value()
        == (
            "Tokenized PaymentIntent create, five per UTC calendar day, resetting at "
            "00:00 UTC + hardware JIT credential"
        ),
        "Stripe manual credential name was not prefilled",
    )
    _require(
        json.loads(page.locator("#credential-metadata").input_value())
        == {"provider": "stripe"},
        "Stripe provider metadata was not prefilled",
    )
    _require(
        page.evaluate("document.activeElement?.id") == "credential-name",
        "Stripe setup did not focus the manual static credential form",
    )

    stripe_state = page.evaluate(
        """
        () => ({
          sessionId: state.setupSession?.id || null,
          revision: state.setupSession?.revision ?? null,
          oauthSetupSessionId: state.oauthSetupSessionId,
          oauthProvider: document.querySelector('#oauth-provider')?.value || '',
          oauthDraft: sessionStorage.getItem('serverware.oauthDraft')
        })
        """
    )
    _require(stripe_state["sessionId"], "Stripe setup did not create its temporary run")
    _require(
        stripe_state["oauthSetupSessionId"] == oauth_state_before["setupSessionId"],
        "Stripe manual setup was incorrectly attached to OAuth state",
    )
    _require(
        stripe_state["oauthProvider"] == oauth_state_before["provider"]
        and stripe_state["oauthDraft"] == oauth_state_before["draft"],
        "Stripe manual setup changed the selected OAuth provider or draft",
    )
    oauth_requests_after = sum(
        1
        for item in browser_observations
        if item.get("type") == "request" and "/api/oauth/" in item.get("url", "")
    )
    _require(
        oauth_requests_after == oauth_requests_before,
        "Stripe manual setup started an OAuth request",
    )

    cancelled = page.evaluate(
        """
        async ({sessionId, revision}) => {
          const token = document.querySelector('#admin-token')?.value || '';
          const response = await fetch(`/api/setup/sessions/${encodeURIComponent(sessionId)}/cancel`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-Serverware-Admin-Token': token,
              'Authorization': `Bearer ${token}`
            },
            credentials: 'same-origin',
            body: JSON.stringify({
              expectedRevision: revision,
              reason: 'Browser Stripe manual credential flow assertion complete'
            })
          });
          return {status: response.status, text: await response.text()};
        }
        """,
        {"sessionId": stripe_state["sessionId"], "revision": stripe_state["revision"]},
    )
    _require(
        200 <= cancelled["status"] < 300,
        f"temporary Stripe setup run could not be cancelled: {cancelled}",
    )
    page.locator("#setup-session").select_option("")
    page.wait_for_function(
        """
        () => !new URL(window.location.href).searchParams.has('setup')
          && state.setupSession === null
        """,
        timeout=DEFAULT_TIMEOUT_MS,
    )
    page.locator("#setup-template").select_option("gmail_recent")
    page.locator("#credential-name").fill(credential_form_before["name"])
    page.locator("#credential-kind").select_option(credential_form_before["kind"])
    page.locator("#credential-metadata").fill(credential_form_before["metadata"])
    page.wait_for_function(
        """
        () => document.querySelector('#setup-template')?.value === 'gmail_recent'
          && document.querySelector('#setup-connect-button')?.textContent === 'Connect credential'
        """,
        timeout=DEFAULT_TIMEOUT_MS,
    )


def _connect_oauth(
    page: Any,
    context: Any,
    reviewer_page: Any,
    public_url: str,
    *,
    provider: str,
    name: str,
    scopes: list[str],
    account: str,
) -> dict[str, Any]:
    page.locator("#oauth-provider").select_option(provider)
    page.locator("#oauth-credential-name").fill(name)
    page.locator("#oauth-scopes").fill("\n".join(scopes))
    page.locator("#oauth-metadata").fill(
        json.dumps({"evidence": "deterministic-browser-oauth"}, separators=(",", ":"))
    )
    _require(
        page.locator("#oauth-submit").is_enabled(),
        f"{provider} OAuth submit is disabled",
    )
    page.locator("#oauth-submit").click(no_wait_after=True)
    try:
        page.get_by_role(
            "heading", name="OAuth account verified", exact=True
        ).wait_for(state="visible", timeout=DEFAULT_TIMEOUT_MS)
    except Exception as exc:
        diagnostic = page.evaluate(
            """
            () => ({
              url: window.location.href,
              heading: document.querySelector('h1,h2')?.textContent || '',
              body: (document.body?.innerText || '').slice(0, 1000)
            })
            """
        )
        raise AssertionError(
            f"{provider} OAuth callback did not stage exact-account activation: {diagnostic}"
        ) from exc
    page.wait_for_url(
        re.compile(rf"^{re.escape(public_url)}/(?:\?.*)?$"), timeout=DEFAULT_TIMEOUT_MS
    )
    _require(
        page.locator("#admin-token").input_value() == "",
        "manual admin token unexpectedly survived the OAuth navigation",
    )
    page.locator("#admin-token").fill(ADMIN_TOKEN)
    page.locator("#admin-token").dispatch_event("change")
    _wait_for_portal(page, public_url)
    page.wait_for_function(
        """
        ({name, account}) => (state.pendingOAuthCredentials || []).some(
          (item) => item.name === name
            && item.requester_id === 'user:operator'
            && item.status === 'pending'
            && item.review?.provider_account === account
        )
        """,
        arg={"name": name, "account": account},
        timeout=DEFAULT_TIMEOUT_MS,
    )
    pending = page.evaluate(
        """
        ({name, account}) => (state.pendingOAuthCredentials || []).find(
          (item) => item.name === name && item.review?.provider_account === account
        )
        """,
        {"name": name, "account": account},
    )
    _require(
        pending.get("requester_id") == "user:operator",
        f"{provider} pending activation was not bound to the requester: {pending}",
    )
    pending_item = page.locator(
        "#pending-oauth-credentials .pending-oauth-item"
    ).filter(has_text=account)
    pending_item.get_by_role(
        "button", name="Request approval and activate", exact=True
    ).click()
    page.wait_for_function(
        """
        () => {
          try {
            const mutation = JSON.parse(
              sessionStorage.getItem('serverware.pendingMutation') || 'null'
            );
            return mutation?.kind === 'oauth-activate'
              && typeof mutation?.approvalId === 'string';
          } catch (_) {
            return false;
          }
        }
        """,
        timeout=DEFAULT_TIMEOUT_MS,
    )
    pending_mutation = page.evaluate(
        "() => JSON.parse(sessionStorage.getItem('serverware.pendingMutation'))"
    )
    approval_id = pending_mutation["approvalId"]
    _require(
        pending_mutation.get("path") == f"/api/oauth/pending/{pending['id']}/activate",
        f"{provider} retry mutation is not bound to the pending credential",
    )
    self_approval = page.evaluate(
        """
        async ({id, token}) => {
          const response = await fetch(`/api/control-plane/approvals/${id}/approve`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-Serverware-Admin-Token': token,
              'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({note: 'requester self-approval must fail'}),
            credentials: 'same-origin',
            cache: 'no-store'
          });
          return {status: response.status, body: await response.json()};
        }
        """,
        {"id": approval_id, "token": ADMIN_TOKEN},
    )
    _require(
        self_approval.get("status") == 403
        and "requester cannot approve" in str(self_approval.get("body")),
        f"{provider} requester self-approval did not fail closed: {self_approval}",
    )

    reviewer_page.goto(public_url + "/", wait_until="domcontentloaded")
    reviewer_page.locator("#admin-token").fill(ADMIN_TOKEN)
    reviewer_page.locator("#admin-token").dispatch_event("change")
    _wait_for_portal(reviewer_page, public_url)
    reviewer_page.wait_for_function(
        """
        (id) => (state.controlPlaneApprovals || []).some(
          (item) => item.id === id
            && item.status === 'pending'
            && item.action === 'credential.oauth.activate'
            && item.requester_id === 'user:operator'
        )
        """,
        arg=approval_id,
        timeout=DEFAULT_TIMEOUT_MS,
    )
    reviewer_activation = reviewer_page.evaluate(
        """
        async ({pendingId, setupSessionId, setupRevision, token}) => {
          const response = await fetch(`/api/oauth/pending/${pendingId}/activate`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-Serverware-Admin-Token': token,
              'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
              setupSessionId,
              setupRevision
            }),
            credentials: 'same-origin',
            cache: 'no-store'
          });
          return {status: response.status, body: await response.json()};
        }
        """,
        {
            "pendingId": pending["id"],
            "setupSessionId": pending_mutation.get("body", {}).get("setupSessionId"),
            "setupRevision": pending_mutation.get("body", {}).get("setupRevision"),
            "token": ADMIN_TOKEN,
        },
    )
    _require(
        reviewer_activation.get("status") == 403
        and "only the OAuth requester" in str(reviewer_activation.get("body")),
        f"{provider} reviewer directly activated requester grant: {reviewer_activation}",
    )
    approval_row = reviewer_page.locator("#control-plane-approvals tr").filter(
        has_text=pending["id"]
    )
    approval_text = approval_row.inner_text()
    for marker in (
        "credential.oauth.activate",
        "user:operator",
        account,
        str(pending["review"]["provider_subject"]),
    ):
        _require(
            marker in approval_text,
            f"{provider} exact-account approval omitted {marker!r}",
        )
    approval_row.get_by_role("button", name="Approve", exact=True).click()
    reviewer_page.wait_for_function(
        """
        (id) => (state.controlPlaneApprovals || []).some(
          (item) => item.id === id
            && item.status === 'approved'
            && item.approved_by === 'user:demo'
        )
        """,
        arg=approval_id,
        timeout=DEFAULT_TIMEOUT_MS,
    )

    page.get_by_role("button", name="Continue approved request", exact=True).click()
    page.wait_for_function(
        """
        ({name, account}) => [...document.querySelectorAll('#credentials tr')].some(
          (row) => row.textContent.includes(name)
            && row.textContent.includes(account)
            && row.textContent.includes('verified identity')
        )
        """,
        arg={"name": name, "account": account},
        timeout=DEFAULT_TIMEOUT_MS,
    )
    page.wait_for_function(
        """
        (id) => !(state.pendingOAuthCredentials || []).some((item) => item.id === id)
          && sessionStorage.getItem('serverware.pendingMutation') === null
        """,
        arg=pending["id"],
        timeout=DEFAULT_TIMEOUT_MS,
    )
    _assert_no_oauth_cookies(context)
    bootstrap = _api_json(page, "/api/bootstrap")
    credential = _credential_by_name(bootstrap, name)
    credential["browserApprovalId"] = approval_id
    return credential


def _preview_stage_activate_policy(
    page: Any,
    *,
    template: str,
    route_id: str,
    credential_id: str,
    custom_route: dict[str, Any] | None = None,
) -> dict[str, Any]:
    active_before = _api_json(page, "/api/policy")
    _require(
        active_before.get("ready") is True, "demo seed did not install an active policy"
    )
    old_hash = active_before.get("policy_hash")
    page.wait_for_function(
        "() => !refreshInFlight",
        timeout=DEFAULT_TIMEOUT_MS,
    )
    page.evaluate(
        "(activePolicy) => { state.activePolicy = activePolicy; }",
        active_before,
    )

    page.locator("#policy-template").select_option(template)
    page.locator("#policy-route-id").fill(route_id)
    page.locator("#policy-principal").select_option("agent:demo")
    page.locator("#policy-credential").select_option(credential_id)
    if custom_route is not None:
        _require(template == "custom_json", "custom route requires custom_json template")
        page.locator("#policy-custom-route").fill(
            json.dumps(custom_route, indent=2, sort_keys=True)
        )
    page.locator("#policy-route-form button[type='submit']").click()
    try:
        page.wait_for_function(
            """
            (routeId) => state.policyCandidate?.routeId === routeId
              && state.policyCandidate?.report?.dryRun?.passed === true
              && document.querySelector('#policy-candidate-summary')?.textContent.includes(
                '2/2 dry-run checks passed'
              )
            """,
            arg=route_id,
            timeout=DEFAULT_TIMEOUT_MS,
        )
    except Exception as exc:
        diagnostics = page.evaluate(
            """
            () => ({
              status: document.querySelector('#operator-status')?.textContent || '',
              authStatus: document.querySelector('#operator-auth-status')?.textContent || '',
              candidateSummary: document.querySelector('#policy-candidate-summary')?.textContent || '',
              candidateOutput: document.querySelector('#policy-candidate-output')?.value || '',
              tokenLength: document.querySelector('#admin-token')?.value?.length || 0
            })
            """
        )
        raise AssertionError(
            f"{route_id} candidate preview did not complete: {diagnostics}"
        ) from exc
    preview = json.loads(page.locator("#policy-candidate-output").input_value())
    report = preview.get("candidate") or {}
    checks = (report.get("dryRun") or {}).get("results") or []
    _require(report.get("ok") is True, f"{route_id} candidate preview failed")
    _require(
        (report.get("dryRun") or {}).get("passed") is True
        and len(checks) == 2
        and all(item.get("passed") is True for item in checks),
        f"{route_id} candidate did not pass both allow/deny dry runs",
    )

    page.locator("#policy-stage-button").wait_for(
        state="visible", timeout=DEFAULT_TIMEOUT_MS
    )
    _require(
        page.locator("#policy-stage-button").is_enabled(),
        "validated candidate cannot be staged",
    )
    page.locator("#policy-stage-button").click()
    try:
        page.wait_for_function(
            """
            () => {
              try {
                return JSON.parse(document.querySelector('#policy-canary-status')?.value || '{}')
                  .canary?.status === 'running';
              } catch (_) {
                return false;
              }
            }
            """,
            timeout=DEFAULT_TIMEOUT_MS,
        )
    except Exception as exc:
        diagnostics = page.evaluate(
            """
            () => ({
              status: document.querySelector('#operator-status')?.textContent || '',
              canaryStatus: document.querySelector('#policy-canary-status')?.value || '',
              candidateOutput: document.querySelector('#policy-candidate-output')?.value || ''
            })
            """
        )
        raise AssertionError(
            f"{route_id} candidate staging did not complete: {diagnostics}"
        ) from exc
    _require(
        page.locator("#policy-activate-button").is_enabled(),
        "running canary cannot be activated",
    )
    page.locator("#policy-activate-button").click()
    active_after = _wait_for_api(
        page,
        "/api/policy",
        lambda payload: payload.get("ready") is True
        and payload.get("policy_hash") != old_hash,
    )
    page.wait_for_function(
        "(policyHash) => state.activePolicy?.policy_hash === policyHash",
        arg=active_after["policy_hash"],
        timeout=DEFAULT_TIMEOUT_MS,
    )
    route = next(
        (
            item
            for item in active_after["bundle"].get("routes", [])
            if item.get("id") == route_id
        ),
        None,
    )
    _require(route is not None, f"activated policy omits route {route_id}")
    _require(
        route.get("credentialRef") == credential_id,
        f"{route_id} credential assignment mismatch",
    )
    _require(
        route.get("principals") == ["agent:demo"],
        f"{route_id} principal assignment mismatch",
    )
    return active_after


def _assert_policy_evidence(
    policy: dict[str, Any],
    google_id: str,
    x_id: str,
    simulator: OAuthProviderSimulator,
    npm_registry: _NpmRegistryFixture,
) -> None:
    bundle = policy["bundle"]
    defaults = bundle.get("defaults") or {}
    _require(
        defaults
        == {
            "action": "deny",
            "failMode": "closed",
            "unknownHosts": "block",
            "unknownPaths": "block",
            "validationFailure": "block",
        },
        "activated policy is not fail closed",
    )
    credentials = {item["id"]: item for item in bundle.get("credentials", [])}
    google = credentials.get(google_id) or {}
    x_credential = credentials.get(x_id) or {}
    _require(google.get("provider") == "google", "policy lost Google provider binding")
    _require(
        google.get("providerSubject") == "google-subject-001",
        "policy lost callback-verified Google subject",
    )
    _require(
        set(google.get("scopes") or []) == set(GOOGLE_SCOPES),
        "policy lost Google scopes",
    )
    _require(x_credential.get("provider") == "x", "policy lost X provider binding")
    _require(
        x_credential.get("providerSubject") == "x-subject-001",
        "policy lost callback-verified X subject",
    )
    _require(
        set(x_credential.get("scopes") or []) == set(X_SCOPES), "policy lost X scopes"
    )

    routes = {item["id"]: item for item in bundle.get("routes", [])}
    gmail = routes["browser.gmail.last-30-days"]
    x_search = routes["browser.x.search.seven-days"]
    x_post = routes[X_JIT_ROUTE_ID]
    npm_writes = routes[NPM_JIT_ROUTE_ID]
    _require(gmail["match"]["methods"] == ["GET"], "Gmail route is not read-only")
    _require(
        gmail["match"].get("host") == "127.0.0.1"
        and gmail["match"].get("port") == urlsplit(simulator.base_url).port,
        "Gmail route is not bound to the local HTTPS provider simulator",
    )
    _require(gmail["adapter"]["type"] == "gmail.v1", "Gmail route adapter mismatch")
    _require(
        gmail["adapter"]["config"].get("maxAgeDays") == 30
        and gmail["adapter"]["config"]["response"].get("validateInternalDate") is True,
        "Gmail route does not enforce and validate the 30-day boundary",
    )
    _require(x_search["match"]["methods"] == ["GET"], "X search route is not read-only")
    _require(
        x_search["match"].get("host") == "127.0.0.1"
        and x_search["match"].get("port") == urlsplit(simulator.base_url).port,
        "X search route is not bound to the local HTTPS provider simulator",
    )
    _require(
        x_search["adapter"]["config"].get("blockWrites") is True,
        "X search route does not block writes",
    )
    _require(
        x_search["adapter"]["config"].get("appIds") == [simulator.X_CLIENT_ID],
        "X route is not bound to the verified OAuth app",
    )
    _require(
        any(
            item.get("type") == "responseDateWindow" and item.get("maxAgeDays") == 7
            for item in x_search.get("constraints", [])
        ),
        "X route does not validate the seven-day response boundary",
    )
    _require(x_post["match"]["methods"] == ["POST"], "X posting route is not write-only")
    _require(
        x_post["match"].get("host") == "127.0.0.1"
        and x_post["match"].get("port") == urlsplit(simulator.base_url).port,
        "X posting route is not bound to the local simulator authority",
    )
    _require(
        x_post["adapter"]["config"].get("appIds") == [simulator.X_CLIENT_ID],
        "X posting route is not bound to the verified OAuth app",
    )
    daily_limits = [
        item
        for item in x_post.get("constraints", [])
        if item.get("type") == "rateLimit"
    ]
    _require(
        len(daily_limits) == 1
        and daily_limits[0].get("max") == 1
        and daily_limits[0].get("calendarWindow") == "utcDay"
        and daily_limits[0].get("store") == "shared"
        and (daily_limits[0].get("key") or {}).get("scope") == ["route", "operation"]
        and (daily_limits[0].get("key") or {}).get("operationFields")
        == ["providerAccount"],
        "X posting route lost its provider-account UTC calendar quota",
    )
    jit = x_post.get("jit") or {}
    authn = (jit.get("approvers") or {}).get("authn") or {}
    _require(
        jit.get("required") is True
        and jit.get("mode") == "perOperation"
        and jit.get("maxUses") == 1
        and jit.get("consumeOn") == "forwardStart"
        and (jit.get("approvers") or {}).get("users") == ["user:demo"]
        and authn.get("webauthnRequired") is True
        and authn.get("userVerification") == "required"
        and authn.get("allowedAuthenticatorClasses") == ["dev"]
        and authn.get("requireHardwareAttestation") is False,
        "X posting route lost its one-use reviewer WebAuthn JIT binding",
    )
    npm_operations = {
        "npm.publish",
        "npm.unpublish",
        "npm.distTagWrite",
        "npm.tokenWrite",
        "npm.metadataWrite",
    }
    npm_operation_policy = next(
        (
            item
            for item in npm_writes.get("constraints", [])
            if item.get("type") == "operationPolicy"
        ),
        {},
    )
    npm_jit = npm_writes.get("jit") or {}
    npm_authn = (npm_jit.get("approvers") or {}).get("authn") or {}
    _require(
        npm_writes.get("credentialRef") == NPM_CREDENTIAL_ID
        and npm_writes.get("match", {}).get("host") == "127.0.0.1"
        and npm_writes.get("match", {}).get("port") == npm_registry.port
        and npm_writes.get("match", {}).get("resolvedCidrs")
        == ["127.0.0.1/32"]
        and set(npm_writes.get("match", {}).get("methods") or [])
        == {"PUT", "POST", "DELETE"}
        and set(npm_writes.get("adapter", {}).get("config", {}).get("operations") or [])
        == {"publish", "unpublish", "distTagWrite", "tokenWrite", "metadataWrite"}
        and set(npm_operation_policy.get("allowedOperations") or [])
        == npm_operations
        and "npm.tokenCreate"
        not in set(npm_operation_policy.get("allowedOperations") or []),
        "npm route lost its exact local authority or closed five-operation allowlist",
    )
    _require(
        npm_jit.get("required") is True
        and npm_jit.get("mode") == "perOperation"
        and npm_jit.get("maxUses") == 1
        and npm_jit.get("consumeOn") == "forwardStart"
        and npm_jit.get("binding", {}).get("type") == "operationDigest"
        and "operation" in set(npm_jit.get("binding", {}).get("fields") or [])
        and (npm_jit.get("approvers") or {}).get("users") == ["user:demo"]
        and npm_authn.get("webauthnRequired") is True
        and npm_authn.get("userVerification") == "required"
        and npm_authn.get("allowedAuthenticatorClasses") == ["hardware"]
        and npm_authn.get("requireHardwareAttestation") is True,
        "npm route lost immutable operation-bound one-use reviewer WebAuthn JIT",
    )


def _settle_screenshot_focus(page: Any) -> None:
    page.evaluate(
        """() => {
          const active = document.activeElement;
          if (active instanceof HTMLElement) active.blur();
          const skipLink = document.querySelector('.skip-link');
          if (skipLink instanceof HTMLElement) skipLink.style.visibility = 'hidden';
        }"""
    )
    page.wait_for_timeout(50)


def _capture_screenshot(page: Any, selector: str, destination: Path) -> None:
    page.set_viewport_size({"width": 1440, "height": 1100})
    page.locator(selector).scroll_into_view_if_needed()
    page.evaluate("window.scrollBy(0, -16)")
    page.wait_for_timeout(150)
    _settle_screenshot_focus(page)
    page.screenshot(
        path=str(destination),
        type="png",
        full_page=False,
        mask=[page.locator("#admin-token")],
        mask_color="#e8efed",
    )


def _capture_mobile_screenshot(page: Any, selector: str, destination: Path) -> None:
    page.set_viewport_size({"width": 390, "height": 844})
    page.locator(selector).scroll_into_view_if_needed()
    page.evaluate("window.scrollBy(0, -8)")
    page.wait_for_timeout(150)
    _settle_screenshot_focus(page)
    page.screenshot(
        path=str(destination),
        type="png",
        full_page=False,
        mask=[page.locator("#admin-token")],
        mask_color="#e8efed",
    )


def _capture_element_screenshot(page: Any, selector: str, destination: Path) -> None:
    page.set_viewport_size({"width": 1440, "height": 1100})
    target = page.locator(selector)
    target.scroll_into_view_if_needed()
    page.wait_for_timeout(150)
    _settle_screenshot_focus(page)
    target.screenshot(path=str(destination), type="png")


def _jit_state_snapshot(route_id: str, credential_id: str) -> dict[str, Any]:
    from serverware import db

    def rows(conn: Any, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        return [dict(item) for item in conn.execute(sql, params).fetchall()]

    with db.connect() as conn:
        credential_row = conn.execute(
            """
            SELECT credential_version, secret_updated_at, lifecycle_status
            FROM credentials
            WHERE id = ?
            """,
            (credential_id,),
        ).fetchone()
        _require(credential_row is not None, "callback credential disappeared")
        approvals = rows(
            conn,
            """
            SELECT id, status, principal_id, credential_id, credential_version,
                   policy_hash, request_digest, operation_digest, approved_by,
                   approval_challenge_id
            FROM approval_requests
            WHERE route_id = ?
            ORDER BY requested_at, id
            """,
            (route_id,),
        )
        receipts = rows(
            conn,
            """
            SELECT receipt.id, receipt.approval_request_id, receipt.reviewer_id,
                   receipt.review_digest, receipt.used_at
            FROM approval_review_receipts AS receipt
            INNER JOIN approval_requests AS approval
              ON approval.id = receipt.approval_request_id
            WHERE approval.route_id = ?
            ORDER BY receipt.created_at, receipt.id
            """,
            (route_id,),
        )
        grants = rows(
            conn,
            """
            SELECT id, approval_request_id, state, uses_remaining,
                   reserved_attempt_id, consumed_at
            FROM approval_grants
            WHERE route_id = ?
            ORDER BY created_at, id
            """,
            (route_id,),
        )
        attempts = rows(
            conn,
            """
            SELECT attempt_id, flow_id, state, credential_version, policy_hash,
                   request_digest, operation_digest, grant_id,
                   approval_request_id, completion_outcome
            FROM release_authorization_attempts
            WHERE route_id = ?
            ORDER BY created_at, attempt_id
            """,
            (route_id,),
        )
        issuances = rows(
            conn,
            """
            SELECT issuance.attempt_id, issuance.binding_digest,
                   issuance.request_binding_sha256
            FROM release_authorization_credential_issuances AS issuance
            INNER JOIN release_authorization_attempts AS attempt
              ON attempt.attempt_id = issuance.attempt_id
            WHERE attempt.route_id = ?
            ORDER BY issuance.created_at, issuance.attempt_id
            """,
            (route_id,),
        )
        quotas = rows(
            conn,
            """
            SELECT quota.attempt_id, quota.constraint_id, quota.window_kind,
                   quota.max_count, quota.count_after, quota.reservation_state
            FROM release_authorization_quota_reservations AS quota
            INNER JOIN release_authorization_attempts AS attempt
              ON attempt.attempt_id = quota.attempt_id
            WHERE attempt.route_id = ?
            ORDER BY quota.created_at, quota.attempt_id, quota.counter_key
            """,
            (route_id,),
        )
        consumptions = rows(
            conn,
            """
            SELECT id, grant_id, approval_request_id, attempt_id, outcome,
                   uses_remaining_before, uses_remaining_after
            FROM approval_grant_consumptions
            WHERE route_id = ?
            ORDER BY created_at, id
            """,
            (route_id,),
        )
        counters = rows(
            conn,
            """
            SELECT counter_key, constraint_id, window_kind, max_count, count
            FROM rate_limit_counters
            WHERE route_id = ?
            ORDER BY counter_key
            """,
            (route_id,),
        )
        release_event_count = conn.execute(
            """
            SELECT COUNT(*)
            FROM release_authorization_events AS event
            INNER JOIN release_authorization_attempts AS attempt
              ON attempt.attempt_id = event.attempt_id
            WHERE attempt.route_id = ?
            """,
            (route_id,),
        ).fetchone()[0]
    return {
        "credential": dict(credential_row),
        "approvals": approvals,
        "reviewReceipts": receipts,
        "grants": grants,
        "attempts": attempts,
        "credentialIssuances": issuances,
        "quotaReservations": quotas,
        "grantConsumptions": consumptions,
        "rateLimitCounters": counters,
        "releaseEventCount": int(release_event_count),
    }


def _simulator_resource_state(simulator: OAuthProviderSimulator) -> dict[str, Any]:
    observations = simulator.observations()
    google_counts = observations["counts"]["google"]
    x_counts = observations["counts"]["x"]
    return {
        "googleResourceRequests": int(
            google_counts.get("resource_requests") or 0
        ),
        "googleResourceRejections": int(
            google_counts.get("resource_rejections") or 0
        ),
        "gmailLists": int(
            google_counts.get("resource_gmail.messages.list") or 0
        ),
        "gmailMetadataGets": int(
            google_counts.get("resource_gmail.message.get") or 0
        ),
        "googleRefreshRequests": int(
            google_counts.get("refresh_exchanges") or 0
        ),
        "xResourceRequests": int(x_counts.get("resource_requests") or 0),
        "xResourceRejections": int(x_counts.get("resource_rejections") or 0),
        "tweetCreates": int(x_counts.get("resource_x.tweet.create") or 0),
        "recentSearches": int(x_counts.get("resource_x.search.recent") or 0),
        "xRefreshRequests": int(x_counts.get("refresh_exchanges") or 0),
        "resourceEvents": [
            {
                "type": item.get("type"),
                "provider": item.get("provider"),
                "operation": item.get("operation"),
                "reason": item.get("reason"),
            }
            for item in observations["events"]
            if str(item.get("type") or "").startswith("resource_")
        ],
    }


def _parse_http_response(raw: bytes) -> dict[str, Any]:
    _require(len(raw) <= 2 * 1024 * 1024, "gate response exceeded test bound")
    head, separator, body = raw.partition(b"\r\n\r\n")
    _require(bool(separator), f"gate response omitted header terminator: {raw[:500]!r}")
    lines = head.split(b"\r\n")
    _require(bool(lines), "gate response omitted a status line")
    status_parts = lines[0].split(b" ", 2)
    _require(
        len(status_parts) >= 2 and status_parts[1].isdigit(),
        f"gate response status line was malformed: {lines[0]!r}",
    )
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        _require(bool(separator), f"gate response header was malformed: {line!r}")
        normalized_name = name.decode("ascii").lower()
        _require(
            normalized_name not in headers,
            f"gate response duplicated header {normalized_name!r}",
        )
        headers[normalized_name] = value.decode("latin-1").strip()
    content_length = headers.get("content-length")
    if content_length is not None:
        _require(content_length.isdigit(), "gate response Content-Length was invalid")
        _require(
            len(body) == int(content_length),
            "gate response body length did not match Content-Length",
        )
    payload = json.loads(body) if body else None
    return {
        "status": int(status_parts[1]),
        "headers": headers,
        "body": body,
        "json": payload,
    }


def _send_connect_tls_request(
    gate: _DecisionGateProcess,
    *,
    authority_host: str,
    authority_port: int,
    request_bytes: bytes,
) -> dict[str, Any]:
    _require(type(request_bytes) is bytes, "proxy request must be immutable bytes")
    sent_request_sha256 = "sha256:" + hashlib.sha256(request_bytes).hexdigest()
    sent_request_length = len(request_bytes)
    authority = f"{authority_host}:{authority_port}"
    connect_request = (
        f"CONNECT {authority} HTTP/1.1\r\n"
        f"Host: {authority}\r\n"
        "X-Serverware-Agent: demo-agent\r\n"
        "Connection: keep-alive\r\n\r\n"
    ).encode("ascii")
    with socket.create_connection(("127.0.0.1", gate.proxy_port), timeout=10) as sock:
        sock.settimeout(10)
        sock.sendall(connect_request)
        connect_response = b""
        while b"\r\n\r\n" not in connect_response:
            chunk = sock.recv(4096)
            _require(bool(chunk), "gate closed before CONNECT response completed")
            connect_response += chunk
            _require(
                len(connect_response) <= 64 * 1024,
                "CONNECT response headers exceeded test bound",
            )
        connect_head, separator, connect_remainder = connect_response.partition(
            b"\r\n\r\n"
        )
        _require(not connect_remainder, "gate sent bytes before the TLS handshake")
        _require(
            connect_head.startswith(b"HTTP/1.1 200 "),
            f"gate CONNECT preflight failed: {connect_head[:1000]!r}",
        )
        context = ssl.create_default_context(cafile=str(gate.ca_cert_path))
        with context.wrap_socket(sock, server_hostname=authority_host) as tls:
            tls.settimeout(10)
            tls.sendall(request_bytes)
            response = b""
            while True:
                try:
                    chunk = tls.recv(64 * 1024)
                except ssl.SSLEOFError:
                    break
                if not chunk:
                    break
                response += chunk
                _require(
                    len(response) <= 2 * 1024 * 1024,
                    "gate response exceeded test bound",
                )
    parsed = _parse_http_response(response)
    parsed["sentRequestSha256"] = sent_request_sha256
    parsed["sentRequestLength"] = sent_request_length
    return parsed


def _assert_storage_and_disk_do_not_leak_tokens(
    page: Any,
    context: Any,
    data_dir: Path,
    simulator: OAuthProviderSimulator,
    api_documents: list[Any],
    browser_observations: list[dict[str, Any]],
) -> None:
    storage = page.evaluate(
        """
        () => ({
          session: Object.fromEntries(Object.entries(sessionStorage)),
          local: Object.fromEntries(Object.entries(localStorage)),
          html: document.documentElement.outerHTML
        })
        """
    )
    observable = {
        "storage": storage,
        "cookies": context.cookies(),
        "api": api_documents,
        "browser": browser_observations,
    }
    simulator.assert_no_token_values(
        json.dumps(observable, sort_keys=True, default=str)
    )
    for path in data_dir.rglob("*"):
        if not path.is_file():
            continue
        size = path.stat().st_size
        _require(
            size <= MAX_EVIDENCE_FILE_BYTES,
            f"unexpected oversized evidence file: {path}",
        )
        simulator.assert_no_token_values(path.read_bytes())


def _assert_provider_observations(simulator: OAuthProviderSimulator) -> dict[str, Any]:
    observations = simulator.observations()
    for provider in ("google", "x"):
        counts = observations["counts"][provider]
        for key in (
            "authorization_requests",
            "authorization_codes_issued",
            "token_requests",
            "authorization_code_exchanges",
            "token_responses",
            "identity_requests",
        ):
            _require(
                counts.get(key) == 1, f"{provider} {key} count was {counts.get(key)!r}"
            )
        for key in (
            "authorization_denials",
            "token_rejections",
            "identity_rejections",
            "revocation_rejections",
        ):
            _require(not counts.get(key), f"{provider} recorded unexpected {key}")
    _require(
        observations["active"]["authorizationCodes"] == 0,
        "simulator retained an unconsumed authorization code",
    )
    _require(
        observations["counts"]["google"].get("resource_requests") == 3
        and observations["counts"]["google"].get(
            "resource_gmail.messages.list"
        )
        == 1
        and observations["counts"]["google"].get(
            "resource_gmail.message.get"
        )
        == 2
        and not observations["counts"]["google"].get("resource_rejections")
        and not observations["counts"]["google"].get("refresh_exchanges"),
        "simulator did not accept one callback-token Gmail list with two "
        "metadata hydration requests and no refresh",
    )
    _require(
        observations["counts"]["x"].get("resource_requests") == 2
        and observations["counts"]["x"].get("resource_x.search.recent") == 1
        and observations["counts"]["x"].get("resource_x.tweet.create") == 1
        and not observations["counts"]["x"].get("resource_rejections")
        and not observations["counts"]["x"].get("refresh_exchanges"),
        "simulator did not accept one callback-token X search and one post "
        "without refresh",
    )
    rejected = [
        event for event in observations["events"] if "rejected" in event.get("type", "")
    ]
    _require(
        not rejected, f"simulator recorded rejected or replayed operations: {rejected}"
    )
    return observations


def _x_jit_route(simulator: OAuthProviderSimulator) -> dict[str, Any]:
    simulator_port = urlsplit(simulator.base_url).port
    _require(simulator_port is not None, "simulator URL omitted its port")
    return {
        "match": {
            "scheme": "https",
            "host": "127.0.0.1",
            "port": simulator_port,
            "resolvedCidrs": ["127.0.0.0/8"],
            "methods": ["POST"],
            "paths": ["/2/tweets"],
        },
        "adapter": {
            "type": "x.v2",
            "config": {
                "mode": "controlledWrite",
                "blockWrites": False,
                "appIds": [simulator.X_CLIENT_ID],
                "request": {
                    "allowedHeaders": [
                        "accept",
                        "accept-encoding",
                        "content-type",
                        "user-agent",
                    ],
                    "allowedQueryKeys": [],
                    "allowedMediaTypes": ["application/json"],
                    "maxBodyBytes": 65536,
                },
                "response": {
                    "mode": "json",
                    "maxBodyBytes": 65536,
                    "allowedFields": ["data.id", "data.text"],
                    "allowedHeaders": [],
                    "error": {
                        "mode": "json",
                        "maxBodyBytes": 65536,
                        "allowedFields": [
                            "title",
                            "detail",
                            "type",
                            "status",
                            "errors.title",
                            "errors.detail",
                            "errors.type",
                            "errors.value",
                        ],
                        "allowedHeaders": ["retry-after"],
                        "onInvalid": "block",
                    },
                },
            },
        },
        "constraints": [
            {
                "id": "browser-x-only-tweet-create",
                "type": "operationPolicy",
                "allowedOperations": ["tweets.write"],
            },
            {
                "id": "browser-x-one-post-per-day",
                "type": "rateLimit",
                "max": 1,
                "calendarWindow": "utcDay",
                "store": "shared",
                "key": {
                    "scope": ["route", "operation"],
                    "operationFields": ["providerAccount"],
                },
            },
            {
                "id": "browser-x-plain-text-body",
                "type": "jsonBody",
                "contentTypes": ["application/json"],
                "allowedFields": ["text", "reply_settings"],
                "requiredFields": ["text"],
                "deniedFields": ["media", "poll", "direct_message_deep_link"],
                "fields": {
                    "text": {"type": "string", "minLength": 1, "maxLength": 280},
                    "reply_settings": {
                        "type": "string",
                        "enum": ["following", "mentionedUsers"],
                    },
                },
            },
        ],
        "jit": {
            "required": True,
            "mode": "perOperation",
            "ttlSeconds": 120,
            "maxUses": 1,
            "consumeOn": "forwardStart",
            "binding": {
                "type": "operationDigest",
                "fields": [
                    "principal",
                    "routeId",
                    "credentialRef",
                    "credentialVersion",
                    "policyHash",
                    "method",
                    "authority",
                    "path",
                    "query",
                    "selectedHeaders",
                    "bodySha256",
                    "operation",
                ],
            },
            "approvers": {
                "quorum": 1,
                "users": ["user:demo"],
                "authn": {
                    "webauthnRequired": True,
                    "userVerification": "required",
                    "allowedAuthenticatorClasses": ["dev"],
                    "requireHardwareAttestation": False,
                },
            },
        },
    }


def _npm_jit_route(registry: _NpmRegistryFixture) -> dict[str, Any]:
    return {
        "match": {
            "scheme": "https",
            "host": "127.0.0.1",
            "port": registry.port,
            "resolvedCidrs": ["127.0.0.1/32"],
            "methods": ["PUT", "POST", "DELETE"],
            "paths": [
                "/{package}",
                "/{package}/-rev/{revision}",
                "/-/package/{package}/dist-tags/{tag}",
                "/-/npm/v1/tokens",
                "/-/npm/v1/tokens/token/{token}",
            ],
        },
        "adapter": {
            "type": "npm.registry",
            "config": {
                "request": {
                    "allowedHeaders": [
                        "accept",
                        "accept-encoding",
                        "content-type",
                        "npm-auth-type",
                        "npm-command",
                        "npm-in-ci",
                        "npm-otp",
                        "npm-scope",
                        "npm-session",
                        "user-agent",
                    ],
                    "allowedQueryKeys": [],
                    "allowedMediaTypes": ["application/json"],
                    "maxBodyBytes": 16_777_216,
                },
                "operations": [
                    "publish",
                    "unpublish",
                    "distTagWrite",
                    "tokenWrite",
                    "metadataWrite",
                ],
                "response": {
                    "mode": "json",
                    "maxBodyBytes": 65_536,
                    "allowedFields": [
                        "ok",
                        "package",
                        "version",
                        "published",
                        "revision",
                        "unpublished",
                        "tag",
                        "dist_tag_written",
                        "token_revoked",
                        "metadata_updated",
                    ],
                    "allowedHeaders": [],
                    "error": {
                        "mode": "json",
                        "maxBodyBytes": 65_536,
                        "allowedFields": ["error", "reason", "code"],
                        "allowedHeaders": [],
                        "onInvalid": "block",
                    },
                },
            },
        },
        "constraints": [
            {
                "id": "browser-npm-five-write-classes",
                "type": "operationPolicy",
                "allowedOperations": [
                    "npm.publish",
                    "npm.unpublish",
                    "npm.distTagWrite",
                    "npm.tokenWrite",
                    "npm.metadataWrite",
                ],
            },
            {
                "id": "browser-npm-publish-identity",
                "type": "responseBinding",
                "phase": "response",
                "operations": ["npm.publish"],
                "successStatusCodes": [200],
                "contentTypes": ["application/json"],
                "bindings": [
                    {
                        "id": "package-name",
                        "operationField": "packageName",
                        "responseField": "package",
                        "comparison": "exactString",
                    },
                    {
                        "id": "package-version",
                        "operationField": "packageVersion",
                        "responseField": "version",
                        "comparison": "exactString",
                    },
                ],
            },
            {
                "id": "browser-npm-publish-success",
                "type": "responseJson",
                "phase": "response",
                "operations": ["npm.publish"],
                "required": True,
                "fields": {
                    "published": {
                        "required": True,
                        "type": "boolean",
                        "equals": True,
                    }
                },
            },
        ],
        "jit": {
            "required": True,
            "mode": "perOperation",
            "ttlSeconds": 300,
            "maxUses": 1,
            "consumeOn": "forwardStart",
            "binding": {
                "type": "operationDigest",
                "fields": [
                    "principal",
                    "routeId",
                    "credentialRef",
                    "credentialVersion",
                    "policyHash",
                    "method",
                    "authority",
                    "path",
                    "query",
                    "selectedHeaders",
                    "bodySha256",
                    "operation",
                    "packageName",
                    "packageVersion",
                    "tarballIntegrity",
                ],
            },
            "approvers": {
                "quorum": 1,
                "users": ["user:demo"],
                "authn": {
                    "webauthnRequired": True,
                    "userVerification": "required",
                    "allowedAuthenticatorClasses": ["hardware"],
                    "requireHardwareAttestation": True,
                },
            },
        },
    }


def _npm_request_bytes(
    registry: _NpmRegistryFixture,
    operation: str,
) -> tuple[bytes, dict[str, Any]]:
    if operation == "npm.publish":
        method = "PUT"
        path = f"/{NPM_PACKAGE_PATH}"
        command = "publish"
        body_value: Any = _npm_publish_document()
    elif operation == "npm.unpublish":
        method = "PUT"
        path = f"/{NPM_PACKAGE_PATH}/-rev/{NPM_REVISION}"
        command = "unpublish"
        body_value = _npm_unpublish_document()
    elif operation == "npm.distTagWrite":
        method = "PUT"
        path = f"/-/package/{NPM_PACKAGE_PATH}/dist-tags/latest"
        command = "dist-tag"
        body_value = NPM_PACKAGE_VERSION
    elif operation == "npm.tokenWrite":
        method = "DELETE"
        path = f"/-/npm/v1/tokens/token/{NPM_TOKEN_KEY}"
        command = "token-revoke"
        body_value = None
    elif operation == "npm.metadataWrite":
        method = "PUT"
        path = f"/{NPM_PACKAGE_PATH}"
        command = "deprecate"
        body_value = _npm_metadata_document()
    elif operation == "npm.tokenCreate":
        method = "POST"
        path = "/-/npm/v1/tokens"
        command = "token-create"
        body_value = {
            "name": "serverware-browser-token",
            "readonly": False,
            "cidr_whitelist": [],
        }
    else:
        raise AssertionError(f"unsupported npm browser operation: {operation}")

    body = (
        b""
        if body_value is None
        else json.dumps(body_value, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    )
    headers = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{registry.port}\r\n"
        "Accept: application/json\r\n"
        f"Npm-Command: {command}\r\n"
        f"User-Agent: serverware-browser-rust-{command}\r\n"
    )
    if body_value is not None:
        headers += (
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
        )
    headers += "Connection: close\r\n\r\n"
    expected_response = (
        {}
        if operation == "npm.tokenCreate"
        else _NpmRegistryFixture._response_for(operation)
    )
    return headers.encode("ascii") + body, expected_response


def _localized_read_route(
    page: Any,
    *,
    template_id: str,
    simulator: OAuthProviderSimulator,
) -> dict[str, Any]:
    localized = page.evaluate(
        """
        (templateId) => {
          const template = policyTemplates[templateId];
          if (!template) return null;
          return JSON.parse(JSON.stringify({
            match: template.match,
            adapter: template.adapter,
            constraints: template.constraints || []
          }));
        }
        """,
        template_id,
    )
    _require(
        isinstance(localized, dict),
        f"portal omitted canonical policy template {template_id}",
    )
    simulator_port = urlsplit(simulator.base_url).port
    _require(simulator_port is not None, "simulator URL omitted its port")
    localized["match"]["host"] = "127.0.0.1"
    localized["match"]["port"] = simulator_port
    localized["match"]["resolvedCidrs"] = ["127.0.0.1/32"]
    if localized["adapter"].get("type") == "x.v2":
        localized["adapter"]["config"]["appIds"] = [simulator.X_CLIENT_ID]
    return localized


def _exercise_rust_reads(
    *,
    gate: _DecisionGateProcess,
    simulator: OAuthProviderSimulator,
) -> dict[str, Any]:
    simulator_port = urlsplit(simulator.base_url).port
    _require(simulator_port is not None, "simulator URL omitted its port")
    before = _simulator_resource_state(simulator)

    gmail_request = (
        "GET /gmail/v1/users/me/messages?maxResults=2 HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{simulator_port}\r\n"
        "Accept: application/json\r\n"
        "User-Agent: serverware-browser-rust-gmail\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    gmail = _send_connect_tls_request(
        gate,
        authority_host="127.0.0.1",
        authority_port=simulator_port,
        request_bytes=gmail_request,
    )
    gmail_payload = gmail["json"]
    gmail_messages = (
        gmail_payload.get("messages") if isinstance(gmail_payload, dict) else None
    )
    now_ms = int(time.time() * 1000)
    _require(
        gmail["status"] == 200
        and isinstance(gmail_messages, list)
        and len(gmail_messages) == 2
        and all(
            isinstance(item, dict)
            and set(item).issubset(
                {"id", "threadId", "internalDate", "serverwareAgeProof"}
            )
            and isinstance(item.get("id"), str)
            and isinstance(item.get("threadId"), str)
            and str(item.get("internalDate") or "").isdigit()
            and item.get("serverwareAgeProof") == "validated"
            and 0 <= now_ms - int(item["internalDate"]) <= 30 * 86_400_000
            for item in gmail_messages
        )
        and "resultSizeEstimate" not in gmail_payload,
        f"Rust Gmail route did not hydrate, validate, and project recent messages: {gmail}",
    )

    x_request = (
        "GET /2/tweets/search/recent"
        "?max_results=10&query=serverware&tweet.fields=created_at HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{simulator_port}\r\n"
        "Accept: application/json\r\n"
        "User-Agent: serverware-browser-rust-x-search\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    x_search = _send_connect_tls_request(
        gate,
        authority_host="127.0.0.1",
        authority_port=simulator_port,
        request_bytes=x_request,
    )
    x_payload = x_search["json"]
    x_items = x_payload.get("data") if isinstance(x_payload, dict) else None
    _require(
        x_search["status"] == 200
        and isinstance(x_items, list)
        and len(x_items) == 1
        and set(x_payload).issubset({"data", "meta"})
        and set(x_items[0]).issubset({"id", "text", "created_at"})
        and x_items[0].get("id") == "x-search-result-1"
        and isinstance(x_items[0].get("created_at"), str)
        and (x_payload.get("meta") or {}).get("result_count") == 1,
        f"Rust X route did not validate and project the recent search: {x_search}",
    )

    after = _simulator_resource_state(simulator)
    _require(
        after["googleResourceRequests"] == before["googleResourceRequests"] + 3
        and after["gmailLists"] == before["gmailLists"] + 1
        and after["gmailMetadataGets"] == before["gmailMetadataGets"] + 2
        and after["googleResourceRejections"]
        == before["googleResourceRejections"]
        and after["googleRefreshRequests"] == before["googleRefreshRequests"]
        and after["xResourceRequests"] == before["xResourceRequests"] + 1
        and after["recentSearches"] == before["recentSearches"] + 1
        and after["xResourceRejections"] == before["xResourceRejections"]
        and after["xRefreshRequests"] == before["xRefreshRequests"],
        f"callback-created read credentials did not reach the exact provider "
        f"operations without refresh or rejection: {before} -> {after}",
    )
    return {
        "gmail": {
            "status": gmail["status"],
            "requestBytesSha256": gmail["sentRequestSha256"],
            "messages": [item["id"] for item in gmail_messages],
            "metadataHydrations": 2,
        },
        "xSearch": {
            "status": x_search["status"],
            "requestBytesSha256": x_search["sentRequestSha256"],
            "resultIds": [item["id"] for item in x_items],
        },
    }


def _exercise_rust_jit(
    *,
    gate: _DecisionGateProcess,
    operator_page: Any,
    reviewer_page: Any,
    browser_observations: list[dict[str, Any]],
    public_url: str,
    simulator: OAuthProviderSimulator,
    policy_hash: str,
    credential_id: str,
    credential_version: int,
    binary_digest: str,
    screenshots_dir: Path | None,
) -> dict[str, Any]:
    from serverware import db

    simulator_port = urlsplit(simulator.base_url).port
    _require(simulator_port is not None, "simulator URL omitted its port")
    body = json.dumps(
        {"text": "Browser callback credential Rust JIT proof"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    immutable_request = (
        "POST /2/tweets HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{simulator_port}\r\n"
        "Accept: application/json\r\n"
        "Content-Type: application/json\r\n"
        "User-Agent: serverware-browser-rust-jit\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + body
    request_digest = "sha256:" + hashlib.sha256(immutable_request).hexdigest()
    before = _jit_state_snapshot(X_JIT_ROUTE_ID, credential_id)

    gate_health = gate.wait_ready(
        policy_hash=policy_hash,
        binary_digest=binary_digest,
    )
    read_routes = _exercise_rust_reads(gate=gate, simulator=simulator)
    provider_before = _simulator_resource_state(simulator)
    first_send_digest = "sha256:" + hashlib.sha256(immutable_request).hexdigest()
    first = _send_connect_tls_request(
        gate,
        authority_host="127.0.0.1",
        authority_port=simulator_port,
        request_bytes=immutable_request,
    )
    decision = first["json"]
    _require(first["status"] == 428 and isinstance(decision, dict), f"first gate request was not a JSON 428: {first}")
    approval_id = decision.get("approval_id")
    approval_url = decision.get("approval_url")
    _require(
        decision.get("action") == "jit_required"
        and decision.get("allowed") is False
        and (decision.get("payload") or {}).get("error") == "jit_grant_unavailable"
        and isinstance(approval_id, str)
        and approval_url == f"/approvals/{approval_id}"
        and decision.get("approval_status") == "pending"
        and decision.get("approval_created") is True
        and decision.get("route_id") == X_JIT_ROUTE_ID
        and decision.get("principal_id") == "agent:demo"
        and decision.get("policy_hash") == policy_hash
        and str(decision.get("request_digest") or "").startswith("sha256:")
        and str(decision.get("operation_digest") or "").startswith("sha256:")
        and (decision.get("jit") or {}).get("grant_store")
        == "atomic_release_authorization",
        f"Rust 428 lost its exact JIT binding: {decision}",
    )
    after_428 = _jit_state_snapshot(X_JIT_ROUTE_ID, credential_id)
    _require(
        len(after_428["approvals"]) == len(before["approvals"]) + 1
        and after_428["approvals"][-1]["id"] == approval_id
        and after_428["approvals"][-1]["status"] == "pending"
        and after_428["approvals"][-1]["principal_id"] == "agent:demo"
        and after_428["approvals"][-1]["credential_id"] == credential_id
        and after_428["approvals"][-1]["credential_version"]
        == credential_version
        and after_428["approvals"][-1]["policy_hash"] == policy_hash
        and after_428["approvals"][-1]["request_digest"]
        == decision.get("request_digest")
        and after_428["approvals"][-1]["operation_digest"]
        == decision.get("operation_digest")
        and after_428["credential"] == before["credential"]
        and after_428["reviewReceipts"] == before["reviewReceipts"]
        and after_428["grants"] == before["grants"]
        and after_428["attempts"] == before["attempts"]
        and after_428["credentialIssuances"] == before["credentialIssuances"]
        and after_428["quotaReservations"] == before["quotaReservations"]
        and after_428["grantConsumptions"] == before["grantConsumptions"]
        and after_428["rateLimitCounters"] == before["rateLimitCounters"]
        and _simulator_resource_state(simulator) == provider_before,
        f"initial 428 caused secret, release, quota, or upstream side effects: {before} -> {after_428}",
    )
    hot_health = gate.wait_ready(
        policy_hash=policy_hash,
        binary_digest=binary_digest,
        require_hot_generation=True,
    )

    denied_review = _api_result(
        operator_page, f"/api/approvals/{approval_id}/review"
    )
    denied_approve = _api_result(
        operator_page,
        f"/api/approvals/{approval_id}/approve",
        method="POST",
        payload={"reviewReceiptId": "00000000-0000-4000-8000-000000000000"},
    )
    _require(
        denied_review["status"] == 403 and denied_approve["status"] == 403,
        f"unlisted operator was not denied review and approval: {denied_review}, {denied_approve}",
    )
    _require(
        _jit_state_snapshot(X_JIT_ROUTE_ID, credential_id) == after_428,
        "operator denial mutated JIT authority state",
    )

    exact_approval_url = public_url + approval_url
    response = reviewer_page.goto(exact_approval_url, wait_until="domcontentloaded")
    _require(
        response is not None and response.status == 200,
        "reviewer approval URL did not return the portal",
    )
    reviewer_page.locator("#admin-token").fill(ADMIN_TOKEN)
    reviewer_page.locator("#admin-token").dispatch_event("change")
    _wait_for_portal(reviewer_page, public_url, expected_url=exact_approval_url)
    reviewer_page.wait_for_function(
        "(id) => state.approvalReview?.id === id && state.approvalReview?.review_receipt?.id",
        arg=approval_id,
        timeout=DEFAULT_TIMEOUT_MS,
    )
    review = reviewer_page.evaluate("() => state.approvalReview")
    receipt_id = (review.get("review_receipt") or {}).get("id")
    _require(
        review.get("id") == approval_id
        and review.get("status") == "pending"
        and review.get("route_id") == X_JIT_ROUTE_ID
        and review.get("principal_id") == "agent:demo"
        and review.get("credential_ref") == credential_id
        and review.get("credential_version") == credential_version
        and review.get("policy_hash") == policy_hash
        and (review.get("retry_semantics") or {}).get("request_digest")
        == decision.get("request_digest")
        and (review.get("retry_semantics") or {}).get("operation_digest")
        == decision.get("operation_digest")
        and review.get("body_hash")
        == "sha256:" + hashlib.sha256(body).hexdigest()
        and isinstance(receipt_id, str),
        f"review document did not match the Rust 428: {review}",
    )
    active_receipt = db.get_active_approval_review_receipt(
        receipt_id,
        approval_request_id=approval_id,
        reviewer_id="user:demo",
    )
    _require(
        active_receipt is not None
        and active_receipt["review_digest"] == review.get("review_digest"),
        "reviewer did not receive the exact active review receipt",
    )
    if screenshots_dir is not None:
        _capture_element_screenshot(
            reviewer_page,
            ".approval-review-context",
            screenshots_dir / "operator-portal-approval.png",
        )
    approval_button = reviewer_page.locator("#approval-review-actions").get_by_role(
        "button", name="Approve", exact=True
    )
    approval_button.click()
    reviewer_page.wait_for_function(
        "(id) => state.approvalReview?.id === id && state.approvalReview?.status === 'approved'",
        arg=approval_id,
        timeout=DEFAULT_TIMEOUT_MS,
    )
    approved = _assert_single_approval_decision(
        reviewer_page,
        browser_observations,
        approval_id,
        "approve",
        expected_request_count=2,
        expected_denied_count=1,
    )
    stored_approval = db.get_approval_request(approval_id)
    authn = (stored_approval or {}).get("approval_authn") or {}
    _require(
        approved.get("approved_by") == "user:demo"
        and authn.get("method") == "webauthn"
        and authn.get("user_id") == "user:demo"
        and authn.get("user_verified") is True
        and authn.get("review_receipt_id") == receipt_id
        and db.get_active_approval_review_receipt(
            receipt_id,
            approval_request_id=approval_id,
            reviewer_id="user:demo",
        )
        is None,
        f"review receipt or WebAuthn authority was not consumed exactly once: {stored_approval}",
    )
    options_requests = [
        item
        for item in browser_observations
        if item.get("type") == "request"
        and item.get("method") == "POST"
        and f"/api/approvals/{approval_id}/webauthn/options" in item.get("url", "")
    ]
    assertion_requests = [
        item
        for item in browser_observations
        if item.get("type") == "request"
        and item.get("method") == "POST"
        and "/api/dev/webauthn/assertion" in item.get("url", "")
    ]
    _require(
        len(options_requests) == 1 and len(assertion_requests) == 1,
        "reviewer did not perform exactly one options and WebAuthn assertion request",
    )

    approved_state = _jit_state_snapshot(X_JIT_ROUTE_ID, credential_id)
    _require(
        len(approved_state["grants"]) == 1
        and approved_state["grants"][0]["state"] == "active"
        and approved_state["grants"][0]["uses_remaining"] == 1
        and approved_state["attempts"] == before["attempts"],
        f"approval did not create exactly one unused grant: {approved_state}",
    )
    retry_send_digest = "sha256:" + hashlib.sha256(immutable_request).hexdigest()
    retry = _send_connect_tls_request(
        gate,
        authority_host="127.0.0.1",
        authority_port=simulator_port,
        request_bytes=immutable_request,
    )
    _require(
        first["sentRequestSha256"]
        == retry["sentRequestSha256"]
        == first_send_digest
        == retry_send_digest
        == request_digest
        and first["sentRequestLength"]
        == retry["sentRequestLength"]
        == len(immutable_request)
        and retry["status"] == 201
        and (retry["json"] or {}).get("data", {}).get("text")
        == "Browser callback credential Rust JIT proof",
        f"approved byte-identical retry did not reach the simulator: {retry}",
    )
    after_success = _jit_state_snapshot(X_JIT_ROUTE_ID, credential_id)
    provider_success = _simulator_resource_state(simulator)
    _require(
        len(after_success["attempts"]) == 1
        and after_success["attempts"][0]["state"] == "committed"
        and after_success["attempts"][0]["completion_outcome"] == "forwarded"
        and after_success["attempts"][0]["approval_request_id"] == approval_id
        and after_success["attempts"][0]["request_digest"]
        == decision.get("request_digest")
        and after_success["attempts"][0]["operation_digest"]
        == decision.get("operation_digest")
        and len(after_success["credentialIssuances"]) == 1
        and len(after_success["quotaReservations"]) == 1
        and after_success["quotaReservations"][0]["window_kind"] == "utcDay"
        and after_success["quotaReservations"][0]["count_after"] == 1
        and after_success["quotaReservations"][0]["reservation_state"] == "committed"
        and len(after_success["grantConsumptions"]) == 1
        and after_success["grantConsumptions"][0]["uses_remaining_before"] == 1
        and after_success["grantConsumptions"][0]["uses_remaining_after"] == 0
        and after_success["grants"][0]["state"] == "consumed"
        and after_success["grants"][0]["uses_remaining"] == 0
        and after_success["credential"] == before["credential"]
        and provider_success["xResourceRequests"]
        == provider_before["xResourceRequests"] + 1
        and provider_success["tweetCreates"] == provider_before["tweetCreates"] + 1
        and provider_success["xRefreshRequests"] == provider_before["xRefreshRequests"],
        f"approved retry lost callback-token or atomic lifecycle evidence: {after_success}, {provider_success}",
    )

    third = _send_connect_tls_request(
        gate,
        authority_host="127.0.0.1",
        authority_port=simulator_port,
        request_bytes=immutable_request,
    )
    third_decision = third["json"]
    after_third = _jit_state_snapshot(X_JIT_ROUTE_ID, credential_id)
    _require(
        third["status"] == 428
        and third_decision.get("action") == "jit_required"
        and third_decision.get("approval_created") is True
        and third_decision.get("approval_id") != approval_id
        and len(after_third["approvals"]) == len(after_success["approvals"]) + 1
        and after_third["attempts"] == after_success["attempts"]
        and after_third["credentialIssuances"] == after_success["credentialIssuances"]
        and after_third["quotaReservations"] == after_success["quotaReservations"]
        and after_third["grantConsumptions"] == after_success["grantConsumptions"]
        and after_third["rateLimitCounters"] == after_success["rateLimitCounters"]
        and _simulator_resource_state(simulator) == provider_success,
        f"one-use retry did not create a fresh side-effect-free 428: {third}, {after_third}",
    )

    unknown_request = (
        "GET /2/users/me HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{simulator_port}\r\n"
        "Accept: application/json\r\n"
        "User-Agent: serverware-browser-rust-unknown-route\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    unknown_before = _jit_state_snapshot(X_JIT_ROUTE_ID, credential_id)
    provider_unknown_before = _simulator_resource_state(simulator)
    unknown = _send_connect_tls_request(
        gate,
        authority_host="127.0.0.1",
        authority_port=simulator_port,
        request_bytes=unknown_request,
    )
    _require(
        unknown["status"] == 403
        and (unknown["json"] or {}).get("payload", {}).get("error")
        == "unknown_route_denied"
        and _jit_state_snapshot(X_JIT_ROUTE_ID, credential_id) == unknown_before
        and _simulator_resource_state(simulator) == provider_unknown_before,
        f"same-authority unknown route did not fail before secret/JIT/upstream effects: {unknown}",
    )
    return {
        "approvalId": approval_id,
        "freshApprovalId": third_decision["approval_id"],
        "requestBytesSha256": request_digest,
        "requestBytesLength": len(immutable_request),
        "requestDigest": decision["request_digest"],
        "operationDigest": decision["operation_digest"],
        "credentialVersion": credential_version,
        "readRoutes": read_routes,
        "retryStatus": retry["status"],
        "unknownRouteStatus": unknown["status"],
        "gateHealth": gate_health,
        "hotGateHealth": hot_health,
    }


def _exercise_one_npm_jit_operation(
    *,
    gate: _DecisionGateProcess,
    operator_page: Any,
    reviewer_page: Any,
    browser_observations: list[dict[str, Any]],
    public_url: str,
    registry: _NpmRegistryFixture,
    policy_hash: str,
    credential_version: int,
    operation: str,
) -> dict[str, Any]:
    from serverware import db

    immutable_request, expected_response = _npm_request_bytes(registry, operation)
    request_bytes_sha256 = (
        "sha256:" + hashlib.sha256(immutable_request).hexdigest()
    )
    _, _, body = immutable_request.partition(b"\r\n\r\n")
    body_sha256 = "sha256:" + hashlib.sha256(body).hexdigest()
    before = _jit_state_snapshot(NPM_JIT_ROUTE_ID, NPM_CREDENTIAL_ID)
    registry_before = registry.observations()

    first = _send_connect_tls_request(
        gate,
        authority_host="127.0.0.1",
        authority_port=registry.port,
        request_bytes=immutable_request,
    )
    decision = first["json"]
    _require(
        first["status"] == 428
        and isinstance(decision, dict)
        and decision.get("action") == "jit_required"
        and decision.get("allowed") is False
        and (decision.get("payload") or {}).get("error")
        == "jit_grant_unavailable"
        and decision.get("route_id") == NPM_JIT_ROUTE_ID
        and decision.get("principal_id") == "agent:demo"
        and decision.get("policy_hash") == policy_hash
        and isinstance(decision.get("approval_id"), str)
        and decision.get("approval_url")
        == f"/approvals/{decision.get('approval_id')}"
        and decision.get("approval_status") == "pending"
        and decision.get("approval_created") is True
        and str(decision.get("request_digest") or "").startswith("sha256:")
        and str(decision.get("operation_digest") or "").startswith("sha256:")
        and (decision.get("jit") or {}).get("grant_store")
        == "atomic_release_authorization",
        f"{operation} initial Rust request did not create an exact JIT 428: {first}",
    )
    approval_id = decision["approval_id"]
    after_428 = _jit_state_snapshot(NPM_JIT_ROUTE_ID, NPM_CREDENTIAL_ID)
    approval_rows = [
        item for item in after_428["approvals"] if item["id"] == approval_id
    ]
    _require(
        len(after_428["approvals"]) == len(before["approvals"]) + 1
        and len(approval_rows) == 1
        and approval_rows[0]["status"] == "pending"
        and approval_rows[0]["principal_id"] == "agent:demo"
        and approval_rows[0]["credential_id"] == NPM_CREDENTIAL_ID
        and approval_rows[0]["credential_version"] == credential_version
        and approval_rows[0]["policy_hash"] == policy_hash
        and approval_rows[0]["request_digest"] == decision["request_digest"]
        and approval_rows[0]["operation_digest"] == decision["operation_digest"]
        and after_428["credential"] == before["credential"]
        and after_428["reviewReceipts"] == before["reviewReceipts"]
        and after_428["grants"] == before["grants"]
        and after_428["attempts"] == before["attempts"]
        and after_428["credentialIssuances"] == before["credentialIssuances"]
        and after_428["quotaReservations"] == before["quotaReservations"]
        and after_428["grantConsumptions"] == before["grantConsumptions"]
        and after_428["rateLimitCounters"] == before["rateLimitCounters"]
        and after_428["releaseEventCount"] == before["releaseEventCount"]
        and registry.observations() == registry_before,
        f"{operation} initial 428 caused credential, release, or upstream effects",
    )

    denied_review = _api_result(
        operator_page,
        f"/api/approvals/{approval_id}/review",
    )
    denied_approve = _api_result(
        operator_page,
        f"/api/approvals/{approval_id}/approve",
        method="POST",
        payload={"reviewReceiptId": "00000000-0000-4000-8000-000000000000"},
    )
    _require(
        denied_review["status"] == 403 and denied_approve["status"] == 403,
        f"{operation} requester was not denied review and approval",
    )
    _require(
        _jit_state_snapshot(NPM_JIT_ROUTE_ID, NPM_CREDENTIAL_ID) == after_428,
        f"{operation} requester denials mutated JIT state",
    )

    assertion_requests_before = sum(
        1
        for item in browser_observations
        if item.get("type") == "request"
        and item.get("method") == "POST"
        and "/api/dev/webauthn/assertion" in item.get("url", "")
    )
    exact_approval_url = public_url + decision["approval_url"]
    response = reviewer_page.goto(exact_approval_url, wait_until="domcontentloaded")
    _require(
        response is not None and response.status == 200,
        f"{operation} reviewer deep link did not return the portal",
    )
    reviewer_page.locator("#admin-token").fill(ADMIN_TOKEN)
    reviewer_page.locator("#admin-token").dispatch_event("change")
    _wait_for_portal(
        reviewer_page,
        public_url,
        expected_url=exact_approval_url,
    )
    reviewer_page.wait_for_function(
        "(id) => state.approvalReview?.id === id && state.approvalReview?.review_receipt?.id",
        arg=approval_id,
        timeout=DEFAULT_TIMEOUT_MS,
    )
    review = reviewer_page.evaluate("() => state.approvalReview")
    receipt_id = (review.get("review_receipt") or {}).get("id")
    operation_fields = review.get("normalized_operation_fields") or {}
    _require(
        review.get("id") == approval_id
        and review.get("status") == "pending"
        and review.get("route_id") == NPM_JIT_ROUTE_ID
        and review.get("principal_id") == "agent:demo"
        and review.get("credential_ref") == NPM_CREDENTIAL_ID
        and review.get("credential_version") == credential_version
        and review.get("policy_hash") == policy_hash
        and review.get("body_hash") == body_sha256
        and (review.get("retry_semantics") or {}).get("request_digest")
        == decision["request_digest"]
        and (review.get("retry_semantics") or {}).get("operation_digest")
        == decision["operation_digest"]
        and (review.get("retry_semantics") or {}).get("agent_action")
        == "retry-identical-request-through-proxy"
        and (review.get("retry_semantics") or {}).get(
            "agent_receives_secret_or_token"
        )
        is False
        and operation_fields.get("operation") == operation
        and isinstance(receipt_id, str),
        f"{operation} browser review did not expose its exact safe operation binding: {review}",
    )
    if operation in {
        "npm.publish",
        "npm.unpublish",
        "npm.distTagWrite",
        "npm.metadataWrite",
    }:
        _require(
            operation_fields.get("packageName") == NPM_PACKAGE_NAME,
            f"{operation} review lost its package binding: {operation_fields}",
        )
    if operation == "npm.publish":
        _require(
            operation_fields.get("packageVersion") == NPM_PACKAGE_VERSION
            and str(operation_fields.get("tarballIntegrity") or "").startswith(
                "sha512-"
            ),
            f"{operation} review lost its version or derived integrity binding",
        )
    active_receipt = db.get_active_approval_review_receipt(
        receipt_id,
        approval_request_id=approval_id,
        reviewer_id="user:demo",
    )
    _require(
        active_receipt is not None
        and active_receipt["review_digest"] == review.get("review_digest"),
        f"{operation} reviewer did not receive the active exact-review receipt",
    )

    reviewer_page.locator("#approval-review-actions").get_by_role(
        "button",
        name="Approve",
        exact=True,
    ).click()
    reviewer_page.wait_for_function(
        "(id) => state.approvalReview?.id === id && state.approvalReview?.status === 'approved'",
        arg=approval_id,
        timeout=DEFAULT_TIMEOUT_MS,
    )
    approved = _assert_single_approval_decision(
        reviewer_page,
        browser_observations,
        approval_id,
        "approve",
        expected_request_count=2,
        expected_denied_count=1,
    )
    stored_approval = db.get_approval_request(approval_id)
    authn = (stored_approval or {}).get("approval_authn") or {}
    assertion_requests_after = sum(
        1
        for item in browser_observations
        if item.get("type") == "request"
        and item.get("method") == "POST"
        and "/api/dev/webauthn/assertion" in item.get("url", "")
    )
    operation_options_requests = [
        item
        for item in browser_observations
        if item.get("type") == "request"
        and item.get("method") == "POST"
        and f"/api/approvals/{approval_id}/webauthn/options"
        in item.get("url", "")
    ]
    _require(
        approved.get("approved_by") == "user:demo"
        and authn.get("method") == "webauthn"
        and authn.get("user_id") == "user:demo"
        and authn.get("user_verified") is True
        and authn.get("review_receipt_id") == receipt_id
        and len(operation_options_requests) == 1
        and assertion_requests_after == assertion_requests_before + 1
        and db.get_active_approval_review_receipt(
            receipt_id,
            approval_request_id=approval_id,
            reviewer_id="user:demo",
        )
        is None,
        f"{operation} did not consume one browser WebAuthn review authority",
    )

    approved_state = _jit_state_snapshot(NPM_JIT_ROUTE_ID, NPM_CREDENTIAL_ID)
    grants = [
        item
        for item in approved_state["grants"]
        if item["approval_request_id"] == approval_id
    ]
    _require(
        len(grants) == 1
        and grants[0]["state"] == "active"
        and grants[0]["uses_remaining"] == 1
        and approved_state["attempts"] == before["attempts"],
        f"{operation} approval did not create exactly one unused grant",
    )

    retry = _send_connect_tls_request(
        gate,
        authority_host="127.0.0.1",
        authority_port=registry.port,
        request_bytes=immutable_request,
    )
    _require(
        first["sentRequestSha256"]
        == retry["sentRequestSha256"]
        == request_bytes_sha256
        and first["sentRequestLength"]
        == retry["sentRequestLength"]
        == len(immutable_request)
        and retry["status"] == 200
        and retry["json"] == expected_response,
        f"{operation} approved byte-identical retry failed: {retry}",
    )
    after_success = _jit_state_snapshot(NPM_JIT_ROUTE_ID, NPM_CREDENTIAL_ID)
    registry_success = registry.observations()
    attempts = [
        item
        for item in after_success["attempts"]
        if item["approval_request_id"] == approval_id
    ]
    consumptions = [
        item
        for item in after_success["grantConsumptions"]
        if item["approval_request_id"] == approval_id
    ]
    success_grants = [
        item
        for item in after_success["grants"]
        if item["approval_request_id"] == approval_id
    ]
    issuance_attempt_ids = {
        item["attempt_id"] for item in after_success["credentialIssuances"]
    }
    operation_events = [
        item
        for item in registry_success["events"]
        if item.get("operation") == operation
    ]
    _require(
        len(after_success["attempts"]) == len(before["attempts"]) + 1
        and len(attempts) == 1
        and attempts[0]["state"] == "committed"
        and attempts[0]["completion_outcome"] == "forwarded"
        and attempts[0]["request_digest"] == decision["request_digest"]
        and attempts[0]["operation_digest"] == decision["operation_digest"]
        and attempts[0]["attempt_id"] in issuance_attempt_ids
        and len(after_success["credentialIssuances"])
        == len(before["credentialIssuances"]) + 1
        and after_success["quotaReservations"] == before["quotaReservations"]
        and len(after_success["grantConsumptions"])
        == len(before["grantConsumptions"]) + 1
        and len(consumptions) == 1
        and consumptions[0]["uses_remaining_before"] == 1
        and consumptions[0]["uses_remaining_after"] == 0
        and len(success_grants) == 1
        and success_grants[0]["state"] == "consumed"
        and success_grants[0]["uses_remaining"] == 0
        and after_success["credential"] == before["credential"]
        and after_success["releaseEventCount"] > before["releaseEventCount"]
        and registry_success["counts"][operation]
        == registry_before["counts"][operation] + 1
        and registry_success["counts"]["rejected"]
        == registry_before["counts"]["rejected"]
        and len(operation_events) == 1
        and operation_events[0]["bodySha256"] == body_sha256
        and operation_events[0]["authorizationPresent"] is True
        and operation_events[0]["authorizationScheme"] == "Bearer",
        f"{operation} approved retry lost atomic release or upstream evidence",
    )

    third = _send_connect_tls_request(
        gate,
        authority_host="127.0.0.1",
        authority_port=registry.port,
        request_bytes=immutable_request,
    )
    third_decision = third["json"]
    after_third = _jit_state_snapshot(NPM_JIT_ROUTE_ID, NPM_CREDENTIAL_ID)
    _require(
        third["status"] == 428
        and isinstance(third_decision, dict)
        and third_decision.get("action") == "jit_required"
        and third_decision.get("approval_created") is True
        and third_decision.get("approval_id") != approval_id
        and len(after_third["approvals"]) == len(after_success["approvals"]) + 1
        and after_third["attempts"] == after_success["attempts"]
        and after_third["credentialIssuances"]
        == after_success["credentialIssuances"]
        and after_third["quotaReservations"] == after_success["quotaReservations"]
        and after_third["grantConsumptions"]
        == after_success["grantConsumptions"]
        and after_third["rateLimitCounters"]
        == after_success["rateLimitCounters"]
        and registry.observations() == registry_success,
        f"{operation} one-use grant did not produce a fresh side-effect-free 428",
    )
    return {
        "operation": operation,
        "approvalId": approval_id,
        "freshApprovalId": third_decision["approval_id"],
        "requestBytesSha256": request_bytes_sha256,
        "requestBytesLength": len(immutable_request),
        "requestDigest": decision["request_digest"],
        "operationDigest": decision["operation_digest"],
        "retryStatus": retry["status"],
    }


def _exercise_rust_npm(
    *,
    gate: _DecisionGateProcess,
    operator_page: Any,
    reviewer_page: Any,
    browser_observations: list[dict[str, Any]],
    public_url: str,
    registry: _NpmRegistryFixture,
    policy_hash: str,
    credential_version: int,
) -> dict[str, Any]:
    operations = [
        "npm.publish",
        "npm.unpublish",
        "npm.distTagWrite",
        "npm.tokenWrite",
        "npm.metadataWrite",
    ]
    journeys = [
        _exercise_one_npm_jit_operation(
            gate=gate,
            operator_page=operator_page,
            reviewer_page=reviewer_page,
            browser_observations=browser_observations,
            public_url=public_url,
            registry=registry,
            policy_hash=policy_hash,
            credential_version=credential_version,
            operation=operation,
        )
        for operation in operations
    ]
    _require(
        len({item["requestBytesSha256"] for item in journeys}) == len(operations)
        and len({item["requestDigest"] for item in journeys}) == len(operations)
        and len({item["operationDigest"] for item in journeys}) == len(operations),
        "npm operation journeys did not retain distinct immutable request bindings",
    )

    before_token_create = _jit_state_snapshot(
        NPM_JIT_ROUTE_ID,
        NPM_CREDENTIAL_ID,
    )
    registry_before_token_create = registry.observations()
    token_create_request, _ = _npm_request_bytes(registry, "npm.tokenCreate")
    token_create = _send_connect_tls_request(
        gate,
        authority_host="127.0.0.1",
        authority_port=registry.port,
        request_bytes=token_create_request,
    )
    token_create_payload = token_create["json"] or {}
    _require(
        token_create["status"] == 403
        and token_create_payload.get("action") == "deny"
        and (token_create_payload.get("payload") or {}).get("error")
        == "npm_token_creation_denied"
        and _jit_state_snapshot(NPM_JIT_ROUTE_ID, NPM_CREDENTIAL_ID)
        == before_token_create
        and registry.observations() == registry_before_token_create,
        f"npm token creation did not fail before JIT, credential release, or upstream: {token_create}",
    )

    final_registry = registry.observations()
    _require(
        all(final_registry["counts"][operation] == 1 for operation in operations)
        and final_registry["counts"]["npm.tokenCreate"] == 0
        and final_registry["counts"]["rejected"] == 0
        and len(final_registry["events"]) == len(operations),
        f"npm registry did not observe exactly the five approved write classes: {final_registry}",
    )
    return {
        "routeId": NPM_JIT_ROUTE_ID,
        "credentialId": NPM_CREDENTIAL_ID,
        "credentialVersion": credential_version,
        "writeClasses": journeys,
        "tokenCreation": {
            "status": token_create["status"],
            "error": "npm_token_creation_denied",
            "requestBytesSha256": token_create["sentRequestSha256"],
            "preSideEffectDenied": True,
        },
        "registryCounts": final_registry["counts"],
    }


def _run_browser_journey(
    public_url: str,
    data_dir: Path,
    simulator: OAuthProviderSimulator,
    npm_registry: _NpmRegistryFixture,
    screenshots_dir: Path | None,
    decision_gate_binary: Path,
    decision_gate_digest: str,
    response_proof_fixture: Path,
    install_enrollment_attestation_fixture: Callable[[], None],
) -> dict[str, Any]:
    try:
        from playwright.sync_api import sync_playwright
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Playwright is unavailable; install playwright==1.61.0 and its Chromium browser"
        ) from exc

    browser_observations: list[dict[str, Any]] = []
    console_errors: list[str] = []
    page_errors: list[str] = []
    api_documents: list[Any] = []
    gate: _DecisionGateProcess | None = None
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            args=[
                "--host-resolver-rules=MAP serverware.test 127.0.0.1",
                f"--ignore-certificate-errors-spki-list={_certificate_spki_sha256(simulator.server_cert_path)}",
                "--no-proxy-server",
                "--disable-background-networking",
            ],
        )
        context = browser.new_context(
            viewport={"width": 1440, "height": 1100},
            locale="en-US",
            timezone_id="UTC",
            reduced_motion="reduce",
            extra_http_headers={"X-Test-Actor": "operator"},
        )
        reviewer_context = browser.new_context(
            viewport={"width": 1440, "height": 1100},
            locale="en-US",
            timezone_id="UTC",
            reduced_motion="reduce",
            extra_http_headers={"X-Test-Actor": "reviewer"},
        )
        _install_dev_webauthn_shim(context)
        _install_dev_webauthn_shim(reviewer_context)
        page = context.new_page()
        reviewer_page = reviewer_context.new_page()
        page.set_default_timeout(DEFAULT_TIMEOUT_MS)
        reviewer_page.set_default_timeout(DEFAULT_TIMEOUT_MS)

        def record_request(request: Any) -> None:
            browser_observations.append(
                {"type": "request", "method": request.method, "url": request.url}
            )

        def record_response(response: Any) -> None:
            browser_observations.append(
                {"type": "response", "status": response.status, "url": response.url}
            )

        page.on("request", record_request)
        page.on("response", record_response)
        reviewer_page.on("request", record_request)
        reviewer_page.on("response", record_response)
        page.on(
            "console",
            lambda message: console_errors.append(message.text)
            if message.type == "error"
            else None,
        )
        page.on("pageerror", lambda error: page_errors.append(str(error)))
        reviewer_page.on(
            "console",
            lambda message: console_errors.append(message.text)
            if message.type == "error"
            else None,
        )
        reviewer_page.on("pageerror", lambda error: page_errors.append(str(error)))

        try:
            response = page.goto(public_url + "/", wait_until="domcontentloaded")
            _require(
                response is not None and response.status == 200,
                "portal did not return HTTP 200",
            )
            response_headers = response.headers
            expected_headers = {
                "cache-control": "no-store",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "referrer-policy": "no-referrer",
                "cross-origin-opener-policy": "same-origin",
                "cross-origin-resource-policy": "same-origin",
            }
            for name, expected in expected_headers.items():
                _require(
                    response_headers.get(name) == expected,
                    f"portal security header {name} was not {expected!r}",
                )
            _require(
                "frame-ancestors 'none'" in response_headers.get(
                    "content-security-policy", ""
                ),
                "portal CSP does not deny framing",
            )
            _require(
                response_headers.get("strict-transport-security", "").startswith(
                    "max-age=31536000"
                ),
                "HTTPS portal response omitted HSTS",
            )
            page.locator("#admin-token").fill(ADMIN_TOKEN)
            page.locator("#admin-token").dispatch_event("change")
            _wait_for_portal(page, public_url)
            token_storage = page.evaluate(
                "() => JSON.stringify({session: {...sessionStorage}, local: {...localStorage}})"
            )
            _require(
                ADMIN_TOKEN not in token_storage,
                "manually entered operator token was written to Web Storage",
            )
            page.reload(wait_until="domcontentloaded")
            _require(
                page.locator("#admin-token").input_value() == "",
                "manually entered operator token survived a portal reload",
            )
            page.locator("#admin-token").fill(ADMIN_TOKEN)
            page.locator("#admin-token").dispatch_event("change")
            _wait_for_portal(page, public_url)
            _assert_no_horizontal_overflow(page, label="desktop initial")

            page.once("dialog", lambda dialog: dialog.accept())
            page.get_by_role("button", name="Seed demo", exact=True).click()
            _wait_for_api(
                page,
                "/api/policy",
                lambda payload: payload.get("ready") is True,
            )
            _wait_for_api(
                page,
                "/api/bootstrap",
                lambda payload: any(
                    item.get("id") == "agent:demo"
                    for item in payload.get("policyPrincipals", [])
                ),
            )
            page.wait_for_function(
                """
                () => [...document.querySelectorAll('#policy-principal option')].some(
                  (item) => item.value === 'agent:demo'
                )
                """,
                timeout=DEFAULT_TIMEOUT_MS,
            )
            _assert_refresh_preserves_live_oauth_form(page)
            seed_status = page.locator("#operator-status").inner_text()
            if "failed:" in seed_status.lower():
                refresh_stack = page.evaluate(
                    """
                    async () => {
                      try {
                        await refresh();
                        return null;
                      } catch (error) {
                        return String(error?.stack || error);
                      }
                    }
                    """
                )
                raise AssertionError(
                    f"demo seed failed: {seed_status}; refresh stack: {refresh_stack}"
                )
            _assert_stripe_uses_manual_credential_flow(page, browser_observations)
            if screenshots_dir is not None:
                _capture_screenshot(
                    page,
                    ".passkey-section",
                    screenshots_dir / "operator-portal-desktop.png",
                )
                _capture_mobile_screenshot(
                    page,
                    ".passkey-section",
                    screenshots_dir / "operator-portal-mobile.png",
                )
                page.set_viewport_size({"width": 1440, "height": 1100})

            reviewer_page.goto(public_url + "/", wait_until="domcontentloaded")
            reviewer_page.locator("#admin-token").fill(ADMIN_TOKEN)
            reviewer_page.locator("#admin-token").dispatch_event("change")
            _wait_for_portal(reviewer_page, public_url)
            _require(
                reviewer_page.evaluate("state.currentUserId") == "user:demo",
                "review browser did not receive the distinct reviewer identity",
            )
            dev_credential = _api_post_json(
                reviewer_page, "/api/dev/webauthn/credential"
            )
            _require(
                dev_credential.get("user_id") == "user:demo"
                and dev_credential.get("attestation_trusted") is True,
                f"dev authenticator registration was not trusted: {dev_credential}",
            )
            _require(
                reviewer_page.evaluate(
                    "window.__serverwareDevWebAuthnShim === true"
                ),
                "browser WebAuthn shim was not installed",
            )

            page.locator("#setup-template").select_option("gmail_recent")
            page.wait_for_function(
                """
                () => {
                  const text = document.querySelector('#setup-template-summary')?.textContent || '';
                  return text.includes('Gmail messages from last 30 days')
                    && text.includes('gmail.googleapis.com')
                    && text.includes('Response age: at most 30 days')
                    && text.includes('Unknown host, path, method, or validation result is denied');
                }
                """,
                timeout=DEFAULT_TIMEOUT_MS,
            )
            page.locator("#setup-principal").select_option("agent:demo")
            page.locator("#setup-route-id").fill("browser.gmail.last-30-days")
            page.locator("#setup-connect-button").click()
            page.wait_for_function(
                """
                () => state.oauthSetupSessionId
                  && state.setupSession?.id === state.oauthSetupSessionId
                  && state.setupSession?.routeId === 'browser.gmail.last-30-days'
                  && state.setupSession?.routePolicyDigest === null
                  && document.activeElement?.id === 'oauth-provider'
                """,
                timeout=DEFAULT_TIMEOUT_MS,
            )
            google_credential = _connect_oauth(
                page,
                context,
                reviewer_page,
                public_url,
                provider="google",
                name=GOOGLE_NAME,
                scopes=GOOGLE_SCOPES,
                account="operator@example.test",
            )
            _assert_public_credential(
                google_credential,
                provider="google",
                subject="google-subject-001",
                account="operator@example.test",
                scopes=GOOGLE_SCOPES,
            )
            setup_after_google = page.evaluate("() => state.setupSession")
            _require(
                setup_after_google.get("routeId") == "browser.gmail.last-30-days"
                and setup_after_google.get("credentialId") == google_credential["id"]
                and setup_after_google.get("phase") == "credential_activated",
                f"fresh Setup OAuth flow did not bind its credential: {setup_after_google}",
            )
            if screenshots_dir is not None:
                _capture_element_screenshot(
                    page,
                    ".oauth-connect-section",
                    screenshots_dir / "operator-portal-oauth.png",
                )

            gmail_policy = _preview_stage_activate_policy(
                page,
                template="custom_json",
                route_id="browser.gmail.last-30-days",
                credential_id=google_credential["id"],
                custom_route=_localized_read_route(
                    page,
                    template_id="gmail_recent",
                    simulator=simulator,
                ),
            )
            api_documents.append(gmail_policy)

            x_credential = _connect_oauth(
                page,
                context,
                reviewer_page,
                public_url,
                provider="x",
                name=X_NAME,
                scopes=X_SCOPES,
                account="@operator_x",
            )
            _assert_public_credential(
                x_credential,
                provider="x",
                subject="x-subject-001",
                account="@operator_x",
                scopes=X_SCOPES,
            )
            _require(
                (x_credential.get("metadata") or {}).get("x_app_id")
                == simulator.X_CLIENT_ID,
                "X credential is not bound to the OAuth client app",
            )

            x_read_policy = _preview_stage_activate_policy(
                page,
                template="custom_json",
                route_id="browser.x.search.seven-days",
                credential_id=x_credential["id"],
                custom_route=_localized_read_route(
                    page,
                    template_id="x_read_recent",
                    simulator=simulator,
                ),
            )
            api_documents.append(x_read_policy)
            x_write_policy = _preview_stage_activate_policy(
                page,
                template="custom_json",
                route_id=X_JIT_ROUTE_ID,
                credential_id=x_credential["id"],
                custom_route=_x_jit_route(simulator),
            )
            api_documents.append(x_write_policy)
            final_policy = _preview_stage_activate_policy(
                page,
                template="custom_json",
                route_id=NPM_JIT_ROUTE_ID,
                credential_id=NPM_CREDENTIAL_ID,
                custom_route=_npm_jit_route(npm_registry),
            )
            _assert_policy_evidence(
                final_policy,
                google_credential["id"],
                x_credential["id"],
                simulator,
                npm_registry,
            )
            if screenshots_dir is not None:
                _capture_element_screenshot(
                    page,
                    ".policy-authoring-section",
                    screenshots_dir / "operator-portal-policy.png",
                )

            final_bootstrap = _api_json(page, "/api/bootstrap")
            final_policy_api = _api_json(page, "/api/policy")
            api_documents.extend([final_bootstrap, final_policy_api])
            from serverware import db

            stored_x_credential = db.get_credential(x_credential["id"])
            stored_npm_credential = db.get_credential(NPM_CREDENTIAL_ID)
            _require(
                stored_x_credential is not None,
                "callback-created X credential disappeared before Rust startup",
            )
            _require(
                stored_npm_credential is not None,
                "seeded npm credential disappeared before Rust startup",
            )
            x_credential_version = int(
                stored_x_credential["credential_version"]
            )
            npm_credential_version = int(
                stored_npm_credential["credential_version"]
            )
            gate = _DecisionGateProcess(
                binary=decision_gate_binary,
                response_proof_fixture=response_proof_fixture,
                data_dir=data_dir,
                portal_url=public_url,
                simulator=simulator,
            )
            gate.start()
            rust_jit = _exercise_rust_jit(
                gate=gate,
                operator_page=page,
                reviewer_page=reviewer_page,
                browser_observations=browser_observations,
                public_url=public_url,
                simulator=simulator,
                policy_hash=final_policy_api["policy_hash"],
                credential_id=x_credential["id"],
                credential_version=x_credential_version,
                binary_digest=decision_gate_digest,
                screenshots_dir=screenshots_dir,
            )
            api_documents.append(rust_jit)
            rust_npm = _exercise_rust_npm(
                gate=gate,
                operator_page=page,
                reviewer_page=reviewer_page,
                browser_observations=browser_observations,
                public_url=public_url,
                registry=npm_registry,
                policy_hash=final_policy_api["policy_hash"],
                credential_version=npm_credential_version,
            )
            api_documents.append(rust_npm)
            gate.close()
            gate = None
            install_enrollment_attestation_fixture()
            page.locator("#enrollment-principal").select_option("agent:demo")
            with page.expect_response(
                lambda item: item.request.method == "POST"
                and item.url.endswith("/api/agents/enrollment"),
                timeout=DEFAULT_TIMEOUT_MS,
            ) as enrollment_response_info:
                page.locator("#agent-enrollment-form button[type='submit']").click()
            enrollment_response = enrollment_response_info.value
            enrollment_response_bytes = enrollment_response.body()
            enrollment_response_sha256 = enrollment_response.headers.get(
                "x-serverware-enrollment-packet-sha256"
            )
            observed_enrollment_response_sha256 = (
                "sha256:"
                + hashlib.sha256(enrollment_response_bytes).hexdigest()
            )
            _require(
                enrollment_response.status == 200
                and {
                    item.strip()
                    for item in enrollment_response.headers.get(
                        "cache-control", ""
                    ).split(",")
                    if item.strip()
                }
                == {"no-store"}
                and {
                    item.strip()
                    for item in enrollment_response.headers.get(
                        "x-content-type-options", ""
                    ).split(",")
                    if item.strip()
                }
                == {"nosniff"}
                and enrollment_response.headers.get("content-type", "")
                .split(";", 1)[0]
                .strip()
                .lower()
                == "application/json"
                and enrollment_response_sha256
                == observed_enrollment_response_sha256,
                "enrollment API response did not authenticate its exact canonical "
                f"bytes: status={enrollment_response.status}, "
                f"headers={enrollment_response.headers}, "
                f"observedSha256={observed_enrollment_response_sha256}",
            )
            try:
                page.wait_for_function(
                    """
                    ({policyHash, routeId, credentialId}) => {
                      const packet = state.enrollmentPacket;
                      return packet?.apiVersion === 'serverware.agentEnrollment/v1'
                        && packet?.principalId === 'agent:demo'
                        && packet?.pinning?.policyHash === policyHash
                        && (packet?.allowedRoutes || []).some(
                          (item) => item.id === routeId
                            && item.credentialRef === credentialId
                        );
                    }
                    """,
                    arg={
                        "policyHash": final_policy_api["policy_hash"],
                        "routeId": "browser.gmail.last-30-days",
                        "credentialId": google_credential["id"],
                    },
                    timeout=DEFAULT_TIMEOUT_MS,
                )
            except Exception as exc:
                diagnostics = page.evaluate(
                    """
                    () => ({
                      status: document.querySelector('#operator-status')?.textContent || '',
                      packet: state.enrollmentPacket,
                      principal: document.querySelector('#enrollment-principal')?.value || '',
                      output: (document.querySelector('#enrollment-output')?.value || '').slice(0, 2000)
                    })
                    """
                )
                raise AssertionError(
                    f"browser enrollment packet did not bind the Gmail assignment: {diagnostics}"
                ) from exc
            if screenshots_dir is not None:
                _capture_element_screenshot(
                    page,
                    "section:has(#agent-enrollment-form)",
                    screenshots_dir / "operator-portal-enrollment.png",
                )
            with page.expect_download(timeout=DEFAULT_TIMEOUT_MS) as download_info:
                page.get_by_role("button", name="Download", exact=True).click()
            download = download_info.value
            packet_path = Path(download.path())
            packet_bytes = packet_path.read_bytes()
            _require(
                0 < len(packet_bytes) <= 1024 * 1024,
                "downloaded enrollment packet has an invalid size",
            )
            enrollment_packet = json.loads(packet_bytes)
            state_packet = page.evaluate("() => state.enrollmentPacket")
            state_packet_text = page.evaluate("() => state.enrollmentPacketText")
            state_packet_sha256 = page.evaluate(
                "() => state.enrollmentPacketFileSha256"
            )
            _require(
                packet_bytes == enrollment_response_bytes
                and state_packet_text.encode("utf-8") == enrollment_response_bytes
                and state_packet_sha256 == enrollment_response_sha256
                and enrollment_packet == state_packet,
                "downloaded enrollment packet differs from the authenticated API response bytes",
            )
            _require(
                download.suggested_filename
                == "serverware-enrollment-agent-demo.json",
                "downloaded enrollment packet filename is not principal-bound",
            )
            unknown_route_canaries = [
                item
                for item in (enrollment_packet.get("canaries", {}).get("deny") or [])
                if item.get("expectedError") == "unknown_route_denied"
            ]
            _require(
                len(unknown_route_canaries) == 1
                and unknown_route_canaries[0].get("expectedStatus") == 403,
                "enrollment packet does not bind one fail-closed unknown-route canary",
            )
            enrollment_packet_sha256 = enrollment_response_sha256
            api_documents.append(enrollment_packet)
            _require(
                not final_bootstrap.get("pendingOAuthCredentials"),
                "browser journey left a pending OAuth credential",
            )
            _require(
                not final_bootstrap.get("oauthIssuanceUncertainties"),
                "browser journey left uncertain provider issuance",
            )
            _assert_no_oauth_cookies(context)
            state_path = data_dir / "oauth-states.json"
            if state_path.exists():
                state_document = json.loads(state_path.read_text(encoding="utf-8"))
                _require(
                    state_document.get("states") == {},
                    "consumed OAuth state remains on disk",
                )

            page.set_viewport_size({"width": 390, "height": 844})
            page.evaluate("window.scrollTo(0, 0)")
            page.wait_for_timeout(100)
            _assert_no_horizontal_overflow(page, label="mobile final")
            page.set_viewport_size({"width": 1440, "height": 1100})
            page.evaluate("window.scrollTo(0, 0)")
            page.wait_for_timeout(100)
            _assert_no_horizontal_overflow(page, label="desktop final")

            _require(not page_errors, f"browser page errors occurred: {page_errors}")
            expected_activation_challenges = [
                item
                for item in browser_observations
                if item.get("type") == "response"
                and item.get("status") == 428
                and re.search(
                    r"/api/oauth/pending/[^/]+/activate$",
                    str(item.get("url") or ""),
                )
            ]
            _require(
                len(expected_activation_challenges) == 2,
                "browser journey did not observe exactly one two-person activation "
                "challenge for each OAuth credential",
            )
            expected_separation_denials = [
                item
                for item in browser_observations
                if item.get("type") == "response"
                and item.get("status") == 403
                and (
                    re.search(
                        r"/api/control-plane/approvals/[^/]+/approve$",
                        str(item.get("url") or ""),
                    )
                    or re.search(
                        r"/api/oauth/pending/[^/]+/activate$",
                        str(item.get("url") or ""),
                    )
                )
            ]
            _require(
                len(expected_separation_denials) == 4,
                "browser journey did not observe requester self-approval and reviewer "
                "direct-activation denials for both OAuth credentials",
            )
            jit_separation_denials = [
                item
                for item in browser_observations
                if item.get("type") == "response"
                and item.get("status") == 403
                and re.search(
                    rf"/api/approvals/{re.escape(rust_jit['approvalId'])}/(?:review|approve)$",
                    str(item.get("url") or ""),
                )
            ]
            _require(
                len(jit_separation_denials) == 2,
                "browser journey did not observe operator review and approval denials",
            )
            npm_approval_ids = {
                item["approvalId"] for item in rust_npm["writeClasses"]
            }
            npm_jit_separation_denials = [
                item
                for item in browser_observations
                if item.get("type") == "response"
                and item.get("status") == 403
                and any(
                    re.search(
                        rf"/api/approvals/{re.escape(approval_id)}/(?:review|approve)$",
                        str(item.get("url") or ""),
                    )
                    for approval_id in npm_approval_ids
                )
            ]
            _require(
                len(npm_jit_separation_denials) == 2 * len(npm_approval_ids),
                "browser journey did not observe requester review and approval denials "
                "for every npm write class",
            )
            expected_console_428 = (
                "Failed to load resource: the server responded with a status of 428 "
                "(Precondition Required)"
            )
            expected_console_403 = (
                "Failed to load resource: the server responded with a status of 403 "
                "(Forbidden)"
            )
            unexpected_console_errors = [
                message
                for message in console_errors
                if message not in {expected_console_428, expected_console_403}
            ]
            _require(
                console_errors.count(expected_console_428) == 2
                and console_errors.count(expected_console_403) == 16
                and not unexpected_console_errors,
                f"browser console errors occurred: {console_errors}",
            )
            _assert_storage_and_disk_do_not_leak_tokens(
                page,
                context,
                data_dir,
                simulator,
                api_documents,
                browser_observations,
            )
            _assert_storage_and_disk_do_not_leak_tokens(
                reviewer_page,
                reviewer_context,
                data_dir,
                simulator,
                api_documents,
                browser_observations,
            )
            observations = _assert_provider_observations(simulator)
            return {
                "ok": True,
                "portalUrl": public_url,
                "credentials": {
                    "google": google_credential["id"],
                    "x": x_credential["id"],
                },
                "oauthActivationApprovals": {
                    "google": google_credential["browserApprovalId"],
                    "x": x_credential["browserApprovalId"],
                    "approvedBy": "user:demo",
                    "requestedBy": "user:operator",
                },
                "enrollment": {
                    "filename": download.suggested_filename,
                    "packetSha256": enrollment_packet_sha256,
                    "principalId": enrollment_packet["principalId"],
                    "policyHash": enrollment_packet["pinning"]["policyHash"],
                    "gmailRoute": "browser.gmail.last-30-days",
                    "unknownRouteCanary": unknown_route_canaries[0],
                },
                "rustJit": rust_jit,
                "rustNpm": rust_npm,
                "policyHash": final_policy_api["policy_hash"],
                "routes": [
                    "browser.gmail.last-30-days",
                    "browser.x.search.seven-days",
                    X_JIT_ROUTE_ID,
                    NPM_JIT_ROUTE_ID,
                ],
                "providerCounts": observations["counts"],
                "testAssurance": {
                    "productionProof": False,
                    "identity": "header-selected-distinct-test-subjects",
                    "webauthn": "server-generated-development-authenticator",
                    "attestation": (
                        "signed-development-consistency; no TEE workload custody"
                    ),
                    "jitOrigin": "measured-host-rust-connect-tls",
                    "dataPlaneBinaryDigest": decision_gate_digest,
                    "byteIdenticalRetry": True,
                    "oneUseGrantSequentialRuntimeAsserted": True,
                    "oauthActivationChallenges": len(
                        expected_activation_challenges
                    ),
                    "oauthSeparationDenials": len(expected_separation_denials),
                    "jitSeparationDenials": len(jit_separation_denials),
                    "npmJitSeparationDenials": len(
                        npm_jit_separation_denials
                    ),
                    "npmWriteClassesThroughRust": len(
                        rust_npm["writeClasses"]
                    ),
                    "npmTokenCreationDeniedPreSideEffect": True,
                    "downloadedPacketExactBytesVerified": True,
                    "enrollmentResponseDigestHeaderVerified": True,
                    "unknownRouteRuntimeAsserted": True,
                },
                "screenshots": str(screenshots_dir)
                if screenshots_dir is not None
                else None,
            }
        finally:
            if gate is not None:
                gate.close()
            reviewer_context.close()
            context.close()
            browser.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Drive the real HTTPS Serverware portal through deterministic Google and X OAuth"
    )
    parser.add_argument(
        "--screenshots-dir",
        type=Path,
        help="refresh the canonical portal, approval, OAuth, and policy screenshots",
    )
    parser.add_argument(
        "--decision-gate-binary",
        type=Path,
        default=ROOT
        / "data-plane"
        / "decision-gate-rs"
        / "target"
        / "debug"
        / "serverware-decision-gate",
    )
    parser.add_argument(
        "--response-proof-fixture",
        type=Path,
        default=ROOT
        / "data-plane"
        / "decision-gate-rs"
        / "target"
        / "debug"
        / "serverware-response-proof-fixture",
    )
    args = parser.parse_args()
    screenshots_dir = args.screenshots_dir.resolve() if args.screenshots_dir else None
    decision_gate_binary = args.decision_gate_binary.resolve()
    response_proof_fixture = args.response_proof_fixture.resolve()
    _require(
        decision_gate_binary.is_file(),
        f"build the host decision gate before this journey: {decision_gate_binary}",
    )
    _require(
        response_proof_fixture.is_file(),
        f"build the response proof fixture before this journey: {response_proof_fixture}",
    )
    decision_gate_digest = _sha256_path(decision_gate_binary)
    if screenshots_dir is not None:
        screenshots_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        prefix="serverware-oauth-contract-"
    ) as raw_contract_tmp:
        _assert_redirect_validation(Path(raw_contract_tmp))
    with tempfile.TemporaryDirectory(prefix="serverware-browser-oauth-") as raw_tmp:
        tmp = Path(raw_tmp)
        listener = _reserve_https_socket()
        portal_port = int(listener.getsockname()[1])
        public_url = f"https://serverware.test:{portal_port}"
        simulator = OAuthProviderSimulator(
            tmp / "provider",
            redirect_base_url=public_url,
            authorization_token_ttl_seconds=300,
        )
        npm_registry: _NpmRegistryFixture | None = None
        portal: _UvicornThread | None = None
        original_providers: Any = None
        original_request_bytes: Any = None
        original_reconciler: Any = None
        original_attestation_document: Any = None
        oauth_module: Any = None
        app_module: Any = None
        try:
            simulator.start()
            _assert_simulator_contract(simulator)
            npm_registry = _NpmRegistryFixture(simulator)
            npm_registry.start()
            _configure_environment(
                tmp / "serverware",
                public_url,
                simulator,
                decision_gate_digest,
            )

            from serverware import app as app_module
            from serverware import oauth as oauth_module
            from fastapi import HTTPException, Request
            from serverware.auth import AdminIdentity, require_admin
            from serverware.response_identity import response_public_key_info

            identities = {
                "operator": AdminIdentity(
                    "user:operator",
                    frozenset(
                        {
                            "admin",
                            "approver",
                            "auditor",
                            "policy_author",
                            "policy_publisher",
                            "credential_owner",
                            "attestation_operator",
                            "attestation_reviewer",
                        }
                    ),
                    "browser-test-actor",
                ),
                "reviewer": AdminIdentity(
                    "user:demo",
                    frozenset({"admin", "approver", "auditor", "credential_owner"}),
                    "browser-test-actor",
                ),
            }

            def test_require_admin(request: Request) -> AdminIdentity:
                identity = identities.get(request.headers.get("X-Test-Actor", ""))
                if identity is None:
                    raise HTTPException(
                        status_code=401, detail="recognized browser actor required"
                    )
                return identity

            test_require_admin.__annotations__["request"] = Request
            app_module.app.dependency_overrides[require_admin] = test_require_admin

            original_providers = oauth_module._providers
            configured = original_providers()
            google_provider = replace(
                configured["google"],
                **simulator.provider_urls("google"),
            )
            x_provider = replace(configured["x"], **simulator.provider_urls("x"))
            oauth_module._providers = lambda: {
                "google": google_provider,
                "x": x_provider,
                "twitter": x_provider,
            }

            original_request_bytes = oauth_module.request_bytes

            def trusted_provider_request(request: Any, **kwargs: Any) -> Any:
                kwargs["context"] = simulator.client_ssl_context
                return original_request_bytes(request, **kwargs)

            oauth_module.request_bytes = trusted_provider_request
            original_reconciler = app_module._start_oauth_revocation_reconciler
            app_module._start_oauth_revocation_reconciler = lambda: None
            original_attestation_document = app_module.attestation_document

            def install_enrollment_attestation_fixture() -> None:
                def browser_attestation_document(
                    nonce: str | None = None,
                ) -> dict[str, Any]:
                    snapshot = app_module.get_policy_snapshot()
                    if snapshot is None:
                        return original_attestation_document(nonce)
                    metadata = snapshot.raw.get("metadata") or {}
                    return {
                        "nonce": nonce,
                        "policy_bundle_digest": snapshot.hash,
                        "policy_signing_key_id": metadata.get("signingKeyId"),
                        "policy_sequence": metadata.get("sequence"),
                        "rollback_epoch": metadata.get("rollbackEpoch"),
                        "policy_high_water_digest": "sha256:" + "1" * 64,
                        "release_channel": "dev",
                        "ca_intermediate_spki_sha256": "sha256:" + "2" * 64,
                        "data_plane_binary_digest": decision_gate_digest,
                        "runtime_manifest_digest": "sha256:" + "3" * 64,
                        "response_signing_key_id": response_public_key_info()[
                            "spki_sha256"
                        ],
                        "provenance_digest": "sha256:" + "5" * 64,
                        "image_signatures_digest": "sha256:" + "6" * 64,
                        "source_tree_digest": "sha256:" + "7" * 64,
                        "assurance": {
                            "class": "deterministic-browser-simulator",
                            "fact_origin": "test-fixture",
                            "hardware_proof": False,
                            "workload_custody_proven": False,
                            "tls_peer_binding_proven": False,
                            "reason": (
                                "Enrollment UI contract fixture installed only after "
                                "the measured Rust gate proof completed."
                            ),
                        },
                    }

                app_module.attestation_document = browser_attestation_document

            portal = _UvicornThread(app_module.app, listener, simulator)
            portal.start()
            result = _run_browser_journey(
                public_url,
                tmp / "serverware",
                simulator,
                npm_registry,
                screenshots_dir,
                decision_gate_binary,
                decision_gate_digest,
                response_proof_fixture,
                install_enrollment_attestation_fixture,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
        finally:
            if portal is not None:
                portal.close()
            else:
                listener.close()
            if oauth_module is not None:
                if original_providers is not None:
                    oauth_module._providers = original_providers
                if original_request_bytes is not None:
                    oauth_module.request_bytes = original_request_bytes
            if app_module is not None and original_reconciler is not None:
                app_module._start_oauth_revocation_reconciler = original_reconciler
            if app_module is not None and original_attestation_document is not None:
                app_module.attestation_document = original_attestation_document
            if app_module is not None:
                app_module.app.dependency_overrides.clear()
            if npm_registry is not None:
                npm_registry.close()
            simulator.close()


if __name__ == "__main__":
    main()
