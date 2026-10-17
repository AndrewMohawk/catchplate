#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import collections
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import re
import ssl
import tempfile
import threading
import urllib.parse
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


MAX_REQUEST_LINE_BYTES = 8 * 1024
MAX_HEADER_BYTES = 32 * 1024
MAX_FORM_BYTES = 16 * 1024
MAX_RESOURCE_BODY_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_EVENTS = 256
MAX_QUERY_FIELDS = 24
_PKCE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_STATE_RE = re.compile(r"^[A-Za-z0-9_-]{43,128}$")
_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


@dataclass
class _AuthorizationCode:
    provider: str
    redirect_uri: str
    code_challenge: str
    scopes: tuple[str, ...]
    outcome: str
    used: bool = False


@dataclass
class _Grant:
    provider: str
    client_id: str
    provider_subject: str
    scopes: tuple[str, ...]
    outcome: str
    active: bool = True


@dataclass
class _TokenReference:
    grant_id: str
    active: bool = True


class _BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class OAuthProviderSimulator:
    """Bounded local HTTPS OAuth provider fixture for Google and X."""

    GOOGLE_CLIENT_ID = "oauth-sim-google-client"
    GOOGLE_CLIENT_SECRET = "oauth-sim-google-secret"
    X_CLIENT_ID = "oauth-sim-x-client"
    X_CLIENT_SECRET = "oauth-sim-x-secret"

    _CLIENTS = {
        "google": (GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
        "x": (X_CLIENT_ID, X_CLIENT_SECRET),
    }
    _PROVIDER_SUBJECTS = {
        "google": "google-subject-001",
        "x": "x-subject-001",
    }
    _ALLOWED_SCOPES = {
        "google": frozenset(
            {
                "openid",
                "email",
                "profile",
                "https://www.googleapis.com/auth/gmail.readonly",
            }
        ),
        "x": frozenset(
            {
                "tweet.read",
                "tweet.write",
                "users.read",
                "offline.access",
                "follows.read",
            }
        ),
    }
    _EXPANDED_SCOPE = {"google": "profile", "x": "follows.read"}
    _OUTCOMES = frozenset(
        {"success", "denial", "scope_expansion", "malformed_identity"}
    )

    def __init__(
        self,
        work_dir: Path,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        redirect_base_url: str = "https://catchplate.test",
        authorization_token_ttl_seconds: int = 1,
        refresh_token_ttl_seconds: int = 300,
    ) -> None:
        for name, value in (
            ("authorization_token_ttl_seconds", authorization_token_ttl_seconds),
            ("refresh_token_ttl_seconds", refresh_token_ttl_seconds),
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 1 <= value <= 3600
            ):
                raise ValueError(f"{name} must be an integer between 1 and 3600")
        self.work_dir = Path(work_dir)
        self.host = host
        self.port = port
        self.authorization_token_ttl_seconds = authorization_token_ttl_seconds
        self.refresh_token_ttl_seconds = refresh_token_ttl_seconds
        self.redirect_base_url, self.redirect_hostname = self._validated_redirect_base(
            redirect_base_url
        )
        self._lock = threading.RLock()
        self._server: _BoundedThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._sequence = 0
        self._code_counter = 0
        self._grant_counter = 0
        self._token_counter = 0
        self._codes: dict[str, _AuthorizationCode] = {}
        self._grants: dict[str, _Grant] = {}
        self._access_tokens: dict[str, _TokenReference] = {}
        self._refresh_tokens: dict[str, _TokenReference] = {}
        self._token_values: set[str] = set()
        self._outcomes: dict[str, collections.deque[str]] = {
            "google": collections.deque(),
            "x": collections.deque(),
        }
        self._counts: dict[str, collections.Counter[str]] = {
            "google": collections.Counter(),
            "x": collections.Counter(),
        }
        self._events: collections.deque[dict[str, Any]] = collections.deque(
            maxlen=MAX_EVENTS
        )
        self.ca_cert_path = self.work_dir / "oauth-simulator-ca.pem"
        self.server_cert_path = self.work_dir / "oauth-simulator-server.pem"
        self.server_key_path = self.work_dir / "oauth-simulator-server-key.pem"

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise RuntimeError("OAuth simulator is not running")
        return f"https://{self.host}:{self._server.server_address[1]}"

    @property
    def client_ssl_context(self) -> ssl.SSLContext:
        if self._server is None:
            raise RuntimeError("OAuth simulator is not running")
        return ssl.create_default_context(cafile=str(self.ca_cert_path))

    def provider_urls(self, provider: str) -> dict[str, str]:
        normalized = self._normalize_provider(provider)
        return {
            "authorization_url": f"{self.base_url}/{normalized}/authorize",
            "token_url": f"{self.base_url}/{normalized}/token",
            "identity_url": f"{self.base_url}/{normalized}/identity",
            "revocation_url": f"{self.base_url}/{normalized}/revoke",
        }

    @property
    def observations_url(self) -> str:
        return f"{self.base_url}/__test__/observations"

    def queue_authorization_outcome(self, provider: str, outcome: str) -> None:
        normalized = self._normalize_provider(provider)
        if outcome not in self._OUTCOMES:
            raise ValueError(f"unsupported simulator outcome: {outcome}")
        with self._lock:
            if len(self._outcomes[normalized]) >= 32:
                raise RuntimeError("OAuth simulator outcome queue is full")
            self._outcomes[normalized].append(outcome)

    def observations(self) -> dict[str, Any]:
        with self._lock:
            payload = {
                "counts": {
                    provider: dict(sorted(self._counts[provider].items()))
                    for provider in ("google", "x")
                },
                "events": [dict(event) for event in self._events],
                "active": {
                    "authorizationCodes": sum(
                        not item.used for item in self._codes.values()
                    ),
                    "grants": sum(item.active for item in self._grants.values()),
                },
                "bounds": {
                    "maxFormBytes": MAX_FORM_BYTES,
                    "maxResourceBodyBytes": MAX_RESOURCE_BODY_BYTES,
                    "maxResponseBytes": MAX_RESPONSE_BYTES,
                    "maxEvents": MAX_EVENTS,
                },
                "tokenLifetimes": {
                    "authorizationCodeExchangeSeconds": (
                        self.authorization_token_ttl_seconds
                    ),
                    "refreshExchangeSeconds": self.refresh_token_ttl_seconds,
                },
            }
        self.assert_no_token_values(json.dumps(payload, sort_keys=True).encode("utf-8"))
        return payload

    def assert_no_token_values(self, value: bytes | str) -> None:
        encoded = value.encode("utf-8") if isinstance(value, str) else value
        with self._lock:
            leaked = any(
                token.encode("ascii") in encoded for token in self._token_values
            )
        if leaked:
            raise AssertionError(
                "OAuth token material appeared in an observable payload"
            )

    def start(self) -> OAuthProviderSimulator:
        if self._server is not None:
            return self
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self._write_test_pki()
        simulator = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "OAuthSimulator/1"
            sys_version = ""

            def do_GET(self) -> None:  # noqa: N802
                simulator._handle_get(self)

            def do_POST(self) -> None:  # noqa: N802
                simulator._handle_post(self)

            def do_DELETE(self) -> None:  # noqa: N802
                simulator._handle_unsupported_resource_method(self)

            def do_PATCH(self) -> None:  # noqa: N802
                simulator._handle_unsupported_resource_method(self)

            def do_PUT(self) -> None:  # noqa: N802
                simulator._handle_unsupported_resource_method(self)

            def log_message(self, _format: str, *args: object) -> None:
                return

        server = _BoundedThreadingHTTPServer((self.host, self.port), Handler)
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        tls_context.load_cert_chain(
            str(self.server_cert_path), str(self.server_key_path)
        )
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
        self._server = server
        self._thread = threading.Thread(
            target=server.serve_forever, name="oauth-provider-simulator", daemon=True
        )
        self._thread.start()
        return self

    def close(self) -> None:
        server = self._server
        thread = self._thread
        self._server = None
        self._thread = None
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=5)
            if thread.is_alive():
                raise RuntimeError("OAuth simulator did not stop")

    def __enter__(self) -> OAuthProviderSimulator:
        return self.start()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    @staticmethod
    def _normalize_provider(provider: str) -> str:
        normalized = provider.strip().lower()
        if normalized == "twitter":
            normalized = "x"
        if normalized not in {"google", "x"}:
            raise ValueError(f"unsupported OAuth simulator provider: {provider}")
        return normalized

    @staticmethod
    def _validated_redirect_base(value: str) -> tuple[str, str]:
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or len(value) > 2048
            or any(
                ord(character) < 0x21 or ord(character) == 0x7F for character in value
            )
        ):
            raise ValueError(
                "OAuth simulator redirect base must be a bounded HTTPS origin"
            )
        try:
            parsed = urllib.parse.urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise ValueError(
                "OAuth simulator redirect base has an invalid authority"
            ) from exc
        if (
            parsed.scheme.lower() != "https"
            or not parsed.netloc
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("OAuth simulator redirect base must be an HTTPS origin")
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("OAuth simulator redirect base port is invalid")

        raw_hostname = parsed.hostname
        try:
            address = ipaddress.ip_address(raw_hostname)
        except ValueError:
            if raw_hostname.endswith("."):
                raise ValueError(
                    "OAuth simulator redirect hostname must not have a trailing dot"
                )
            try:
                hostname = raw_hostname.encode("idna").decode("ascii").lower()
            except UnicodeError as exc:
                raise ValueError(
                    "OAuth simulator redirect hostname is invalid"
                ) from exc
            if (
                len(hostname) > 253
                or not hostname
                or any(
                    _DNS_LABEL_RE.fullmatch(label) is None
                    for label in hostname.split(".")
                )
            ):
                raise ValueError("OAuth simulator redirect hostname is invalid")
            authority_host = hostname
        else:
            hostname = address.compressed
            authority_host = f"[{hostname}]" if address.version == 6 else hostname
        authority = authority_host if port is None else f"{authority_host}:{port}"
        return f"https://{authority}", hostname

    def _write_test_pki(self) -> None:
        now = dt.datetime.now(dt.timezone.utc)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Catchplate OAuth Test CA")]
        )
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(1001)
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=7))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    ca_key.public_key()
                ),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    key_cert_sign=True,
                    key_agreement=False,
                    content_commitment=False,
                    data_encipherment=False,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )
        server_key = ec.generate_private_key(ec.SECP256R1())
        server_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "catchplate.test")]
        )
        dns_names = {"localhost", "catchplate.test"}
        ip_addresses = {ipaddress.ip_address("127.0.0.1")}
        for hostname in (self.host, self.redirect_hostname):
            try:
                ip_addresses.add(ipaddress.ip_address(hostname))
            except ValueError:
                try:
                    encoded_hostname = hostname.encode("idna").decode("ascii").lower()
                except UnicodeError as exc:
                    raise ValueError("OAuth simulator TLS hostname is invalid") from exc
                if len(encoded_hostname) > 253 or any(
                    _DNS_LABEL_RE.fullmatch(label) is None
                    for label in encoded_hostname.split(".")
                ):
                    raise ValueError("OAuth simulator TLS hostname is invalid")
                dns_names.add(encoded_hostname)
        subject_alternative_names: list[x509.GeneralName] = [
            x509.DNSName(name) for name in sorted(dns_names)
        ]
        subject_alternative_names.extend(
            x509.IPAddress(address) for address in sorted(ip_addresses, key=str)
        )
        server_cert = (
            x509.CertificateBuilder()
            .subject_name(server_name)
            .issuer_name(ca_name)
            .public_key(server_key.public_key())
            .serial_number(1002)
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=7))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    ca_key.public_key()
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(subject_alternative_names),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    key_cert_sign=False,
                    key_agreement=True,
                    content_commitment=False,
                    data_encipherment=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )
        self.ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        self.server_cert_path.write_bytes(
            server_cert.public_bytes(serialization.Encoding.PEM)
        )
        self.server_key_path.write_bytes(
            server_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.ca_cert_path.chmod(0o644)
        self.server_cert_path.chmod(0o644)
        self.server_key_path.chmod(0o600)

    def _request_headers_are_bounded(self, handler: BaseHTTPRequestHandler) -> bool:
        request_line_size = len(handler.raw_requestline)
        header_size = sum(
            len(name) + len(value) + 4 for name, value in handler.headers.items()
        )
        if request_line_size > MAX_REQUEST_LINE_BYTES or header_size > MAX_HEADER_BYTES:
            self._send_json(handler, 431, {"error": "request_too_large"})
            return False
        return True

    def _handle_get(self, handler: BaseHTTPRequestHandler) -> None:
        if not self._request_headers_are_bounded(handler):
            return
        parsed = urllib.parse.urlsplit(handler.path)
        if parsed.path == "/__test__/observations" and not parsed.query:
            self._send_json(handler, 200, self.observations())
            return
        if parsed.path.startswith("/gmail/v1/"):
            self._gmail_resource(handler, parsed)
            return
        if parsed.path == "/2/tweets/search/recent":
            self._x_search_resource(handler, parsed)
            return
        match = re.fullmatch(r"/(google|x)/(authorize|identity)", parsed.path)
        if match is None:
            self._send_json(handler, 404, {"error": "not_found"})
            return
        provider, operation = match.groups()
        if operation == "authorize":
            self._authorize(handler, provider, parsed.query)
        else:
            if parsed.query:
                self._send_json(handler, 400, {"error": "invalid_request"})
                return
            self._identity(handler, provider)

    def _handle_post(self, handler: BaseHTTPRequestHandler) -> None:
        if not self._request_headers_are_bounded(handler):
            return
        parsed = urllib.parse.urlsplit(handler.path)
        if parsed.path == "/2/tweets":
            self._x_post_resource(handler, parsed)
            return
        if parsed.query:
            self._send_json(handler, 400, {"error": "invalid_request"})
            return
        match = re.fullmatch(r"/(google|x)/(token|revoke)", parsed.path)
        if match is None:
            self._send_json(handler, 404, {"error": "not_found"})
            return
        form = self._read_form(handler)
        if form is None:
            return
        provider, operation = match.groups()
        if operation == "token":
            self._token(handler, provider, form)
        else:
            self._revoke(handler, provider, form)

    def _handle_unsupported_resource_method(
        self, handler: BaseHTTPRequestHandler
    ) -> None:
        if not self._request_headers_are_bounded(handler):
            return
        parsed = urllib.parse.urlsplit(handler.path)
        if parsed.path.startswith("/gmail/v1/") or parsed.path.startswith("/2/"):
            self._send_json(handler, 405, {"error": "method_not_allowed"})
            return
        self._send_json(handler, 404, {"error": "not_found"})

    def _authorized_grant(
        self,
        handler: BaseHTTPRequestHandler,
        *,
        provider: str,
        required_scope: str,
        operation: str,
    ) -> _Grant | None:
        authorization = handler.headers.get("Authorization", "")
        if (
            not authorization.startswith("Bearer ")
            or len(authorization) > 1024
            or authorization.count(" ") != 1
        ):
            self._record(
                provider,
                "resource_rejected",
                operation=operation,
                reason="invalid_token",
            )
            self._send_json(handler, 401, {"error": "invalid_token"})
            return None
        token = authorization.removeprefix("Bearer ")
        with self._lock:
            reference = self._access_tokens.get(token)
            grant = (
                self._grants.get(reference.grant_id) if reference is not None else None
            )
            valid = bool(
                reference
                and reference.active
                and grant
                and grant.active
                and grant.provider == provider
            )
            scope_allowed = bool(valid and required_scope in grant.scopes)
            if not valid:
                self._counts[provider]["resource_rejections"] += 1
                self._record_locked(
                    provider,
                    "resource_rejected",
                    operation=operation,
                    reason="invalid_token",
                )
            elif not scope_allowed:
                self._counts[provider]["resource_rejections"] += 1
                self._record_locked(
                    provider,
                    "resource_rejected",
                    operation=operation,
                    reason="insufficient_scope",
                )
            else:
                self._counts[provider]["resource_requests"] += 1
                self._counts[provider][f"resource_{operation}"] += 1
                self._record_locked(
                    provider,
                    "resource_authorized",
                    operation=operation,
                )
        if not valid:
            self._send_json(handler, 401, {"error": "invalid_token"})
            return None
        if not scope_allowed:
            self._send_json(handler, 403, {"error": "insufficient_scope"})
            return None
        return grant

    def _parse_query(
        self,
        handler: BaseHTTPRequestHandler,
        query: str,
        *,
        allowed: set[str],
    ) -> dict[str, list[str]] | None:
        try:
            encoded_query = query.encode("ascii")
        except UnicodeEncodeError:
            self._send_json(handler, 400, {"error": "invalid_request"})
            return None
        if len(encoded_query) > MAX_REQUEST_LINE_BYTES:
            self._send_json(handler, 413, {"error": "request_too_large"})
            return None
        try:
            parsed = urllib.parse.parse_qs(
                query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=MAX_QUERY_FIELDS,
            )
        except ValueError:
            self._send_json(handler, 400, {"error": "invalid_request"})
            return None
        if not set(parsed).issubset(allowed):
            self._send_json(handler, 400, {"error": "invalid_request"})
            return None
        return parsed

    def _read_json_object(
        self, handler: BaseHTTPRequestHandler
    ) -> dict[str, Any] | None:
        if handler.headers.get("Transfer-Encoding"):
            self._send_json(handler, 400, {"error": "invalid_request"})
            return None
        if handler.headers.get_content_type().lower() != "application/json":
            self._send_json(handler, 415, {"error": "invalid_content_type"})
            return None
        raw_length = handler.headers.get("Content-Length")
        try:
            length = int(raw_length or "")
        except ValueError:
            self._send_json(handler, 411, {"error": "length_required"})
            return None
        if length < 1 or length > MAX_RESOURCE_BODY_BYTES:
            self._send_json(handler, 413, {"error": "request_too_large"})
            return None
        body = handler.rfile.read(length)
        if len(body) != length:
            self._send_json(handler, 400, {"error": "invalid_request"})
            return None

        def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON key")
                result[key] = value
            return result

        def reject_constant(_value: str) -> Any:
            raise ValueError("non-standard JSON constant")

        try:
            value = json.loads(
                body,
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=reject_constant,
            )
        except (UnicodeDecodeError, ValueError, RecursionError):
            self._send_json(handler, 400, {"error": "invalid_json"})
            return None
        if not isinstance(value, dict):
            self._send_json(handler, 400, {"error": "invalid_json"})
            return None
        return value

    def _gmail_resource(
        self,
        handler: BaseHTTPRequestHandler,
        parsed: urllib.parse.SplitResult,
    ) -> None:
        match = re.fullmatch(
            r"/gmail/v1/users/(me)/messages(?:/([A-Za-z0-9_-]{1,128}))?",
            parsed.path,
        )
        if match is None:
            self._send_json(handler, 404, {"error": "not_found"})
            return
        message_id = match.group(2)
        operation = "gmail.message.get" if message_id else "gmail.messages.list"
        if (
            self._authorized_grant(
                handler,
                provider="google",
                required_scope="https://www.googleapis.com/auth/gmail.readonly",
                operation=operation,
            )
            is None
        ):
            return
        query = self._parse_query(
            handler,
            parsed.query,
            allowed={
                "fields",
                "format",
                "includeSpamTrash",
                "labelIds",
                "maxResults",
                "pageToken",
                "q",
            },
        )
        if query is None:
            return
        now_ms = int(dt.datetime.now(dt.timezone.utc).timestamp() * 1000)
        messages = {
            "gmail-recent-1": {
                "id": "gmail-recent-1",
                "threadId": "gmail-thread-1",
                "labelIds": ["INBOX"],
                "snippet": "Recent fixture message one",
                "internalDate": str(now_ms - 3_600_000),
            },
            "gmail-recent-2": {
                "id": "gmail-recent-2",
                "threadId": "gmail-thread-2",
                "labelIds": ["INBOX"],
                "snippet": "Recent fixture message two",
                "internalDate": str(now_ms - 7 * 86_400_000),
            },
        }
        if message_id is None:
            max_results_values = query.get("maxResults", ["10"])
            if (
                len(max_results_values) != 1
                or not max_results_values[0].isdigit()
                or not 1 <= int(max_results_values[0]) <= 100
            ):
                self._send_json(handler, 400, {"error": "invalid_request"})
                return
            limit = min(int(max_results_values[0]), len(messages))
            self._send_json(
                handler,
                200,
                {
                    "messages": [
                        {"id": item["id"], "threadId": item["threadId"]}
                        for item in list(messages.values())[:limit]
                    ],
                    "resultSizeEstimate": limit,
                },
            )
            return
        message = messages.get(message_id)
        if message is None:
            self._send_json(handler, 404, {"error": {"code": 404}})
            return
        if query.get("format") == ["metadata"] and query.get("fields") == [
            "id,internalDate"
        ]:
            self._send_json(
                handler,
                200,
                {"id": message["id"], "internalDate": message["internalDate"]},
            )
            return
        self._send_json(handler, 200, message)

    def _x_search_resource(
        self,
        handler: BaseHTTPRequestHandler,
        parsed: urllib.parse.SplitResult,
    ) -> None:
        if (
            self._authorized_grant(
                handler,
                provider="x",
                required_scope="tweet.read",
                operation="x.search.recent",
            )
            is None
        ):
            return
        query = self._parse_query(
            handler,
            parsed.query,
            allowed={"end_time", "max_results", "query", "start_time", "tweet.fields"},
        )
        if query is None:
            return
        if len(query.get("query", [])) != 1 or not query["query"][0]:
            self._send_json(handler, 400, {"error": "invalid_request"})
            return
        max_results = query.get("max_results", ["10"])
        if (
            len(max_results) != 1
            or not max_results[0].isdigit()
            or not 1 <= int(max_results[0]) <= 100
        ):
            self._send_json(handler, 400, {"error": "invalid_request"})
            return
        created_at = (
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
        ).isoformat(timespec="seconds").replace("+00:00", "Z")
        self._send_json(
            handler,
            200,
            {
                "data": [
                    {
                        "id": "x-search-result-1",
                        "text": "Bounded recent-search fixture",
                        "created_at": created_at,
                    }
                ],
                "meta": {"result_count": 1},
            },
        )

    def _x_post_resource(
        self,
        handler: BaseHTTPRequestHandler,
        parsed: urllib.parse.SplitResult,
    ) -> None:
        if parsed.query:
            self._send_json(handler, 400, {"error": "invalid_request"})
            return
        if (
            self._authorized_grant(
                handler,
                provider="x",
                required_scope="tweet.write",
                operation="x.tweet.create",
            )
            is None
        ):
            return
        payload = self._read_json_object(handler)
        if payload is None:
            return
        if set(payload) - {"reply_settings", "text"}:
            self._send_json(handler, 400, {"error": "invalid_request"})
            return
        text = payload.get("text")
        if not isinstance(text, str) or not 1 <= len(text) <= 280:
            self._send_json(handler, 400, {"error": "invalid_request"})
            return
        reply_settings = payload.get("reply_settings")
        if reply_settings is not None and reply_settings not in {
            "following",
            "mentionedUsers",
        }:
            self._send_json(handler, 400, {"error": "invalid_request"})
            return
        self._send_json(
            handler,
            201,
            {
                "data": {
                    "id": "x-created-tweet-1",
                    "text": text,
                }
            },
        )

    def _read_form(
        self, handler: BaseHTTPRequestHandler
    ) -> dict[str, list[str]] | None:
        if handler.headers.get("Transfer-Encoding"):
            self._send_json(handler, 400, {"error": "invalid_request"})
            return None
        if (
            handler.headers.get_content_type().lower()
            != "application/x-www-form-urlencoded"
        ):
            self._send_json(handler, 415, {"error": "invalid_content_type"})
            return None
        raw_length = handler.headers.get("Content-Length")
        try:
            length = int(raw_length or "")
        except ValueError:
            self._send_json(handler, 411, {"error": "length_required"})
            return None
        if length < 0 or length > MAX_FORM_BYTES:
            self._send_json(handler, 413, {"error": "request_too_large"})
            return None
        body = handler.rfile.read(length)
        if len(body) != length:
            self._send_json(handler, 400, {"error": "invalid_request"})
            return None
        try:
            decoded = body.decode("ascii")
            return urllib.parse.parse_qs(
                decoded,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=MAX_QUERY_FIELDS,
            )
        except (UnicodeDecodeError, ValueError):
            self._send_json(handler, 400, {"error": "invalid_request"})
            return None

    @staticmethod
    def _one(form: dict[str, list[str]], name: str) -> str | None:
        values = form.get(name)
        if not isinstance(values, list) or len(values) != 1:
            return None
        return values[0]

    def _authorize(
        self, handler: BaseHTTPRequestHandler, provider: str, query: str
    ) -> None:
        if len(query.encode("ascii", "ignore")) > MAX_REQUEST_LINE_BYTES:
            self._send_json(handler, 413, {"error": "request_too_large"})
            return
        try:
            params = urllib.parse.parse_qs(
                query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=MAX_QUERY_FIELDS,
            )
        except ValueError:
            self._send_json(handler, 400, {"error": "invalid_request"})
            return
        common_fields = {
            "response_type",
            "client_id",
            "redirect_uri",
            "scope",
            "state",
            "code_challenge",
            "code_challenge_method",
        }
        google_fields = {"access_type", "prompt", "include_granted_scopes"}
        if set(params) != common_fields | (
            google_fields if provider == "google" else set()
        ):
            self._record(provider, "authorization_rejected", reason="invalid_request")
            self._send_json(handler, 400, {"error": "invalid_request"})
            return
        client_id = self._one(params, "client_id")
        redirect_uri = self._one(params, "redirect_uri")
        state = self._one(params, "state")
        raw_scope = self._one(params, "scope")
        challenge = self._one(params, "code_challenge")
        if (
            self._one(params, "response_type") != "code"
            or client_id != self._CLIENTS[provider][0]
            or redirect_uri != self._redirect_uri(provider)
            or not state
            or _STATE_RE.fullmatch(state) is None
            or not raw_scope
            or len(raw_scope) > 2048
            or not challenge
            or _PKCE_RE.fullmatch(challenge) is None
            or self._one(params, "code_challenge_method") != "S256"
            or (
                provider == "google"
                and (
                    self._one(params, "access_type") != "offline"
                    or self._one(params, "prompt") != "consent"
                    or self._one(params, "include_granted_scopes") != "true"
                )
            )
        ):
            self._record(provider, "authorization_rejected", reason="invalid_request")
            self._send_json(handler, 400, {"error": "invalid_request"})
            return
        scopes = tuple(raw_scope.split(" "))
        if (
            not scopes
            or any(not scope for scope in scopes)
            or len(scopes) != len(set(scopes))
            or not set(scopes).issubset(self._ALLOWED_SCOPES[provider])
        ):
            self._record(provider, "authorization_rejected", reason="invalid_scope")
            self._send_json(handler, 400, {"error": "invalid_scope"})
            return
        with self._lock:
            outcome = (
                self._outcomes[provider].popleft()
                if self._outcomes[provider]
                else "success"
            )
            self._counts[provider]["authorization_requests"] += 1
            self._record_locked(
                provider,
                "authorization_validated",
                outcome=outcome,
                requested_scopes=list(scopes),
            )
            if outcome == "denial":
                self._counts[provider]["authorization_denials"] += 1
                location = self._callback_location(
                    redirect_uri,
                    {
                        "error": "access_denied",
                        "error_description": "Access denied by test provider",
                        "state": state,
                    },
                )
                self._send_redirect(handler, location)
                return
            self._code_counter += 1
            code = f"oauth-sim-code-{provider}-{self._code_counter:06d}"
            self._codes[code] = _AuthorizationCode(
                provider=provider,
                redirect_uri=redirect_uri,
                code_challenge=challenge,
                scopes=scopes,
                outcome=outcome,
            )
            self._counts[provider]["authorization_codes_issued"] += 1
            self._record_locked(
                provider, "authorization_code_issued", requested_scopes=list(scopes)
            )
        self._send_redirect(
            handler,
            self._callback_location(redirect_uri, {"code": code, "state": state}),
        )

    def _token(
        self, handler: BaseHTTPRequestHandler, provider: str, form: dict[str, list[str]]
    ) -> None:
        grant_type = self._one(form, "grant_type")
        if grant_type == "authorization_code":
            fields = {
                "grant_type",
                "code",
                "redirect_uri",
                "client_id",
                "code_verifier",
            }
            if provider == "google":
                fields.add("client_secret")
        elif grant_type == "refresh_token":
            fields = {"grant_type", "refresh_token"}
            if provider == "google":
                fields.update({"client_id", "client_secret"})
        else:
            fields = set()
        if set(form) != fields:
            self._record(provider, "token_rejected", reason="invalid_request")
            self._send_json(handler, 400, {"error": "invalid_request"})
            return
        if not self._validate_client_auth(handler, provider, form):
            self._record(provider, "token_rejected", reason="invalid_client")
            self._send_json(handler, 401, {"error": "invalid_client"})
            return
        with self._lock:
            self._counts[provider]["token_requests"] += 1
            if grant_type == "authorization_code":
                payload = self._exchange_authorization_code_locked(provider, form)
            elif grant_type == "refresh_token":
                payload = self._exchange_refresh_token_locked(provider, form)
            else:
                payload = None
            if payload is None:
                self._counts[provider]["token_rejections"] += 1
                self._record_locked(provider, "token_rejected", reason="invalid_grant")
        if payload is None:
            self._send_json(handler, 400, {"error": "invalid_grant"})
            return
        self._send_json(handler, 200, payload)

    def _exchange_authorization_code_locked(
        self,
        provider: str,
        form: dict[str, list[str]],
    ) -> dict[str, Any] | None:
        code_value = self._one(form, "code")
        redirect_uri = self._one(form, "redirect_uri")
        verifier = self._one(form, "code_verifier")
        client_id = self._one(form, "client_id")
        code = self._codes.get(code_value or "")
        if code is None or code.used or code.provider != provider:
            return None
        code.used = True
        if (
            redirect_uri != code.redirect_uri
            or not verifier
            or _PKCE_RE.fullmatch(verifier) is None
            or not hmac.compare_digest(
                self._pkce_challenge(verifier), code.code_challenge
            )
            or client_id != self._CLIENTS[provider][0]
        ):
            return None
        scopes = code.scopes
        if code.outcome == "scope_expansion":
            expanded = self._EXPANDED_SCOPE[provider]
            if expanded not in scopes:
                scopes = (*scopes, expanded)
        self._grant_counter += 1
        grant_id = f"grant-{provider}-{self._grant_counter:06d}"
        self._grants[grant_id] = _Grant(
            provider=provider,
            client_id=client_id,
            provider_subject=self._PROVIDER_SUBJECTS[provider],
            scopes=scopes,
            outcome=code.outcome,
        )
        self._counts[provider]["authorization_code_exchanges"] += 1
        self._record_locked(
            provider,
            "authorization_code_exchanged",
            pkce="S256",
            granted_scopes=list(scopes),
        )
        return self._issue_tokens_locked(
            provider, grant_id, scopes, grant_type="authorization_code"
        )

    def _exchange_refresh_token_locked(
        self,
        provider: str,
        form: dict[str, list[str]],
    ) -> dict[str, Any] | None:
        refresh_value = self._one(form, "refresh_token")
        reference = self._refresh_tokens.get(refresh_value or "")
        if reference is None or not reference.active:
            return None
        grant = self._grants.get(reference.grant_id)
        if grant is None or not grant.active or grant.provider != provider:
            return None
        reference.active = False
        self._counts[provider]["refresh_exchanges"] += 1
        self._record_locked(
            provider, "refresh_token_rotated", granted_scopes=list(grant.scopes)
        )
        return self._issue_tokens_locked(
            provider, reference.grant_id, grant.scopes, grant_type="refresh_token"
        )

    def _issue_tokens_locked(
        self,
        provider: str,
        grant_id: str,
        scopes: tuple[str, ...],
        *,
        grant_type: str,
    ) -> dict[str, Any]:
        self._token_counter += 1
        access_token = f"oauth-sim-access-{provider}-{self._token_counter:06d}-material"
        refresh_token = (
            f"oauth-sim-refresh-{provider}-{self._token_counter:06d}-material"
        )
        self._token_values.update({access_token, refresh_token})
        self._access_tokens[access_token] = _TokenReference(grant_id)
        self._refresh_tokens[refresh_token] = _TokenReference(grant_id)
        self._counts[provider]["token_responses"] += 1
        self._record_locked(
            provider,
            "tokens_issued",
            grant_type=grant_type,
            granted_scopes=list(scopes),
        )
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "scope": " ".join(scopes),
            "expires_in": (
                self.authorization_token_ttl_seconds
                if grant_type == "authorization_code"
                else self.refresh_token_ttl_seconds
            ),
            "refresh_token_expires_in": 3600,
        }

    def _identity(self, handler: BaseHTTPRequestHandler, provider: str) -> None:
        authorization = handler.headers.get("Authorization", "")
        if not authorization.startswith("Bearer ") or len(authorization) > 1024:
            self._send_json(handler, 401, {"error": "invalid_token"})
            return
        token = authorization.removeprefix("Bearer ").strip()
        with self._lock:
            reference = self._access_tokens.get(token)
            grant = (
                self._grants.get(reference.grant_id) if reference is not None else None
            )
            valid = bool(
                reference
                and reference.active
                and grant
                and grant.active
                and grant.provider == provider
            )
            if not valid:
                self._counts[provider]["identity_rejections"] += 1
                self._record_locked(
                    provider, "identity_rejected", reason="invalid_token"
                )
                payload = None
            else:
                self._counts[provider]["identity_requests"] += 1
                malformed = grant.outcome == "malformed_identity"
                self._record_locked(provider, "identity_returned", malformed=malformed)
                if malformed:
                    payload = (
                        {"sub": 7}
                        if provider == "google"
                        else {"data": {"id": "x-subject-001"}}
                    )
                elif provider == "google":
                    payload = {
                        "sub": "google-subject-001",
                        "email": "operator@example.test",
                        "email_verified": True,
                    }
                else:
                    payload = {
                        "data": {
                            "id": "x-subject-001",
                            "name": "Test Operator",
                            "username": "operator_x",
                            "verified": False,
                        }
                    }
        if payload is None:
            self._send_json(handler, 401, {"error": "invalid_token"})
            return
        self._send_json(handler, 200, payload)

    def _revoke(
        self, handler: BaseHTTPRequestHandler, provider: str, form: dict[str, list[str]]
    ) -> None:
        if set(form) != {"token", "token_type_hint"}:
            self._send_json(handler, 400, {"error": "invalid_request"})
            return
        if provider == "x" and not self._validate_client_auth(handler, provider, form):
            self._record(provider, "revocation_rejected", reason="invalid_client")
            self._send_json(handler, 401, {"error": "invalid_client"})
            return
        token = self._one(form, "token")
        hint = self._one(form, "token_type_hint")
        if not token or hint not in {"access_token", "refresh_token"}:
            self._send_json(handler, 400, {"error": "invalid_request"})
            return
        with self._lock:
            references = (
                self._refresh_tokens if hint == "refresh_token" else self._access_tokens
            )
            reference = references.get(token)
            grant = (
                self._grants.get(reference.grant_id) if reference is not None else None
            )
            if reference is None or grant is None or grant.provider != provider:
                self._counts[provider]["revocation_rejections"] += 1
                self._record_locked(
                    provider, "revocation_rejected", reason="invalid_token"
                )
                valid = False
            else:
                if provider == "google":
                    family_grant_ids = {
                        grant_id
                        for grant_id, candidate in self._grants.items()
                        if candidate.provider == "google"
                        and candidate.client_id == grant.client_id
                        and candidate.provider_subject == grant.provider_subject
                    }
                    for grant_id in family_grant_ids:
                        self._grants[grant_id].active = False
                    for item in self._access_tokens.values():
                        if item.grant_id in family_grant_ids:
                            item.active = False
                    for item in self._refresh_tokens.values():
                        if item.grant_id in family_grant_ids:
                            item.active = False
                    event_type = "grant_family_revoked"
                    event_fields = {"family_grant_count": len(family_grant_ids)}
                else:
                    reference.active = False
                    event_type = "token_revoked"
                    event_fields = {}
                self._counts[provider]["revocation_requests"] += 1
                self._counts[provider]["successful_revocations"] += 1
                self._record_locked(
                    provider,
                    event_type,
                    token_type_hint=hint,
                    **event_fields,
                )
                valid = True
        if not valid:
            self._send_json(handler, 400, {"error": "invalid_token"})
            return
        self._send_json(handler, 200, {})

    def _validate_client_auth(
        self,
        handler: BaseHTTPRequestHandler,
        provider: str,
        form: dict[str, list[str]],
    ) -> bool:
        expected_id, expected_secret = self._CLIENTS[provider]
        if provider == "google":
            return hmac.compare_digest(
                self._one(form, "client_id") or "", expected_id
            ) and hmac.compare_digest(
                self._one(form, "client_secret") or "", expected_secret
            )
        authorization = handler.headers.get("Authorization", "")
        if not authorization.startswith("Basic ") or len(authorization) > 1024:
            return False
        try:
            decoded = base64.b64decode(
                authorization.removeprefix("Basic "), validate=True
            ).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return False
        expected = f"{expected_id}:{expected_secret}"
        if not hmac.compare_digest(decoded, expected):
            return False
        client_id = self._one(form, "client_id")
        return client_id is None or hmac.compare_digest(client_id, expected_id)

    def _redirect_uri(self, provider: str) -> str:
        return f"{self.redirect_base_url}/api/oauth/callback/{provider}"

    @staticmethod
    def _pkce_challenge(verifier: str) -> str:
        return (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
            .decode("ascii")
            .rstrip("=")
        )

    @staticmethod
    def _callback_location(redirect_uri: str, params: dict[str, str]) -> str:
        separator = "&" if urllib.parse.urlsplit(redirect_uri).query else "?"
        return redirect_uri + separator + urllib.parse.urlencode(params)

    def _record(self, provider: str, event_type: str, **details: Any) -> None:
        with self._lock:
            self._record_locked(provider, event_type, **details)

    def _record_locked(self, provider: str, event_type: str, **details: Any) -> None:
        self._sequence += 1
        self._events.append(
            {
                "sequence": self._sequence,
                "provider": provider,
                "type": event_type,
                **details,
            }
        )

    def _send_redirect(self, handler: BaseHTTPRequestHandler, location: str) -> None:
        encoded = location.encode("ascii")
        if len(encoded) > MAX_RESPONSE_BYTES:
            self._send_json(handler, 500, {"error": "response_too_large"})
            return
        handler.send_response(302)
        handler.send_header("Location", location)
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("Referrer-Policy", "no-referrer")
        handler.send_header("Content-Length", "0")
        handler.send_header("Connection", "close")
        handler.end_headers()

    def _send_json(
        self, handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]
    ) -> None:
        body = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        if len(body) > MAX_RESPONSE_BYTES:
            status = 500
            body = b'{"error":"response_too_large"}'
        if handler.path == "/__test__/observations":
            self.assert_no_token_values(body)
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the bounded local HTTPS OAuth provider simulator"
    )
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--redirect-base-url", default="https://catchplate.test")
    args = parser.parse_args()
    temporary = tempfile.TemporaryDirectory() if args.work_dir is None else None
    work_dir = args.work_dir or Path(temporary.name)
    simulator = OAuthProviderSimulator(
        work_dir,
        port=args.port,
        redirect_base_url=args.redirect_base_url,
    )
    try:
        simulator.start()
        print(
            json.dumps(
                {
                    "baseUrl": simulator.base_url,
                    "caCert": str(simulator.ca_cert_path),
                    "redirectBaseUrl": simulator.redirect_base_url,
                },
                sort_keys=True,
            )
        )
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        simulator.close()
        if temporary is not None:
            temporary.cleanup()


if __name__ == "__main__":
    main()
