"""Explicit, buffered HTTP(S) calls through one workload-authenticated proxy.

This is a transport, not enrollment, attestation or response-proof verification.
Callers must independently admit the supplied identities, roots and endpoint.
There is no provider credential setting, direct fallback, retry or redirect.
"""

from __future__ import annotations

import os
import re
import threading
import time
import urllib.parse
from collections.abc import Mapping
from contextlib import ExitStack
from dataclasses import dataclass

from ._workload_handoff import extract_workload_handoff
from ._workload_http import WorkloadResponse, encode_connect, encode_request, read_response
from ._workload_signed_packet import verify_signed_workload_packet
from ._workload_stream import (
    Budget, InnerTLS, OuterTLS, WorkloadClientError, _endpoint, _require_name,
)
from ._workload_tls import PinnedFile, TlsContexts, _load_original, _require_linux, load_tls_contexts


__all__ = ["PinnedFile", "WorkloadClientError", "WorkloadProxyClient", "WorkloadResponse"]

_MAX_BODY_BYTES = 8 * 1024 * 1024
_MAX_URL_BYTES = 8192
_PORT = re.compile(r"[1-9][0-9]{0,4}\Z")
_BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")


@dataclass(frozen=True, repr=False)
class _HandoffLifetime:
    admitted_at_epoch_ms: int
    issued_at_epoch_ms: int
    expires_at_epoch_ms: int
    deadline: float

    def check(self) -> None:
        now = time.time_ns() // 1_000_000
        if (
            now < self.admitted_at_epoch_ms or now < self.issued_at_epoch_ms
            or now >= self.expires_at_epoch_ms or time.monotonic() >= self.deadline
        ):
            raise WorkloadClientError("workload signed handoff expired or clock moved before admission")


@dataclass(frozen=True, repr=False)
class _Destination:
    scheme: str
    server_name: str
    authority: str
    target: str


def _destination(url: str) -> _Destination:
    if (
        type(url) is not str or not 1 <= len(url) <= _MAX_URL_BYTES
        or not url.isascii() or any(ord(char) < 33 or ord(char) > 126 for char in url)
        or "#" in url or "\\" in url
        or not url.startswith(("http://", "https://"))
        or _BAD_PERCENT.search(url) is not None
    ):
        raise WorkloadClientError("workload URL must be bounded explicit ASCII HTTP(S) without a fragment")
    try:
        parsed = urllib.parse.urlsplit(url)
        if not parsed.netloc or "@" in parsed.netloc or "%" in parsed.netloc:
            raise WorkloadClientError("workload URL authority must not contain credentials or escapes")
        authority = parsed.netloc
        if authority.startswith("["):
            end = authority.find("]")
            if end < 0:
                raise WorkloadClientError("workload IPv6 authority is malformed")
            server_name, suffix = authority[1:end], authority[end + 1:]
            if ":" not in server_name:
                raise WorkloadClientError("workload brackets are reserved for IPv6")
            host = "[" + server_name + "]"
        else:
            server_name, colon, port_text = authority.partition(":")
            suffix = colon + port_text
            host = server_name
        _require_name(server_name)
        default_port = 443 if parsed.scheme == "https" else 80
        if suffix:
            if not suffix.startswith(":") or _PORT.fullmatch(suffix[1:]) is None:
                raise WorkloadClientError("workload URL port is not canonical")
            port = int(suffix[1:])
            if port > 65535:
                raise WorkloadClientError("workload URL port exceeds 65535")
        else:
            port = default_port
        # Preserve the caller's path/query bytes, including a trailing empty
        # query marker. Only an absent path and absent port gain explicit values.
        path_query = url[len(parsed.scheme) + 3 + len(authority):]
        if not path_query or path_query.startswith("?"):
            path_query = "/" + path_query
        if not path_query.startswith("/"):
            raise WorkloadClientError("workload request target is not an absolute path")
        joined_authority = host + ":" + str(port)
        target = path_query if parsed.scheme == "https" else "http://" + joined_authority + path_query
        return _Destination(parsed.scheme, server_name, joined_authority, target)
    except WorkloadClientError:
        raise
    except ValueError as exc:
        raise WorkloadClientError("workload URL is malformed") from exc


def _headers(value: Mapping[str, str] | None, budget: Budget) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise WorkloadClientError("workload headers must be a mapping")
    result: dict[str, str] = {}
    names: set[str] = set()
    total = 0
    for name, item in value.items():
        budget.check()
        if type(name) is not str or type(item) is not str:
            raise WorkloadClientError("workload header names and values must be strings")
        total += len(name) + len(item) + 4
        if len(result) >= 128 or total > 32 * 1024:
            raise WorkloadClientError("workload headers exceed their bound")
        if name.lower() in names:
            raise WorkloadClientError("workload headers repeat a case-insensitive name")
        names.add(name.lower())
        result[name] = item
    budget.check()
    return result


class WorkloadProxyClient:
    """Linux, synchronous, creator-thread/process-confined workload client.

    Configuration loads pinned materials once; request() opens a fresh outer
    mTLS channel every time. HTTPS adds a separate CA-only provider-name TLS
    layer inside CONNECT. Each returned body has complete bounded framing;
    this class does not verify signed Catchplate response proofs.
    """

    def __init__(
        self, *, proxy_ip: str, proxy_port: int, proxy_server_name: str,
        proxy_ca: PinnedFile, client_certificate: PinnedFile,
        client_private_key: PinnedFile, interception_ca: PinnedFile,
        proxy_headers: Mapping[str, str] | None = None,
        timeout_ms: int = 30_000, max_response_bytes: int = _MAX_BODY_BYTES,
    ) -> None:
        budget = Budget(timeout_ms)
        _endpoint((proxy_ip, proxy_port))
        _require_name(proxy_server_name)
        if type(max_response_bytes) is not int or not 1 <= max_response_bytes <= _MAX_BODY_BYTES:
            raise WorkloadClientError("workload response limit must be an integer in 1..8388608 bytes")
        scoped_headers = _headers(proxy_headers, budget)
        # Validate before private material is read; this does not send bytes.
        encode_connect("validation.invalid:443", scoped_headers)
        self._pid = os.getpid()
        self._thread = threading.current_thread()
        self._closed = False
        self._active = False
        self._endpoint = (proxy_ip, proxy_port)
        self._server_name = proxy_server_name
        self._proxy_headers = scoped_headers
        self._provider_headers: dict[str, str] = {}
        self._lifetime: _HandoffLifetime | None = None
        self._timeout_ms = timeout_ms
        self._max_response_bytes = max_response_bytes
        self._contexts: TlsContexts | None = load_tls_contexts(
            proxy_ca=proxy_ca, client_certificate=client_certificate,
            client_private_key=client_private_key, interception_ca=interception_ca,
            budget=budget,
        )
        budget.check()

    @classmethod
    def from_signed_handoff(
        cls, *, packet: PinnedFile, packet_signing_key: PinnedFile,
        expected_principal: str, expected_nonce: str, proxy_ip: str,
        proxy_ca: PinnedFile, client_certificate: PinnedFile,
        client_private_key: PinnedFile, interception_ca: PinnedFile,
        proxy_authorization: str | None = None,
        timeout_ms: int = 30_000, max_response_bytes: int = _MAX_BODY_BYTES,
    ) -> WorkloadProxyClient:
        """Derive transport settings from an original authenticated handoff.

        The signing key and every file pin must already be independently
        admitted. This checks signature/configuration compatibility, not fresh
        attestation, egress enforcement, canaries or enrollment completion.
        No receipt flag, packet-supplied key, command or CA installer is used.
        """
        budget = Budget(timeout_ms)
        anchored_monotonic = time.monotonic()
        anchored_epoch_ms = time.time_ns() // 1_000_000
        if type(max_response_bytes) is not int or not 1 <= max_response_bytes <= _MAX_BODY_BYTES:
            raise WorkloadClientError("workload response limit must be an integer in 1..8388608 bytes")
        try:
            _require_linux()
            with ExitStack() as owners:
                packet_original = _load_original(packet, 8 * 1024 * 1024, False, budget, owners)
                key_original = _load_original(packet_signing_key, 64 * 1024, False, budget, owners)
                authenticated = verify_signed_workload_packet(
                    packet_original.raw, key_original.raw,
                    expected_principal=expected_principal, expected_nonce=expected_nonce,
                    budget=budget,
                )
                settings = extract_workload_handoff(
                    authenticated, proxy_ip=proxy_ip, proxy_authorization=proxy_authorization,
                    budget=budget,
                )
                if not settings.issued_at_epoch_ms <= anchored_epoch_ms < settings.expires_at_epoch_ms:
                    raise WorkloadClientError("workload handoff is outside its original admission window")
                lifetime = _HandoffLifetime(
                    anchored_epoch_ms, settings.issued_at_epoch_ms, settings.expires_at_epoch_ms,
                    anchored_monotonic + (settings.expires_at_epoch_ms - anchored_epoch_ms) / 1000,
                )
                budget._bind_lifetime(lifetime.deadline, lifetime.check)
                contexts = load_tls_contexts(
                    proxy_ca=proxy_ca, client_certificate=client_certificate,
                    client_private_key=client_private_key, interception_ca=interception_ca,
                    budget=budget, expected_mtls=settings.mtls,
                    expected_interception_ca_spki_sha256=settings.interception_ca_spki_sha256,
                )
                packet_original.recheck(budget)
                key_original.recheck(budget)
                # Reuse only the actual admitted contexts. Calling __init__
                # here would reload paths and give construction a new budget.
                client = object.__new__(cls)
                client._pid = os.getpid()
                client._thread = threading.current_thread()
                client._closed = False
                client._active = False
                client._endpoint = (settings.proxy_ip, settings.proxy_port)
                client._server_name = settings.proxy_server_name
                client._proxy_headers = dict(settings.proxy_headers)
                client._provider_headers = dict(settings.provider_headers)
                client._lifetime = lifetime
                client._timeout_ms = timeout_ms
                client._max_response_bytes = max_response_bytes
                client._contexts = contexts
            budget.check()
            return client
        except WorkloadClientError:
            raise
        except Exception:
            raise WorkloadClientError("workload signed handoff construction failed") from None

    def _request_headers(
        self, supplied: Mapping[str, str] | None, *, plain_http: bool, budget: Budget,
    ) -> dict[str, str]:
        fields = dict(self._provider_headers)
        required = {name.lower(): name for name in fields}
        for name, value in _headers(supplied, budget).items():
            signed_name = required.get(name.lower())
            if signed_name is not None:
                if fields[signed_name] != value:
                    raise WorkloadClientError("workload request cannot replace a signed required header")
            else:
                fields[name] = value
        if plain_http:
            proxy = {name.lower(): value for name, value in self._proxy_headers.items()}
            # The signed handoff repeats identity headers for HTTPS's two
            # phases. Plain HTTP has one head: emit each signed copy once.
            # Other caller-created overlaps still fail in encode_request.
            for lower, name in required.items():
                if lower in proxy:
                    if fields[name] != proxy[lower]:
                        raise WorkloadClientError("signed provider and proxy header values disagree")
                    del fields[name]
        return _headers(fields, budget)

    def _check_owner(self) -> None:
        if os.getpid() != self._pid or threading.current_thread() is not self._thread:
            raise WorkloadClientError("workload client belongs to its creating process and thread")
        if self._closed or self._contexts is None:
            raise WorkloadClientError("workload client is closed")
        if self._active:
            raise WorkloadClientError("workload client cannot run reentrant operations")

    def request(
        self, method: str, url: str, *, headers: Mapping[str, str] | None = None,
        body: bytes = b"",
    ) -> WorkloadResponse:
        """Perform one request; non-2xx statuses are returned, never replayed.

        phase='connect' is a proxy tunnel denial, not a provider response.
        A transport error after dispatch does not establish whether a side
        effect occurred. Callers must not infer that a retry is safe.
        """
        self._check_owner()
        budget = Budget(self._timeout_ms)
        if self._lifetime is not None:
            budget._bind_lifetime(self._lifetime.deadline, self._lifetime.check)
        self._active = True
        outer: OuterTLS | None = None
        inner: InnerTLS | None = None
        try:
            destination = _destination(url)
            if type(body) is not bytes or len(body) > _MAX_BODY_BYTES:
                raise WorkloadClientError("workload request body must be bytes no larger than 8MiB")
            provider_headers = self._request_headers(
                headers, plain_http=destination.scheme == "http", budget=budget,
            )
            contexts = self._contexts
            if contexts is None:
                raise WorkloadClientError("workload client is closed")
            # Serialize both heads before opening any socket. Proxy-only
            # fields belong on CONNECT, never on the inner HTTPS request.
            if destination.scheme == "https":
                connect = encode_connect(destination.authority, self._proxy_headers)
                request = encode_request(
                    method, destination.target, destination.authority, provider_headers, body,
                )
            else:
                connect = None
                request = encode_request(
                    method, destination.target, destination.authority, provider_headers, body,
                    proxy_headers=self._proxy_headers,
                )
            budget.check()
            outer = OuterTLS.connect(self._endpoint, self._server_name, contexts.proxy, budget)
            if connect is not None:
                outer.sendall(connect)
                response = read_response(
                    outer, budget, method="CONNECT", max_response_bytes=self._max_response_bytes,
                    phase="connect",
                )
                if response.status != 200:
                    budget.check()
                    return response
                inner = InnerTLS(outer, destination.server_name, contexts.provider, budget)
                stream = inner
            else:
                stream = outer
            stream.sendall(request)
            response = read_response(
                stream, budget, method=method, max_response_bytes=self._max_response_bytes,
                phase="response",
            )
            budget.check()
            return response
        finally:
            try:
                if inner is not None:
                    inner.close()
            finally:
                if outer is not None:
                    outer.close()
                self._active = False

    def close(self) -> None:
        """Discard retained contexts; Python/OpenSSL key erasure is not guaranteed."""
        if self._closed:
            return
        self._check_owner()
        self._contexts = None
        self._proxy_headers.clear()
        self._provider_headers.clear()
        self._closed = True

    def __enter__(self) -> WorkloadProxyClient:
        self._check_owner()
        if self._lifetime is not None:
            self._lifetime.check()
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()
