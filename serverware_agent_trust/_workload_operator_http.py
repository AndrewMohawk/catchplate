"""One explicit, pinned operator HTTPS request; never a workload proxy.

TLS authenticates the configured software endpoint, not enclave attestation or
Serverware signed HTTP evidence. No credential, input body or response body has
an automatic repr, retry, redirect, proxy or cookie-jar path.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import ssl
import threading
import weakref
from contextlib import ExitStack
from dataclasses import dataclass

from . import _workload_http as framing
from . import _workload_identity as identity
from . import _workload_tls as tls
from ._workload_stream import Budget, OuterTLS, WorkloadClientError, _endpoint, _require_name


OPTIONS_PATH = "/api/agents/workload-identity/issue/options"
ISSUE_PATH = "/api/agents/workload-identity/issue"
MAX_REQUEST_BYTES = framing.MAX_BODY_BYTES
MAX_RESPONSE_BYTES = 128 * 1024
MAX_TLS_CA_BYTES = 64 * 1024
MAX_COOKIE_BYTES = 8 * 1024
MAX_CSRF_BYTES = 4 * 1024
RESERVATION_BYTES = (8 * (MAX_TLS_CA_BYTES + MAX_COOKIE_BYTES + MAX_CSRF_BYTES)
    + 4 * MAX_RESPONSE_BYTES + framing.MAX_RESPONSE_HEAD_BYTES
    + framing.MAX_REQUEST_HEAD_BYTES + 64 * 1024)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONSTRUCTION = object()
_LOCK = threading.Lock()
_LIVE = weakref.WeakKeyDictionary()
_PID = os.getpid()


@dataclass(frozen=True, repr=False)
class OperatorEndpoint:
    origin: str
    endpoint: tuple[str, int]
    server_name: str
    trust: tls.PinnedFile
    server_spki_sha256: str
    cookie: tls.PinnedFile
    csrf: tls.PinnedFile


@dataclass(frozen=True, repr=False)
class OperatorResponse:
    status: int
    body: bytes


def _fail():
    raise WorkloadClientError("operator HTTPS inputs, lifetime or one-use exchange are invalid")


def _configuration(connection):
    if type(connection) is not OperatorEndpoint:
        _fail()
    _endpoint(connection.endpoint)
    _require_name(connection.server_name)
    name = connection.server_name
    authority = "[" + name + "]" if ":" in name else name
    if connection.endpoint[1] != 443:
        authority += ":" + str(connection.endpoint[1])
    if (type(connection.origin) is not str or connection.origin != "https://" + authority
            or type(connection.server_spki_sha256) is not str
            or _DIGEST.fullmatch(connection.server_spki_sha256) is None
            or connection.server_spki_sha256 == "sha256:" + "0" * 64):
        _fail()
    for pin in (connection.trust, connection.cookie, connection.csrf):
        if type(pin) is not tls.PinnedFile:
            _fail()
        tls._validate_pin(pin)
    return authority, (connection.origin, connection.endpoint, connection.server_name,
        connection.server_spki_sha256,
        *((os.fspath(pin.path), pin.sha256)
          for pin in (connection.trust, connection.cookie, connection.csrf)))


def _credentials(cookie, csrf):
    # Canonical header values only: no trimming, header prefix or newline.
    try:
        cookie_text, csrf_text = cookie.decode("ascii"), csrf.decode("ascii")
    except UnicodeError:
        _fail()
    parts = cookie_text.split("; ")
    if len(parts) != 2 or not csrf_text:
        _fail()
    values = {}
    for part in parts:
        name, separator, value = part.partition("=")
        if (separator != "=" or name in values or not 1 <= len(value) <= 4096
                or any(ord(char) < 33 or ord(char) > 126 or char in '\",;\\' for char in value)):
            _fail()
        values[name] = value
    if (set(values) not in ({"serverware_admin", "serverware_csrf"},
            {"serverware_oidc_session", "serverware_csrf"})
            or not hmac.compare_digest(values["serverware_csrf"], csrf_text)):
        _fail()
    return cookie_text, csrf_text


def _original_pin(original):
    return (original.descriptor, tuple(original.parts), original.sha256,
        original.maximum, original.private, original.metadata, original.raw)


def _close(owner):
    with _LOCK:
        _LIVE.pop(owner, None)
    owner._originals = ()
    owner._headers = ()
    owner._context = None
    owner._seal = ()


class _OperatorTransport:
    __slots__ = ("_connection", "_configuration", "_authority", "_budget", "_originals",
        "_pins", "_context", "_headers", "_seal", "__weakref__")

    def __init__(self, construction, connection, configuration, authority, budget,
            originals, context, headers):
        if construction is not _CONSTRUCTION:
            _fail()
        self._connection, self._configuration, self._authority = connection, configuration, authority
        self._budget, self._originals, self._context = budget, originals, context
        self._pins = tuple(_original_pin(original) for original in originals)
        self._headers = headers
        self._seal = (connection, configuration, authority, budget, originals,
            self._pins, context, headers)
        with _LOCK:
            _LIVE[self] = "ready"

    def current(self):
        with _LOCK:
            if os.getpid() != _PID or type(self) is not _OperatorTransport or _LIVE.get(self) not in {
                    "ready", "spent"}:
                _fail()
        fields = (self._connection, self._configuration, self._authority, self._budget,
            self._originals, self._pins, self._context, self._headers)
        if len(self._seal) != len(fields) or any(a is not b for a, b in zip(fields, self._seal)):
            _fail()
        self._budget.check()
        if _configuration(self._connection) != (self._authority, self._configuration):
            _fail()
        for original, pin in zip(self._originals, self._pins):
            if _original_pin(original) != pin:
                _fail()
            original.recheck(self._budget)
        self._budget.check()

    def _peer(self, stream, socket):
        self._budget.check()
        if (type(stream) is not OuterTLS or stream._socket is not socket
                or type(socket) is not ssl.SSLSocket or stream._budget is not self._budget
                or stream._context is not self._context):
            _fail()
        stream._check()
        original = socket.getpeercert(binary_form=True)
        self._budget.check()
        if type(original) is not bytes or not 1 <= len(original) <= 64 * 1024:
            _fail()
        _issuer, _subject, spki = identity._certificate_parts(original)
        self._budget.check()
        digest = "sha256:" + hashlib.sha256(spki).hexdigest()
        if not hmac.compare_digest(digest, self._configuration[3]):
            _fail()
        return original

    def post(self, *, path, body):
        self.current()
        if (type(path) is not str or path not in {OPTIONS_PATH, ISSUE_PATH}
                or type(body) is not bytes or not 1 <= len(body) <= MAX_REQUEST_BYTES):
            _fail()
        encoded = framing.encode_request("POST", path, self._authority, dict(self._headers), body)
        self.current()
        with _LOCK:
            if _LIVE.get(self) != "ready":
                _fail()
            _LIVE[self] = "spent"  # No exception can restore connection permission.
        stream = None
        try:
            stream = OuterTLS.connect(self._connection.endpoint, self._connection.server_name,
                self._context, self._budget)
            socket = stream._socket
            peer = self._peer(stream, socket)
            self.current()  # No cookie byte precedes independent TLS and SPKI admission.
            stream.sendall(encoded)
            response = framing.read_response(stream, self._budget, method="POST",
                max_response_bytes=MAX_RESPONSE_BYTES, phase="response")
            if self._peer(stream, socket) != peer:
                _fail()
            fields = {}
            for name, value in response.headers:
                fields.setdefault(name.lower(), []).append(value)
            if (response.trailers or len(fields.get("content-length", ())) != 1
                    or fields.get("content-type") not in (
                        ["application/json"], ["application/json; charset=utf-8"])
                    or any(name in fields for name in ("set-cookie", "content-encoding",
                        "transfer-encoding", "proxy-authenticate", "proxy-authorization"))):
                _fail()
            self.current()
            result = OperatorResponse(response.status, response.body)
        except (OSError, ValueError):
            raise WorkloadClientError("operator HTTPS exchange is unavailable; no automatic retry") from None
        finally:
            if stream is not None:
                stream.close()
        self.current()
        return result


def _prepare_on_budget(connection, *, budget, owners):
    if type(budget) is not Budget or type(owners) is not ExitStack:
        _fail()
    budget.check()
    tls._require_linux()
    authority, configuration = _configuration(connection)
    try:
        originals = (
            tls._load_original(connection.trust, MAX_TLS_CA_BYTES, False, budget, owners),
            tls._load_original(connection.cookie, MAX_COOKIE_BYTES, True, budget, owners),
            tls._load_original(connection.csrf, MAX_CSRF_BYTES, True, budget, owners),
        )
        ca_text, _certificates = tls._public_certificates(originals[0].raw, budget, client=False)
        cookie, csrf = _credentials(originals[1].raw, originals[2].raw)
        context = tls._context(ca_text, budget)
        headers = (("Content-Type", "application/json"), ("Accept", "application/json"),
            ("Origin", connection.origin), ("Cookie", cookie), ("X-Serverware-CSRF-Token", csrf))
        result = _OperatorTransport(_CONSTRUCTION, connection, configuration, authority,
            budget, originals, context, headers)
        owners.callback(_close, result)
        result.current()
        return result
    except (OSError, ValueError):
        raise WorkloadClientError("operator HTTPS pinned configuration is invalid") from None
