"""Fixed release-grant issuance framing, never issuance or response admission.

The request contains only the literal issuer purpose and the actual LIVE raw7
release originals. Policy, resources and issuer authority stay independently
held by the service. The opaque raw2 response must be retained and genuinely
admitted by the caller; no status/error frame, new allowance or retry exists.
"""
from __future__ import annotations

from serverware import authority_contract as authority
from serverware import authority_registration_completion_transport as framing
from serverware import oidc_session_activation_release_transport as release
from serverware import oidc_session_activation_release_client_authorization as client


authority_transport, io = framing.authority_transport, framing.io
AuthorityTransportError = framing.AuthorityTransportError
REQUEST_PEER_UID = REQUEST_PEER_GID = 65532
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
LISTENER_PATH = "/run/serverware/oidc-session-activation-token-release/grants.sock"
PURPOSE = b"issue-oidc-session-activation-release-grants"
REQUEST_MAGIC, RESPONSE_MAGIC = b"SWOGIQ01", b"SWOGIR01"
REQUEST_LIMITS = (len(PURPOSE), *release.LIVE_REQUEST_LIMITS)
RESPONSE_LIMITS = (client.MAX_BYTES, client.MAX_SERVER_BOOTSTRAP_BYTES)
REQUEST_HEADER_BYTES = 8 + 8 * len(REQUEST_LIMITS)
RESPONSE_HEADER_BYTES = 8 + 8 * len(RESPONSE_LIMITS)
MAX_BYTES = MAX_REQUEST_BYTES = sum(REQUEST_LIMITS)
MAX_RESPONSE_BYTES = sum(RESPONSE_LIMITS)
MAX_EXCHANGE_BYTES = authority.MAX_RESULT_BYTES
_timeout, _deadline_ns = framing._timeout, framing._deadline_ns
_check_deadline = io._check_deadline


def _fail(message):
    raise AuthorityTransportError(message)


def _endpoint(endpoint):
    if type(endpoint) is not tuple or len(endpoint) != 4:
        _fail("release grant endpoint requires its exact configured tuple")
    path, timeout, uid, gid = endpoint
    if (type(path) is not str or path != LISTENER_PATH
            or type(uid) is not int or uid != EXPECTED_PEER_UID
            or type(gid) is not int or gid != EXPECTED_PEER_GID):
        _fail("release grant endpoint differs from its fixed root listener")
    return path, _timeout(timeout), uid, gid


def _exchange_bound():
    if (MAX_EXCHANGE_BYTES != 64 * 1024 * 1024
            or REQUEST_HEADER_BYTES + MAX_REQUEST_BYTES + RESPONSE_HEADER_BYTES
                + MAX_RESPONSE_BYTES > MAX_EXCHANGE_BYTES):
        _fail("release grant framing exceeds its complete exchange ceiling")


def _request_lengths(lengths):
    _exchange_bound()
    if (type(lengths) is not tuple or len(lengths) != len(REQUEST_LIMITS)
            or any(type(size) is not int for size in lengths)
            or lengths[0] != REQUEST_LIMITS[0]):
        _fail("release grant request lengths differ from its fixed raw8")
    release._request_lengths(lengths[1:], release.LIVE_PROFILE)


def _response_lengths(lengths):
    _exchange_bound()
    if (type(lengths) is not tuple or len(lengths) != len(RESPONSE_LIMITS)
            or any(type(size) is not int or not 0 <= size <= maximum
                for size, maximum in zip(lengths, RESPONSE_LIMITS))):
        _fail("release grant response exceeds its opaque raw2 bounds")


def _originals(values, *, response):
    if type(response) is not bool:
        _fail("release grant frame direction is invalid")
    count = len(RESPONSE_LIMITS) if response else len(REQUEST_LIMITS)
    if (type(values) is not tuple or len(values) != count
            or any(type(raw) is not bytes for raw in values)):
        _fail("release grant transport requires its exact immutable originals")
    (_response_lengths if response else _request_lengths)(tuple(map(len, values)))
    if not response:
        if values[0] != PURPOSE:
            _fail("release grant request purpose differs")
        release._originals(values[1:], response=False, profile=release.LIVE_PROFILE)
    return values


def _recv_request(connection, *, deadline_ns, work, current):
    """Admit the fixed peer before reading the bounded request inventory."""
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    release._guard(work, current, deadline_ns)
    release._connection(connection, **kwargs)
    release._peer(connection, (REQUEST_PEER_UID, REQUEST_PEER_GID), **kwargs)
    if release._recv_exact(connection, 8, **kwargs) != REQUEST_MAGIC:
        _fail("release grant request magic differs")
    header = release._recv_exact(connection, 8 * len(REQUEST_LIMITS), **kwargs)
    work.charge(input_bytes=len(header))
    lengths = tuple(int.from_bytes(header[index:index + 8], "big")
        for index in range(0, len(header), 8))
    _request_lengths(lengths)
    work.charge(input_bytes=2 * sum(lengths))
    originals = tuple(release._recv_precharged(connection, size, **kwargs) for size in lengths)
    release._eof(connection, **kwargs)
    originals = _originals(originals, response=False)
    release._guard(work, current, deadline_ns)
    return originals


def _send_response(connection, originals, *, deadline_ns, work, current):
    """Bound original bytes only; retain startup ownership of the socket."""
    held = _originals(originals, response=True)
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    release._guard(work, current, deadline_ns)
    release._connection(connection, **kwargs)
    release._peer(connection, (REQUEST_PEER_UID, REQUEST_PEER_GID), **kwargs)
    work.charge(input_bytes=2 * RESPONSE_HEADER_BYTES + sum(map(len, held)))
    header = RESPONSE_MAGIC + b"".join(len(raw).to_bytes(8, "big") for raw in held)
    for raw in (header, *held):
        release._send_precharged(connection, raw, **kwargs)
    release._guard(work, current, deadline_ns)


def _socket_request_on_work(endpoint, *, originals, deadline_ns, work, current):
    """One same-work caller exchange returning unauthenticated raw2."""
    from serverware import authority_oidc_session_activation_caller_transport as guarded
    return guarded._release_grants_on_work(endpoint, originals=originals,
        deadline_ns=deadline_ns, work=work, current=current)
