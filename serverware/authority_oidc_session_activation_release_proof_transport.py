"""One bounded private proof exchange; framing never admits its response.

The fixed request carries only purpose, intent identity and ephemeral old-token
possession. Raw4 responses remain opaque until a caller retains and genuinely
authenticates their custody/proof/enrollment originals. Server sockets remain
owned by startup; no error frame, new allowance or retry is provided here.
"""
from __future__ import annotations

from serverware import authority_contract as authority
from serverware import authority_registration_completion_transport as framing
from serverware import oidc_session_activation_release_transport as chunks
from serverware import oidc_session_activation_release_custody_bootstrap as custody
from serverware import oidc_session_activation_release_proof as proof
from serverware import oidc_session_activation_release_proof_enrollment as enrollment


authority_transport, io = framing.authority_transport, framing.io
AuthorityTransportError = framing.AuthorityTransportError
PROCESS_MODE = "oidc-session-activation-delivery-completion"
SERVICE_UID = SERVICE_GID = 65497
REQUEST_PEER_UID = REQUEST_PEER_GID = 65532
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
LISTENER_PATH = "/run/serverware/oidc-session-activation-token-release/proof.sock"
PURPOSE = b"prove-oidc-session-activation-release"
REQUEST_MAGIC, RESPONSE_MAGIC = b"SWORPQ01", b"SWORPR01"
REQUEST_LIMITS = (len(PURPOSE), 71, 64)
RESPONSE_LIMITS = (6, custody.MAX_BYTES, proof.MAX_BYTES, enrollment.MAX_BYTES)
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
        _fail("release proof endpoint requires its exact configured tuple")
    path, timeout, uid, gid = endpoint
    if (type(path) is not str or path != LISTENER_PATH
            or type(uid) is not int or uid != EXPECTED_PEER_UID
            or type(gid) is not int or gid != EXPECTED_PEER_GID):
        _fail("release proof endpoint differs from its fixed root listener")
    return path, _timeout(timeout), uid, gid


def _exchange_bound():
    if (MAX_EXCHANGE_BYTES != 64 * 1024 * 1024
            or REQUEST_HEADER_BYTES + MAX_REQUEST_BYTES + RESPONSE_HEADER_BYTES
                + MAX_RESPONSE_BYTES > MAX_EXCHANGE_BYTES):
        _fail("release proof framing exceeds its complete exchange ceiling")


def _request_lengths(lengths):
    _exchange_bound()
    if (type(lengths) is not tuple or lengths != REQUEST_LIMITS
            or any(type(size) is not int for size in lengths)):
        _fail("release proof request lengths differ from its exact raw3")


def _response_limit(maximum_response_bytes):
    maximum = MAX_RESPONSE_BYTES if maximum_response_bytes is None else maximum_response_bytes
    if type(maximum) is not int or not 0 < maximum <= MAX_RESPONSE_BYTES:
        _fail("release proof response capacity may only tighten the original bound")
    return maximum


def _response_lengths(lengths):
    _exchange_bound()
    if (type(lengths) is not tuple or len(lengths) != len(RESPONSE_LIMITS)
            or any(type(size) is not int or not 0 <= size <= maximum
                for size, maximum in zip(lengths, RESPONSE_LIMITS))):
        _fail("release proof response exceeds its opaque raw4 bounds")


def _originals(values, *, response):
    if type(response) is not bool:
        _fail("release proof frame direction is invalid")
    count = len(RESPONSE_LIMITS) if response else len(REQUEST_LIMITS)
    if (type(values) is not tuple or len(values) != count
            or any(type(raw) is not bytes for raw in values)):
        _fail("release proof requires an exact immutable original inventory")
    (_response_lengths if response else _request_lengths)(tuple(map(len, values)))
    if not response and (values[0] != PURPOSE or not framing._digest_bytes(values[1])):
        _fail("release proof request purpose or intent identity differs")
    return values


def _recv_request(connection, *, deadline_ns, work, current):
    """Fixed peer admission precedes even the first header/body allocation."""
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    chunks._guard(work, current, deadline_ns)
    chunks._connection(connection, **kwargs)
    chunks._peer(connection, (REQUEST_PEER_UID, REQUEST_PEER_GID), **kwargs)
    if chunks._recv_exact(connection, 8, **kwargs) != REQUEST_MAGIC:
        _fail("release proof request magic differs")
    header = chunks._recv_exact(connection, 8 * len(REQUEST_LIMITS), **kwargs)
    work.charge(input_bytes=len(header))
    lengths = tuple(int.from_bytes(header[index:index + 8], "big")
        for index in range(0, len(header), 8))
    _request_lengths(lengths)
    work.charge(input_bytes=2 * sum(lengths))
    originals = tuple(chunks._recv_precharged(connection, size, **kwargs) for size in lengths)
    chunks._eof(connection, **kwargs)
    originals = _originals(originals, response=False)
    chunks._guard(work, current, deadline_ns)
    return originals


def _send_response(connection, originals, *, deadline_ns, work, current):
    """Only the actual startup chooses success; this helper bounds raw bytes."""
    held = _originals(originals, response=True)
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    chunks._guard(work, current, deadline_ns)
    chunks._connection(connection, **kwargs)
    chunks._peer(connection, (REQUEST_PEER_UID, REQUEST_PEER_GID), **kwargs)
    work.charge(input_bytes=2 * RESPONSE_HEADER_BYTES + sum(map(len, held)))
    header = RESPONSE_MAGIC + b"".join(len(raw).to_bytes(8, "big") for raw in held)
    for raw in (header, *held):
        chunks._send_precharged(connection, raw, **kwargs)
    chunks._guard(work, current, deadline_ns)


def _socket_request_on_work(endpoint, *, originals, deadline_ns, work, current,
        maximum_response_bytes=None):
    """One actual same-work caller exchange, returning unauthenticated raw4."""
    from serverware import authority_oidc_session_activation_caller_transport as guarded
    return guarded._release_proof_on_work(endpoint, originals=originals,
        deadline_ns=deadline_ns, work=work, current=current,
        maximum_response_bytes=maximum_response_bytes)
