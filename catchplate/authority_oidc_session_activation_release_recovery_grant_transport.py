"""Fixed recovery-grant framing, not recovery authority or token delivery.

The issuer purpose precedes the existing recovery prefix7, without a candidate
outcome. The exact response is client/server/outcome raw3. There is no status,
error, retry, staging operation or caller-selected framing profile.
"""
from __future__ import annotations

from catchplate import authority_registration_completion_transport as framing
from catchplate import authority_oidc_session_activation_release_recovery_grant_production as grants
from catchplate import oidc_session_activation_release_transport as release


authority_transport, io = framing.authority_transport, framing.io
AuthorityTransportError = framing.AuthorityTransportError
REQUEST_PEER_UID = REQUEST_PEER_GID = 65532
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
LISTENER_PATH = "/run/catchplate/oidc-session-activation-token-release/recovery-grants.sock"
PURPOSE = b"issue-oidc-session-activation-release-recovery-grants"
REQUEST_MAGIC, RESPONSE_MAGIC = b"SWORGQ01", b"SWORGR01"
REQUEST_LIMITS = (len(PURPOSE), *release.RECOVERY_REQUEST_LIMITS[:7])
RESPONSE_LIMITS = (grants.clients.MAX_BYTES, grants.server.MAX_BYTES, grants.outcomes.MAX_BYTES)
REQUEST_HEADER_BYTES = 8 + 8 * len(REQUEST_LIMITS)
RESPONSE_HEADER_BYTES = 8 + 8 * len(RESPONSE_LIMITS)
MAX_BYTES = MAX_REQUEST_BYTES = sum(REQUEST_LIMITS)
MAX_RESPONSE_BYTES = sum(RESPONSE_LIMITS)
MAX_EXCHANGE_BYTES = grants.MAX_ORIGINAL_BYTES
_timeout, _deadline_ns = framing._timeout, framing._deadline_ns


def _fail(message):
    raise AuthorityTransportError(message)


def _endpoint(endpoint):
    if type(endpoint) is not tuple or len(endpoint) != 4:
        _fail("recovery grant endpoint requires its independently configured tuple")
    path, timeout, uid, gid = endpoint
    if (type(path) is not str or path != LISTENER_PATH or type(timeout) is not int
            or type(uid) is not int or uid != EXPECTED_PEER_UID
            or type(gid) is not int or gid != EXPECTED_PEER_GID):
        _fail("recovery grant endpoint differs from the fixed root listener")
    return path, _timeout(timeout), uid, gid


def _exchange_bound():
    if (MAX_EXCHANGE_BYTES != 64 * 1024 * 1024
            or REQUEST_HEADER_BYTES + MAX_REQUEST_BYTES + RESPONSE_HEADER_BYTES
                + MAX_RESPONSE_BYTES > MAX_EXCHANGE_BYTES):
        _fail("recovery grant framing exceeds its complete exchange ceiling")


def _request_lengths(lengths):
    _exchange_bound()
    if (type(lengths) is not tuple or len(lengths) != len(REQUEST_LIMITS)
            or any(type(size) is not int for size in lengths)
            or lengths[:2] != REQUEST_LIMITS[:2]
            or lengths[6:8] != REQUEST_LIMITS[6:8]
            or any(not 2 <= lengths[index] <= REQUEST_LIMITS[index] for index in (2, 3, 4, 5))):
        _fail("recovery grant request lengths differ from its fixed raw8")


def _response_limit(maximum_response_bytes):
    maximum = MAX_RESPONSE_BYTES if maximum_response_bytes is None else maximum_response_bytes
    if type(maximum) is not int or not 6 <= maximum <= MAX_RESPONSE_BYTES:
        _fail("recovery grant response capacity may only tighten its fixed total bound")
    return maximum


def _response_lengths(lengths, *, maximum_response_bytes=None):
    _exchange_bound()
    maximum = _response_limit(maximum_response_bytes)
    if (type(lengths) is not tuple or len(lengths) != len(RESPONSE_LIMITS)
            or any(type(size) is not int or not 2 <= size <= limit
                for size, limit in zip(lengths, RESPONSE_LIMITS))
            or sum(lengths) > maximum):
        _fail("recovery grant response differs from its bounded original triple")


def _originals(values, *, response):
    if (type(response) is not bool or type(values) is not tuple
            or len(values) != (3 if response else 8)
            or any(type(raw) is not bytes for raw in values)):
        _fail("recovery grant framing requires its exact immutable originals")
    (_response_lengths if response else _request_lengths)(tuple(map(len, values)))
    if not response:
        if values[0] != PURPOSE:
            _fail("recovery grant issuer purpose differs")
        grants._request_originals(values[1:])
    return values


def _recv_request(connection, *, deadline_ns, work, current, maximum_request_bytes=None):
    """Check the fixed peer and every length before bounded body allocation."""
    maximum = MAX_REQUEST_BYTES if maximum_request_bytes is None else maximum_request_bytes
    if type(maximum) is not int or not 1 <= maximum <= MAX_REQUEST_BYTES:
        _fail("recovery grant request capacity may only tighten its fixed bound")
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    release._guard(work, current, deadline_ns)
    release._connection(connection, **kwargs)
    release._peer(connection, (REQUEST_PEER_UID, REQUEST_PEER_GID), **kwargs)
    if release._recv_exact(connection, 8, **kwargs) != REQUEST_MAGIC:
        _fail("recovery grant request magic differs")
    header = release._recv_exact(connection, REQUEST_HEADER_BYTES - 8, **kwargs)
    work.charge(input_bytes=len(header))
    lengths = tuple(int.from_bytes(header[index:index + 8], "big")
        for index in range(0, len(header), 8))
    _request_lengths(lengths)
    if sum(lengths) > maximum:
        _fail("recovery grant request exceeds remaining service capacity")
    work.charge(input_bytes=2 * sum(lengths))
    originals = tuple(release._recv_precharged(connection, size, **kwargs) for size in lengths)
    release._eof(connection, **kwargs)
    originals = _originals(originals, response=False)
    release._guard(work, current, deadline_ns)
    return originals


def _send_response(connection, originals, *, deadline_ns, work, current):
    """Send only raw originals; startup keeps accepted-socket ownership."""
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


def _socket_request_on_work(endpoint, *, originals, deadline_ns, work, current,
        maximum_response_bytes=None):
    """One same-work exchange; returned bytes remain unauthenticated here."""
    from catchplate import authority_oidc_session_activation_caller_transport as guarded
    return guarded._recovery_grants_on_work(endpoint, originals=originals,
        deadline_ns=deadline_ns, work=work, current=current,
        maximum_response_bytes=_response_limit(maximum_response_bytes))
