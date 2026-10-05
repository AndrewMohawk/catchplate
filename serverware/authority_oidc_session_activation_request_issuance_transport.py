"""Fixed raw1/raw7 issuance framing; neither peer nor bytes grant authority."""
from __future__ import annotations

from serverware import authority_oidc_session_activation_request_issuance as issuance
from serverware import oidc_session_activation_release_transport as chunks
from serverware import authority_registration_completion_transport as framing


AuthorityTransportError = framing.AuthorityTransportError
LISTENER_PATH = "/run/serverware/oidc-session-activation-request-issuance/issue.sock"
REQUEST_MAGIC, RESPONSE_MAGIC = b"SWOAIQ01", b"SWOAIR01"
REQUEST_PEER_UID = REQUEST_PEER_GID = 65532
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
REQUEST_LIMITS = (issuance.MAX_REQUEST_BYTES,)
RESPONSE_LIMITS = (issuance.MAX_REQUEST_BYTES, issuance.head.MAX_QUERY_BYTES,
    issuance.head.MAX_BYTES, issuance.planner.MAX_BYTES,
    *(issuance.receiving.MAX_BYTES for _ in issuance.policy.RECEIVERS))
REQUEST_HEADER_BYTES = 8 + 8 * len(REQUEST_LIMITS)
RESPONSE_HEADER_BYTES = 8 + 8 * len(RESPONSE_LIMITS)
MAX_RESPONSE_BYTES = sum(RESPONSE_LIMITS)
MAX_BYTES = MAX_EXCHANGE_BYTES = issuance.policy.authority.MAX_RESULT_BYTES
_deadline_ns = framing._deadline_ns


def _fail(message):
    raise AuthorityTransportError(message)


def _endpoint(value):
    if (type(value) is not tuple or len(value) != 4 or type(value[0]) is not str
            or value[0] != LISTENER_PATH or type(value[1]) is not int or not 1 <= value[1] <= 30
            or type(value[2]) is not int or value[2] != 0
            or type(value[3]) is not int or value[3] != 0):
        _fail("activation request issuer endpoint differs from its fixed root listener")
    return value


def _lengths(lengths, *, response):
    if type(response) is not bool:
        _fail("activation request issuance direction is not exact")
    limits = RESPONSE_LIMITS if response else REQUEST_LIMITS
    if (type(lengths) is not tuple or len(lengths) != len(limits)
            or any(type(size) is not int or not 2 <= size <= maximum
                for size, maximum in zip(lengths, limits, strict=True))
            or sum(lengths) + REQUEST_HEADER_BYTES + RESPONSE_HEADER_BYTES
                + (sum(REQUEST_LIMITS) if response else MAX_RESPONSE_BYTES) > MAX_EXCHANGE_BYTES):
        _fail("activation request issuance exceeds its fixed frame or complete exchange bound")


def _response_lengths(lengths):
    _lengths(lengths, response=True)


def _originals(values, *, response):
    if type(values) is not tuple or any(type(raw) is not bytes for raw in values):
        _fail("activation request issuance requires exact immutable original frames")
    _lengths(tuple(map(len, values)), response=response)
    return values


def _recv_request(connection, *, deadline_ns, work, current):
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    chunks._guard(work, current, deadline_ns)
    chunks._connection(connection, **kwargs)
    chunks._peer(connection, (REQUEST_PEER_UID, REQUEST_PEER_GID), **kwargs)
    if chunks._recv_exact(connection, 8, **kwargs) != REQUEST_MAGIC:
        _fail("activation request issuance magic differs")
    header = chunks._recv_exact(connection, 8, **kwargs)
    work.charge(input_bytes=8)
    lengths = (int.from_bytes(header, "big"),)
    _lengths(lengths, response=False)
    work.charge(input_bytes=2 * lengths[0])
    raw = chunks._recv_precharged(connection, lengths[0], **kwargs)
    chunks._eof(connection, **kwargs)
    chunks._guard(work, current, deadline_ns)
    return _originals((raw,), response=False)


def _send_response(connection, originals, *, deadline_ns, work, current):
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


def _socket_request_on_work(endpoint, *, request_bytes, deadline_ns, work, current):
    from serverware import authority_oidc_session_activation_caller_transport as guarded
    return guarded._request_issuance_on_work(endpoint, originals=(request_bytes,),
        deadline_ns=deadline_ns, work=work, current=current)
