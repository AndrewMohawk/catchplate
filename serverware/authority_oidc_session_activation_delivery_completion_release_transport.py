"""Explicit raw2/raw6 completion profile carrying unsigned release hints.

Launch v3 alone selects this grammar. The request remains the original caller
authorization; response raw4 is unchanged and two bounded hint frames follow.
No hint is authenticated by the completion/state signatures or grants release.
"""
from __future__ import annotations

from serverware import authority_oidc_session_activation_delivery_completion_dispatch_transport as dispatch
from serverware import authority_oidc_session_activation_release_hints as hints


authority_transport, io = dispatch.authority_transport, dispatch.io
AuthorityTransportError = dispatch.AuthorityTransportError
PURPOSE = dispatch.PURPOSE
REQUEST_MAGIC, RESPONSE_MAGIC = b"SWODCM03", b"SWODCR02"
LISTENER_PATH = dispatch.LISTENER_PATH
REQUEST_PEER_UID, REQUEST_PEER_GID = dispatch.REQUEST_PEER_UID, dispatch.REQUEST_PEER_GID
EXPECTED_PEER_UID, EXPECTED_PEER_GID = dispatch.EXPECTED_PEER_UID, dispatch.EXPECTED_PEER_GID
REQUEST_LIMITS = dispatch.REQUEST_LIMITS
RESPONSE_LIMITS = dispatch.RESPONSE_LIMITS + hints.LIMITS
REQUEST_HEADER_BYTES = len(REQUEST_MAGIC) + 8 * len(REQUEST_LIMITS)
RESPONSE_HEADER_BYTES = len(RESPONSE_MAGIC) + 8 * len(RESPONSE_LIMITS)
MAX_BYTES = MAX_REQUEST_BYTES = sum(REQUEST_LIMITS)
MAX_RESPONSE_BYTES = sum(RESPONSE_LIMITS)
MAX_EXCHANGE_BYTES = dispatch.MAX_EXCHANGE_BYTES
_endpoint, _timeout, _deadline_ns = dispatch._endpoint, dispatch._timeout, dispatch._deadline_ns
_check_deadline, _recv_prefix = dispatch._check_deadline, dispatch._recv_prefix


def _exchange_bound():
    if (REQUEST_HEADER_BYTES + MAX_REQUEST_BYTES + RESPONSE_HEADER_BYTES
            + MAX_RESPONSE_BYTES > MAX_EXCHANGE_BYTES):
        raise AuthorityTransportError("consume release-hint exchange exceeds its fixed bound")


def _response_limit(maximum_response_bytes):
    maximum = MAX_RESPONSE_BYTES if maximum_response_bytes is None else maximum_response_bytes
    if type(maximum) is not int or not 1 <= maximum <= MAX_RESPONSE_BYTES:
        raise AuthorityTransportError("consume completion hints response cap must only tighten")
    return maximum


def _response_lengths(lengths, *, maximum_response_bytes=None):
    _exchange_bound()
    if (type(lengths) is not tuple or len(lengths) != 6
            or any(type(size) is not int or not 0 <= size <= maximum
                for size, maximum in zip(lengths, RESPONSE_LIMITS))
            or sum(lengths) > _response_limit(maximum_response_bytes)):
        raise AuthorityTransportError("consume release-hint response lengths differ")
    dispatch._response_lengths(lengths[:4])
    if not ((lengths[0] == len(b"acknowledged") and lengths[4] == 71 and lengths[5] >= 2)
            or (lengths[0] == len(b"uncertain") and lengths[4:] == (0, 0))):
        raise AuthorityTransportError("consume release-hint response inventory differs")


def _originals(values, *, response):
    if type(response) is not bool:
        raise AuthorityTransportError("consume release-hint direction is invalid")
    _exchange_bound()
    if not response:
        return dispatch._originals(values, response=False)
    if (type(values) is not tuple or len(values) != 6
            or any(type(raw) is not bytes for raw in values)):
        raise AuthorityTransportError("consume release hints require immutable raw6")
    _response_lengths(tuple(map(len, values)))
    dispatch._originals(values[:4], response=True)
    # Do not decode or admit hints before the caller durably retains them.
    return values


def _recv_request(connection, *, deadline_ns):
    if _recv_prefix(connection, deadline_ns=deadline_ns) != REQUEST_MAGIC:
        raise AuthorityTransportError("consume release-hint request magic differs")
    header = io._recv_exact_until(connection, 8 * len(REQUEST_LIMITS), deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[offset:offset + 8], "big")
        for offset in range(0, len(header), 8))
    dispatch._request_lengths(lengths)
    values = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns) for size in lengths)
    io._require_eof(connection, deadline_ns)
    return _originals(values, response=False)


def _send_response(connection, originals, *, deadline_ns):
    held = _originals(originals, response=True)
    header = RESPONSE_MAGIC + b"".join(len(raw).to_bytes(8, "big") for raw in held)
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    for raw in held:
        if raw:
            io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _socket_request_on_work(endpoint, *, originals, deadline_ns, work, current,
        maximum_response_bytes=None):
    from serverware import authority_oidc_session_activation_caller_transport as guarded
    return guarded._consume_completion_release_on_work(endpoint, originals=originals,
        deadline_ns=deadline_ns, work=work, current=current,
        maximum_response_bytes=_response_limit(maximum_response_bytes))
