"""Explicit consume completion dispatch raw2/raw4, not original admission.

Only the signed launch-v2 service selects this grammar and control-plane peer.
The request contains the exact signed consume caller authorization, never a
caller-selected packet locator. The actual owner must join it to its root-held
authorization before using its independently pinned packet and private custody.
The selector-v1 grammar and operation-neutral raw4 response remain unchanged.
"""
from __future__ import annotations

from serverware import authority_oidc_session_activation_delivery_completion_transport as completion
from serverware import authority_oidc_session_activation_delivery_execution_authorization as caller


authority_transport, io = completion.authority_transport, completion.io
AuthorityTransportError = completion.AuthorityTransportError
PURPOSE = b"complete-oidc-session-activation-delivery"
REQUEST_MAGIC, RESPONSE_MAGIC = b"SWODCM02", completion.RESPONSE_MAGIC
LISTENER_PATH = completion.LISTENER_PATH
REQUEST_PEER_UID = REQUEST_PEER_GID = 65532
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
REQUEST_LIMITS = (len(PURPOSE), caller.MAX_AUTHORIZATION_BYTES)
RESPONSE_LIMITS = completion.RESPONSE_LIMITS
REQUEST_HEADER_BYTES = len(REQUEST_MAGIC) + 8 * len(REQUEST_LIMITS)
RESPONSE_HEADER_BYTES = completion.RESPONSE_HEADER_BYTES
MAX_BYTES = MAX_REQUEST_BYTES = sum(REQUEST_LIMITS)
MAX_RESPONSE_BYTES = completion.MAX_RESPONSE_BYTES
MAX_EXCHANGE_BYTES = completion.MAX_EXCHANGE_BYTES
_endpoint, _timeout, _deadline_ns = completion._endpoint, completion._timeout, completion._deadline_ns
_check_deadline, _recv_prefix = completion._check_deadline, completion._recv_prefix


def _exchange_bound():
    if (REQUEST_HEADER_BYTES + MAX_REQUEST_BYTES + RESPONSE_HEADER_BYTES
            + MAX_RESPONSE_BYTES > MAX_EXCHANGE_BYTES):
        raise AuthorityTransportError("consume completion dispatch source exchange exceeds its bound")


def _request_lengths(lengths):
    _exchange_bound()
    if (type(lengths) is not tuple or len(lengths) != 2
            or any(type(size) is not int for size in lengths)
            or lengths[0] != len(PURPOSE)
            or not 2 <= lengths[1] <= caller.MAX_AUTHORIZATION_BYTES):
        raise AuthorityTransportError("consume completion dispatch request lengths differ")


def _response_lengths(lengths):
    _exchange_bound()
    completion._response_lengths(lengths)


def _originals(values, *, response):
    if type(response) is not bool:
        raise AuthorityTransportError("consume completion dispatch frame direction is invalid")
    _exchange_bound()
    if response:
        return completion._originals(values, response=True)
    if (type(values) is not tuple or len(values) != 2
            or any(type(raw) is not bytes for raw in values)):
        raise AuthorityTransportError("consume completion dispatch requires exact immutable raw2")
    _request_lengths(tuple(len(raw) for raw in values))
    if values[0] != PURPOSE:
        raise AuthorityTransportError("consume completion dispatch purpose differs")
    return values


def _recv_request(connection, *, deadline_ns):
    """The admitted service checks its launch-selected peer before decoding."""
    if _recv_prefix(connection, deadline_ns=deadline_ns) != REQUEST_MAGIC:
        raise AuthorityTransportError("consume completion dispatch request magic differs")
    header = io._recv_exact_until(connection, 8 * len(REQUEST_LIMITS), deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[offset:offset + 8], "big")
        for offset in range(0, len(header), 8))
    _request_lengths(lengths)
    values = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    io._require_eof(connection, deadline_ns)
    return _originals(values, response=False)


def _send_response(connection, originals, *, deadline_ns):
    _originals(originals, response=True)
    completion._send_response(connection, originals, deadline_ns=deadline_ns)


def _socket_request_on_work(endpoint, *, originals, deadline_ns, work, current):
    """One same-work/current exchange returns unverified consume raw4 only."""
    from serverware import authority_oidc_session_activation_caller_transport as guarded
    return guarded._consume_completion_dispatch_on_work(endpoint, originals=originals,
        deadline_ns=deadline_ns, work=work, current=current)
