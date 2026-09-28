"""Fixed public proof-setup request; no packet, token or target authority.

Raw4 carries purpose, completion request, state receipt and signed intent.
The opaque raw1 reply is a root bootstrap, never proof-worker readiness.
The issuer's independent packet acquisition and signer service are separate.
"""
from __future__ import annotations

from serverware import authority_registration_completion_transport as framing
from serverware import oidc_session_activation_release_proof_bootstrap as bootstrap
from serverware import oidc_session_activation_release_transport as chunks


AuthorityTransportError = framing.AuthorityTransportError
authority_transport, io = framing.authority_transport, framing.io
REQUEST_PEER_UID = REQUEST_PEER_GID = 65532
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
LISTENER_PATH = "/run/serverware/oidc-session-activation-release-proof-inputs/grants.sock"
PURPOSE = b"issue-oidc-session-activation-release-proof-inputs"
REQUEST_MAGIC, RESPONSE_MAGIC = b"SWOPIQ01", b"SWOPIR01"
REQUEST_LIMITS = (len(PURPOSE), bootstrap.records.MAX_REQUEST_BYTES,
    bootstrap.records.MAX_RECEIPT_BYTES, bootstrap.intent.MAX_BYTES)
RESPONSE_LIMITS = (bootstrap.MAX_BYTES,)
REQUEST_HEADER_BYTES, RESPONSE_HEADER_BYTES = 40, 16
MAX_BYTES = MAX_REQUEST_BYTES = sum(REQUEST_LIMITS)
MAX_RESPONSE_BYTES = bootstrap.MAX_BYTES
MAX_EXCHANGE_BYTES = bootstrap.MAX_ORIGINAL_BYTES
_timeout, _deadline_ns = framing._timeout, framing._deadline_ns


def _fail(message):
    raise AuthorityTransportError(message)


def _endpoint(endpoint):
    if type(endpoint) is not tuple or len(endpoint) != 4:
        _fail("proof input endpoint requires its fixed four-tuple")
    path, timeout, uid, gid = endpoint
    if (type(path) is not str or path != LISTENER_PATH or type(timeout) is not int
            or type(uid) is not int or uid != 0 or type(gid) is not int or gid != 0):
        _fail("proof input endpoint differs from its fixed root listener")
    return path, _timeout(timeout), uid, gid


def _exchange_bound():
    if (MAX_EXCHANGE_BYTES != 64 * 1024 * 1024 or MAX_RESPONSE_BYTES != 48 * 1024 * 1024
            or REQUEST_HEADER_BYTES + MAX_REQUEST_BYTES + RESPONSE_HEADER_BYTES
                + MAX_RESPONSE_BYTES > MAX_EXCHANGE_BYTES):
        _fail("proof input framing exceeds the complete exchange bound")


def _request_lengths(lengths):
    _exchange_bound()
    if (type(lengths) is not tuple or len(lengths) != 4
            or any(type(size) is not int for size in lengths)
            or lengths[0] != len(PURPOSE)
            or any(not 2 <= size <= maximum for size, maximum in zip(lengths[1:], REQUEST_LIMITS[1:]))):
        _fail("proof input request differs from its bounded raw4")


def _response_limit(maximum_response_bytes):
    maximum = MAX_RESPONSE_BYTES if maximum_response_bytes is None else maximum_response_bytes
    if type(maximum) is not int or not 2 <= maximum <= MAX_RESPONSE_BYTES:
        _fail("proof input response capacity may only tighten the original bound")
    return maximum


def _response_lengths(lengths, *, maximum_response_bytes=None):
    _exchange_bound()
    maximum = _response_limit(maximum_response_bytes)
    if (type(lengths) is not tuple or len(lengths) != 1
            or type(lengths[0]) is not int or not 0 <= lengths[0] <= maximum):
        _fail("proof input response exceeds its opaque raw1 bound")


def _originals(values, *, response):
    if (type(response) is not bool or type(values) is not tuple
            or len(values) != (1 if response else 4) or any(type(raw) is not bytes for raw in values)):
        _fail("proof input framing requires exact immutable originals")
    (_response_lengths if response else _request_lengths)(tuple(map(len, values)))
    if not response and values[0] != PURPOSE:
        _fail("proof input request purpose differs")
    return values


def _recv_request(connection, *, deadline_ns, work, current, maximum_request_bytes=None):
    maximum = MAX_REQUEST_BYTES if maximum_request_bytes is None else maximum_request_bytes
    if type(maximum) is not int or not 1 <= maximum <= MAX_REQUEST_BYTES:
        _fail("proof input request capacity may only tighten its fixed bound")
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    chunks._guard(work, current, deadline_ns)
    chunks._connection(connection, **kwargs)
    chunks._peer(connection, (REQUEST_PEER_UID, REQUEST_PEER_GID), **kwargs)
    if chunks._recv_exact(connection, 8, **kwargs) != REQUEST_MAGIC:
        _fail("proof input request magic differs")
    header = chunks._recv_exact(connection, REQUEST_HEADER_BYTES - 8, **kwargs)
    work.charge(input_bytes=len(header))
    lengths = tuple(int.from_bytes(header[index:index + 8], "big") for index in range(0, len(header), 8))
    _request_lengths(lengths)
    if sum(lengths) > maximum:
        _fail("proof input request exceeds remaining service capacity")
    work.charge(input_bytes=2 * sum(lengths))
    originals = tuple(chunks._recv_precharged(connection, size, **kwargs) for size in lengths)
    chunks._eof(connection, **kwargs)
    originals = _originals(originals, response=False)
    chunks._guard(work, current, deadline_ns)
    return originals


def _send_response(connection, originals, *, deadline_ns, work, current):
    held = _originals(originals, response=True)
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    chunks._guard(work, current, deadline_ns)
    chunks._connection(connection, **kwargs)
    chunks._peer(connection, (REQUEST_PEER_UID, REQUEST_PEER_GID), **kwargs)
    work.charge(input_bytes=2 * RESPONSE_HEADER_BYTES + len(held[0]))
    header = RESPONSE_MAGIC + len(held[0]).to_bytes(8, "big")
    for raw in (header, *held):
        chunks._send_precharged(connection, raw, **kwargs)
    chunks._guard(work, current, deadline_ns)


def _socket_request_on_work(endpoint, *, originals, deadline_ns, work, current,
        maximum_response_bytes=None):
    from serverware import authority_oidc_session_activation_caller_transport as guarded
    return guarded._release_proof_inputs_on_work(endpoint, originals=originals,
        deadline_ns=deadline_ns, work=work, current=current,
        maximum_response_bytes=_response_limit(maximum_response_bytes))
