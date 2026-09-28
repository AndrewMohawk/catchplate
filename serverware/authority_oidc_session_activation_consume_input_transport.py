"""Fixed consume-input issuance framing, never planning or root authority.

Raw17 carries exact activation originals, expectations, before-vector and
ephemeral old-token possession. The raw2 response is opaque until genuine
receiving admission. This transport creates no service, key, replacement work
or clock allowance, journal entry, error status or automatic retry.
"""
from __future__ import annotations

from serverware import authority_contract as authority
from serverware import authority_registration_completion_transport as framing
from serverware import oidc_session_activation_release_transport as chunks
from serverware import authority_oidc_session_activation_delivery_planner_transport as planner
from serverware import authority_oidc_session_activation_execution_expectations as expectations
from serverware import authority_current_root_vector as vector
from serverware import oidc_session_activation_delivery_planner_bootstrap as bootstrap
from serverware import oidc_session_activation_history_custody_bootstrap as history


authority_transport, io = framing.authority_transport, framing.io
AuthorityTransportError = framing.AuthorityTransportError
REQUEST_PEER_UID = REQUEST_PEER_GID = 65532
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
LISTENER_PATH = "/run/serverware/oidc-session-activation-consume-inputs/grants.sock"
PURPOSE = b"issue-oidc-session-activation-consume-inputs"
REQUEST_MAGIC, RESPONSE_MAGIC = b"SWOCIQ01", b"SWOCIR01"
ACTIVATION_LIMITS = planner.ACTIVATION_LIMITS
REQUEST_LIMITS = (len(PURPOSE), *ACTIVATION_LIMITS, expectations.MAX_BYTES, vector.MAX_BYTES, 64)
RESPONSE_LIMITS = (bootstrap.MAX_BYTES, history.MAX_BYTES)
REQUEST_HEADER_BYTES = 8 + 8 * len(REQUEST_LIMITS)
RESPONSE_HEADER_BYTES = 8 + 8 * len(RESPONSE_LIMITS)
MAX_RESPONSE_BYTES = sum(RESPONSE_LIMITS)
MAX_EXCHANGE_BYTES = authority.MAX_RESULT_BYTES
# Large individual ciphertext caps cannot enlarge this complete exchange.
MAX_BYTES = MAX_REQUEST_BYTES = min(sum(REQUEST_LIMITS),
    MAX_EXCHANGE_BYTES - REQUEST_HEADER_BYTES - RESPONSE_HEADER_BYTES - MAX_RESPONSE_BYTES)
_timeout, _deadline_ns = planner._timeout, framing._deadline_ns
_check_deadline = io._check_deadline


def _fail(message):
    raise AuthorityTransportError(message)


def _endpoint(endpoint):
    if type(endpoint) is not tuple or len(endpoint) != 4:
        _fail("consume input endpoint requires its exact configured tuple")
    path, timeout, uid, gid = endpoint
    if (type(path) is not str or path != LISTENER_PATH
            or type(uid) is not int or uid != EXPECTED_PEER_UID
            or type(gid) is not int or gid != EXPECTED_PEER_GID):
        _fail("consume input endpoint differs from its fixed root listener")
    return path, _timeout(timeout), uid, gid


def _exchange_bound():
    if (len(ACTIVATION_LIMITS) != 13 or len(REQUEST_LIMITS) != 17 or len(RESPONSE_LIMITS) != 2
            or MAX_EXCHANGE_BYTES != 64 * 1024 * 1024 or MAX_REQUEST_BYTES <= 0
            or REQUEST_HEADER_BYTES + MAX_REQUEST_BYTES + RESPONSE_HEADER_BYTES
                + MAX_RESPONSE_BYTES > MAX_EXCHANGE_BYTES):
        _fail("consume input framing exceeds its fixed complete exchange")


def _request_lengths(lengths):
    _exchange_bound()
    if (type(lengths) is not tuple or len(lengths) != len(REQUEST_LIMITS)
            or any(type(size) is not int or not 0 <= size <= maximum
                for size, maximum in zip(lengths, REQUEST_LIMITS))
            or lengths[0] != len(PURPOSE) or lengths[-1] != 64
            or any(size < 2 for size in lengths[5:16]) or sum(lengths) > MAX_REQUEST_BYTES):
        _fail("consume input request exceeds its raw17 or whole-exchange bounds")
    # Actual completion framing only, not signature, replay or state admission.
    planner.completion.transport._response_lengths(lengths[1:5])


def _response_lengths(lengths):
    _exchange_bound()
    if (type(lengths) is not tuple or len(lengths) != len(RESPONSE_LIMITS)
            or any(type(size) is not int or not 0 <= size <= maximum
                for size, maximum in zip(lengths, RESPONSE_LIMITS))):
        _fail("consume input response exceeds its opaque original raw2 bounds")


def _originals(values, *, response):
    if type(response) is not bool:
        _fail("consume input frame direction is invalid")
    count = len(RESPONSE_LIMITS) if response else len(REQUEST_LIMITS)
    if (type(values) is not tuple or len(values) != count
            or any(type(raw) is not bytes for raw in values)):
        _fail("consume input transport requires its exact immutable original inventory")
    (_response_lengths if response else _request_lengths)(tuple(map(len, values)))
    if not response:
        if values[0] != PURPOSE or any(point not in planner._URLSAFE for point in values[-1]):
            _fail("consume input request purpose or old-token grammar differs")
        planner.completion.transport._originals(values[1:5], response=True)
    return values


def _recv_request(connection, *, deadline_ns, work, current):
    """Fixed public caller peer precedes header and bounded body allocation."""
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    chunks._guard(work, current, deadline_ns)
    chunks._connection(connection, **kwargs)
    chunks._peer(connection, (REQUEST_PEER_UID, REQUEST_PEER_GID), **kwargs)
    if chunks._recv_exact(connection, 8, **kwargs) != REQUEST_MAGIC:
        _fail("consume input request magic differs")
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
    """Frame opaque original bytes; the actual service owns its socket."""
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


def _socket_request_on_work(endpoint, *, originals, deadline_ns, work, current):
    """One original-work exchange returning unverified planner/history raw2."""
    from serverware import authority_oidc_session_activation_caller_transport as guarded
    return guarded._consume_inputs_on_work(endpoint, originals=originals,
        deadline_ns=deadline_ns, work=work, current=current)
