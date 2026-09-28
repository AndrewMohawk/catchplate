"""One fixed original-only workload issuance exchange, never admission.

Lengths and the complete representation reserve are checked before body one.
The existing work and absolute deadline cover peer checks, every native chunk
and sends. Only success raw2 exists; uncertainty closes the connection.
"""
from __future__ import annotations

import select
import socket
import time

from serverware import authority_transport
from serverware.authority_query_read_work import _ValidationWork


LISTENER_PATH = "/run/serverware/workload-identity-issuer/issuer.sock"
SERVICE_UID = SERVICE_GID = 65492
REQUEST_PEER_UID = REQUEST_PEER_GID = 65532
REQUEST_MAGIC, RESPONSE_MAGIC = b"SWWIIQ01", b"SWWIIR01"
REQUEST_LIMITS = (32 * 1024, 8 * 1024 * 1024, 64 * 1024)
RESPONSE_LIMITS = (4 * 1024, 64 * 1024)
REQUEST_HEADER_BYTES = 8 + 8 * len(REQUEST_LIMITS)
RESPONSE_HEADER_BYTES = 8 + 8 * len(RESPONSE_LIMITS)
MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES = sum(REQUEST_LIMITS), sum(RESPONSE_LIMITS)
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
_CHUNK_BYTES = 64 * 1024
JOURNAL_RESERVATION_BYTES = 2 * 1024 * 1024
FIXED_RESERVATION_BYTES = 16 * MAX_RESPONSE_BYTES + JOURNAL_RESERVATION_BYTES + 128 * 1024


class WorkloadIdentityIssuerTransportError(ValueError):
    pass


def _fail(message):
    raise WorkloadIdentityIssuerTransportError(message)


def _guard(work, current, deadline_ns):
    if (type(work) is not _ValidationWork or not callable(current)
            or type(deadline_ns) is not int or deadline_ns <= 0):
        _fail("workload issuer requires its original work, guard and deadline")
    limits, before = work.limits, work.metrics
    ceiling = (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
    current()
    after = work.metrics
    if (work.limits is not limits
            or ceiling != (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
            or after.hash_work < before.hash_work or after.input_bytes < before.input_bytes
            or after.json_nodes < before.json_nodes):
        _fail("workload issuer guard changed or reset its original allowance")
    work.charge(input_bytes=1)
    remaining = deadline_ns - time.monotonic_ns()
    if remaining <= 0:
        _fail("workload issuer original transport deadline expired")
    return remaining


def _native(operation, *, work, current, deadline_ns):
    work.charge(input_bytes=1)
    _guard(work, current, deadline_ns)
    limits, before = work.limits, work.metrics
    ceiling = (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
    try:
        return operation()
    finally:
        if (work.limits is not limits or work.metrics != before
                or ceiling != (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)):
            _fail("workload issuer native operation changed its metered ledger")
        _guard(work, current, deadline_ns)


def _connection(connection, *, work, current, deadline_ns):
    if type(connection) is not socket.socket:
        _fail("workload issuer requires its actual owned Unix connection")
    observed = _native(lambda: (connection.family, connection.type,
        connection.gettimeout(), connection.fileno(),
        connection.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)),
        work=work, current=current, deadline_ns=deadline_ns)
    if (observed[0] != socket.AF_UNIX or observed[1] != socket.SOCK_STREAM
            or observed[2] != 0.0 or observed[3] < 0 or observed[4] != 0):
        _fail("workload issuer connection is not an owned nonblocking Unix stream")
    work.charge(input_bytes=12)
    uid, gid, _pid = _native(lambda: authority_transport._peer_identity(connection),
        work=work, current=current, deadline_ns=deadline_ns)
    if (uid, gid) != (REQUEST_PEER_UID, REQUEST_PEER_GID):
        _fail("workload issuer connection has a different purpose peer")


def _ready(connection, *, writing, work, current, deadline_ns):
    remaining = _guard(work, current, deadline_ns)
    readable, writable, exceptional = _native(lambda: select.select(
        [] if writing else [connection], [connection] if writing else [],
        [connection], remaining / 1_000_000_000),
        work=work, current=current, deadline_ns=deadline_ns)
    if exceptional or not (writable if writing else readable):
        _fail("workload issuer readiness expired or failed")


def _lengths(lengths, *, response):
    limits = RESPONSE_LIMITS if response else REQUEST_LIMITS
    if (type(response) is not bool or type(lengths) is not tuple or len(lengths) != len(limits)
            or any(type(size) is not int or not 2 <= size <= maximum
                for size, maximum in zip(lengths, limits))):
        _fail("workload issuer frame inventory differs from its closed profile")
    return lengths


def _originals(values, *, response):
    if type(values) is not tuple or any(type(raw) is not bytes for raw in values):
        _fail("workload issuer transport requires immutable originals")
    _lengths(tuple(map(len, values)), response=response)
    return values


def _request_reservation(lengths):
    """Source representation ceiling, not a new allowance or heap estimate."""
    _lengths(lengths, response=False)
    return (8 * sum(lengths) + FIXED_RESERVATION_BYTES
        + REQUEST_HEADER_BYTES + RESPONSE_HEADER_BYTES)


def _recv_precharged(connection, count, *, work, current, deadline_ns):
    _guard(work, current, deadline_ns)
    buffer = bytearray(count)
    view, offset = memoryview(buffer), 0
    while offset < count:
        _ready(connection, writing=False, work=work, current=current, deadline_ns=deadline_ns)
        size = min(count - offset, _CHUNK_BYTES)
        received, ancillary, flags, _address = _native(
            lambda: connection.recvmsg_into([view[offset:offset + size]], 0),
            work=work, current=current, deadline_ns=deadline_ns)
        if ancillary or flags or type(received) is not int or not 1 <= received <= size:
            _fail("workload issuer frame closed early or carried ancillary data")
        offset += received
    result = bytes(buffer)
    _guard(work, current, deadline_ns)
    return result


def _recv_request(connection, *, maximum_original_bytes, deadline_ns, work, current):
    if (type(maximum_original_bytes) is not int
            or not 0 < maximum_original_bytes <= MAX_ORIGINAL_BYTES):
        _fail("workload issuer request allowance can only tighten the source ceiling")
    kwargs = dict(deadline_ns=deadline_ns, work=work, current=current)
    _connection(connection, **kwargs)
    work.charge(input_bytes=2 * REQUEST_HEADER_BYTES)
    header = _recv_precharged(connection, REQUEST_HEADER_BYTES, **kwargs)
    if header[:8] != REQUEST_MAGIC:
        _fail("workload issuer request purpose/version differs")
    lengths = tuple(int.from_bytes(header[index:index + 8], "big")
        for index in range(8, REQUEST_HEADER_BYTES, 8))
    if _request_reservation(lengths) > maximum_original_bytes:
        _fail("workload issuer request representations exceed retained capacity")
    work.charge(input_bytes=2 * sum(lengths))
    originals = tuple(_recv_precharged(connection, size, **kwargs) for size in lengths)
    work.charge(input_bytes=1)
    _ready(connection, writing=False, **kwargs)
    tail, ancillary, flags, _address = _native(lambda: connection.recvmsg(1, 0), **kwargs)
    if tail != b"" or ancillary or flags:
        _fail("workload issuer request has trailing or ancillary data")
    _connection(connection, **kwargs)
    return _originals(originals, response=False)


def _send_response(connection, originals, *, deadline_ns, work, current):
    held = _originals(originals, response=True)
    kwargs = dict(deadline_ns=deadline_ns, work=work, current=current)
    _connection(connection, **kwargs)
    work.charge(input_bytes=2 * RESPONSE_HEADER_BYTES + sum(map(len, held)))
    header = RESPONSE_MAGIC + b"".join(len(raw).to_bytes(8, "big") for raw in held)
    for raw in (header, *held):
        view, offset = memoryview(raw), 0
        while offset < len(raw):
            _ready(connection, writing=True, **kwargs)
            size = min(len(raw) - offset, _CHUNK_BYTES)
            sent = _native(lambda: connection.send(view[offset:offset + size]), **kwargs)
            if type(sent) is not int or not 1 <= sent <= size:
                _fail("workload issuer response closed early or changed its write bound")
            offset += sent
    _connection(connection, **kwargs)
