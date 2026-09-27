"""Guarded, bounded private release framing; never response authentication.

The independently root-selected profile fixes raw7 or raw8 before allocation.
Only raw2 success exists: request identity and the actual 64-byte token. Every
native chunk retains the caller's work and genuine current guard. Server socket
ownership stays with startup; only the private client closes its own socket.
There is no error response, fallback, new allowance or exchange retry.
"""
from __future__ import annotations

import errno
import select
import socket

from serverware import authority_registration_completion_transport as framing
from serverware import oidc_session_activation_release_bootstrap as bootstrap
from serverware import oidc_session_activation_release_intent as intent
from serverware import oidc_session_activation_release_intent_enrollment as intent_enrollment
from serverware import oidc_session_activation_release_outcome as outcome


authority_transport, io = framing.authority_transport, framing.io
production, capture, plan = bootstrap.production, bootstrap.capture, bootstrap.plan
AuthorityTransportError = framing.AuthorityTransportError
PROCESS_MODE = bootstrap.PROCESS_MODE
SERVICE_UID, SERVICE_GID = bootstrap.SERVICE_UID, bootstrap.SERVICE_GID
REQUEST_PEER_UID, REQUEST_PEER_GID = bootstrap.PEER_UID, bootstrap.PEER_GID
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
LISTENER_PATH = bootstrap.LISTENER_PATH
LIVE_PROFILE, RECOVERY_PROFILE = bootstrap.LIVE_PROFILE, bootstrap.RECOVERY_PROFILE
LIVE_PURPOSE = b"open-oidc-session-activation-release"
RECOVERY_PURPOSE = b"recover-oidc-session-activation-release"
LIVE_REQUEST_MAGIC, RECOVERY_REQUEST_MAGIC = b"SWORLQ01", b"SWORRQ01"
RESPONSE_MAGIC = b"SWORRS01"
REQUEST_IDENTITY_DOMAIN = "serverware.oidcSessionActivationReleaseTransportRequestIdentity/v1"
_COMMON_LIMITS = (bootstrap.proof.MAX_BYTES, bootstrap.proof.enrollments.MAX_BYTES,
    intent.MAX_BYTES, intent_enrollment.MAX_BYTES, 64, bootstrap.delivery.ENVELOPE_BYTES)
LIVE_REQUEST_LIMITS = (len(LIVE_PURPOSE), *_COMMON_LIMITS)
RECOVERY_REQUEST_LIMITS = (len(RECOVERY_PURPOSE), *_COMMON_LIMITS, outcome.MAX_BYTES)
RESPONSE_LIMITS = (71, 64)
LIVE_REQUEST_HEADER_BYTES = 8 + 8 * len(LIVE_REQUEST_LIMITS)
RECOVERY_REQUEST_HEADER_BYTES = 8 + 8 * len(RECOVERY_REQUEST_LIMITS)
RESPONSE_HEADER_BYTES = 8 + 8 * len(RESPONSE_LIMITS)
MAX_REQUEST_BYTES = sum(RECOVERY_REQUEST_LIMITS)
MAX_RESPONSE_BYTES = sum(RESPONSE_LIMITS)
MAX_EXCHANGE_BYTES = bootstrap.authority.MAX_RESULT_BYTES
_CHUNK_BYTES = 64 * 1024


def _fail(message):
    raise AuthorityTransportError(message)


def _profile(profile):
    if type(profile) is not str:
        _fail("release transport requires the independently held root profile")
    if profile == LIVE_PROFILE:
        return LIVE_PURPOSE, LIVE_REQUEST_MAGIC, LIVE_REQUEST_LIMITS
    if profile == RECOVERY_PROFILE:
        return RECOVERY_PURPOSE, RECOVERY_REQUEST_MAGIC, RECOVERY_REQUEST_LIMITS
    _fail("release transport profile is not a fixed live or recovery purpose")


def _exchange_bound(profile):
    _purpose, _magic, limits = _profile(profile)
    if (MAX_EXCHANGE_BYTES != 64 * 1024 * 1024
            or 8 + 8 * len(limits) + sum(limits)
                + RESPONSE_HEADER_BYTES + MAX_RESPONSE_BYTES > MAX_EXCHANGE_BYTES):
        _fail("release transport exceeds its fixed whole-exchange bound")


def _request_lengths(lengths, profile):
    _exchange_bound(profile)
    _purpose, _magic, limits = _profile(profile)
    if (type(lengths) is not tuple or len(lengths) != len(limits)
            or any(type(size) is not int for size in lengths)
            or lengths[0] != limits[0] or lengths[5:7] != limits[5:7]
            or any(not 2 <= lengths[index] <= limits[index] for index in (1, 2, 3, 4))
            or (profile == RECOVERY_PROFILE and not 2 <= lengths[7] <= limits[7])):
        _fail("release request lengths differ from the root-selected grammar")
    if (8 + 8 * len(limits) + sum(lengths)
            + RESPONSE_HEADER_BYTES + MAX_RESPONSE_BYTES > MAX_EXCHANGE_BYTES):
        _fail("release request and reserved response exceed the exchange bound")


def _response_lengths(lengths):
    if (type(lengths) is not tuple or len(lengths) != 2
            or any(type(size) is not int for size in lengths) or lengths != RESPONSE_LIMITS):
        _fail("release response is not exact identity71 and token64")


def _originals(values, *, response=False, profile=None):
    """Hold immutable original frames only; no parsing or admission occurs."""
    if type(response) is not bool:
        _fail("release frame direction is invalid")
    if response:
        if profile is not None:
            _fail("release response has no caller-selected profile")
        count = 2
    else:
        _exchange_bound(profile)
        count = len(_profile(profile)[2])
    if (type(values) is not tuple or len(values) != count
            or any(type(raw) is not bytes for raw in values)):
        _fail("release transport requires its exact immutable original inventory")
    lengths = tuple(len(raw) for raw in values)
    if response:
        _response_lengths(lengths)
        if not framing._digest_bytes(values[0]):
            _fail("release response request identity is not canonical")
    else:
        _request_lengths(lengths, profile)
        if values[0] != _profile(profile)[0]:
            _fail("release request purpose differs from the root-selected profile")
    return values


def _guard(work, current, deadline_ns):
    """The fixed caller supplies actual authority checks, not a success value."""
    if not callable(current) or type(deadline_ns) is not int or deadline_ns <= 0:
        _fail("release transport requires the original deadline and actual current guard")
    capture._SharedLedger(work)
    limits, before = work.limits, work.metrics
    ceiling = (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
    current()  # Its result is deliberately ignored; it is not incoming authority.
    capture._SharedLedger(work)
    after = work.metrics
    if (work.limits is not limits
            or ceiling != (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
            or after.hash_work < before.hash_work or after.input_bytes < before.input_bytes
            or after.json_nodes < before.json_nodes):
        _fail("release current guard replaced or reset the original work ledger")
    return io._check_deadline(deadline_ns)


def _native(operation, *, work, current, deadline_ns):
    # Charge before the callback whose contract requires unchanged metrics.
    work.charge(input_bytes=1)
    _guard(work, current, deadline_ns)
    try:
        return production._callback(work, operation)
    finally:
        _guard(work, current, deadline_ns)


def _connection(connection, *, work, current, deadline_ns):
    if type(connection) is not socket.socket:
        _fail("release transport requires an actual owned socket")
    actual = _native(lambda: (connection.family, connection.type,
        connection.gettimeout(), connection.fileno()), work=work, current=current,
        deadline_ns=deadline_ns)
    if (actual[0] != socket.AF_UNIX or actual[1] != socket.SOCK_STREAM
            or actual[2] != 0.0 or type(actual[3]) is not int or actual[3] < 0):
        _fail("release transport requires an owned nonblocking Unix stream")


def _ready(connection, *, writing, work, current, deadline_ns):
    remaining = _guard(work, current, deadline_ns)
    readers, writers = ([], [connection]) if writing else ([connection], [])
    readable, writable, exceptional = _native(
        lambda: select.select(readers, writers, [connection], remaining / 1_000_000_000),
        work=work, current=current, deadline_ns=deadline_ns)
    if exceptional or not (writable if writing else readable):
        _fail("release transport readiness expired or failed")
    # _native's post-readiness guard runs before the subsequent native I/O guard.


def _recv_precharged(connection, count, *, work, current, deadline_ns):
    # The fixed caller charged the complete storage/copy cost before allocation.
    _guard(work, current, deadline_ns)
    buffer = bytearray(count)
    view = memoryview(buffer)
    offset = 0
    while offset < count:
        _ready(connection, writing=False, work=work, current=current, deadline_ns=deadline_ns)
        size = min(count - offset, _CHUNK_BYTES)
        received = _native(lambda: connection.recv_into(view[offset:offset + size], size),
            work=work, current=current, deadline_ns=deadline_ns)
        if type(received) is not int or not 1 <= received <= size:
            _fail("release transport closed early or returned an invalid read")
        offset += received
    result = bytes(buffer)
    _guard(work, current, deadline_ns)
    return result


def _recv_exact(connection, count, *, work, current, deadline_ns):
    work.charge(input_bytes=2 * count)
    return _recv_precharged(connection, count, work=work, current=current, deadline_ns=deadline_ns)


def _eof(connection, *, work, current, deadline_ns):
    work.charge(input_bytes=1)
    _ready(connection, writing=False, work=work, current=current, deadline_ns=deadline_ns)
    tail = _native(lambda: connection.recv(1), work=work, current=current, deadline_ns=deadline_ns)
    if type(tail) is not bytes or tail != b"":
        _fail("release transport has trailing bytes")


def _receive(connection, *, response, profile, work, current, deadline_ns):
    if response:
        magic, count = RESPONSE_MAGIC, 2
    else:
        _exchange_bound(profile)
        _purpose, magic, limits = _profile(profile)
        count = len(limits)
    prefix = _recv_exact(connection, 8, work=work, current=current, deadline_ns=deadline_ns)
    if prefix != magic:
        _fail("release transport magic differs from the fixed grammar")
    header = _recv_exact(connection, count * 8, work=work, current=current, deadline_ns=deadline_ns)
    work.charge(input_bytes=len(header))
    lengths = tuple(int.from_bytes(header[index:index + 8], "big")
        for index in range(0, len(header), 8))
    if response:
        _response_lengths(lengths)
    else:
        _request_lengths(lengths, profile)
    # Validate the complete inventory, then precharge every body before any body.
    work.charge(input_bytes=2 * sum(lengths))
    values = tuple(_recv_precharged(connection, size, work=work, current=current,
        deadline_ns=deadline_ns) for size in lengths)
    _eof(connection, work=work, current=current, deadline_ns=deadline_ns)
    held = _originals(values, response=response, profile=profile)
    _guard(work, current, deadline_ns)
    return held


def _peer(connection, expected, *, work, current, deadline_ns):
    work.charge(input_bytes=12)
    uid, gid, _pid = _native(lambda: authority_transport._peer_identity(connection),
        work=work, current=current, deadline_ns=deadline_ns)
    if (uid, gid) != expected:
        _fail("release transport peer differs from its fixed purpose")


def _recv_request(connection, *, expected_profile, deadline_ns, work, current):
    """Receive raw7/raw8 only after fixed peer admission; never own the socket."""
    _exchange_bound(expected_profile)
    _guard(work, current, deadline_ns)
    _connection(connection, work=work, current=current, deadline_ns=deadline_ns)
    _peer(connection, (REQUEST_PEER_UID, REQUEST_PEER_GID), work=work,
        current=current, deadline_ns=deadline_ns)
    return _receive(connection, response=False, profile=expected_profile,
        work=work, current=current, deadline_ns=deadline_ns)


def _send_precharged(connection, raw, *, work, current, deadline_ns):
    view, offset = memoryview(raw), 0
    while offset < len(raw):
        _ready(connection, writing=True, work=work, current=current, deadline_ns=deadline_ns)
        size = min(len(raw) - offset, _CHUNK_BYTES)
        sent = _native(lambda: connection.send(view[offset:offset + size]),
            work=work, current=current, deadline_ns=deadline_ns)
        if type(sent) is not int or not 1 <= sent <= size:
            _fail("release transport closed early or returned an invalid write")
        offset += sent


def _send(connection, originals, *, response, profile, work, current, deadline_ns):
    held = _originals(originals, response=response, profile=profile)
    magic = RESPONSE_MAGIC if response else _profile(profile)[1]
    header_size = len(magic) + 8 * len(held)
    work.charge(input_bytes=2 * header_size + sum(len(raw) for raw in held))
    _guard(work, current, deadline_ns)
    header = magic + b"".join(len(raw).to_bytes(8, "big") for raw in held)
    for raw in (header, *held):
        _send_precharged(connection, raw, work=work, current=current, deadline_ns=deadline_ns)
    _guard(work, current, deadline_ns)


def _send_response(connection, originals, *, deadline_ns, work, current):
    """Frame only actual success bytes; startup retains all socket ownership."""
    held = _originals(originals, response=True)
    _guard(work, current, deadline_ns)
    _connection(connection, work=work, current=current, deadline_ns=deadline_ns)
    _peer(connection, (REQUEST_PEER_UID, REQUEST_PEER_GID), work=work,
        current=current, deadline_ns=deadline_ns)
    _send(connection, held, response=True, profile=None, work=work,
        current=current, deadline_ns=deadline_ns)


def _request_identity_on_work(originals, *, profile, deadline_ns, work, current):
    held = _originals(originals, response=False, profile=profile)
    _guard(work, current, deadline_ns)
    identity = plan._frame(REQUEST_IDENTITY_DOMAIN, held, work)
    work.charge(input_bytes=71)
    result = identity.encode("ascii")
    if not framing._digest_bytes(result):
        _fail("release request identity is not canonical")
    _guard(work, current, deadline_ns)
    return result


def _endpoint(endpoint):
    if type(endpoint) is not tuple or len(endpoint) != 4:
        _fail("release endpoint requires its exact fixed four-tuple")
    path, timeout, uid, gid = endpoint
    if (type(path) is not str or path != LISTENER_PATH
            or type(uid) is not int or uid != EXPECTED_PEER_UID
            or type(gid) is not int or gid != EXPECTED_PEER_GID):
        _fail("release endpoint differs from its root-created listener")
    return path, framing._timeout(timeout), uid, gid


def _close_client(connection, *, work, current, deadline_ns):
    # A failed guard must not prevent cleanup. Never retry a possibly closed FD.
    failure = None
    try:
        work.charge(input_bytes=1)
        _guard(work, current, deadline_ns)
    except BaseException as exc:
        failure = exc
    try:
        production._callback(work, connection.close)
    except BaseException as exc:
        if failure is None:
            failure = exc
    try:
        _guard(work, current, deadline_ns)
    except BaseException as exc:
        if failure is None:
            failure = exc
    if failure is not None:
        raise failure


def _socket_request(endpoint, *, profile, originals, deadline_ns, work, current):
    """One private exchange; return unverified raw2 only after normal close."""
    path, timeout, uid, gid = _endpoint(endpoint)
    held = _originals(originals, response=False, profile=profile)
    _guard(work, current, deadline_ns)
    # This local transport cap can only shorten the supplied absolute deadline.
    bound = min(deadline_ns, _native(lambda: framing._deadline_ns(timeout),
        work=work, current=current, deadline_ns=deadline_ns))
    identity = _request_identity_on_work(held, profile=profile, deadline_ns=bound,
        work=work, current=current)
    work.charge(input_bytes=1)
    _guard(work, current, bound)
    connection = production._callback(work, lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
    closing = False
    try:
        _guard(work, current, bound)
        _native(lambda: connection.setblocking(False), work=work, current=current, deadline_ns=bound)
        _connection(connection, work=work, current=current, deadline_ns=bound)
        connected = _native(lambda: connection.connect_ex(path),
            work=work, current=current, deadline_ns=bound)
        if type(connected) is not int or connected not in (0, errno.EINPROGRESS, errno.EALREADY):
            _fail("release private connection was not established")
        if connected != 0:
            _ready(connection, writing=True, work=work, current=current, deadline_ns=bound)
            error = _native(lambda: connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR),
                work=work, current=current, deadline_ns=bound)
            if type(error) is not int or error != 0:
                _fail("release private connection failed")
        _peer(connection, (uid, gid), work=work, current=current, deadline_ns=bound)
        _send(connection, held, response=False, profile=profile,
            work=work, current=current, deadline_ns=bound)
        _native(lambda: connection.shutdown(socket.SHUT_WR), work=work, current=current, deadline_ns=bound)
        received = _receive(connection, response=True, profile=None,
            work=work, current=current, deadline_ns=bound)
        work.charge(input_bytes=2 * len(identity))
        if received[0] != identity:
            _fail("release response request echo differs")
        closing = True
        _close_client(connection, work=work, current=current, deadline_ns=bound)
        return received
    except BaseException:
        if not closing:
            try:
                _close_client(connection, work=work, current=current, deadline_ns=bound)
            except BaseException:
                pass
        raise
