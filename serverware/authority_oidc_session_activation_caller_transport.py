"""Guarded caller I/O for nine source-fixed activation/consume wire profiles.

These private adapters preserve the actual caller's work and current guard;
they do not admit requests, replies, socket peers or callback results as proof.
No operation/profile, timeout allowance, clock window or retry is supplied by
request data. Existing role transports remain the sole framing definitions.
"""
from __future__ import annotations

import socket

from serverware import authority_transport
from serverware import authority_revocation_capability_production as production
from serverware import authority_revocation_writer_transport as io
from serverware import authority_oidc_session_activation_execution_authorizer_transport as authorizer
from serverware import authority_oidc_session_activation_reservation_transport as reservation
from serverware import authority_oidc_session_activation_sql_transport as sql
from serverware import authority_oidc_session_activation_completion_transport as completion
from serverware import authority_oidc_session_activation_completion_dispatch_transport as completion_dispatch
from serverware import authority_oidc_session_activation_delivery_execution_authorizer_transport as consume_authorizer
from serverware import authority_oidc_session_activation_delivery_reservation_transport as consume_reservation
from serverware import authority_oidc_session_activation_delivery_sql_transport as consume_sql
from serverware import authority_oidc_session_activation_delivery_completion_dispatch_transport as consume_completion_dispatch


AuthorityTransportError = authority_transport.AuthorityTransportError
capture = production.capability.capture


def _exchange_on_work(profile, endpoint, *, originals, deadline_ns, work, current):
    # The nine literal entry functions below choose this closed source set.
    # No path, framing callback or caller-selected profile is accepted instead.
    if not (profile is authorizer or profile is reservation or profile is sql
            or profile is completion or profile is completion_dispatch
            or profile is consume_authorizer or profile is consume_reservation or profile is consume_sql
            or profile is consume_completion_dispatch):
        raise AuthorityTransportError("activation caller transport profile is not source fixed")
    # Completion's MAX_BYTES intentionally means only its fixed raw2 request;
    # its separate source exchange ceiling covers the bounded raw4 response.
    exchange_maximum = (profile.MAX_EXCHANGE_BYTES
        if profile is completion or profile is completion_dispatch or profile is consume_completion_dispatch
        else profile.MAX_BYTES)
    capture._SharedLedger(work)
    if type(deadline_ns) is not int or deadline_ns <= 0 or not callable(current):
        raise AuthorityTransportError("activation caller transport requires its original deadline and guard")
    path, timeout, uid, gid = profile._endpoint(endpoint)
    held = profile._originals(originals, response=False)
    limits = work.limits
    observed_epoch = None
    bound = deadline_ns
    connection = None

    def check():
        nonlocal observed_epoch
        capture._SharedLedger(work)
        if work.limits is not limits:
            raise AuthorityTransportError("activation caller transport work limits changed")
        io._check_deadline(bound)
        before = work.metrics
        try:
            epoch = current()
        finally:
            capture._SharedLedger(work)
            after = work.metrics
            if (work.limits is not limits
                    or after.hash_work < before.hash_work
                    or after.input_bytes < before.input_bytes
                    or after.json_nodes < before.json_nodes):
                raise AuthorityTransportError("activation caller guard changed its inherited work")
            io._check_deadline(bound)
        if (type(epoch) is not int or epoch <= 0
                or observed_epoch is not None and epoch < observed_epoch):
            raise AuthorityTransportError("activation caller guard epoch moved backward")
        observed_epoch = epoch

    def call(operation):
        # The actual guard may charge work. It must remain outside the native
        # callback, whose suffix requires unchanged ledger metrics.
        check()
        try:
            return production._callback(work,
                lambda: io._call_until(connection, bound, operation))
        finally:
            check()

    def send_precharged(raw):
        for offset in range(0, len(raw), io._CHUNK_BYTES):
            check()
            chunk = raw[offset:offset + io._CHUNK_BYTES]
            call(lambda: connection.sendall(chunk))
        check()

    def receive_precharged(size):
        if type(size) is not int or not 0 <= size <= exchange_maximum:
            raise AuthorityTransportError("activation caller response allocation differs")
        check()
        if size == 0:
            return b""
        buffer = bytearray(size)
        offset = 0
        while offset < size:
            count = min(size - offset, io._CHUNK_BYTES)
            chunk = call(lambda: connection.recv(count))
            if type(chunk) is not bytes or not 1 <= len(chunk) <= count:
                raise AuthorityTransportError("activation caller response closed early or over-read")
            buffer[offset:offset + len(chunk)] = chunk
            offset += len(chunk)
        result = bytes(buffer)
        check()
        return result

    check()
    # This local socket ceiling can only tighten the inherited absolute bound.
    bound = min(deadline_ns, profile._deadline_ns(timeout))
    check()
    request_bytes = sum(len(raw) for raw in held)
    # Reserve header construction/copies, every request chunk, both response
    # header buffers/copies and native socket/peer bookkeeping before contact.
    work.charge(input_bytes=4096 + request_bytes
        + 4 * profile.REQUEST_HEADER_BYTES + 3 * profile.RESPONSE_HEADER_BYTES)
    header = profile.REQUEST_MAGIC + b"".join(len(raw).to_bytes(8, "big") for raw in held)

    def allocate():
        nonlocal connection
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    try:
        check()
        try:
            # Assign ownership inside the callback: a failing suffix must not
            # lose a socket which the native allocation already returned.
            production._callback(work, allocate)
        finally:
            check()
        call(lambda: connection.connect(path))
        actual_uid, actual_gid, _pid = call(lambda: authority_transport._peer_identity(connection))
        if (actual_uid, actual_gid) != (uid, gid):
            raise AuthorityTransportError("activation caller server peer differs")
        send_precharged(header)
        for raw in held:
            send_precharged(raw)
        call(lambda: connection.shutdown(socket.SHUT_WR))
        prefix = receive_precharged(len(profile.RESPONSE_MAGIC))
        if prefix != profile.RESPONSE_MAGIC:
            raise AuthorityTransportError("activation caller response magic differs")
        length_header = receive_precharged(8 * len(profile.RESPONSE_LIMITS))
        lengths = tuple(int.from_bytes(length_header[offset:offset + 8], "big")
            for offset in range(0, len(length_header), 8))
        if (profile is sql or profile is completion or profile is completion_dispatch
                or profile is consume_sql or profile is consume_completion_dispatch):
            profile._response_lengths(lengths)
        else:
            profile._lengths(lengths, response=True)
        response_bytes = sum(lengths)
        if (response_bytes > profile.MAX_RESPONSE_BYTES
                or request_bytes + response_bytes + profile.REQUEST_HEADER_BYTES
                    + profile.RESPONSE_HEADER_BYTES > exchange_maximum):
            raise AuthorityTransportError("activation caller whole exchange exceeds its fixed bound")
        # All response lengths and aggregate limits are admitted before any
        # body allocation. Reserve bytearray, received chunks and owned bytes
        # for all frames together, plus the terminal exact-EOF byte.
        work.charge(input_bytes=3 * response_bytes + 1)
        received = tuple(receive_precharged(size) for size in lengths)
        if call(lambda: connection.recv(1)) != b"":
            raise AuthorityTransportError("activation caller response has trailing bytes")
        result = profile._originals(received, response=True)
        check()
    finally:
        if connection is not None:
            # Always attempt this owned close once, even if the prefix guard
            # failed. Close or suffix uncertainty suppresses every response;
            # neither close nor a request is retried on another descriptor.
            try:
                check()
            finally:
                try:
                    production._callback(work, connection.close)
                finally:
                    check()
    check()
    return result


def _authorizer_on_work(endpoint, *, originals, deadline_ns, work, current):
    return _exchange_on_work(authorizer, endpoint, originals=originals,
        deadline_ns=deadline_ns, work=work, current=current)[0]


def _reservation_on_work(endpoint, *, originals, deadline_ns, work, current):
    return _exchange_on_work(reservation, endpoint, originals=originals,
        deadline_ns=deadline_ns, work=work, current=current)


def _sql_on_work(endpoint, *, originals, deadline_ns, work, current):
    return _exchange_on_work(sql, endpoint, originals=originals,
        deadline_ns=deadline_ns, work=work, current=current)


def _completion_on_work(endpoint, *, originals, deadline_ns, work, current):
    return _exchange_on_work(completion, endpoint, originals=originals,
        deadline_ns=deadline_ns, work=work, current=current)


def _completion_dispatch_on_work(endpoint, *, originals, deadline_ns, work, current):
    return _exchange_on_work(completion_dispatch, endpoint, originals=originals,
        deadline_ns=deadline_ns, work=work, current=current)


def _consume_authorizer_on_work(endpoint, *, originals, deadline_ns, work, current):
    return _exchange_on_work(consume_authorizer, endpoint, originals=originals,
        deadline_ns=deadline_ns, work=work, current=current)[0]


def _consume_reservation_on_work(endpoint, *, originals, deadline_ns, work, current):
    return _exchange_on_work(consume_reservation, endpoint, originals=originals,
        deadline_ns=deadline_ns, work=work, current=current)


def _consume_sql_on_work(endpoint, *, originals, deadline_ns, work, current):
    return _exchange_on_work(consume_sql, endpoint, originals=originals,
        deadline_ns=deadline_ns, work=work, current=current)


def _consume_completion_dispatch_on_work(endpoint, *, originals, deadline_ns, work, current):
    return _exchange_on_work(consume_completion_dispatch, endpoint, originals=originals,
        deadline_ns=deadline_ns, work=work, current=current)
