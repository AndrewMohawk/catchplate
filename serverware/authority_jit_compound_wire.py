"""Metered opaque request/raw-four planning exchange, not plan admission.

The signed control and request stay separate original bytes. Reply bodies are
parent/request/context/manifest, each with its genuine source ceiling. The
literal request echo is only transport correlation; a receiver must still
verify the planner signature, independent roots and complete retained replay.
No parsed result, successful proof DTO, clock or work allowance is accepted.
"""
from __future__ import annotations

from serverware import authority_jit_compound_transport as transport
from serverware.authority_query_read_work import _ValidationWork


evidence = transport.plan.evidence


class JitCompoundWireError(ValueError):
    pass


def _require(value):
    if not value:
        raise JitCompoundWireError("JIT planning wire differs from its immutable originals")


def _work(work):
    _require(type(work) is _ValidationWork)
    evidence.capture._SharedLedger(work)


def _frame(actual, expected):
    _require(type(actual) is transport.FrameMetrics
        and type(actual.body_bytes) is tuple
        and all(type(value) is int for value in actual.body_bytes)
        and type(actual.framing_bytes) is int and type(actual.wire_bytes) is int
        and actual == expected)


def receive_request(connection, *, prefix, deadline_ns, work):
    """One borrowed read after peer admission, charged on the original work."""
    _work(work)
    _require(work.limits.max_input_bytes - work.input_bytes
        >= transport.REQUEST_HEADER_BYTES + sum(transport.REQUEST_LIMITS))
    actual = evidence.production._callback(work, lambda: transport._recv_request(
        connection, prefix=prefix, deadline_ns=deadline_ns))
    _require(type(actual) is transport.RawRequest)
    lengths = transport._bodies((actual.control_bytes, actual.request_bytes), transport.REQUEST_LIMITS)
    expected = transport._metrics(lengths, transport.REQUEST_HEADER_BYTES)
    _frame(actual.metrics, expected)
    work.charge(input_bytes=expected.wire_bytes)
    return actual


def send_reply(connection, *, originals, request_bytes, deadline_ns, check, work, processing_owner=None):
    """Send only raw originals; caller retains both authenticated live guards."""
    _work(work)
    _require(callable(check))
    lengths = transport._bodies(originals, transport.REPLY_LIMITS)
    _require(type(request_bytes) is bytes
        and 2 <= len(request_bytes) <= transport.REQUEST_LIMITS[1])
    work.charge(input_bytes=len(request_bytes) + len(originals[1]))
    _require(originals[1] == request_bytes)
    expected = transport._metrics(lengths, transport.REPLY_HEADER_BYTES)
    work.charge(input_bytes=expected.wire_bytes)
    if processing_owner is not None:
        # Twelve exact source-owner metadata checks: header/four bodies and
        # entry/return. The original meter and generic ceilings stay unchanged.
        work.charge(input_bytes=1024 * 1024, json_nodes=65536)
    _require(evidence.production._callback(work, check) is None)
    actual = evidence.production._callback(work, lambda: transport._send_reply(
        connection, originals=originals, deadline_ns=deadline_ns,
        processing_owner=processing_owner, processing_work=work if processing_owner is not None else None))
    _frame(actual, expected)
    _require(evidence.production._callback(work, check) is None)
    return actual


def exchange(path, *, control_bytes, request_bytes, original_deadline_ns,
        expected_peer_uid, expected_peer_gid, work, transport_deadline_ns=None):
    """Return unadmitted raw four bodies and actual application-wire metrics."""
    _work(work)
    lengths = transport._bodies((control_bytes, request_bytes), transport.REQUEST_LIMITS)
    _require(type(original_deadline_ns) is int and 0 < original_deadline_ns < 2**63
        and (transport_deadline_ns is None or type(transport_deadline_ns) is int
            and 0 < transport_deadline_ns < 2**63))
    deadline = original_deadline_ns if transport_deadline_ns is None else min(
        original_deadline_ns, transport_deadline_ns)
    expected_request = transport._metrics(lengths, transport.REQUEST_HEADER_BYTES)
    work.charge(input_bytes=expected_request.wire_bytes)
    _require(work.limits.max_input_bytes - work.input_bytes
        >= transport.REPLY_HEADER_BYTES + sum(transport.REPLY_LIMITS))
    actual = evidence.production._callback(work, lambda: transport._socket_exchange(path,
        control_bytes=control_bytes, request_bytes=request_bytes, original_deadline_ns=deadline,
        expected_peer_uid=expected_peer_uid, expected_peer_gid=expected_peer_gid))
    _require(type(actual) is transport.RawReply and type(actual.metrics) is transport.ExchangeMetrics)
    response_lengths = transport._bodies(actual.originals, transport.REPLY_LIMITS)
    expected_reply = transport._metrics(response_lengths, transport.REPLY_HEADER_BYTES)
    _frame(actual.metrics.request, expected_request)
    _frame(actual.metrics.reply, expected_reply)
    work.charge(input_bytes=expected_reply.wire_bytes
        + len(actual.originals[1]) + len(request_bytes))
    _require(actual.originals[1] == request_bytes)
    evidence.production._callback(work, lambda: transport._deadline(deadline))
    return actual
