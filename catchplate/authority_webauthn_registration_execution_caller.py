"""Fixed private transport for original registration execution preparation.

Peer-checked control-plane -> runtime relay -> actual verifier carries signer
request8/response2, an independently held configuration digest and a deadline.
The response preserves planning request3/response4 and the genuinely acquired
complete before vector. Framing authenticates none of those bytes. The relay
is opaque; the verifier invokes the real preparation on one cumulative work.

No operation, root, historical expectation, DSN, key, callback or successful
result carrier is selected by the wire. This does not contact the grant service,
reserve roots, write custody or execute a business operation. Existing raw6
custody prefixes and behavior are separate and unchanged. Complete lengths
precede body allocation; both directions require exact EOF, one original
deadline and no retry. Hard blocking-I/O termination remains external.
"""
from __future__ import annotations

import socket

from catchplate import authority_custody_caller_transport as framing
from catchplate import authority_current_root_vector as vector
from catchplate import authority_revocation_writer_transport as io
from catchplate import authority_webauthn_evidence_plan_request as plan_request
from catchplate import authority_webauthn_evidence_plan_response as plan_response
from catchplate import authority_webauthn_evidence_plan_transport as plan_transport
from catchplate import authority_webauthn_registration_custody_caller as original_signer


REQUEST_MAGIC = b"SWREPQ01"
RESPONSE_MAGIC = b"SWREPR01"
MAX_REQUEST_BYTES = original_signer.MAX_REQUEST_BYTES
MAX_RESPONSE_BYTES = original_signer.MAX_RESPONSE_BYTES
_RESPONSE_LIMITS = (plan_request.MAX_CONTROL_BYTES, plan_request.MAX_CONTEXT_BYTES,
    plan_request.MAX_INPUT_BYTES, plan_response.MAX_CONTROL_BYTES,
    plan_response.plan.contract.MAX_BYTES, plan_response.plan.inputs_wire.MAX_BYTES,
    plan_response.retention.context_wire.MAX_BYTES, vector.MAX_BYTES)
AuthorityTransportError = framing.AuthorityTransportError
_check_deadline, _recv_prefix = io._check_deadline, io._recv_prefix
_epoch_deadline = original_signer._epoch_deadline
_receipt_interval = original_signer._receipt_interval
_request_lengths = original_signer._request_lengths
_request_originals = original_signer._request_originals


def _response_lengths(lengths):
    if (type(lengths) is not tuple or len(lengths) != 8
            or any(type(size) is not int or not 2 <= size <= maximum
                for size, maximum in zip(lengths, _RESPONSE_LIMITS))
            or sum(lengths) > MAX_RESPONSE_BYTES):
        raise AuthorityTransportError("registration execution preparation response lengths are invalid")
    plan_transport._lengths(lengths[:3], _RESPONSE_LIMITS[:3])
    plan_transport._lengths(lengths[3:7], _RESPONSE_LIMITS[3:7])


def _response_originals(originals):
    if (type(originals) is not tuple or len(originals) != 8
            or any(type(raw) is not bytes for raw in originals)):
        raise AuthorityTransportError("registration execution preparation requires original raw eight")
    _response_lengths(tuple(len(raw) for raw in originals))
    plan_transport._validate_request(control_bytes=originals[0],
        context_bytes=originals[1], inputs_bytes=originals[2])
    plan_transport._validate_response(*originals[3:7])
    return originals


def _recv_request(connection, *, deadline_ns, prefix):
    if type(prefix) is not bytes or prefix != REQUEST_MAGIC:
        raise AuthorityTransportError("registration execution preparation request prefix is invalid")
    encoded = io._recv_exact_until(connection, 71, deadline_ns=deadline_ns)
    try:
        digest = framing._configuration_digest(encoded.decode("ascii"))
    except UnicodeError as exc:
        raise AuthorityTransportError("registration execution preparation configuration is not ASCII") from exc
    deadline = _epoch_deadline(int.from_bytes(
        io._recv_exact_until(connection, 8, deadline_ns=deadline_ns), "big"))
    header = io._recv_exact_until(connection, 80, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[index:index + 8], "big") for index in range(0, 80, 8))
    _request_lengths(lengths)
    originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    io._require_eof(connection, deadline_ns)
    return digest, deadline, _request_originals(originals)


def _send_response(connection, originals, *, deadline_ns):
    held = _response_originals(originals)
    header = RESPONSE_MAGIC + b"".join(len(raw).to_bytes(8, "big") for raw in held)
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    for raw in held:
        io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _socket_request(path, *, configuration_digest, deadline_epoch_ns, originals,
        deadline_ns, expected_peer_uid, expected_peer_gid):
    """Return original raw8 from one fixed peer; admission follows elsewhere."""
    held = _request_originals(originals)
    digest = framing._configuration_digest(configuration_digest)
    deadline = _epoch_deadline(deadline_epoch_ns)
    if (type(path) is not str or not 1 <= len(path) <= 107
            or not path.startswith("/") or "\x00" in path
            or not 1 <= len(path.encode("utf-8")) <= 107
            or any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
                for value in (expected_peer_uid, expected_peer_gid))):
        raise AuthorityTransportError("registration execution preparation endpoint is invalid")
    header = (REQUEST_MAGIC + digest.encode("ascii") + deadline.to_bytes(8, "big")
        + b"".join(len(raw).to_bytes(8, "big") for raw in held))
    _check_deadline(deadline_ns)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        io._call_until(connection, deadline_ns, lambda: connection.connect(path))
        uid, gid, _pid = io._call_until(connection, deadline_ns,
            lambda: framing.authority_transport._peer_identity(connection))
        if (uid, gid) != (expected_peer_uid, expected_peer_gid):
            raise AuthorityTransportError("registration execution preparation server peer differs")
        io._send_exact_until(connection, header, deadline_ns=deadline_ns)
        for raw in held:
            io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
        io._call_until(connection, deadline_ns, lambda: connection.shutdown(socket.SHUT_WR))
        if _recv_prefix(connection, deadline_ns=deadline_ns) != RESPONSE_MAGIC:
            raise AuthorityTransportError("registration execution preparation response prefix is invalid")
        header = io._recv_exact_until(connection, 64, deadline_ns=deadline_ns)
        lengths = tuple(int.from_bytes(header[index:index + 8], "big") for index in range(0, 64, 8))
        _response_lengths(lengths)
        response = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
            for size in lengths)
        io._require_eof(connection, deadline_ns)
    except BaseException:
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    _check_deadline(deadline_ns)
    return _response_originals(response)


def _serve_relay(trust, connection, *, deadline_ns, prefix):
    from catchplate import authority_service as service
    from catchplate import authority_custody_caller_service as caller
    from catchplate import authority_launch_guard as launch
    import os

    if type(trust) is not service.AuthorityRuntimeClient:
        raise AuthorityTransportError("registration execution relay requires actual runtime trust")
    path, uid, gid = trust.verifier_socket_path, trust.verifier_uid, trust.verifier_gid
    relay_uid, relay_gid = trust.server_uid, trust.server_gid
    digest = framing._configuration_digest(trust.configuration_digest)
    receipt = trust.attestation_evidence
    interval = _receipt_interval(receipt)
    if (any(type(value) is not int for value in (uid, gid, relay_uid, relay_gid))
            or os.environ.get("CATCHPLATE_PROCESS_MODE", "").strip() != service.RUNTIME_RELAY_PROCESS_MODE
            or (os.geteuid(), os.getegid()) != (relay_uid, relay_gid)):
        raise AuthorityTransportError("registration execution relay process is not admitted")
    deadline_ns = caller._relay_deadline(interval, deadline_ns)
    launch.require_active("runtime")
    generation = launch.generation()
    generation_identity = tuple(generation[name] for name in ("sequence", "digest", "configurationBindingDigest"))

    def current():
        if ((trust.verifier_socket_path, trust.verifier_uid, trust.verifier_gid,
                trust.server_uid, trust.server_gid, trust.configuration_digest)
                != (path, uid, gid, relay_uid, relay_gid, digest)
                or trust.attestation_evidence is not receipt or _receipt_interval(receipt) != interval):
            raise AuthorityTransportError("registration execution relay configuration changed")
        launch.require_active("runtime")
        actual = launch.generation()
        if tuple(actual[name] for name in ("sequence", "digest", "configurationBindingDigest")) != generation_identity:
            raise AuthorityTransportError("registration execution relay generation changed")
        clipped = caller._relay_deadline(interval, deadline_ns)
        if ((trust.verifier_socket_path, trust.verifier_uid, trust.verifier_gid,
                trust.server_uid, trust.server_gid, trust.configuration_digest)
                != (path, uid, gid, relay_uid, relay_gid, digest)
                or trust.attestation_evidence is not receipt or _receipt_interval(receipt) != interval):
            raise AuthorityTransportError("registration execution relay changed during callbacks")
        return clipped

    received, deadline, originals = _recv_request(connection, deadline_ns=deadline_ns, prefix=prefix)
    if received != digest:
        raise AuthorityTransportError("registration execution preparation differs from runtime configuration")
    deadline_ns = current()
    response = _socket_request(path, configuration_digest=digest, deadline_epoch_ns=deadline,
        originals=originals, deadline_ns=deadline_ns, expected_peer_uid=uid, expected_peer_gid=gid)
    deadline_ns = current()
    _send_response(connection, response, deadline_ns=deadline_ns)
    current()


def _serve_verifier(process, connection, *, deadline_ns, prefix):
    from catchplate import authority_service as service
    from catchplate import authority_custody_caller_service as caller
    from catchplate import authority_launch_guard as launch
    from catchplate import authority_revocation_configuration as measured
    from catchplate import authority_webauthn_registration_execution_preparation as preparation
    from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    if (type(process) is not service.AuthorityProcess or process.role_name != "verifier"
            or process.process_mode != service.PROCESS_MODES["verifier"]
            or type(process.configuration) is not service.MeasuredConfiguration):
        raise AuthorityTransportError("registration execution preparation requires the actual verifier")
    observed = process.configuration
    digest = framing._configuration_digest(observed.digest)
    receipt = observed.attestation_evidence
    interval = _receipt_interval(receipt)
    deadline_ns = caller._relay_deadline(interval, deadline_ns)
    received, deadline, originals = _recv_request(connection, deadline_ns=deadline_ns, prefix=prefix)
    if received != digest or process.configuration is not observed:
        raise AuthorityTransportError("registration execution preparation differs from verifier configuration")
    # The outer router's peer check, bounded immutable raw10 and exact EOF all
    # precede the sole allowance. No successful result graph crosses this seam.
    work = _ValidationWork(QueryReadValidationLimits())
    evidence = preparation.evidence
    callback = evidence.production._callback
    callback(work, lambda: launch.require_active("verifier"))
    generation = callback(work, lambda: dict(launch.generation()))
    held_generation = evidence.capture._JSONCapture(evidence.capture._SharedLedger(work)).visit(
        {name: generation[name] for name in measured._GENERATION_FIELDS})

    def current():
        if (process.configuration is not observed or observed.digest != digest
                or process.role_name != "verifier" or process.process_mode != service.PROCESS_MODES["verifier"]
                or observed.attestation_evidence is not receipt or _receipt_interval(receipt) != interval):
            raise AuthorityTransportError("registration execution verifier scope changed")
        callback(work, lambda: launch.require_active("verifier"))
        actual = callback(work, lambda: dict(launch.generation()))
        evidence.plan._same(tuple(held_generation[name] for name in measured._GENERATION_FIELDS),
            tuple(actual[name] for name in measured._GENERATION_FIELDS), work,
            "registration execution verifier generation changed")
        clipped = callback(work, lambda: caller._relay_deadline(interval, deadline_ns))
        if (process.configuration is not observed or observed.digest != digest
                or observed.attestation_evidence is not receipt or _receipt_interval(receipt) != interval):
            raise AuthorityTransportError("registration execution verifier changed during callbacks")
        return clipped

    deadline_ns = current()
    response = preparation._prepare_on_work(process, request_originals=originals[:8],
        response_originals=originals[8:], deadline_epoch_ns=min(deadline, interval[1]),
        work=work, transport_deadline_ns=deadline_ns)
    response = _response_originals(response)
    deadline_ns = current()
    _send_response(connection, response, deadline_ns=deadline_ns)
    current()
