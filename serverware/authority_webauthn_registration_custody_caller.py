"""Fixed registration signer-originals to private custody preparation bridge.

The real routers admit their configured peers before reading the prefix. Raw
ten contain the original signer request eight and response two, never a typed
request or successful-proof carrier. The verifier genuinely replays those
originals before preparing evidence raw six on its sole existing allowance.
The relay remains opaque. No writer, journal, business finalizer, retry or
enrollment signer is invoked here; returned originals must be journaled before
any separately authorized, potentially committing forward attempt.
"""
from __future__ import annotations

import socket

from serverware import authority_custody_caller_transport as framing
from serverware import authority_revocation_writer_transport as io
from serverware import authority_webauthn_evidence_custody_transport as custody
from serverware import authority_webauthn_registration_signer_wire as signer_wire


REQUEST_MAGIC = b"SWRCPQ01"
RESPONSE_MAGIC = b"SWRCPR01"
MAX_REQUEST_BYTES = signer_wire.authority.MAX_RESULT_BYTES
MAX_RESPONSE_BYTES = signer_wire.authority.MAX_RESULT_BYTES
AuthorityTransportError = framing.AuthorityTransportError
_check_deadline = io._check_deadline
_recv_prefix = io._recv_prefix


def _epoch_deadline(value):
    if type(value) is not int or not 1 <= value <= (1 << 63) - 1:
        raise AuthorityTransportError("registration custody deadline is not positive I63")
    return value


def _request_lengths(lengths):
    if type(lengths) is not tuple or len(lengths) != 10:
        raise AuthorityTransportError("registration custody request requires ten lengths")
    signer_wire._request_lengths(lengths[:8])
    signer_wire._response_lengths(lengths[8:])
    if (sum(lengths[:2]) > signer_wire.source_request.MAX_REQUEST_BYTES
            or sum(lengths[2:4]) > signer_wire.source_response.MAX_RESPONSE_BYTES
            or sum(lengths) > MAX_REQUEST_BYTES):
        raise AuthorityTransportError("registration custody original groups exceed their aggregate bounds")


def _request_originals(originals):
    if (type(originals) is not tuple or len(originals) != 10
            or any(type(raw) is not bytes for raw in originals)):
        raise AuthorityTransportError("registration custody request is not original raw ten")
    _request_lengths(tuple(len(raw) for raw in originals))
    signer_wire._request_originals(originals[:8])
    signer_wire._response_originals(originals[8:])
    return originals


def _response_originals(originals):
    if type(originals) is not tuple or len(originals) != 6:
        raise AuthorityTransportError("registration custody response is not original raw six")
    custody._validate_originals(intent_bytes=originals[0], relay_bytes=originals[1],
        envelope_bytes=originals[2], inputs_bytes=originals[3],
        evaluation_context_bytes=originals[4], historical_expectations_bytes=originals[5])
    if sum(len(raw) for raw in originals) > MAX_RESPONSE_BYTES:
        raise AuthorityTransportError("registration custody response exceeds its aggregate bound")
    return originals


def _recv_request(connection, *, deadline_ns, prefix):
    if type(prefix) is not bytes or prefix != REQUEST_MAGIC:
        raise AuthorityTransportError("registration custody request prefix is invalid")
    encoded = io._recv_exact_until(connection, 71, deadline_ns=deadline_ns)
    try:
        digest = framing._configuration_digest(encoded.decode("ascii"))
    except UnicodeError as exc:
        raise AuthorityTransportError("registration custody configuration digest is not ASCII") from exc
    deadline = _epoch_deadline(int.from_bytes(
        io._recv_exact_until(connection, 8, deadline_ns=deadline_ns), "big"))
    header = io._recv_exact_until(connection, 80, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[index:index + 8], "big") for index in range(0, 80, 8))
    # All ten individual lengths, both signer groups and the complete aggregate
    # are admitted before allocating any original body.
    _request_lengths(lengths)
    originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    io._require_eof(connection, deadline_ns)
    return digest, deadline, _request_originals(originals)


def _send_response(connection, originals, *, deadline_ns):
    originals = _response_originals(originals)
    header = RESPONSE_MAGIC + b"".join(len(raw).to_bytes(8, "big") for raw in originals)
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    for raw in originals:
        io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _socket_request(path, *, configuration_digest, deadline_epoch_ns, originals,
        deadline_ns, expected_peer_uid, expected_peer_gid):
    """One peer-checked exchange bounded by the existing absolute deadline."""
    originals = _request_originals(originals)
    digest = framing._configuration_digest(configuration_digest)
    deadline = _epoch_deadline(deadline_epoch_ns)
    if (type(path) is not str or not 1 <= len(path) <= 107
            or not path.startswith("/") or "\x00" in path
            or not 1 <= len(path.encode("utf-8")) <= 107
            or any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
                for value in (expected_peer_uid, expected_peer_gid))):
        raise AuthorityTransportError("registration custody endpoint is invalid")
    header = (REQUEST_MAGIC + digest.encode("ascii") + deadline.to_bytes(8, "big")
        + b"".join(len(raw).to_bytes(8, "big") for raw in originals))
    _check_deadline(deadline_ns)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        io._call_until(connection, deadline_ns, lambda: connection.connect(path))
        uid, gid, _pid = io._call_until(connection, deadline_ns,
            lambda: framing.authority_transport._peer_identity(connection))
        if (uid, gid) != (expected_peer_uid, expected_peer_gid):
            raise AuthorityTransportError("registration custody server peer differs")
        io._send_exact_until(connection, header, deadline_ns=deadline_ns)
        for raw in originals:
            io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
        io._call_until(connection, deadline_ns, lambda: connection.shutdown(socket.SHUT_WR))
        if _recv_prefix(connection, deadline_ns=deadline_ns) != RESPONSE_MAGIC:
            raise AuthorityTransportError("registration custody response prefix is invalid")
        header = io._recv_exact_until(connection, 48, deadline_ns=deadline_ns)
        lengths = tuple(int.from_bytes(header[index:index + 8], "big") for index in range(0, 48, 8))
        custody._validate_lengths(lengths)
        if sum(lengths) > MAX_RESPONSE_BYTES:
            raise AuthorityTransportError("registration custody response exceeds its aggregate bound")
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


def _receipt_interval(receipt):
    if type(receipt) is not dict or type(receipt.get("payload")) is not dict:
        raise AuthorityTransportError("registration custody original receipt is missing")
    payload = receipt["payload"]
    interval = (_epoch_deadline(payload.get("issuedAtEpochNs")),
        _epoch_deadline(payload.get("expiresAtEpochNs")))
    if interval[0] >= interval[1]:
        raise AuthorityTransportError("registration custody original receipt interval is invalid")
    return interval


def _serve_relay(trust, connection, *, deadline_ns, prefix):
    from serverware import authority_service as service
    from serverware import authority_custody_caller_service as caller
    from serverware import authority_launch_guard as launch
    import os

    if type(trust) is not service.AuthorityRuntimeClient:
        raise AuthorityTransportError("registration custody relay requires actual runtime trust")
    path, uid, gid = trust.verifier_socket_path, trust.verifier_uid, trust.verifier_gid
    relay_uid, relay_gid = trust.server_uid, trust.server_gid
    digest = framing._configuration_digest(trust.configuration_digest)
    receipt = trust.attestation_evidence
    interval = _receipt_interval(receipt)
    if (any(type(value) is not int for value in (uid, gid, relay_uid, relay_gid))
            or os.environ.get("SERVERWARE_PROCESS_MODE", "").strip() != service.RUNTIME_RELAY_PROCESS_MODE
            or (os.geteuid(), os.getegid()) != (relay_uid, relay_gid)):
        raise AuthorityTransportError("registration custody relay process is not admitted")
    deadline_ns = caller._relay_deadline(interval, deadline_ns)
    launch.require_active("runtime")
    generation = launch.generation()
    generation_identity = tuple(generation[name] for name in ("sequence", "digest", "configurationBindingDigest"))

    def current():
        if ((trust.verifier_socket_path, trust.verifier_uid, trust.verifier_gid,
                trust.server_uid, trust.server_gid, trust.configuration_digest)
                != (path, uid, gid, relay_uid, relay_gid, digest)
                or trust.attestation_evidence is not receipt or _receipt_interval(receipt) != interval):
            raise AuthorityTransportError("registration custody relay configuration changed")
        launch.require_active("runtime")
        actual = launch.generation()
        if tuple(actual[name] for name in ("sequence", "digest", "configurationBindingDigest")) != generation_identity:
            raise AuthorityTransportError("registration custody relay generation changed")
        clipped = caller._relay_deadline(interval, deadline_ns)
        if ((trust.verifier_socket_path, trust.verifier_uid, trust.verifier_gid,
                trust.server_uid, trust.server_gid, trust.configuration_digest)
                != (path, uid, gid, relay_uid, relay_gid, digest)
                or trust.attestation_evidence is not receipt or _receipt_interval(receipt) != interval):
            raise AuthorityTransportError("registration custody relay changed during callbacks")
        return clipped

    received, deadline, originals = _recv_request(connection, deadline_ns=deadline_ns, prefix=prefix)
    if received != digest:
        raise AuthorityTransportError("registration custody differs from runtime configuration")
    deadline_ns = current()
    response = _socket_request(path, configuration_digest=digest, deadline_epoch_ns=deadline,
        originals=originals, deadline_ns=deadline_ns, expected_peer_uid=uid, expected_peer_gid=gid)
    deadline_ns = current()
    _send_response(connection, response, deadline_ns=deadline_ns)


def _serve_verifier(process, connection, *, deadline_ns, prefix):
    from serverware import authority_service as service
    from serverware import authority_custody_caller_service as caller
    from serverware import authority_launch_guard as launch
    from serverware import authority_revocation_configuration as measured
    from serverware import authority_webauthn_evidence_custody_configuration as configuration
    from serverware import authority_webauthn_evidence_plan_clock as clock
    from serverware import authority_webauthn_registration_signer_response as signer_response
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    if (type(process) is not service.AuthorityProcess or process.role_name != "verifier"
            or process.process_mode != service.PROCESS_MODES["verifier"]
            or type(process.configuration) is not service.MeasuredConfiguration):
        raise AuthorityTransportError("registration custody requires the actual verifier")
    observed = process.configuration
    digest = framing._configuration_digest(observed.digest)
    receipt = observed.attestation_evidence
    interval = _receipt_interval(receipt)
    deadline_ns = caller._relay_deadline(interval, deadline_ns)
    received, deadline, originals = _recv_request(connection, deadline_ns=deadline_ns, prefix=prefix)
    if received != digest or process.configuration is not observed:
        raise AuthorityTransportError("registration custody differs from verifier configuration")
    # The peer, complete immutable raw ten and EOF precede the sole allowance.
    work = _ValidationWork(QueryReadValidationLimits())
    evidence = signer_response.evidence
    ledger = evidence.capture._SharedLedger(work)
    payload, captured_digest, generation, _dsn, _key, runtime = service._webauthn_evidence_custody_context(
        process, role_name="verifier", signing=False, work=work)
    held_generation = evidence.capture._JSONCapture(ledger).visit(
        {name: generation[name] for name in measured._GENERATION_FIELDS})
    held_runtime = evidence.capture._JSONCapture(ledger, maximum_bytes=8192).visit(runtime)
    evidence.plan._same(captured_digest, digest, work, "registration custody configuration changed")
    configured = configuration._capture_on_work(purpose="registration", payload=payload,
        configuration_digest=digest, generation=held_generation,
        runtime_role_identities=held_runtime, work=work)
    window = clock._open_on_work(deadline_epoch_ns=min(deadline, interval[1]),
        maximum_lifetime_ns=configured.maximum_control_age_ns,
        maximum_clock_skew_ns=configured.pins[9], work=work)
    deadline_ns = min(deadline_ns, window[4])

    def current():
        if (process.configuration is not observed or observed.digest != digest
                or process.role_name != "verifier" or process.process_mode != service.PROCESS_MODES["verifier"]
                or observed.attestation_evidence is not receipt or _receipt_interval(receipt) != interval):
            raise AuthorityTransportError("registration custody verifier scope changed")
        evidence.production._callback(work, lambda: launch.require_active("verifier"))
        actual = evidence.production._callback(work, lambda: dict(launch.generation()))
        evidence.plan._same(tuple(held_generation[name] for name in measured._GENERATION_FIELDS),
            tuple(actual[name] for name in measured._GENERATION_FIELDS), work,
            "registration custody verifier generation changed")
        evidence.plan._same(observed.runtime_role_identities, held_runtime, work,
            "registration custody verifier runtime cohort changed")
        now = clock._check_on_work(window, work=work)
        if not interval[0] <= now < interval[1]:
            raise AuthorityTransportError("registration custody verifier original receipt expired")
        if (process.configuration is not observed or observed.digest != digest
                or observed.attestation_evidence is not receipt or _receipt_interval(receipt) != interval):
            raise AuthorityTransportError("registration custody verifier changed during callbacks")
        evidence.production._callback(work, lambda: _check_deadline(deadline_ns))

    current()
    request, inputs_bytes = signer_response._verify_on_configuration(payload=payload,
        configuration_digest=digest, generation=held_generation, runtime_role_identities=held_runtime,
        request_originals=originals[:8], response_originals=originals[8:], work=work)
    current()
    response = service.AuthorityProcess._prepare_webauthn_evidence_custody(process,
        purpose="registration", request=request, inputs_bytes=inputs_bytes,
        deadline_epoch_ns=deadline, work=work, transport_deadline_ns=deadline_ns)
    response = _response_originals(response)
    current()
    _send_response(connection, response, deadline_ns=deadline_ns)
