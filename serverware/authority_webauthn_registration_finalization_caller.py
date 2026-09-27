"""Fixed original-byte registration finalization preparation framing.

Raw eleven retain signer request eight, response two and one opaque sibling-list
document. The wire never parses that document, admits siblings or accepts a
successful verification carrier. Raw seven are the actual transition-custody
originals, not a committed registration or a durable writer receipt.

Serving owners must admit their peer before reading the prefix or bodies. The
client checks its configured peer before sending. One supplied absolute local
deadline covers the exchange, with exact EOF and request half-close. Framing
does no JSON or signature work. The verifier serving continuation owns the sole
request allowance, decodes lookup hints and invokes genuine preparation; the
relay remains opaque. Neither adds timeout renewal or an automatic write/retry.
"""
from __future__ import annotations

import socket

from serverware import authority_custody_caller_transport as framing
from serverware import authority_revocation_writer_transport as io
from serverware import authority_webauthn_registration_custody_caller as registration_custody
from serverware import authority_webauthn_transition_custody_transport as custody


REQUEST_MAGIC = b"SWRFPQ01"
RESPONSE_MAGIC = b"SWRFPR01"
MAX_REQUEST_BYTES = registration_custody.MAX_REQUEST_BYTES
MAX_RESPONSE_BYTES = custody.MAX_REQUEST_BYTES
MAX_HINTS_BYTES = 1024 * 1024
AuthorityTransportError = framing.AuthorityTransportError
_check_deadline = io._check_deadline
_recv_prefix = io._recv_prefix
_epoch_deadline = registration_custody._epoch_deadline
_receipt_interval = registration_custody._receipt_interval


def _request_lengths(lengths):
    if (type(lengths) is not tuple or len(lengths) != 11
            or type(lengths[10]) is not int or not 2 <= lengths[10] <= MAX_HINTS_BYTES):
        raise AuthorityTransportError("registration finalization request requires eleven bounded lengths")
    registration_custody._request_lengths(lengths[:10])
    if sum(lengths) > MAX_REQUEST_BYTES:
        raise AuthorityTransportError("registration finalization originals exceed their aggregate bound")


def _request_originals(originals):
    if (type(originals) is not tuple or len(originals) != 11
            or any(type(raw) is not bytes for raw in originals)):
        raise AuthorityTransportError("registration finalization request is not original raw eleven")
    _request_lengths(tuple(len(raw) for raw in originals))
    registration_custody._request_originals(originals[:10])
    return originals


def _response_lengths(lengths):
    custody._validate_lengths(lengths)
    if sum(lengths) > MAX_RESPONSE_BYTES:
        raise AuthorityTransportError("registration finalization response exceeds its aggregate bound")


def _response_originals(originals):
    if (type(originals) is not tuple or len(originals) != 7
            or any(type(raw) is not bytes for raw in originals)):
        raise AuthorityTransportError("registration finalization response is not original raw seven")
    _response_lengths(tuple(len(raw) for raw in originals))
    custody._validate_originals(intent_bytes=originals[0], relay_bytes=originals[1],
        envelope_bytes=originals[2], proof_bytes=originals[3], inputs_bytes=originals[4],
        context_bytes=originals[5], historical_expectations_bytes=originals[6])
    return originals


def _recv_request(connection, *, deadline_ns, prefix):
    return _recv_request_profile(connection, deadline_ns=deadline_ns, prefix=prefix, execution=False)


def _profile(execution):
    if type(execution) is not bool:
        raise AuthorityTransportError("registration finalization profile is not source fixed")
    if execution:
        from serverware import authority_webauthn_registration_finalization_execution_caller as wire
        return wire.REQUEST_MAGIC, wire.RESPONSE_MAGIC, 8, wire._response_lengths, wire._response_originals
    return REQUEST_MAGIC, RESPONSE_MAGIC, 7, _response_lengths, _response_originals


def _recv_request_profile(connection, *, deadline_ns, prefix, execution):
    request_magic, _response_magic, _count, _lengths, _originals = _profile(execution)
    if type(prefix) is not bytes or prefix != request_magic:
        raise AuthorityTransportError("registration finalization request prefix is invalid")
    encoded = io._recv_exact_until(connection, 71, deadline_ns=deadline_ns)
    try:
        digest = framing._configuration_digest(encoded.decode("ascii"))
    except UnicodeError as exc:
        raise AuthorityTransportError("registration finalization configuration digest is not ASCII") from exc
    deadline = _epoch_deadline(int.from_bytes(
        io._recv_exact_until(connection, 8, deadline_ns=deadline_ns), "big"))
    header = io._recv_exact_until(connection, 88, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[index:index + 8], "big") for index in range(0, 88, 8))
    # First-ten family/group limits, the opaque hint cap and the full aggregate
    # are checked before allocating any received original body.
    _request_lengths(lengths)
    originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    io._require_eof(connection, deadline_ns)
    return digest, deadline, _request_originals(originals)


def _send_response(connection, originals, *, deadline_ns):
    return _send_response_profile(connection, originals, deadline_ns=deadline_ns, execution=False)


def _send_response_profile(connection, originals, *, deadline_ns, execution):
    _request_magic, response_magic, _count, _lengths, validate = _profile(execution)
    originals = validate(originals)
    header = response_magic + b"".join(len(raw).to_bytes(8, "big") for raw in originals)
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    for raw in originals:
        io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _socket_request(path, *, configuration_digest, deadline_epoch_ns, originals,
        deadline_ns, expected_peer_uid, expected_peer_gid):
    """One peer-checked exchange under the original absolute local deadline."""
    return _socket_request_profile(path, configuration_digest=configuration_digest,
        deadline_epoch_ns=deadline_epoch_ns, originals=originals, deadline_ns=deadline_ns,
        expected_peer_uid=expected_peer_uid, expected_peer_gid=expected_peer_gid, execution=False)


def _socket_request_profile(path, *, configuration_digest, deadline_epoch_ns, originals,
        deadline_ns, expected_peer_uid, expected_peer_gid, execution):
    request_magic, response_magic, count, validate_lengths, validate_response = _profile(execution)
    originals = _request_originals(originals)
    digest = framing._configuration_digest(configuration_digest)
    deadline = _epoch_deadline(deadline_epoch_ns)
    if (type(path) is not str or not 1 <= len(path) <= 107
            or not path.startswith("/") or "\x00" in path
            or any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
                for value in (expected_peer_uid, expected_peer_gid))):
        raise AuthorityTransportError("registration finalization endpoint is invalid")
    try:
        path_bytes = path.encode("utf-8")
    except UnicodeError as exc:
        raise AuthorityTransportError("registration finalization endpoint is not valid UTF-8") from exc
    if not 1 <= len(path_bytes) <= 107:
        raise AuthorityTransportError("registration finalization endpoint is too long")
    header = (request_magic + digest.encode("ascii") + deadline.to_bytes(8, "big")
        + b"".join(len(raw).to_bytes(8, "big") for raw in originals))
    _check_deadline(deadline_ns)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        io._call_until(connection, deadline_ns, lambda: connection.connect(path))
        uid, gid, _pid = io._call_until(connection, deadline_ns,
            lambda: framing.authority_transport._peer_identity(connection))
        if (uid, gid) != (expected_peer_uid, expected_peer_gid):
            raise AuthorityTransportError("registration finalization server peer differs")
        io._send_exact_until(connection, header, deadline_ns=deadline_ns)
        for raw in originals:
            io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
        io._call_until(connection, deadline_ns, lambda: connection.shutdown(socket.SHUT_WR))
        if _recv_prefix(connection, deadline_ns=deadline_ns) != response_magic:
            raise AuthorityTransportError("registration finalization response prefix is invalid")
        header = io._recv_exact_until(connection, 8 * count, deadline_ns=deadline_ns)
        lengths = tuple(int.from_bytes(header[index:index + 8], "big")
            for index in range(0, len(header), 8))
        validate_lengths(lengths)
        response = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
            for size in lengths)
        io._require_eof(connection, deadline_ns)
    except BaseException:
        # Preserve the first native failure; an uncertain exchange provides no
        # retry, absence, rollback or completion authority.
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    _check_deadline(deadline_ns)
    return validate_response(response)


def _hints_on_work(raw, work):
    """Decode lookup hints only, never complete-population or row authority."""
    import json
    from serverware import authority_webauthn_evidence as evidence

    ledger = evidence.capture._SharedLedger(work)
    if type(raw) is not bytes or not 2 <= len(raw) <= MAX_HINTS_BYTES:
        raise AuthorityTransportError("registration finalization hints exceed their original byte bound")
    # Reuse the actual lexical admission and strict parser hooks. The sole
    # allocation reservation precedes ASCII decode/loads, just as for the
    # existing object codec; this fixed root is a list, not a control object.
    nodes, hooks = evidence.wire._preflight(raw, work, maximum_nodes=33, maximum_depth=1)
    work.charge(input_bytes=3 * len(raw), json_nodes=nodes + hooks)
    try:
        hints = json.loads(raw.decode("ascii"), object_pairs_hook=evidence.wire._unique_object,
            parse_int=evidence.wire._parse_integer, parse_float=evidence.wire._reject_number,
            parse_constant=evidence.wire._reject_number)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AuthorityTransportError("registration finalization hints are not bounded JSON") from exc
    if (type(hints) is not list or len(hints) > 32
            or any(type(value) is not str or not 1 <= len(value) <= 4096 for value in hints)):
        raise AuthorityTransportError("registration finalization hints are not bounded strings")
    previous = None
    for value in hints:
        if previous is not None:
            work.prepare_comparison(previous, value)
            if previous >= value:
                raise AuthorityTransportError("registration finalization hints are not sorted and unique")
        previous = value
    evidence.capability._canonical(raw, hints, ledger, MAX_HINTS_BYTES, 33)
    return hints


def _serve_relay(trust, connection, *, deadline_ns, prefix):
    return _serve_relay_profile(trust, connection, deadline_ns=deadline_ns, prefix=prefix, execution=False)


def _serve_relay_profile(trust, connection, *, deadline_ns, prefix, execution):
    from serverware import authority_service as service
    from serverware import authority_custody_caller_service as caller
    from serverware import authority_launch_guard as launch
    import os

    _profile(execution)
    if type(trust) is not service.AuthorityRuntimeClient:
        raise AuthorityTransportError("registration finalization relay requires actual runtime trust")
    path, uid, gid = trust.verifier_socket_path, trust.verifier_uid, trust.verifier_gid
    relay_uid, relay_gid = trust.server_uid, trust.server_gid
    digest = framing._configuration_digest(trust.configuration_digest)
    receipt = trust.attestation_evidence
    interval = _receipt_interval(receipt)
    if (any(type(value) is not int for value in (uid, gid, relay_uid, relay_gid))
            or os.environ.get("SERVERWARE_PROCESS_MODE", "").strip() != service.RUNTIME_RELAY_PROCESS_MODE
            or (os.geteuid(), os.getegid()) != (relay_uid, relay_gid)):
        raise AuthorityTransportError("registration finalization relay process is not admitted")
    deadline_ns = caller._relay_deadline(interval, deadline_ns)
    launch.require_active("runtime")
    generation = launch.generation()
    generation_identity = tuple(generation[name] for name in ("sequence", "digest", "configurationBindingDigest"))

    def current():
        if ((trust.verifier_socket_path, trust.verifier_uid, trust.verifier_gid,
                trust.server_uid, trust.server_gid, trust.configuration_digest)
                != (path, uid, gid, relay_uid, relay_gid, digest)
                or trust.attestation_evidence is not receipt or _receipt_interval(receipt) != interval):
            raise AuthorityTransportError("registration finalization relay configuration changed")
        launch.require_active("runtime")
        actual = launch.generation()
        if tuple(actual[name] for name in ("sequence", "digest", "configurationBindingDigest")) != generation_identity:
            raise AuthorityTransportError("registration finalization relay generation changed")
        clipped = caller._relay_deadline(interval, deadline_ns)
        if ((trust.verifier_socket_path, trust.verifier_uid, trust.verifier_gid,
                trust.server_uid, trust.server_gid, trust.configuration_digest)
                != (path, uid, gid, relay_uid, relay_gid, digest)
                or trust.attestation_evidence is not receipt or _receipt_interval(receipt) != interval):
            raise AuthorityTransportError("registration finalization relay changed during callbacks")
        return clipped

    received, deadline, originals = _recv_request_profile(connection, deadline_ns=deadline_ns,
        prefix=prefix, execution=execution)
    if received != digest:
        raise AuthorityTransportError("registration finalization differs from runtime configuration")
    deadline_ns = current()
    response = _socket_request_profile(path, configuration_digest=digest, deadline_epoch_ns=deadline,
        originals=originals, deadline_ns=deadline_ns, expected_peer_uid=uid, expected_peer_gid=gid,
        execution=execution)
    deadline_ns = current()
    _send_response_profile(connection, response, deadline_ns=deadline_ns, execution=execution)


def _serve_verifier(process, connection, *, deadline_ns, prefix):
    return _serve_verifier_profile(process, connection, deadline_ns=deadline_ns, prefix=prefix, execution=False)


def _serve_verifier_profile(process, connection, *, deadline_ns, prefix, execution):
    from serverware import authority_service as service
    from serverware import authority_custody_caller_service as caller
    from serverware import authority_launch_guard as launch
    from serverware import authority_webauthn_evidence as evidence
    from serverware import authority_webauthn_transition_service as transition
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    _request_magic, _response_magic, _count, _lengths, validate_response = _profile(execution)
    if (type(process) is not service.AuthorityProcess or process.role_name != "verifier"
            or process.process_mode != service.PROCESS_MODES["verifier"]
            or type(process.configuration) is not service.MeasuredConfiguration):
        raise AuthorityTransportError("registration finalization requires the actual verifier")
    observed = process.configuration
    digest = framing._configuration_digest(observed.digest)
    receipt = observed.attestation_evidence
    interval = _receipt_interval(receipt)
    deadline_ns = caller._relay_deadline(interval, deadline_ns)
    received, deadline, originals = _recv_request_profile(connection, deadline_ns=deadline_ns,
        prefix=prefix, execution=execution)
    if received != digest or process.configuration is not observed:
        raise AuthorityTransportError("registration finalization differs from verifier configuration")
    # Complete immutable raw eleven and EOF precede this sole allowance. No
    # wrapper window replaces the actual finalization composition's opening.
    work = _ValidationWork(QueryReadValidationLimits())
    hints = _hints_on_work(originals[10], work)
    ledger = evidence.capture._SharedLedger(work)
    runtime = evidence.capture._JSONCapture(ledger, maximum_bytes=8192).visit(observed.runtime_role_identities)
    evidence.production._callback(work, lambda: launch.require_active("verifier"))
    actual = evidence.production._callback(work, lambda: dict(launch.generation()))
    generation = transition._generation_on_work(actual, work)

    def current():
        if (process.configuration is not observed or observed.digest != digest
                or process.role_name != "verifier" or process.process_mode != service.PROCESS_MODES["verifier"]
                or observed.attestation_evidence is not receipt or _receipt_interval(receipt) != interval):
            raise AuthorityTransportError("registration finalization verifier scope changed")
        transition._require_generation_on_work("verifier", generation, work)
        evidence.plan._same(observed.runtime_role_identities, runtime, work,
            "registration finalization verifier runtime cohort changed")
        clipped = evidence.production._callback(work, lambda: caller._relay_deadline(interval, deadline_ns))
        if (process.configuration is not observed or observed.digest != digest
                or observed.attestation_evidence is not receipt or _receipt_interval(receipt) != interval):
            raise AuthorityTransportError("registration finalization verifier changed during callbacks")
        return clipped

    deadline_ns = current()
    prepare = (service.AuthorityProcess._prepare_webauthn_registration_finalization_execution
        if execution else service.AuthorityProcess._prepare_webauthn_registration_finalization)
    response = prepare(process,
        request_originals=originals[:8], response_originals=originals[8:10],
        sibling_challenge_ids=hints, deadline_epoch_ns=deadline,
        work=work, transport_deadline_ns=deadline_ns)
    response = validate_response(response)
    deadline_ns = current()
    _send_response_profile(connection, response, deadline_ns=deadline_ns, execution=execution)
