"""Closed CP -> runtime relay -> verifier registration source acquisition.

The existing routers admit their actual peers before calling these handlers.
The relay forwards bounded original selector bytes; the verifier observes its
own roots and invokes the genuine signed source exchange. A selector is not
enrollment, publication provenance or currentness authority. Returned raw four
remain data requiring independent signature and membership replay. No grants,
keys, roots, caller callbacks, custody, business writes or retry enter this wire.
"""
from __future__ import annotations

import socket

from serverware import authority_custody_caller_transport as framing
from serverware import authority_revocation_writer_transport as io
from serverware import authority_webauthn_registration_source_request as request
from serverware import authority_webauthn_registration_source_response as response


REQUEST_MAGIC = b"SWRCAQ01"
RESPONSE_MAGIC = b"SWRCAR01"
SCHEMA = "serverware.registrationSourceAcquisition/v1"
MAX_REQUEST_BYTES = 65536
MAX_REQUEST_NODES = 64
MAX_REQUEST_DEPTH = 4
MAX_RESPONSE_BYTES = request.authority.MAX_RESULT_BYTES
_FIELDS = frozenset({"schema", "sourceRevision", "registrationChallengeId",
    "publishedPublicationId", "oidcSessionId", "deadlineEpochNs"})
_LIMITS = (request.MAX_CONTROL_BYTES, request.MAX_CONTEXT_BYTES,
    response.MAX_CONTROL_BYTES, response.MAX_SOURCE_BYTES)
_check_deadline = io._check_deadline


def _raw(value):
    if type(value) is not bytes or not 2 <= len(value) <= MAX_REQUEST_BYTES:
        raise ValueError("registration source acquisition request is not bounded original bytes")
    return value


def _shape(value):
    shape = request.evidence.plan.contract
    shape._object(value, _FIELDS, "registration source acquisition")
    shape._literal(value["schema"], SCHEMA)
    shape._literal(value["sourceRevision"], request.authority.SOURCE_REVISION)
    for name in ("registrationChallengeId", "publishedPublicationId"):
        shape._text(value[name], 4096)
    if value["oidcSessionId"] is not None:
        shape._text(value["oidcSessionId"], 4096)
    shape._integer(value["deadlineEpochNs"], minimum=1)


def _produce_request_on_work(*, registration_challenge_id, published_publication_id,
        oidc_session_id, deadline_epoch_ns, work):
    ledger = request.evidence.capture._SharedLedger(work)
    owned = request.evidence.capture._JSONCapture(ledger,
        maximum_bytes=MAX_REQUEST_BYTES).visit({"schema": SCHEMA,
            "sourceRevision": request.authority.SOURCE_REVISION,
            "registrationChallengeId": registration_challenge_id,
            "publishedPublicationId": published_publication_id,
            "oidcSessionId": oidc_session_id, "deadlineEpochNs": deadline_epoch_ns})
    _shape(owned)
    return request.evidence.capability._wire(owned, ledger,
        MAX_REQUEST_BYTES, MAX_REQUEST_NODES)


def _read_request_on_work(original, work):
    raw = _raw(original)
    value = request.evidence.wire._decode_object(raw, work=work,
        maximum_bytes=MAX_REQUEST_BYTES, maximum_nodes=MAX_REQUEST_NODES,
        maximum_depth=MAX_REQUEST_DEPTH)
    _shape(value)
    request.evidence.capability._canonical(raw, value,
        request.evidence.capture._SharedLedger(work), MAX_REQUEST_BYTES, MAX_REQUEST_NODES)
    return value


def _lengths(lengths):
    if (type(lengths) is not tuple or len(lengths) != 4
            or any(type(size) is not int or not 2 <= size <= limit
                for size, limit in zip(lengths, _LIMITS))
            or sum(lengths) > MAX_RESPONSE_BYTES):
        raise ValueError("registration source acquisition response lengths are invalid")


def _originals(originals):
    if (type(originals) is not tuple or len(originals) != 4
            or any(type(raw) is not bytes for raw in originals)):
        raise ValueError("registration source acquisition response is not raw four")
    _lengths(tuple(len(raw) for raw in originals))
    return originals


def _recv_request(connection, *, deadline_ns, prefix):
    if type(prefix) is not bytes or prefix != REQUEST_MAGIC:
        raise ValueError("registration source acquisition prefix is invalid")
    digest = io._recv_exact_until(connection, 71, deadline_ns=deadline_ns)
    digest = framing._configuration_digest(digest.decode("ascii"))
    size = int.from_bytes(io._recv_exact_until(connection, 8, deadline_ns=deadline_ns), "big")
    if not 2 <= size <= MAX_REQUEST_BYTES:
        raise ValueError("registration source acquisition request length is invalid")
    original = io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
    io._require_eof(connection, deadline_ns)
    return digest, _raw(original)


def _send_response(connection, originals, *, deadline_ns):
    originals = _originals(originals)
    header = RESPONSE_MAGIC + b"".join(len(raw).to_bytes(8, "big") for raw in originals)
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    for raw in originals:
        io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _socket_request(path, *, configuration_digest, request_bytes, deadline_ns,
        expected_peer_uid, expected_peer_gid):
    """One exact peer exchange; the owner supplies the existing total deadline."""
    raw, digest = _raw(request_bytes), framing._configuration_digest(configuration_digest)
    if (type(path) is not str or not 1 <= len(path) <= 107
            or not path.startswith("/") or "\x00" in path
            or not 1 <= len(path.encode("utf-8")) <= 107
            or any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
                for value in (expected_peer_uid, expected_peer_gid))):
        raise ValueError("registration source acquisition endpoint is invalid")
    header = REQUEST_MAGIC + digest.encode("ascii") + len(raw).to_bytes(8, "big")
    _check_deadline(deadline_ns)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        io._call_until(connection, deadline_ns, lambda: connection.connect(path))
        uid, gid, _pid = io._call_until(connection, deadline_ns,
            lambda: framing.authority_transport._peer_identity(connection))
        if (uid, gid) != (expected_peer_uid, expected_peer_gid):
            raise ValueError("registration source acquisition server peer differs")
        io._send_exact_until(connection, header, deadline_ns=deadline_ns)
        io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
        io._call_until(connection, deadline_ns, lambda: connection.shutdown(socket.SHUT_WR))
        if io._recv_prefix(connection, deadline_ns=deadline_ns) != RESPONSE_MAGIC:
            raise ValueError("registration source acquisition response prefix is invalid")
        header = io._recv_exact_until(connection, 32, deadline_ns=deadline_ns)
        lengths = tuple(int.from_bytes(header[index:index + 8], "big") for index in range(0, 32, 8))
        _lengths(lengths)
        originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
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
    return _originals(originals)


def _serve_relay(trust, connection, *, deadline_ns, prefix):
    from serverware import authority_service as service
    from serverware import authority_custody_caller_service as custody
    from serverware import authority_launch_guard as guard
    import os

    if type(trust) is not service.AuthorityRuntimeClient:
        raise ValueError("registration source relay requires its actual runtime trust")
    path, uid, gid = trust.verifier_socket_path, trust.verifier_uid, trust.verifier_gid
    relay_uid, relay_gid = trust.server_uid, trust.server_gid
    digest = framing._configuration_digest(trust.configuration_digest)
    attestation = trust.attestation_evidence
    if type(attestation) is not dict or type(attestation.get("payload")) is not dict:
        raise ValueError("registration source relay original receipt is missing")
    payload = attestation["payload"]
    interval = payload.get("issuedAtEpochNs"), payload.get("expiresAtEpochNs")
    if (any(type(value) is not int or not 1 <= value <= (1 << 63) - 1 for value in interval)
            or interval[0] >= interval[1]
            or any(type(value) is not int for value in (uid, gid, relay_uid, relay_gid))
            or os.environ.get("SERVERWARE_PROCESS_MODE", "").strip() != service.RUNTIME_RELAY_PROCESS_MODE
            or (os.geteuid(), os.getegid()) != (relay_uid, relay_gid)):
        raise ValueError("registration source relay process or original receipt is invalid")
    deadline_ns = custody._relay_deadline(interval, deadline_ns)
    guard.require_active("runtime")
    received_digest, raw = _recv_request(connection, deadline_ns=deadline_ns, prefix=prefix)
    if received_digest != digest:
        raise ValueError("registration source acquisition differs from runtime configuration")
    deadline_ns = custody._relay_deadline(interval, deadline_ns)
    originals = _socket_request(path, configuration_digest=digest, request_bytes=raw,
        deadline_ns=deadline_ns, expected_peer_uid=uid, expected_peer_gid=gid)
    deadline_ns = custody._relay_deadline(interval, deadline_ns)
    guard.require_active("runtime")
    _send_response(connection, originals, deadline_ns=deadline_ns)


def _serve_verifier(process, connection, *, deadline_ns, prefix):
    from serverware import authority_service as service
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    if (type(process) is not service.AuthorityProcess or process.role_name != "verifier"
            or process.process_mode != service.PROCESS_MODES["verifier"]
            or type(process.configuration) is not service.MeasuredConfiguration):
        raise ValueError("registration source acquisition requires the actual verifier")
    configuration = process.configuration
    digest = framing._configuration_digest(configuration.digest)
    received_digest, raw = _recv_request(connection, deadline_ns=deadline_ns, prefix=prefix)
    if received_digest != digest or process.configuration is not configuration:
        raise ValueError("registration source acquisition configuration differs")
    # The actual ingress peer, complete bounded frame and EOF precede allocation.
    work = _ValidationWork(QueryReadValidationLimits())
    value = _read_request_on_work(raw, work)
    _check_deadline(deadline_ns)
    originals = service.AuthorityProcess._acquire_webauthn_registration_source(process,
        registration_challenge_id=value["registrationChallengeId"],
        published_publication_id=value["publishedPublicationId"],
        oidc_session_id=value["oidcSessionId"], deadline_epoch_ns=value["deadlineEpochNs"],
        work=work, transport_deadline_ns=deadline_ns)
    if process.configuration is not configuration:
        raise ValueError("registration source acquisition configuration changed")
    _check_deadline(deadline_ns)
    _send_response(connection, originals, deadline_ns=deadline_ns)
