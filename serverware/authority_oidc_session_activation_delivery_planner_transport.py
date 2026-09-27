"""Fixed consume prepare/retained/export wire originals, not planning authority.

Distinct request magics carry raw15 prepare or raw4 known-plan replay/export.
Prepare/replay retain raw6; export has a distinct ciphertext-only raw7 response.
Every exchange uses the supplied work/window/deadline; no allowance, endpoint,
retry, policy, key, successful proof carrier or operation is selected by input.
"""
from __future__ import annotations

import socket

from serverware import authority_contract as authority
from serverware import authority_transport
from serverware import authority_revocation_writer_transport as io
from serverware import authority_oidc_session_activation_delivery_plan as consume
from serverware import authority_oidc_session_activation_delivery_execution_bundle as execution_bundle
from serverware import oidc_session_activation_delivery as lifetime
from serverware import oidc_session_activation_history_custody_bootstrap as history


assertion, evidence, clock = consume.assertion, consume.evidence, consume.clock
completion, bundle = consume.provenance.response, consume.bundle
OPERATION = consume.contract.OPERATION
PREPARE_PURPOSE = b"prepare-oidc-session-activation-delivery-plan"
RETAINED_PURPOSE = b"verify-retained-oidc-session-activation-delivery-plan"
EXPORT_PURPOSE = b"export-oidc-session-activation-delivery-plan"
PREPARE_REQUEST_MAGIC, RETAINED_REQUEST_MAGIC = b"SWODPQ01", b"SWODVQ01"
RESPONSE_MAGIC = b"SWODPR01"
EXPORT_REQUEST_MAGIC, EXPORT_RESPONSE_MAGIC = b"SWODXQ01", b"SWODXR01"
LISTENER_PATH = "/run/serverware/oidc-session-activation/delivery-planner.sock"
SERVICE_UID = SERVICE_GID = 65501
REQUEST_PEER_UID = REQUEST_PEER_GID = 65532
# Kernel socket-activation creator, not an attestation of executing service UID.
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
ACTIVATION_LIMITS = (*completion.transport.RESPONSE_LIMITS, consume.activation_plan.contract.MAX_BYTES,
    bundle.MAX_BYTES, completion.authorization.MAX_BYTES, completion.pending.MAX_RECEIPT_BYTES,
    completion.pending.computation.MAX_SNAPSHOT_BYTES, completion.admission.caller.MAX_AUTHORIZATION_BYTES,
    completion.grants.MAX_GRANT_BYTES, completion.admission.caller.MAX_ENROLLMENT_BYTES,
    completion.grants.MAX_ENROLLMENT_BYTES)
PREPARE_REQUEST_LIMITS = (len(PREPARE_PURPOSE), 64, *ACTIVATION_LIMITS)
RETAINED_REQUEST_LIMITS = (len(RETAINED_PURPOSE), consume.contract.MAX_BYTES, 20, 71)
EXPORT_REQUEST_LIMITS = (len(EXPORT_PURPOSE), consume.contract.MAX_BYTES, 20, 71)
RESPONSE_LIMITS = (len(b"uncertain"), history.MAX_CONSUME_REQUEST_BYTES,
    assertion.MAX_CONTEXT_BYTES, consume.contract.MAX_BYTES, 71, 71)
PREPARE_REQUEST_HEADER_BYTES = len(PREPARE_REQUEST_MAGIC) + 8 * len(PREPARE_REQUEST_LIMITS)
RETAINED_REQUEST_HEADER_BYTES = len(RETAINED_REQUEST_MAGIC) + 8 * len(RETAINED_REQUEST_LIMITS)
RESPONSE_HEADER_BYTES = len(RESPONSE_MAGIC) + 8 * len(RESPONSE_LIMITS)
EXPORT_REQUEST_HEADER_BYTES = len(EXPORT_REQUEST_MAGIC) + 8 * len(EXPORT_REQUEST_LIMITS)
EXPORT_RESPONSE_HEADER_BYTES = len(EXPORT_RESPONSE_MAGIC) + 8 * 7
MAX_BYTES = authority.MAX_RESULT_BYTES
MAX_RESPONSE_BYTES = sum(RESPONSE_LIMITS)
# Reserve the entire maximum response and both headers before reading a body.
# Individual ciphertext limits cannot enlarge the existing 64 MiB exchange.
MAX_PREPARE_REQUEST_BYTES = MAX_BYTES - PREPARE_REQUEST_HEADER_BYTES - RESPONSE_HEADER_BYTES - MAX_RESPONSE_BYTES
MAX_RETAINED_REQUEST_BYTES = min(sum(RETAINED_REQUEST_LIMITS),
    MAX_BYTES - RETAINED_REQUEST_HEADER_BYTES - RESPONSE_HEADER_BYTES - MAX_RESPONSE_BYTES)
MAX_EXPORT_REQUEST_BYTES = sum(EXPORT_REQUEST_LIMITS)
# The raw7 has exactly the old six bounded fields plus its ciphertext frame.
# Reserve the worst-case request, both headers and every other response field
# before accepting any body; the codec ceiling cannot enlarge this exchange.
MAX_EXPORT_BUNDLE_BYTES = min(execution_bundle.MAX_BYTES,
    MAX_BYTES - MAX_EXPORT_REQUEST_BYTES - EXPORT_REQUEST_HEADER_BYTES
    - EXPORT_RESPONSE_HEADER_BYTES - MAX_RESPONSE_BYTES)
EXPORT_RESPONSE_LIMITS = (*RESPONSE_LIMITS[:4], MAX_EXPORT_BUNDLE_BYTES, *RESPONSE_LIMITS[4:])
MAX_EXPORT_RESPONSE_BYTES = sum(EXPORT_RESPONSE_LIMITS)
AuthorityTransportError = authority_transport.AuthorityTransportError
_URLSAFE = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
_check_deadline = io._check_deadline


def _fail(message):
    raise AuthorityTransportError(message)


def _source_bounds():
    if (len(ACTIVATION_LIMITS) != 13 or len(PREPARE_REQUEST_LIMITS) != 15
            or len(RETAINED_REQUEST_LIMITS) != 4 or len(RESPONSE_LIMITS) != 6
            or len(EXPORT_REQUEST_LIMITS) != 4 or len(EXPORT_RESPONSE_LIMITS) != 7
            or MAX_BYTES != 64 * 1024 * 1024 or MAX_BYTES > io.MAX_REQUEST_BYTES
            or MAX_PREPARE_REQUEST_BYTES <= 0 or MAX_RETAINED_REQUEST_BYTES <= 0
            or not execution_bundle.OVERHEAD_BYTES + 2 <= MAX_EXPORT_BUNDLE_BYTES <= execution_bundle.MAX_BYTES
            or (MAX_EXPORT_REQUEST_BYTES + MAX_EXPORT_RESPONSE_BYTES
                + EXPORT_REQUEST_HEADER_BYTES + EXPORT_RESPONSE_HEADER_BYTES > MAX_BYTES)
            or MAX_RESPONSE_BYTES + PREPARE_REQUEST_HEADER_BYTES + RESPONSE_HEADER_BYTES >= MAX_BYTES):
        _fail("consume planner fixed frame inventory exceeds its source exchange")


def _timeout(value):
    if type(value) is not int or not 1 <= value <= 30:
        _fail("consume planner timeout is outside its fixed profile")
    return value


def _endpoint(endpoint):
    if type(endpoint) is not tuple or len(endpoint) != 4:
        _fail("consume planner endpoint is not an exact four-tuple")
    path, timeout, uid, gid = endpoint
    if (type(path) is not str or path != LISTENER_PATH
            or type(uid) is not int or uid != EXPECTED_PEER_UID
            or type(gid) is not int or gid != EXPECTED_PEER_GID):
        _fail("consume planner endpoint differs from its fixed root-created listener")
    return path, _timeout(timeout), uid, gid


def _profile(purpose):
    if type(purpose) is not bytes:
        _fail("consume planner purpose is not a fixed original")
    if purpose == PREPARE_PURPOSE:
        return PREPARE_REQUEST_MAGIC, PREPARE_REQUEST_LIMITS, MAX_PREPARE_REQUEST_BYTES, PREPARE_REQUEST_HEADER_BYTES
    if purpose == RETAINED_PURPOSE:
        return RETAINED_REQUEST_MAGIC, RETAINED_REQUEST_LIMITS, MAX_RETAINED_REQUEST_BYTES, RETAINED_REQUEST_HEADER_BYTES
    if purpose == EXPORT_PURPOSE:
        return EXPORT_REQUEST_MAGIC, EXPORT_REQUEST_LIMITS, MAX_EXPORT_REQUEST_BYTES, EXPORT_REQUEST_HEADER_BYTES
    _fail("consume planner purpose is not source admitted")


def _request_lengths(lengths, purpose):
    _source_bounds()
    _magic, limits, maximum, _header = _profile(purpose)
    if (type(lengths) is not tuple or len(lengths) != len(limits)
            or any(type(size) is not int or not 0 <= size <= cap for size, cap in zip(lengths, limits))
            or lengths[0] != len(purpose) or sum(lengths) > maximum):
        _fail("consume planner request exceeds its fixed frame/aggregate bounds")
    if purpose == PREPARE_PURPOSE:
        if lengths[1] != 64 or any(size < 2 for size in lengths[6:]) or lengths[7] < bundle.OVERHEAD_BYTES + 2:
            _fail("consume prepare original inventory differs")
        # Closed original completion shape only, never signature admission.
        completion.transport._response_lengths(lengths[2:6])
    elif lengths[1] < 2 or not 1 <= lengths[2] <= 20 or lengths[3] != 71:
        _fail("consume retained selector lengths differ")


def _response_lengths(lengths, *, export=False):
    _source_bounds()
    if type(export) is not bool:
        _fail("consume planner response branch is not source fixed")
    limits = EXPORT_RESPONSE_LIMITS if export else RESPONSE_LIMITS
    maximum = MAX_EXPORT_RESPONSE_BYTES if export else MAX_RESPONSE_BYTES
    if (type(lengths) is not tuple or len(lengths) != len(limits)
            or any(type(size) is not int or not 0 <= size <= cap for size, cap in zip(lengths, limits))
            or sum(lengths) > maximum):
        _fail("consume planner response exceeds its fixed bounds")
    if export:
        status, request, scope, envelope, ciphertext, plan_digest, journal_digest = lengths
        if not ((status == len(b"exported") and request >= 2 and scope >= 2 and envelope >= 2
                and ciphertext >= execution_bundle.OVERHEAD_BYTES + 2 and plan_digest == journal_digest == 71)
                or (status == len(b"uncertain")
                    and request == scope == envelope == ciphertext == plan_digest == journal_digest == 0)):
            _fail("consume planner export response branch differs")
        return
    status, request, scope, envelope, plan_digest, journal_digest = lengths
    if not ((status == len(b"prepared") and request >= 2 and scope >= 2 and envelope >= 2
            and plan_digest == journal_digest == 71)
            or (status == len(b"uncertain") and request == scope == envelope == plan_digest == journal_digest == 0)):
        # prepared and verified deliberately have the same bounded length.
        _fail("consume planner response branch differs")


def _digest(raw):
    return len(raw) == 71 and raw[:7] == b"sha256:" and all(item in b"0123456789abcdef" for item in raw[7:])


def _deadline_original(raw):
    return 1 <= len(raw) <= 20 and raw[0] in b"123456789" and all(item in b"0123456789" for item in raw)


def _originals(values, *, response, export=False):
    """Closed byte shape only; no request, plan or completion proof is admitted."""
    if (type(response) is not bool or type(export) is not bool or type(values) is not tuple
            or (export and not response)):
        _fail("consume planner requires source-fixed immutable originals")
    counts = ((7,) if export else (6,)) if response else (15, 4)
    if len(values) not in counts or any(type(raw) is not bytes for raw in values):
        _fail("consume planner original frame inventory differs")
    lengths = tuple(len(raw) for raw in values)
    if response:
        _response_lengths(lengths, export=export)
        statuses = (b"exported",) if export else (b"prepared", b"verified")
        if not ((values[0] in statuses and _digest(values[-2]) and _digest(values[-1]))
                or (values[0] == b"uncertain" and all(raw == b"" for raw in values[1:]))):
            _fail("consume planner response values differ")
        if export and values[0] == b"exported":
            try:
                execution_bundle._bounded_frame(values[4])
            except execution_bundle.DeliveryExecutionBundleError as exc:
                raise AuthorityTransportError("consume export encrypted original frame differs") from exc
    else:
        purpose = values[0]
        _request_lengths(lengths, purpose)
        if purpose == PREPARE_PURPOSE:
            if any(item not in _URLSAFE for item in values[1]):
                _fail("consume prepare token is not its exact original grammar")
            completion.transport._originals(values[2:6], response=True)
            try:
                bundle._bounded_frame(values[7])
            except bundle.ActivationExecutionBundleError as exc:
                raise AuthorityTransportError("consume prepare encrypted original frame differs") from exc
        elif not _deadline_original(values[2]) or not _digest(values[3]):
            _fail("consume retained deadline or journal identity is not canonical")
    return values


def _retained_scope(originals, work):
    """Decode only caller-retained ordinary expectations, never signed facts."""
    evidence.capture._SharedLedger(work)
    held = _originals(originals, response=False)
    if len(held) != 4 or held[0] not in (RETAINED_PURPOSE, EXPORT_PURPOSE):
        _fail("consume retained decoding requires its fixed request branch")
    work.charge(input_bytes=2 * (len(held[2]) + len(held[3])))
    return int(held[2].decode("ascii")), held[3].decode("ascii")


def _guard(live_window, deadline_ns, work):
    evidence.capture._SharedLedger(work)
    if type(deadline_ns) is not int or deadline_ns <= 0:
        _fail("consume planner requires its inherited absolute deadline")
    window, live = lifetime._window(live_window, deadline_ns, work)
    bound = min(window[4], deadline_ns)
    live()
    return window, bound, live


def _recv_exact(connection, size, bound, work, live):
    # Existing I/O allocates a fixed buffer, receive chunks and final bytes.
    work.charge(input_bytes=3 * size)
    live()
    value = evidence.production._callback(work,
        lambda: io._recv_exact_until(connection, size, deadline_ns=bound))
    live()
    return value


def _recv_bodies(connection, *, purpose, response, bound, work, live):
    export = response and purpose == EXPORT_PURPOSE
    limits = (EXPORT_RESPONSE_LIMITS if export else RESPONSE_LIMITS) if response else _profile(purpose)[1]
    header = _recv_exact(connection, 8 * len(limits), bound, work, live)
    lengths = tuple(int.from_bytes(header[index:index + 8], "big") for index in range(0, len(header), 8))
    if response:
        _response_lengths(lengths, export=export)
    else:
        _request_lengths(lengths, purpose)
    # Lengths AND the request+maximum-response aggregate were admitted above.
    originals = tuple(_recv_exact(connection, size, bound, work, live) if size else b"" for size in lengths)
    work.charge(input_bytes=1)
    live()
    evidence.production._callback(work, lambda: io._require_eof(connection, bound))
    live()
    held = _originals(originals, response=response, export=export)
    if not response and held[0] != purpose:
        _fail("consume planner magic and original purpose differ")
    return held


def _recv_request(connection, *, live_window, deadline_ns, work):
    """Admit fixed caller peer before even reading the purpose/magic prefix."""
    _window, bound, live = _guard(live_window, deadline_ns, work)
    peer_uid, peer_gid, _pid = evidence.production._callback(work,
        lambda: io._call_until(connection, bound, lambda: authority_transport._peer_identity(connection)))
    live()
    if (peer_uid, peer_gid) != (REQUEST_PEER_UID, REQUEST_PEER_GID):
        _fail("consume planner caller peer differs")
    magic = _recv_exact(connection, 8, bound, work, live)
    if magic == PREPARE_REQUEST_MAGIC:
        purpose = PREPARE_PURPOSE
    elif magic == RETAINED_REQUEST_MAGIC:
        purpose = RETAINED_PURPOSE
    elif magic == EXPORT_REQUEST_MAGIC:
        purpose = EXPORT_PURPOSE
    else:
        _fail("consume planner request magic differs")
    result = _recv_bodies(connection, purpose=purpose, response=False, bound=bound, work=work, live=live)
    live()
    return result


def _send(connection, held, *, response, bound, work, live, export=False):
    magic = (EXPORT_RESPONSE_MAGIC if export else RESPONSE_MAGIC) if response else _profile(held[0])[0]
    work.charge(input_bytes=2 * (len(magic) + 8 * len(held)))
    header = magic + b"".join(len(raw).to_bytes(8, "big") for raw in held)
    for raw in (header, *held):
        if raw:
            work.charge(input_bytes=2 * len(raw))
            live()
            evidence.production._callback(work,
                lambda: io._send_exact_until(connection, raw, deadline_ns=bound))
            live()


def _send_response(connection, originals, *, live_window, deadline_ns, work, export=False):
    """The actual service supplies originals and closes the connection for EOF."""
    held = _originals(originals, response=True, export=export)
    _window, bound, live = _guard(live_window, deadline_ns, work)
    _send(connection, held, response=True, bound=bound, work=work, live=live, export=export)
    live()


def _socket_request(endpoint, *, originals, live_window, deadline_ns, work):
    # All originals, endpoint scalars and the original window are held before
    # the first native/clock callback. No callback or received proof is input.
    held = _originals(originals, response=False)
    exporting = held[0] == EXPORT_PURPOSE
    response_magic = EXPORT_RESPONSE_MAGIC if exporting else RESPONSE_MAGIC
    response_header = EXPORT_RESPONSE_HEADER_BYTES if exporting else RESPONSE_HEADER_BYTES
    path, timeout, uid, gid = _endpoint(endpoint)
    window, bound, live = _guard(live_window, deadline_ns, work)
    timeout_bound = evidence.production._callback(work, lambda: io._deadline_ns(timeout))
    bound = min(bound, timeout_bound)
    inherited_live = live

    def live():
        # Keep the existing sticky epoch/monotonic observations when narrowing
        # the timeout; do not replace their guard with a fresh one.
        now = inherited_live()
        evidence.production._callback(work, lambda: io._check_deadline(bound))
        return now

    live()
    connection = evidence.production._callback(work, lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
    try:
        live()
        evidence.production._callback(work, lambda: io._call_until(connection, bound, lambda: connection.connect(path)))
        live()
        actual_uid, actual_gid, _pid = evidence.production._callback(work,
            lambda: io._call_until(connection, bound, lambda: authority_transport._peer_identity(connection)))
        live()
        if (actual_uid, actual_gid) != (uid, gid):
            _fail("consume planner root-created listener peer differs")
        _send(connection, held, response=False, bound=bound, work=work, live=live)
        evidence.production._callback(work, lambda: io._call_until(connection, bound,
            lambda: connection.shutdown(socket.SHUT_WR)))
        live()
        if _recv_exact(connection, 8, bound, work, live) != response_magic:
            _fail("consume planner response magic differs")
        result = _recv_bodies(connection, purpose=held[0], response=True, bound=bound, work=work, live=live)
        expected_status = b"exported" if exporting else (b"prepared" if held[0] == PREPARE_PURPOSE else b"verified")
        if result[0] not in (expected_status, b"uncertain"):
            _fail("consume planner response belongs to another request branch")
        if (sum(map(len, held)) + sum(map(len, result)) + _profile(held[0])[3]
                + response_header > MAX_BYTES):
            _fail("consume planner aggregate exchange exceeds its source ceiling")
        live()
    except BaseException:
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    live()
    return result


def _socket_prepare(endpoint, *, old_token_bytes, activation_originals, live_window, deadline_ns, work):
    """One attempt returns unverified raw6; never a prepared-plan capability."""
    if type(activation_originals) is not tuple or len(activation_originals) != 13:
        _fail("consume prepare needs the original fixed activation tuple13")
    originals = (PREPARE_PURPOSE, old_token_bytes, *activation_originals)
    return _socket_request(endpoint, originals=originals,
        live_window=live_window, deadline_ns=deadline_ns, work=work)


def _socket_retained(endpoint, *, purpose, envelope_bytes, expected_deadline_epoch_ns,
        expected_journal_digest, live_window, deadline_ns, work):
    if type(purpose) is not bytes or purpose not in (RETAINED_PURPOSE, EXPORT_PURPOSE):
        _fail("consume retained client purpose differs")
    evidence.capture._SharedLedger(work)
    deadline, digest = expected_deadline_epoch_ns, expected_journal_digest
    if type(deadline) is not int or not 1 <= deadline < 10**20:
        _fail("consume independently retained deadline is outside its fixed grammar")
    if type(digest) is not str or len(digest) != 71:
        _fail("consume independently retained journal identity is not bounded")
    work.charge(input_bytes=2 * (20 + 71))
    try:
        original_deadline, original_digest = str(deadline).encode("ascii"), digest.encode("ascii")
    except UnicodeError as exc:
        raise AuthorityTransportError("consume retained selector is not ASCII") from exc
    originals = (purpose, envelope_bytes, original_deadline, original_digest)
    return _socket_request(endpoint, originals=originals,
        live_window=live_window, deadline_ns=deadline_ns, work=work)


def _socket_verify_retained(endpoint, *, envelope_bytes, expected_deadline_epoch_ns,
        expected_journal_digest, live_window, deadline_ns, work):
    """Known original replay only; deadline/journal identity must be held independently."""
    return _socket_retained(endpoint, purpose=RETAINED_PURPOSE, envelope_bytes=envelope_bytes,
        expected_deadline_epoch_ns=expected_deadline_epoch_ns, expected_journal_digest=expected_journal_digest,
        live_window=live_window, deadline_ns=deadline_ns, work=work)


def _socket_export_retained(endpoint, *, envelope_bytes, expected_deadline_epoch_ns,
        expected_journal_digest, live_window, deadline_ns, work):
    """One retained export attempt returns unverified raw7, never execution authority."""
    return _socket_retained(endpoint, purpose=EXPORT_PURPOSE, envelope_bytes=envelope_bytes,
        expected_deadline_epoch_ns=expected_deadline_epoch_ns, expected_journal_digest=expected_journal_digest,
        live_window=live_window, deadline_ns=deadline_ns, work=work)
