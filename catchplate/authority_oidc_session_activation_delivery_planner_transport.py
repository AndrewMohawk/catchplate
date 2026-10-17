"""Fixed consume prepare/retained/export wire originals, not planning authority.

Distinct request magics carry raw15 prepare, bounded raw16 prepare or raw4
known-plan replay/export.
Prepare/replay retain raw6; export has a distinct ciphertext-only raw7 response.
Every exchange uses the supplied work/window/deadline; no allowance, endpoint,
retry, policy, key, successful proof carrier or operation is selected by input.
"""
from __future__ import annotations

import socket

from catchplate import authority_contract as authority
from catchplate import authority_transport
from catchplate import authority_revocation_writer_transport as io
from catchplate import authority_oidc_session_activation_delivery_plan as consume
from catchplate import authority_oidc_session_activation_delivery_execution_bundle as execution_bundle
from catchplate import oidc_session_activation_delivery as lifetime
from catchplate import oidc_session_activation_history_custody_bootstrap as history


assertion, evidence, clock = consume.assertion, consume.evidence, consume.clock
completion, bundle = consume.provenance.response, consume.bundle
OPERATION = consume.contract.OPERATION
PREPARE_PURPOSE = b"prepare-oidc-session-activation-delivery-plan"
BOUNDED_PREPARE_PURPOSE = b"prepare-bounded-oidc-session-activation-delivery-plan"
RETAINED_PURPOSE = b"verify-retained-oidc-session-activation-delivery-plan"
EXPORT_PURPOSE = b"export-oidc-session-activation-delivery-plan"
PREPARE_REQUEST_MAGIC, RETAINED_REQUEST_MAGIC = b"SWODPQ01", b"SWODVQ01"
BOUNDED_PREPARE_REQUEST_MAGIC = b"SWODPQ02"
RESPONSE_MAGIC = b"SWODPR01"
EXPORT_REQUEST_MAGIC, EXPORT_RESPONSE_MAGIC = b"SWODXQ01", b"SWODXR01"
LISTENER_PATH = "/run/catchplate/oidc-session-activation/delivery-planner.sock"
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
BOUNDED_PREPARE_REQUEST_LIMITS = (len(BOUNDED_PREPARE_PURPOSE), 64, *ACTIVATION_LIMITS, 19)
RETAINED_REQUEST_LIMITS = (len(RETAINED_PURPOSE), consume.contract.MAX_BYTES, 20, 71)
EXPORT_REQUEST_LIMITS = (len(EXPORT_PURPOSE), consume.contract.MAX_BYTES, 20, 71)
RESPONSE_LIMITS = (len(b"uncertain"), history.MAX_CONSUME_REQUEST_BYTES,
    assertion.MAX_CONTEXT_BYTES, consume.contract.MAX_BYTES, 71, 71)
PREPARE_REQUEST_HEADER_BYTES = len(PREPARE_REQUEST_MAGIC) + 8 * len(PREPARE_REQUEST_LIMITS)
BOUNDED_PREPARE_REQUEST_HEADER_BYTES = len(BOUNDED_PREPARE_REQUEST_MAGIC) + 8 * len(BOUNDED_PREPARE_REQUEST_LIMITS)
RETAINED_REQUEST_HEADER_BYTES = len(RETAINED_REQUEST_MAGIC) + 8 * len(RETAINED_REQUEST_LIMITS)
RESPONSE_HEADER_BYTES = len(RESPONSE_MAGIC) + 8 * len(RESPONSE_LIMITS)
EXPORT_REQUEST_HEADER_BYTES = len(EXPORT_REQUEST_MAGIC) + 8 * len(EXPORT_REQUEST_LIMITS)
EXPORT_RESPONSE_HEADER_BYTES = len(EXPORT_RESPONSE_MAGIC) + 8 * 7
MAX_BYTES = authority.MAX_RESULT_BYTES
MAX_RESPONSE_BYTES = sum(RESPONSE_LIMITS)
# Reserve the entire maximum response and both headers before reading a body.
# Individual ciphertext limits cannot enlarge the existing 64 MiB exchange.
MAX_PREPARE_REQUEST_BYTES = MAX_BYTES - PREPARE_REQUEST_HEADER_BYTES - RESPONSE_HEADER_BYTES - MAX_RESPONSE_BYTES
MAX_BOUNDED_PREPARE_REQUEST_BYTES = MAX_BYTES - BOUNDED_PREPARE_REQUEST_HEADER_BYTES - RESPONSE_HEADER_BYTES - MAX_RESPONSE_BYTES
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
            or len(BOUNDED_PREPARE_REQUEST_LIMITS) != 16
            or len(RETAINED_REQUEST_LIMITS) != 4 or len(RESPONSE_LIMITS) != 6
            or len(EXPORT_REQUEST_LIMITS) != 4 or len(EXPORT_RESPONSE_LIMITS) != 7
            or MAX_BYTES != 64 * 1024 * 1024 or MAX_BYTES > io.MAX_REQUEST_BYTES
            or MAX_PREPARE_REQUEST_BYTES <= 0 or MAX_RETAINED_REQUEST_BYTES <= 0
            or MAX_BOUNDED_PREPARE_REQUEST_BYTES <= 0
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
    if purpose == BOUNDED_PREPARE_PURPOSE:
        return (BOUNDED_PREPARE_REQUEST_MAGIC, BOUNDED_PREPARE_REQUEST_LIMITS,
            MAX_BOUNDED_PREPARE_REQUEST_BYTES, BOUNDED_PREPARE_REQUEST_HEADER_BYTES)
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
    if purpose in (PREPARE_PURPOSE, BOUNDED_PREPARE_PURPOSE):
        activation_end = 15
        if (lengths[1] != 64 or any(size < 2 for size in lengths[6:activation_end])
                or lengths[7] < bundle.OVERHEAD_BYTES + 2
                or purpose == BOUNDED_PREPARE_PURPOSE and not 1 <= lengths[-1] <= 19):
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


def _bounded_deadline_original(raw):
    return (_deadline_original(raw) and len(raw) <= 19
        and (len(raw) < 19 or raw <= b"9223372036854775807"))


def _originals(values, *, response, export=False):
    """Closed byte shape only; no request, plan or completion proof is admitted."""
    if (type(response) is not bool or type(export) is not bool or type(values) is not tuple
            or (export and not response)):
        _fail("consume planner requires source-fixed immutable originals")
    counts = ((7,) if export else (6,)) if response else (15, 16, 4)
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
        if purpose in (PREPARE_PURPOSE, BOUNDED_PREPARE_PURPOSE):
            if any(item not in _URLSAFE for item in values[1]):
                _fail("consume prepare token is not its exact original grammar")
            completion.transport._originals(values[2:6], response=True)
            try:
                bundle._bounded_frame(values[7])
            except bundle.ActivationExecutionBundleError as exc:
                raise AuthorityTransportError("consume prepare encrypted original frame differs") from exc
            if purpose == BOUNDED_PREPARE_PURPOSE and not _bounded_deadline_original(values[-1]):
                _fail("consume bounded prepare deadline is not canonical positive i64")
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


def _bounded_prepare_deadline_on_work(originals, work):
    """The caller's untrusted ceiling can only shorten real server processing."""
    evidence.capture._SharedLedger(work)
    held = _originals(originals, response=False)
    if held[0] != BOUNDED_PREPARE_PURPOSE:
        _fail("consume bounded deadline requires the explicit raw16 profile")
    work.charge(input_bytes=2 * len(held[-1]))
    return int(held[-1].decode("ascii"))


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
    elif magic == BOUNDED_PREPARE_REQUEST_MAGIC:
        purpose = BOUNDED_PREPARE_PURPOSE
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


def _recv_request_on_work(connection, *, deadline_ns, work, current,
        maximum_request_bytes=None, expected_purpose=None):
    """Dynamic worker intake retains actual original guards between chunks.

    This is the existing closed grammar on an owned nonblocking socket. The
    optional body cap only tightens the profile's prior whole-exchange ceiling.
    No numeric-window-only guard can replace the actual delivery continuation.
    """
    from catchplate import oidc_session_activation_release_transport as chunks

    maximum = MAX_BYTES if maximum_request_bytes is None else maximum_request_bytes
    if type(maximum) is not int or not 1 <= maximum <= MAX_BYTES:
        _fail("consume planner dynamic request cap must only restrict the fixed inventory")
    if expected_purpose is not None:
        _profile(expected_purpose)
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    chunks._guard(work, current, deadline_ns)
    chunks._connection(connection, **kwargs)
    chunks._peer(connection, (REQUEST_PEER_UID, REQUEST_PEER_GID), **kwargs)
    magic = chunks._recv_exact(connection, 8, **kwargs)
    if magic == PREPARE_REQUEST_MAGIC:
        purpose = PREPARE_PURPOSE
    elif magic == BOUNDED_PREPARE_REQUEST_MAGIC:
        purpose = BOUNDED_PREPARE_PURPOSE
    elif magic == RETAINED_REQUEST_MAGIC:
        purpose = RETAINED_PURPOSE
    elif magic == EXPORT_REQUEST_MAGIC:
        purpose = EXPORT_PURPOSE
    else:
        _fail("consume planner dynamic request magic differs")
    if expected_purpose is not None and purpose != expected_purpose:
        _fail("consume planner dynamic request differs from the owner's fixed phase")
    limits = _profile(purpose)[1]
    header = chunks._recv_exact(connection, 8 * len(limits), **kwargs)
    work.charge(input_bytes=len(header))
    lengths = tuple(int.from_bytes(header[index:index + 8], "big")
        for index in range(0, len(header), 8))
    _request_lengths(lengths, purpose)
    if sum(lengths) > maximum:
        _fail("consume planner dynamic request exceeds the remaining held inventory")
    work.charge(input_bytes=2 * sum(lengths))
    originals = tuple(chunks._recv_precharged(connection, size, **kwargs) for size in lengths)
    chunks._eof(connection, **kwargs)
    held = _originals(originals, response=False)
    if held[0] != purpose:
        _fail("consume planner dynamic magic and original purpose differ")
    chunks._guard(work, current, deadline_ns)
    return held


def _send_response_on_work(connection, originals, *, deadline_ns, work, current, export=False):
    """The dynamic owner retains its genuine guard through each response chunk."""
    from catchplate import oidc_session_activation_release_transport as chunks

    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    chunks._guard(work, current, deadline_ns)
    held = _originals(originals, response=True, export=export)
    chunks._connection(connection, **kwargs)
    chunks._peer(connection, (REQUEST_PEER_UID, REQUEST_PEER_GID), **kwargs)
    magic = EXPORT_RESPONSE_MAGIC if export else RESPONSE_MAGIC
    header_bytes = len(magic) + 8 * len(held)
    work.charge(input_bytes=2 * header_bytes + sum(map(len, held)))
    header = magic + b"".join(len(raw).to_bytes(8, "big") for raw in held)
    for raw in (header, *held):
        chunks._send_precharged(connection, raw, **kwargs)
    chunks._guard(work, current, deadline_ns)


def _socket_request(endpoint, *, originals, live_window, deadline_ns, work):
    # All originals, endpoint scalars and the original window are held before
    # the first native/clock callback. No callback or received proof is input.
    held = _originals(originals, response=False)
    if held[0] == BOUNDED_PREPARE_PURPOSE:
        _fail("bounded consume prepare requires its guarded caller entrypoint")
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


def _socket_request_on_work(endpoint, *, originals, live_window, deadline_ns,
        work, current, maximum_response_bytes=None):
    """Only bounded prepare/export; retain actual parent and window guards."""
    held = _originals(originals, response=False)
    if held[0] not in (BOUNDED_PREPARE_PURPOSE, EXPORT_PURPOSE):
        _fail("guarded consume caller requires its fixed prepare or export profile")
    path, timeout, uid, gid = _endpoint(endpoint)
    window = clock._validate(live_window)
    evidence.capture._SharedLedger(work)
    if type(deadline_ns) is not int or deadline_ns <= 0 or not callable(current):
        _fail("guarded consume caller requires its original deadline and parent guard")
    if (held[0] == BOUNDED_PREPARE_PURPOSE
            and _bounded_prepare_deadline_on_work(held, work) != window[3]):
        _fail("consume prepare epoch ceiling differs from its original caller window")
    exporting = held[0] == EXPORT_PURPOSE
    request_magic, _limits, _maximum, request_header = _profile(held[0])
    response_magic = EXPORT_RESPONSE_MAGIC if exporting else RESPONSE_MAGIC
    response_header = EXPORT_RESPONSE_HEADER_BYTES if exporting else RESPONSE_HEADER_BYTES
    response_limits = EXPORT_RESPONSE_LIMITS if exporting else RESPONSE_LIMITS
    source_response_maximum = MAX_EXPORT_RESPONSE_BYTES if exporting else MAX_RESPONSE_BYTES
    response_maximum = source_response_maximum if maximum_response_bytes is None else maximum_response_bytes
    if type(response_maximum) is not int or not 1 <= response_maximum <= source_response_maximum:
        _fail("consume caller response ceiling is not a source-bounded tightening")
    # This creates no opening sample or allowance. Both closures retain the
    # actual supplied window; the parent additionally owns its original scope.
    window, window_live = lifetime._window(window, deadline_ns, work)
    bound = min(window[4], deadline_ns)
    limits = work.limits
    observed_epoch = window[0]
    connection = None

    def check():
        nonlocal observed_epoch
        evidence.capture._SharedLedger(work)
        if work.limits is not limits:
            _fail("consume caller changed its inherited work limits")
        io._check_deadline(bound)
        # Sandwich the genuine local epoch/monotonic observation in the actual
        # parent guard. Every observed epoch remains a floor for later stages.
        for guard in (current, window_live, current):
            before = work.metrics
            try:
                epoch = guard()
            finally:
                evidence.capture._SharedLedger(work)
                after = work.metrics
                if (work.limits is not limits or after.hash_work < before.hash_work
                        or after.input_bytes < before.input_bytes or after.json_nodes < before.json_nodes):
                    _fail("consume caller guard changed its original work")
                io._check_deadline(bound)
            if type(epoch) is not int or epoch <= 0 or epoch < observed_epoch:
                _fail("consume caller current epoch reversed")
            observed_epoch = epoch
        return observed_epoch

    def call(operation):
        check()
        try:
            return evidence.production._callback(work,
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
        if type(size) is not int or not 0 <= size <= MAX_BYTES:
            _fail("consume caller response allocation exceeds its source bound")
        check()
        if size == 0:
            return b""
        buffer = bytearray(size)
        offset = 0
        while offset < size:
            count = min(size - offset, io._CHUNK_BYTES)
            chunk = call(lambda: connection.recv(count))
            if type(chunk) is not bytes or not 1 <= len(chunk) <= count:
                _fail("consume caller response closed early or over-read")
            buffer[offset:offset + len(chunk)] = chunk
            offset += len(chunk)
        result = bytes(buffer)
        check()
        return result

    check()
    timeout_bound = evidence.production._callback(work, lambda: io._deadline_ns(timeout))
    check()
    bound = min(bound, timeout_bound)
    check()
    request_bytes = sum(len(raw) for raw in held)
    work.charge(input_bytes=4096 + 2 * request_bytes + 4 * request_header + 4 * response_header)
    header = request_magic + b"".join(len(raw).to_bytes(8, "big") for raw in held)

    def allocate():
        nonlocal connection
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    try:
        check()
        try:
            # Keep the allocation cleanup-owned even if the stable callback
            # suffix or parent/current suffix rejects immediately afterward.
            evidence.production._callback(work, allocate)
        finally:
            check()
        call(lambda: connection.connect(path))
        actual_uid, actual_gid, _pid = call(lambda: authority_transport._peer_identity(connection))
        if (actual_uid, actual_gid) != (uid, gid):
            _fail("consume caller root-created listener peer differs")
        send_precharged(header)
        for raw in held:
            send_precharged(raw)
        call(lambda: connection.shutdown(socket.SHUT_WR))
        if receive_precharged(len(response_magic)) != response_magic:
            _fail("consume caller response magic differs")
        length_header = receive_precharged(8 * len(response_limits))
        lengths = tuple(int.from_bytes(length_header[offset:offset + 8], "big")
            for offset in range(0, len(length_header), 8))
        _response_lengths(lengths, export=exporting)
        response_bytes = sum(lengths)
        if (response_bytes > response_maximum
                or request_bytes + response_bytes + request_header + response_header > MAX_BYTES):
            _fail("consume caller response exceeds its held aggregate ceiling")
        # Reserve all response buffers, chunks and immutable bodies together,
        # before any response body allocation, plus the exact-EOF read.
        work.charge(input_bytes=3 * response_bytes + 1)
        received = tuple(receive_precharged(size) for size in lengths)
        if call(lambda: connection.recv(1)) != b"":
            _fail("consume caller response contains trailing bytes")
        result = _originals(received, response=True, export=exporting)
        expected_status = b"exported" if exporting else b"prepared"
        if result[0] not in (expected_status, b"uncertain"):
            _fail("consume caller response belongs to another fixed branch")
        check()
    finally:
        if connection is not None:
            try:
                check()
            finally:
                # Close the actual owned socket once even when a guard or
                # ledger is already invalid. No numeric descriptor retry.
                try:
                    connection.close()
                finally:
                    check()
    check()
    return result


def _socket_prepare_on_work(endpoint, *, old_token_bytes, activation_originals,
        live_window, deadline_ns, work, current, maximum_response_bytes=None):
    """Guarded raw16 prepare; old_token64 is sent only, never retained here."""
    if type(activation_originals) is not tuple or len(activation_originals) != 13:
        _fail("guarded consume prepare needs the exact original activation tuple13")
    window = clock._validate(live_window)
    ceiling = window[3]
    if type(ceiling) is not int or not 1 <= ceiling <= 2**63 - 1:
        _fail("consume caller original epoch ceiling exceeds positive i64")
    evidence.capture._SharedLedger(work)
    work.charge(input_bytes=2 * 19)
    original_ceiling = str(ceiling).encode("ascii")
    originals = (BOUNDED_PREPARE_PURPOSE, old_token_bytes, *activation_originals, original_ceiling)
    return _socket_request_on_work(endpoint, originals=originals, live_window=window,
        deadline_ns=deadline_ns, work=work, current=current, maximum_response_bytes=maximum_response_bytes)


def _socket_export_retained_on_work(endpoint, *, envelope_bytes, expected_deadline_epoch_ns,
        expected_journal_digest, live_window, deadline_ns, work, current, maximum_response_bytes=None):
    """Guarded existing raw4 export; return unverified ciphertext-only raw7."""
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
    originals = (EXPORT_PURPOSE, envelope_bytes, original_deadline, original_digest)
    return _socket_request_on_work(endpoint, originals=originals, live_window=live_window,
        deadline_ns=deadline_ns, work=work, current=current, maximum_response_bytes=maximum_response_bytes)
