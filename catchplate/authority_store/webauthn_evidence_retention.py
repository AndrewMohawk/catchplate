"""Content-addressed PostgreSQL custody of three original evidence-plan bytes.

Both entrypoints require the actual PostgreSQL facade in a caller-owned
SERIALIZABLE planner-writer transaction. Each uses a real nested savepoint and
genuinely replays raw originals with independent historical expectations and
held public keys. No successful verification carrier is accepted as input.

The sole INSERT is immutable metadata, not the proposed evidence/business row.
Content identity has no uniqueness or authority over a logical operation.
Identical retries compare all immutable material and preserve the first stored
timestamp. Historical reads sample no current clock; writes retain the original
absolute deadline and signed lifetime, including on an identical retry.

Returned raw3/digest/time observations are pending the caller's outer commit.
Normal savepoint exit is not durability; a later failure or uncertain outer
exit grants no rollback claim, execution capability, new signing attempt or
retry allowance. Physical-handle/status checks cannot detect a hostile driver's
hidden commit-and-BEGIN. SQL/native driver work retains its separate boundary;
all variable codecs, comparisons and genuine replay use the existing work.
"""
from __future__ import annotations

from contextlib import contextmanager

from catchplate import authority_contract as authority
from catchplate import authority_revocation_root_reader as reader
from catchplate import authority_revocation_writer_connection as writer
from catchplate import authority_webauthn_evidence_plan_clock as clock
from catchplate import authority_webauthn_evidence_plan_retention as retention
from catchplate.authority_store import planner_connection as connection_contract
from catchplate.authority_store import revocation_retention as codecs


plan, evidence = retention.plan, retention.evidence
_FIELDS = authority.WEBAUTHN_EVIDENCE_RETAINED_COLUMNS
_TABLE = "catchplate_metadata." + authority.WEBAUTHN_EVIDENCE_RETAINED_TABLE
_SELECT = ("SELECT " + ", ".join(_FIELDS) + " FROM " + _TABLE
    + " WHERE retained_record_digest = %s")
_INSERT = ("INSERT INTO " + _TABLE + " (" + ", ".join(_FIELDS)
    + ") VALUES (" + ", ".join(("%s",) * len(_FIELDS))
    + ") ON CONFLICT (retained_record_digest) DO NOTHING")
_BODIES = (
    ("exact_envelope_base64url", "exact_envelope_bytes_digest", "exact_envelope_byte_count", plan.contract.MAX_BYTES),
    ("original_inputs_base64url", "original_inputs_bytes_digest", "original_inputs_byte_count", plan.inputs_wire.MAX_BYTES),
    ("evaluation_context_base64url", "evaluation_context_bytes_digest", "evaluation_context_byte_count",
        retention.context_wire.MAX_BYTES),
)


def _error(message):
    return connection_contract._db_value("MetadataStoreError")(message)


def _guard(work, call):
    # Unlike the older store/proxy success-only guard, this real shared helper
    # checks the original allowance in finally, including getter/call failures.
    return evidence.production._callback(work, call)


def _same(connection, raw, original):
    physical, proxy_binding = original
    if (connection_contract._require_postgres_connection(connection) is not raw
            or connection.in_transaction is not True):
        raise _error("evidence custody caller transaction or facade handle changed")
    if proxy_binding is not None:
        if type(raw) is not writer._Connection or proxy_binding[1] is not physical:
            raise _error("evidence custody existing writer proxy changed")
        raw._require(proxy_binding)
    reader._require_connection(raw, physical, 2)


def _call(connection, raw, original, work, call):
    def invoke():
        _same(connection, raw, original)
        try:
            result = call()
        except BaseException:
            # A failed callback cannot publish data. Recheck observable
            # continuity, but preserve the first failure for real cleanup.
            try:
                _same(connection, raw, original)
            except BaseException:
                pass
            raise
        _same(connection, raw, original)
        return result
    return _guard(work, invoke)


def _cleanup(manager, failure, work):
    called = False

    def close():
        nonlocal called
        called = True
        return manager.__exit__(type(failure), failure, failure.__traceback__)

    try:
        _guard(work, close)
    except BaseException:
        # Invalid work must never prevent rollback/close from being reached.
        # No cleanup error suppresses/replaces the first invocation failure.
        if not called:
            try:
                close()
            except BaseException:
                pass


@contextmanager
def _scope(manager, connection, raw, original, work):
    entered = False

    def enter():
        nonlocal entered
        value = manager.__enter__()
        entered = True
        if value is not manager:
            raise _error("evidence custody manager replaced its entered handle")
        return value

    try:
        active = _call(connection, raw, original, work, enter)
        yield active
    except BaseException as failure:
        if entered:
            _cleanup(manager, failure, work)
        raise
    else:
        exited = False

        def leave():
            nonlocal exited
            exited = True
            return manager.__exit__(None, None, None)

        try:
            _call(connection, raw, original, work, leave)
        except BaseException as failure:
            if not exited:
                _cleanup(manager, failure, work)
            raise


def _proxy_binding(raw, work):
    if type(raw) is not writer._Connection:
        if isinstance(raw, writer._Connection):
            raise _error("evidence custody does not accept a writer proxy subclass")
        return None
    binding = raw._binding
    if (type(binding) is not tuple or len(binding) != 3 or binding[2] is not work
            or isinstance(binding[0], writer._Connection)):
        raise _error("evidence custody existing writer proxy is not singly bound to this work")
    raw._require(binding)
    return binding


def _admit(connection, work):
    raw = _guard(work, lambda: connection_contract._require_postgres_connection(connection))
    binding = _guard(work, lambda: _proxy_binding(raw, work))
    physical = _guard(work, lambda: reader._connection_identity(raw, 2))
    original = physical, binding
    admitted = _call(connection, raw, original, work,
        lambda: connection_contract._require_planner_writer(connection))
    if admitted is not raw:
        raise _error("evidence custody writer admission replaced its raw handle")
    # The configured writer owner already supplies this exact proxy. Reuse its
    # held binding: wrapping it again would confuse its real cursor/result
    # identity contract. A native facade receives exactly one new proxy.
    # Local outer guards additionally cover the proxy's exceptional callbacks.
    guarded = raw if binding is not None else writer._Connection(raw, physical, work)
    return raw, original, guarded


def _expectations(expectations, planner_public_key, evidence_public_key, work):
    ledger = evidence.capture._SharedLedger(work)
    if (not isinstance(planner_public_key, plan.Ed25519PublicKey)
            or not isinstance(evidence_public_key, plan.Ed25519PublicKey)):
        raise ValueError("evidence custody requires independently held Ed25519 public keys")
    evidence.plan.contract._object(expectations, plan._EXPECTATION_FIELDS, "independent custody expectations")
    owned = evidence.capture._JSONCapture(ledger).visit(expectations)
    request = owned["request"]
    if type(request) is not dict:
        raise ValueError("evidence custody request is not an exact object")
    plan._validate_expectations(owned, request.get("operation"))
    return owned


def _raw3(envelope_bytes, inputs_bytes, evaluation_context_bytes):
    values = (envelope_bytes, inputs_bytes, evaluation_context_bytes)
    for raw, body in zip(values, _BODIES):
        if type(raw) is not bytes or not 2 <= len(raw) <= body[3]:
            raise ValueError("evidence custody requires bounded immutable original bytes")
    return values


def _owned_row(row, work):
    if (type(row) is not dict or len(row) != len(_FIELDS)
            or any(type(name) is not str for name in row) or set(row) != set(_FIELDS)):
        raise _error("evidence custody is missing or not a complete closed row")
    transports = frozenset(name for body in _BODIES for name in (body[0], body[2]))
    for encoded_name, _digest_name, count_name, maximum in _BODIES:
        count, encoded = row[count_name], row[encoded_name]
        if (type(count) is not int or not 2 <= count <= maximum
                or type(encoded) is not str or len(encoded) != (4 * count + 2) // 3):
            raise _error("evidence custody original-byte transport exceeds its bound")
    shape = evidence.plan.contract
    for name in _FIELDS:
        if name in transports:
            continue
        value = row[name]
        if name == "plan_protocol":
            shape._literal(value, retention.PLAN_PROTOCOL)
        elif name == "source_revision":
            shape._literal(value, authority.SOURCE_REVISION)
        elif name == "operation":
            if type(value) is not str or value not in plan.contract.OPERATIONS:
                raise _error("evidence custody operation is not source fixed")
        elif name == "retained_at_epoch_ns":
            shape._integer(value, minimum=1)
        else:
            shape._digest(value)
    work.prepare_copy(row)
    return row.copy()


def _material(record, work):
    header = record.header
    return {"retained_record_digest": record.record_digest, "plan_protocol": header["planProtocol"],
        "operation": header["operation"], "operation_id": header["operationId"],
        "request_digest": header["requestDigest"], "configuration_digest": header["configurationDigest"],
        "plan_digest": header["planDigest"],
        "exact_envelope_base64url": codecs._encode(record.envelope_bytes, work),
        "exact_envelope_bytes_digest": header["envelopeBytesDigest"],
        "exact_envelope_byte_count": header["envelopeByteCount"],
        "original_inputs_base64url": codecs._encode(record.inputs_bytes, work),
        "original_inputs_bytes_digest": header["inputsBytesDigest"],
        "original_inputs_byte_count": header["inputsByteCount"],
        "evaluation_context_base64url": codecs._encode(record.evaluation_context_bytes, work),
        "evaluation_context_bytes_digest": header["contextBytesDigest"],
        "evaluation_context_byte_count": header["contextByteCount"],
        "planner_key_digest": header["plannerKeyDigest"], "evidence_key_digest": header["evidenceKeyDigest"],
        "source_revision": header["sourceRevision"]}


def _payload(record, work):
    value = evidence.wire._decode_object(record.verification.payload_bytes, work=work,
        maximum_bytes=plan.contract.MAX_BYTES, maximum_nodes=plan.contract.MAX_NODES,
        maximum_depth=plan.contract.MAX_DEPTH)
    plan.contract.validate_payload_shape(value)
    return value


def _live(payload, owned, window, work):
    now = clock._check_on_work(window, work=work)
    plan._fresh(payload, owned, now)
    return now


def _observation(record, row):
    return {"envelope_bytes": record.envelope_bytes, "inputs_bytes": record.inputs_bytes,
        "evaluation_context_bytes": record.evaluation_context_bytes,
        "retained_record_digest": record.record_digest, "retained_at_epoch_ns": row["retained_at_epoch_ns"]}


def persist_webauthn_evidence_plan_record(*, envelope_bytes, inputs_bytes, evaluation_context_bytes,
        expectations, planner_public_key, evidence_public_key, connection, work):
    """Replay raw3 and INSERT/readback metadata within one real savepoint.

    Returns pending observations only. A post-savepoint rejection cannot undo
    its release; the caller must abort the still-owned outer transaction.
    """
    originals = _raw3(envelope_bytes, inputs_bytes, evaluation_context_bytes)
    owned = _expectations(expectations, planner_public_key, evidence_public_key, work)
    raw, original, guarded = _admit(connection, work)
    manager = _call(connection, raw, original, work, lambda: guarded.transaction())
    with _scope(manager, connection, raw, original, work):
        record = retention._verify_record_on_work(envelope_bytes=originals[0], inputs_bytes=originals[1],
            evaluation_context_bytes=originals[2], expectations=owned,
            planner_public_key=planner_public_key, evidence_public_key=evidence_public_key, work=work)
        _call(connection, raw, original, work, lambda: None)
        payload = _payload(record, work)
        window = clock._open_on_work(deadline_epoch_ns=min(owned["deadlineEpochNs"], payload["expiresAtEpochNs"]),
            maximum_lifetime_ns=owned["maximumPlanAgeNs"],
            maximum_clock_skew_ns=owned["maximumClockSkewNs"], work=work)
        expected = _material(record, work)
        parameters = codecs._parameters(expected, _FIELDS[:-1], work)
        cursor_manager = _call(connection, raw, original, work, lambda: guarded.cursor())
        with _scope(cursor_manager, connection, raw, original, work) as cursor:
            retained_at = _live(payload, owned, window, work)
            # The nineteen variable values were prepared above. Appending one
            # actual clock scalar is fixed twenty-column parameter scaffolding.
            _call(connection, raw, original, work, lambda: cursor.execute(_INSERT, (*parameters, retained_at)))
            result = _call(connection, raw, original, work,
                lambda: cursor.execute(_SELECT, (record.record_digest,)))
            row = _owned_row(_call(connection, raw, original, work, lambda: result.fetchone()), work)
            codecs._match(row, expected, work)
            # The immutable first timestamp is not replaced by retry time.
            plan._fresh(payload, owned, row["retained_at_epoch_ns"])
            _live(payload, owned, window, work)
            _call(connection, raw, original, work, lambda: None)
        _live(payload, owned, window, work)
        _call(connection, raw, original, work, lambda: None)
    _live(payload, owned, window, work)
    _call(connection, raw, original, work, lambda: None)
    return _observation(record, row)


def read_webauthn_evidence_plan_record(*, retained_record_digest, expectations,
        planner_public_key, evidence_public_key, connection, work):
    """Read and genuinely replay stored raw3 without refreshing historical time.

    Missing/incomplete custody raises; it never proves that a prior commit did
    not happen. No stored key/context field supplies independent expectations.
    """
    evidence.plan.contract._digest(retained_record_digest)
    owned = _expectations(expectations, planner_public_key, evidence_public_key, work)
    raw, original, guarded = _admit(connection, work)
    manager = _call(connection, raw, original, work, lambda: guarded.transaction())
    with _scope(manager, connection, raw, original, work):
        cursor_manager = _call(connection, raw, original, work, lambda: guarded.cursor())
        with _scope(cursor_manager, connection, raw, original, work) as cursor:
            result = _call(connection, raw, original, work,
                lambda: cursor.execute(_SELECT, (retained_record_digest,)))
            row = _owned_row(_call(connection, raw, original, work, lambda: result.fetchone()), work)
        codecs._match(row, {"retained_record_digest": retained_record_digest}, work)
        originals = tuple(codecs._decode(row[body[0]], row[body[2]], body[3], work) for body in _BODIES)
        record = retention._verify_record_on_work(envelope_bytes=originals[0], inputs_bytes=originals[1],
            evaluation_context_bytes=originals[2], expectations=owned,
            planner_public_key=planner_public_key, evidence_public_key=evidence_public_key, work=work)
        _call(connection, raw, original, work, lambda: None)
        codecs._match(row, _material(record, work), work)
        plan._fresh(_payload(record, work), owned, row["retained_at_epoch_ns"])
        _call(connection, raw, original, work, lambda: None)
    _call(connection, raw, original, work, lambda: None)
    return _observation(record, row)
