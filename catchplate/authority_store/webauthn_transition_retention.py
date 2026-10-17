"""Content-addressed PostgreSQL custody of four successor-plan originals.

Both entrypoints require the genuine PostgreSQL facade in a caller-owned
SERIALIZABLE planner-writer transaction. They use the existing generic physical
connection/work guards and a real nested savepoint, but only this dedicated
transition protocol, row shape and actual original-proof replay. No successful
verification carrier, received context or stored key enrolls independent pins.

The only write is immutable custody metadata, not business execution. Identical
retries compare all immutable material and preserve the first stored timestamp.
Writes check the original signed expiry and invocation deadline against an
actual clock window; reads replay historical originals without a current clock.
All four raw lengths and their aggregate are admitted before codec allocation.

Returned raw4/digest/time observations remain pending the caller's outer commit.
Savepoint release is not durability; uncertain outer exit or missing custody
does not establish rollback, absence, current roots or execution authority.
There is no automatic retry, signer, new work allowance or connection opener.
Native driver resources and undetectable hidden commit-and-BEGIN behavior retain
the same boundary as the existing writer owner.
"""
from __future__ import annotations

from catchplate import authority_contract as authority
from catchplate import authority_webauthn_evidence_plan_clock as clock
from catchplate import authority_webauthn_transition_retention as retention
from catchplate.authority_store import planner_connection as connection_contract
from catchplate.authority_store import revocation_retention as codecs
from catchplate.authority_store import webauthn_evidence_retention as lifecycle


plan, evidence = retention.plan, retention.evidence
_FIELDS = authority.WEBAUTHN_TRANSITION_RETAINED_COLUMNS
_TABLE = "catchplate_metadata." + authority.WEBAUTHN_TRANSITION_RETAINED_TABLE
_SELECT = ("SELECT " + ", ".join(_FIELDS) + " FROM " + _TABLE
    + " WHERE retained_record_digest = %s")
_INSERT = ("INSERT INTO " + _TABLE + " (" + ", ".join(_FIELDS)
    + ") VALUES (" + ", ".join(("%s",) * len(_FIELDS))
    + ") ON CONFLICT (retained_record_digest) DO NOTHING")
_BODIES = (
    ("exact_envelope_base64url", "exact_envelope_bytes_digest", "exact_envelope_byte_count", plan.contract.MAX_BYTES),
    ("original_proof_base64url", "original_proof_bytes_digest", "original_proof_byte_count", plan.proof.contract.MAX_BYTES),
    ("original_inputs_base64url", "original_inputs_bytes_digest", "original_inputs_byte_count", plan.proof.wire.MAX_BYTES),
    ("evaluation_context_base64url", "evaluation_context_bytes_digest", "evaluation_context_byte_count", plan.context.MAX_BYTES),
)

# These helpers enforce the actual facade, singly bound writer proxy, physical
# transaction identity, finally-preserved work, and failure cleanup. They do not
# interpret evidence-plan shapes or accept a successful verification result.
_admit, _call, _scope = lifecycle._admit, lifecycle._call, lifecycle._scope
_raw4 = retention._raw4


def _error(message):
    return connection_contract._db_value("MetadataStoreError")(message)


def _expectations(expectations, planner_public_key, operation_public_key, work):
    ledger = evidence.capture._SharedLedger(work)
    if (not isinstance(planner_public_key, plan.Ed25519PublicKey)
            or not isinstance(operation_public_key, plan.Ed25519PublicKey)):
        raise ValueError("transition custody requires independently held Ed25519 public keys")
    evidence.plan.contract._object(expectations, plan.contract.EXPECTATION_FIELDS,
        "independent transition custody expectations")
    owned = evidence.capture._JSONCapture(ledger).visit(expectations)
    plan.contract._validate_expectations(owned)
    return owned


def _owned_row(row, work):
    if (type(row) is not dict or len(row) != len(_FIELDS)
            or any(type(name) is not str for name in row) or set(row) != set(_FIELDS)):
        raise _error("transition custody is missing or not a complete closed row")
    counts = []
    transports = frozenset(name for body in _BODIES for name in (body[0], body[2]))
    for encoded_name, _digest_name, count_name, maximum in _BODIES:
        count, encoded = row[count_name], row[encoded_name]
        if (type(count) is not int or not 2 <= count <= maximum
                or type(encoded) is not str or len(encoded) != (4 * count + 2) // 3):
            raise _error("transition custody original-byte transport exceeds its bound")
        counts.append(count)
    if sum(counts) > retention.MAX_ORIGINAL_BYTES:
        raise _error("transition custody originals exceed their aggregate bound")
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
                raise _error("transition custody operation is not source fixed")
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
        "original_proof_base64url": codecs._encode(record.proof_bytes, work),
        "original_proof_bytes_digest": header["proofBytesDigest"],
        "original_proof_byte_count": header["proofByteCount"],
        "original_inputs_base64url": codecs._encode(record.inputs_bytes, work),
        "original_inputs_bytes_digest": header["inputsBytesDigest"],
        "original_inputs_byte_count": header["inputsByteCount"],
        "evaluation_context_base64url": codecs._encode(record.context_bytes, work),
        "evaluation_context_bytes_digest": header["contextBytesDigest"],
        "evaluation_context_byte_count": header["contextByteCount"],
        "planner_key_digest": header["plannerKeyDigest"], "operation_key_digest": header["operationKeyDigest"],
        "source_revision": header["sourceRevision"]}


def _timing(record, work):
    # This record was produced locally by genuine original-byte replay. Its
    # verification observation intentionally has no decoded payload authority.
    envelope = evidence.wire._decode_object(record.envelope_bytes, work=work,
        maximum_bytes=plan.contract.MAX_BYTES, maximum_nodes=plan.contract.MAX_NODES,
        maximum_depth=plan.contract.MAX_DEPTH)
    plan.contract.validate_envelope_shape(envelope)
    evidence.capability._canonical(record.envelope_bytes, envelope,
        evidence.capture._SharedLedger(work), plan.contract.MAX_BYTES, plan.contract.MAX_NODES)
    payload = envelope["payload"]
    return payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]


def _fresh(timing, owned, now):
    plan._fresh({"issuedAtEpochNs": timing[0], "expiresAtEpochNs": timing[1]}, owned, now)


def _live(timing, owned, window, work):
    now = clock._check_on_work(window, work=work)
    _fresh(timing, owned, now)
    return now


def _observation(record, row):
    return {"envelope_bytes": record.envelope_bytes, "proof_bytes": record.proof_bytes,
        "inputs_bytes": record.inputs_bytes, "context_bytes": record.context_bytes,
        "retained_record_digest": record.record_digest, "retained_at_epoch_ns": row["retained_at_epoch_ns"]}


def persist_webauthn_transition_plan_record(*, envelope_bytes, proof_bytes, inputs_bytes,
        context_bytes, expectations, planner_public_key, operation_public_key, connection, work):
    """Genuinely replay raw4 and INSERT/readback inside one actual savepoint.

    A post-savepoint rejection requires the caller to abort its still-owned
    outer transaction; this function never commits or reports durability.
    """
    originals = _raw4(envelope_bytes, proof_bytes, inputs_bytes, context_bytes)
    owned = _expectations(expectations, planner_public_key, operation_public_key, work)
    raw, original, guarded = _admit(connection, work)
    manager = _call(connection, raw, original, work, lambda: guarded.transaction())
    with _scope(manager, connection, raw, original, work):
        record = retention._verify_record_on_work(envelope_bytes=originals[0], proof_bytes=originals[1],
            inputs_bytes=originals[2], context_bytes=originals[3], expectations=owned,
            planner_public_key=planner_public_key, operation_public_key=operation_public_key, work=work)
        _call(connection, raw, original, work, lambda: None)
        timing = _timing(record, work)
        policy = owned["proofExpectations"]["policy"]
        window = clock._open_on_work(deadline_epoch_ns=min(policy["deadlineEpochNs"], timing[1]),
            maximum_lifetime_ns=owned["maximumPlanAgeNs"],
            maximum_clock_skew_ns=policy["maximumClockSkewNs"], work=work)
        expected = _material(record, work)
        parameters = codecs._parameters(expected, _FIELDS[:-1], work)
        cursor_manager = _call(connection, raw, original, work, lambda: guarded.cursor())
        with _scope(cursor_manager, connection, raw, original, work) as cursor:
            retained_at = _live(timing, owned, window, work)
            # Twenty-two variable values were prepared above; appending the
            # actual sampled timestamp is fixed twenty-three-column scaffolding.
            _call(connection, raw, original, work, lambda: cursor.execute(_INSERT, (*parameters, retained_at)))
            result = _call(connection, raw, original, work,
                lambda: cursor.execute(_SELECT, (record.record_digest,)))
            row = _owned_row(_call(connection, raw, original, work, lambda: result.fetchone()), work)
            codecs._match(row, expected, work)
            # DO NOTHING preserves the immutable first timestamp on retries.
            _fresh(timing, owned, row["retained_at_epoch_ns"])
            _live(timing, owned, window, work)
            _call(connection, raw, original, work, lambda: None)
        _live(timing, owned, window, work)
        _call(connection, raw, original, work, lambda: None)
    _live(timing, owned, window, work)
    _call(connection, raw, original, work, lambda: None)
    return _observation(record, row)


def read_webauthn_transition_plan_record(*, retained_record_digest, expectations,
        planner_public_key, operation_public_key, connection, work):
    """Read and replay historical raw4 without sampling or renewing current time.

    Missing, incomplete or conflicting custody raises and never proves absence
    of an earlier commit. Only independent expectations supply history and pins.
    """
    evidence.plan.contract._digest(retained_record_digest)
    owned = _expectations(expectations, planner_public_key, operation_public_key, work)
    raw, original, guarded = _admit(connection, work)
    manager = _call(connection, raw, original, work, lambda: guarded.transaction())
    with _scope(manager, connection, raw, original, work):
        cursor_manager = _call(connection, raw, original, work, lambda: guarded.cursor())
        with _scope(cursor_manager, connection, raw, original, work) as cursor:
            result = _call(connection, raw, original, work,
                lambda: cursor.execute(_SELECT, (retained_record_digest,)))
            row = _owned_row(_call(connection, raw, original, work, lambda: result.fetchone()), work)
        codecs._match(row, {"retained_record_digest": retained_record_digest}, work)
        originals = _raw4(*(codecs._decode(row[body[0]], row[body[2]], body[3], work)
            for body in _BODIES))
        record = retention._verify_record_on_work(envelope_bytes=originals[0], proof_bytes=originals[1],
            inputs_bytes=originals[2], context_bytes=originals[3], expectations=owned,
            planner_public_key=planner_public_key, operation_public_key=operation_public_key, work=work)
        _call(connection, raw, original, work, lambda: None)
        codecs._match(row, _material(record, work), work)
        _fresh(_timing(record, work), owned, row["retained_at_epoch_ns"])
        _call(connection, raw, original, work, lambda: None)
    _call(connection, raw, original, work, lambda: None)
    return _observation(record, row)
