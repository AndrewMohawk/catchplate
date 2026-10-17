"""Fixed live raw4 custody inside the caller's genuine writer transaction.

Originals are replayed against independent expectations and the held planner
key. This module neither commits nor admits execution. Results remain pending
the configured owner's outer commit and close. Reads retain the same original
live interval; there is no historical-expiry fallback or implicit retry.
"""
from __future__ import annotations

from catchplate import authority_contract as authority
from catchplate import authority_recovery_invalidation_retention as retention
from catchplate.authority_store import webauthn_evidence_retention as lifecycle

plan, proof = retention.plan, retention.plan.proof
TABLE = "catchplate_metadata." + authority.RECOVERY_INVALIDATION_RETAINED_TABLE
COLUMNS = authority.RECOVERY_INVALIDATION_RETAINED_COLUMNS
CONTRACT = authority.RECOVERY_INVALIDATION_RETENTION_CONTRACT
_RAW_NAMES = ("envelope_bytes", "request_bytes", "proof_bytes", "context_bytes")
_HEADER_NAMES = (
    "planProtocol", "operation", "operationId", "requestDigest", "configurationDigest",
    "plannerKeyDigest", "planDigest", "envelopeBytesDigest", "envelopeByteCount",
    "requestBytesDigest", "requestByteCount", "proofBytesDigest", "proofByteCount",
    "contextBytesDigest", "contextByteCount", "issuedAtEpochNs", "expiresAtEpochNs",
    "originalDeadlineNs", "sourceRevision",
)
_SELECT = "SELECT " + ", ".join(COLUMNS) + " FROM " + TABLE + " WHERE retained_record_digest = %s"
_INSERT = ("INSERT INTO " + TABLE + " (" + ", ".join(COLUMNS) + ") VALUES ("
    + ", ".join(("%s",) * len(COLUMNS)) + ") ON CONFLICT (retained_record_digest) DO NOTHING")


def _require(value):
    if not value:
        raise retention.RecoveryInvalidationRetentionError("durable invalidation originals differ")


def installation_sql():
    """Actual source DDL; the locked-empty installer owns all installation."""
    _require(tuple(CONTRACT["maximumOriginalBytes"]) == retention._ORIGINAL_LIMITS)
    _require(CONTRACT["maximumAggregateBytes"] == retention.MAX_ORIGINAL_BYTES)
    declarations = []
    for name in COLUMNS:
        if name in _RAW_NAMES:
            kind = "BYTEA"
        elif name.endswith(("_count", "_ns")):
            kind = "BIGINT"
        else:
            kind = "TEXT"
        declarations.append(name + " " + kind + " NOT NULL")
    checks = ["PRIMARY KEY (retained_record_digest)",
        "CHECK (plan_protocol = 'recovery-invalidation-v1')",
        "CHECK (operation = 'webauthn.recovery.invalidate')",
        "CHECK (source_revision = '" + authority.SOURCE_REVISION + "')",
        "CHECK (issued_at_epoch_ns > 0 AND expires_at_epoch_ns > issued_at_epoch_ns",
    ]
    checks[-1] += " AND original_deadline_ns > 0 AND retained_at_epoch_ns > 0 AND retained_at_epoch_ns < expires_at_epoch_ns)"
    counts = []
    for raw, maximum in zip(_RAW_NAMES, CONTRACT["maximumOriginalBytes"]):
        count = raw.removesuffix("_bytes") + "_byte_count"
        counts.append(count)
        checks.append(f"CHECK ({count} BETWEEN 2 AND {maximum} AND octet_length({raw}) = {count})")
    checks.append("CHECK (" + " + ".join(counts) + " <= " + str(CONTRACT["maximumAggregateBytes"]) + ")")
    for name in COLUMNS:
        if name.endswith("_digest") or name == "operation_id":
            checks.append("CHECK (" + name + " ~ '^sha256:[0-9a-f]{64}$')")
    return "CREATE TABLE IF NOT EXISTS " + TABLE + " (\n    " + ",\n    ".join(declarations + checks) + "\n);\n"


def _raw4(originals):
    _require(type(originals) is tuple and len(originals) == 4)
    result = retention._raw4(*originals)
    _require(sum(map(len, result)) <= CONTRACT["maximumAggregateBytes"])
    return result


def _material(record, work):
    # These are the actual verifier's same-call originals, never input DTOs.
    work.charge(input_bytes=4096, json_nodes=128)
    result = {"retained_record_digest": record.record_digest}
    result.update((column, record.header[field])
        for column, field in zip(COLUMNS[1:20], _HEADER_NAMES, strict=True))
    result.update(zip(_RAW_NAMES, (record.envelope_bytes, record.request_bytes,
        record.proof_bytes, record.context_bytes), strict=True))
    return result


def _row(row, work):
    _require(type(row) is dict and set(row) == set(COLUMNS)
        and all(type(name) is str for name in row))
    originals = _raw4(tuple(row[name] for name in _RAW_NAMES))
    for name, raw in zip(_RAW_NAMES, originals):
        count = row[name.removesuffix("_bytes") + "_byte_count"]
        _require(type(count) is int and count == len(raw))
    for name in COLUMNS:
        value = row[name]
        if name in _RAW_NAMES:
            continue
        if name.endswith(("_count", "_ns")):
            plan.shape._integer(value, minimum=1)
        elif name == "plan_protocol":
            _require(type(value) is str and value == retention.PLAN_PROTOCOL)
        elif name == "operation":
            _require(type(value) is str and value == plan.OPERATION)
        elif name == "source_revision":
            _require(type(value) is str and value == authority.SOURCE_REVISION)
        else:
            plan.shape._digest(value)
    work.charge(input_bytes=4096, json_nodes=128)
    return row.copy(), originals


def _match(row, expected, work):
    for name, value in expected.items():
        actual = row[name]
        _require(type(actual) is type(value))
        if type(value) is bytes:
            work.charge(input_bytes=len(actual) + len(value))
        else:
            work.prepare_comparison(actual, value)
        _require(actual == value)


def _replay(originals, expectations, planner_public_key, live_window, check, work):
    return retention._verify_record_on_work(envelope_bytes=originals[0], request_bytes=originals[1],
        proof_bytes=originals[2], context_bytes=originals[3], expectations=expectations,
        planner_public_key=planner_public_key, live_window=live_window, check=check, work=work)


def _run(*, originals, retained_record_digest, expectations, planner_public_key,
        live_window, check, connection, work):
    # The configured owner supplied this neutral original-window guard before
    # opening the connection; every native proxy call also retains it.
    lifecycle._guard(work, check)
    raw, identity, guarded = lifecycle._admit(connection, work)
    _require(type(raw) is lifecycle.writer._Connection
        and raw._held_continuity[0] is check)
    manager = lifecycle._call(connection, raw, identity, work, lambda: guarded.transaction())
    with lifecycle._scope(manager, connection, raw, identity, work):
        record = None
        if originals is not None:
            originals = _raw4(originals)
            record = _replay(originals, expectations, planner_public_key, live_window, check, work)
            retained_record_digest = record.record_digest
        else:
            plan.shape._digest(retained_record_digest)
        cursor_manager = lifecycle._call(connection, raw, identity, work, lambda: guarded.cursor())
        with lifecycle._scope(cursor_manager, connection, raw, identity, work) as cursor:
            if record is not None:
                live = plan._Live(expectations, record.payload, live_window, check, work)
                live.checked()
                expected = _material(record, work)
                retained_at = plan.clock._check_on_work(live_window, work=work)
                live.checked()
                work.charge(input_bytes=sum(len(value) for value in originals), json_nodes=len(COLUMNS))
                parameters = tuple(expected[name] for name in COLUMNS[:-1]) + (retained_at,)
                cursor.execute(_INSERT, parameters)
                live.checked()
            row, stored = _row(cursor.execute(_SELECT, (retained_record_digest,)).fetchone(), work)
        if record is None:
            record = _replay(stored, expectations, planner_public_key, live_window, check, work)
            live = plan._Live(expectations, record.payload, live_window, check, work)
            expected = _material(record, work)
        live.checked()
        _match(row, expected, work)
        _match(row, {"retained_record_digest": retained_record_digest}, work)
        stamp = row["retained_at_epoch_ns"]
        _require(record.original_interval[0] <= stamp + expectations["maximumClockSkewNs"]
            and stamp < record.original_interval[1]
            and stamp - record.original_interval[0] <= expectations["maximumPlanAgeNs"])
        work.charge(input_bytes=1024, json_nodes=32)
        result = {"originals": stored, "retained_record_digest": record.record_digest,
            "retained_at_epoch_ns": stamp}
        live.checked()
    live.checked()
    lifecycle._guard(work, check)
    return result


def persist_record(*, originals, expectations, planner_public_key, live_window, check, connection, work):
    return _run(originals=originals, retained_record_digest=None, expectations=expectations,
        planner_public_key=planner_public_key, live_window=live_window, check=check,
        connection=connection, work=work)


def read_record(*, retained_record_digest, expectations, planner_public_key, live_window, check, connection, work):
    return _run(originals=None, retained_record_digest=retained_record_digest, expectations=expectations,
        planner_public_key=planner_public_key, live_window=live_window, check=check,
        connection=connection, work=work)
