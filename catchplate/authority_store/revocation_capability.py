"""Private original-byte capability custody on an admitted issuer transaction.

The caller owns the real issuer connection and outer transaction. Only the two
fixed SECURITY DEFINER functions are called; no planner-writer admission or
direct table access is borrowed. One genuine capability verifier replays the
actual loaded plan on the original work, before any issuance write. Returned
rows and verifier observations are data, never successful-proof inputs.

SQL/driver work, configured role/TLS admission and fixed column scaffolding are
outside H/B/N. Variable row copies, codecs, parameter preparation, authentic
replay and comparisons use the supplied meter. Current clock admission is
separate from the independently supplied historical verification expectations.
No public route, post-plan witness binding, current roots or execution authority
is installed here.
"""
from __future__ import annotations

import time
from contextlib import contextmanager

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from catchplate import authority_contract as authority
from catchplate import authority_revocation_capability as capability
from catchplate.authority_query_read_work import _ValidationWork
from catchplate.authority_store import authorization_records, revocation_execution
from catchplate.authority_store import revocation_retention as store


_PIN_FIELDS = frozenset({"measurementDigest", "attestationReceiptDigest",
    "credentialIssuanceDigest", "maximumAgeNs", "maximumClockSkewNs"})
_LOAD_FIELDS = ("plannerTransactionId", "executionEnvelopeId", "capabilityId",
    "measurementDigest", "attestationReceiptDigest", "credentialIssuanceDigest")
_STORE_FIELDS = ("capabilityBase64Url", "witnessRequestBase64Url", "recordDigest",
    "signerKeyDigest", "witnessKeyDigest", "measurementDigest",
    "attestationReceiptDigest", "credentialIssuanceDigest")
_IDENTITY_FIELDS = ("capabilityId", "capabilityDigest", "capabilityRecordDigest")
_WRITER_FIELDS = (authority.WRITER_CAPABILITY_IMMUTABLE_COLUMNS
    + authority.WRITER_CAPABILITY_TERMINAL_COLUMNS)
_WITNESS_FIELDS = ("witness_receipt_digest", "witness_identity_digest", "witness_sequence",
    "witness_head_digest", "predecessor_head_digest", "predecessor_receipt_digest",
    "log_predecessor_head_digest", "phase", "operation", "request_digest",
    "capability_id", "result_digest", "fence", "receipt_json", "recorded_at_epoch_ns")
_ROW_FIELDS = {
    "planner": store._PARENT_FIELDS, "retainedPlan": store._RECORD_FIELDS,
    "execution": revocation_execution._FIELDS,
    "assertion": authorization_records._ASSERTION_FIELDS,
    "projection": authorization_records._PROJECTION_FIELDS,
    "capability": _WRITER_FIELDS,
    "retainedCapability": authority.REVOCATION_RETAINED_CAPABILITY_COLUMNS,
    "witness": _WITNESS_FIELDS,
}
_LOAD_SQL = ("SELECT catchplate_metadata.catchplate_policy_authority_load_revocation_issuance("
    + ", ".join(("%s",) * len(_LOAD_FIELDS)) + ") AS issuance")
_STORE_SQL = ("SELECT catchplate_metadata.catchplate_policy_authority_issue_revocation_capability("
    + ", ".join(("%s",) * len(_STORE_FIELDS)) + ") AS issuance")


class RevocationCapabilityIssuanceError(ValueError):
    pass


def _closed(value, fields):
    if (type(value) is not dict or len(value) != len(fields)
            or any(type(name) is not str for name in value) or set(value) != set(fields)):
        raise RevocationCapabilityIssuanceError("revocation issuance data is not closed")


def _active(connection, original):
    # psycopg's actual TransactionStatus is an IntEnum. This does not replace
    # connector/definer role admission or authenticate an arbitrary Python DTO.
    # Observed pgconn/status cannot detect a hostile driver's commit-and-BEGIN;
    # the caller's actual driver/process remains trusted for transaction history.
    status = connection.info.transaction_status
    if (connection.pgconn is not original or connection.closed is not False
            or connection.autocommit is not False or isinstance(status, bool)
            or not isinstance(status, int) or status != 2):
        raise RevocationCapabilityIssuanceError("revocation issuance requires its original active issuer transaction")


def _call(connection, original, work, callback, *args):
    def invoke():
        _active(connection, original)
        result = callback(*args)
        _active(connection, original)
        return result
    return store._callback(work, invoke)


@contextmanager
def _scope(connection, original, work, factory):
    manager = _call(connection, original, work, factory)
    with store._context(manager, work) as value:
        _call(connection, original, work, lambda: None)
        yield value
        _call(connection, original, work, lambda: None)
    _call(connection, original, work, lambda: None)


def _string_bound(field):
    if field in ("exact_plan_base64url", "exact_envelope_base64url"):
        return 4 * ((capability.shape.MAX_PAYLOAD_BYTES + 2) // 3)
    if field == "evaluation_context_base64url":
        return 4 * ((capability.retention.MAX_CONTEXT_BYTES + 2) // 3)
    if field == "exact_witness_request_base64url":
        return 4 * ((capability.MAX_WITNESS_REQUEST_BYTES + 2) // 3)
    if field.endswith("base64url"):
        return 4 * ((authority.MAX_REQUEST_BYTES + 2) // 3)
    if field == "mutation_plan_json":
        return authority.MAX_RESULT_BYTES
    if field == "selected_business_rows_json":
        return authority.MAX_PLAN_SELECTED_BYTES
    return authority.MAX_REQUEST_BYTES


def _row(value, fields, work):
    _closed(value, fields)
    for name, item in value.items():
        if (type(item) not in (str, int, type(None))
                or type(item) is str and len(item) > _string_bound(name)
                or type(item) is int and not 0 <= item <= 2**63 - 1):
            raise RevocationCapabilityIssuanceError("revocation issuance row exceeds its scalar source bounds")
    work.prepare_copy(value)
    return value.copy()


def _query(connection, original, cursor, sql, parameters, work):
    result = _call(connection, original, work, cursor.execute, sql, parameters)
    row = _call(connection, original, work, result.fetchone)
    _closed(row, ("issuance",))
    return row["issuance"]


def _load(connection, original, cursor, parameters, work):
    observed = _query(connection, original, cursor, _LOAD_SQL, parameters, work)
    _closed(observed, _ROW_FIELDS)
    owned = {}
    for name, fields in _ROW_FIELDS.items():
        value = observed[name]
        if name in ("capability", "retainedCapability", "witness") and value is None:
            owned[name] = None
        else:
            owned[name] = _row(value, fields, work)
    if ((owned["capability"] is None) != (owned["retainedCapability"] is None)
            or owned["capability"] is not None and owned["witness"] is None):
        raise RevocationCapabilityIssuanceError("revocation issuance custody is incomplete")
    return owned


def _fresh(payload, pins, connection, original, work):
    now_monotonic = _call(connection, original, work, time.monotonic_ns)
    now_epoch = _call(connection, original, work, time.time_ns)
    if any(type(value) is not int or not 1 <= value <= 2**63 - 1
           for value in (now_monotonic, now_epoch)):
        raise RevocationCapabilityIssuanceError("revocation issuance current clock is invalid")
    remaining_mono = payload["deadlineMonotonicNs"] - now_monotonic
    remaining_epoch = payload["deadlineEpochNs"] - now_epoch
    age, skew = pins["maximumAgeNs"], pins["maximumClockSkewNs"]
    if (payload["issuedAtEpochNs"] > now_epoch + skew
            or now_epoch - payload["issuedAtEpochNs"] > age
            or remaining_mono <= 0 or remaining_epoch <= 0
            or remaining_mono > age or remaining_epoch > age + skew
            or abs(remaining_mono - remaining_epoch) > skew):
        raise RevocationCapabilityIssuanceError("revocation issuance current deadline is stale or inconsistent")


def _custody_rows(observation, pins, work):
    """Fixed actual SQL custody fields derived only after genuine verification."""
    payload, receipt = observation.payload, observation.payload["witnessReservation"]
    mapping = {
        "capability_id": "capabilityId", "envelope_id": "envelopeId", "operation": "operation",
        "operation_id": "operationId", "handler_name": "handlerName", "request_digest": "requestDigest",
        "operation_manifest_digest": "operationManifestDigest", "query_manifest_digest": "queryManifestDigest",
        "authority_root_set_digest": "authorityRootSetDigest", "authority_snapshot_digest": "authoritySnapshotDigest",
        "approver_policy_digest": "approverPolicyDigest", "webauthn_receipt_digest": "webauthnReceiptDigest",
        "webauthn_trust_high_water_digest": "webauthnTrustHighWaterDigest",
        "witness_reservation_digest": "witnessReservationDigest", "witness_sequence": "witnessSequence",
        "witness_head_digest": "witnessHeadDigest", "deadline_monotonic_ns": "deadlineMonotonicNs",
        "fence": "fence", "issued_monotonic_ns": "issuedMonotonicNs", "issued_at_epoch_ns": "issuedAtEpochNs",
        "expires_at_epoch_ns": "expiresAtEpochNs", "issuer_session_identity_digest": "issuerSessionIdentityDigest",
        "expected_result_digest": "expectedResultDigest", "planner_transaction_id": "plannerTransactionId",
        "authorization_projection_digest": "authorizationProjectionDigest",
        "selected_business_rows_digest": "selectedBusinessRowsDigest", "mutation_plan_digest": "mutationPlanDigest",
        "deadline_epoch_ns": "deadlineEpochNs",
    }
    writer = {field: payload[key] for field, key in mapping.items()}
    writer.update({"capability_protocol": capability.CAPABILITY_PROTOCOL,
        "capability_record_digest": observation.record_digest, "capability_digest": observation.capability_digest,
        "webauthn_receipt_json": store._json_text(payload["webauthnReceipt"], authority.MAX_REQUEST_BYTES, work),
        "issuer_measurement_digest": pins["measurementDigest"],
        "issuer_attestation_receipt_digest": pins["attestationReceiptDigest"],
        "issuer_credential_issuance_digest": pins["credentialIssuanceDigest"], "status": "issued",
        **{field: None for field in authority.WRITER_CAPABILITY_TERMINAL_COLUMNS if field != "status"}})
    retained = {
        "capability_id": payload["capabilityId"], "capability_protocol": capability.CAPABILITY_PROTOCOL,
        "capability_record_digest": observation.record_digest, "planner_transaction_id": payload["plannerTransactionId"],
        "plan_protocol": capability.CAPABILITY_PROTOCOL, "retained_record_digest": observation.retained_record.record_digest,
        "execution_envelope_id": payload["envelopeId"], "capability_digest": observation.capability_digest,
        "root_transition_digest": payload["rootTransitionDigest"], "authority_snapshot_digest": payload["authoritySnapshotDigest"],
        "exact_request_bytes_digest": payload["exactRequestBytesDigest"],
        "exact_capability_base64url": store._encode(observation.envelope_bytes, work),
        "exact_capability_bytes_digest": observation.envelope_digest,
        "exact_capability_byte_count": len(observation.envelope_bytes),
        "signer_key_digest": observation.signer_key_digest, "witness_key_digest": observation.witness_key_digest,
        "exact_witness_request_base64url": store._encode(observation.witness_request_bytes, work),
        "exact_witness_request_bytes_digest": observation.witness_request_bytes_digest,
        "exact_witness_request_byte_count": len(observation.witness_request_bytes),
        "source_revision": authority.SOURCE_REVISION,
    }
    witness = {"witness_receipt_digest": observation.witness_receipt_digest,
        "witness_identity_digest": receipt["witnessIdentityDigest"], "witness_sequence": receipt["sequence"],
        "witness_head_digest": receipt["headDigest"], "predecessor_head_digest": receipt["predecessorHeadDigest"],
        "predecessor_receipt_digest": receipt["predecessorReceiptDigest"],
        "log_predecessor_head_digest": receipt["logPredecessorHeadDigest"], "phase": receipt["phase"],
        "operation": receipt["operation"], "request_digest": receipt["requestDigest"],
        "capability_id": receipt["capabilityId"], "result_digest": receipt["resultDigest"], "fence": receipt["fence"],
        "receipt_json": store._json_text(receipt, capability.MAX_WITNESS_REQUEST_BYTES, work),
        "recorded_at_epoch_ns": receipt["issuedAtEpochNs"]}
    return writer, retained, witness


def _expected_rows(observation, loaded, pins, work):
    record = observation.retained_record
    reservation, planned, retained = store._bindings(record, work)
    timestamp = loaded["planner"]["planned_at_epoch_ns"]
    store._planned_time(timestamp, reservation)
    parent = {**reservation, **planned, "status": "planned", "planned_at_epoch_ns": timestamp}
    evidence, projection = store._authorization_bindings(record, work)
    execution = revocation_execution._expected_reservation(observation.payload["envelopeId"], record, parent, work)
    writer, retained_capability, witness = _custody_rows(observation, pins, work)
    return {"planner": parent, "retainedPlan": retained, "execution": execution,
        "assertion": evidence, "projection": projection, "capability": writer,
        "retainedCapability": retained_capability, "witness": witness}


def _compare(loaded, expected, work, *, initial):
    for name, row in expected.items():
        if initial and loaded[name] is None and name in ("capability", "retainedCapability", "witness"):
            continue
        if loaded[name] is None:
            raise RevocationCapabilityIssuanceError("revocation issuance readback lost custody")
        store._match(loaded[name], row, work)


def _issue_on_connection(*, connection, envelope_bytes: bytes, witness_request_bytes: bytes,
        issuer_pins: dict, work: _ValidationWork, signer_public_key: Ed25519PublicKey,
        witness_public_key: Ed25519PublicKey, expected_signer_identity,
        expected_issuer_session_identity_digest: str, expected_execution_envelope_id: str,
        expected_witness_receipt_digest: str, expected_witness_identity_digest: str,
        expected_configuration_digest: str, expected_generation_sequence: int,
        expected_generation_digest: str, retention_expectations: dict) -> dict:
    """Issue or exactly retry original bytes in the caller's active transaction.

    Configured issuer pins are independently supplied, never taken from the
    capability. SQL repeats their actual admission. Both new and issued retries
    genuinely replay once and pass today's clock policy; terminal parents,
    envelopes or capabilities cannot enter this path. A savepoint contains all
    load/store work and returned-ID checks. It never commits the outer owner.
    """
    ledger = capability.capture._SharedLedger(work)
    capability.shape._object(retention_expectations, capability.wire._EXPECTATIONS, "retention expectations")
    handles = {name: retention_expectations[name] for name in capability._HANDLE_FIELDS}
    capability.plan._verification_types(**handles)
    if not isinstance(signer_public_key, Ed25519PublicKey) or not isinstance(witness_public_key, Ed25519PublicKey):
        raise RevocationCapabilityIssuanceError("revocation issuance keys are not Ed25519 public keys")
    for value, maximum in ((envelope_bytes, capability.MAX_CAPABILITY_BYTES),
                           (witness_request_bytes, capability.MAX_WITNESS_REQUEST_BYTES)):
        if type(value) is not bytes or not 2 <= len(value) <= maximum:
            raise RevocationCapabilityIssuanceError("revocation issuance requires bounded original bytes")
    owned = capability._capture_expectations(ledger, retention_expectations,
        expected_signer_identity=expected_signer_identity,
        expected_issuer_session_identity_digest=expected_issuer_session_identity_digest,
        expected_execution_envelope_id=expected_execution_envelope_id,
        expected_witness_receipt_digest=expected_witness_receipt_digest,
        expected_witness_identity_digest=expected_witness_identity_digest,
        expected_configuration_digest=expected_configuration_digest,
        expected_generation_sequence=expected_generation_sequence,
        expected_generation_digest=expected_generation_digest)
    _closed(issuer_pins, _PIN_FIELDS)
    pins = capability.capture._JSONCapture(ledger).visit(issuer_pins, depth=0)
    for name in ("measurementDigest", "attestationReceiptDigest", "credentialIssuanceDigest"):
        capability.shape._digest(pins[name])
    capability.shape._integer(pins["maximumAgeNs"], minimum=1)
    capability.shape._integer(pins["maximumClockSkewNs"])
    historical = {**owned["retention"], **handles}
    load_arguments = {"plannerTransactionId": historical["expected_planner_transaction_id"],
        "executionEnvelopeId": owned["expectedExecutionEnvelopeId"],
        "capabilityId": historical["expected_capability_id"],
        **{name: pins[name] for name in _LOAD_FIELDS[3:]}}
    load_parameters = store._parameters(load_arguments, _LOAD_FIELDS, work)
    original = store._callback(work, lambda: connection.pgconn)
    _call(connection, original, work, lambda: None)
    with _scope(connection, original, work, connection.transaction):
        with _scope(connection, original, work, connection.cursor) as cursor:
            loaded = _load(connection, original, cursor, load_parameters, work)
            retained, execution = loaded["retainedPlan"], loaded["execution"]
            retained_bytes = store._decode(retained["exact_envelope_base64url"],
                retained["exact_envelope_byte_count"], capability.shape.MAX_PAYLOAD_BYTES, work)
            context_bytes = store._decode(retained["evaluation_context_base64url"],
                retained["evaluation_context_byte_count"], capability.retention.MAX_CONTEXT_BYTES, work)
            execution_bytes = store._decode(execution["exact_request_base64url"],
                execution["exact_request_byte_count"], authority.MAX_REQUEST_BYTES, work)
            observation = capability._verify_signed_capability_on_work(work=work,
                envelope_bytes=envelope_bytes, witness_request_bytes=witness_request_bytes,
                retained_envelope_bytes=retained_bytes, evaluation_context_bytes=context_bytes,
                execution_request_bytes=execution_bytes, signer_public_key=signer_public_key,
                witness_public_key=witness_public_key, expected_signer_identity=owned["expectedSignerIdentity"],
                expected_issuer_session_identity_digest=owned["expectedIssuerSessionIdentityDigest"],
                expected_execution_envelope_id=owned["expectedExecutionEnvelopeId"],
                expected_witness_receipt_digest=owned["expectedWitnessReceiptDigest"],
                expected_witness_identity_digest=owned["expectedWitnessIdentityDigest"],
                expected_configuration_digest=owned["expectedConfigurationDigest"],
                expected_generation_sequence=owned["expectedGenerationSequence"],
                expected_generation_digest=owned["expectedGenerationDigest"], retention_expectations=historical)
            _call(connection, original, work, lambda: None)
            expected = _expected_rows(observation, loaded, pins, work)
            _compare(loaded, expected, work, initial=True)
            retained_capability = expected["retainedCapability"]
            store_arguments = {"capabilityBase64Url": retained_capability["exact_capability_base64url"],
                "witnessRequestBase64Url": retained_capability["exact_witness_request_base64url"],
                "recordDigest": observation.record_digest, "signerKeyDigest": observation.signer_key_digest,
                "witnessKeyDigest": observation.witness_key_digest,
                **{name: pins[name] for name in _STORE_FIELDS[5:]}}
            parameters = store._parameters(store_arguments, _STORE_FIELDS, work)
            identity = {"capabilityId": observation.payload["capabilityId"],
                "capabilityDigest": observation.capability_digest, "capabilityRecordDigest": observation.record_digest}
            _fresh(observation.payload, pins, connection, original, work)
            returned = _row(_query(connection, original, cursor, _STORE_SQL, parameters, work), _IDENTITY_FIELDS, work)
            store._match(returned, identity, work)
            reread = _load(connection, original, cursor, load_parameters, work)
            _compare(reread, expected, work, initial=False)
            _fresh(observation.payload, pins, connection, original, work)
    return returned
