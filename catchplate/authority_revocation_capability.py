"""Inactive original-byte capability/v4 verification on existing work.

The preliminary witness reservation is authenticated, not upgraded to a
post-plan witness bind. Keys, identities, the accepted reservation digest and
historical plan expectations must be independently admitted. No clock, SQL,
registry, current-root admission, one-use consumption or key enrollment occurs.
Returned observations are never accepted as substitute verification inputs.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from catchplate import authority_contract as authority
from catchplate import authority_revocation_retention as retention
from catchplate.authority_query_read_work import QueryReadValidationMetrics, _ValidationWork


plan, wire, capture = retention.plan, retention.wire, retention.capture
shape = plan.contract
OPERATION = shape.OPERATION
CAPABILITY_SCHEMA = "catchplate.policyAuthorityDatabaseCapability/v4"
SIGNED_SCHEMA = "catchplate.signedPolicyAuthorityDatabaseCapability/v4"
RECORD_SCHEMA = "catchplate.policyAuthorityRevocationRetainedCapability/v1"
CAPABILITY_PROTOCOL = "revocation-v4"
EXECUTION_REQUEST_SCHEMA = "catchplate.policyAuthorityRevocationExecutionRequest/v1"
WITNESS_REQUEST_SCHEMA = "catchplate.policyAuthorityReplayWitnessRequest/v2"
WITNESS_RECEIPT_SCHEMA = "catchplate.policyAuthorityReplayWitnessReceipt/v2"
WITNESS_HEAD_SCHEMA = "catchplate.policyAuthorityReplayWitnessHead/v2"
WITNESS_ENVELOPE_SCHEMA = "catchplate.policyAuthorityReplayWitnessEnvelope/v2"
WEBAUTHN_RECEIPT_SCHEMA = "catchplate.policyAuthorityWebAuthnReceipt/v1"
MAX_CAPABILITY_BYTES = authority.MAX_REQUEST_BYTES
MAX_WITNESS_REQUEST_BYTES = 64 * 1024
MAX_JSON_NODES = 4096
MAX_JSON_DEPTH = 16
SIGNED_FIELDS = frozenset({"schema", "sourceRevision", "signerIdentity", "payload", "signatureBase64Url"})
PAYLOAD_FIELDS = frozenset({
    "schema", "capabilityId", "envelopeId", "plannerTransactionId",
    "authorizationProjectionDigest", "selectedBusinessRowsDigest", "mutationPlanDigest",
    "expectedResultDigest", "operation", "operationId", "handlerName", "requestDigest",
    "operationManifestDigest", "queryManifestDigest", "authorityRootSetDigest",
    "authoritySnapshotDigest", "approverPolicyDigest", "webauthnReceipt",
    "webauthnReceiptDigest", "webauthnTrustHighWaterDigest", "witnessReservation",
    "witnessReservationDigest", "witnessSequence", "witnessHeadDigest",
    "witnessPredecessorHeadDigest", "deadlineMonotonicNs", "deadlineEpochNs", "fence",
    "issuedMonotonicNs", "issuedAtEpochNs", "expiresAtEpochNs", "issuerSessionIdentityDigest",
    "planProtocol", "retainedRecordDigest", "rootTransitionDigest", "exactRequestBytesDigest",
})
WITNESS_REQUEST_FIELDS = frozenset({
    "schema", "envelopeId", "parentEnvelopeId", "phase", "operation", "requestDigest",
    "capabilityId", "resultDigest", "predecessorReceiptDigest", "deadlineMonotonicNs",
    "configurationDigest", "operationManifestDigest", "generationSequence", "generationDigest",
    "issuedAtEpochNs", "signature",
})
WITNESS_RECEIPT_FIELDS = frozenset({
    "schema", "envelopeId", "parentEnvelopeId", "phase", "operation", "requestDigest",
    "capabilityId", "resultDigest", "witnessIdentityDigest", "sequence", "fence", "headDigest",
    "predecessorHeadDigest", "predecessorReceiptDigest", "logPredecessorHeadDigest",
    "deadlineMonotonicNs", "issuedAtEpochNs", "generationSequence", "generationDigest",
    "canonicalRequestDigest", "signature",
})
_RECEIPT_EVIDENCE_FIELDS = (
    "operationId", "challengeDigest", "challengeId", "credentialRecordId", "credentialId",
    "credentialPolicyDigest", "trustHighWaterDigest", "clientDataJSONDigest",
    "authenticatorDataDigest", "signatureDigest", "flags", "priorCounter", "counter",
    "userPresent", "userVerified", "verifiedAtEpochNs",
)
WEBAUTHN_RECEIPT_FIELDS = frozenset({"schema", "challengeRowDigest", "credentialBindingDigest",
                                      *_RECEIPT_EVIDENCE_FIELDS})
_CREDENTIAL_FIELDS = (
    "id", "credential_id", "user_id", "public_key_cose", "sign_count", "aaguid",
    "authenticator_class", "attestation_trusted", "attestation_leaf_sha256",
    "attestation_root_sha256", "attestation_trust_bundle_digest",
    "attestation_trust_bundle_sequence", "revoked_at",
)
_CHALLENGE_FIELDS = (
    "id", "challenge", "challenge_type", "user_id", "scope_key", "approval_request_id",
    "payload_json", "expires_at", "used_at", "created_at",
)
_HANDLE_FIELDS = frozenset({"planner_public_key", "verifier_public_key", "database_now"})
_CAPABILITY_INTEGERS = frozenset({"witnessSequence", "fence", "deadlineMonotonicNs", "deadlineEpochNs",
    "issuedMonotonicNs", "issuedAtEpochNs", "expiresAtEpochNs"})
_CAPABILITY_NON_DIGESTS = frozenset({"schema", "operation", "handlerName", "planProtocol",
    "webauthnReceipt", "witnessReservation", "approverPolicyDigest", "witnessPredecessorHeadDigest"})


class RevocationCapabilityError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RevocationCapabilityMetrics:
    capture: QueryReadValidationMetrics
    transport: QueryReadValidationMetrics
    capability_authentication: QueryReadValidationMetrics
    witness_verification: QueryReadValidationMetrics
    retained_verification: QueryReadValidationMetrics
    bindings: QueryReadValidationMetrics
    record: QueryReadValidationMetrics
    capability_signature_attempts: int
    request_signature_attempts: int
    witness_signature_attempts: int
    total_hashes: int
    total_input_bytes: int
    total_json_nodes: int


@dataclass(frozen=True, slots=True)
class RevocationCapabilityObservation:
    envelope_bytes: bytes
    payload_bytes: bytes
    witness_request_bytes: bytes
    execution_request_bytes: bytes
    payload: dict
    retained_record: retention._RetainedRevocationRecord
    capability_digest: str
    witness_receipt_digest: str
    signer_key_digest: str
    witness_key_digest: str
    envelope_digest: str
    witness_request_bytes_digest: str
    header: dict
    record_digest: str
    metrics: RevocationCapabilityMetrics


def _wire(value, ledger, maximum=MAX_CAPABILITY_BYTES, nodes=MAX_JSON_NODES):
    return plan.retained._bounded_wire(value, ledger, maximum_bytes=maximum, maximum_nodes=nodes)


def _same(actual, expected, work, label):
    plan._same(actual, expected, work, label)


def _canonical(raw, value, ledger, maximum, nodes=MAX_JSON_NODES):
    encoded = _wire(value, ledger, maximum, nodes)
    ledger.work.charge(input_bytes=2 * len(raw))
    if encoded != raw:
        raise RevocationCapabilityError("revocation capability original bytes are not canonical")
    return encoded


def _digest(domain, value, ledger):
    return plan._frame(domain, (_wire(value, ledger),), ledger.work)


def _signature(key, encoded, domain, unsigned, ledger):
    """One real Ed25519 callback; no callback-owned budget or key enrollment."""
    work = ledger.work
    shape._base64url(encoded, signature=True)
    work.charge(input_bytes=4 * 88 + 64)
    signature = base64.b64decode(encoded + "==", altchars=b"-_", validate=True)
    message = plan._ascii(plan._frame(domain, (unsigned,), work), work)
    limits, metrics = work.limits, work.metrics
    values = (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
    try:
        key.verify(signature, message)
    finally:
        capture._SharedLedger(work)
        if (work.limits is not limits or work.metrics != metrics
                or (work.limits.max_hashes, work.limits.max_input_bytes, work.limits.max_json_nodes) != values):
            raise RevocationCapabilityError("revocation capability work changed during signature verification")


def _witness_shape(value, *, request):
    shape._object(value, WITNESS_REQUEST_FIELDS if request else WITNESS_RECEIPT_FIELDS, "witness")
    shape._literal(value["schema"], WITNESS_REQUEST_SCHEMA if request else WITNESS_RECEIPT_SCHEMA)
    shape._literal(value["phase"], "reserve")
    shape._literal(value["operation"], OPERATION)
    for field in ("parentEnvelopeId", "resultDigest", "predecessorReceiptDigest"):
        if value[field] is not None:
            raise RevocationCapabilityError("revocation preliminary witness predecessor is not absent")
    for field in ("deadlineMonotonicNs", "issuedAtEpochNs", "generationSequence"):
        shape._integer(value[field], minimum=1)
    digests = ("envelopeId", "requestDigest", "capabilityId", "generationDigest")
    for field in digests + (("configurationDigest", "operationManifestDigest") if request else
                           ("witnessIdentityDigest", "headDigest", "canonicalRequestDigest")):
        shape._digest(value[field])
    if not request:
        shape._integer(value["sequence"], minimum=1)
        shape._integer(value["fence"], minimum=1)
        if value["predecessorHeadDigest"] is not None:
            raise RevocationCapabilityError("revocation preliminary witness has a predecessor head")
        if value["logPredecessorHeadDigest"] is not None:
            shape._digest(value["logPredecessorHeadDigest"])
    shape._base64url(value["signature"], signature=True)


def _shape(envelope):
    shape._object(envelope, SIGNED_FIELDS, "signed capability")
    shape._literal(envelope["schema"], SIGNED_SCHEMA)
    shape._literal(envelope["sourceRevision"], authority.SOURCE_REVISION)
    shape.validate_identity_shape(envelope["signerIdentity"])
    shape._base64url(envelope["signatureBase64Url"], signature=True)
    value = envelope["payload"]
    shape._object(value, PAYLOAD_FIELDS, "capability")
    shape._literal(value["schema"], CAPABILITY_SCHEMA)
    shape._literal(value["operation"], OPERATION)
    shape._literal(value["handlerName"], authority.operation_spec(OPERATION)["handler"])
    shape._literal(value["planProtocol"], CAPABILITY_PROTOCOL)
    for field in _CAPABILITY_INTEGERS:
        shape._integer(value[field], minimum=1)
    for field in PAYLOAD_FIELDS - _CAPABILITY_INTEGERS - _CAPABILITY_NON_DIGESTS:
        shape._digest(value[field])
    if value["approverPolicyDigest"] is not None:
        shape._digest(value["approverPolicyDigest"])
    if value["witnessPredecessorHeadDigest"] is not None:
        raise RevocationCapabilityError("revocation preliminary capability has a predecessor head")
    receipt = value["webauthnReceipt"]
    shape._object(receipt, WEBAUTHN_RECEIPT_FIELDS, "WebAuthn receipt")
    shape._literal(receipt["schema"], WEBAUTHN_RECEIPT_SCHEMA)
    for field in ("challengeId", "credentialRecordId", "credentialId"):
        shape._text(receipt[field], maximum=4096)
    for field in WEBAUTHN_RECEIPT_FIELDS - {"schema", "challengeId", "credentialRecordId", "credentialId",
            "flags", "priorCounter", "counter", "userPresent", "userVerified", "verifiedAtEpochNs"}:
        shape._digest(receipt[field])
    shape._integer(receipt["flags"], maximum=255)
    shape._integer(receipt["priorCounter"], maximum=2_147_483_647)
    shape._integer(receipt["counter"], maximum=2_147_483_647, minimum=1)
    shape._integer(receipt["verifiedAtEpochNs"], minimum=1)
    if receipt["userPresent"] is not True or receipt["userVerified"] is not True:
        raise RevocationCapabilityError("revocation capability WebAuthn booleans are not exact")
    _witness_shape(value["witnessReservation"], request=False)


def _witness(request, receipt, owned, signer_key, witness_key, ledger):
    work, historical = ledger.work, owned["retention"]
    _witness_shape(request, request=True)
    for field, expected in (
        ("configurationDigest", owned["expectedConfigurationDigest"]),
        ("operationManifestDigest", authority.OPERATION_MANIFEST_DIGEST),
        ("generationSequence", owned["expectedGenerationSequence"]),
        ("generationDigest", owned["expectedGenerationDigest"]),
        ("capabilityId", historical["expected_capability_id"]),
        ("requestDigest", historical["expected_request"]["requestDigest"]),
        ("deadlineMonotonicNs", historical["deadline_monotonic_ns"]),
    ):
        _same(request[field], expected, work, "revocation preliminary witness request binding changed")
    material = {field: request[field] for field in ("phase", "operation", "requestDigest", "capabilityId",
        "resultDigest", "predecessorReceiptDigest", "generationSequence", "generationDigest")}
    _same(request["envelopeId"], _digest(WITNESS_ENVELOPE_SCHEMA, material, ledger), work,
          "revocation witness envelope identity changed")
    work.prepare_copy(request)
    unsigned_request = request.copy()
    unsigned_request.pop("signature")
    _signature(signer_key, request["signature"], WITNESS_REQUEST_SCHEMA,
               _wire(unsigned_request, ledger, MAX_WITNESS_REQUEST_BYTES), ledger)
    for field in ("envelopeId", "parentEnvelopeId", "phase", "operation", "requestDigest", "capabilityId",
                  "resultDigest", "predecessorReceiptDigest", "deadlineMonotonicNs",
                  "generationSequence", "generationDigest"):
        _same(receipt[field], request[field], work, "revocation witness receipt request binding changed")
    for actual, expected in (
        (receipt["witnessIdentityDigest"], owned["expectedWitnessIdentityDigest"]),
        (receipt["fence"], historical["expected_fence"]),
        (receipt["canonicalRequestDigest"], _digest(WITNESS_REQUEST_SCHEMA, request, ledger)),
    ):
        _same(actual, expected, work, "revocation witness receipt independent binding changed")
    reserved, now, skew = (historical["reserved_at_epoch_ns"], historical["now_epoch_ns"],
                           historical["maximum_clock_skew_ns"])
    for value in (request["issuedAtEpochNs"], receipt["issuedAtEpochNs"]):
        if value < reserved - skew or value > now + skew:
            raise RevocationCapabilityError("revocation witness historical issue time is inconsistent")
    if receipt["issuedAtEpochNs"] < request["issuedAtEpochNs"] - skew:
        raise RevocationCapabilityError("revocation witness receipt precedes its request")
    work.prepare_copy(receipt)
    unsigned_receipt = receipt.copy()
    unsigned_receipt.pop("signature")
    work.prepare_copy(unsigned_receipt)
    head = unsigned_receipt.copy()
    head["headDigest"] = None
    _same(receipt["headDigest"], _digest(WITNESS_HEAD_SCHEMA, head, ledger), work,
          "revocation witness head commitment changed")
    _signature(witness_key, receipt["signature"], WITNESS_RECEIPT_SCHEMA,
               _wire(unsigned_receipt, ledger), ledger)
    digest = _digest(WITNESS_RECEIPT_SCHEMA, receipt, ledger)
    _same(digest, owned["expectedWitnessReceiptDigest"], work,
          "revocation witness is not the independently accepted preliminary receipt")
    return digest


def _old_row(record, table, identifier, work):
    mutations = record.payload["mutationPlan"]
    work.prepare_scan(mutations)
    work.prepare_scan(identifier)
    found = None
    for mutation in mutations:
        if mutation["table"] == table and mutation["key"] == {"id": identifier}:
            if found is not None or type(mutation["expectedRow"]) is not dict:
                raise RevocationCapabilityError("revocation capability original row is ambiguous or absent")
            found = mutation["expectedRow"]
    if found is None:
        raise RevocationCapabilityError("revocation capability lacks its proved original row")
    return found


def _credential_binding(value, ledger):
    # Preserve the actual service receipt recipe. Unlike all NUL-domain
    # digests here, this legacy field length-prefixes the DOMAIN itself.
    domain = "catchplate.policyAuthorityWebAuthnCredentialBinding/v1"
    raw = _wire(value, ledger)
    ledger.work.prepare_utf8(domain)
    encoded = domain.encode("ascii")
    ledger.work.charge(hashes=1, input_bytes=16 + len(raw))
    digest = hashlib.sha256()
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)
    digest.update(len(raw).to_bytes(8, "big"))
    digest.update(raw)
    return "sha256:" + digest.hexdigest()


def _receipt(record, ledger):
    evidence, work = record.payload["webauthnEvidence"], ledger.work
    challenge_row = _old_row(record, "webauthn_challenges", evidence["challengeId"], work)
    credential_row = _old_row(record, "webauthn_credentials", evidence["credentialRecordId"], work)
    # Fixed source-field scaffolding aliases only already-owned immutable
    # scalars. The actual scans, wire encodings and hashes are charged below.
    challenge = {field: challenge_row[field] for field in _CHALLENGE_FIELDS}
    credential = {field: credential_row[field] for field in _CREDENTIAL_FIELDS}
    return {"schema": WEBAUTHN_RECEIPT_SCHEMA,
        **{field: evidence[field] for field in _RECEIPT_EVIDENCE_FIELDS},
        "challengeRowDigest": _digest("catchplate.policyAuthorityWebAuthnChallengeRow/v1", challenge, ledger),
        "credentialBindingDigest": _credential_binding(credential, ledger)}


def _capture_expectations(ledger, retention_expectations, *, expected_signer_identity,
        expected_issuer_session_identity_digest, expected_execution_envelope_id,
        expected_witness_receipt_digest, expected_witness_identity_digest,
        expected_configuration_digest, expected_generation_sequence, expected_generation_digest):
    """The actual shared external-input capture; it creates no work allowance."""
    owned = capture._JSONCapture(ledger).visit({
        "retention": {field: retention_expectations[field] for field in wire._EXPECTATIONS - _HANDLE_FIELDS},
        "expectedSignerIdentity": expected_signer_identity,
        "expectedIssuerSessionIdentityDigest": expected_issuer_session_identity_digest,
        "expectedExecutionEnvelopeId": expected_execution_envelope_id,
        "expectedWitnessReceiptDigest": expected_witness_receipt_digest,
        "expectedWitnessIdentityDigest": expected_witness_identity_digest,
        "expectedConfigurationDigest": expected_configuration_digest,
        "expectedGenerationSequence": expected_generation_sequence,
        "expectedGenerationDigest": expected_generation_digest,
    }, depth=-1)
    shape.validate_identity_shape(owned["expectedSignerIdentity"])
    for name in ("expectedIssuerSessionIdentityDigest", "expectedExecutionEnvelopeId",
            "expectedWitnessReceiptDigest", "expectedWitnessIdentityDigest",
            "expectedConfigurationDigest", "expectedGenerationDigest"):
        shape._digest(owned[name])
    shape._integer(owned["expectedGenerationSequence"], minimum=1)
    historical = owned["retention"]
    for name in ("expected_fence", "reserved_at_epoch_ns", "deadline_epoch_ns", "deadline_monotonic_ns",
            "now_epoch_ns", "now_monotonic_ns", "maximum_assertion_age_ns", "maximum_plan_age_ns"):
        shape._integer(historical[name], minimum=1)
    shape._integer(historical["maximum_clock_skew_ns"])
    shape._digest(historical["expected_capability_id"])
    shape._digest(historical["expected_planner_transaction_id"])
    return owned


def _expected_payload(record, execution, execution_request_bytes, witness_receipt,
        witness_digest, owned, ledger):
    """Bind the exact wrapper and derive the one source-owned 36-field recipe.

    Only this invocation's genuine raw replay calls this helper. Its result is
    a graph, not an admission token; consumers still authenticate original bytes.
    """
    work, historical = ledger.work, owned["retention"]
    measured, actual = record.payload["measuredPlan"], record.payload
    expected_execution = {"schema": EXECUTION_REQUEST_SCHEMA, "planProtocol": CAPABILITY_PROTOCOL,
        "retainedRecordDigest": record.record_digest, "rootTransitionDigest": measured["rootTransitionDigest"],
        "typedRequest": actual["typedRequest"]}
    _same(execution, expected_execution, work, "revocation capability exact execution wrapper changed")
    exact_request_digest = retention._bytes_digest(execution_request_bytes, work)
    receipt = _receipt(record, ledger)
    return {
        "schema": CAPABILITY_SCHEMA, "capabilityId": measured["capabilityId"],
        "envelopeId": owned["expectedExecutionEnvelopeId"],
        "plannerTransactionId": measured["plannerTransactionId"],
        "authorizationProjectionDigest": measured["authorizationProjectionDigest"],
        "selectedBusinessRowsDigest": measured["selectedBusinessRowsDigest"],
        "mutationPlanDigest": measured["mutationPlanDigest"], "expectedResultDigest": actual["expectedResultDigest"],
        "operation": OPERATION, "operationId": measured["operationId"],
        "handlerName": authority.operation_spec(OPERATION)["handler"], "requestDigest": measured["requestDigest"],
        "operationManifestDigest": measured["operationManifestDigest"], "queryManifestDigest": measured["queryManifestDigest"],
        "authorityRootSetDigest": measured["authorityRootSetBeforeDigest"],
        "authoritySnapshotDigest": measured["authoritySnapshotDigest"],
        "approverPolicyDigest": actual["authorizationProjection"]["approverPolicyDigest"],
        "webauthnReceipt": receipt, "webauthnReceiptDigest": _digest(WEBAUTHN_RECEIPT_SCHEMA, receipt, ledger),
        "webauthnTrustHighWaterDigest": actual["webauthnEvidence"]["trustHighWaterDigest"],
        "witnessReservation": witness_receipt, "witnessReservationDigest": witness_digest,
        "witnessSequence": witness_receipt["sequence"], "witnessHeadDigest": witness_receipt["headDigest"],
        "witnessPredecessorHeadDigest": None,
        "deadlineMonotonicNs": measured["deadlineMonotonicNs"], "deadlineEpochNs": measured["deadlineEpochNs"],
        "fence": measured["fence"], "issuedAtEpochNs": historical["reserved_at_epoch_ns"],
        "issuedMonotonicNs": historical["deadline_monotonic_ns"] - (
            historical["deadline_epoch_ns"] - historical["reserved_at_epoch_ns"]),
        "expiresAtEpochNs": measured["deadlineEpochNs"],
        "issuerSessionIdentityDigest": owned["expectedIssuerSessionIdentityDigest"],
        "planProtocol": CAPABILITY_PROTOCOL, "retainedRecordDigest": record.record_digest,
        "rootTransitionDigest": measured["rootTransitionDigest"], "exactRequestBytesDigest": exact_request_digest,
    }


def _verify_signed_capability_on_work(*, work: _ValidationWork, envelope_bytes: bytes,
        retained_envelope_bytes: bytes, evaluation_context_bytes: bytes, execution_request_bytes: bytes,
        witness_request_bytes: bytes, signer_public_key: Ed25519PublicKey,
        witness_public_key: Ed25519PublicKey, expected_signer_identity,
        expected_issuer_session_identity_digest: str, expected_execution_envelope_id: str,
        expected_witness_receipt_digest: str, expected_witness_identity_digest: str,
        expected_configuration_digest: str, expected_generation_sequence: int,
        expected_generation_digest: str, retention_expectations: dict) -> RevocationCapabilityObservation:
    """Verify original transports, three signatures and one genuine retained plan.

    One independently admitted signer key authenticates the capability and
    preliminary witness request; it is not inferred from the assertion key.
    Original times/roots/request are external historical expectations, not
    sampled current authority. Every failure aborts the invocation without a
    counter refund. Fixed field/tuple scaffolding and native cryptographic
    internals are excluded from canonical H/B/N units; signature attempts are
    separate. This function cannot establish storage/retry identity by itself.
    """
    try:
        ledger = capture._SharedLedger(work)
        if not isinstance(signer_public_key, Ed25519PublicKey) or not isinstance(witness_public_key, Ed25519PublicKey):
            raise RevocationCapabilityError("revocation capability keys are not Ed25519 public keys")
        shape._object(retention_expectations, wire._EXPECTATIONS, "retention expectations")
        handles = {field: retention_expectations[field] for field in _HANDLE_FIELDS}
        plan._verification_types(**handles)
        for raw, maximum in ((envelope_bytes, MAX_CAPABILITY_BYTES),
                (witness_request_bytes, MAX_WITNESS_REQUEST_BYTES),
                (execution_request_bytes, authority.MAX_REQUEST_BYTES),
                (retained_envelope_bytes, shape.MAX_PAYLOAD_BYTES),
                (evaluation_context_bytes, retention.MAX_CONTEXT_BYTES)):
            if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
                raise RevocationCapabilityError("revocation capability original transport is not exact and bounded")
        before = work.metrics
        owned = _capture_expectations(ledger, retention_expectations,
            expected_signer_identity=expected_signer_identity,
            expected_issuer_session_identity_digest=expected_issuer_session_identity_digest,
            expected_execution_envelope_id=expected_execution_envelope_id,
            expected_witness_receipt_digest=expected_witness_receipt_digest,
            expected_witness_identity_digest=expected_witness_identity_digest,
            expected_configuration_digest=expected_configuration_digest,
            expected_generation_sequence=expected_generation_sequence,
            expected_generation_digest=expected_generation_digest)
        captured = plan.mixed._delta(before, work.metrics)
        # Validate all historical scalar types before arithmetic or callbacks;
        # the actual retained worker repeats the complete admission itself.
        historical = owned["retention"]
        before = work.metrics
        envelope = wire._decode_object(envelope_bytes, work=work, maximum_bytes=MAX_CAPABILITY_BYTES,
            maximum_nodes=MAX_JSON_NODES, maximum_depth=MAX_JSON_DEPTH)
        request = wire._decode_object(witness_request_bytes, work=work, maximum_bytes=MAX_WITNESS_REQUEST_BYTES,
            maximum_nodes=MAX_JSON_NODES, maximum_depth=MAX_JSON_DEPTH)
        execution = wire._decode_object(execution_request_bytes, work=work, maximum_bytes=authority.MAX_REQUEST_BYTES)
        _shape(envelope)
        _canonical(envelope_bytes, envelope, ledger, MAX_CAPABILITY_BYTES)
        _canonical(witness_request_bytes, request, ledger, MAX_WITNESS_REQUEST_BYTES)
        _canonical(execution_request_bytes, execution, ledger, authority.MAX_REQUEST_BYTES, shape.MAX_JSON_NODES)
        payload = envelope["payload"]
        payload_bytes = _wire(payload, ledger)
        transported = plan.mixed._delta(before, work.metrics)
        before = work.metrics
        _same(envelope["signerIdentity"], owned["expectedSignerIdentity"], work,
              "revocation capability signer identity changed")
        work.prepare_copy(envelope)
        unsigned = envelope.copy()
        unsigned.pop("signatureBase64Url")
        _signature(signer_public_key, envelope["signatureBase64Url"], SIGNED_SCHEMA, _wire(unsigned, ledger), ledger)
        authenticated = plan.mixed._delta(before, work.metrics)
        before = work.metrics
        witness_digest = _witness(request, payload["witnessReservation"], owned,
                                  signer_public_key, witness_public_key, ledger)
        witnessed = plan.mixed._delta(before, work.metrics)
        before = work.metrics
        record = retention._verify_record_on_work(envelope_bytes=retained_envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes, work=work, **historical, **handles)
        replayed = plan.mixed._delta(before, work.metrics)
        before = work.metrics
        expected = _expected_payload(record, execution, execution_request_bytes,
            payload["witnessReservation"], witness_digest, owned, ledger)
        _same(payload, expected, work, "revocation capability differs from genuine retained plan bindings")
        bound = plan.mixed._delta(before, work.metrics)
        before = work.metrics
        capability_digest = plan._frame(CAPABILITY_SCHEMA, (payload_bytes,), work)
        signer_digest = retention._key_digest(signer_public_key, work)
        witness_key_digest = retention._key_digest(witness_public_key, work)
        envelope_digest = retention._bytes_digest(envelope_bytes, work)
        request_bytes_digest = retention._bytes_digest(witness_request_bytes, work)
        header = {"schema": RECORD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "capabilityProtocol": CAPABILITY_PROTOCOL, "capabilityId": payload["capabilityId"],
            "plannerTransactionId": payload["plannerTransactionId"], "executionEnvelopeId": payload["envelopeId"],
            "retainedRecordDigest": record.record_digest, "rootTransitionDigest": payload["rootTransitionDigest"],
            "authoritySnapshotDigest": payload["authoritySnapshotDigest"], "exactRequestBytesDigest": expected["exactRequestBytesDigest"],
            "capabilityDigest": capability_digest, "signerKeyDigest": signer_digest, "witnessKeyDigest": witness_key_digest,
            "envelopeDigest": envelope_digest, "envelopeByteCount": len(envelope_bytes),
            "witnessRequestBytesDigest": request_bytes_digest, "witnessRequestByteCount": len(witness_request_bytes)}
        record_digest = _digest(RECORD_SCHEMA, header, ledger)
        recorded = plan.mixed._delta(before, work.metrics)
        capture._SharedLedger(work)
        return RevocationCapabilityObservation(envelope_bytes, payload_bytes, witness_request_bytes,
            execution_request_bytes, payload, record, capability_digest, witness_digest, signer_digest,
            witness_key_digest, envelope_digest, request_bytes_digest, header, record_digest,
            RevocationCapabilityMetrics(captured, transported, authenticated, witnessed, replayed, bound,
                recorded, 1, 1, 1, work.hash_work, work.input_bytes, work.json_nodes))
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, RevocationCapabilityError):
            raise
        raise RevocationCapabilityError("signed revocation capability verification failed") from exc
