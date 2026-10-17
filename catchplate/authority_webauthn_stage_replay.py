"""Original trust-stage inputs and genuine semantic/query replay.

The retained codec preserves the complete signed assertion, original candidate
bundle and original candidate verification context. Stored key DER, schema and
time do not establish independent key enrollment, request/root authority or a
successful prior verification. Replay independently binds those originals and
repeats real candidate and assertion verification before deriving stage effects.

Actual source queries, query-record associations, aggregate semantics and audit
capacity are recomputed on the caller's original work. This module does not
prove primary membership, counted completeness or changed roots; those remain
mandatory enclosing proof phases. There is no SQL, clock sample, signing,
installation, registry activation, retry or replacement work allowance.
"""
from __future__ import annotations

from catchplate import authority_audit_capacity as capacity
from catchplate import authority_query_reads as reads
from catchplate import authority_request_commitment as commitment
from catchplate import authority_revocation_semantics as semantics
from catchplate import authority_transition_webauthn as support
from catchplate import authority_transition_webauthn_registration as registration
from catchplate import authority_transition_webauthn_trust_stage as stage
from catchplate import authority_webauthn_assertion as assertion
from catchplate import authority_webauthn_transition_inputs as shared
from catchplate import authority_webauthn_trust_candidate as candidate


wire, evidence, authority, core = shared.wire, shared.evidence, shared.authority, shared.core
OPERATION = stage.OPERATION
_FIELDS = frozenset({"assertionEvidence", "candidateBundle", "candidateVerificationContext"})
_CONTEXT_FIELDS = frozenset({"publicKeyDer", "schema", "verifiedAtEpochUs"})
_RAW_FIELDS = frozenset({"base64Url", "byteCount"})
_TRANSITION_FIELDS = frozenset({"mutations", "result", "kernelWorkUnits", "workUnits"})
_shape = evidence.plan.contract


class WebAuthnStageReplayError(ValueError):
    pass


def _raw_shape(value, maximum):
    _shape._object(value, _RAW_FIELDS, "retained stage original")
    _shape._integer(value["byteCount"], maximum, minimum=1)
    if (type(value["base64Url"]) is not str
            or len(value["base64Url"]) != (4 * value["byteCount"] + 2) // 3):
        raise WebAuthnStageReplayError("retained stage original has an invalid encoded length")


def _inputs_shape(inputs, work):
    _shape._object(inputs, _FIELDS, "retained trust-stage inputs")
    _shape._object(inputs["assertionEvidence"], assertion.EVIDENCE_FIELDS, "retained stage assertion")
    assertion_size, _ = work.measure(inputs["assertionEvidence"])
    if assertion_size > authority.MAX_REQUEST_BYTES:
        raise WebAuthnStageReplayError("retained stage assertion exceeds its source bound")
    _raw_shape(inputs["candidateBundle"], candidate.bundle_core.MAX_INPUT_BYTES)
    context = inputs["candidateVerificationContext"]
    _shape._object(context, _CONTEXT_FIELDS, "retained candidate verification context")
    _raw_shape(context["publicKeyDer"], candidate.bundle_core.MAX_PUBLIC_KEY_BYTES)
    _raw_shape(context["schema"], candidate.bundle_core.MAX_SCHEMA_BYTES)
    instant = wire._from_epoch_us(context["verifiedAtEpochUs"])
    if registration._now(instant) != context["verifiedAtEpochUs"] * 1000:
        raise WebAuthnStageReplayError("retained candidate time lost its original precision")
    return instant


def _encode_inputs_on_work(*, assertion_evidence, candidate_bundle_bytes,
        candidate_verification_context, work):
    evidence.capture._SharedLedger(work)
    if type(candidate_verification_context) is not candidate.bundle_core.TrustVerificationContext:
        raise WebAuthnStageReplayError("stage retention requires the actual candidate context type")
    # Snapshot members before any codec or native callback. Even a frozen
    # caller dataclass is not re-read after these immutable members are held.
    public_der = candidate_verification_context.public_key_der
    schema_bytes = candidate_verification_context.schema_bytes
    verified_at = candidate_verification_context.verified_at
    originals = (candidate_bundle_bytes, public_der, schema_bytes)
    maxima = (candidate.bundle_core.MAX_INPUT_BYTES, candidate.bundle_core.MAX_PUBLIC_KEY_BYTES,
        candidate.bundle_core.MAX_SCHEMA_BYTES)
    for raw, maximum in zip(originals, maxima):
        if type(raw) is not bytes or not 1 <= len(raw) <= maximum:
            raise WebAuthnStageReplayError("stage retention requires bounded immutable originals")
    verified_ns, verified_us = registration._now(verified_at), wire._to_epoch_us(verified_at)
    if verified_ns != verified_us * 1000:
        raise WebAuthnStageReplayError("candidate verification instant did not round-trip")
    owned_assertion = wire._capture(assertion_evidence, work)
    _shape._object(owned_assertion, assertion.EVIDENCE_FIELDS, "original signed stage assertion")
    size, _ = work.measure(owned_assertion)
    if size > authority.MAX_REQUEST_BYTES:
        raise WebAuthnStageReplayError("original stage assertion exceeds its source bound")
    bundle, key, schema = tuple(wire._pack_raw(raw, minimum=1, maximum=maximum, work=work)
        for raw, maximum in zip(originals, maxima))
    inputs = {"assertionEvidence": owned_assertion, "candidateBundle": bundle,
        "candidateVerificationContext": {"publicKeyDer": key, "schema": schema,
            "verifiedAtEpochUs": verified_us}}
    _inputs_shape(inputs, work)
    return shared._encode_on_work(OPERATION, inputs, work)


def _replay_on_work(*, request, selected_rows, database_now, query_reads, inputs_bytes,
        expected_inputs_digest, expected_transition, verifier_public_key, verifier_identity,
        capability_id, expected_candidate_signing_key_id, development_enabled,
        require_approval, require_approver_webauthn, now_epoch_ns, deadline_epoch_ns,
        maximum_age_ns, maximum_clock_skew_ns, work):
    evidence.capture._SharedLedger(work)
    spec = authority.operation_spec(OPERATION)
    public_key = verifier_public_key
    cutoff_ns = registration._now(database_now)
    cutoff_us = wire._to_epoch_us(database_now)
    wire._raw(inputs_bytes, 2, wire.MAX_BYTES)
    original = inputs_bytes
    if (type(selected_rows) is not tuple or len(selected_rows) > spec["maximumQueryRows"]
            or any(type(row) is not dict for row in selected_rows)
            or type(query_reads) is not tuple or len(query_reads) > spec["maximumQueryRows"]
            or not isinstance(public_key, evidence.keys.Ed25519PublicKey)
            or any(type(value) is not bool for value in
                (development_enabled, require_approval, require_approver_webauthn))):
        raise WebAuthnStageReplayError("stage replay inputs differ from their exact source types")
    work.prepare_copy(selected_rows)
    owned = wire._capture({"request": request, "selected": list(selected_rows),
        "expectedInputsDigest": expected_inputs_digest, "expectedTransition": expected_transition,
        "verifierIdentity": verifier_identity, "capabilityId": capability_id,
        "candidateSigningKeyId": expected_candidate_signing_key_id,
        "developmentEnabled": development_enabled, "requireApproval": require_approval,
        "requireApproverWebauthn": require_approver_webauthn,
        "nowEpochNs": now_epoch_ns, "deadlineEpochNs": deadline_epoch_ns,
        "maximumAgeNs": maximum_age_ns, "maximumClockSkewNs": maximum_clock_skew_ns}, work)
    records = tuple(reads._copy_read(record, work) for record in query_reads)
    for field in ("expectedInputsDigest", "capabilityId", "candidateSigningKeyId"):
        _shape._digest(owned[field])
    evidence._identity(owned["verifierIdentity"])
    for field in ("nowEpochNs", "deadlineEpochNs"):
        _shape._integer(owned[field], minimum=1)
    _shape._integer(owned["maximumAgeNs"], authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    _shape._integer(owned["maximumClockSkewNs"], authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    if owned["nowEpochNs"] >= owned["deadlineEpochNs"]:
        raise WebAuthnStageReplayError("stage replay historical invocation has expired")
    expected = owned["expectedTransition"]
    _shape._object(expected, _TRANSITION_FIELDS, "expected trust-stage transition")
    _shape._array(expected["mutations"], spec["maximumMutations"], "expected trust-stage mutations")
    _shape._integer(expected["kernelWorkUnits"], spec["maximumBusinessWorkUnits"], minimum=1)
    _shape._integer(expected["workUnits"], spec["maximumWorkUnits"], minimum=1)
    actual_request = owned["request"]
    if (type(actual_request) is not dict or actual_request.get("operation") != OPERATION
            or actual_request.get("handler") != "stage_webauthn_trust_publication"
            or type(actual_request.get("arguments")) is not dict):
        raise WebAuthnStageReplayError("stage replay request is not the fixed source operation")
    inputs = shared._decode_on_work(OPERATION, original, owned["expectedInputsDigest"], work)
    verified_at = _inputs_shape(inputs, work)
    if registration._now(verified_at) != owned["nowEpochNs"]:
        raise WebAuthnStageReplayError("candidate verification instant differs from independent history")
    candidate_context = inputs["candidateVerificationContext"]
    candidate_raw = wire._unpack_raw(inputs["candidateBundle"], minimum=1,
        maximum=candidate.bundle_core.MAX_INPUT_BYTES, work=work)
    public_der = wire._unpack_raw(candidate_context["publicKeyDer"], minimum=1,
        maximum=candidate.bundle_core.MAX_PUBLIC_KEY_BYTES, work=work)
    schema_bytes = wire._unpack_raw(candidate_context["schema"], minimum=1,
        maximum=candidate.bundle_core.MAX_SCHEMA_BYTES, work=work)
    stage._same(candidate.bundle_core.sha256_prefixed(public_der, _work=work),
        owned["candidateSigningKeyId"], work, "candidate DER differs from the independent key pin")
    context = candidate.bundle_core.TrustVerificationContext(public_der, schema_bytes, verified_at, _work=work)
    arguments, candidate_roots = candidate._admit_on_work(arguments=actual_request["arguments"],
        bundle_bytes=candidate_raw, verification_context=context,
        expected_signing_key_id=owned["candidateSigningKeyId"], work=work)
    semantics._canonical_equal(arguments, actual_request["arguments"], work=work,
        label="candidate replay changed the held request arguments")
    actual_request["arguments"] = arguments
    digest = commitment._typed_request_digest(actual_request, work=work)
    if commitment._request_different(digest, actual_request.get("requestDigest"), work=work):
        raise WebAuthnStageReplayError("stage replay request commitment changed")
    work.prepare_utf8(OPERATION)
    work.prepare_utf8(digest)
    work.charge(hashes=1)
    operation_id = commitment.operation_id(OPERATION, digest)
    if commitment._request_different(operation_id, actual_request.get("operationId"), work=work):
        raise WebAuthnStageReplayError("stage replay operation commitment changed")
    verified = assertion._verify_stage_assertion_evidence(inputs["assertionEvidence"],
        operation_id=operation_id, request_digest=digest, capability_id=owned["capabilityId"],
        verifier_identity=owned["verifierIdentity"], verifier_public_key=public_key,
        now_epoch_ns=owned["nowEpochNs"], deadline_epoch_ns=owned["deadlineEpochNs"],
        maximum_age_ns=owned["maximumAgeNs"], work=assertion._ReceiptWork(work))
    work.prepare_copy(inputs["assertionEvidence"])
    verified = dict(verified)
    if (abs(cutoff_ns - owned["nowEpochNs"]) > owned["maximumClockSkewNs"]
            or not verified["verifiedAtEpochNs"] <= cutoff_ns < verified["expiresAtEpochNs"]
            or cutoff_ns >= owned["deadlineEpochNs"]):
        raise WebAuthnStageReplayError("stage replay cutoff differs from admitted assertion and historical time")
    cutoff = wire._from_epoch_us(cutoff_us)
    candidate._require_valid_at_on_work(arguments=arguments, verified_at=cutoff, work=work)
    queries = stage._query_recipe_on_work(arguments=arguments, database_now=cutoff,
        request_digest=digest, verified_webauthn_evidence=verified, work=work)
    support._prepare_complete_copies(queries, work)
    support._prepare_complete_copies(queries, work)
    queries = capacity.add_capacity_query(OPERATION, queries)
    work.prepare_copy(owned["selected"])
    selected = tuple(owned["selected"])
    queries, records = reads._validate_query_reads(OPERATION, queries=queries,
        query_reads=records, selected_rows=selected, work=work)
    kernel_context = core.KernelContext(OPERATION, arguments, selected, cutoff, digest,
        verified, query_reads=records)
    kernel = stage._kernel_transition_on_work(kernel_context, candidate_roots=candidate_roots,
        development_enabled=owned["developmentEnabled"], require_approval=owned["requireApproval"],
        require_approver_webauthn=owned["requireApproverWebauthn"], work=work)
    finalized = capacity._finalize_capacity(kernel_context, kernel.mutations, work=work)
    total = capacity.transition_work_units(operation=OPERATION,
        query_work_units=sum(query.work_units for query in queries),
        kernel_work_units=kernel.work_units, mutations=finalized)
    capacity.validate_transition_work_units(OPERATION, total, finalized)
    mutations = semantics._ordered_mutations(finalized, work=work)
    observation = shared._ReplayObservation(kernel, mutations, total, queries)
    shared._compare_transition(observation, expected, OPERATION, work)
    return observation
