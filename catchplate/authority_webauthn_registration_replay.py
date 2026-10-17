"""Registration query and semantic replay from original successor inputs.

The typed request already contains the original signed attestation envelope;
the separate input record is therefore an exact empty object, not a claims or
successful-verification carrier. The real registration kernel re-verifies that
original statement and consumes the exact selected v2 evidence custody row.
It does not repeat the earlier native attestation ceremony parser.

The owning verifier must independently authenticate selected primary rows,
complete counted populations, current or historical root/cutoff provenance,
request authority and the configured evidence key/identity/RP policy. Query
association checks below do not supply membership or predicate completeness.
This component regenerates the real query program, kernel and common capacity
transition, then compares the complete expected transition on the same work.
No SQL, signature production, clock, proof token, protocol relabeling, registry
change or replacement work allowance is introduced.
"""
from __future__ import annotations

from catchplate import authority_audit_capacity as capacity
from catchplate import authority_query_reads as reads
from catchplate import authority_request_commitment as commitment
from catchplate import authority_transition_webauthn_registration as registration
from catchplate import authority_webauthn_transition_inputs as inputs


OPERATION = registration.OPERATION
evidence, authority, core = inputs.evidence, inputs.authority, inputs.core


class WebAuthnRegistrationReplayError(ValueError):
    pass


def _encode_inputs_on_work(*, work):
    """Encode the fixed empty original-input record for this operation."""
    return inputs._encode_on_work(OPERATION, {}, work)


def _replay_on_work(*, request, selected_rows, database_now, query_reads,
        inputs_bytes, expected_inputs_digest, expected_transition,
        evidence_public_key, expected_signer_identity, expected_signer_spki_digest,
        expected_rp_id, expected_origin, now_epoch_ns, deadline_epoch_ns,
        maximum_age_ns, maximum_clock_skew_ns, work):
    """Recompute actual semantics; primary and counted proofs remain external."""
    evidence.capture._SharedLedger(work)
    spec = authority.operation_spec(OPERATION)
    if (type(request) is not dict or type(selected_rows) is not tuple
            or len(selected_rows) > spec["maximumQueryRows"]
            or any(type(row) is not dict for row in selected_rows)
            or type(query_reads) is not tuple or len(query_reads) > spec["maximumQueryRows"]
            or not isinstance(evidence_public_key, evidence.keys.Ed25519PublicKey)):
        raise WebAuthnRegistrationReplayError("registration replay inputs are not exact source-bounded values")
    inputs.wire._raw(inputs_bytes, 2, inputs.wire.MAX_BYTES)
    original = inputs_bytes
    cutoff_ns = registration._now(database_now)
    cutoff = database_now
    public_key = evidence_public_key
    owned = reads._CopyBudget(work).copy({"request": request, "selected": selected_rows,
        "expectedInputsDigest": expected_inputs_digest, "expectedTransition": expected_transition,
        "signerIdentity": expected_signer_identity, "signerSpkiDigest": expected_signer_spki_digest,
        "rpId": expected_rp_id, "origin": expected_origin, "nowEpochNs": now_epoch_ns,
        "deadlineEpochNs": deadline_epoch_ns, "maximumAgeNs": maximum_age_ns,
        "maximumClockSkewNs": maximum_clock_skew_ns})
    # Real record constructors copy every address and retain only exact bytes
    # and scalars. No caller record or graph is reread after native callbacks.
    records = tuple(reads._copy_read(record, work) for record in query_reads)
    shape = evidence.plan.contract
    shape._digest(owned["expectedInputsDigest"])
    shape._digest(owned["signerSpkiDigest"])
    evidence._identity(owned["signerIdentity"])
    for name in ("nowEpochNs", "deadlineEpochNs"):
        shape._integer(owned[name], minimum=1)
    shape._integer(owned["maximumAgeNs"], authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(owned["maximumClockSkewNs"], authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    registration._text(owned["rpId"], "independent RP ID", 4096, work)
    registration._text(owned["origin"], "independent origin", 8192, work)
    if (owned["nowEpochNs"] >= owned["deadlineEpochNs"]
            or cutoff_ns >= owned["deadlineEpochNs"]
            or abs(cutoff_ns - owned["nowEpochNs"]) > owned["maximumClockSkewNs"]):
        raise WebAuthnRegistrationReplayError("registration replay cutoff differs from admitted time/deadline")
    actual = owned["request"]
    if (actual.get("operation") != OPERATION
            or actual.get("handler") != spec["handler"]):
        raise WebAuthnRegistrationReplayError("registration replay request has the wrong fixed operation")
    registration._arguments(actual.get("arguments"), work)
    request_digest = commitment._typed_request_digest(actual, work=work)
    if commitment._request_different(request_digest, actual.get("requestDigest"), work=work):
        raise WebAuthnRegistrationReplayError("registration replay request commitment changed")
    work.prepare_utf8(OPERATION)
    work.prepare_utf8(request_digest)
    work.charge(hashes=1)
    if commitment._request_different(commitment.operation_id(OPERATION, request_digest),
            actual.get("operationId"), work=work):
        raise WebAuthnRegistrationReplayError("registration replay operation commitment changed")
    decoded = inputs._decode_on_work(OPERATION, original, owned["expectedInputsDigest"], work)
    shape._object(decoded, frozenset(), "registration original inputs")
    evidence.keys._public_binding(public_key, owned["signerSpkiDigest"], work)
    queries = registration._query_recipe_on_work(arguments=actual["arguments"],
        database_now=cutoff, request_digest=request_digest, work=work)
    # Match actual acquisition's two complete-declaration copies inside the
    # common capacity constructor/closure, with no unmetered substitute query.
    registration.support._prepare_complete_copies(queries, work)
    registration.support._prepare_complete_copies(queries, work)
    queries = capacity.add_capacity_query(OPERATION, queries)
    queries, records = reads._validate_query_reads(OPERATION, queries=queries,
        query_reads=records, selected_rows=owned["selected"], work=work)
    context = core.KernelContext(OPERATION, actual["arguments"], owned["selected"],
        cutoff, request_digest, query_reads=records)
    kernel = registration._kernel_transition_on_work(context, evidence_public_key=public_key,
        expected_signer_identity=owned["signerIdentity"],
        expected_signer_spki_digest=owned["signerSpkiDigest"], expected_rp_id=owned["rpId"],
        expected_origin=owned["origin"], maximum_age_ns=owned["maximumAgeNs"],
        maximum_clock_skew_ns=owned["maximumClockSkewNs"], work=work)
    finalized = capacity._finalize_capacity(context, kernel.mutations, work=work)
    work_units = capacity.transition_work_units(operation=OPERATION,
        query_work_units=sum(query.work_units for query in queries),
        kernel_work_units=kernel.work_units, mutations=finalized)
    capacity.validate_transition_work_units(OPERATION, work_units, finalized)
    work.prepare_copy(finalized)
    ordered = sorted(finalized, key=lambda item: (item["table"], item["keyDigest"], item["operation"]))
    work.prepare_copy(ordered)
    mutations = tuple(ordered)
    observed = inputs._ReplayObservation(kernel, mutations, work_units, queries)
    inputs._compare_transition(observed, owned["expectedTransition"], OPERATION, work)
    return observed
