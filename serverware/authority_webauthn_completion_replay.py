"""Original-byte and semantic replay for trust publication completion.

The caller independently admits the historical request, selected rows and
database cutoff, original-input commitment, installer pins, target and committed
stage. This component does not verify primary/count proofs or establish that
installation, readback or a stage commit occurred. It repeats the genuine
completion signature/consumption, query and capacity computations and compares
their full transition on the caller's original work allowance.

The input record retains only the three original byte strings. Independent
stage/key/time authority is never adopted from that record. No SQL, clock,
signer, registry change, fresh allowance or successful-proof input is present.
"""
from __future__ import annotations

from serverware import authority_audit_capacity as capacity
from serverware import authority_query_reads as reads
from serverware import authority_request_commitment as commitment
from serverware import authority_transition_webauthn_completion as completion
from serverware import authority_webauthn_transition_inputs as inputs_wire


wire, evidence, authority, core = (
    inputs_wire.wire, inputs_wire.evidence, inputs_wire.authority, inputs_wire.core)
OPERATION = completion.OPERATION
_RAW_LIMITS = (
    ("installationEnvelope", evidence.MAX_EVIDENCE_BYTES),
    ("installedBundle", completion.bundle_core.MAX_INSTALLATION_BYTES),
    ("installedState", completion.bundle_core.MAX_STATE_BYTES),
)
_INPUT_FIELDS = frozenset(name for name, _maximum in _RAW_LIMITS)
_RAW_FIELDS = frozenset({"base64Url", "byteCount"})
_TRANSITION_FIELDS = frozenset({"mutations", "result", "kernelWorkUnits", "workUnits"})


class WebAuthnCompletionReplayError(ValueError):
    pass


def _input_shape(inputs):
    """Admit every local raw length before the first original-byte decode."""
    shape = evidence.plan.contract
    shape._object(inputs, _INPUT_FIELDS, "completion original inputs")
    for name, maximum in _RAW_LIMITS:
        value = inputs[name]
        shape._object(value, _RAW_FIELDS, "completion original byte record")
        shape._integer(value["byteCount"], maximum, minimum=2)
        encoded = value["base64Url"]
        if type(encoded) is not str or len(encoded) != (4 * value["byteCount"] + 2) // 3:
            raise WebAuthnCompletionReplayError("completion original encoding length changed")


def _encode_inputs_on_work(*, installation_envelope_bytes, installed_bundle_bytes,
        installed_state_bytes, work):
    """Encode actual immutable originals without supplying historical authority."""
    evidence.capture._SharedLedger(work)
    originals = (installation_envelope_bytes, installed_bundle_bytes, installed_state_bytes)
    for raw, (_name, maximum) in zip(originals, _RAW_LIMITS):
        wire._raw(raw, 2, maximum)
    inputs = {name: wire._pack_raw(raw, minimum=2, maximum=maximum, work=work)
        for raw, (name, maximum) in zip(originals, _RAW_LIMITS)}
    _input_shape(inputs)
    return inputs_wire._encode_on_work(OPERATION, inputs, work)


def _decode_inputs_on_work(inputs_bytes, expected_inputs_digest, work):
    """Return original raw3 after real commitment/canonical checks, not proof."""
    inputs = inputs_wire._decode_on_work(OPERATION, inputs_bytes, expected_inputs_digest, work)
    _input_shape(inputs)
    return tuple(wire._unpack_raw(inputs[name], minimum=2, maximum=maximum, work=work)
        for name, maximum in _RAW_LIMITS)


def _replay_on_work(*, request, selected_rows, database_now, query_reads,
        inputs_bytes, expected_inputs_digest, expected_transition,
        installation_target_digest, expected_committed_stage, installer_public_key,
        expected_installer_identity, expected_installer_spki_digest, now_epoch_ns,
        deadline_epoch_ns, maximum_age_ns, maximum_clock_skew_ns, work):
    """Recompute actual completion effects and capacity, without proof engines."""
    evidence.capture._SharedLedger(work)
    spec = authority.operation_spec(OPERATION)
    if (type(selected_rows) is not tuple or len(selected_rows) > spec["maximumQueryRows"]
            or any(type(row) is not dict for row in selected_rows)
            or type(query_reads) is not tuple or len(query_reads) > spec["maximumQueryRows"]
            or not isinstance(installer_public_key, evidence.keys.Ed25519PublicKey)):
        raise WebAuthnCompletionReplayError("completion replay requires bounded rows, reads and a pinned key")
    wire._raw(inputs_bytes, 2, wire.MAX_BYTES)
    original_inputs, public_key, instant = inputs_bytes, installer_public_key, database_now
    cutoff_us = wire._to_epoch_us(instant)
    cutoff_ns = completion._now(instant)
    if cutoff_ns != cutoff_us * 1000:
        raise WebAuthnCompletionReplayError("completion database cutoff lost precision")
    # Own every variable caller graph and actual immutable query record before
    # original decoding or any native/key callback. Retained stage data never
    # replaces this independently supplied historical graph.
    work.prepare_copy(selected_rows)
    owned = wire._capture({"request": request, "selected": list(selected_rows),
        "expectedInputsDigest": expected_inputs_digest, "expectedTransition": expected_transition,
        "stage": expected_committed_stage, "identity": expected_installer_identity,
        "spkiDigest": expected_installer_spki_digest, "target": installation_target_digest,
        "nowEpochNs": now_epoch_ns, "deadlineEpochNs": deadline_epoch_ns,
        "maximumAgeNs": maximum_age_ns, "maximumClockSkewNs": maximum_clock_skew_ns}, work)
    records = tuple(reads._copy_read(record, work) for record in query_reads)
    shape = evidence.plan.contract
    for name in ("expectedInputsDigest", "spkiDigest", "target"):
        shape._digest(owned[name])
    evidence._identity(owned["identity"])
    completion._object(owned["stage"], completion._STAGE_FIELDS, "historical committed stage")
    for name in completion._STAGE_FIELDS - {"witnessSequence"}:
        shape._digest(owned["stage"][name])
    shape._integer(owned["stage"]["witnessSequence"], minimum=1)
    for name in ("nowEpochNs", "deadlineEpochNs"):
        shape._integer(owned[name], minimum=1)
    shape._integer(owned["maximumAgeNs"], authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(owned["maximumClockSkewNs"], authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    if (owned["nowEpochNs"] >= owned["deadlineEpochNs"]
            or abs(cutoff_ns - owned["nowEpochNs"]) > owned["maximumClockSkewNs"]
            or cutoff_ns >= owned["deadlineEpochNs"]):
        raise WebAuthnCompletionReplayError("completion cutoff differs from independent historical time")
    expected = owned["expectedTransition"]
    shape._object(expected, _TRANSITION_FIELDS, "historical completion transition")
    shape._array(expected["mutations"], spec["maximumMutations"], "historical completion mutations")
    shape._integer(expected["kernelWorkUnits"], spec["maximumBusinessWorkUnits"], minimum=1)
    shape._integer(expected["workUnits"], spec["maximumWorkUnits"], minimum=1)
    actual = owned["request"]
    if (type(actual) is not dict or actual.get("operation") != OPERATION
            or actual.get("handler") != "complete_webauthn_trust_publication"):
        raise WebAuthnCompletionReplayError("completion request differs from the fixed operation")
    completion._object(actual.get("arguments"), completion._ARGUMENT_FIELDS, "completion arguments")
    digest = commitment._typed_request_digest(actual, work=work)
    if commitment._request_different(digest, actual.get("requestDigest"), work=work):
        raise WebAuthnCompletionReplayError("completion typed request commitment changed")
    work.prepare_utf8(OPERATION)
    work.prepare_utf8(digest)
    work.charge(hashes=1)
    if commitment._request_different(commitment.operation_id(OPERATION, digest), actual.get("operationId"), work=work):
        raise WebAuthnCompletionReplayError("completion operation commitment changed")
    originals = _decode_inputs_on_work(original_inputs, owned["expectedInputsDigest"], work)
    arguments = actual["arguments"]
    queries = completion.completion_queries(publication_id=arguments["publication_id"],
        verification_evidence_digest=arguments["verification_evidence_digest"],
        request_digest=digest, work=work)
    queries = capacity.add_capacity_query(OPERATION, queries)
    work.prepare_copy(owned["selected"])
    selected = tuple(owned["selected"])
    capacity._validate_capacity_transition(operation=OPERATION, selected_rows=selected,
        mutations=(), work=work)
    _, records = reads._validate_query_reads(OPERATION, queries=queries,
        query_reads=records, selected_rows=selected, work=work)
    evidence.keys._public_binding(public_key, owned["spkiDigest"], work)
    context = core.KernelContext(OPERATION, arguments, selected, instant, digest, query_reads=records)
    kernel = completion._kernel_transition_on_work(context,
        installation_envelope_bytes=originals[0], installed_bundle_bytes=originals[1],
        installed_state_bytes=originals[2], installation_target_digest=owned["target"],
        expected_committed_stage=owned["stage"], installer_public_key=public_key,
        expected_installer_identity=owned["identity"], expected_installer_spki_digest=owned["spkiDigest"],
        maximum_age_ns=owned["maximumAgeNs"], maximum_clock_skew_ns=owned["maximumClockSkewNs"], work=work)
    finalized = capacity._finalize_capacity(context, kernel.mutations, work=work)
    work_units = capacity.transition_work_units(operation=OPERATION,
        query_work_units=sum(query.work_units for query in queries),
        kernel_work_units=kernel.work_units, mutations=finalized)
    capacity.validate_transition_work_units(OPERATION, work_units, finalized)
    work.prepare_copy(finalized)
    ordered = sorted(finalized, key=lambda item: (item["table"], item["keyDigest"], item["operation"]))
    work.prepare_copy(ordered)
    observation = inputs_wire._ReplayObservation(kernel=kernel, mutations=tuple(ordered),
        work_units=work_units, queries=queries)
    inputs_wire._compare_transition(observation, expected, OPERATION, work)
    return observation
