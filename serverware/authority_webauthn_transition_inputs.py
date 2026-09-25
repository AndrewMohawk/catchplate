"""Original-input commitments and effect comparisons for three successors.

These records carry reproducible inputs, not signatures, admitted history or
successful proof results. Family codecs close their own input shapes. Shared
wire mechanics retain the existing source byte/node/depth ceilings and the
caller's cumulative work; this module allocates no replacement allowance.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_webauthn_evidence_input_wire as wire


evidence = wire.evidence
authority, core = evidence.authority, evidence.plan.core
SCHEMA = "serverware.policyAuthorityWebAuthnTransitionInputs/v1"
IDENTITY_DOMAIN = "serverware.policyAuthorityWebAuthnTransitionInputsIdentity/v1"
OPERATIONS = frozenset({"webauthn.registration.finalize", "webauthn.trust.stage", "webauthn.trust.complete"})
_FIELDS = frozenset({"schema", "sourceRevision", "operation", "inputs"})
_TRANSITION_FIELDS = frozenset({"mutations", "result", "kernelWorkUnits", "workUnits"})


class WebAuthnTransitionInputsError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _ReplayObservation:
    """Actual semantic outputs only; primary/count proof checks are separate."""

    kernel: core.KernelTransition
    mutations: tuple
    work_units: int
    queries: tuple


@dataclass(frozen=True, slots=True)
class _RetainedAcquisition:
    """Raw acquisition, originals and local replay, never admission authority."""

    acquisition: object
    inputs_bytes: bytes
    inputs_digest: str
    semantics: _ReplayObservation


def _operation(operation):
    if type(operation) is not str or operation not in OPERATIONS:
        raise WebAuthnTransitionInputsError("transition inputs operation is not source fixed")


def _encode_on_work(operation, inputs, work):
    _operation(operation)
    if type(inputs) is not dict:
        raise WebAuthnTransitionInputsError("transition inputs must be an exact object")
    return wire._encode_document({"schema": SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "operation": operation, "inputs": inputs}, work)


def _digest_on_work(raw, work):
    evidence.capture._SharedLedger(work)
    wire._raw(raw, 2, wire.MAX_BYTES)
    return evidence.plan._frame(IDENTITY_DOMAIN, (raw,), work)


def _decode_on_work(operation, raw, expected_inputs_digest, work):
    _operation(operation)
    evidence.plan.contract._digest(expected_inputs_digest)
    evidence.plan._same(_digest_on_work(raw, work), expected_inputs_digest, work,
        "transition originals differ from the independently held input commitment")
    document = wire._decode_document(raw, work)
    shape = evidence.plan.contract
    shape._object(document, _FIELDS, "WebAuthn transition inputs")
    shape._literal(document["schema"], SCHEMA)
    shape._literal(document["sourceRevision"], authority.SOURCE_REVISION)
    shape._literal(document["operation"], operation)
    if type(document["inputs"]) is not dict:
        raise WebAuthnTransitionInputsError("transition originals inputs are not an exact object")
    return document["inputs"]


def _compare_transition(observation, expected_transition, operation, work):
    """Compare complete computed effects, not a caller's successful-proof flag."""
    _operation(operation)
    if (type(observation) is not _ReplayObservation
            or type(observation.kernel) is not core.KernelTransition
            or type(observation.mutations) is not tuple or type(observation.queries) is not tuple):
        raise WebAuthnTransitionInputsError("transition replay result is not an actual computation")
    spec = authority.operation_spec(operation)
    shape = evidence.plan.contract
    shape._object(expected_transition, _TRANSITION_FIELDS, "expected WebAuthn transition")
    shape._array(expected_transition["mutations"], spec["maximumMutations"], "expected transition mutations")
    shape._integer(expected_transition["kernelWorkUnits"], spec["maximumBusinessWorkUnits"], minimum=1)
    shape._integer(expected_transition["workUnits"], spec["maximumWorkUnits"], minimum=1)
    if len(observation.mutations) > spec["maximumMutations"]:
        raise WebAuthnTransitionInputsError("transition replay mutations exceed their source operation")
    work.prepare_copy(observation.mutations)
    actual = {"mutations": list(observation.mutations), "result": observation.kernel.result,
        "kernelWorkUnits": observation.kernel.work_units, "workUnits": observation.work_units}
    evidence.plan._same(actual, expected_transition, work,
        "genuine successor replay differs from the complete expected transition")
