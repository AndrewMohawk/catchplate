"""Resolve supported historical replay pins from an admitted startup archive.

The selector comes from independently admitted or authenticated original
history, never from a returned plan. It selects only an already admitted
configuration/cohort snapshot. This module performs same-work consistency and
key mapping, not artifact, configuration-root or historical provenance admission.
Current transport identities, clocks and database settings are not replaced.
Source/schema gates remain exact; this is not cross-source replay support.
"""
from __future__ import annotations

from serverware import authority_historical_archive as archive
from serverware import authority_revocation_configuration as configuration
from serverware import authority_webauthn_evidence_plan_admission as evidence_admission
from serverware import authority_webauthn_evidence_plan_verifier_configuration as evidence_configuration
from serverware import authority_webauthn_transition_plan_admission as transition_admission
from serverware import authority_webauthn_transition_configuration as transition_configuration


class WebAuthnCustodyHistoryError(ValueError):
    pass


def _configuration_on_work(snapshots, expected, evaluation_epoch_ns, work):
    snapshot = archive._lookup_on_work(snapshots,
        configuration_digest=expected["configurationDigest"],
        planner_attestation_receipt_digest=expected["plannerIdentity"]["attestationReceiptDigest"],
        evaluation_epoch_ns=evaluation_epoch_ns, work=work)
    # These are the detached startup archive graphs, not incoming key material.
    payload, digest, generation, runtime = (snapshot.payload, snapshot.configuration_digest,
        snapshot.generation, snapshot.runtime_role_identities)
    owned, launch = configuration._capture_configuration_on_work(payload=payload,
        configuration_digest=digest, generation=generation, work=work)
    owned_runtime = configuration._capture_runtime_role_identities_on_work(
        runtime_role_identities=runtime, owned_payload=owned,
        configuration_digest=digest, launch=launch, work=work)
    return owned, digest, owned_runtime


def _evidence_pins_on_work(*, purpose, snapshots, expectations, work):
    """Return actual historical pins13 and owned independent18 on the same work."""
    admission = evidence_admission
    ledger = admission.evidence.capture._SharedLedger(work)
    if type(purpose) is not str or purpose not in ("registration", "installation"):
        raise WebAuthnCustodyHistoryError("historical evidence purpose is not source fixed")
    operation = ("webauthn.registration.evidence.admit" if purpose == "registration"
        else "webauthn.trust.installation.admit")
    admission.evidence.plan.contract._object(expectations, admission.plan._EXPECTATION_FIELDS,
        "independent historical evidence expectations")
    expected = admission.evidence.capture._JSONCapture(ledger).visit(expectations)
    admission.plan._validate_expectations(expected, operation)
    owned, digest, runtime = _configuration_on_work(snapshots, expected, expected["nowEpochNs"], work)
    pins = evidence_configuration._pins_from_owned_configuration_on_work(purpose=purpose,
        owned_payload=owned, owned_runtime_identities=runtime, configuration_digest=digest, work=work)
    admitted = admission._capture_expectations_on_work(pins, expected, work)
    return pins, admitted


def _transition_pins_on_work(*, operation, snapshots, expectations, work):
    """Return actual historical pins7 and owned independent5 on the same work."""
    admission = transition_admission
    ledger = admission.evidence.capture._SharedLedger(work)
    transition_configuration._operation(operation)
    admission.shape._object(expectations, admission.plan.contract.EXPECTATION_FIELDS,
        "independent historical transition expectations")
    expected = admission.evidence.capture._JSONCapture(ledger).visit(expectations)
    actual_operation = admission.plan.contract._validate_expectations(expected)
    admission.evidence.plan._same(actual_operation, operation, work,
        "historical transition operation differs from the fixed lookup")
    owned, digest, runtime = _configuration_on_work(snapshots, expected,
        expected["proofExpectations"]["policy"]["nowEpochNs"], work)
    pins = transition_configuration._pins_from_owned_configuration_on_work(operation=operation,
        owned_payload=owned, owned_runtime_identities=runtime, configuration_digest=digest, work=work)
    admitted = admission._capture_expectations_on_work(pins, expected, work)
    return pins, admitted
