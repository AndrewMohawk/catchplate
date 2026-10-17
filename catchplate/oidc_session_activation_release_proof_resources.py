"""Actual static proof resources and late same-authority completion joins.

No API accepts a successful planner/completion DTO from an external caller.
Cold callers supply root-signed policy/enrollment originals; the late helper is
called only with this invocation's genuinely verified completion observation.
No vector, pending head, issue time or processing allowance is manufactured.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import oidc_session_activation_request_issuance_policy as resources
from catchplate import oidc_session_activation_release_proof_input_issuer_policy as issuer


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Resources:
    issuance_policy_bytes: bytes
    policy: object
    proof_public_key: object
    intent_public_key: object
    live: object


def _original(payload, work, current):
    return issuer.completion.grammar._original(payload["activationIssuancePolicy"],
        resources.MAX_BYTES, work, current)


def _same_configuration(actual, expected, work):
    ledger = issuer.capture._SharedLedger(work)
    left = resources.configuration._configuration_wire(actual, ledger)
    right = resources.configuration._configuration_wire(expected, ledger)
    issuer.lifetime_source._same_bytes(left, right, work, "proof resource original configuration cohort")


def _admit_on_work(*, payload, proof_enrollment_bytes, intent_enrollment_bytes,
        root_public_key, live_window, transport_deadline_ns, work, _continuity=None):
    """Authenticate static delegation and both genuine distinct enrollments."""
    issuer.capture._SharedLedger(work)
    owned = issuer._capture(payload, work)
    issuer._payload_shape(owned, work)
    issuer.shape._literal(owned["schema"], issuer.V3_PAYLOAD_SCHEMA)
    root = root_public_key
    issuer.authorization._public(root)
    if (live_window is None) != (transport_deadline_ns is None):
        issuer._fail("proof resources require the complete original processing pair")
    window = None if live_window is None else issuer.clock._validate(live_window)
    if transport_deadline_ns is not None:
        issuer.shape._integer(transport_deadline_ns, minimum=1)
    bound = None if window is None else min(window[4], transport_deadline_ns)
    current = resources._clock(owned, window, bound, work, _continuity)
    current()
    raw = _original(owned, work, current)
    admitted = resources._verify_on_work(policy_bytes=raw, root_public_key=root,
        live_window=window, transport_deadline_ns=bound, work=work, _continuity=_continuity)
    if not (admitted.payload["issuedAtEpochNs"] <= owned["issuedAtEpochNs"]
            < owned["expiresAtEpochNs"] <= admitted.payload["expiresAtEpochNs"]):
        issuer._fail("proof resource policy exceeds its original delegated runtime interval")

    def live():
        first = current()
        observed = admitted.live()
        final = current()
        if not first <= observed <= final:
            issuer._fail("proof resource clocks reversed across original delegation")
        return final

    live()
    # Prepay the fixed scope/key roster scaffolding; all actual originals,
    # canonical graphs, hashes and signatures keep their separate real debits.
    work.charge(input_bytes=32768, json_nodes=1024)
    configured, generation, _runtime, planner, state_raw, _state_pin, _reader = admitted.resource_facts
    state = issuer.authorization._admit_enrollment_on_work(
        enrollment_bytes=state_raw, root_public_key=root, work=work)
    grants = resources.caller.grants._admit_enrollment_on_work(
        grant_enrollment_bytes=admitted.grant_enrollment, current_root_enrollment_bytes=state_raw,
        root_public_key=root, work=work)
    live()
    selected = owned["proofScope"]
    for name, expected in (("configurationDigest", admitted.payload["plannerResources"]["configurationDigest"]),
            ("generationDigest", generation["digest"]), ("databaseId", state.payload["databaseId"]),
            ("runtimeClosureDigest", admitted.payload["plannerResources"]["runtimeClosureDigest"])):
        issuer.plan._same(selected[name], expected, work, "proof static resource scope " + name)
    forbidden = issuer.bootstrap._unique_keys((root, planner, admitted.caller.caller_public_key,
        state.computation_public_key, state.completion_public_key, state.state_public_key,
        grants.authorizer_public_key), work)
    intent_scope = {name: selected[name] for name in issuer.intent_enrollments.SCOPE_FIELDS if name != "callerId"}
    intent_scope["callerId"] = owned["callerId"]
    intent_raw = issuer.authorization._original(intent_enrollment_bytes,
        issuer.intent_enrollments.MAX_BYTES, "static proof intent enrollment")
    proof_raw = issuer.authorization._original(proof_enrollment_bytes,
        issuer.proof_enrollments.MAX_BYTES, "static proof signer enrollment")
    intent = issuer.intent_enrollments._admit_on_work(enrollment_bytes=intent_raw,
        root_public_key=root, expected_scope=intent_scope, forbidden_public_keys=forbidden, work=work)
    live()
    proof = issuer.proof_enrollments._admit_on_work(enrollment_bytes=proof_raw,
        root_public_key=root, expected_scope=selected,
        forbidden_public_keys=issuer.bootstrap._unique_keys((*forbidden, intent.caller_public_key), work), work=work)
    for actual, expected in ((intent.enrollment_digest, owned["intentEnrollmentDigest"]),
            (proof.enrollment_digest, owned["proofEnrollmentDigest"])):
        issuer.plan._same(actual, expected, work, "proof resource exact enrollment original")
    issuer.completion._configured_keys(configured, intent.payload["callerKey"]["spkiDigest"],
        proof.payload["proofKey"]["spkiDigest"], work)
    result = _Resources(raw, admitted, proof.proof_public_key, intent.caller_public_key, live)
    live()
    return result


def _verify_on_work(*, policy_bytes, proof_enrollment_bytes, intent_enrollment_bytes,
        root_public_key, live_window=None, transport_deadline_ns=None, work, _continuity=None):
    """Static raw-original verification; never a completion or future plan."""
    root = root_public_key
    issuer.authorization._public(root)
    raw = issuer.authorization._original(policy_bytes, issuer.V3_MAX_BYTES, "static proof resource policy")
    envelope = issuer._read(raw, work)
    issuer.shape._literal(envelope["schema"], issuer.V3_SCHEMA)
    issuer._signature(envelope, root, work)
    admitted = _admit_on_work(payload=envelope["payload"], proof_enrollment_bytes=proof_enrollment_bytes,
        intent_enrollment_bytes=intent_enrollment_bytes, root_public_key=root,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work, _continuity=_continuity)
    issuer._canonical(raw, envelope, work)
    admitted.live()
    return admitted


def _late_on_work(resources_material, completion_material, *, root_public_key, lifetime, work):
    """Join observations produced locally by the two actual original verifiers.

    The first-request v3 lane is deliberately same-authority/live. It does not
    inherit the older v2 cross-root historical recovery template semantics.
    """
    if type(resources_material) is not _Resources or type(completion_material) is not issuer.completion._CompletionMaterial:
        issuer._fail("late proof resources require this invocation's genuine original admissions")
    selected, cm, root = resources_material, completion_material, root_public_key
    current = lifetime.current
    selected.live()
    current()
    actual_raw = cm.custody_material.history.planner.bootstrap_bytes
    planner = resources.planner._verify_on_work(bootstrap_bytes=actual_raw, root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work)
    lifetime.attach(resources.planner._launch_guard(planner.attestation_interval,
        planner.opening_sample, lifetime.base, work))
    # Compare every delegated static field, including authentication policies,
    # cipher-key digests and fixed launch/reader resources, not just its labels.
    # Only the real vector and signed request interval differ from resources.
    work.charge(input_bytes=16384, json_nodes=256)
    payload = resources.planner.codec._decode(actual_raw, work)["payload"]
    projected = {name: payload[name] for name in sorted(resources.RESOURCE_FIELDS)}
    _same_configuration(projected, selected.policy.payload["plannerResources"], work)
    configured, generation, runtime, public, state_raw, _pin, _reader = selected.policy.resource_facts
    for actual, expected in ((planner.configuration_payload, configured), (planner.generation, generation),
            (planner.runtime_role_identities, runtime), (cm.configuration_payload, configured),
            (cm.generation, generation), (cm.runtime_role_identities, runtime)):
        _same_configuration(actual, expected, work)
    for actual, expected in ((planner.configuration_digest, cm.configuration_digest),
            (planner.generation["digest"], cm.generation_digest),
            (planner.runtime_closure_digest, cm.runtime_closure_digest),
            (planner.runtime_closure_digest, selected.policy.payload["plannerResources"]["runtimeClosureDigest"])):
        issuer.plan._same(actual, expected, work, "late proof actual resource cohort")
    for actual, expected in ((planner.planner_public_key, public), (cm.evidence_root_public_key, root),
            (cm.operation_public_key, root)):
        issuer.plan._same(issuer.keys._spki_on_work(actual, work), issuer.keys._spki_on_work(expected, work),
            work, "late proof actual root and planner purpose keys")
    for actual in (planner.state_enrollment_bytes, cm.current_root_enrollment_bytes):
        issuer.lifetime_source._same_bytes(actual, state_raw, work, "late proof original state enrollment")
    current()
    selected.live()
    return planner
