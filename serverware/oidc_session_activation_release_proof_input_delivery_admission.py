"""Independent proof-bootstrap staging admission, not private replay.

The root receiver independently pins completion and both signer originals.
It has no packet or old token; committed-original derivation and possession
remain obligations of the issuer and actual private proof worker respectively.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_oidc_session_activation_release_proof_input_delivery_transport as transport
from serverware import oidc_session_activation_release_proof_input_issuer_policy as issuer


bootstrap = issuer.bootstrap
authorization, shape, plan = issuer.authorization, issuer.shape, issuer.plan
capture, clock = issuer.capture, issuer.clock
MAX_ORIGINAL_BYTES = issuer.MAX_ORIGINAL_BYTES


class ReleaseProofInputDeliveryAdmissionError(ValueError):
    pass


def _fail(message):
    raise ReleaseProofInputDeliveryAdmissionError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _DeliveryMaterial:
    bootstrap_bytes: bytes
    proof_material: object
    policy_material: object
    bootstrap_identity: bytes
    live_window: tuple
    deadline_ns: int
    live: object


def _verify_on_work(*, proof_bootstrap_bytes, issuer_policy_bytes, completion_bootstrap_bytes,
        proof_enrollment_bytes, intent_enrollment_bytes, root_public_key,
        live_window, transport_deadline_ns, work, _continuity=None):
    capture._SharedLedger(work)
    root = root_public_key
    authorization._public(root)
    original = authorization._original(proof_bootstrap_bytes, bootstrap.MAX_BYTES, "staged proof bootstrap")
    policy_original = authorization._original(issuer_policy_bytes, issuer.MAX_BYTES, "independent proof input policy")
    originals = issuer._originals(completion_bootstrap_bytes, proof_enrollment_bytes,
        intent_enrollment_bytes, work, len(policy_original))
    # Tightening whole-call reservation includes nested base64 originals and
    # canonical/capture copies; individual wire maxima are not additive quotas.
    reserved = 8 * (len(original) + len(originals[0])) + 4 * (len(policy_original)
        + len(originals[1]) + len(originals[2]))
    if reserved > MAX_ORIGINAL_BYTES:
        _fail("proof staging exceeds its original and decoded capacity")
    work.charge(input_bytes=len(original))
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    lifetime = issuer._Lifetime(window, min(window[4], transport_deadline_ns), work, _continuity)
    current = lifetime.current
    current()
    policy = issuer._verify_on_work(policy_bytes=policy_original,
        completion_bootstrap_bytes=originals[0], proof_enrollment_bytes=originals[1],
        intent_enrollment_bytes=originals[2], root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _continuity=lifetime.continuity)
    if type(policy) is not issuer._IssuerPolicyMaterial:
        _fail("proof staging requires genuine independent policy admission")
    lifetime.attach(policy.live)
    lifetime.adopt(policy.live_window, policy.deadline_ns)
    material = bootstrap._verify_on_work(bootstrap_bytes=original, root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _current=lifetime.base)
    if type(material) is not bootstrap._ProofMaterial:
        _fail("proof staging requires genuine proof-bootstrap original admission")
    for actual, expected, label in ((material.bootstrap_bytes, original, "bootstrap"),
            (material.completion_bootstrap_bytes, originals[0], "completion bootstrap"),
            (material.proof_enrollment_bytes, originals[1], "proof enrollment"),
            (material.intent_enrollment_bytes, originals[2], "intent enrollment")):
        bootstrap.completion.receiving._same_bytes(actual, expected, work,
            "proof staging exact independent " + label)
        current()
    for actual, expected, label in ((material.expected_proof_scope, policy.proof_scope, "proof scope"),
            (material.caller_id, policy.caller_id, "intent caller"),
            (material.launch, policy.proof_launch, "fixed resources and listener"),
            (material.proof_spki_digest, issuer.keys._spki_on_work(policy.proof_public_key, work), "proof signer")):
        plan._same(actual, expected, work, "proof staging independent " + label)
        current()
    interval = policy.payload["issuedAtEpochNs"], policy.payload["expiresAtEpochNs"]
    if not interval[0] <= material.attestation_interval[0] < material.attestation_interval[1] <= interval[1]:
        _fail("proof staging launch escapes its independently signed policy interval")
    lifetime.attach(material.live)
    lifetime.adopt(material.live_window, material.deadline_ns)
    identity = transport._bootstrap_identity_on_work(original, deadline_ns=lifetime.bound,
        work=work, current=current)
    current()
    return _DeliveryMaterial(original, material, policy, identity,
        lifetime.window, lifetime.bound, current)
