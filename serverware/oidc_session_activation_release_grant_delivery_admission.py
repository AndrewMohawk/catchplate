"""Admit an issued release bootstrap against independent receiving originals.

This is public-original verification only. It opens no resources or private key,
accepts no successful material carrier, and cannot establish staged delivery,
storage emptiness, worker readiness or a returned session token.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_oidc_session_activation_release_grant_production as producer


issuer, server, clients = producer.issuer, producer.server, producer.clients
authorization, shape, plan = producer.authorization, producer.shape, producer.plan
capture, clock, state = producer.capture, producer.clock, producer.state
MAX_ORIGINAL_BYTES = issuer.MAX_ORIGINAL_BYTES


class ReleaseGrantDeliveryAdmissionError(ValueError):
    pass


def _fail(message):
    raise ReleaseGrantDeliveryAdmissionError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _DeliveryMaterial:
    """Same-call verified output; never an accepted admission input."""

    server_bootstrap_bytes: bytes
    server_material: server._ReleaseMaterial
    issuer_policy_material: issuer._IssuerPolicyMaterial
    bootstrap_identity: bytes
    live_window: tuple
    deadline_ns: int
    live: object


def _verify_on_work(*, server_bootstrap_bytes, issuer_policy_bytes, proof_bootstrap_bytes,
        root_public_key, live_window, transport_deadline_ns, work, _continuity=None):
    """Join actual signatures, original custody, target and resource policy."""
    original = authorization._original(server_bootstrap_bytes, server.MAX_BYTES,
        "delivered release server bootstrap")
    policy_original = authorization._original(issuer_policy_bytes, issuer.MAX_BYTES,
        "independent release delivery issuer policy")
    proof_original = authorization._original(proof_bootstrap_bytes, issuer.MAX_PROOF_BOOTSTRAP_BYTES,
        "independent release delivery proof bootstrap")
    root, continuation = root_public_key, _continuity
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(window[4], transport_deadline_ns)
    original_bytes = len(original) + len(policy_original) + len(proof_original)
    proof_reservation = producer.cold._proof_reservation(len(policy_original), len(proof_original))
    if original_bytes + proof_reservation + 8 * len(original) > MAX_ORIGINAL_BYTES:
        _fail("release delivery exceeds its complete original inventory")
    capture._SharedLedger(work)
    work.charge(input_bytes=original_bytes)
    authorization._public(root)
    # Reuse only private clock/ledger bookkeeping, never the signing producer
    # or a successful issuance result as receiving authority.
    lifetime = producer._Lifetime(window, bound, work, continuation)
    current = lifetime.current
    current()
    policy = issuer._verify_on_work(policy_bytes=policy_original,
        proof_bootstrap_bytes=proof_original, root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work)
    if type(policy) is not issuer._IssuerPolicyMaterial:
        _fail("release delivery requires genuine independent policy admission")
    lifetime.attach(policy.live)
    lifetime.adopt(policy.live_window, policy.deadline_ns)
    proof = policy.proof_material
    if type(proof) is not issuer.proof_bootstrap._ProofMaterial:
        _fail("release delivery requires the actual policy-bound proof original")
    completion = proof.completion_material
    embedded = (proof.completion_bootstrap_bytes, proof.proof_enrollment_bytes,
        proof.release_custody_bytes, proof.intent_bytes, proof.intent_enrollment_bytes,
        proof.completion_request_bytes, proof.state_receipt_bytes,
        completion.current_root_enrollment_bytes, completion.authorization_enrollment_bytes,
        completion.grant_enrollment_bytes)
    current_planner = proof.current_activation_planner
    if current_planner is not None:
        if type(current_planner) is not server.custody.planner_bootstrap._PlannerMaterial:
            _fail("release delivery current template lacks actual proof admission")
        embedded += (proof.current_activation_planner_bytes, current_planner.bootstrap_bytes,
            current_planner.state_enrollment_bytes, current_planner.complete_root_vector_bytes)
    embedded_bytes = sum(map(len, embedded))
    if original_bytes + embedded_bytes > MAX_ORIGINAL_BYTES:
        _fail("release delivery independent decoded originals exceed the held inventory")
    work.charge(input_bytes=embedded_bytes)
    current()
    material = server._verify_on_work(bootstrap_bytes=original, root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work)
    if type(material) is not server._ReleaseMaterial or material.profile != server.LIVE_PROFILE:
        _fail("dynamic release delivery requires actual LIVE server-original admission")
    lifetime.attach(material.live)
    lifetime.adopt(material.live_window, material.deadline_ns)
    decoded_bytes = (len(material.custody_bytes) + len(material.storage_authorization_bytes)
        + len(material.custody_material.planner.bootstrap_bytes))
    if original_bytes + embedded_bytes + decoded_bytes > MAX_ORIGINAL_BYTES:
        _fail("release delivery nested server originals exceed the complete held inventory")
    work.charge(input_bytes=decoded_bytes)
    producer._same_bytes(material.custody_bytes, proof.release_custody_bytes, work,
        "release delivery exact independently provisioned custody original")
    custody = material.custody_material
    if current_planner is None:
        if proof.current_activation_planner_bytes is not None:
            _fail("legacy release delivery has an unexpected current template")
        plan._same(issuer.keys._spki_on_work(completion.evidence_root_public_key, work),
            issuer.keys._spki_on_work(root, work), work, "legacy release delivery evidence root")
        producer._same_bytes(custody.planner.state_enrollment_bytes, completion.current_root_enrollment_bytes,
            work, "legacy release delivery exact state original")
    else:
        producer._same_bytes(custody.planner.bootstrap_bytes, proof.current_activation_planner_bytes,
            work, "release delivery exact current custody planner")
        producer._same_bytes(current_planner.bootstrap_bytes, proof.current_activation_planner_bytes,
            work, "release delivery genuine current template")
    old_state = authorization._admit_enrollment_on_work(
        enrollment_bytes=completion.current_root_enrollment_bytes,
        root_public_key=completion.evidence_root_public_key, work=work)
    current()
    current_state = authorization._admit_enrollment_on_work(
        enrollment_bytes=custody.planner.state_enrollment_bytes, root_public_key=root, work=work)
    current()
    for actual, expected in ((old_state.payload, current_state.payload),
            (old_state.enrollment_digest, completion.enrollment_digest),
            (current_state.enrollment_digest, custody.planner.state_enrollment_digest),
            (completion.database_id, material.database_id),
            (completion.generation_digest, material.generation_digest),
            (custody.delivery_key_digest, completion.custody_material.history.planner.delivery_key_digest)):
        plan._same(actual, expected, work, "release delivery original/current state and delivery key")
    current()
    scope = proof.expected_proof_scope
    for actual, expected, label in (
            (material.launch, policy.release_launch, "release launch resources"),
            (material.expected_release, proof.expected_release, "complete expected release"),
            (material.configuration_digest, scope["configurationDigest"], "configuration"),
            (material.database_id, scope["databaseId"], "database"),
            (material.generation_digest, scope["generationDigest"], "generation"),
            (material.runtime_closure_digest, scope["runtimeClosureDigest"], "runtime closure"),
            (material.receiver_identity, scope["receiverIdentity"], "receiver"),
            (material.producer_id, scope["producerId"], "producer"),
            (material.producer_identity, scope["producerIdentity"], "producer identity"),
            (material.caller_id, proof.caller_id, "independent caller"),
            (material.storage_scope["checkpoint"], {"recordCount": 0, "outcomeDigest": None},
                "authorized empty checkpoint")):
        plan._same(actual, expected, work, "release delivery " + label)
    current()
    receipt_digest = plan._frame(state.RECEIPT_IDENTITY_DOMAIN, (proof.state_receipt_bytes,), work)
    plan._same(material.state_receipt_digest, receipt_digest, work,
        "release delivery exact independently admitted completion receipt")
    server._contains(material.attestation_interval,
        (policy.payload["issuedAtEpochNs"], policy.payload["expiresAtEpochNs"]))
    server._contains(material.attestation_interval, proof.attestation_interval)
    current()
    identity = clients._server_bootstrap_digest_on_work(original, work)
    shape._digest(identity)
    work.prepare_utf8(identity)
    encoded_identity = identity.encode("ascii")
    if len(encoded_identity) != 71:
        _fail("release delivery bootstrap identity differs from its fixed frame")
    current()
    return _DeliveryMaterial(original, material, policy, encoded_identity,
        lifetime.window, lifetime.bound, current)
