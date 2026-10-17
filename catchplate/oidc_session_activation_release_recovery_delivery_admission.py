"""Original-only RECOVERY worker staging admission, never store evidence.

The independently provisioned root policy, custody and enrollments supply every
expectation. The incoming root-signed server original cannot select its own
target, checkpoint or resource pins. This module opens no private resource and
accepts no successful admission carrier, token or historical request tuple.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import oidc_session_activation_release_recovery_issuer_policy as issuer


server, clients = issuer.server, issuer.client
authorization, shape, plan = issuer.authorization, issuer.shape, issuer.plan
capture, clock = issuer.capture, issuer.clock
MAX_ORIGINAL_BYTES = issuer.MAX_ORIGINAL_BYTES


class ReleaseRecoveryDeliveryAdmissionError(ValueError):
    pass


def _fail(message):
    raise ReleaseRecoveryDeliveryAdmissionError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _DeliveryMaterial:
    """Private same-call result; no admission accepts this instead of originals."""

    server_bootstrap_bytes: bytes
    server_material: server._ReleaseMaterial
    issuer_policy_material: issuer._IssuerPolicyMaterial
    bootstrap_identity: bytes
    live_window: tuple
    deadline_ns: int
    live: object


def _reserve(original, independent, work):
    """Reserve both genuine admission paths before parsing either original."""
    policy, custody, proof_enrollment, intent_enrollment = independent
    planner = server.custody.planner_bootstrap
    # Nested decoded bytes cannot exceed their enclosing canonical base64
    # original. Keep both independent historical planner paths, not just the
    # eventually equal custody bytes in the candidate and root configuration.
    planner_bounds = (min(planner.MAX_BYTES, len(custody)),
        min(planner.MAX_BYTES, server.custody.MAX_BYTES, len(original)))
    nested = (sum(min(maximum, len(original)) for maximum in
            (server.custody.MAX_BYTES, server.storage.MAX_BYTES, server.recovery.MAX_BYTES))
        + sum(size + min(planner.vector.MAX_BYTES, size)
            + min(authorization.MAX_ENROLLMENT_BYTES, size) for size in planner_bounds))
    reserved = (8 * len(custody)
        + 4 * sum(map(len, (original, policy, proof_enrollment, intent_enrollment))) + nested)
    if MAX_ORIGINAL_BYTES != 64 * 1024 * 1024 or reserved > MAX_ORIGINAL_BYTES:
        _fail("recovery delivery exceeds its complete original and capture capacity")
    work.charge(input_bytes=sum(map(len, (original, *independent))))
    return reserved


def _same_bytes(actual, expected, work, label):
    if type(actual) is not bytes or type(expected) is not bytes:
        _fail(label + " requires exact immutable originals")
    work.charge(input_bytes=len(actual) + len(expected))
    if actual != expected:
        _fail(label + " differs")


def _scopes(policy, reserved, work):
    """Derive exact scopes solely from independently admitted policy originals."""
    payload = policy.payload
    scope, release, evidence = payload["proofScope"], payload["expectedRelease"], payload["expectedEvidence"]
    directory = {name: policy.release_launch["outcomeDirectory" + name[0].upper() + name[1:]]
        for name in server.storage.DIRECTORY_FIELDS}
    storage_scope = {**{name: scope[name] for name in (
        "configurationDigest", "databaseId", "generationDigest", "runtimeClosureDigest", "receiverIdentity")},
        "deliveryId": release["deliveryScope"]["deliveryId"],
        "releaseCustodyDigest": evidence["releaseCustodyDigest"], "directory": directory,
        "checkpoint": {"recordCount": 1, "outcomeDigest": payload["expectedOutcomeDigest"]}}
    recovery_scope = {**{name: storage_scope[name] for name in (
        "configurationDigest", "databaseId", "generationDigest", "runtimeClosureDigest", "receiverIdentity",
        "deliveryId", "releaseCustodyDigest", "directory")}, "callerId": payload["callerId"],
        "deliveryKeyDigest": policy.custody_material.delivery_key_digest,
        "outcomeDigest": payload["expectedOutcomeDigest"],
        **({"currentReleaseCustodyDigest": payload["currentReleaseCustodyDigest"]}
            if payload["schema"] == issuer.V2_PAYLOAD_SCHEMA else {})}
    # These graphs contain only source-fixed fields and retained references.
    # Measure before capture/canonical comparison creates their representations.
    graph_bytes = sum(work.measure(graph)[0] for graph in
        (storage_scope, recovery_scope, policy.release_launch, scope, release))
    if reserved + 4 * graph_bytes > MAX_ORIGINAL_BYTES:
        _fail("recovery delivery independent comparison graphs exceed remaining capacity")
    return (server.storage._scope(storage_scope, work),
        server.recovery._scope(recovery_scope, work))


def _verify_on_work(*, server_bootstrap_bytes, issuer_policy_bytes, release_custody_bytes,
        proof_enrollment_bytes, intent_enrollment_bytes, root_public_key,
        live_window, transport_deadline_ns, work, _continuity=None):
    """Admit the root recovery launch against separately provisioned originals.

    The checkpoint is independent policy, not evidence of an existing record.
    Fresh recovery authority never extends historical execution validity or the
    original delivery expiry. Only restrictive original clock floors propagate.
    """
    capture._SharedLedger(work)
    original = authorization._original(server_bootstrap_bytes, server.MAX_BYTES,
        "delivered recovery server bootstrap")
    policy_original = authorization._original(issuer_policy_bytes, issuer.MAX_BYTES,
        "independent recovery delivery issuer policy")
    custody_original = authorization._original(release_custody_bytes, issuer.MAX_CUSTODY_BYTES,
        "independent recovery delivery historical custody")
    proof_original = authorization._original(proof_enrollment_bytes, issuer.MAX_PROOF_ENROLLMENT_BYTES,
        "independent recovery delivery proof enrollment")
    intent_original = authorization._original(intent_enrollment_bytes, issuer.MAX_INTENT_ENROLLMENT_BYTES,
        "independent recovery delivery intent enrollment")
    independent = policy_original, custody_original, proof_original, intent_original
    reserved = _reserve(original, independent, work)
    root = root_public_key
    authorization._public(root)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    lifetime = issuer._Lifetime(window, min(window[4], transport_deadline_ns), work, _continuity)
    current = lifetime.current
    current()
    policy = issuer._verify_on_work(policy_bytes=policy_original,
        release_custody_bytes=custody_original, proof_enrollment_bytes=proof_original,
        intent_enrollment_bytes=intent_original, root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _continuity=lifetime.continuity)
    if (type(policy) is not issuer._IssuerPolicyMaterial
            or type(policy.custody_material) is not server.custody._ReleaseCustodyMaterial):
        _fail("recovery delivery requires genuine independent policy and historical custody")
    # The floor-only hook calls the parent's base, never its attached children.
    # Attaching the returned guard therefore cannot create an aggregation cycle.
    lifetime.attach(policy.live)
    lifetime.adopt(policy.live_window, policy.deadline_ns)
    current()
    storage_scope, recovery_scope = _scopes(policy, reserved, work)
    current()
    material = server._verify_on_work(bootstrap_bytes=original, root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _continuity=lifetime.continuity)
    if (type(material) is not server._ReleaseMaterial or material.profile != server.RECOVERY_PROFILE
            or type(material.recovery_authorization_bytes) is not bytes
            or type(material.custody_material) is not server.custody._ReleaseCustodyMaterial):
        _fail("recovery delivery requires the genuine RECOVERY server original")
    lifetime.attach(material.live)
    lifetime.adopt(material.live_window, material.deadline_ns)
    current()
    _same_bytes(material.custody_bytes, custody_original, work,
        "recovery delivery exact independently provisioned custody")
    current()
    payload, scope = policy.payload, policy.payload["proofScope"]
    for actual, expected, label in (
            (material.launch, policy.release_launch, "launch resources"),
            (material.storage_scope, storage_scope, "checkpoint-one storage scope"),
            (material.recovery_scope, recovery_scope, "fresh recovery scope"),
            (material.expected_release, payload["expectedRelease"], "complete release target"),
            (material.configuration_digest, scope["configurationDigest"], "configuration"),
            (material.database_id, scope["databaseId"], "database"),
            (material.generation_digest, scope["generationDigest"], "generation"),
            (material.runtime_closure_digest, scope["runtimeClosureDigest"], "runtime closure"),
            (material.receiver_identity, scope["receiverIdentity"], "receiver"),
            (material.producer_id, scope["producerId"], "producer"),
            (material.producer_identity, scope["producerIdentity"], "producer identity"),
            (material.caller_id, payload["callerId"], "independent caller"),
            (material.state_receipt_digest, payload["expectedEvidence"]["stateReceiptDigest"],
                "independent completion receipt"),
            (material.delivery_key_digest, policy.custody_material.delivery_key_digest,
                "independent delivery key")):
        plan._same(actual, expected, work, "recovery delivery " + label)
        current()
    server._contains(material.attestation_interval,
        (payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]))
    # Do not contain fresh recovery inside expired historical custody/intent
    # intervals. Both actual admissions retain the original delivery expiry.
    nested = (material.custody_bytes, material.storage_authorization_bytes,
        material.recovery_authorization_bytes,
        policy.custody_material.planner.bootstrap_bytes,
        policy.custody_material.planner.state_enrollment_bytes,
        policy.custody_material.planner.complete_root_vector_bytes,
        material.custody_material.planner.bootstrap_bytes,
        material.custody_material.planner.state_enrollment_bytes,
        material.custody_material.planner.complete_root_vector_bytes)
    if sum(map(len, (original, *independent, *nested))) > MAX_ORIGINAL_BYTES:
        _fail("recovery delivery actual decoded original inventory exceeds its bound")
    work.charge(input_bytes=sum(map(len, nested)))
    current()
    identity = clients._server_bootstrap_digest_on_work(original, work)
    shape._digest(identity)
    work.prepare_utf8(identity)
    encoded_identity = identity.encode("ascii")
    if len(encoded_identity) != 71:
        _fail("recovery delivery bootstrap identity differs from its fixed frame")
    current()
    return _DeliveryMaterial(original, material, policy, encoded_identity,
        lifetime.window, lifetime.bound, current)
