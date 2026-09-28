"""Original-only recovery grant admission, never durable-outcome evidence.

The independently signed policy and historical request originals supply the
expectations. Returned root originals authenticate no expectation by themselves.
This module opens no token, reads no store and grants no retry or exchange.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_oidc_session_activation_release_recovery_grant_production as production
from serverware import oidc_session_activation_release_recovery_issuer_policy as issuer


clients, server = issuer.client, issuer.server
authorization, capture, plan = issuer.authorization, issuer.capture, issuer.plan
outcomes = production.outcomes
MAX_ORIGINAL_BYTES = issuer.MAX_ORIGINAL_BYTES
RESPONSE_LIMITS = (clients.MAX_BYTES, server.MAX_BYTES, outcomes.MAX_BYTES)
MAX_RESPONSE_BYTES = sum(RESPONSE_LIMITS)


class OidcSessionActivationReleaseRecoveryGrantAdmissionError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationReleaseRecoveryGrantAdmissionError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _RecoveryGrantMaterial:
    """Same-call result only; no admission API accepts this as authority."""

    client_authorization_bytes: bytes
    server_bootstrap_bytes: bytes
    outcome_bytes: bytes
    client_material: clients._ClientAuthorization
    issuer_policy_material: issuer._IssuerPolicyMaterial
    live_window: tuple
    deadline_ns: int
    live: object


def _originals(values):
    if (type(values) is not tuple or len(values) != len(RESPONSE_LIMITS)
            or any(type(raw) is not bytes or not 2 <= len(raw) <= maximum
                for raw, maximum in zip(values, RESPONSE_LIMITS))):
        _fail("recovery grant response requires exact bounded client/server/outcome originals")
    return values


def _unique_bytes(originals):
    # The inventory has fourteen source-fixed positions at most, not an incoming
    # iterable. Shared immutable references consume capacity once, not per role.
    held = []
    total = 0
    for raw in originals:
        if not any(raw is prior for prior in held):
            held.append(raw)
            total += len(raw)
    return total


def _reserve(request, response, independent, work):
    policy, custody, proof_enrollment, intent_enrollment = independent
    planner = server.custody.planner_bootstrap
    # A decoded original cannot exceed its enclosing base64 JSON original.
    # Reserve both independently decoded historical planner paths before either
    # genuine policy or returned-server admission allocates their originals.
    planner_bounds = (min(planner.MAX_BYTES, len(custody)),
        min(planner.MAX_BYTES, len(response[1])))
    nested = (sum(min(maximum, len(response[1]))
            for maximum in (server.custody.MAX_BYTES, server.storage.MAX_BYTES,
                server.recovery.MAX_BYTES))
        + sum(size + min(planner.vector.MAX_BYTES, size)
            + min(authorization.MAX_ENROLLMENT_BYTES, size) for size in planner_bounds)
        + outcomes.MAX_BYTES)
    originals = (*request, *response, *independent)
    held = _unique_bytes(originals)
    # Original-byte capacity and cumulative charged work are separate limits.
    # Also retain conservative custody/canonical capture and response-readback
    # capacity. Shared derivation reserves its read-only outcome/raw8 path;
    # grant-generation output capacity belongs to the separate producer.
    other = _unique_bytes((*request, policy, proof_enrollment, intent_enrollment))
    reserved = max(held + nested,
        8 * len(custody) + 4 * other + 2 * _unique_bytes(response) + nested)
    if MAX_ORIGINAL_BYTES != 64 * 1024 * 1024 or reserved > MAX_ORIGINAL_BYTES:
        _fail("recovery grant admission exceeds its complete retained-original capacity")
    work.charge(input_bytes=sum(map(len, originals)))
    return reserved


def _verify_on_work(*, response_originals, request_originals, issuer_policy_bytes,
        release_custody_bytes, proof_enrollment_bytes, intent_enrollment_bytes,
        root_public_key, live_window, transport_deadline_ns, work, _continuity=None):
    """Authenticate fresh recovery originals against independent original pins.

    Request input is prefix7, without an outcome. Genuine historical admission
    reconstructs that token-free record and the actual recovery raw8 identity.
    Neither the reconstruction nor a signed checkpoint proves storage exists.
    """
    capture._SharedLedger(work)
    response = _originals(response_originals)
    request = production._request_originals(request_originals)
    policy_raw = authorization._original(issuer_policy_bytes, issuer.MAX_BYTES,
        "independent recovery issuer policy")
    custody_raw = authorization._original(release_custody_bytes, issuer.MAX_CUSTODY_BYTES,
        "independent historical release custody")
    proof_raw = authorization._original(proof_enrollment_bytes, issuer.MAX_PROOF_ENROLLMENT_BYTES,
        "independent recovery proof enrollment")
    intent_raw = authorization._original(intent_enrollment_bytes, issuer.MAX_INTENT_ENROLLMENT_BYTES,
        "independent recovery intent enrollment")
    reserved = _reserve(request, response, (policy_raw, custody_raw, proof_raw, intent_raw), work)
    root = root_public_key
    actual_request, policy, record, storage_scope, recovery_scope, request_identity, lifetime = (
        production._derive_on_work(request_originals=request, issuer_policy_bytes=policy_raw,
            release_custody_bytes=custody_raw, proof_enrollment_bytes=proof_raw,
            intent_enrollment_bytes=intent_raw, root_public_key=root, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, work=work, _continuity=_continuity))
    if type(policy) is not issuer._IssuerPolicyMaterial:
        _fail("recovery grant admission requires genuine original policy derivation")
    current = lifetime.current
    current()
    production.shared._same_bytes(response[2], record, work,
        "returned exact independently reconstructed recovery outcome")
    current()
    # No old-token request tuple becomes a result field or retained closure.
    del actual_request, request, request_originals
    payload = policy.payload
    expected = {**payload["proofScope"],
        "serverBootstrapDigest": clients._server_bootstrap_digest_on_work(response[1], work),
        "profile": clients.RECOVERY_PROFILE,
        "requestIdentity": request_identity.decode("ascii"),
        "clientId": policy.client_id, "clientIdentity": policy.client_identity,
        "callerId": payload["callerId"],
        "stateReceiptDigest": payload["expectedEvidence"]["stateReceiptDigest"],
        "expectedRelease": payload["expectedRelease"],
        "expectedOutcomeDigest": payload["expectedOutcomeDigest"],
        "endpoint": payload["endpoint"]}
    current()
    # These finite original-derived graphs contain no private configuration or
    # arbitrary mappings. Reserve both comparison encodings before producing any.
    graphs = (expected, storage_scope, recovery_scope, policy.release_launch)
    graph_bytes = sum(work.measure(graph)[0] for graph in graphs)
    if reserved + 4 * graph_bytes > MAX_ORIGINAL_BYTES:
        _fail("recovery grant scope comparisons exceed the retained-original capacity")
    current()
    admitted = clients._verify_on_work(authorization_bytes=response[0],
        server_bootstrap_bytes=response[1], root_public_key=root, expected_scope=expected,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _continuity=lifetime.continuity)
    if (type(admitted) is not clients._ClientAuthorization
            or type(admitted.server_material) is not server._ReleaseMaterial):
        _fail("recovery grant admission requires genuine client and nested server originals")
    lifetime.attach(admitted.live)
    lifetime.adopt(admitted.live_window, admitted.deadline_ns)
    material = admitted.server_material
    current()
    production.shared._same_bytes(material.custody_bytes, custody_raw, work,
        "recovery server exact independent custody original")
    current()
    for actual, wanted, label in (
            (material.profile, server.RECOVERY_PROFILE, "recovery-only profile"),
            (material.storage_scope, storage_scope, "checkpoint-one storage scope"),
            (material.recovery_scope, recovery_scope, "independent recovery scope"),
            (material.launch, policy.release_launch, "independent launch resources"),
            (material.expected_release, payload["expectedRelease"], "independent release")):
        plan._same(actual, wanted, work, "recovery grant " + label)
        current()
    policy_interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    server._contains(material.attestation_interval, policy_interval)
    server._contains((admitted.payload["issuedAtEpochNs"],
        admitted.payload["expiresAtEpochNs"]), policy_interval)
    current()
    return _RecoveryGrantMaterial(response[0], response[1], response[2], admitted, policy,
        lifetime.window, lifetime.bound, current)
