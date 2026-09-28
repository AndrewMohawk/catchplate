"""Root-original consume pair admission for fixed private resource staging.

Independent policy supplies every static resource/configuration expectation.
The issued pair supplies root-signed dynamic request data, not proof that this
receiver independently replayed raw16, observed old-token possession, or ran a
worker. Actual request admission and private replay remain separate gates.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_oidc_session_activation_consume_input_production as producer
from serverware import authority_oidc_session_activation_consume_input_delivery_transport as transport


issuer, planner, history = producer.issuer, producer.bootstrap, producer.history
authorization, shape, plan = issuer.authorization, issuer.shape, issuer.plan
capture, clock, state = issuer.capture, issuer.clock, producer.state
MAX_ORIGINAL_BYTES = issuer.MAX_ORIGINAL_BYTES
# Whole-call capacity, not a replacement work allowance. Covers bounded owned
# graphs, nested originals and the two comparison encodings before admission.
DECODED_RESERVATION_BYTES = (3 * planner.MAX_BYTES + 2 * history.MAX_BYTES
    + 2 * issuer.MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES
    + 2 * history.MAX_CONSUME_REQUEST_BYTES + 4 * state.MAX_ENROLLMENT_BYTES
    + 4 * state.vector.MAX_BYTES + 4 * issuer.V1_MAX_BYTES)


class ConsumeInputDeliveryAdmissionError(ValueError):
    pass


def _fail(message):
    raise ConsumeInputDeliveryAdmissionError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _DeliveryMaterial:
    """Same-call original-derived output; never accepted as admission input."""

    planner_bootstrap_bytes: bytes
    history_custody_bytes: bytes
    planner_material: planner._PlannerMaterial
    issuer_policy_material: issuer._IssuerPolicyMaterial
    planner_identity: bytes
    history_identity: bytes
    live_window: tuple
    deadline_ns: int
    live: object


def _same_graph(actual, expected, work, current, label):
    current()
    encode = planner.configuration._configuration_wire
    actual_bytes = encode(actual, capture._SharedLedger(work))
    expected_bytes = encode(expected, capture._SharedLedger(work))
    producer._same_bytes(actual_bytes, expected_bytes, work, label)
    current()


def _verify_on_work(*, planner_bootstrap_bytes, history_custody_bytes, issuer_policy_bytes,
        activation_planner_bootstrap_bytes, root_public_key, live_window,
        transport_deadline_ns, work, _continuity=None):
    """Authenticate the exact issued pair and all independently derivable pins."""
    root, continuation = root_public_key, _continuity
    original = authorization._original(planner_bootstrap_bytes, planner.MAX_BYTES,
        "staged consume planner bootstrap")
    custody = authorization._original(history_custody_bytes, history.MAX_BYTES,
        "staged consume history custody")
    policy_original = authorization._original(issuer_policy_bytes, issuer.MAX_BYTES,
        "independent consume staging policy")
    activation_original = authorization._original(activation_planner_bootstrap_bytes,
        issuer.MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES, "independent activation planner")
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(window[4], transport_deadline_ns)
    original_bytes = sum(map(len, (original, custody, policy_original, activation_original)))
    bridge_capture = 8 * max(0, len(policy_original) - issuer.V1_MAX_BYTES)
    if original_bytes + DECODED_RESERVATION_BYTES + bridge_capture > MAX_ORIGINAL_BYTES:
        _fail("consume staging exceeds its complete original and decoded inventory")
    capture._SharedLedger(work)
    work.charge(input_bytes=original_bytes)
    authorization._public(root)
    # Only reuse source-private ledger/clock bookkeeping, never a successful
    # producer result or the request-dependent producer derivation as authority.
    lifetime = producer._Lifetime(window, bound, work, continuation)
    current = lifetime.current
    current()
    policy = issuer._verify_on_work(policy_bytes=policy_original,
        activation_planner_bootstrap_bytes=activation_original, root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        work=work, _continuity=lifetime.continuity)
    if type(policy) is not issuer._IssuerPolicyMaterial:
        _fail("consume staging requires genuine independent policy admission")
    lifetime.attach(policy.live)
    lifetime.adopt(policy.live_window, policy.deadline_ns)
    activation, output = policy.activation_planner, policy.current_planner
    if type(activation) is not issuer.activation._PlannerMaterial:
        _fail("consume staging lacks the genuine policy-bound historical activation original")
    issued = policy.payload["issuedAtEpochNs"]
    expires = min(policy.payload["expiresAtEpochNs"],
        issued + min(output.maximum_plan_age_ns, issuer.activation.MAX_RECEIPT_AGE_NS))
    if issued >= expires:
        _fail("consume staging deterministic policy-derived interval is empty")
    lifetime.narrow(expires, min(activation.maximum_plan_age_ns, output.maximum_plan_age_ns),
        min(activation.maximum_clock_skew_ns, output.maximum_clock_skew_ns))
    current()
    material = planner._verify_on_work(bootstrap_bytes=original, history_custody_bytes=custody,
        root_public_key=root, live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        work=work, _continuity=lifetime.continuity)
    if (type(material) is not planner._PlannerMaterial
            or type(material.history_material) is not history._HistoryCustodyMaterial):
        _fail("consume staging requires the actual live-purpose planner and history verifiers")
    nested, payload = material.history_material, material.payload
    current()
    for actual, expected, label in (
            (material.bootstrap_bytes, original, "exact planner original"),
            (material.history_custody_bytes, custody, "exact history original"),
            (nested.custody_bytes, custody, "genuinely admitted history original"),
            (nested.planner.bootstrap_bytes, activation_original, "independent historical planner original"),
            (material.state_enrollment_bytes, output.state_enrollment_bytes, "current state enrollment original"),
            (material.consume_request_bytes, nested.consume_request_bytes, "paired consume request")):
        producer._same_bytes(actual, expected, work, "consume staging " + label)
        current()
    plan._same((nested.receiver_identity, nested.bundle_key_digest, nested.delivery_key_digest),
        (policy.history["receiverIdentity"], policy.history["bundleKeyDigest"],
            policy.history["deliveryKeyDigest"]), work, "consume staging independent history resource pins")
    plan._same((material.attestation_interval, nested.attestation_interval),
        ((issued, expires), (issued, expires)), work, "consume staging exact policy-derived intervals")
    current()
    expected_static = {
        **policy.consume_planner,
        "configurationPayload": output.configuration_payload,
        "configurationDigest": output.configuration_digest,
        "generation": output.generation,
        "runtimeRoleIdentities": output.runtime_role_identities,
        "runtimeClosureDigest": output.runtime_closure_digest,
        "authenticationPolicy": output.authn_policy,
        "trustPolicy": output.trust_policy,
        "maximumPlanAgeNs": output.maximum_plan_age_ns,
        "maximumClockSkewNs": output.maximum_clock_skew_ns,
        "historyReceiverIdentity": policy.history["receiverIdentity"],
        "queryManifestDigest": output.configuration_payload["queryManifestDigest"],
    }
    _same_graph({name: payload[name] for name in expected_static}, expected_static,
        work, current, "consume staging complete independent static planner configuration")
    # This independently admitted state original pins database/generation; do
    # not infer database identity from a DSN or incoming dynamic request graph.
    enrollment = state._admit_enrollment_on_work(enrollment_bytes=output.state_enrollment_bytes,
        root_public_key=root, work=work)
    current()
    plan._same((payload["databaseId"], payload["activationScope"]["databaseId"],
        payload["activationScope"]["generationDigest"], material.state_enrollment_digest),
        (enrollment.payload["databaseId"], enrollment.payload["databaseId"],
            activation.generation["digest"], output.state_enrollment_digest), work,
        "consume staging independently enrolled database and generation")
    predecessor = policy.activation_predecessor
    plan._same((payload["activationScope"]["pendingSequence"], payload["activationScope"]["fence"]),
        (predecessor[0] + 1, predecessor[2]), work, "consume staging independently pinned activation sequence and fence")
    expected_scope = {"configurationDigest": activation.configuration_digest,
        "plannerIdentity": activation.planner_identity, "plannerSpkiDigest": activation.planner_spki_digest,
        "rpId": activation.rp_id, "origin": activation.origin,
        "authenticationPolicy": activation.authn_policy, "trustPolicy": activation.trust_policy,
        "maximumPlanAgeNs": activation.maximum_plan_age_ns,
        "maximumClockSkewNs": activation.maximum_clock_skew_ns}
    scope = payload["activationExpectations"]["scope"]
    _same_graph({name: scope[name] for name in expected_scope}, expected_scope,
        work, current, "consume staging independently known activation scope")
    plan._same(payload["activationExpectations"]["request"]["arguments"]["delivery_ttl_seconds"],
        activation.delivery_ttl_seconds, work, "consume staging original activation delivery lifetime")
    current()

    def live():
        current()
        for selected in (material, nested):
            observed = planner.shared._fresh(selected.attestation_interval, work,
                opening=selected.opening_sample)
            if observed[1] < lifetime.epoch or observed[0] < lifetime.monotonic:
                _fail("consume staging original clock reversed after admission")
            lifetime.continuity(observed[1], observed[2])
        return current()

    live()
    identities = transport._pair_identities_on_work(original, custody,
        deadline_ns=lifetime.bound, work=work, current=live)
    live()
    return _DeliveryMaterial(original, custody, material, policy, *identities,
        lifetime.window, lifetime.bound, live)
