"""Original-only receiving admission for request-derived consume inputs.

An issuer response is not proof of its own expected target or resource policy.
This receiver re-derives those expectations from independently held originals,
then genuinely authenticates both returned root originals. It loads no private
key, opens no token, provisions no resource and creates no execution permission.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_oidc_session_activation_consume_input_production as production
from serverware import authority_oidc_session_activation_consume_input_transport as transport
from serverware import oidc_session_activation_consume_input_issuer_policy as issuer
from serverware import oidc_session_activation_delivery_planner_bootstrap as planner


authorization, capture, history = issuer.authorization, issuer.capture, planner.history
MAX_ORIGINAL_BYTES = issuer.MAX_ORIGINAL_BYTES


class OidcSessionActivationConsumeInputAdmissionError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationConsumeInputAdmissionError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _InputMaterial:
    """Same-call derived output; never accepted instead of signed originals."""

    planner_bootstrap_bytes: bytes
    history_custody_bytes: bytes
    planner_material: planner._PlannerMaterial
    issuer_policy_material: issuer._IssuerPolicyMaterial
    live_window: tuple
    deadline_ns: int
    live: object


def _verify_on_work(*, response_originals, request_originals, issuer_policy_bytes,
        activation_planner_bootstrap_bytes, root_public_key, live_window,
        transport_deadline_ns, work, _continuity=None, _additional_original_bytes=0):
    """Re-admit independent policy/evidence before comparing the actual reply."""
    response = transport._originals(response_originals, response=True)
    if type(request_originals) is not tuple or len(request_originals) != 16:
        _fail("consume input admission requires the exact original request suffix16")
    request = transport._originals((transport.PURPOSE, *request_originals), response=False)[1:]
    original = authorization._original(response[0], planner.MAX_BYTES, "issued consume planner")
    custody_original = authorization._original(response[1], history.MAX_BYTES, "issued consume history")
    policy_original = authorization._original(issuer_policy_bytes, issuer.MAX_BYTES,
        "independent consume input issuer policy")
    activation_original = authorization._original(activation_planner_bootstrap_bytes,
        issuer.MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES, "independent activation planner")
    root, continuation = root_public_key, _continuity
    original_bytes = sum(map(len, (*request, original, custody_original, policy_original, activation_original)))
    captures = production._derivation_reservation(tuple(map(len, request)),
        len(policy_original), len(activation_original)) + 24 * (len(original) + len(custody_original))
    if (type(_additional_original_bytes) is not int
            or not 0 <= _additional_original_bytes < MAX_ORIGINAL_BYTES
            or _additional_original_bytes + captures > MAX_ORIGINAL_BYTES):
        _fail("consume input response and held captures exceed their whole inventory")
    capture._SharedLedger(work)
    work.charge(input_bytes=original_bytes)
    # This helper performs actual original policy, caller/grant, reservation,
    # completion and possession admission. It accepts no successful carrier.
    policy, lifetime, expected_history, expected_planner = production._derive_on_work(
        request_originals=request, issuer_policy_bytes=policy_original,
        activation_planner_bootstrap_bytes=activation_original, root_public_key=root,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns,
        work=work, _continuity=continuation,
        _additional_original_bytes=_additional_original_bytes
            + 24 * (len(original) + len(custody_original)))
    current = lifetime.current
    current()
    expected_planner = production._bind_history_on_work(expected_planner,
        custody_original, work, current)
    material = planner._verify_on_work(bootstrap_bytes=original,
        history_custody_bytes=custody_original, root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        work=work, _continuity=lifetime.continuity)
    current()
    if (type(material) is not planner._PlannerMaterial
            or type(material.history_material) is not history._HistoryCustodyMaterial):
        _fail("consume input admission requires actual live-purpose root verifiers")
    # The genuine planner verifier has authenticated this exact custody original
    # and its nested activation bootstrap. Decoding again is only comparison.
    history_envelope = history._decode(custody_original, work)
    history._canonical(custody_original, history_envelope, work)
    actual_history = history_envelope["payload"]
    graph_bytes = sum(work.measure(value)[0] for value in (expected_history, actual_history))
    for value in (expected_planner, material.payload):
        measured = planner.configuration._ConfigurationCapture(capture._SharedLedger(work),
            maximum_bytes=planner.MAX_BYTES, retain=False)
        measured.visit(value)
        graph_bytes += measured.bytes
    decoded = (material.consume_request_bytes, material.complete_root_vector_bytes,
        material.state_enrollment_bytes, material.history_material.planner.bootstrap_bytes,
        material.history_material.planner.complete_root_vector_bytes,
        material.history_material.planner.state_enrollment_bytes)
    # Reserve comparison encodings as well as the retained graph originals
    # before making either pair of canonical byte buffers.
    if original_bytes + 2 * graph_bytes + sum(map(len, decoded)) > captures:
        _fail("consume input decoded and compared originals exceed the whole inventory")
    current()
    for actual, expected, encode, label in (
            (actual_history, expected_history, lambda value: history._wire(value, work), "history"),
            (material.payload, expected_planner,
                lambda value: planner.configuration._configuration_wire(value, capture._SharedLedger(work)),
                "planner")):
        actual_bytes, expected_bytes = encode(actual), encode(expected)
        work.charge(input_bytes=len(actual_bytes) + len(expected_bytes))
        if actual_bytes != expected_bytes:
            _fail("consume input " + label + " differs from independently derived complete payload")
        current()

    def live():
        current()
        for nested in (material, material.history_material):
            observed = planner.shared._fresh(nested.attestation_interval, work,
                opening=nested.opening_sample)
            if observed[1] < lifetime.epoch or observed[0] < lifetime.monotonic:
                _fail("consume input original lifetime reversed after admission")
            lifetime.continuity(observed[1], observed[2])
        return current()

    live()
    return _InputMaterial(original, custody_original, material, policy,
        lifetime.window, lifetime.bound, live)
