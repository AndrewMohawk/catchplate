"""Admit fresh consume-planner originals inside an existing live continuation.

Cold configuration pins only the endpoint and stable public key/measurement.
The exact consume request depends on completed activation, so its independently
root-signed planner/history originals arrive later, never as guessed cold pins.
No private key, fresh processing allowance, permission or successful carrier is
accepted or created here. The caller must still join the actual target originals.
"""
from __future__ import annotations

from serverware import control_plane_oidc_session_activation_execution_bootstrap as execution
from serverware import control_plane_oidc_session_activation_planning_bootstrap as canonical
from serverware import oidc_session_activation_delivery_planner_bootstrap as planner


configuration, shape, capture, plan = planner.configuration, planner.shape, planner.capture, planner.plan
MAX_BYTES = planner.authority.MAX_REQUEST_BYTES


class OidcSessionActivationConsumeBootstrapError(ValueError):
    pass


def _same_bytes(actual, expected, work, label):
    work.charge(input_bytes=len(actual) + len(expected))
    if actual != expected:
        raise OidcSessionActivationConsumeBootstrapError(label)


def _admit_on_work(*, planner_bootstrap_bytes, history_custody_bytes,
        configuration_payload, configuration_digest, generation, runtime_role_identities,
        runtime_root_public_key, activation_execution, live_window, transport_deadline_ns, work):
    """Authenticate actual root originals, not a cached bootstrap result.

    The actual parent supplies its immutable key references and public original
    configuration. Returned material is this call's ordinary derived data; it
    is never an alternative input to root or target admission.
    """
    try:
        ledger = capture._SharedLedger(work)
        root, digest, caller = runtime_root_public_key, configuration_digest, activation_execution
        if (type(caller) is not execution._ActivationExecutionMaterial
                or caller.consume_planner_endpoint is None
                or caller.consume_planner_public_key is None
                or caller.consume_planner_measurement_digest is None):
            raise OidcSessionActivationConsumeBootstrapError("consume planning is not explicitly configured")
        raw = planner.authorization._original(planner_bootstrap_bytes,
            planner.MAX_BYTES, "consume planner bootstrap")
        history = planner.authorization._original(history_custody_bytes,
            planner.history.MAX_BYTES, "consume history bootstrap")
        planner.authorization._public(root)
        planner.authorization._public(caller.consume_planner_public_key)
        shape._digest(digest)
        shape._bounded_object(generation, 24, "consume actual parent generation")
        window = planner.clock._validate(live_window)
        shape._integer(transport_deadline_ns, minimum=1)
        bound = min(window[4], transport_deadline_ns)
        owned = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "configuration": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtime": runtime_role_identities})
        current = planner.shared._processing(window, bound, work)
        current()
        configured, launch = configuration._capture_configuration_on_work(
            payload=owned["configuration"], configuration_digest=digest,
            generation=owned["generation"], work=work)
        identities = configuration._capture_runtime_role_identities_on_work(
            runtime_role_identities=owned["runtime"], owned_payload=configured,
            configuration_digest=digest, launch=launch, work=work)
        current()
        material = planner._verify_on_work(bootstrap_bytes=raw, history_custody_bytes=history,
            root_public_key=root, live_window=window, transport_deadline_ns=bound, work=work)
        if current() < material.opening_sample[1]:
            raise OidcSessionActivationConsumeBootstrapError("consume clock reversed across root admission")
        historical_planner = material.history_material.planner
        canonical._same_configuration(historical_planner.configuration_payload, configured, work,
            "consume configuration differs from the actual parent original")
        canonical._same_configuration(historical_planner.generation, launch, work,
            "consume generation differs from the actual parent original")
        canonical._same_configuration(historical_planner.runtime_role_identities, identities, work,
            "consume runtime cohort differs from the actual parent original")
        plan._same(material.payload["configurationDigest"], digest, work,
            "consume actual parent configuration identity")
        keys = execution.caller.keys
        for actual, expected, label in (
                (keys._spki_on_work(material.planner_public_key, work),
                    keys._spki_on_work(caller.consume_planner_public_key, work), "consume planner key"),
                (material.payload["planner"]["identity"]["measurementDigest"],
                    caller.consume_planner_measurement_digest, "consume planner measurement"),
                (historical_planner.planner_spki_digest,
                    keys._spki_on_work(caller.planner_public_key, work), "original activation planner key"),
                (keys._spki_on_work(caller.operation_public_key, work),
                    keys._spki_on_work(root, work), "actual operation root")):
            plan._same(actual, expected, work, label)
        _same_bytes(material.state_enrollment_bytes, caller.current_root_enrollment_bytes,
            work, "consume and activation require the same original state enrollment")
        if caller.consume_planner_endpoint[1] > material.payload["launch"]["requestTimeoutSeconds"]:
            raise OidcSessionActivationConsumeBootstrapError("consume endpoint exceeds its original launch timeout")
        current()
        observed = planner.shared._fresh(material.attestation_interval, work,
            opening=material.opening_sample)
        if current() < observed[1]:
            raise OidcSessionActivationConsumeBootstrapError("consume clock reversed after actual scope joins")
        return material
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, OidcSessionActivationConsumeBootstrapError):
            raise
        raise OidcSessionActivationConsumeBootstrapError("consume root-original admission failed") from exc
