"""Admit fresh consume-planner originals inside an existing live continuation.

Cold configuration pins only the endpoint and stable public key/measurement.
The exact consume request depends on completed activation, so its independently
root-signed planner/history originals arrive later, never as guessed cold pins.
No private key, fresh processing allowance, permission or successful carrier is
accepted or created here. The caller must still join the actual target originals.
"""
from __future__ import annotations

from catchplate import control_plane_oidc_session_activation_execution_bootstrap as execution
from catchplate import control_plane_oidc_session_activation_consume_execution_bootstrap as consume_execution_source
from catchplate import control_plane_oidc_session_activation_planning_bootstrap as canonical
from catchplate import oidc_session_activation_consume_input_issuer_policy as issuer
from catchplate import oidc_session_activation_delivery_planner_bootstrap as planner


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


def _admit_bridge_on_work(*, planner_bootstrap_bytes, history_custody_bytes,
        configuration_payload, configuration_digest, generation, runtime_role_identities,
        runtime_root_public_key, activation_execution, consume_execution,
        historical_activation_execution, historical_root_public_key,
        activation_planner_bootstrap_bytes, issuer_policy_bytes,
        live_window, transport_deadline_ns, work):
    """Re-admit v3/v7 originals under current issuance and old evidence pins.

    Neither a prior receiving result nor an unsigned old-root locator supplies
    authority. The actual signed planner/history pair re-admits its embedded
    current-root policy, then joins both contexts to independently held pins.
    """
    try:
        ledger = capture._SharedLedger(work)
        root, old_root = runtime_root_public_key, historical_root_public_key
        current_policy, old_policy = activation_execution, historical_activation_execution
        if (type(current_policy) is not execution._ActivationExecutionMaterial
                or type(old_policy) is not execution._ActivationExecutionMaterial
                or type(consume_execution) is not consume_execution_source._ConsumeExecutionMaterial
                or current_policy.consume_planner_endpoint is None
                or current_policy.consume_planner_public_key is None
                or current_policy.consume_planner_measurement_digest is None):
            raise OidcSessionActivationConsumeBootstrapError("bridged consume requires independent old and current lanes")
        raw = planner.authorization._original(planner_bootstrap_bytes,
            planner.MAX_BYTES, "bridged consume planner original")
        history = planner.authorization._original(history_custody_bytes,
            planner.history.MAX_BYTES, "bridged consume history original")
        policy_original = planner.authorization._original(issuer_policy_bytes,
            issuer.MAX_BYTES, "independent bridged issuer policy")
        old_original = planner.authorization._original(activation_planner_bootstrap_bytes,
            issuer.MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES, "independent old activation planner")
        for key in (root, old_root, current_policy.consume_planner_public_key,
                consume_execution.planner_public_key, old_policy.planner_public_key,
                old_policy.operation_public_key):
            planner.authorization._public(key)
        shape._digest(configuration_digest)
        shape._bounded_object(generation, 24, "bridged consume actual current generation")
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
            payload=owned["configuration"], configuration_digest=configuration_digest,
            generation=owned["generation"], work=work)
        identities = configuration._capture_runtime_role_identities_on_work(
            runtime_role_identities=owned["runtime"], owned_payload=configured,
            configuration_digest=configuration_digest, launch=launch, work=work)
        current()
        material = planner._verify_on_work(bootstrap_bytes=raw, history_custody_bytes=history,
            root_public_key=root, live_window=window, transport_deadline_ns=bound, work=work)
        if current() < material.opening_sample[1]:
            raise OidcSessionActivationConsumeBootstrapError("bridged consume admission clocks reversed")
        shape._literal(material.payload["schema"], planner.BRIDGE_PAYLOAD_SCHEMA)
        nested = material.history_material
        if (type(nested) is not planner.history._HistoryCustodyMaterial
                or type(nested.bridge_policy) is not issuer._IssuerPolicyMaterial
                or nested.bridge_policy.bridge is None):
            raise OidcSessionActivationConsumeBootstrapError("bridged consume lacks its actual signed history policy")
        policy, old = nested.bridge_policy, nested.planner
        output = policy.current_planner
        _same_bytes(policy.policy_bytes, policy_original, work, "bridged consume changed its independent issuer policy")
        _same_bytes(old.bootstrap_bytes, old_original, work, "bridged consume changed its historical planner")
        _same_bytes(policy.activation_planner_bootstrap_bytes, old_original, work,
            "bridged consume policy changed its historical original")
        for actual, expected, label in ((output.configuration_payload, configured, "configuration"),
                (output.generation, launch, "generation"),
                (output.runtime_role_identities, identities, "runtime cohort")):
            canonical._same_configuration(actual, expected, work,
                "bridged consume current " + label + " differs from actual parent")
        plan._same(material.payload["configurationDigest"], configuration_digest, work,
            "bridged consume current configuration identity")
        keys = execution.caller.keys
        for actual, expected, label in (
                (keys._spki_on_work(nested.historical_root_public_key, work),
                    keys._spki_on_work(old_root, work), "selected historical root"),
                (keys._spki_on_work(policy.historical_root_public_key, work),
                    keys._spki_on_work(old_root, work), "independent historical policy root"),
                (old.planner_spki_digest, keys._spki_on_work(old_policy.planner_public_key, work),
                    "original activation planner key"),
                (keys._spki_on_work(old_policy.operation_public_key, work),
                    keys._spki_on_work(old_root, work), "original activation operation root"),
                (keys._spki_on_work(material.planner_public_key, work),
                    keys._spki_on_work(current_policy.consume_planner_public_key, work), "current consume planner key"),
                (keys._spki_on_work(material.planner_public_key, work),
                    keys._spki_on_work(consume_execution.planner_public_key, work), "current consume execution planner"),
                (material.payload["planner"]["identity"]["measurementDigest"],
                    current_policy.consume_planner_measurement_digest, "current consume measurement")):
            plan._same(actual, expected, work, "bridged consume " + label)
        _same_bytes(old.state_enrollment_bytes, old_policy.current_root_enrollment_bytes, work,
            "bridged consume historical state enrollment differs")
        _same_bytes(material.state_enrollment_bytes, consume_execution.current_root_enrollment_bytes,
            work, "bridged consume current state enrollment differs")
        if current_policy.consume_planner_endpoint[1] > material.payload["launch"]["requestTimeoutSeconds"]:
            raise OidcSessionActivationConsumeBootstrapError("bridged consume endpoint exceeds original launch timeout")
        current()
        observed = planner.shared._fresh(material.attestation_interval, work, opening=material.opening_sample)
        if current() < observed[1]:
            raise OidcSessionActivationConsumeBootstrapError("bridged consume scope clocks reversed")
        return material
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, OidcSessionActivationConsumeBootstrapError):
            raise
        raise OidcSessionActivationConsumeBootstrapError("bridged consume root-original admission failed") from exc
