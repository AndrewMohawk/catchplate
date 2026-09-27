"""Root-original planning configuration inside explicit control-plane v7.

This public-only lane supplies no plan, permission, private key or descriptor.
Its genuine cold original admission is not a request-time freshness result:
the caller must reverify the same originals under its original live allowance.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import control_plane_oidc_session_activation_execution_bootstrap as execution
from serverware import oidc_session_activation_planner_bootstrap as planner


SCHEMA = "serverware.controlPlaneOidcSessionActivationPlanning/v1"
MAX_BYTES = planner.authority.MAX_REQUEST_BYTES
_FIELDS = frozenset({"schema", "plannerBootstrap", "plannerEndpoint"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount"})
_ENDPOINT_FIELDS = frozenset({"socketPath", "requestTimeoutSeconds", "listenerUid", "listenerGid"})
configuration, shape, capture, plan = planner.configuration, planner.shape, planner.capture, planner.plan


class OidcSessionActivationPlanningBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _PlanningMaterial:
    """Immutable original configuration; never accepted as proof of a plan."""

    planner_bootstrap_bytes: bytes
    planner_endpoint: tuple


def _endpoint(value):
    shape._object(value, _ENDPOINT_FIELDS, "activation planner endpoint")
    shape._literal(value["socketPath"], planner.LISTENER_PATH)
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name in ("listenerUid", "listenerGid"):
        shape._integer(value[name], 2**32 - 2)
        if value[name] != 0:
            raise OidcSessionActivationPlanningBootstrapError(
                "activation planner listener must be the fixed root-created peer")
    return value["socketPath"], value["requestTimeoutSeconds"], 0, 0


def _shape(value):
    if value is None:
        return
    shape._object(value, _FIELDS, "control-plane activation planning")
    shape._literal(value["schema"], SCHEMA)
    original = value["plannerBootstrap"]
    shape._object(original, _ORIGINAL_FIELDS, "activation planner bootstrap original")
    shape._integer(original["byteCount"], planner.MAX_BYTES, minimum=2)
    planner.authorization.transport._transport_shape(
        original["base64Url"], original["byteCount"], planner.MAX_BYTES)
    _endpoint(value["plannerEndpoint"])


def _same_configuration(actual, expected, work, label):
    # Configuration originals admit finite floats; do not route them through
    # an integer-only proof JSON codec or compare a successful material DTO.
    left = configuration._configuration_wire(actual, capture._SharedLedger(work))
    right = configuration._configuration_wire(expected, capture._SharedLedger(work))
    work.charge(input_bytes=len(left) + len(right))
    if left != right:
        raise OidcSessionActivationPlanningBootstrapError(label)


def _admit_on_work(*, planning, configuration_payload, configuration_digest,
        generation, runtime_role_identities, runtime_root_public_key,
        activation_execution, work, live_window=None, transport_deadline_ns=None):
    """Verify original root/config/key joins on the supplied work only.

    A request caller supplies both original processing arguments. The cold
    parent has no request allowance; the real planner verifier then applies
    its actual signed launch freshness without manufacturing request authority.
    """
    try:
        ledger = capture._SharedLedger(work)
        root, digest, caller = runtime_root_public_key, configuration_digest, activation_execution
        _shape(planning)
        if planning is None:
            return None
        if type(caller) is not execution._ActivationExecutionMaterial:
            raise OidcSessionActivationPlanningBootstrapError(
                "activation planning requires the separately configured caller lane")
        caller_key, planner_key, operation_key = (
            caller.caller_public_key, caller.planner_public_key, caller.operation_public_key)
        caller_originals = (caller.authorization_enrollment_bytes,
            caller.current_root_enrollment_bytes, caller.grant_enrollment_bytes)
        planner.authorization._public(root)
        shape._digest(digest)
        shape._bounded_object(generation, 24, "activation planning parent generation")
        if (live_window is None) != (transport_deadline_ns is None):
            raise OidcSessionActivationPlanningBootstrapError(
                "activation planning requires the complete original processing pair")
        owned = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "planning": planning, "configuration": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtime": runtime_role_identities})
        value = owned["planning"]
        _shape(value)
        original = value["plannerBootstrap"]
        raw = planner.authorization.transport._decode(original["base64Url"],
            original["byteCount"], planner.MAX_BYTES, work)
        endpoint = _endpoint(value["plannerEndpoint"])
        current = planner._processing(live_window, transport_deadline_ns, work)
        current()
        configured, launch = configuration._capture_configuration_on_work(
            payload=owned["configuration"], configuration_digest=digest,
            generation=owned["generation"], work=work)
        identities = configuration._capture_runtime_role_identities_on_work(
            runtime_role_identities=owned["runtime"], owned_payload=configured,
            configuration_digest=digest, launch=launch, work=work)
        current()
        material = planner._verify_on_work(bootstrap_bytes=raw, root_public_key=root,
            live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
        if current() < material.opening_sample[1]:
            raise OidcSessionActivationPlanningBootstrapError(
                "activation planning clock reversed across nested original admission")
        _same_configuration(material.configuration_payload, configured, work,
            "planner configuration differs from the actual parent original")
        _same_configuration(material.generation, launch, work,
            "planner generation differs from the actual parent original")
        _same_configuration(material.runtime_role_identities, identities, work,
            "planner runtime cohort differs from the actual parent original")
        plan._same(material.configuration_digest, digest, work,
            "activation planner configuration identity")
        keys = execution.caller.keys
        plan._same(material.planner_spki_digest, keys._spki_on_work(planner_key, work),
            work, "activation planner differs from the enrolled caller's planner key")
        plan._same(keys._spki_on_work(operation_key, work), keys._spki_on_work(root, work),
            work, "activation planning operation key is not the actual runtime root")
        admitted = execution.caller._admit_enrollment_on_work(
            authorization_enrollment_bytes=caller_originals[0],
            current_root_enrollment_bytes=caller_originals[1],
            grant_enrollment_bytes=caller_originals[2], root_public_key=root,
            configuration_digest=digest, planner_public_key=planner_key,
            operation_public_key=operation_key, work=work)
        plan._same(keys._spki_on_work(admitted.caller_public_key, work),
            keys._spki_on_work(caller_key, work), work, "activation planning caller key")
        plan._same(admitted.payload["generationDigest"], launch["digest"], work,
            "activation planning caller generation")
        work.charge(input_bytes=len(material.state_enrollment_bytes) + len(caller_originals[1]))
        if material.state_enrollment_bytes != caller_originals[1]:
            raise OidcSessionActivationPlanningBootstrapError(
                "activation planner and caller require the same original state enrollment")
        if endpoint[1] > material.launch["requestTimeoutSeconds"]:
            raise OidcSessionActivationPlanningBootstrapError(
                "activation planner endpoint exceeds its original launch timeout")
        current()
        observed = planner._fresh(material.attestation_interval, work, opening=material.opening_sample)
        if current() < observed[1]:
            raise OidcSessionActivationPlanningBootstrapError(
                "activation planning clock reversed after original scope joins")
        return _PlanningMaterial(raw, endpoint)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, OidcSessionActivationPlanningBootstrapError):
            raise
        raise OidcSessionActivationPlanningBootstrapError(
            "control-plane activation planning configuration failed") from exc
