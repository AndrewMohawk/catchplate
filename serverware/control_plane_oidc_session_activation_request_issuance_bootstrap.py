"""Explicit planning/v2 cold selection; no future planner or success carrier."""
from __future__ import annotations

from dataclasses import dataclass

from serverware import oidc_session_activation_request_issuance_policy as policy
from serverware import authority_oidc_session_activation_request_issuance_transport as transport


SCHEMA = "serverware.controlPlaneOidcSessionActivationPlanning/v2"
FIELDS = frozenset({"schema", "issuancePolicy", "issuanceEndpoint", "plannerEndpoint"})
_ENDPOINT_FIELDS = frozenset({"socketPath", "requestTimeoutSeconds", "listenerUid", "listenerGid"})


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _RequestPlanningMaterial:
    policy_bytes: bytes
    issuance_endpoint: tuple
    planner_endpoint: tuple


def _shape(value):
    from serverware import control_plane_oidc_session_activation_planning_bootstrap as old
    policy.shape._object(value, FIELDS, "request-bound activation planning")
    policy.shape._literal(value["schema"], SCHEMA)
    original = value["issuancePolicy"]
    policy.shape._object(original, frozenset({"base64Url", "byteCount"}), "static issuance policy original")
    policy.authorization.transport._transport_shape(original["base64Url"], original["byteCount"], policy.MAX_BYTES)
    _endpoint(value["issuanceEndpoint"])
    old._endpoint(value["plannerEndpoint"])


def _endpoint(value):
    policy.shape._object(value, _ENDPOINT_FIELDS, "request issuer endpoint")
    return transport._endpoint(tuple(value[name] for name in (
        "socketPath", "requestTimeoutSeconds", "listenerUid", "listenerGid")))


def _admit_on_work(*, planning, configuration_payload, configuration_digest,
        generation, runtime_role_identities, runtime_root_public_key,
        activation_execution, work, live_window, transport_deadline_ns):
    from serverware import control_plane_oidc_session_activation_planning_bootstrap as old
    execution = old.execution
    if type(activation_execution) is not execution._ActivationExecutionMaterial:
        raise policy.RequestIssuancePolicyError("request planning requires its actual separately admitted caller")
    _shape(planning)
    owned = policy._capture({"planning": planning, "configuration": configuration_payload,
        "generation": {name: generation[name] for name in policy.configuration._GENERATION_FIELDS},
        "runtime": runtime_role_identities}, work)
    selected = owned["planning"]
    _shape(selected)
    wrapped = selected["issuancePolicy"]
    raw = policy.authorization.transport._decode(wrapped["base64Url"], wrapped["byteCount"], policy.MAX_BYTES, work)
    admitted = policy._verify_on_work(policy_bytes=raw, root_public_key=runtime_root_public_key,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    configured, launch, runtime, public, enrollment, _digest, _reader = admitted.resource_facts
    for actual, expected, label in ((configured, owned["configuration"], "configuration"),
            (launch, owned["generation"], "generation"), (runtime, owned["runtime"], "runtime cohort")):
        old._same_configuration(actual, expected, work, "request issuer differs from actual parent " + label)
    policy.plan._same(admitted.payload["plannerResources"]["configurationDigest"], configuration_digest,
        work, "request issuer parent configuration identity")
    for actual, expected in ((enrollment, activation_execution.current_root_enrollment_bytes),
            (admitted.authorization_enrollment, activation_execution.authorization_enrollment_bytes),
            (admitted.grant_enrollment, activation_execution.grant_enrollment_bytes)):
        work.charge(input_bytes=len(actual) + len(expected))
        if actual != expected:
            raise policy.RequestIssuancePolicyError("request issuer changed an actual parent purpose enrollment")
    for actual, expected in ((public, activation_execution.planner_public_key),
            (admitted.caller.caller_public_key, activation_execution.caller_public_key),
            (runtime_root_public_key, activation_execution.operation_public_key)):
        policy.plan._same(policy.keys._spki_on_work(actual, work), policy.keys._spki_on_work(expected, work),
            work, "request issuer differs from an actual parent public key")
    endpoint = old._endpoint(selected["plannerEndpoint"])
    if endpoint[1] > admitted.payload["plannerResources"]["launch"]["requestTimeoutSeconds"]:
        raise policy.RequestIssuancePolicyError("request planner endpoint widens its source launch timeout")
    admitted.live()
    return _RequestPlanningMaterial(raw, _endpoint(selected["issuanceEndpoint"]), endpoint)
