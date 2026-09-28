"""Root-authorized, bounded cold bootstrap for the dedicated enrollment issuer.

This is an explicit additional purpose for the independently admitted runtime
root. The message is the ASCII result of the existing framed digest over the
canonical payload, under SCHEMA below; it is deliberately not the runtime
trust document's domain_digest protocol. A genuine signature over the original
canonical envelope precedes configuration, runtime-role and descriptor admission.
The embedded observations alone do not establish root or enclave provenance.

Both entrypoints use only the supplied work. The producer is for an independent
provisioner; it creates no key or descriptor. Admission returns privately owned
ordinary data, not a token accepted as proof by other components. The actual
trusted-host-local cold owner must admit the signed descriptor and real private
key against the returned issuer public pin. No descriptor, database, application,
transport or replacement allowance is opened here. Explicit v7 additionally
checks the nested planner's genuine launch freshness on this same work.
"""
from __future__ import annotations

import base64
import json
import math
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware import authority_contract as authority
from serverware import authority_revocation_configuration as configuration
from serverware import authority_revocation_writer_acknowledgment as keys
from serverware import authority_webauthn_enrollment_policy as enrollment_policy


capability = configuration.capability
capture, wire, plan, production = capability.capture, capability.wire, capability.plan, configuration.production
# v2 adds mandatory root-admitted endpoint authority. Do not silently accept
# a v1 payload under this exact shape, even with a current source revision.
SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v2"
PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v2"
V3_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v3"
V3_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v3"
V4_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v4"
V4_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v4"
V5_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v5"
V5_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v5"
V6_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v6"
V6_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v6"
V7_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v7"
V7_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v7"
V8_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v8"
V8_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v8"
V9_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v9"
V9_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v9"
V10_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v10"
V10_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v10"
V11_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v11"
V11_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v11"
V12_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v12"
V12_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v12"
V13_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v13"
V13_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v13"
V14_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v14"
V14_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v14"
V15_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v15"
V15_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v15"
V16_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v16"
V16_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v16"
V17_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v17"
V17_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v17"
V18_SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v18"
V18_PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v18"
MAX_BYTES = authority.MAX_REQUEST_BYTES
MAX_NODES = capture.MAX_TOTAL_JSON_NODES
MAX_DEPTH = capture.MAX_JSON_DEPTH
SIGNER_SOCKET_PATH = "/run/serverware/registration-evidence/signer.sock"
SIGNER_LISTENER_UID = SIGNER_LISTENER_GID = 0
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "configurationDigest",
    "configurationPayload", "generation", "runtimeRoleIdentities", "issuerPrivateKeyFd", "signerEndpoint"})
_V3_PAYLOAD_FIELDS = _PAYLOAD_FIELDS | frozenset({"registrationExecution"})
_V4_PAYLOAD_FIELDS = _V3_PAYLOAD_FIELDS | frozenset({"registrationFinalization"})
_V5_PAYLOAD_FIELDS = _V4_PAYLOAD_FIELDS | frozenset({"oidcSessionActivationRelease"})
_V6_PAYLOAD_FIELDS = _V5_PAYLOAD_FIELDS | frozenset({"oidcSessionActivationExecution"})
_V7_PAYLOAD_FIELDS = _V6_PAYLOAD_FIELDS | frozenset({"oidcSessionActivationPlanning"})
_V8_PAYLOAD_FIELDS = _V7_PAYLOAD_FIELDS | frozenset({"oidcSessionActivationConsumeExecution"})
_V9_PAYLOAD_FIELDS = _V8_PAYLOAD_FIELDS | frozenset({"oidcSessionActivationReleaseIntent"})
_V10_PAYLOAD_FIELDS = _V9_PAYLOAD_FIELDS | frozenset({"oidcSessionActivationReleaseProof"})
_V11_PAYLOAD_FIELDS = _V10_PAYLOAD_FIELDS | frozenset({"oidcSessionActivationReleaseHandoff"})
_V12_PAYLOAD_FIELDS = _V11_PAYLOAD_FIELDS | frozenset({"oidcSessionActivationReleaseGrantAcquisition"})
_V13_PAYLOAD_FIELDS = _V12_PAYLOAD_FIELDS | frozenset({"oidcSessionActivationConsumeInputAcquisition"})
_V14_PAYLOAD_FIELDS = _V13_PAYLOAD_FIELDS | frozenset({"oidcSessionActivationReleaseProofAcquisition"})
_V15_PAYLOAD_FIELDS = _V14_PAYLOAD_FIELDS | frozenset({"oidcSessionActivationReleaseRecoveryGrantAcquisition"})
_V16_PAYLOAD_FIELDS = _V15_PAYLOAD_FIELDS | frozenset({"oidcSessionActivationCompletionRecovery"})
_V17_PAYLOAD_FIELDS = _V16_PAYLOAD_FIELDS | frozenset({"registrationHistory"})
_V18_PAYLOAD_FIELDS = _V17_PAYLOAD_FIELDS | frozenset({"finalizationHistory"})
_ENDPOINT_FIELDS = frozenset({"socketPath", "requestTimeoutSeconds", "listenerUid", "listenerGid"})
_GENERATION_FIELDS = frozenset(configuration._GENERATION_FIELDS)
_NUMBER_BYTES = frozenset(b"0123456789.eE+-")


class EnrollmentBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _EnrollmentMaterial:
    """Owned cold inputs; construction alone proves no bootstrap admission."""

    configuration_payload: dict
    generation: dict
    runtime_role_identities: dict
    configuration_digest: str
    issuer_private_key_fd: int | None
    issuer_policy: dict | None
    issuer_public_key: object | None
    signer_endpoint: tuple | None
    execution: object | None = None
    finalization: object | None = None
    finalization_slot_reserved: bool = False
    release_client: object | None = None
    activation_execution: object | None = None
    activation_slot_reserved: bool = False
    activation_planning: object | None = None
    consume_execution: object | None = None
    consume_slot_reserved: bool = False
    release_intent: object | None = None
    intent_slot_reserved: bool = False
    release_proof: object | None = None
    release_handoff: object | None = None
    release_grant_acquisition: object | None = None
    consume_input_acquisition: object | None = None
    release_proof_acquisition: object | None = None
    release_recovery_grant_acquisition: object | None = None
    completion_recovery: object | None = None
    registration_history: object | None = None
    finalization_history: object | None = None


def _preflight(raw, work):
    """Reserve parsing with the existing lossless lexical rules plus floats.

    The service configuration permits finite fractional timeouts. Only this
    local configuration-containing wire admits float tokens; retained proof
    and control decoders remain integer-only. No input-sized token collection
    or graph is allocated before the original-work reservation.
    """
    work.charge(input_bytes=len(raw))
    remaining_nodes = work.limits.max_json_nodes - work.json_nodes
    position = nodes = objects = pairs = 0
    stack = []

    def check():
        if nodes > MAX_NODES or nodes + objects + 2 * pairs > remaining_nodes:
            raise EnrollmentBootstrapError("bootstrap parser exceeds remaining node work")

    while position < len(raw):
        point = raw[position]
        if point in (32, 9, 10, 13, 44):
            position += 1
            continue
        if point == 58:
            pairs += 1
            check()
            position += 1
            continue
        if point in (93, 125):
            if not stack or stack.pop() != point:
                raise EnrollmentBootstrapError("bootstrap JSON delimiters do not match")
            position += 1
            continue
        if len(stack) > MAX_DEPTH:
            raise EnrollmentBootstrapError("bootstrap JSON exceeds its source depth")
        nodes += 1
        objects += int(point == 123)
        check()
        if point in (91, 123):
            stack.append(93 if point == 91 else 125)
            position += 1
        elif point == 34:
            position = wire._string_end(raw, position)
        elif point == 45 or 48 <= point <= 57:
            start = position
            while position < len(raw) and raw[position] in _NUMBER_BYTES:
                position += 1
                if position - start > wire._MAX_INTEGER_DIGITS + 1:
                    raise EnrollmentBootstrapError("bootstrap numeric token exceeds its source bound")
        elif raw.startswith(b"true", position):
            position += 4
        elif raw.startswith(b"false", position):
            position += 5
        elif raw.startswith(b"null", position):
            position += 4
        else:
            raise EnrollmentBootstrapError("bootstrap JSON token is not supported")
    if stack:
        raise EnrollmentBootstrapError("bootstrap JSON delimiters are incomplete")
    return nodes, objects + 2 * pairs


def _float(token):
    # Every canonical finite Python float spelling is shorter than this fixed
    # bound. Longer/noncanonical transports cannot match the signed original.
    if len(token) > 64:
        raise EnrollmentBootstrapError("bootstrap float token exceeds its canonical bound")
    value = float(token)
    if not math.isfinite(value):
        raise EnrollmentBootstrapError("bootstrap configuration float is not finite")
    return value


def _decode(raw, work):
    nodes, hook_nodes = _preflight(raw, work)
    work.charge(input_bytes=3 * len(raw), json_nodes=nodes + hook_nodes)
    value = json.loads(raw.decode("ascii"), object_pairs_hook=wire._unique_object,
        parse_int=wire._parse_integer, parse_float=_float, parse_constant=wire._reject_number)
    return configuration._ConfigurationCapture(capture._SharedLedger(work),
        maximum_bytes=MAX_BYTES).visit(value)


def _payload_shape(value):
    shape = capability.shape
    shape._object(value, _PAYLOAD_FIELDS, "enrollment bootstrap payload")
    shape._literal(value["schema"], PAYLOAD_SCHEMA)
    shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
    shape._digest(value["configurationDigest"])
    shape._object(value["generation"], _GENERATION_FIELDS, "enrollment bootstrap generation")
    if type(value["configurationPayload"]) is not dict or type(value["runtimeRoleIdentities"]) is not dict:
        raise EnrollmentBootstrapError("bootstrap configuration and runtime identities are not exact objects")


def _shape(value):
    capability.shape._object(value, _ENVELOPE_FIELDS, "enrollment bootstrap envelope")
    capability.shape._literal(value["schema"], SCHEMA)
    capability.shape._base64url(value["signatureBase64Url"], signature=True)
    _payload_shape(value["payload"])


def _v3_payload_shape(value):
    from serverware import control_plane_registration_execution_bootstrap as execution

    shape = capability.shape
    shape._object(value, _V3_PAYLOAD_FIELDS, "v3 enrollment bootstrap payload")
    shape._literal(value["schema"], V3_PAYLOAD_SCHEMA)
    shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
    shape._digest(value["configurationDigest"])
    shape._object(value["generation"], _GENERATION_FIELDS, "v3 enrollment bootstrap generation")
    if type(value["configurationPayload"]) is not dict or type(value["runtimeRoleIdentities"]) is not dict:
        raise EnrollmentBootstrapError("v3 bootstrap configuration and runtime identities are not exact objects")
    execution._shape(value["registrationExecution"])
    if value["registrationExecution"] is not None:
        shape._integer(value["issuerPrivateKeyFd"], 1023, minimum=32)
        if value["issuerPrivateKeyFd"] == execution.CALLER_KEY_FD:
            raise EnrollmentBootstrapError("enrollment and execution caller key descriptors must differ")


def _v3_shape(value):
    capability.shape._object(value, _ENVELOPE_FIELDS, "v3 enrollment bootstrap envelope")
    capability.shape._literal(value["schema"], V3_SCHEMA)
    capability.shape._base64url(value["signatureBase64Url"], signature=True)
    _v3_payload_shape(value["payload"])


def _v4_payload_shape(value):
    from serverware import control_plane_registration_execution_bootstrap as execution
    from serverware import control_plane_registration_finalization_bootstrap as finalization

    shape = capability.shape
    shape._object(value, _V4_PAYLOAD_FIELDS, "v4 enrollment bootstrap payload")
    shape._literal(value["schema"], V4_PAYLOAD_SCHEMA)
    shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
    shape._digest(value["configurationDigest"])
    shape._object(value["generation"], _GENERATION_FIELDS, "v4 enrollment bootstrap generation")
    if type(value["configurationPayload"]) is not dict or type(value["runtimeRoleIdentities"]) is not dict:
        raise EnrollmentBootstrapError("v4 bootstrap configuration and runtime identities are not exact objects")
    execution._shape(value["registrationExecution"])
    finalization._shape(value["registrationFinalization"])
    descriptor = value["issuerPrivateKeyFd"]
    if descriptor is not None:
        shape._integer(descriptor, 1023, minimum=32)
        if descriptor == finalization.CALLER_KEY_FD:
            raise EnrollmentBootstrapError("v4 reserves the finalization caller key descriptor")
    if value["registrationExecution"] is not None:
        shape._integer(descriptor, 1023, minimum=32)
        if descriptor == execution.CALLER_KEY_FD:
            raise EnrollmentBootstrapError("enrollment and execution caller key descriptors must differ")
    if value["registrationFinalization"] is not None:
        shape._integer(descriptor, 1023, minimum=32)


def _v4_shape(value):
    capability.shape._object(value, _ENVELOPE_FIELDS, "v4 enrollment bootstrap envelope")
    capability.shape._literal(value["schema"], V4_SCHEMA)
    capability.shape._base64url(value["signatureBase64Url"], signature=True)
    _v4_payload_shape(value["payload"])


def _v5_payload_shape(value):
    from serverware import control_plane_oidc_session_activation_release_bootstrap as release

    shape = capability.shape
    shape._object(value, _V5_PAYLOAD_FIELDS, "v5 enrollment bootstrap payload")
    shape._literal(value["schema"], V5_PAYLOAD_SCHEMA)
    # The fixed v4 projection retains every old field and FD reservation;
    # it is only shape checking, never relabeled signed original admission.
    prior = {name: value[name] for name in _V4_PAYLOAD_FIELDS}
    prior["schema"] = V4_PAYLOAD_SCHEMA
    _v4_payload_shape(prior)
    release._shape(value["oidcSessionActivationRelease"])


def _v5_shape(value):
    capability.shape._object(value, _ENVELOPE_FIELDS, "v5 enrollment bootstrap envelope")
    capability.shape._literal(value["schema"], V5_SCHEMA)
    capability.shape._base64url(value["signatureBase64Url"], signature=True)
    _v5_payload_shape(value["payload"])


def _v6_payload_shape(value):
    from serverware import control_plane_oidc_session_activation_execution_bootstrap as activation

    shape = capability.shape
    shape._object(value, _V6_PAYLOAD_FIELDS, "v6 enrollment bootstrap payload")
    shape._literal(value["schema"], V6_PAYLOAD_SCHEMA)
    prior = {name: value[name] for name in _V5_PAYLOAD_FIELDS}
    prior["schema"] = V5_PAYLOAD_SCHEMA
    _v5_payload_shape(prior)
    descriptor = value["issuerPrivateKeyFd"]
    if descriptor == activation.CALLER_KEY_FD:
        raise EnrollmentBootstrapError("v6 reserves the activation caller key descriptor")
    activation._shape(value["oidcSessionActivationExecution"])


def _v6_shape(value):
    capability.shape._object(value, _ENVELOPE_FIELDS, "v6 enrollment bootstrap envelope")
    capability.shape._literal(value["schema"], V6_SCHEMA)
    capability.shape._base64url(value["signatureBase64Url"], signature=True)
    _v6_payload_shape(value["payload"])


def _v7_payload_shape(value):
    from serverware import control_plane_oidc_session_activation_planning_bootstrap as planning

    capability.shape._object(value, _V7_PAYLOAD_FIELDS, "v7 enrollment bootstrap payload")
    capability.shape._literal(value["schema"], V7_PAYLOAD_SCHEMA)
    prior = {name: value[name] for name in _V6_PAYLOAD_FIELDS}
    prior["schema"] = V6_PAYLOAD_SCHEMA
    _v6_payload_shape(prior)
    planning._shape(value["oidcSessionActivationPlanning"])
    if value["oidcSessionActivationPlanning"] is not None and value["oidcSessionActivationExecution"] is None:
        raise EnrollmentBootstrapError("v7 planning requires the dedicated activation caller lane")


def _v7_shape(value):
    capability.shape._object(value, _ENVELOPE_FIELDS, "v7 enrollment bootstrap envelope")
    capability.shape._literal(value["schema"], V7_SCHEMA)
    capability.shape._base64url(value["signatureBase64Url"], signature=True)
    _v7_payload_shape(value["payload"])


def _v8_payload_shape(value):
    from serverware import control_plane_oidc_session_activation_consume_execution_bootstrap as consume

    capability.shape._object(value, _V8_PAYLOAD_FIELDS, "v8 enrollment bootstrap payload")
    capability.shape._literal(value["schema"], V8_PAYLOAD_SCHEMA)
    prior = {name: value[name] for name in _V7_PAYLOAD_FIELDS}
    prior["schema"] = V7_PAYLOAD_SCHEMA
    _v7_payload_shape(prior)
    if value["issuerPrivateKeyFd"] == consume.CALLER_KEY_FD:
        raise EnrollmentBootstrapError("v8 reserves the consume caller descriptor even when disabled")
    selected = value["oidcSessionActivationConsumeExecution"]
    consume._shape(selected)
    if selected is not None:
        from serverware import control_plane_oidc_session_activation_execution_bootstrap as activation
        execution = value["oidcSessionActivationExecution"]
        if (value["oidcSessionActivationPlanning"] is None or execution is None
                or execution["schema"] != activation.V4_SCHEMA):
            raise EnrollmentBootstrapError("v8 consume caller requires activation v4 and enabled planning")


def _v8_shape(value):
    capability.shape._object(value, _ENVELOPE_FIELDS, "v8 enrollment bootstrap envelope")
    capability.shape._literal(value["schema"], V8_SCHEMA)
    capability.shape._base64url(value["signatureBase64Url"], signature=True)
    _v8_payload_shape(value["payload"])


def _v9_payload_shape(value):
    from serverware import control_plane_oidc_session_activation_consume_execution_bootstrap as consume
    from serverware import control_plane_oidc_session_activation_release_intent_bootstrap as intent

    capability.shape._object(value, _V9_PAYLOAD_FIELDS, "v9 enrollment bootstrap payload")
    capability.shape._literal(value["schema"], V9_PAYLOAD_SCHEMA)
    prior = {name: value[name] for name in _V8_PAYLOAD_FIELDS}
    prior["schema"] = V8_PAYLOAD_SCHEMA
    _v8_payload_shape(prior)
    if value["issuerPrivateKeyFd"] == intent.CALLER_KEY_FD:
        raise EnrollmentBootstrapError("v9 reserves the intent caller descriptor even when disabled")
    selected = value["oidcSessionActivationReleaseIntent"]
    intent._shape(selected)
    consumed = value["oidcSessionActivationConsumeExecution"]
    if selected is not None and (consumed is None or consumed["schema"] != consume.V4_SCHEMA):
        raise EnrollmentBootstrapError("v9 release intent requires explicit consume v4")


def _v9_shape(value):
    capability.shape._object(value, _ENVELOPE_FIELDS, "v9 enrollment bootstrap envelope")
    capability.shape._literal(value["schema"], V9_SCHEMA)
    capability.shape._base64url(value["signatureBase64Url"], signature=True)
    _v9_payload_shape(value["payload"])


def _v10_payload_shape(value):
    from serverware import control_plane_oidc_session_activation_release_proof_bootstrap as proof

    capability.shape._object(value, _V10_PAYLOAD_FIELDS, "v10 enrollment bootstrap payload")
    capability.shape._literal(value["schema"], V10_PAYLOAD_SCHEMA)
    prior = {name: value[name] for name in _V9_PAYLOAD_FIELDS}
    prior["schema"] = V9_PAYLOAD_SCHEMA
    _v9_payload_shape(prior)
    selected = value["oidcSessionActivationReleaseProof"]
    proof._shape(selected)
    if selected is not None and value["oidcSessionActivationReleaseIntent"] is None:
        raise EnrollmentBootstrapError("v10 release proof requires enabled release intent")


def _v10_shape(value):
    capability.shape._object(value, _ENVELOPE_FIELDS, "v10 enrollment bootstrap envelope")
    capability.shape._literal(value["schema"], V10_SCHEMA)
    capability.shape._base64url(value["signatureBase64Url"], signature=True)
    _v10_payload_shape(value["payload"])


def _v11_payload_shape(value):
    from serverware import control_plane_oidc_session_activation_release_handoff_bootstrap as handoff

    capability.shape._object(value, _V11_PAYLOAD_FIELDS, "v11 enrollment bootstrap payload")
    capability.shape._literal(value["schema"], V11_PAYLOAD_SCHEMA)
    prior = {name: value[name] for name in _V10_PAYLOAD_FIELDS}
    prior["schema"] = V10_PAYLOAD_SCHEMA
    _v10_payload_shape(prior)
    selected = value["oidcSessionActivationReleaseHandoff"]
    handoff._shape(selected)
    if selected is not None and (value["oidcSessionActivationReleaseIntent"] is None
            or value["oidcSessionActivationReleaseProof"] is None):
        raise EnrollmentBootstrapError("v11 release handoff requires enabled intent and proof")


def _v11_shape(value):
    capability.shape._object(value, _ENVELOPE_FIELDS, "v11 enrollment bootstrap envelope")
    capability.shape._literal(value["schema"], V11_SCHEMA)
    capability.shape._base64url(value["signatureBase64Url"], signature=True)
    _v11_payload_shape(value["payload"])


def _v12_payload_shape(value):
    from serverware import control_plane_oidc_session_activation_release_grant_acquisition_bootstrap as acquisition

    capability.shape._object(value, _V12_PAYLOAD_FIELDS, "v12 enrollment bootstrap payload")
    capability.shape._literal(value["schema"], V12_PAYLOAD_SCHEMA)
    prior = {name: value[name] for name in _V11_PAYLOAD_FIELDS}
    prior["schema"] = V11_PAYLOAD_SCHEMA
    _v11_payload_shape(prior)
    selected = value["oidcSessionActivationReleaseGrantAcquisition"]
    acquisition._shape(selected)
    if selected is not None and value["oidcSessionActivationReleaseHandoff"] is None:
        raise EnrollmentBootstrapError("v12 release grant acquisition requires enabled handoff")


def _v12_shape(value):
    capability.shape._object(value, _ENVELOPE_FIELDS, "v12 enrollment bootstrap envelope")
    capability.shape._literal(value["schema"], V12_SCHEMA)
    capability.shape._base64url(value["signatureBase64Url"], signature=True)
    _v12_payload_shape(value["payload"])


def _v13_payload_shape(value):
    from serverware import control_plane_oidc_session_activation_consume_input_acquisition_bootstrap as acquisition

    capability.shape._object(value, _V13_PAYLOAD_FIELDS, "v13 enrollment bootstrap payload")
    capability.shape._literal(value["schema"], V13_PAYLOAD_SCHEMA)
    prior = {name: value[name] for name in _V12_PAYLOAD_FIELDS}
    prior["schema"] = V12_PAYLOAD_SCHEMA
    _v12_payload_shape(prior)
    selected = value["oidcSessionActivationConsumeInputAcquisition"]
    acquisition._shape(selected)
    if selected is not None and (value["oidcSessionActivationPlanning"] is None
            or value["oidcSessionActivationExecution"] is None):
        raise EnrollmentBootstrapError("v13 consume input acquisition requires enabled planning and execution")


def _v13_shape(value):
    capability.shape._object(value, _ENVELOPE_FIELDS, "v13 enrollment bootstrap envelope")
    capability.shape._literal(value["schema"], V13_SCHEMA)
    capability.shape._base64url(value["signatureBase64Url"], signature=True)
    _v13_payload_shape(value["payload"])


def _v14_payload_shape(value):
    from serverware import control_plane_oidc_session_activation_release_proof_acquisition_bootstrap as acquisition

    capability.shape._object(value, _V14_PAYLOAD_FIELDS, "v14 enrollment bootstrap payload")
    capability.shape._literal(value["schema"], V14_PAYLOAD_SCHEMA)
    prior = {name: value[name] for name in _V13_PAYLOAD_FIELDS}
    prior["schema"] = V13_PAYLOAD_SCHEMA
    _v13_payload_shape(prior)
    selected = value["oidcSessionActivationReleaseProofAcquisition"]
    acquisition._shape(selected)
    if selected is not None and (value["oidcSessionActivationReleaseIntent"] is None
            or value["oidcSessionActivationReleaseProof"] is None):
        raise EnrollmentBootstrapError("v14 proof acquisition requires enabled intent and proof")


def _v14_shape(value):
    capability.shape._object(value, _ENVELOPE_FIELDS, "v14 enrollment bootstrap envelope")
    capability.shape._literal(value["schema"], V14_SCHEMA)
    capability.shape._base64url(value["signatureBase64Url"], signature=True)
    _v14_payload_shape(value["payload"])


def _v15_payload_shape(value):
    from serverware import control_plane_oidc_session_activation_release_recovery_grant_acquisition_bootstrap as acquisition

    capability.shape._object(value, _V15_PAYLOAD_FIELDS, "v15 enrollment bootstrap payload")
    capability.shape._literal(value["schema"], V15_PAYLOAD_SCHEMA)
    prior = {name: value[name] for name in _V14_PAYLOAD_FIELDS}
    prior["schema"] = V14_PAYLOAD_SCHEMA
    _v14_payload_shape(prior)
    selected = value["oidcSessionActivationReleaseRecoveryGrantAcquisition"]
    acquisition._shape(selected)
    if selected is not None and (value["oidcSessionActivationReleaseIntent"] is None
            or value["oidcSessionActivationReleaseProof"] is None):
        raise EnrollmentBootstrapError("v15 recovery acquisition requires enabled intent and proof")


def _v15_shape(value):
    capability.shape._object(value, _ENVELOPE_FIELDS, "v15 enrollment bootstrap envelope")
    capability.shape._literal(value["schema"], V15_SCHEMA)
    capability.shape._base64url(value["signatureBase64Url"], signature=True)
    _v15_payload_shape(value["payload"])


def _v16_payload_shape(value):
    from serverware import control_plane_oidc_session_activation_completion_recovery_bootstrap as recovery

    capability.shape._object(value, _V16_PAYLOAD_FIELDS, "v16 enrollment bootstrap payload")
    capability.shape._literal(value["schema"], V16_PAYLOAD_SCHEMA)
    prior = {name: value[name] for name in _V15_PAYLOAD_FIELDS}
    prior["schema"] = V15_PAYLOAD_SCHEMA
    _v15_payload_shape(prior)
    selected = value["oidcSessionActivationCompletionRecovery"]
    recovery._shape(selected)
    if selected is not None:
        if value["oidcSessionActivationPlanning"] is None:
            raise EnrollmentBootstrapError("v16 completion recovery requires configured activation planning")
        if selected["activation"] is not None and value["oidcSessionActivationExecution"] is None:
            raise EnrollmentBootstrapError("v16 activation completion recovery requires configured execution")
        if selected["consume"] is not None and value["oidcSessionActivationConsumeExecution"] is None:
            raise EnrollmentBootstrapError("v16 consume completion recovery requires configured execution")


def _v16_shape(value):
    capability.shape._object(value, _ENVELOPE_FIELDS, "v16 enrollment bootstrap envelope")
    capability.shape._literal(value["schema"], V16_SCHEMA)
    capability.shape._base64url(value["signatureBase64Url"], signature=True)
    _v16_payload_shape(value["payload"])


def _v17_payload_shape(value):
    from serverware import control_plane_registration_history_bootstrap as history

    capability.shape._object(value, _V17_PAYLOAD_FIELDS, "v17 enrollment bootstrap payload")
    capability.shape._literal(value["schema"], V17_PAYLOAD_SCHEMA)
    prior = {name: value[name] for name in _V16_PAYLOAD_FIELDS}
    prior["schema"] = V16_PAYLOAD_SCHEMA
    _v16_payload_shape(prior)
    history._shape(value["registrationHistory"])
    if value["registrationHistory"] is not None:
        from serverware import control_plane_registration_execution_bootstrap as execution

        configured = value["registrationExecution"]
        if configured is None or configured["schema"] != execution.V3_SCHEMA:
            raise EnrollmentBootstrapError("v17 registration history requires current execution v3")


def _v17_shape(value):
    capability.shape._object(value, _ENVELOPE_FIELDS, "v17 enrollment bootstrap envelope")
    capability.shape._literal(value["schema"], V17_SCHEMA)
    capability.shape._base64url(value["signatureBase64Url"], signature=True)
    _v17_payload_shape(value["payload"])


def _v18_payload_shape(value):
    from serverware import control_plane_registration_finalization_history_bootstrap as history
    from serverware import control_plane_registration_finalization_bootstrap as finalization

    capability.shape._object(value, _V18_PAYLOAD_FIELDS, "v18 enrollment bootstrap payload")
    capability.shape._literal(value["schema"], V18_PAYLOAD_SCHEMA)
    prior = {name: value[name] for name in _V17_PAYLOAD_FIELDS}
    prior["schema"] = V17_PAYLOAD_SCHEMA
    _v17_payload_shape(prior)
    history._shape(value["finalizationHistory"])
    if value["finalizationHistory"] is not None:
        configured = value["registrationFinalization"]
        if (value["registrationHistory"] is None or configured is None
                or configured["schema"] != finalization.V4_SCHEMA):
            raise EnrollmentBootstrapError("v18 finalization history requires registration history and current finalization v4")


def _v18_shape(value):
    capability.shape._object(value, _ENVELOPE_FIELDS, "v18 enrollment bootstrap envelope")
    capability.shape._literal(value["schema"], V18_SCHEMA)
    capability.shape._base64url(value["signatureBase64Url"], signature=True)
    _v18_payload_shape(value["payload"])


def _canonical(raw, value, work):
    encoded = configuration._configuration_wire(value, capture._SharedLedger(work))
    work.charge(input_bytes=len(raw) + len(encoded))
    if encoded != raw:
        raise EnrollmentBootstrapError("bootstrap original bytes are not canonical or changed during admission")
    return encoded


def _signer_endpoint(value):
    """Fixed activation-peer binding, never child signer identity admission."""
    shape = capability.shape
    shape._object(value, _ENDPOINT_FIELDS, "enrollment signer endpoint")
    path, timeout = value["socketPath"], value["requestTimeoutSeconds"]
    uid, gid = value["listenerUid"], value["listenerGid"]
    shape._literal(path, SIGNER_SOCKET_PATH)
    for observed, expected in ((uid, SIGNER_LISTENER_UID), (gid, SIGNER_LISTENER_GID)):
        shape._integer(observed, 2**32 - 2)
        if observed != expected:
            raise EnrollmentBootstrapError("signer activated-listener peer differs from its fixed root identity")
    if (type(timeout) not in (int, float) or not math.isfinite(timeout)
            or not 0.05 <= timeout <= 30):
        raise EnrollmentBootstrapError("signer endpoint request timeout exceeds its service bound")
    # SO_PEERCRED binds the system manager's listen() identity, not the later
    # accepting process. The evidence signature/policy binds the actual signer.
    return path, timeout, uid, gid


def _material(payload, expected_digest, work):
    """Consistency only; the calling entrypoint supplies root provenance."""
    configured, generation = payload["configurationPayload"], payload["generation"]
    runtime, digest, descriptor = (payload["runtimeRoleIdentities"],
        payload["configurationDigest"], payload["issuerPrivateKeyFd"])
    endpoint = payload["signerEndpoint"]
    plan._same(digest, expected_digest, work, "bootstrap configuration differs from admitted runtime trust")
    if configured.get(enrollment_policy.FIELD) is None:
        if descriptor is not None or endpoint is not None:
            raise EnrollmentBootstrapError("disabled enrollment requires absent issuer key and signer endpoint")
        owned, launch = configuration._capture_configuration_on_work(payload=configured,
            configuration_digest=digest, generation=generation, work=work)
        identities = configuration._capture_runtime_role_identities_on_work(
            runtime_role_identities=runtime, owned_payload=owned,
            configuration_digest=digest, launch=launch, work=work)
        return _EnrollmentMaterial(owned, launch, identities, digest, None, None, None, None)
    capability.shape._integer(descriptor, 1023, minimum=32)
    held_endpoint = _signer_endpoint(endpoint)
    settings = enrollment_policy._capture_on_work(payload=configured,
        configuration_digest=digest, generation=generation,
        runtime_role_identities=runtime, work=work)
    # The actual mapper has re-owned and checked all three graphs, the source
    # allowlist/manifest, dedicated issuer/audience and genuine raw32/SPKI keys.
    # These original owned graphs are retained, not an overlay of role pins.
    return _EnrollmentMaterial(configured, generation, runtime, digest, descriptor,
        settings.policy, settings.issuer_public_key, held_endpoint)


def _v3_material(payload, expected_digest, root_public_key, work):
    from serverware import control_plane_registration_execution_bootstrap as execution

    material = _material(payload, expected_digest, work)
    held_execution = execution._admit_on_work(
        registration_execution=payload["registrationExecution"],
        configuration_payload=material.configuration_payload,
        configuration_digest=material.configuration_digest, generation=material.generation,
        runtime_role_identities=material.runtime_role_identities,
        runtime_root_public_key=root_public_key, issuer_public_key=material.issuer_public_key,
        work=work)
    return _EnrollmentMaterial(material.configuration_payload, material.generation,
        material.runtime_role_identities, material.configuration_digest,
        material.issuer_private_key_fd, material.issuer_policy, material.issuer_public_key,
        material.signer_endpoint, held_execution)


def _v4_material(payload, expected_digest, root_public_key, work):
    from serverware import control_plane_registration_finalization_bootstrap as finalization

    material = _v3_material(payload, expected_digest, root_public_key, work)
    held_finalization = finalization._admit_on_work(
        registration_finalization=payload["registrationFinalization"],
        configuration_payload=material.configuration_payload,
        configuration_digest=material.configuration_digest, generation=material.generation,
        runtime_role_identities=material.runtime_role_identities,
        runtime_root_public_key=root_public_key, issuer_public_key=material.issuer_public_key,
        execution_caller_public_key=(None if material.execution is None
            else material.execution.caller_public_key), work=work)
    return _EnrollmentMaterial(material.configuration_payload, material.generation,
        material.runtime_role_identities, material.configuration_digest,
        material.issuer_private_key_fd, material.issuer_policy, material.issuer_public_key,
        material.signer_endpoint, material.execution, held_finalization, True)


def _v5_material(payload, expected_digest, root_public_key, work):
    from serverware import control_plane_oidc_session_activation_release_bootstrap as release

    material = _v4_material(payload, expected_digest, root_public_key, work)
    held_release = release._admit_on_work(
        release_client=payload["oidcSessionActivationRelease"],
        configuration_payload=material.configuration_payload,
        configuration_digest=material.configuration_digest, generation=material.generation,
        runtime_role_identities=material.runtime_role_identities, work=work)
    return _EnrollmentMaterial(material.configuration_payload, material.generation,
        material.runtime_role_identities, material.configuration_digest,
        material.issuer_private_key_fd, material.issuer_policy, material.issuer_public_key,
        material.signer_endpoint, material.execution, material.finalization,
        material.finalization_slot_reserved, held_release)


def _v6_material(payload, expected_digest, root_public_key, work):
    from serverware import control_plane_oidc_session_activation_execution_bootstrap as activation

    material = _v5_material(payload, expected_digest, root_public_key, work)
    held_activation = activation._admit_on_work(
        activation_execution=payload["oidcSessionActivationExecution"],
        configuration_payload=material.configuration_payload,
        configuration_digest=material.configuration_digest, generation=material.generation,
        runtime_role_identities=material.runtime_role_identities,
        runtime_root_public_key=root_public_key, issuer_public_key=material.issuer_public_key,
        execution_caller_public_key=(None if material.execution is None else material.execution.caller_public_key),
        finalization_caller_public_key=(None if material.finalization is None else material.finalization.caller_public_key),
        work=work)
    return _EnrollmentMaterial(material.configuration_payload, material.generation,
        material.runtime_role_identities, material.configuration_digest,
        material.issuer_private_key_fd, material.issuer_policy, material.issuer_public_key,
        material.signer_endpoint, material.execution, material.finalization,
        material.finalization_slot_reserved, material.release_client, held_activation, True)


def _v7_material(payload, expected_digest, root_public_key, work):
    from serverware import control_plane_oidc_session_activation_planning_bootstrap as planning

    material = _v6_material(payload, expected_digest, root_public_key, work)
    held_planning = planning._admit_on_work(planning=payload["oidcSessionActivationPlanning"],
        configuration_payload=material.configuration_payload,
        configuration_digest=material.configuration_digest, generation=material.generation,
        runtime_role_identities=material.runtime_role_identities,
        runtime_root_public_key=root_public_key, activation_execution=material.activation_execution,
        work=work)
    return _EnrollmentMaterial(material.configuration_payload, material.generation,
        material.runtime_role_identities, material.configuration_digest,
        material.issuer_private_key_fd, material.issuer_policy, material.issuer_public_key,
        material.signer_endpoint, material.execution, material.finalization,
        material.finalization_slot_reserved, material.release_client,
        material.activation_execution, material.activation_slot_reserved, held_planning)


def _v8_material(payload, expected_digest, root_public_key, work):
    from serverware import control_plane_oidc_session_activation_consume_execution_bootstrap as consume

    material = _v7_material(payload, expected_digest, root_public_key, work)
    held_consume = consume._admit_on_work(
        consume_execution=payload["oidcSessionActivationConsumeExecution"],
        configuration_payload=material.configuration_payload,
        configuration_digest=material.configuration_digest, generation=material.generation,
        runtime_role_identities=material.runtime_role_identities,
        runtime_root_public_key=root_public_key, activation_execution=material.activation_execution,
        activation_planning=material.activation_planning, issuer_public_key=material.issuer_public_key,
        execution_caller_public_key=(None if material.execution is None else material.execution.caller_public_key),
        finalization_caller_public_key=(None if material.finalization is None else material.finalization.caller_public_key),
        work=work)
    return _EnrollmentMaterial(material.configuration_payload, material.generation,
        material.runtime_role_identities, material.configuration_digest,
        material.issuer_private_key_fd, material.issuer_policy, material.issuer_public_key,
        material.signer_endpoint, material.execution, material.finalization,
        material.finalization_slot_reserved, material.release_client,
        material.activation_execution, material.activation_slot_reserved, material.activation_planning,
        held_consume, True)


def _v9_material(payload, expected_digest, root_public_key, work):
    from serverware import control_plane_oidc_session_activation_release_intent_bootstrap as intent

    material = _v8_material(payload, expected_digest, root_public_key, work)
    held_intent = intent._admit_on_work(
        release_intent=payload["oidcSessionActivationReleaseIntent"],
        configuration_payload=material.configuration_payload,
        configuration_digest=material.configuration_digest, generation=material.generation,
        runtime_role_identities=material.runtime_role_identities,
        runtime_root_public_key=root_public_key, activation_execution=material.activation_execution,
        activation_planning=material.activation_planning, consume_execution=material.consume_execution,
        issuer_public_key=material.issuer_public_key,
        execution_caller_public_key=(None if material.execution is None else material.execution.caller_public_key),
        finalization_caller_public_key=(None if material.finalization is None else material.finalization.caller_public_key),
        work=work)
    return _EnrollmentMaterial(material.configuration_payload, material.generation,
        material.runtime_role_identities, material.configuration_digest,
        material.issuer_private_key_fd, material.issuer_policy, material.issuer_public_key,
        material.signer_endpoint, material.execution, material.finalization,
        material.finalization_slot_reserved, material.release_client,
        material.activation_execution, material.activation_slot_reserved, material.activation_planning,
        material.consume_execution, material.consume_slot_reserved, held_intent, True)


def _v10_material(payload, expected_digest, root_public_key, work):
    from serverware import control_plane_oidc_session_activation_release_proof_bootstrap as proof

    material = _v9_material(payload, expected_digest, root_public_key, work)
    held_proof = proof._admit_on_work(
        release_proof=payload["oidcSessionActivationReleaseProof"],
        release_intent=material.release_intent,
        configuration_payload=material.configuration_payload,
        runtime_root_public_key=root_public_key, work=work)
    return _EnrollmentMaterial(material.configuration_payload, material.generation,
        material.runtime_role_identities, material.configuration_digest,
        material.issuer_private_key_fd, material.issuer_policy, material.issuer_public_key,
        material.signer_endpoint, material.execution, material.finalization,
        material.finalization_slot_reserved, material.release_client,
        material.activation_execution, material.activation_slot_reserved, material.activation_planning,
        material.consume_execution, material.consume_slot_reserved, material.release_intent,
        material.intent_slot_reserved, held_proof)


def _v11_material(payload, expected_digest, root_public_key, work):
    from serverware import control_plane_oidc_session_activation_release_handoff_bootstrap as handoff

    material = _v10_material(payload, expected_digest, root_public_key, work)
    held_handoff = handoff._admit_on_work(
        release_handoff=payload["oidcSessionActivationReleaseHandoff"],
        release_intent=material.release_intent, release_proof=material.release_proof, work=work)
    return _EnrollmentMaterial(material.configuration_payload, material.generation,
        material.runtime_role_identities, material.configuration_digest,
        material.issuer_private_key_fd, material.issuer_policy, material.issuer_public_key,
        material.signer_endpoint, material.execution, material.finalization,
        material.finalization_slot_reserved, material.release_client,
        material.activation_execution, material.activation_slot_reserved, material.activation_planning,
        material.consume_execution, material.consume_slot_reserved, material.release_intent,
        material.intent_slot_reserved, material.release_proof, held_handoff)


def _v12_material(payload, expected_digest, root_public_key, work):
    from serverware import control_plane_oidc_session_activation_release_grant_acquisition_bootstrap as acquisition

    material = _v11_material(payload, expected_digest, root_public_key, work)
    held_acquisition = acquisition._admit_on_work(
        release_grant_acquisition=payload["oidcSessionActivationReleaseGrantAcquisition"],
        release_handoff=material.release_handoff, work=work)
    return _EnrollmentMaterial(material.configuration_payload, material.generation,
        material.runtime_role_identities, material.configuration_digest,
        material.issuer_private_key_fd, material.issuer_policy, material.issuer_public_key,
        material.signer_endpoint, material.execution, material.finalization,
        material.finalization_slot_reserved, material.release_client,
        material.activation_execution, material.activation_slot_reserved, material.activation_planning,
        material.consume_execution, material.consume_slot_reserved, material.release_intent,
        material.intent_slot_reserved, material.release_proof, material.release_handoff, held_acquisition)


def _v13_material(payload, expected_digest, root_public_key, work):
    from serverware import control_plane_oidc_session_activation_consume_input_acquisition_bootstrap as acquisition

    material = _v12_material(payload, expected_digest, root_public_key, work)
    held_acquisition = acquisition._admit_on_work(
        consume_input_acquisition=payload["oidcSessionActivationConsumeInputAcquisition"],
        activation_planning=material.activation_planning, activation_execution=material.activation_execution,
        runtime_root_public_key=root_public_key, work=work)
    return _EnrollmentMaterial(material.configuration_payload, material.generation,
        material.runtime_role_identities, material.configuration_digest,
        material.issuer_private_key_fd, material.issuer_policy, material.issuer_public_key,
        material.signer_endpoint, material.execution, material.finalization,
        material.finalization_slot_reserved, material.release_client,
        material.activation_execution, material.activation_slot_reserved, material.activation_planning,
        material.consume_execution, material.consume_slot_reserved, material.release_intent,
        material.intent_slot_reserved, material.release_proof, material.release_handoff,
        material.release_grant_acquisition, held_acquisition)


def _v14_material(payload, expected_digest, root_public_key, work):
    from serverware import control_plane_oidc_session_activation_release_proof_acquisition_bootstrap as acquisition

    material = _v13_material(payload, expected_digest, root_public_key, work)
    held_acquisition = acquisition._admit_on_work(
        release_proof_acquisition=payload["oidcSessionActivationReleaseProofAcquisition"],
        release_intent=material.release_intent, release_proof=material.release_proof,
        runtime_root_public_key=root_public_key, work=work)
    return _EnrollmentMaterial(material.configuration_payload, material.generation,
        material.runtime_role_identities, material.configuration_digest,
        material.issuer_private_key_fd, material.issuer_policy, material.issuer_public_key,
        material.signer_endpoint, material.execution, material.finalization,
        material.finalization_slot_reserved, material.release_client,
        material.activation_execution, material.activation_slot_reserved, material.activation_planning,
        material.consume_execution, material.consume_slot_reserved, material.release_intent,
        material.intent_slot_reserved, material.release_proof, material.release_handoff,
        material.release_grant_acquisition, material.consume_input_acquisition, held_acquisition)


def _v15_material(payload, expected_digest, root_public_key, work):
    from serverware import control_plane_oidc_session_activation_release_recovery_grant_acquisition_bootstrap as acquisition

    material = _v14_material(payload, expected_digest, root_public_key, work)
    held_acquisition = acquisition._admit_on_work(
        recovery_grant_acquisition=payload["oidcSessionActivationReleaseRecoveryGrantAcquisition"],
        release_intent=material.release_intent, release_proof=material.release_proof,
        runtime_root_public_key=root_public_key, work=work)
    return _EnrollmentMaterial(material.configuration_payload, material.generation,
        material.runtime_role_identities, material.configuration_digest,
        material.issuer_private_key_fd, material.issuer_policy, material.issuer_public_key,
        material.signer_endpoint, material.execution, material.finalization,
        material.finalization_slot_reserved, material.release_client,
        material.activation_execution, material.activation_slot_reserved, material.activation_planning,
        material.consume_execution, material.consume_slot_reserved, material.release_intent,
        material.intent_slot_reserved, material.release_proof, material.release_handoff,
        material.release_grant_acquisition, material.consume_input_acquisition,
        material.release_proof_acquisition, held_acquisition)


def _v16_material(payload, expected_digest, root_public_key, work):
    from serverware import control_plane_oidc_session_activation_completion_recovery_bootstrap as recovery

    material = _v15_material(payload, expected_digest, root_public_key, work)
    held_recovery = recovery._admit_on_work(
        completion_recovery=payload["oidcSessionActivationCompletionRecovery"],
        activation_execution=material.activation_execution, consume_execution=material.consume_execution,
        runtime_root_public_key=root_public_key, configuration_digest=material.configuration_digest,
        generation_digest=material.generation["digest"], work=work)
    return _EnrollmentMaterial(material.configuration_payload, material.generation,
        material.runtime_role_identities, material.configuration_digest,
        material.issuer_private_key_fd, material.issuer_policy, material.issuer_public_key,
        material.signer_endpoint, material.execution, material.finalization,
        material.finalization_slot_reserved, material.release_client,
        material.activation_execution, material.activation_slot_reserved, material.activation_planning,
        material.consume_execution, material.consume_slot_reserved, material.release_intent,
        material.intent_slot_reserved, material.release_proof, material.release_handoff,
        material.release_grant_acquisition, material.consume_input_acquisition,
        material.release_proof_acquisition, material.release_recovery_grant_acquisition, held_recovery)


def _v17_material(payload, expected_digest, root_public_key, work, *,
        current_interval=None, now_epoch_ns=None):
    from serverware import control_plane_registration_history_bootstrap as history

    material = _v16_material(payload, expected_digest, root_public_key, work)
    held_history = history._admit_on_work(registration_history=payload["registrationHistory"],
        configuration_payload=material.configuration_payload, configuration_digest=material.configuration_digest,
        generation=material.generation, runtime_role_identities=material.runtime_role_identities,
        runtime_root_public_key=root_public_key, current_interval=current_interval,
        now_epoch_ns=now_epoch_ns, work=work)
    return _EnrollmentMaterial(material.configuration_payload, material.generation,
        material.runtime_role_identities, material.configuration_digest,
        material.issuer_private_key_fd, material.issuer_policy, material.issuer_public_key,
        material.signer_endpoint, material.execution, material.finalization,
        material.finalization_slot_reserved, material.release_client,
        material.activation_execution, material.activation_slot_reserved, material.activation_planning,
        material.consume_execution, material.consume_slot_reserved, material.release_intent,
        material.intent_slot_reserved, material.release_proof, material.release_handoff,
        material.release_grant_acquisition, material.consume_input_acquisition,
        material.release_proof_acquisition, material.release_recovery_grant_acquisition,
        material.completion_recovery, held_history)


def _v18_material(payload, expected_digest, root_public_key, work, *,
        current_interval=None, now_epoch_ns=None):
    from serverware import control_plane_registration_finalization_history_bootstrap as history

    material = _v17_material(payload, expected_digest, root_public_key, work,
        current_interval=current_interval, now_epoch_ns=now_epoch_ns)
    held_history = history._admit_on_work(finalization_history=payload["finalizationHistory"],
        registration_history=material.registration_history, work=work)
    return _EnrollmentMaterial(material.configuration_payload, material.generation,
        material.runtime_role_identities, material.configuration_digest,
        material.issuer_private_key_fd, material.issuer_policy, material.issuer_public_key,
        material.signer_endpoint, material.execution, material.finalization,
        material.finalization_slot_reserved, material.release_client,
        material.activation_execution, material.activation_slot_reserved, material.activation_planning,
        material.consume_execution, material.consume_slot_reserved, material.release_intent,
        material.intent_slot_reserved, material.release_proof, material.release_handoff,
        material.release_grant_acquisition, material.consume_input_acquisition,
        material.release_proof_acquisition, material.release_recovery_grant_acquisition,
        material.completion_recovery, material.registration_history, held_history)


def _admit_on_work(*, bootstrap_bytes, runtime_root_public_key,
        expected_configuration_digest, work, _history_current_interval=None,
        _history_now_epoch_ns=None):
    """Authenticate exact originals before using their configuration or FD."""
    try:
        capture._SharedLedger(work)
        original, key, expected = bootstrap_bytes, runtime_root_public_key, expected_configuration_digest
        if type(original) is not bytes or not 2 <= len(original) <= MAX_BYTES:
            raise EnrollmentBootstrapError("bootstrap originals exceed their exact byte bound")
        if not isinstance(key, Ed25519PublicKey):
            raise EnrollmentBootstrapError("bootstrap requires the independently admitted Ed25519 runtime root")
        capability.shape._digest(expected)
        envelope = _decode(original, work)
        is_v3 = type(envelope) is dict and envelope.get("schema") == V3_SCHEMA
        is_v4 = type(envelope) is dict and envelope.get("schema") == V4_SCHEMA
        is_v5 = type(envelope) is dict and envelope.get("schema") == V5_SCHEMA
        is_v6 = type(envelope) is dict and envelope.get("schema") == V6_SCHEMA
        is_v7 = type(envelope) is dict and envelope.get("schema") == V7_SCHEMA
        is_v8 = type(envelope) is dict and envelope.get("schema") == V8_SCHEMA
        is_v9 = type(envelope) is dict and envelope.get("schema") == V9_SCHEMA
        is_v10 = type(envelope) is dict and envelope.get("schema") == V10_SCHEMA
        is_v11 = type(envelope) is dict and envelope.get("schema") == V11_SCHEMA
        is_v12 = type(envelope) is dict and envelope.get("schema") == V12_SCHEMA
        is_v13 = type(envelope) is dict and envelope.get("schema") == V13_SCHEMA
        is_v14 = type(envelope) is dict and envelope.get("schema") == V14_SCHEMA
        is_v15 = type(envelope) is dict and envelope.get("schema") == V15_SCHEMA
        is_v16 = type(envelope) is dict and envelope.get("schema") == V16_SCHEMA
        is_v17 = type(envelope) is dict and envelope.get("schema") == V17_SCHEMA
        is_v18 = type(envelope) is dict and envelope.get("schema") == V18_SCHEMA
        if is_v18:
            _v18_shape(envelope)
        elif is_v17:
            _v17_shape(envelope)
        elif is_v16:
            _v16_shape(envelope)
        elif is_v15:
            _v15_shape(envelope)
        elif is_v14:
            _v14_shape(envelope)
        elif is_v13:
            _v13_shape(envelope)
        elif is_v12:
            _v12_shape(envelope)
        elif is_v11:
            _v11_shape(envelope)
        elif is_v10:
            _v10_shape(envelope)
        elif is_v9:
            _v9_shape(envelope)
        elif is_v8:
            _v8_shape(envelope)
        elif is_v7:
            _v7_shape(envelope)
        elif is_v6:
            _v6_shape(envelope)
        elif is_v5:
            _v5_shape(envelope)
        elif is_v4:
            _v4_shape(envelope)
        elif is_v3:
            _v3_shape(envelope)
        else:
            _shape(envelope)
        _canonical(original, envelope, work)
        payload = envelope["payload"]
        payload_bytes = configuration._configuration_wire(payload, capture._SharedLedger(work))
        capability._signature(key, envelope["signatureBase64Url"],
            V18_SCHEMA if is_v18 else V17_SCHEMA if is_v17 else V16_SCHEMA if is_v16 else V15_SCHEMA if is_v15 else V14_SCHEMA if is_v14 else V13_SCHEMA if is_v13 else V12_SCHEMA if is_v12 else V11_SCHEMA if is_v11 else V10_SCHEMA if is_v10 else V9_SCHEMA if is_v9 else V8_SCHEMA if is_v8 else V7_SCHEMA if is_v7 else V6_SCHEMA if is_v6 else V5_SCHEMA if is_v5 else V4_SCHEMA if is_v4 else V3_SCHEMA if is_v3 else SCHEMA,
            payload_bytes, capture._SharedLedger(work))
        _canonical(original, envelope, work)
        material = (_v18_material(payload, expected, key, work,
            current_interval=_history_current_interval, now_epoch_ns=_history_now_epoch_ns) if is_v18
            else _v17_material(payload, expected, key, work,
            current_interval=_history_current_interval, now_epoch_ns=_history_now_epoch_ns) if is_v17
            else _v16_material(payload, expected, key, work) if is_v16
            else _v15_material(payload, expected, key, work) if is_v15
            else _v14_material(payload, expected, key, work) if is_v14
            else _v13_material(payload, expected, key, work) if is_v13
            else _v12_material(payload, expected, key, work) if is_v12
            else _v11_material(payload, expected, key, work) if is_v11
            else _v10_material(payload, expected, key, work) if is_v10
            else _v9_material(payload, expected, key, work) if is_v9
            else _v8_material(payload, expected, key, work) if is_v8
            else _v7_material(payload, expected, key, work) if is_v7
            else _v6_material(payload, expected, key, work) if is_v6
            else _v5_material(payload, expected, key, work) if is_v5
            else _v4_material(payload, expected, key, work) if is_v4
            else _v3_material(payload, expected, key, work) if is_v3
            else _material(payload, expected, work))
        _canonical(original, envelope, work)
        return material
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, EnrollmentBootstrapError):
            raise
        raise EnrollmentBootstrapError("enrollment bootstrap admission failed") from exc


def _measure(value, work):
    measured = configuration._ConfigurationCapture(capture._SharedLedger(work),
        maximum_bytes=MAX_BYTES, retain=False)
    measured.visit(value)
    if measured.nodes > MAX_NODES:
        raise EnrollmentBootstrapError("bootstrap output exceeds its source node bound")
    return measured.bytes, measured.nodes


def _encode(value):
    # Every call is preceded by an actual configuration measurement and
    # reservation; unlike proof canonicalization this preserves finite floats.
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("ascii")


def _produce_on_work(*, configuration_payload, generation, runtime_role_identities,
        configuration_digest, issuer_private_key_fd, signer_endpoint, runtime_root_private_key,
        runtime_root_public_key, work):
    """Produce a dedicated root statement for an independent provisioner."""
    try:
        ledger = capture._SharedLedger(work)
        private_key, public_key = runtime_root_private_key, runtime_root_public_key
        digest, descriptor = configuration_digest, issuer_private_key_fd
        if (not isinstance(private_key, Ed25519PrivateKey)
                or not isinstance(public_key, Ed25519PublicKey)):
            raise EnrollmentBootstrapError("bootstrap production requires the actual admitted root pair")
        capability.shape._digest(digest)
        capability.shape._bounded_object(generation, 24, "bootstrap provisioner launch context")
        payload = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "schema": PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "configurationDigest": digest, "configurationPayload": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtimeRoleIdentities": runtime_role_identities, "issuerPrivateKeyFd": descriptor,
            "signerEndpoint": signer_endpoint})
        _payload_shape(payload)
        envelope = {"schema": SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
        _shape(envelope)
        # Capture and canonicalize before every key/hash callback. Keep these
        # exact bytes through policy admission, pairing and native signing.
        original = configuration._configuration_wire(payload, capture._SharedLedger(work))
        _material(payload, digest, work)
        keys._pair_on_work(private_key, public_key, work)
        _canonical(original, payload, work)
        payload_size, payload_nodes = _measure(payload, work)
        envelope_size, envelope_nodes = _measure(envelope, work)
        # Reserve post-native encoding+comparison, signature transport and
        # final envelope encoding before signing can occur. The real later
        # measurement stays separately charged and must fit before callback.
        work.charge(input_bytes=3 * payload_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=payload_nodes + envelope_nodes)
        frame_bytes = 2 * len(SCHEMA) + 9 + payload_size + 2 * 71
        if (work.limits.max_hashes - work.hash_work < 1
                or work.limits.max_input_bytes - work.input_bytes < frame_bytes + payload_size
                or work.limits.max_json_nodes - work.json_nodes < 4 + payload_nodes):
            raise EnrollmentBootstrapError("bootstrap cannot reserve its signature output")
        message = plan._ascii(plan._frame(SCHEMA, (original,), work), work)
        signature = production._sign_and_verify(private_key, public_key, message, work)
        # Measurement itself still charges the original work; the encoding and
        # complete byte comparison were reserved above, never a fresh budget.
        if _measure(payload, work) != (payload_size, payload_nodes) or _encode(payload) != original:
            raise EnrollmentBootstrapError("bootstrap payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        capability.shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = _encode(envelope)
        if len(result) != envelope_size:
            raise EnrollmentBootstrapError("bootstrap output changed after reservation")
        return result
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, EnrollmentBootstrapError):
            raise
        raise EnrollmentBootstrapError("enrollment bootstrap production failed") from exc


def _produce_v3_on_work(*, configuration_payload, generation, runtime_role_identities,
        configuration_digest, issuer_private_key_fd, signer_endpoint, registration_execution,
        runtime_root_private_key, runtime_root_public_key, work):
    """Produce opt-in v3 originals without changing the evidence-only v2 producer."""
    try:
        ledger = capture._SharedLedger(work)
        private_key, public_key = runtime_root_private_key, runtime_root_public_key
        digest, descriptor = configuration_digest, issuer_private_key_fd
        if (not isinstance(private_key, Ed25519PrivateKey)
                or not isinstance(public_key, Ed25519PublicKey)):
            raise EnrollmentBootstrapError("v3 bootstrap production requires the actual admitted root pair")
        capability.shape._digest(digest)
        capability.shape._bounded_object(generation, 24, "v3 bootstrap provisioner launch context")
        payload = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "schema": V3_PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "configurationDigest": digest, "configurationPayload": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtimeRoleIdentities": runtime_role_identities, "issuerPrivateKeyFd": descriptor,
            "signerEndpoint": signer_endpoint, "registrationExecution": registration_execution})
        _v3_payload_shape(payload)
        envelope = {"schema": V3_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
        _v3_shape(envelope)
        original = configuration._configuration_wire(payload, capture._SharedLedger(work))
        _v3_material(payload, digest, public_key, work)
        keys._pair_on_work(private_key, public_key, work)
        _canonical(original, payload, work)
        payload_size, payload_nodes = _measure(payload, work)
        envelope_size, envelope_nodes = _measure(envelope, work)
        work.charge(input_bytes=3 * payload_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=payload_nodes + envelope_nodes)
        frame_bytes = 2 * len(V3_SCHEMA) + 9 + payload_size + 2 * 71
        if (work.limits.max_hashes - work.hash_work < 1
                or work.limits.max_input_bytes - work.input_bytes < frame_bytes + payload_size
                or work.limits.max_json_nodes - work.json_nodes < 4 + payload_nodes):
            raise EnrollmentBootstrapError("v3 bootstrap cannot reserve its signature output")
        message = plan._ascii(plan._frame(V3_SCHEMA, (original,), work), work)
        signature = production._sign_and_verify(private_key, public_key, message, work)
        if _measure(payload, work) != (payload_size, payload_nodes) or _encode(payload) != original:
            raise EnrollmentBootstrapError("v3 bootstrap payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        capability.shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = _encode(envelope)
        if len(result) != envelope_size:
            raise EnrollmentBootstrapError("v3 bootstrap output changed after reservation")
        return result
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, EnrollmentBootstrapError):
            raise
        raise EnrollmentBootstrapError("v3 enrollment bootstrap production failed") from exc


def _produce_v4_on_work(*, configuration_payload, generation, runtime_role_identities,
        configuration_digest, issuer_private_key_fd, signer_endpoint, registration_execution,
        registration_finalization, runtime_root_private_key, runtime_root_public_key, work):
    """Produce explicit v4 originals; never create or provision either caller key."""
    try:
        ledger = capture._SharedLedger(work)
        private_key, public_key = runtime_root_private_key, runtime_root_public_key
        digest, descriptor = configuration_digest, issuer_private_key_fd
        if (not isinstance(private_key, Ed25519PrivateKey)
                or not isinstance(public_key, Ed25519PublicKey)):
            raise EnrollmentBootstrapError("v4 bootstrap production requires the actual admitted root pair")
        capability.shape._digest(digest)
        capability.shape._bounded_object(generation, 24, "v4 bootstrap provisioner launch context")
        payload = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "schema": V4_PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "configurationDigest": digest, "configurationPayload": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtimeRoleIdentities": runtime_role_identities, "issuerPrivateKeyFd": descriptor,
            "signerEndpoint": signer_endpoint, "registrationExecution": registration_execution,
            "registrationFinalization": registration_finalization})
        _v4_payload_shape(payload)
        envelope = {"schema": V4_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
        _v4_shape(envelope)
        original = configuration._configuration_wire(payload, capture._SharedLedger(work))
        _v4_material(payload, digest, public_key, work)
        keys._pair_on_work(private_key, public_key, work)
        _canonical(original, payload, work)
        payload_size, payload_nodes = _measure(payload, work)
        envelope_size, envelope_nodes = _measure(envelope, work)
        work.charge(input_bytes=3 * payload_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=payload_nodes + envelope_nodes)
        frame_bytes = 2 * len(V4_SCHEMA) + 9 + payload_size + 2 * 71
        if (work.limits.max_hashes - work.hash_work < 1
                or work.limits.max_input_bytes - work.input_bytes < frame_bytes + payload_size
                or work.limits.max_json_nodes - work.json_nodes < 4 + payload_nodes):
            raise EnrollmentBootstrapError("v4 bootstrap cannot reserve its signature output")
        message = plan._ascii(plan._frame(V4_SCHEMA, (original,), work), work)
        signature = production._sign_and_verify(private_key, public_key, message, work)
        if _measure(payload, work) != (payload_size, payload_nodes) or _encode(payload) != original:
            raise EnrollmentBootstrapError("v4 bootstrap payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        capability.shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = _encode(envelope)
        if len(result) != envelope_size:
            raise EnrollmentBootstrapError("v4 bootstrap output changed after reservation")
        return result
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, EnrollmentBootstrapError):
            raise
        raise EnrollmentBootstrapError("v4 enrollment bootstrap production failed") from exc


def _produce_v5_on_work(*, configuration_payload, generation, runtime_role_identities,
        configuration_digest, issuer_private_key_fd, signer_endpoint, registration_execution,
        registration_finalization, oidc_session_activation_release,
        runtime_root_private_key, runtime_root_public_key, work):
    """Sign configured public originals; request-time freshness remains separate."""
    try:
        ledger = capture._SharedLedger(work)
        private_key, public_key = runtime_root_private_key, runtime_root_public_key
        digest, descriptor = configuration_digest, issuer_private_key_fd
        if (not isinstance(private_key, Ed25519PrivateKey)
                or not isinstance(public_key, Ed25519PublicKey)):
            raise EnrollmentBootstrapError("v5 bootstrap production requires the actual admitted root pair")
        capability.shape._digest(digest)
        capability.shape._bounded_object(generation, 24, "v5 bootstrap provisioner launch context")
        payload = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "schema": V5_PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "configurationDigest": digest, "configurationPayload": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtimeRoleIdentities": runtime_role_identities, "issuerPrivateKeyFd": descriptor,
            "signerEndpoint": signer_endpoint, "registrationExecution": registration_execution,
            "registrationFinalization": registration_finalization,
            "oidcSessionActivationRelease": oidc_session_activation_release})
        _v5_payload_shape(payload)
        envelope = {"schema": V5_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
        _v5_shape(envelope)
        original = configuration._configuration_wire(payload, capture._SharedLedger(work))
        _v5_material(payload, digest, public_key, work)
        keys._pair_on_work(private_key, public_key, work)
        _canonical(original, payload, work)
        payload_size, payload_nodes = _measure(payload, work)
        envelope_size, envelope_nodes = _measure(envelope, work)
        work.charge(input_bytes=3 * payload_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=payload_nodes + envelope_nodes)
        frame_bytes = 2 * len(V5_SCHEMA) + 9 + payload_size + 2 * 71
        if (work.limits.max_hashes - work.hash_work < 1
                or work.limits.max_input_bytes - work.input_bytes < frame_bytes + payload_size
                or work.limits.max_json_nodes - work.json_nodes < 4 + payload_nodes):
            raise EnrollmentBootstrapError("v5 bootstrap cannot reserve its signature output")
        message = plan._ascii(plan._frame(V5_SCHEMA, (original,), work), work)
        signature = production._sign_and_verify(private_key, public_key, message, work)
        if _measure(payload, work) != (payload_size, payload_nodes) or _encode(payload) != original:
            raise EnrollmentBootstrapError("v5 bootstrap payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        capability.shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = _encode(envelope)
        if len(result) != envelope_size:
            raise EnrollmentBootstrapError("v5 bootstrap output changed after reservation")
        return result
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, EnrollmentBootstrapError):
            raise
        raise EnrollmentBootstrapError("v5 enrollment bootstrap production failed") from exc


def _produce_v6_on_work(*, configuration_payload, generation, runtime_role_identities,
        configuration_digest, issuer_private_key_fd, signer_endpoint, registration_execution,
        registration_finalization, oidc_session_activation_release, oidc_session_activation_execution,
        runtime_root_private_key, runtime_root_public_key, work):
    """Sign the dedicated caller custody lane; present-user authority stays separate."""
    try:
        ledger = capture._SharedLedger(work)
        private_key, public_key = runtime_root_private_key, runtime_root_public_key
        digest, descriptor = configuration_digest, issuer_private_key_fd
        if (not isinstance(private_key, Ed25519PrivateKey)
                or not isinstance(public_key, Ed25519PublicKey)):
            raise EnrollmentBootstrapError("v6 bootstrap production requires the actual admitted root pair")
        capability.shape._digest(digest)
        capability.shape._bounded_object(generation, 24, "v6 bootstrap provisioner launch context")
        payload = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "schema": V6_PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "configurationDigest": digest, "configurationPayload": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtimeRoleIdentities": runtime_role_identities, "issuerPrivateKeyFd": descriptor,
            "signerEndpoint": signer_endpoint, "registrationExecution": registration_execution,
            "registrationFinalization": registration_finalization,
            "oidcSessionActivationRelease": oidc_session_activation_release,
            "oidcSessionActivationExecution": oidc_session_activation_execution})
        _v6_payload_shape(payload)
        envelope = {"schema": V6_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
        _v6_shape(envelope)
        original = configuration._configuration_wire(payload, capture._SharedLedger(work))
        _v6_material(payload, digest, public_key, work)
        keys._pair_on_work(private_key, public_key, work)
        _canonical(original, payload, work)
        payload_size, payload_nodes = _measure(payload, work)
        envelope_size, envelope_nodes = _measure(envelope, work)
        work.charge(input_bytes=3 * payload_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=payload_nodes + envelope_nodes)
        frame_bytes = 2 * len(V6_SCHEMA) + 9 + payload_size + 2 * 71
        if (work.limits.max_hashes - work.hash_work < 1
                or work.limits.max_input_bytes - work.input_bytes < frame_bytes + payload_size
                or work.limits.max_json_nodes - work.json_nodes < 4 + payload_nodes):
            raise EnrollmentBootstrapError("v6 bootstrap cannot reserve its signature output")
        message = plan._ascii(plan._frame(V6_SCHEMA, (original,), work), work)
        signature = production._sign_and_verify(private_key, public_key, message, work)
        if _measure(payload, work) != (payload_size, payload_nodes) or _encode(payload) != original:
            raise EnrollmentBootstrapError("v6 bootstrap payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        capability.shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = _encode(envelope)
        if len(result) != envelope_size:
            raise EnrollmentBootstrapError("v6 bootstrap output changed after reservation")
        return result
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, EnrollmentBootstrapError):
            raise
        raise EnrollmentBootstrapError("v6 enrollment bootstrap production failed") from exc


def _produce_v7_on_work(*, configuration_payload, generation, runtime_role_identities,
        configuration_digest, issuer_private_key_fd, signer_endpoint, registration_execution,
        registration_finalization, oidc_session_activation_release, oidc_session_activation_execution,
        oidc_session_activation_planning, runtime_root_private_key, runtime_root_public_key, work):
    """Sign explicit public planning originals without widening an old profile."""
    try:
        ledger = capture._SharedLedger(work)
        private_key, public_key = runtime_root_private_key, runtime_root_public_key
        digest, descriptor = configuration_digest, issuer_private_key_fd
        if (not isinstance(private_key, Ed25519PrivateKey)
                or not isinstance(public_key, Ed25519PublicKey)):
            raise EnrollmentBootstrapError("v7 bootstrap production requires the actual admitted root pair")
        capability.shape._digest(digest)
        capability.shape._bounded_object(generation, 24, "v7 bootstrap provisioner launch context")
        payload = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "schema": V7_PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "configurationDigest": digest, "configurationPayload": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtimeRoleIdentities": runtime_role_identities, "issuerPrivateKeyFd": descriptor,
            "signerEndpoint": signer_endpoint, "registrationExecution": registration_execution,
            "registrationFinalization": registration_finalization,
            "oidcSessionActivationRelease": oidc_session_activation_release,
            "oidcSessionActivationExecution": oidc_session_activation_execution,
            "oidcSessionActivationPlanning": oidc_session_activation_planning})
        _v7_payload_shape(payload)
        envelope = {"schema": V7_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
        _v7_shape(envelope)
        original = configuration._configuration_wire(payload, capture._SharedLedger(work))
        _v7_material(payload, digest, public_key, work)
        keys._pair_on_work(private_key, public_key, work)
        _canonical(original, payload, work)
        payload_size, payload_nodes = _measure(payload, work)
        envelope_size, envelope_nodes = _measure(envelope, work)
        work.charge(input_bytes=3 * payload_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=payload_nodes + envelope_nodes)
        frame_bytes = 2 * len(V7_SCHEMA) + 9 + payload_size + 2 * 71
        if (work.limits.max_hashes - work.hash_work < 1
                or work.limits.max_input_bytes - work.input_bytes < frame_bytes + payload_size
                or work.limits.max_json_nodes - work.json_nodes < 4 + payload_nodes):
            raise EnrollmentBootstrapError("v7 bootstrap cannot reserve its signature output")
        message = plan._ascii(plan._frame(V7_SCHEMA, (original,), work), work)
        signature = production._sign_and_verify(private_key, public_key, message, work)
        if _measure(payload, work) != (payload_size, payload_nodes) or _encode(payload) != original:
            raise EnrollmentBootstrapError("v7 bootstrap payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        capability.shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = _encode(envelope)
        if len(result) != envelope_size:
            raise EnrollmentBootstrapError("v7 bootstrap output changed after reservation")
        return result
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, EnrollmentBootstrapError):
            raise
        raise EnrollmentBootstrapError("v7 enrollment bootstrap production failed") from exc


def _produce_v8_on_work(*, configuration_payload, generation, runtime_role_identities,
        configuration_digest, issuer_private_key_fd, signer_endpoint, registration_execution,
        registration_finalization, oidc_session_activation_release, oidc_session_activation_execution,
        oidc_session_activation_planning, oidc_session_activation_consume_execution,
        runtime_root_private_key, runtime_root_public_key, work):
    """Sign the distinct consume caller lane; old signed profiles stay closed."""
    try:
        ledger = capture._SharedLedger(work)
        private_key, public_key = runtime_root_private_key, runtime_root_public_key
        digest, descriptor = configuration_digest, issuer_private_key_fd
        if (not isinstance(private_key, Ed25519PrivateKey)
                or not isinstance(public_key, Ed25519PublicKey)):
            raise EnrollmentBootstrapError("v8 bootstrap production requires the actual admitted root pair")
        capability.shape._digest(digest)
        capability.shape._bounded_object(generation, 24, "v8 bootstrap provisioner launch context")
        payload = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "schema": V8_PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "configurationDigest": digest, "configurationPayload": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtimeRoleIdentities": runtime_role_identities, "issuerPrivateKeyFd": descriptor,
            "signerEndpoint": signer_endpoint, "registrationExecution": registration_execution,
            "registrationFinalization": registration_finalization,
            "oidcSessionActivationRelease": oidc_session_activation_release,
            "oidcSessionActivationExecution": oidc_session_activation_execution,
            "oidcSessionActivationPlanning": oidc_session_activation_planning,
            "oidcSessionActivationConsumeExecution": oidc_session_activation_consume_execution})
        _v8_payload_shape(payload)
        envelope = {"schema": V8_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
        _v8_shape(envelope)
        original = configuration._configuration_wire(payload, capture._SharedLedger(work))
        _v8_material(payload, digest, public_key, work)
        keys._pair_on_work(private_key, public_key, work)
        _canonical(original, payload, work)
        payload_size, payload_nodes = _measure(payload, work)
        envelope_size, envelope_nodes = _measure(envelope, work)
        work.charge(input_bytes=3 * payload_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=payload_nodes + envelope_nodes)
        frame_bytes = 2 * len(V8_SCHEMA) + 9 + payload_size + 2 * 71
        if (work.limits.max_hashes - work.hash_work < 1
                or work.limits.max_input_bytes - work.input_bytes < frame_bytes + payload_size
                or work.limits.max_json_nodes - work.json_nodes < 4 + payload_nodes):
            raise EnrollmentBootstrapError("v8 bootstrap cannot reserve its signature output")
        message = plan._ascii(plan._frame(V8_SCHEMA, (original,), work), work)
        signature = production._sign_and_verify(private_key, public_key, message, work)
        if _measure(payload, work) != (payload_size, payload_nodes) or _encode(payload) != original:
            raise EnrollmentBootstrapError("v8 bootstrap payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        capability.shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = _encode(envelope)
        if len(result) != envelope_size:
            raise EnrollmentBootstrapError("v8 bootstrap output changed after reservation")
        return result
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, EnrollmentBootstrapError):
            raise
        raise EnrollmentBootstrapError("v8 enrollment bootstrap production failed") from exc


def _produce_v9_on_work(*, configuration_payload, generation, runtime_role_identities,
        configuration_digest, issuer_private_key_fd, signer_endpoint, registration_execution,
        registration_finalization, oidc_session_activation_release, oidc_session_activation_execution,
        oidc_session_activation_planning, oidc_session_activation_consume_execution,
        oidc_session_activation_release_intent, runtime_root_private_key, runtime_root_public_key, work):
    """Sign only the distinct intent-key configuration after genuine original admission."""
    try:
        ledger = capture._SharedLedger(work)
        private_key, public_key = runtime_root_private_key, runtime_root_public_key
        digest, descriptor = configuration_digest, issuer_private_key_fd
        if not isinstance(private_key, Ed25519PrivateKey) or not isinstance(public_key, Ed25519PublicKey):
            raise EnrollmentBootstrapError("v9 bootstrap production requires the actual admitted root pair")
        capability.shape._digest(digest)
        capability.shape._bounded_object(generation, 24, "v9 bootstrap provisioner launch context")
        payload = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "schema": V9_PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "configurationDigest": digest, "configurationPayload": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtimeRoleIdentities": runtime_role_identities, "issuerPrivateKeyFd": descriptor,
            "signerEndpoint": signer_endpoint, "registrationExecution": registration_execution,
            "registrationFinalization": registration_finalization,
            "oidcSessionActivationRelease": oidc_session_activation_release,
            "oidcSessionActivationExecution": oidc_session_activation_execution,
            "oidcSessionActivationPlanning": oidc_session_activation_planning,
            "oidcSessionActivationConsumeExecution": oidc_session_activation_consume_execution,
            "oidcSessionActivationReleaseIntent": oidc_session_activation_release_intent})
        _v9_payload_shape(payload)
        envelope = {"schema": V9_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
        _v9_shape(envelope)
        original = configuration._configuration_wire(payload, capture._SharedLedger(work))
        _v9_material(payload, digest, public_key, work)
        keys._pair_on_work(private_key, public_key, work)
        _canonical(original, payload, work)
        payload_size, payload_nodes = _measure(payload, work)
        envelope_size, envelope_nodes = _measure(envelope, work)
        work.charge(input_bytes=3 * payload_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=payload_nodes + envelope_nodes)
        frame_bytes = 2 * len(V9_SCHEMA) + 9 + payload_size + 2 * 71
        if (work.limits.max_hashes - work.hash_work < 1
                or work.limits.max_input_bytes - work.input_bytes < frame_bytes + payload_size
                or work.limits.max_json_nodes - work.json_nodes < 4 + payload_nodes):
            raise EnrollmentBootstrapError("v9 bootstrap cannot reserve its signature output")
        message = plan._ascii(plan._frame(V9_SCHEMA, (original,), work), work)
        signature = production._sign_and_verify(private_key, public_key, message, work)
        if _measure(payload, work) != (payload_size, payload_nodes) or _encode(payload) != original:
            raise EnrollmentBootstrapError("v9 bootstrap payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        capability.shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = _encode(envelope)
        if len(result) != envelope_size:
            raise EnrollmentBootstrapError("v9 bootstrap output changed after reservation")
        return result
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, EnrollmentBootstrapError):
            raise
        raise EnrollmentBootstrapError("v9 enrollment bootstrap production failed") from exc


def _produce_v10_on_work(*, configuration_payload, generation, runtime_role_identities,
        configuration_digest, issuer_private_key_fd, signer_endpoint, registration_execution,
        registration_finalization, oidc_session_activation_release, oidc_session_activation_execution,
        oidc_session_activation_planning, oidc_session_activation_consume_execution,
        oidc_session_activation_release_intent, oidc_session_activation_release_proof,
        runtime_root_private_key, runtime_root_public_key, work):
    """Sign a distinct public-proof configuration after genuine original admission."""
    try:
        ledger = capture._SharedLedger(work)
        private_key, public_key = runtime_root_private_key, runtime_root_public_key
        digest, descriptor = configuration_digest, issuer_private_key_fd
        if not isinstance(private_key, Ed25519PrivateKey) or not isinstance(public_key, Ed25519PublicKey):
            raise EnrollmentBootstrapError("v10 bootstrap production requires the actual admitted root pair")
        capability.shape._digest(digest)
        capability.shape._bounded_object(generation, 24, "v10 bootstrap provisioner launch context")
        payload = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "schema": V10_PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "configurationDigest": digest, "configurationPayload": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtimeRoleIdentities": runtime_role_identities, "issuerPrivateKeyFd": descriptor,
            "signerEndpoint": signer_endpoint, "registrationExecution": registration_execution,
            "registrationFinalization": registration_finalization,
            "oidcSessionActivationRelease": oidc_session_activation_release,
            "oidcSessionActivationExecution": oidc_session_activation_execution,
            "oidcSessionActivationPlanning": oidc_session_activation_planning,
            "oidcSessionActivationConsumeExecution": oidc_session_activation_consume_execution,
            "oidcSessionActivationReleaseIntent": oidc_session_activation_release_intent,
            "oidcSessionActivationReleaseProof": oidc_session_activation_release_proof})
        _v10_payload_shape(payload)
        envelope = {"schema": V10_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
        _v10_shape(envelope)
        original = configuration._configuration_wire(payload, capture._SharedLedger(work))
        _v10_material(payload, digest, public_key, work)
        keys._pair_on_work(private_key, public_key, work)
        _canonical(original, payload, work)
        payload_size, payload_nodes = _measure(payload, work)
        envelope_size, envelope_nodes = _measure(envelope, work)
        work.charge(input_bytes=3 * payload_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=payload_nodes + envelope_nodes)
        frame_bytes = 2 * len(V10_SCHEMA) + 9 + payload_size + 2 * 71
        if (work.limits.max_hashes - work.hash_work < 1
                or work.limits.max_input_bytes - work.input_bytes < frame_bytes + payload_size
                or work.limits.max_json_nodes - work.json_nodes < 4 + payload_nodes):
            raise EnrollmentBootstrapError("v10 bootstrap cannot reserve its signature output")
        message = plan._ascii(plan._frame(V10_SCHEMA, (original,), work), work)
        signature = production._sign_and_verify(private_key, public_key, message, work)
        if _measure(payload, work) != (payload_size, payload_nodes) or _encode(payload) != original:
            raise EnrollmentBootstrapError("v10 bootstrap payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        capability.shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = _encode(envelope)
        if len(result) != envelope_size:
            raise EnrollmentBootstrapError("v10 bootstrap output changed after reservation")
        return result
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, EnrollmentBootstrapError):
            raise
        raise EnrollmentBootstrapError("v10 enrollment bootstrap production failed") from exc


def _produce_v11_on_work(*, configuration_payload, generation, runtime_role_identities,
        configuration_digest, issuer_private_key_fd, signer_endpoint, registration_execution,
        registration_finalization, oidc_session_activation_release, oidc_session_activation_execution,
        oidc_session_activation_planning, oidc_session_activation_consume_execution,
        oidc_session_activation_release_intent, oidc_session_activation_release_proof,
        oidc_session_activation_release_handoff, runtime_root_private_key, runtime_root_public_key, work):
    """Sign separate static handoff pins after actual parent original admission."""
    try:
        ledger = capture._SharedLedger(work)
        private_key, public_key = runtime_root_private_key, runtime_root_public_key
        digest, descriptor = configuration_digest, issuer_private_key_fd
        if not isinstance(private_key, Ed25519PrivateKey) or not isinstance(public_key, Ed25519PublicKey):
            raise EnrollmentBootstrapError("v11 bootstrap production requires the actual admitted root pair")
        capability.shape._digest(digest)
        capability.shape._bounded_object(generation, 24, "v11 bootstrap provisioner launch context")
        payload = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "schema": V11_PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "configurationDigest": digest, "configurationPayload": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtimeRoleIdentities": runtime_role_identities, "issuerPrivateKeyFd": descriptor,
            "signerEndpoint": signer_endpoint, "registrationExecution": registration_execution,
            "registrationFinalization": registration_finalization,
            "oidcSessionActivationRelease": oidc_session_activation_release,
            "oidcSessionActivationExecution": oidc_session_activation_execution,
            "oidcSessionActivationPlanning": oidc_session_activation_planning,
            "oidcSessionActivationConsumeExecution": oidc_session_activation_consume_execution,
            "oidcSessionActivationReleaseIntent": oidc_session_activation_release_intent,
            "oidcSessionActivationReleaseProof": oidc_session_activation_release_proof,
            "oidcSessionActivationReleaseHandoff": oidc_session_activation_release_handoff})
        _v11_payload_shape(payload)
        envelope = {"schema": V11_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
        _v11_shape(envelope)
        original = configuration._configuration_wire(payload, capture._SharedLedger(work))
        _v11_material(payload, digest, public_key, work)
        keys._pair_on_work(private_key, public_key, work)
        _canonical(original, payload, work)
        payload_size, payload_nodes = _measure(payload, work)
        envelope_size, envelope_nodes = _measure(envelope, work)
        work.charge(input_bytes=3 * payload_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=payload_nodes + envelope_nodes)
        frame_bytes = 2 * len(V11_SCHEMA) + 9 + payload_size + 2 * 71
        if (work.limits.max_hashes - work.hash_work < 1
                or work.limits.max_input_bytes - work.input_bytes < frame_bytes + payload_size
                or work.limits.max_json_nodes - work.json_nodes < 4 + payload_nodes):
            raise EnrollmentBootstrapError("v11 bootstrap cannot reserve its signature output")
        message = plan._ascii(plan._frame(V11_SCHEMA, (original,), work), work)
        signature = production._sign_and_verify(private_key, public_key, message, work)
        if _measure(payload, work) != (payload_size, payload_nodes) or _encode(payload) != original:
            raise EnrollmentBootstrapError("v11 bootstrap payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        capability.shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = _encode(envelope)
        if len(result) != envelope_size:
            raise EnrollmentBootstrapError("v11 bootstrap output changed after reservation")
        return result
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, EnrollmentBootstrapError):
            raise
        raise EnrollmentBootstrapError("v11 enrollment bootstrap production failed") from exc


def _produce_v12_on_work(*, configuration_payload, generation, runtime_role_identities,
        configuration_digest, issuer_private_key_fd, signer_endpoint, registration_execution,
        registration_finalization, oidc_session_activation_release, oidc_session_activation_execution,
        oidc_session_activation_planning, oidc_session_activation_consume_execution,
        oidc_session_activation_release_intent, oidc_session_activation_release_proof,
        oidc_session_activation_release_handoff, oidc_session_activation_release_grant_acquisition,
        runtime_root_private_key, runtime_root_public_key, work):
    """Sign the public acquisition endpoint after genuine parent admission."""
    try:
        ledger = capture._SharedLedger(work)
        private_key, public_key = runtime_root_private_key, runtime_root_public_key
        digest, descriptor = configuration_digest, issuer_private_key_fd
        if not isinstance(private_key, Ed25519PrivateKey) or not isinstance(public_key, Ed25519PublicKey):
            raise EnrollmentBootstrapError("v12 bootstrap production requires the actual admitted root pair")
        capability.shape._digest(digest)
        capability.shape._bounded_object(generation, 24, "v12 bootstrap provisioner launch context")
        payload = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "schema": V12_PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "configurationDigest": digest, "configurationPayload": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtimeRoleIdentities": runtime_role_identities, "issuerPrivateKeyFd": descriptor,
            "signerEndpoint": signer_endpoint, "registrationExecution": registration_execution,
            "registrationFinalization": registration_finalization,
            "oidcSessionActivationRelease": oidc_session_activation_release,
            "oidcSessionActivationExecution": oidc_session_activation_execution,
            "oidcSessionActivationPlanning": oidc_session_activation_planning,
            "oidcSessionActivationConsumeExecution": oidc_session_activation_consume_execution,
            "oidcSessionActivationReleaseIntent": oidc_session_activation_release_intent,
            "oidcSessionActivationReleaseProof": oidc_session_activation_release_proof,
            "oidcSessionActivationReleaseHandoff": oidc_session_activation_release_handoff,
            "oidcSessionActivationReleaseGrantAcquisition": oidc_session_activation_release_grant_acquisition})
        _v12_payload_shape(payload)
        envelope = {"schema": V12_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
        _v12_shape(envelope)
        original = configuration._configuration_wire(payload, capture._SharedLedger(work))
        _v12_material(payload, digest, public_key, work)
        keys._pair_on_work(private_key, public_key, work)
        _canonical(original, payload, work)
        payload_size, payload_nodes = _measure(payload, work)
        envelope_size, envelope_nodes = _measure(envelope, work)
        work.charge(input_bytes=3 * payload_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=payload_nodes + envelope_nodes)
        frame_bytes = 2 * len(V12_SCHEMA) + 9 + payload_size + 2 * 71
        if (work.limits.max_hashes - work.hash_work < 1
                or work.limits.max_input_bytes - work.input_bytes < frame_bytes + payload_size
                or work.limits.max_json_nodes - work.json_nodes < 4 + payload_nodes):
            raise EnrollmentBootstrapError("v12 bootstrap cannot reserve its signature output")
        message = plan._ascii(plan._frame(V12_SCHEMA, (original,), work), work)
        signature = production._sign_and_verify(private_key, public_key, message, work)
        if _measure(payload, work) != (payload_size, payload_nodes) or _encode(payload) != original:
            raise EnrollmentBootstrapError("v12 bootstrap payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        capability.shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = _encode(envelope)
        if len(result) != envelope_size:
            raise EnrollmentBootstrapError("v12 bootstrap output changed after reservation")
        return result
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, EnrollmentBootstrapError):
            raise
        raise EnrollmentBootstrapError("v12 enrollment bootstrap production failed") from exc


def _produce_v13_on_work(*, configuration_payload, generation, runtime_role_identities,
        configuration_digest, issuer_private_key_fd, signer_endpoint, registration_execution,
        registration_finalization, oidc_session_activation_release, oidc_session_activation_execution,
        oidc_session_activation_planning, oidc_session_activation_consume_execution,
        oidc_session_activation_release_intent, oidc_session_activation_release_proof,
        oidc_session_activation_release_handoff, oidc_session_activation_release_grant_acquisition,
        oidc_session_activation_consume_input_acquisition,
        runtime_root_private_key, runtime_root_public_key, work):
    """Sign the public consume-input endpoint and exact independent policy."""
    try:
        ledger = capture._SharedLedger(work)
        private_key, public_key = runtime_root_private_key, runtime_root_public_key
        digest, descriptor = configuration_digest, issuer_private_key_fd
        if not isinstance(private_key, Ed25519PrivateKey) or not isinstance(public_key, Ed25519PublicKey):
            raise EnrollmentBootstrapError("v13 bootstrap production requires the actual admitted root pair")
        capability.shape._digest(digest)
        capability.shape._bounded_object(generation, 24, "v13 bootstrap provisioner launch context")
        payload = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "schema": V13_PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "configurationDigest": digest, "configurationPayload": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtimeRoleIdentities": runtime_role_identities, "issuerPrivateKeyFd": descriptor,
            "signerEndpoint": signer_endpoint, "registrationExecution": registration_execution,
            "registrationFinalization": registration_finalization,
            "oidcSessionActivationRelease": oidc_session_activation_release,
            "oidcSessionActivationExecution": oidc_session_activation_execution,
            "oidcSessionActivationPlanning": oidc_session_activation_planning,
            "oidcSessionActivationConsumeExecution": oidc_session_activation_consume_execution,
            "oidcSessionActivationReleaseIntent": oidc_session_activation_release_intent,
            "oidcSessionActivationReleaseProof": oidc_session_activation_release_proof,
            "oidcSessionActivationReleaseHandoff": oidc_session_activation_release_handoff,
            "oidcSessionActivationReleaseGrantAcquisition": oidc_session_activation_release_grant_acquisition,
            "oidcSessionActivationConsumeInputAcquisition": oidc_session_activation_consume_input_acquisition})
        _v13_payload_shape(payload)
        envelope = {"schema": V13_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
        _v13_shape(envelope)
        original = configuration._configuration_wire(payload, capture._SharedLedger(work))
        _v13_material(payload, digest, public_key, work)
        keys._pair_on_work(private_key, public_key, work)
        _canonical(original, payload, work)
        payload_size, payload_nodes = _measure(payload, work)
        envelope_size, envelope_nodes = _measure(envelope, work)
        work.charge(input_bytes=3 * payload_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=payload_nodes + envelope_nodes)
        frame_bytes = 2 * len(V13_SCHEMA) + 9 + payload_size + 2 * 71
        if (work.limits.max_hashes - work.hash_work < 1
                or work.limits.max_input_bytes - work.input_bytes < frame_bytes + payload_size
                or work.limits.max_json_nodes - work.json_nodes < 4 + payload_nodes):
            raise EnrollmentBootstrapError("v13 bootstrap cannot reserve its signature output")
        message = plan._ascii(plan._frame(V13_SCHEMA, (original,), work), work)
        signature = production._sign_and_verify(private_key, public_key, message, work)
        if _measure(payload, work) != (payload_size, payload_nodes) or _encode(payload) != original:
            raise EnrollmentBootstrapError("v13 bootstrap payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        capability.shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = _encode(envelope)
        if len(result) != envelope_size:
            raise EnrollmentBootstrapError("v13 bootstrap output changed after reservation")
        return result
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, EnrollmentBootstrapError):
            raise
        raise EnrollmentBootstrapError("v13 enrollment bootstrap production failed") from exc


def _produce_v14_on_work(*, configuration_payload, generation, runtime_role_identities,
        configuration_digest, issuer_private_key_fd, signer_endpoint, registration_execution,
        registration_finalization, oidc_session_activation_release, oidc_session_activation_execution,
        oidc_session_activation_planning, oidc_session_activation_consume_execution,
        oidc_session_activation_release_intent, oidc_session_activation_release_proof,
        oidc_session_activation_release_handoff, oidc_session_activation_release_grant_acquisition,
        oidc_session_activation_consume_input_acquisition, oidc_session_activation_release_proof_acquisition,
        runtime_root_private_key, runtime_root_public_key, work):
    """Sign the public proof-setup endpoint and independent original policy."""
    try:
        ledger = capture._SharedLedger(work)
        private_key, public_key = runtime_root_private_key, runtime_root_public_key
        digest, descriptor = configuration_digest, issuer_private_key_fd
        if not isinstance(private_key, Ed25519PrivateKey) or not isinstance(public_key, Ed25519PublicKey):
            raise EnrollmentBootstrapError("v14 bootstrap production requires the actual admitted root pair")
        capability.shape._digest(digest)
        capability.shape._bounded_object(generation, 24, "v14 bootstrap provisioner launch context")
        payload = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "schema": V14_PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "configurationDigest": digest, "configurationPayload": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtimeRoleIdentities": runtime_role_identities, "issuerPrivateKeyFd": descriptor,
            "signerEndpoint": signer_endpoint, "registrationExecution": registration_execution,
            "registrationFinalization": registration_finalization,
            "oidcSessionActivationRelease": oidc_session_activation_release,
            "oidcSessionActivationExecution": oidc_session_activation_execution,
            "oidcSessionActivationPlanning": oidc_session_activation_planning,
            "oidcSessionActivationConsumeExecution": oidc_session_activation_consume_execution,
            "oidcSessionActivationReleaseIntent": oidc_session_activation_release_intent,
            "oidcSessionActivationReleaseProof": oidc_session_activation_release_proof,
            "oidcSessionActivationReleaseHandoff": oidc_session_activation_release_handoff,
            "oidcSessionActivationReleaseGrantAcquisition": oidc_session_activation_release_grant_acquisition,
            "oidcSessionActivationConsumeInputAcquisition": oidc_session_activation_consume_input_acquisition,
            "oidcSessionActivationReleaseProofAcquisition": oidc_session_activation_release_proof_acquisition})
        _v14_payload_shape(payload)
        envelope = {"schema": V14_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
        _v14_shape(envelope)
        original = configuration._configuration_wire(payload, capture._SharedLedger(work))
        _v14_material(payload, digest, public_key, work)
        keys._pair_on_work(private_key, public_key, work)
        _canonical(original, payload, work)
        payload_size, payload_nodes = _measure(payload, work)
        envelope_size, envelope_nodes = _measure(envelope, work)
        work.charge(input_bytes=3 * payload_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=payload_nodes + envelope_nodes)
        frame_bytes = 2 * len(V14_SCHEMA) + 9 + payload_size + 2 * 71
        if (work.limits.max_hashes - work.hash_work < 1
                or work.limits.max_input_bytes - work.input_bytes < frame_bytes + payload_size
                or work.limits.max_json_nodes - work.json_nodes < 4 + payload_nodes):
            raise EnrollmentBootstrapError("v14 bootstrap cannot reserve its signature output")
        message = plan._ascii(plan._frame(V14_SCHEMA, (original,), work), work)
        signature = production._sign_and_verify(private_key, public_key, message, work)
        if _measure(payload, work) != (payload_size, payload_nodes) or _encode(payload) != original:
            raise EnrollmentBootstrapError("v14 bootstrap payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        capability.shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = _encode(envelope)
        if len(result) != envelope_size:
            raise EnrollmentBootstrapError("v14 bootstrap output changed after reservation")
        return result
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, EnrollmentBootstrapError):
            raise
        raise EnrollmentBootstrapError("v14 enrollment bootstrap production failed") from exc


def _produce_v15_on_work(*, configuration_payload, generation, runtime_role_identities,
        configuration_digest, issuer_private_key_fd, signer_endpoint, registration_execution,
        registration_finalization, oidc_session_activation_release, oidc_session_activation_execution,
        oidc_session_activation_planning, oidc_session_activation_consume_execution,
        oidc_session_activation_release_intent, oidc_session_activation_release_proof,
        oidc_session_activation_release_handoff, oidc_session_activation_release_grant_acquisition,
        oidc_session_activation_consume_input_acquisition, oidc_session_activation_release_proof_acquisition,
        oidc_session_activation_release_recovery_grant_acquisition,
        runtime_root_private_key, runtime_root_public_key, work):
    """Sign public recovery acquisition originals without a new key or FD."""
    try:
        ledger = capture._SharedLedger(work)
        private_key, public_key = runtime_root_private_key, runtime_root_public_key
        digest, descriptor = configuration_digest, issuer_private_key_fd
        if not isinstance(private_key, Ed25519PrivateKey) or not isinstance(public_key, Ed25519PublicKey):
            raise EnrollmentBootstrapError("v15 bootstrap production requires the actual admitted root pair")
        capability.shape._digest(digest)
        capability.shape._bounded_object(generation, 24, "v15 bootstrap provisioner launch context")
        payload = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "schema": V15_PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "configurationDigest": digest, "configurationPayload": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtimeRoleIdentities": runtime_role_identities, "issuerPrivateKeyFd": descriptor,
            "signerEndpoint": signer_endpoint, "registrationExecution": registration_execution,
            "registrationFinalization": registration_finalization,
            "oidcSessionActivationRelease": oidc_session_activation_release,
            "oidcSessionActivationExecution": oidc_session_activation_execution,
            "oidcSessionActivationPlanning": oidc_session_activation_planning,
            "oidcSessionActivationConsumeExecution": oidc_session_activation_consume_execution,
            "oidcSessionActivationReleaseIntent": oidc_session_activation_release_intent,
            "oidcSessionActivationReleaseProof": oidc_session_activation_release_proof,
            "oidcSessionActivationReleaseHandoff": oidc_session_activation_release_handoff,
            "oidcSessionActivationReleaseGrantAcquisition": oidc_session_activation_release_grant_acquisition,
            "oidcSessionActivationConsumeInputAcquisition": oidc_session_activation_consume_input_acquisition,
            "oidcSessionActivationReleaseProofAcquisition": oidc_session_activation_release_proof_acquisition,
            "oidcSessionActivationReleaseRecoveryGrantAcquisition": oidc_session_activation_release_recovery_grant_acquisition})
        _v15_payload_shape(payload)
        envelope = {"schema": V15_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
        _v15_shape(envelope)
        _v15_material(payload, digest, public_key, work)
        keys._pair_on_work(private_key, public_key, work)
        payload_size, payload_nodes = _measure(payload, work)
        envelope_size, envelope_nodes = _measure(envelope, work)
        work.charge(input_bytes=3 * payload_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=payload_nodes + envelope_nodes)
        frame_bytes = 2 * len(V15_SCHEMA) + 9 + payload_size + 2 * 71
        if (work.limits.max_hashes - work.hash_work < 1
                or work.limits.max_input_bytes - work.input_bytes < frame_bytes + payload_size
                or work.limits.max_json_nodes - work.json_nodes < 4 + payload_nodes):
            raise EnrollmentBootstrapError("v15 bootstrap cannot reserve its signature output")
        original = configuration._configuration_wire(payload, capture._SharedLedger(work))
        if len(original) != payload_size:
            raise EnrollmentBootstrapError("v15 bootstrap payload changed after measurement")
        message = plan._ascii(plan._frame(V15_SCHEMA, (original,), work), work)
        signature = production._sign_and_verify(private_key, public_key, message, work)
        if _measure(payload, work) != (payload_size, payload_nodes) or _encode(payload) != original:
            raise EnrollmentBootstrapError("v15 bootstrap payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        capability.shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = _encode(envelope)
        if len(result) != envelope_size:
            raise EnrollmentBootstrapError("v15 bootstrap output changed after reservation")
        return result
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, EnrollmentBootstrapError):
            raise
        raise EnrollmentBootstrapError("v15 enrollment bootstrap production failed") from exc


def _produce_v16_on_work(*, configuration_payload, generation, runtime_role_identities,
        configuration_digest, issuer_private_key_fd, signer_endpoint, registration_execution,
        registration_finalization, oidc_session_activation_release, oidc_session_activation_execution,
        oidc_session_activation_planning, oidc_session_activation_consume_execution,
        oidc_session_activation_release_intent, oidc_session_activation_release_proof,
        oidc_session_activation_release_handoff, oidc_session_activation_release_grant_acquisition,
        oidc_session_activation_consume_input_acquisition, oidc_session_activation_release_proof_acquisition,
        oidc_session_activation_release_recovery_grant_acquisition,
        oidc_session_activation_completion_recovery,
        runtime_root_private_key, runtime_root_public_key, work):
    """Sign explicit fixed completion-recovery scope without granting an effect."""
    try:
        ledger = capture._SharedLedger(work)
        private_key, public_key = runtime_root_private_key, runtime_root_public_key
        digest, descriptor = configuration_digest, issuer_private_key_fd
        if not isinstance(private_key, Ed25519PrivateKey) or not isinstance(public_key, Ed25519PublicKey):
            raise EnrollmentBootstrapError("v16 bootstrap production requires the actual admitted root pair")
        capability.shape._digest(digest)
        capability.shape._bounded_object(generation, 24, "v16 bootstrap provisioner launch context")
        payload = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "schema": V16_PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "configurationDigest": digest, "configurationPayload": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtimeRoleIdentities": runtime_role_identities, "issuerPrivateKeyFd": descriptor,
            "signerEndpoint": signer_endpoint, "registrationExecution": registration_execution,
            "registrationFinalization": registration_finalization,
            "oidcSessionActivationRelease": oidc_session_activation_release,
            "oidcSessionActivationExecution": oidc_session_activation_execution,
            "oidcSessionActivationPlanning": oidc_session_activation_planning,
            "oidcSessionActivationConsumeExecution": oidc_session_activation_consume_execution,
            "oidcSessionActivationReleaseIntent": oidc_session_activation_release_intent,
            "oidcSessionActivationReleaseProof": oidc_session_activation_release_proof,
            "oidcSessionActivationReleaseHandoff": oidc_session_activation_release_handoff,
            "oidcSessionActivationReleaseGrantAcquisition": oidc_session_activation_release_grant_acquisition,
            "oidcSessionActivationConsumeInputAcquisition": oidc_session_activation_consume_input_acquisition,
            "oidcSessionActivationReleaseProofAcquisition": oidc_session_activation_release_proof_acquisition,
            "oidcSessionActivationReleaseRecoveryGrantAcquisition": oidc_session_activation_release_recovery_grant_acquisition,
            "oidcSessionActivationCompletionRecovery": oidc_session_activation_completion_recovery})
        _v16_payload_shape(payload)
        envelope = {"schema": V16_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
        _v16_shape(envelope)
        _v16_material(payload, digest, public_key, work)
        keys._pair_on_work(private_key, public_key, work)
        payload_size, payload_nodes = _measure(payload, work)
        envelope_size, envelope_nodes = _measure(envelope, work)
        work.charge(input_bytes=3 * payload_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=payload_nodes + envelope_nodes)
        frame_bytes = 2 * len(V16_SCHEMA) + 9 + payload_size + 2 * 71
        if (work.limits.max_hashes - work.hash_work < 1
                or work.limits.max_input_bytes - work.input_bytes < frame_bytes + payload_size
                or work.limits.max_json_nodes - work.json_nodes < 4 + payload_nodes):
            raise EnrollmentBootstrapError("v16 bootstrap cannot reserve its signature output")
        original = configuration._configuration_wire(payload, capture._SharedLedger(work))
        if len(original) != payload_size:
            raise EnrollmentBootstrapError("v16 bootstrap payload changed after measurement")
        message = plan._ascii(plan._frame(V16_SCHEMA, (original,), work), work)
        signature = production._sign_and_verify(private_key, public_key, message, work)
        if _measure(payload, work) != (payload_size, payload_nodes) or _encode(payload) != original:
            raise EnrollmentBootstrapError("v16 bootstrap payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        capability.shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = _encode(envelope)
        if len(result) != envelope_size:
            raise EnrollmentBootstrapError("v16 bootstrap output changed after reservation")
        return result
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, EnrollmentBootstrapError):
            raise
        raise EnrollmentBootstrapError("v16 enrollment bootstrap production failed") from exc


def _produce_v17_on_work(*, configuration_payload, generation, runtime_role_identities,
        configuration_digest, issuer_private_key_fd, signer_endpoint, registration_execution,
        registration_finalization, oidc_session_activation_release, oidc_session_activation_execution,
        oidc_session_activation_planning, oidc_session_activation_consume_execution,
        oidc_session_activation_release_intent, oidc_session_activation_release_proof,
        oidc_session_activation_release_handoff, oidc_session_activation_release_grant_acquisition,
        oidc_session_activation_consume_input_acquisition, oidc_session_activation_release_proof_acquisition,
        oidc_session_activation_release_recovery_grant_acquisition,
        oidc_session_activation_completion_recovery, registration_history,
        history_current_interval, history_now_epoch_ns,
        runtime_root_private_key, runtime_root_public_key, work):
    """Independent provisioner signs explicit history; no key or effect is created."""
    try:
        ledger = capture._SharedLedger(work)
        private_key, public_key = runtime_root_private_key, runtime_root_public_key
        digest, descriptor = configuration_digest, issuer_private_key_fd
        if not isinstance(private_key, Ed25519PrivateKey) or not isinstance(public_key, Ed25519PublicKey):
            raise EnrollmentBootstrapError("v17 bootstrap production requires the actual admitted root pair")
        capability.shape._digest(digest)
        capability.shape._bounded_object(generation, 24, "v17 bootstrap provisioner launch context")
        payload = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "schema": V17_PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "configurationDigest": digest, "configurationPayload": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtimeRoleIdentities": runtime_role_identities, "issuerPrivateKeyFd": descriptor,
            "signerEndpoint": signer_endpoint, "registrationExecution": registration_execution,
            "registrationFinalization": registration_finalization,
            "oidcSessionActivationRelease": oidc_session_activation_release,
            "oidcSessionActivationExecution": oidc_session_activation_execution,
            "oidcSessionActivationPlanning": oidc_session_activation_planning,
            "oidcSessionActivationConsumeExecution": oidc_session_activation_consume_execution,
            "oidcSessionActivationReleaseIntent": oidc_session_activation_release_intent,
            "oidcSessionActivationReleaseProof": oidc_session_activation_release_proof,
            "oidcSessionActivationReleaseHandoff": oidc_session_activation_release_handoff,
            "oidcSessionActivationReleaseGrantAcquisition": oidc_session_activation_release_grant_acquisition,
            "oidcSessionActivationConsumeInputAcquisition": oidc_session_activation_consume_input_acquisition,
            "oidcSessionActivationReleaseProofAcquisition": oidc_session_activation_release_proof_acquisition,
            "oidcSessionActivationReleaseRecoveryGrantAcquisition": oidc_session_activation_release_recovery_grant_acquisition,
            "oidcSessionActivationCompletionRecovery": oidc_session_activation_completion_recovery,
            "registrationHistory": registration_history})
        _v17_payload_shape(payload)
        envelope = {"schema": V17_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
        _v17_shape(envelope)
        _v17_material(payload, digest, public_key, work,
            current_interval=history_current_interval, now_epoch_ns=history_now_epoch_ns)
        keys._pair_on_work(private_key, public_key, work)
        payload_size, payload_nodes = _measure(payload, work)
        envelope_size, envelope_nodes = _measure(envelope, work)
        work.charge(input_bytes=3 * payload_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=payload_nodes + envelope_nodes)
        frame_bytes = 2 * len(V17_SCHEMA) + 9 + payload_size + 2 * 71
        if (work.limits.max_hashes - work.hash_work < 1
                or work.limits.max_input_bytes - work.input_bytes < frame_bytes + payload_size
                or work.limits.max_json_nodes - work.json_nodes < 4 + payload_nodes):
            raise EnrollmentBootstrapError("v17 bootstrap cannot reserve its signature output")
        original = configuration._configuration_wire(payload, capture._SharedLedger(work))
        if len(original) != payload_size:
            raise EnrollmentBootstrapError("v17 bootstrap payload changed after measurement")
        message = plan._ascii(plan._frame(V17_SCHEMA, (original,), work), work)
        signature = production._sign_and_verify(private_key, public_key, message, work)
        if _measure(payload, work) != (payload_size, payload_nodes) or _encode(payload) != original:
            raise EnrollmentBootstrapError("v17 bootstrap payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        capability.shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = _encode(envelope)
        if len(result) != envelope_size:
            raise EnrollmentBootstrapError("v17 bootstrap output changed after reservation")
        return result
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, EnrollmentBootstrapError):
            raise
        raise EnrollmentBootstrapError("v17 enrollment bootstrap production failed") from exc


def _produce_v18_on_work(*, configuration_payload, generation, runtime_role_identities,
        configuration_digest, issuer_private_key_fd, signer_endpoint, registration_execution,
        registration_finalization, oidc_session_activation_release, oidc_session_activation_execution,
        oidc_session_activation_planning, oidc_session_activation_consume_execution,
        oidc_session_activation_release_intent, oidc_session_activation_release_proof,
        oidc_session_activation_release_handoff, oidc_session_activation_release_grant_acquisition,
        oidc_session_activation_consume_input_acquisition, oidc_session_activation_release_proof_acquisition,
        oidc_session_activation_release_recovery_grant_acquisition,
        oidc_session_activation_completion_recovery, registration_history, finalization_history,
        history_current_interval, history_now_epoch_ns,
        runtime_root_private_key, runtime_root_public_key, work):
    """Sign shared-archive finalization history without issuing execution authority."""
    try:
        ledger = capture._SharedLedger(work)
        private_key, public_key = runtime_root_private_key, runtime_root_public_key
        digest, descriptor = configuration_digest, issuer_private_key_fd
        if not isinstance(private_key, Ed25519PrivateKey) or not isinstance(public_key, Ed25519PublicKey):
            raise EnrollmentBootstrapError("v18 bootstrap production requires the actual admitted root pair")
        capability.shape._digest(digest)
        capability.shape._bounded_object(generation, 24, "v18 bootstrap provisioner launch context")
        payload = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "schema": V18_PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "configurationDigest": digest, "configurationPayload": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtimeRoleIdentities": runtime_role_identities, "issuerPrivateKeyFd": descriptor,
            "signerEndpoint": signer_endpoint, "registrationExecution": registration_execution,
            "registrationFinalization": registration_finalization,
            "oidcSessionActivationRelease": oidc_session_activation_release,
            "oidcSessionActivationExecution": oidc_session_activation_execution,
            "oidcSessionActivationPlanning": oidc_session_activation_planning,
            "oidcSessionActivationConsumeExecution": oidc_session_activation_consume_execution,
            "oidcSessionActivationReleaseIntent": oidc_session_activation_release_intent,
            "oidcSessionActivationReleaseProof": oidc_session_activation_release_proof,
            "oidcSessionActivationReleaseHandoff": oidc_session_activation_release_handoff,
            "oidcSessionActivationReleaseGrantAcquisition": oidc_session_activation_release_grant_acquisition,
            "oidcSessionActivationConsumeInputAcquisition": oidc_session_activation_consume_input_acquisition,
            "oidcSessionActivationReleaseProofAcquisition": oidc_session_activation_release_proof_acquisition,
            "oidcSessionActivationReleaseRecoveryGrantAcquisition": oidc_session_activation_release_recovery_grant_acquisition,
            "oidcSessionActivationCompletionRecovery": oidc_session_activation_completion_recovery,
            "registrationHistory": registration_history, "finalizationHistory": finalization_history})
        _v18_payload_shape(payload)
        envelope = {"schema": V18_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
        _v18_shape(envelope)
        _v18_material(payload, digest, public_key, work,
            current_interval=history_current_interval, now_epoch_ns=history_now_epoch_ns)
        keys._pair_on_work(private_key, public_key, work)
        payload_size, payload_nodes = _measure(payload, work)
        envelope_size, envelope_nodes = _measure(envelope, work)
        work.charge(input_bytes=3 * payload_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=payload_nodes + envelope_nodes)
        frame_bytes = 2 * len(V18_SCHEMA) + 9 + payload_size + 2 * 71
        if (work.limits.max_hashes - work.hash_work < 1
                or work.limits.max_input_bytes - work.input_bytes < frame_bytes + payload_size
                or work.limits.max_json_nodes - work.json_nodes < 4 + payload_nodes):
            raise EnrollmentBootstrapError("v18 bootstrap cannot reserve its signature output")
        original = configuration._configuration_wire(payload, capture._SharedLedger(work))
        if len(original) != payload_size:
            raise EnrollmentBootstrapError("v18 bootstrap payload changed after measurement")
        message = plan._ascii(plan._frame(V18_SCHEMA, (original,), work), work)
        signature = production._sign_and_verify(private_key, public_key, message, work)
        if _measure(payload, work) != (payload_size, payload_nodes) or _encode(payload) != original:
            raise EnrollmentBootstrapError("v18 bootstrap payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        capability.shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = _encode(envelope)
        if len(result) != envelope_size:
            raise EnrollmentBootstrapError("v18 bootstrap output changed after reservation")
        return result
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, EnrollmentBootstrapError):
            raise
        raise EnrollmentBootstrapError("v18 enrollment bootstrap production failed") from exc
