"""Explicit all-nine request-bound parent profile, without future originals.

Old parent versions keep their exact shapes and child restrictions. This
profile uses the same genuine child admissions and cold owner material, but
selects only resource-bound children where request originals do not yet exist.
"""
from __future__ import annotations

import base64

from serverware import control_plane_enrollment_bootstrap as parent
from serverware import control_plane_oidc_session_activation_execution_bootstrap as activation
from serverware import control_plane_oidc_session_activation_request_issuance_bootstrap as planning
from serverware import control_plane_oidc_session_activation_consume_execution_bootstrap as consume
from serverware import control_plane_oidc_session_activation_release_intent_bootstrap as intent
from serverware import control_plane_oidc_session_activation_release_proof_bootstrap as proof
from serverware import control_plane_oidc_session_activation_release_handoff_bootstrap as handoff
from serverware import control_plane_oidc_session_activation_release_grant_acquisition_bootstrap as grants
from serverware import control_plane_oidc_session_activation_consume_input_acquisition_bootstrap as inputs
from serverware import control_plane_oidc_session_activation_release_proof_acquisition_bootstrap as proofs


SCHEMA = "serverware.signedControlPlaneEnrollmentBootstrap/v24"
PAYLOAD_SCHEMA = "serverware.controlPlaneEnrollmentBootstrap/v24"
FIELDS = parent._V14_PAYLOAD_FIELDS


def _payload_shape(payload):
    shape = parent.capability.shape
    shape._object(payload, FIELDS, "request-bound enrollment parent")
    shape._literal(payload["schema"], PAYLOAD_SCHEMA)
    prior = {name: payload[name] for name in parent._V4_PAYLOAD_FIELDS}
    prior["schema"] = parent.V4_PAYLOAD_SCHEMA
    parent._v4_payload_shape(prior)
    if payload["oidcSessionActivationRelease"] is not None:
        raise parent.EnrollmentBootstrapError("request parent excludes the old fixed-original release client")
    for name, module, schema in (
            ("oidcSessionActivationExecution", activation, activation.V5_SCHEMA),
            ("oidcSessionActivationPlanning", planning, planning.SCHEMA),
            ("oidcSessionActivationConsumeExecution", consume, consume.V5_SCHEMA),
            ("oidcSessionActivationReleaseIntent", intent, intent.V2_SCHEMA),
            ("oidcSessionActivationReleaseProof", proof, proof.SCHEMA),
            ("oidcSessionActivationReleaseHandoff", handoff, handoff.SCHEMA),
            ("oidcSessionActivationReleaseGrantAcquisition", grants, grants.SCHEMA),
            ("oidcSessionActivationConsumeInputAcquisition", inputs, inputs.V3_SCHEMA),
            ("oidcSessionActivationReleaseProofAcquisition", proofs, proofs.V3_SCHEMA)):
        selected = payload[name]
        if type(selected) is not dict:
            raise parent.EnrollmentBootstrapError("request parent requires every actual activation lane")
        shape._literal(selected.get("schema"), schema)
        module._shape(selected)
    if payload["issuerPrivateKeyFd"] in (activation.CALLER_KEY_FD, consume.CALLER_KEY_FD, intent.CALLER_KEY_FD):
        raise parent.EnrollmentBootstrapError("request parent reserves all three distinct activation caller slots")


def _shape(envelope):
    parent.capability.shape._object(envelope, parent._ENVELOPE_FIELDS, "request-bound parent envelope")
    parent.capability.shape._literal(envelope["schema"], SCHEMA)
    parent.capability.shape._base64url(envelope["signatureBase64Url"], signature=True)
    _payload_shape(envelope["payload"])


def _material(payload, expected_digest, root, work, *, live_window, transport_deadline_ns):
    # The genuine startup supplies its one actual processing bracket. A
    # missing pair is not permission to open a second clock or work allowance.
    if live_window is None or transport_deadline_ns is None:
        raise parent.EnrollmentBootstrapError("request parent requires its actual cold processing window")
    current = planning.policy.planner._processing(live_window, transport_deadline_ns, work)
    current()
    _payload_shape(payload)
    material = parent._v14_material(payload, expected_digest, root, work)
    current()
    if (type(material.activation_planning) is not planning._RequestPlanningMaterial
            or material.activation_execution.request_bound is not True
            or material.consume_execution.request_bound is not True
            or material.activation_execution.reservation_predecessor is not None
            or material.consume_execution.reservation_predecessor is not None
            or material.consume_input_acquisition.request_bound is not True
            or material.release_proof_acquisition.request_bound is not True):
        raise parent.EnrollmentBootstrapError("request parent lost an actual resource-bound child")
    # Bind the final return to the original static signed interval as well as
    # the independently supplied processing bracket. This creates no launch.
    policy = planning.policy._verify_on_work(policy_bytes=material.activation_planning.policy_bytes,
        root_public_key=root, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work)

    def final():
        current()
        return policy.live()

    final()
    return material, final


def _produce_on_work(*, payload, runtime_root_private_key, runtime_root_public_key,
        live_window, transport_deadline_ns, work):
    ledger = parent.capture._SharedLedger(work)
    private, root = runtime_root_private_key, runtime_root_public_key
    planning.policy.authorization._private(private)
    planning.policy.authorization._public(root)
    owned = parent.configuration._ConfigurationCapture(ledger, maximum_bytes=parent.MAX_BYTES).visit(payload)
    _payload_shape(owned)
    envelope = dict(schema=SCHEMA, payload=owned, signatureBase64Url="A" * 86)
    _shape(envelope)
    original = parent.configuration._configuration_wire(owned, parent.capture._SharedLedger(work))
    _material_owned, current = _material(owned, owned["configurationDigest"], root, work,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns)
    current()
    parent.keys._pair_on_work(private, root, work)
    current()
    parent._canonical(original, owned, work)
    size, nodes = parent._measure(owned, work)
    envelope_size, envelope_nodes = parent._measure(envelope, work)
    work.charge(input_bytes=3 * size + envelope_size + parent.production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=nodes + envelope_nodes)
    frame_bytes = 2 * len(SCHEMA) + 9 + size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + size
            or work.limits.max_json_nodes - work.json_nodes < 4 + nodes):
        raise parent.EnrollmentBootstrapError("request parent cannot reserve its actual signature output")
    message = parent.plan._ascii(parent.plan._frame(SCHEMA, (original,), work), work)
    current()
    signature = parent.production._sign_and_verify(private, root, message, work)
    current()
    if parent._measure(owned, work) != (size, nodes) or parent._encode(owned) != original:
        raise parent.EnrollmentBootstrapError("request parent changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    parent.capability.shape._base64url(encoded, signature=True)
    envelope["signatureBase64Url"] = encoded
    result = parent._encode(envelope)
    if len(result) != envelope_size:
        raise parent.EnrollmentBootstrapError("request parent changed its reserved encoding")
    current()
    return result
