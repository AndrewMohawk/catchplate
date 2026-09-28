"""Public proof-setup endpoint and original policy in signed parent v14.

Cold signature/static joins do not create a live policy allowance. The caller
admits the original policy and returned bootstrap under its existing proof
continuation; no packet, private key or new processing window enters here.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_oidc_session_activation_release_proof_input_transport as transport
from serverware import control_plane_oidc_session_activation_release_intent_bootstrap as intent
from serverware import control_plane_oidc_session_activation_release_proof_bootstrap as proof
from serverware import oidc_session_activation_release_proof_input_issuer_policy as issuer


SCHEMA = "serverware.controlPlaneOidcSessionActivationReleaseProofAcquisition/v1"
SOCKET_PATH = "/run/serverware/oidc-session-activation-release-proof-inputs/grants.sock"
MAX_BYTES, MAX_NODES, MAX_DEPTH = 128 * 1024, 64, 4
shape, capture, plan = proof.shape, proof.capture, proof.plan
_FIELDS = frozenset({"schema", "endpoint", "issuerPolicy"})
_ENDPOINT_FIELDS = frozenset({"path", "timeoutSeconds", "peerUid", "peerGid"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount"})


class OidcSessionActivationReleaseProofAcquisitionBootstrapError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationReleaseProofAcquisitionBootstrapError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ReleaseProofAcquisitionMaterial:
    endpoint: tuple
    issuer_policy_bytes: bytes


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("release proof acquisition exceeds its shape bound")
        owned = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("release proof acquisition exceeds its node bound")
        return owned


def _endpoint(value):
    shape._object(value, _ENDPOINT_FIELDS, "release proof acquisition endpoint")
    shape._literal(value["path"], SOCKET_PATH)
    shape._integer(value["timeoutSeconds"], 30, minimum=1)
    for name in ("peerUid", "peerGid"):
        shape._integer(value[name], 2**32 - 2)
    return transport._endpoint((value["path"], value["timeoutSeconds"],
        value["peerUid"], value["peerGid"]))


def _shape(value):
    if value is None:
        return
    shape._object(value, _FIELDS, "control-plane release proof acquisition")
    shape._literal(value["schema"], SCHEMA)
    _endpoint(value["endpoint"])
    original = value["issuerPolicy"]
    shape._object(original, _ORIGINAL_FIELDS, "release proof issuer policy original")
    shape._integer(original["byteCount"], issuer.MAX_BYTES, minimum=2)
    intent.enrollment.authorization.transport._transport_shape(
        original["base64Url"], original["byteCount"], issuer.MAX_BYTES)


def _policy_on_work(original, *, release_intent, release_proof, root_public_key, work):
    """Authenticate only static root policy and exact independently admitted pins."""
    if (type(release_intent) is not intent._ReleaseIntentMaterial
            or type(release_proof) is not proof._ReleaseProofMaterial):
        _fail("release proof acquisition requires actual intent and proof configuration")
    original = intent.enrollment.authorization._original(
        original, issuer.MAX_BYTES, "release proof issuer policy")
    intent.enrollment.authorization._public(root_public_key)
    envelope = issuer._read(original, work)
    issuer._signature(envelope, root_public_key, work)
    payload = envelope["payload"]
    intent_scope = intent._scope_on_work(release_intent.expected_scope_bytes, work)
    proof_scope = proof._scope_on_work(release_proof.expected_scope_bytes, work)
    for actual, expected, label in (
            (payload["proofScope"], proof_scope, "independent proof scope"),
            (payload["callerId"], intent_scope["callerId"], "independent intent caller"),
            (payload["proofEnrollmentDigest"], release_proof.enrollment_digest, "proof enrollment"),
            (payload["intentEnrollmentDigest"], release_intent.enrollment_digest, "intent enrollment")):
        plan._same(actual, expected, work, "release proof acquisition " + label)
    return payload


def _admit_on_work(*, release_proof_acquisition, release_intent, release_proof,
        runtime_root_public_key, work):
    """Preserve the exact policy original without inventing cold liveness."""
    try:
        ledger = capture._SharedLedger(work)
        _shape(release_proof_acquisition)
        if release_proof_acquisition is None:
            return None
        held_intent, held_proof, root = release_intent, release_proof, runtime_root_public_key
        owned = _Capture(ledger, maximum_bytes=MAX_BYTES).visit(release_proof_acquisition)
        _shape(owned)
        wrapped = owned["issuerPolicy"]
        original = intent.enrollment.authorization.transport._decode(
            wrapped["base64Url"], wrapped["byteCount"], issuer.MAX_BYTES, work)
        endpoint = _endpoint(owned["endpoint"])
        _policy_on_work(original, release_intent=held_intent, release_proof=held_proof,
            root_public_key=root, work=work)
        return _ReleaseProofAcquisitionMaterial(endpoint, original)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, OidcSessionActivationReleaseProofAcquisitionBootstrapError):
            raise
        raise OidcSessionActivationReleaseProofAcquisitionBootstrapError(
            "release proof acquisition cold configuration failed") from exc
