"""Public-only release-proof enrollment and endpoint inside explicit parent v10.

The root-selected producer scope is independent of the intent caller identity.
This cold configuration admits no request, committed outcome or present release
permission, and delivers no proof signing, delivery or historical private key.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import control_plane_oidc_session_activation_release_intent_bootstrap as intent
from catchplate import oidc_session_activation_release_proof_enrollment as enrollment


SCHEMA = "catchplate.controlPlaneOidcSessionActivationReleaseProof/v1"
SOCKET_PATH = "/run/catchplate/oidc-session-activation-token-release/proof.sock"
MAX_BYTES = intent.MAX_BYTES
_FIELDS = frozenset({"schema", "proofEnrollment", "expectedScope", "endpoint"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount"})
_ENDPOINT_FIELDS = frozenset({"socketPath", "requestTimeoutSeconds", "listenerUid", "listenerGid"})
_SHARED_FIELDS = ("configurationDigest", "databaseId", "generationDigest",
    "runtimeClosureDigest", "receiverIdentity")
configuration, shape, capture, plan = intent.configuration, enrollment.shape, enrollment.capture, enrollment.plan


class OidcSessionActivationReleaseProofBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ReleaseProofMaterial:
    proof_public_key: object
    enrollment_bytes: bytes
    enrollment_digest: str
    expected_scope_bytes: bytes
    endpoint: tuple
    forbidden_public_keys: tuple


def _endpoint(value):
    shape._object(value, _ENDPOINT_FIELDS, "release proof endpoint")
    shape._literal(value["socketPath"], SOCKET_PATH)
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name in ("listenerUid", "listenerGid"):
        shape._integer(value[name], 2**32 - 2)
        if value[name] != 0:
            raise OidcSessionActivationReleaseProofBootstrapError(
                "release proof listener must be the fixed root-created peer")
    return value["socketPath"], value["requestTimeoutSeconds"], 0, 0


def _shape(value):
    if value is None:
        return
    shape._object(value, _FIELDS, "control-plane release proof configuration")
    shape._literal(value["schema"], SCHEMA)
    enrollment._scope_shape(value["expectedScope"])
    original = value["proofEnrollment"]
    shape._object(original, _ORIGINAL_FIELDS, "release proof enrollment original")
    shape._integer(original["byteCount"], enrollment.MAX_BYTES, minimum=2)
    enrollment.authorization.transport._transport_shape(
        original["base64Url"], original["byteCount"], enrollment.MAX_BYTES)
    _endpoint(value["endpoint"])


def _scope_on_work(scope_bytes, work):
    original = enrollment.authorization._original(scope_bytes, enrollment.MAX_BYTES,
        "independent cold proof scope")
    decoded = enrollment.wire._decode_object(original, work=work,
        maximum_bytes=enrollment.MAX_BYTES, maximum_nodes=enrollment.MAX_NODES,
        maximum_depth=enrollment.MAX_DEPTH)
    owned = enrollment._scope(decoded, work)
    enrollment.capability._canonical(original, owned, capture._SharedLedger(work),
        enrollment.MAX_BYTES, enrollment.MAX_NODES)
    return owned


def _admit_on_work(*, release_proof, release_intent, configuration_payload,
        runtime_root_public_key, work):
    try:
        ledger = capture._SharedLedger(work)
        root, intent_material = runtime_root_public_key, release_intent
        _shape(release_proof)
        if release_proof is None:
            return None
        if type(intent_material) is not intent._ReleaseIntentMaterial:
            raise OidcSessionActivationReleaseProofBootstrapError(
                "release proof requires actual parent release-intent admission")
        intent_scope_bytes = intent_material.expected_scope_bytes
        intent_enrollment_bytes = intent_material.enrollment_bytes
        intent_enrollment_digest = intent_material.enrollment_digest
        intent_key = intent_material.caller_public_key
        held_keys = intent_material.forbidden_public_keys
        enrollment.authorization._public(root)
        owned = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "proof": release_proof, "configuration": configuration_payload})
        value = owned["proof"]
        _shape(value)
        expected = enrollment._scope(value["expectedScope"], work)
        intent_scope = intent._scope_on_work(intent_scope_bytes, work)
        # Reauthenticate the retained intent enrollment, not its material alone.
        admitted_intent = intent.enrollment._admit_on_work(
            enrollment_bytes=intent_enrollment_bytes, root_public_key=root,
            expected_scope=intent_scope, forbidden_public_keys=held_keys, work=work)
        plan._same(admitted_intent.enrollment_digest, intent_enrollment_digest, work,
            "release proof parent intent enrollment")
        plan._same(enrollment.keys._spki_on_work(admitted_intent.caller_public_key, work),
            enrollment.keys._spki_on_work(intent_key, work), work,
            "release proof parent intent key")
        for name in _SHARED_FIELDS:
            plan._same(expected[name], intent_scope[name], work,
                "release proof independent shared " + name)
        # producerId/producerIdentity stay independent; callerId is not relabeled.
        forbidden = intent._unique_keys((*held_keys, intent_key), work)
        record = value["proofEnrollment"]
        raw = enrollment.authorization.transport._decode(
            record["base64Url"], record["byteCount"], enrollment.MAX_BYTES, work)
        admitted = enrollment._admit_on_work(enrollment_bytes=raw, root_public_key=root,
            expected_scope=expected, forbidden_public_keys=forbidden, work=work)
        pin = admitted.payload["proofKey"]["spkiDigest"]
        pins = intent.activation._purpose_pins(owned["configuration"], root, forbidden, work)
        work.prepare_scan(pins)
        for previous in pins:
            work.prepare_comparison(pin, previous)
            if pin == previous:
                raise OidcSessionActivationReleaseProofBootstrapError(
                    "release proof key reuses another configured purpose")
        scope_bytes = enrollment.capability._wire(expected, ledger, enrollment.MAX_BYTES, enrollment.MAX_NODES)
        _scope_on_work(scope_bytes, work)
        return _ReleaseProofMaterial(admitted.proof_public_key, raw,
            admitted.enrollment_digest, scope_bytes, _endpoint(value["endpoint"]), forbidden)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, OidcSessionActivationReleaseProofBootstrapError):
            raise
        raise OidcSessionActivationReleaseProofBootstrapError("release proof cold admission failed") from exc
