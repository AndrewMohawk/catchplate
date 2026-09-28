"""Public recovery issuer originals in explicit signed parent v15.

Cold signature and static original joins create no recovery permission or live
allowance. The actual client must freshly admit every original under the
actor's existing work/window before contacting the separate recovery issuer.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_oidc_session_activation_release_recovery_grant_transport as transport
from serverware import control_plane_oidc_session_activation_release_intent_bootstrap as intent
from serverware import control_plane_oidc_session_activation_release_proof_bootstrap as proof
from serverware import oidc_session_activation_release_recovery_issuer_policy as issuer


SCHEMA = "serverware.controlPlaneOidcSessionActivationReleaseRecoveryGrantAcquisition/v1"
SOCKET_PATH = transport.LISTENER_PATH
MAX_BYTES = issuer.authority.MAX_REQUEST_BYTES
MAX_NODES, MAX_DEPTH = 128, 4
shape, capture, plan = issuer.shape, issuer.capture, issuer.plan
_FIELDS = frozenset({"schema", "endpoint", "issuerPolicy", "releaseCustody", "proofEnrollment", "intentEnrollment"})
_ENDPOINT_FIELDS = frozenset({"path", "timeoutSeconds", "peerUid", "peerGid"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount"})
_ORIGINALS = (("issuerPolicy", issuer.MAX_BYTES), ("releaseCustody", issuer.MAX_CUSTODY_BYTES),
    ("proofEnrollment", issuer.MAX_PROOF_ENROLLMENT_BYTES),
    ("intentEnrollment", issuer.MAX_INTENT_ENROLLMENT_BYTES))


class OidcSessionActivationReleaseRecoveryGrantAcquisitionBootstrapError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationReleaseRecoveryGrantAcquisitionBootstrapError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _RecoveryGrantAcquisitionMaterial:
    """Exact independent cold inputs, never a current authorization result."""

    endpoint: tuple
    issuer_policy_bytes: bytes
    release_custody_bytes: bytes
    proof_enrollment_bytes: bytes
    intent_enrollment_bytes: bytes


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("recovery grant acquisition exceeds its structure bound")
        owned = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("recovery grant acquisition exceeds its node bound")
        return owned


def _endpoint(value):
    shape._object(value, _ENDPOINT_FIELDS, "recovery grant acquisition endpoint")
    shape._literal(value["path"], SOCKET_PATH)
    shape._integer(value["timeoutSeconds"], 30, minimum=1)
    for name in ("peerUid", "peerGid"):
        shape._integer(value[name], 2**32 - 2)
    return transport._endpoint((value["path"], value["timeoutSeconds"], value["peerUid"], value["peerGid"]))


def _shape(value):
    if value is None:
        return
    shape._object(value, _FIELDS, "control-plane recovery grant acquisition")
    shape._literal(value["schema"], SCHEMA)
    _endpoint(value["endpoint"])
    for name, maximum in _ORIGINALS:
        original = value[name]
        shape._object(original, _ORIGINAL_FIELDS, "recovery grant " + name + " original")
        shape._integer(original["byteCount"], maximum, minimum=2)
        issuer.authorization.transport._transport_shape(original["base64Url"], original["byteCount"], maximum)


def _same_bytes(actual, expected, work, label):
    if type(actual) is not bytes or type(expected) is not bytes:
        _fail(label + " requires immutable original bytes")
    work.charge(input_bytes=len(actual) + len(expected))
    if actual != expected:
        _fail(label + " differs")


def _admit_on_work(*, recovery_grant_acquisition, release_intent, release_proof,
        runtime_root_public_key, work):
    """Authenticate only cold static bindings, without inventing a live clock."""
    try:
        ledger = capture._SharedLedger(work)
        _shape(recovery_grant_acquisition)
        if recovery_grant_acquisition is None:
            return None
        held_intent, held_proof, root = release_intent, release_proof, runtime_root_public_key
        if (type(held_intent) is not intent._ReleaseIntentMaterial
                or type(held_proof) is not proof._ReleaseProofMaterial):
            _fail("recovery grant acquisition requires actual configured intent and proof")
        owned = _Capture(ledger, maximum_bytes=MAX_BYTES).visit(recovery_grant_acquisition)
        _shape(owned)
        originals = tuple(issuer.authorization.transport._decode(owned[name]["base64Url"],
            owned[name]["byteCount"], maximum, work) for name, maximum in _ORIGINALS)
        policy_raw, custody_raw, proof_raw, intent_raw = originals
        endpoint = _endpoint(owned["endpoint"])
        issuer.authorization._public(root)
        envelope = issuer._read(policy_raw, work)
        issuer._signature(envelope, root, work)
        issuer._canonical(policy_raw, envelope, work)
        payload = envelope["payload"]
        _same_bytes(proof_raw, held_proof.enrollment_bytes, work, "recovery exact parent proof enrollment")
        _same_bytes(intent_raw, held_intent.enrollment_bytes, work, "recovery exact parent intent enrollment")
        proof_scope = proof._scope_on_work(held_proof.expected_scope_bytes, work)
        intent_scope = intent._scope_on_work(held_intent.expected_scope_bytes, work)
        for actual, expected, label in (
                (payload["proofScope"], proof_scope, "independent proof scope"),
                (payload["callerId"], intent_scope["callerId"], "independent intent caller"),
                (payload["proofEnrollmentDigest"], held_proof.enrollment_digest, "parent proof enrollment"),
                (payload["intentEnrollmentDigest"], held_intent.enrollment_digest, "parent intent enrollment"),
                (issuer._custody_digest_on_work(custody_raw, work),
                    payload["expectedEvidence"]["releaseCustodyDigest"], "exact historical custody"),
                (issuer._proof_enrollment_digest_on_work(proof_raw, work),
                    payload["proofEnrollmentDigest"], "exact proof original"),
                (issuer._intent_enrollment_digest_on_work(intent_raw, work),
                    payload["intentEnrollmentDigest"], "exact intent original")):
            plan._same(actual, expected, work, "recovery grant acquisition " + label)
        return _RecoveryGrantAcquisitionMaterial(endpoint, *originals)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, OidcSessionActivationReleaseRecoveryGrantAcquisitionBootstrapError):
            raise
        raise OidcSessionActivationReleaseRecoveryGrantAcquisitionBootstrapError(
            "recovery grant acquisition cold configuration failed") from exc
