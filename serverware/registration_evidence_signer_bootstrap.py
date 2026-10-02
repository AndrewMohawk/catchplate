"""Separate trusted-host-local root admission for the registration signer.

The root first signs configuration-independent signer attestation originals.
The registration purpose can therefore pin their exact identity without a
configuration/receipt digest cycle. A separate root-signed bootstrap binds
those original bytes to the configuration, generation/runtime identities and
fixed launch descriptors. Both signatures use their own schema as the domain
of the existing framed canonical-payload digest, not runtime-trust framing.

Attestation is an explicit trusted-host-local root assertion about the signer,
including its runtime closure. This module does not measure that closure,
establish hardware, native-stage-zero, HSM, TEE or external-witness assurance,
or admit the root key from received data. The independent provisioner supplies
the actual root pair; the cold owners independently provision its public pin.
No descriptor, path, listener, key, storage, clock override or fresh work
allowance is created. Returned material is ordinary owned data, not a token
whose construction proves admission elsewhere.
"""
from __future__ import annotations

import base64
import math
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware import control_plane_enrollment_bootstrap as codec
from serverware import authority_webauthn_enrollment_policy as enrollment_policy
from serverware import authority_webauthn_evidence_policy as evidence_policy
from serverware import authority_webauthn_evidence_plan_clock as clock
from serverware.authority_local_limits import LOCAL_SESSION_MAX_NS


authority, configuration = codec.authority, codec.configuration
capability, capture, plan, production, keys = (
    codec.capability, codec.capture, codec.plan, codec.production, codec.keys)
ROLE = PROCESS_MODE = "webauthn-registration-evidence-signer"
SIGNER_UID = SIGNER_GID = 65517
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, REPLAY_FD = 198, 199, 200, 201, 202
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, REPLAY_FD)
LISTENER_PATH = "/run/serverware/registration-evidence/signer.sock"
MAX_BYTES = authority.MAX_REQUEST_BYTES
MAX_ATTESTATION_BYTES = 16 * 1024
MAX_RECEIPT_AGE_NS = LOCAL_SESSION_MAX_NS
SCHEMA = "serverware.signedRegistrationEvidenceSignerBootstrap/v1"
PAYLOAD_SCHEMA = "serverware.registrationEvidenceSignerBootstrap/v1"
LAUNCH_SCHEMA = "serverware.registrationEvidenceSignerLaunch/v1"
ATTESTATION_SCHEMA = "serverware.signedTrustedHostLocalRegistrationEvidenceSignerAttestation/v1"
ATTESTATION_PAYLOAD_SCHEMA = "serverware.trustedHostLocalRegistrationEvidenceSignerAttestation/v1"
ATTESTATION_IDENTITY_DOMAIN = "serverware.trustedHostLocalRegistrationEvidenceSignerAttestationIdentity/v1"
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "configurationDigest", "configurationPayload",
    "generation", "runtimeRoleIdentities", "attestationBase64Url", "attestationMaximumAgeNs", "launch"})
_LAUNCH_FIELDS = frozenset({"schema", "processMode", "serviceUid", "serviceGid", "peerUid", "peerGid",
    "rootPublicKeyFd", "bootstrapFd", "listenerFd", "signingKeyFd", "replayDirectoryFd",
    "inheritedFileDescriptors", "listenerPath", "requestTimeoutSeconds", "replayDirectoryDevice",
    "replayDirectoryInode", "replayMaximumRecords"})
_ATTESTATION_FIELDS = frozenset({"schema", "sourceRevision", "role", "processMode", "sessionIdentityDigest",
    "measurementDigest", "runtimeClosureDigest", "signingSpkiDigest", "issuedAtEpochNs", "expiresAtEpochNs",
    "trustMode", "coLocated", "hardwareBacked", "nativeStageZero", "hsmBackedKeys", "teeVerified",
    "externalWitnessVerified"})


class RegistrationEvidenceSignerBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _SignerMaterial:
    configuration_payload: dict
    generation: dict
    runtime_role_identities: dict
    configuration_digest: str
    evidence_public_key: object
    evidence_signer_identity: dict
    attestation_interval: tuple
    launch: dict


def _raw(value, maximum, label):
    if type(value) is not bytes or not 2 <= len(value) <= maximum:
        raise RegistrationEvidenceSignerBootstrapError(label + " is not bounded original bytes")
    return value


def _key(public_key):
    if not isinstance(public_key, Ed25519PublicKey):
        raise RegistrationEvidenceSignerBootstrapError("signer bootstrap requires its independently provisioned Ed25519 root")
    return public_key


def _envelope_shape(value, schema):
    capability.shape._object(value, _ENVELOPE_FIELDS, "registration signer root envelope")
    capability.shape._literal(value["schema"], schema)
    capability.shape._base64url(value["signatureBase64Url"], signature=True)
    if type(value["payload"]) is not dict:
        raise RegistrationEvidenceSignerBootstrapError("registration signer root payload is not an exact object")


def _payload_shape(value):
    shape = capability.shape
    shape._object(value, _PAYLOAD_FIELDS, "registration signer bootstrap payload")
    shape._literal(value["schema"], PAYLOAD_SCHEMA)
    shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
    shape._digest(value["configurationDigest"])
    shape._object(value["generation"], frozenset(configuration._GENERATION_FIELDS), "signer generation")
    if type(value["configurationPayload"]) is not dict or type(value["runtimeRoleIdentities"]) is not dict:
        raise RegistrationEvidenceSignerBootstrapError("signer configuration and runtime identities are not exact objects")
    shape._text(value["attestationBase64Url"], (4 * MAX_ATTESTATION_BYTES + 2) // 3, minimum=3)
    shape._integer(value["attestationMaximumAgeNs"], MAX_RECEIPT_AGE_NS, minimum=1)


def _launch_shape(value, work):
    shape = capability.shape
    shape._object(value, _LAUNCH_FIELDS, "registration signer launch")
    shape._literal(value["schema"], LAUNCH_SCHEMA)
    shape._literal(value["processMode"], PROCESS_MODE)
    shape._literal(value["listenerPath"], LISTENER_PATH)
    fixed = (("serviceUid", SIGNER_UID), ("serviceGid", SIGNER_GID), ("peerUid", PEER_UID),
        ("peerGid", PEER_GID), ("rootPublicKeyFd", ROOT_FD), ("bootstrapFd", BOOTSTRAP_FD),
        ("listenerFd", LISTENER_FD), ("signingKeyFd", KEY_FD), ("replayDirectoryFd", REPLAY_FD))
    for name, expected in fixed:
        shape._integer(value[name], 2**32 - 2, minimum=1)
        if value[name] != expected:
            raise RegistrationEvidenceSignerBootstrapError("registration signer fixed launch scalar differs")
    descriptors = value["inheritedFileDescriptors"]
    shape._array(descriptors, len(INHERITED_DESCRIPTORS), "signer inherited descriptors")
    for descriptor in descriptors:
        shape._integer(descriptor, 1023, minimum=3)
    plan._same(descriptors, list(INHERITED_DESCRIPTORS), work,
        "registration signer inherited descriptor inventory differs")
    timeout = value["requestTimeoutSeconds"]
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0.05 <= timeout <= 30:
        raise RegistrationEvidenceSignerBootstrapError("registration signer request timeout is invalid")
    shape._integer(value["replayDirectoryDevice"], 2**64 - 1)
    shape._integer(value["replayDirectoryInode"], 2**64 - 1, minimum=1)
    shape._integer(value["replayMaximumRecords"], 4096, minimum=1)


def _attestation_shape(value):
    shape = capability.shape
    shape._object(value, _ATTESTATION_FIELDS, "registration signer attestation")
    for name, expected in (("schema", ATTESTATION_PAYLOAD_SCHEMA),
            ("sourceRevision", authority.SOURCE_REVISION), ("role", ROLE),
            ("processMode", PROCESS_MODE), ("trustMode", "trusted-host-local")):
        shape._literal(value[name], expected)
    for name in ("sessionIdentityDigest", "measurementDigest", "runtimeClosureDigest", "signingSpkiDigest"):
        shape._digest(value[name])
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(value[name], minimum=1)
    if not 0 < value["expiresAtEpochNs"] - value["issuedAtEpochNs"] <= MAX_RECEIPT_AGE_NS:
        raise RegistrationEvidenceSignerBootstrapError("signer attestation lifetime exceeds its source bound")
    if value["coLocated"] is not True or any(value[name] is not False for name in (
            "hardwareBacked", "nativeStageZero", "hsmBackedKeys", "teeVerified", "externalWitnessVerified")):
        raise RegistrationEvidenceSignerBootstrapError("signer attestation is not the fixed trusted-host-local assurance")


def _fresh(interval, maximum_age, work, opening=None):
    """Check actual current time inside the unchanged signed receipt interval."""
    issued, expires = interval
    capability.shape._integer(maximum_age, MAX_RECEIPT_AGE_NS, minimum=1)
    if not 0 < expires - issued <= maximum_age:
        raise RegistrationEvidenceSignerBootstrapError("signer receipt exceeds its bootstrap lifetime policy")
    sample = clock._sample_on_work(work)
    before, epoch, after = sample
    if not issued <= epoch < expires or epoch - issued > maximum_age:
        raise RegistrationEvidenceSignerBootstrapError("signer original attestation is future-issued, stale or expired")
    if opening is not None:
        old_before, old_epoch, old_after = opening
        if (before < old_after or after >= old_before + expires - old_epoch
                or not old_epoch + before - old_after <= epoch <= old_epoch + after - old_before):
            raise RegistrationEvidenceSignerBootstrapError("signer receipt clock continuity or original expiry changed")
    return sample


def _attestation_digest_on_work(original, work):
    """Commit exact original bytes only; this helper admits no signature."""
    capture._SharedLedger(work)
    raw = _raw(original, MAX_ATTESTATION_BYTES, "signer attestation")
    return plan._frame(ATTESTATION_IDENTITY_DOMAIN, (raw,), work)


def _read_attestation(original, root_key, maximum_age, work):
    raw = _raw(original, MAX_ATTESTATION_BYTES, "signer attestation")
    envelope = capability.wire._decode_object(raw, work=work, maximum_bytes=MAX_ATTESTATION_BYTES,
        maximum_nodes=capability.MAX_JSON_NODES, maximum_depth=capability.MAX_JSON_DEPTH)
    envelope = capture._JSONCapture(capture._SharedLedger(work), maximum_bytes=MAX_ATTESTATION_BYTES).visit(envelope)
    _envelope_shape(envelope, ATTESTATION_SCHEMA)
    _attestation_shape(envelope["payload"])
    codec._canonical(raw, envelope, work)
    payload_bytes = configuration._configuration_wire(envelope["payload"], capture._SharedLedger(work))
    capability._signature(root_key, envelope["signatureBase64Url"], ATTESTATION_SCHEMA,
        payload_bytes, capture._SharedLedger(work))
    codec._canonical(raw, envelope, work)
    claims = envelope["payload"]
    interval = claims["issuedAtEpochNs"], claims["expiresAtEpochNs"]
    opening = _fresh(interval, maximum_age, work)
    return envelope, claims, interval, opening, _attestation_digest_on_work(raw, work)


def _material(payload, attestation_bytes, root_key, work):
    """Join separately root-authenticated statements, never infer provenance."""
    _payload_shape(payload)
    launch = payload["launch"]
    _launch_shape(launch, work)
    configured, generation, runtime = (payload["configurationPayload"],
        payload["generation"], payload["runtimeRoleIdentities"])
    digest, maximum_age = payload["configurationDigest"], payload["attestationMaximumAgeNs"]
    envelope, claims, interval, opening, receipt_digest = _read_attestation(
        attestation_bytes, root_key, maximum_age, work)
    # The actual enabled mapper performs configuration commitment, generation
    # membership, runtime-cohort/static joins, source allowlist/manifest and
    # genuine dedicated enrollment/audience/key validation on this same work.
    enrollment_policy._capture_on_work(payload=configured, configuration_digest=digest,
        generation=generation, runtime_role_identities=runtime, work=work)
    policy, public_keys = evidence_policy._validate_policy_on_work(
        configured.get(evidence_policy.FIELD), webauthn=configured["webauthn"], work=work)
    selected = policy["registration"]
    if selected is None:
        raise RegistrationEvidenceSignerBootstrapError("registration evidence purpose is disabled")
    identity, spki, public_key = selected["signerIdentity"], selected["signingSpkiDigest"], public_keys["registration"]
    plan._same((claims["sessionIdentityDigest"], claims["measurementDigest"], receipt_digest,
        claims["signingSpkiDigest"]), (identity["sessionIdentityDigest"], identity["measurementDigest"],
        identity["attestationReceiptDigest"], spki), work,
        "signer attestation differs from the actual registration evidence purpose")
    forbidden = []
    roles = configured["roles"]
    capability.shape._object(roles, frozenset(configuration._ROLE_NAMES), "signer authority roles")
    for name in configuration._ROLE_NAMES:
        role = roles[name]
        if type(role) is not dict:
            raise RegistrationEvidenceSignerBootstrapError("signer authority role is not an exact object")
        capability.shape._integer(role["serviceUid"], 2**32 - 2)
        if role["serviceUid"] == SIGNER_UID:
            raise RegistrationEvidenceSignerBootstrapError("signer UID is not independent of authority roles")
        capability.shape._digest(role["responseSigningSpkiDigest"])
        forbidden.append(role["responseSigningSpkiDigest"])
        if name in ("verifier", "planner"):
            capability.shape._digest(role["signingSpkiDigest"])
            forbidden.append(role["signingSpkiDigest"])
    work.prepare_scan(forbidden)
    if spki in forbidden:
        raise RegistrationEvidenceSignerBootstrapError("evidence signer reuses a generic authority role key")
    _fresh(interval, maximum_age, work, opening)
    codec._canonical(attestation_bytes, envelope, work)
    return _SignerMaterial(configured, generation, runtime, digest, public_key, identity, interval, launch), opening


def _admit_on_work(*, bootstrap_bytes, root_public_key, work):
    try:
        capture._SharedLedger(work)
        original, key = _raw(bootstrap_bytes, MAX_BYTES, "signer bootstrap"), _key(root_public_key)
        envelope = codec._decode(original, work)
        _envelope_shape(envelope, SCHEMA)
        # Only the outer bounded canonical envelope is interpreted before its
        # genuine root signature. No embedded FD/configuration is admitted yet.
        codec._canonical(original, envelope, work)
        payload = envelope["payload"]
        payload_bytes = configuration._configuration_wire(payload, capture._SharedLedger(work))
        capability._signature(key, envelope["signatureBase64Url"], SCHEMA,
            payload_bytes, capture._SharedLedger(work))
        codec._canonical(original, envelope, work)
        _payload_shape(payload)
        encoded = payload["attestationBase64Url"]
        attestation = configuration.invocation._decode(encoded, len(encoded) * 3 // 4,
            MAX_ATTESTATION_BYTES, work)
        material, opening = _material(payload, attestation, key, work)
        codec._canonical(original, envelope, work)
        _fresh(material.attestation_interval, payload["attestationMaximumAgeNs"], work, opening)
        codec._canonical(original, envelope, work)
        return material
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, RegistrationEvidenceSignerBootstrapError):
            raise
        raise RegistrationEvidenceSignerBootstrapError("registration signer bootstrap admission failed") from exc


def _sign(payload, schema, maximum_bytes, private_key, public_key, work):
    if not isinstance(private_key, Ed25519PrivateKey):
        raise RegistrationEvidenceSignerBootstrapError("provisioner requires the actual root private key")
    _key(public_key)
    owned = configuration._ConfigurationCapture(capture._SharedLedger(work), maximum_bytes=maximum_bytes).visit(payload)
    envelope = {"schema": schema, "payload": owned, "signatureBase64Url": "A" * 86}
    payload_size, payload_nodes = codec._measure(owned, work)
    envelope_size, envelope_nodes = codec._measure(envelope, work)
    if max(payload_size, envelope_size) > maximum_bytes:
        raise RegistrationEvidenceSignerBootstrapError("signer root output exceeds its complete bound")
    original = configuration._configuration_wire(owned, capture._SharedLedger(work))
    keys._pair_on_work(private_key, public_key, work)
    codec._canonical(original, owned, work)
    work.charge(input_bytes=3 * payload_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=payload_nodes + envelope_nodes)
    frame_bytes = 2 * len(schema) + 9 + payload_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + payload_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + payload_nodes):
        raise RegistrationEvidenceSignerBootstrapError("signer root output cannot reserve its signature work")
    message = plan._ascii(plan._frame(schema, (original,), work), work)
    signature = production._sign_and_verify(private_key, public_key, message, work)
    if codec._measure(owned, work) != (payload_size, payload_nodes) or codec._encode(owned) != original:
        raise RegistrationEvidenceSignerBootstrapError("signer root payload changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    capability.shape._base64url(encoded, signature=True)
    envelope["signatureBase64Url"] = encoded
    result = codec._encode(envelope)
    if len(result) != envelope_size:
        raise RegistrationEvidenceSignerBootstrapError("signer root output changed after reservation")
    return result


def _produce_attestation_on_work(*, claims, root_private_key, root_public_key, work):
    """Sign the full exact17 independent trusted-host-local root claims."""
    try:
        capture._SharedLedger(work)
        private_key, public_key = root_private_key, _key(root_public_key)
        owned = capture._JSONCapture(capture._SharedLedger(work),
            maximum_bytes=MAX_ATTESTATION_BYTES).visit(claims)
        _attestation_shape(owned)
        interval = owned["issuedAtEpochNs"], owned["expiresAtEpochNs"]
        opening = _fresh(interval, MAX_RECEIPT_AGE_NS, work)
        original = _sign(owned, ATTESTATION_SCHEMA, MAX_ATTESTATION_BYTES, private_key, public_key, work)
        _fresh(interval, MAX_RECEIPT_AGE_NS, work, opening)
        return original
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, RegistrationEvidenceSignerBootstrapError):
            raise
        raise RegistrationEvidenceSignerBootstrapError("registration signer attestation production failed") from exc


def _produce_on_work(*, configuration_payload, generation, runtime_role_identities,
        configuration_digest, attestation_bytes, attestation_maximum_age_ns, launch,
        root_private_key, root_public_key, work):
    try:
        ledger = capture._SharedLedger(work)
        private_key, public_key = root_private_key, _key(root_public_key)
        attestation = _raw(attestation_bytes, MAX_ATTESTATION_BYTES, "signer attestation")
        digest, maximum_age = configuration_digest, attestation_maximum_age_ns
        capability.shape._digest(digest)
        capability.shape._integer(maximum_age, MAX_RECEIPT_AGE_NS, minimum=1)
        capability.shape._bounded_object(generation, 24, "signer provisioner generation")
        owned = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "configurationPayload": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtimeRoleIdentities": runtime_role_identities, "launch": launch})
        # Every caller graph and original/key/scalar reference is held before
        # the first base64 codec, root verification, hash, policy or clock call.
        payload = {"schema": PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "configurationDigest": digest, "configurationPayload": owned["configurationPayload"],
            "generation": owned["generation"], "runtimeRoleIdentities": owned["runtimeRoleIdentities"],
            "attestationBase64Url": configuration.invocation._encode(attestation, work),
            "attestationMaximumAgeNs": maximum_age, "launch": owned["launch"]}
        _payload_shape(payload)
        material, opening = _material(payload, attestation, public_key, work)
        original = _sign(payload, SCHEMA, MAX_BYTES, private_key, public_key, work)
        _fresh(material.attestation_interval, maximum_age, work, opening)
        return original
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, RegistrationEvidenceSignerBootstrapError):
            raise
        raise RegistrationEvidenceSignerBootstrapError("registration signer bootstrap production failed") from exc
