"""Pinned verifier evidence admission for the standalone revocation planner.

This verifies the measured verifier's receipt, not a physical authenticator or
deployment. Business-row freshness and atomic CAS remain kernel/executor duties.
"""
from __future__ import annotations

import base64
import hashlib
import json
from types import MappingProxyType
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_contract
from serverware import authority_transition_core as core


OPERATION = "webauthn.credential.revoke"
RECEIPT_DOMAIN = "serverware.policyAuthorityVerifiedWebAuthnAssertionReceipt/v1"
IDENTITY_FIELDS = frozenset({"sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest"})
DIGEST_FIELDS = frozenset({
    "operationId", "requestDigest", "capabilityId", "challengeDigest",
    "clientChallengeDigest", "credentialPolicyDigest", "authenticatorDataDigest",
    "clientDataJSONDigest", "signatureDigest", "rpIdHashDigest", "trustHighWaterDigest",
    "verifierSessionIdentityDigest", "verifierMeasurementDigest",
    "verifierAttestationReceiptDigest", "verifiedAssertionReceiptDigest",
    "verifierSignatureDigest",
})
TEXT_FIELDS = frozenset({"operation", "challengeId", "credentialRecordId", "credentialId", "rpId", "origin"})
ENCODED_FIELDS = frozenset({"authenticatorDataBase64url", "clientDataJSONBase64url", "signatureBase64url", "verifierSignatureBase64url"})
INTEGER_FIELDS = frozenset({"flags", "priorCounter", "counter", "metadataPublicationSequence", "verifiedAtEpochNs", "expiresAtEpochNs"})
EVIDENCE_FIELDS = DIGEST_FIELDS | TEXT_FIELDS | ENCODED_FIELDS | INTEGER_FIELDS | {"userPresent", "userVerified"}


class AssertionEvidenceError(ValueError):
    pass


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _decode(value: Any, *, size: int | None = None) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > authority_contract.MAX_REQUEST_BYTES
        or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in value)
    ):
        raise AssertionEvidenceError("assertion evidence bytes are not canonical")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (ValueError, TypeError) as exc:
        raise AssertionEvidenceError("assertion evidence bytes are not canonical") from exc
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value or size is not None and len(decoded) != size:
        raise AssertionEvidenceError("assertion evidence bytes are not canonical")
    return decoded


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for name, item in pairs:
        if name in value:
            raise AssertionEvidenceError("assertion client data has duplicate fields")
        value[name] = item
    return value


def verify_revoke_assertion_evidence(
    evidence: Mapping[str, Any],
    *,
    operation_id: str,
    request_digest: str,
    capability_id: str,
    verifier_identity: Mapping[str, str],
    verifier_public_key: Ed25519PublicKey,
    now_epoch_ns: int,
    deadline_epoch_ns: int,
    maximum_age_ns: int,
) -> Mapping[str, Any]:
    """Return an immutable snapshot only after independent pinned-key verification."""
    if (
        not isinstance(evidence, Mapping)
        or set(evidence) != EVIDENCE_FIELDS
        or not isinstance(verifier_identity, Mapping)
        or set(verifier_identity) != IDENTITY_FIELDS
        or not isinstance(verifier_public_key, Ed25519PublicKey)
    ):
        raise AssertionEvidenceError("assertion evidence or verifier pin is not closed")
    snapshot = dict(evidence)
    try:
        encoded = core.canonical_bytes(snapshot)
        if len(encoded) > authority_contract.MAX_REQUEST_BYTES:
            raise AssertionEvidenceError("assertion evidence exceeds its bound")
        for field in DIGEST_FIELDS:
            core.require_digest(snapshot[field], "assertion evidence digest")
        for value in (operation_id, request_digest, capability_id, *verifier_identity.values()):
            core.require_digest(value, "assertion evidence binding")
        for field in TEXT_FIELDS:
            core.require_text(snapshot[field], "assertion evidence text", maximum_bytes=4096)
        for field in INTEGER_FIELDS:
            core.require_integer(snapshot[field], "assertion evidence integer", minimum=0, maximum=2**63 - 1)
        for value in (now_epoch_ns, deadline_epoch_ns, maximum_age_ns):
            core.require_integer(value, "assertion evidence time bound", minimum=1, maximum=2**63 - 1)
    except (core.TransitionKernelError, UnicodeError) as exc:
        raise AssertionEvidenceError("assertion evidence fields are invalid") from exc
    if (
        snapshot["operation"] != OPERATION
        or snapshot["operationId"] != operation_id
        or operation_id != core.framed_digest("serverware.policyAuthorityOperation/v2", OPERATION.encode("ascii"), request_digest.encode("ascii"))
        or snapshot["requestDigest"] != request_digest
        or snapshot["capabilityId"] != capability_id
        or snapshot["verifierSessionIdentityDigest"] != verifier_identity["sessionIdentityDigest"]
        or snapshot["verifierMeasurementDigest"] != verifier_identity["measurementDigest"]
        or snapshot["verifierAttestationReceiptDigest"] != verifier_identity["attestationReceiptDigest"]
        or snapshot["userPresent"] is not True
        or snapshot["userVerified"] is not True
        or not 0 <= snapshot["priorCounter"] < snapshot["counter"] <= 2_147_483_647
        or not 0 <= snapshot["flags"] <= 255
        or snapshot["flags"] & 0x05 != 0x05
        or snapshot["metadataPublicationSequence"] < 1
        or not 0 < snapshot["verifiedAtEpochNs"] <= now_epoch_ns < snapshot["expiresAtEpochNs"] <= deadline_epoch_ns
        or snapshot["expiresAtEpochNs"] - snapshot["verifiedAtEpochNs"] > maximum_age_ns
    ):
        raise AssertionEvidenceError("assertion evidence binding or lifetime changed")
    signature = _decode(snapshot["verifierSignatureBase64url"], size=64)
    unsigned = {name: value for name, value in snapshot.items() if name not in {
        "verifiedAssertionReceiptDigest", "verifierSignatureBase64url", "verifierSignatureDigest",
    }}
    receipt_digest = core.framed_digest(RECEIPT_DOMAIN, core.canonical_bytes(unsigned))
    if receipt_digest != snapshot["verifiedAssertionReceiptDigest"] or _sha256(signature) != snapshot["verifierSignatureDigest"]:
        raise AssertionEvidenceError("assertion verifier receipt digest changed")
    try:
        verifier_public_key.verify(signature, receipt_digest.encode("ascii"))
    except InvalidSignature as exc:
        raise AssertionEvidenceError("assertion verifier signature is invalid") from exc

    authenticator = _decode(snapshot["authenticatorDataBase64url"])
    client_bytes = _decode(snapshot["clientDataJSONBase64url"])
    assertion_signature = _decode(snapshot["signatureBase64url"])
    rp_hash = hashlib.sha256(snapshot["rpId"].encode("utf-8")).digest()
    try:
        client = json.loads(client_bytes.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError) as exc:
        raise AssertionEvidenceError("assertion client data is invalid") from exc
    if (
        len(authenticator) < 37
        or authenticator[:32] != rp_hash
        or authenticator[32] != snapshot["flags"]
        or int.from_bytes(authenticator[33:37], "big") != snapshot["counter"]
        or _sha256(authenticator) != snapshot["authenticatorDataDigest"]
        or _sha256(client_bytes) != snapshot["clientDataJSONDigest"]
        or _sha256(assertion_signature) != snapshot["signatureDigest"]
        or "sha256:" + rp_hash.hex() != snapshot["rpIdHashDigest"]
        or not isinstance(client, dict)
        or set(client) != {"type", "challenge", "origin", "crossOrigin"}
        or client["type"] != "webauthn.get"
        or client["origin"] != snapshot["origin"]
        or client["crossOrigin"] is not False
        or _sha256(_decode(client["challenge"])) != snapshot["clientChallengeDigest"]
    ):
        raise AssertionEvidenceError("assertion signed byte bindings changed")
    return MappingProxyType(snapshot)
