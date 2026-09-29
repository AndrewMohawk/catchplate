"""Pinned verifier evidence for revocation and private aggregate trust stage.

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
from serverware import authority_publication_approval as publication_approval
from serverware import authority_transition_core as core
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


OPERATION = "webauthn.credential.revoke"
STAGE_OPERATION = "webauthn.trust.stage"
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
MAX_SIGNATURE_ATTEMPTS = 1
MAX_CLIENT_CONTAINER_NESTING = 128


class AssertionEvidenceError(ValueError):
    pass


class _ReceiptWork:
    """One receipt attempt quota layered on an existing cumulative meter.

    The enclosing composer must create and reuse one wrapper. This is not a
    global registry of wrappers or a tamper-resistant caller authority token.
    Neither this wrapper nor any helper creates a replacement shared allowance.
    """

    __slots__ = ("_shared", "_signature_attempts")

    def __init__(self, shared: _ValidationWork) -> None:
        if type(shared) is not _ValidationWork:
            raise AssertionEvidenceError("assertion receipt work requires the exact shared meter")
        self._shared = shared
        self._signature_attempts = 0

    @property
    def shared(self) -> _ValidationWork:
        return self._shared

    @property
    def signature_attempts(self) -> int:
        return self._signature_attempts

    def _consume_signature(self) -> None:
        if type(self._signature_attempts) is not int or self._signature_attempts != 0:
            raise AssertionEvidenceError("assertion receipt signature attempt allowance is exhausted")
        self._signature_attempts += MAX_SIGNATURE_ATTEMPTS


def _require_work(work: _ReceiptWork | None) -> None:
    if work is not None and (
        type(work) is not _ReceiptWork
        or type(getattr(work, "_shared", None)) is not _ValidationWork
        or type(getattr(work, "_signature_attempts", None)) is not int
        or not 0 <= work.signature_attempts <= MAX_SIGNATURE_ATTEMPTS
    ):
        raise AssertionEvidenceError("assertion receipt work is not the exact shared wrapper")


def _sha256(value: bytes, *, work: _ReceiptWork | None = None) -> str:
    if work is not None:
        work.shared.charge(hashes=1)
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _decode(value: Any, *, size: int | None = None, work: _ReceiptWork | None = None) -> bytes:
    if work is not None:
        if (type(value) is not str or not value
                or len(value) > authority_contract.MAX_REQUEST_BYTES
                or size is not None and len(value) != (size * 8 + 5) // 6):
            raise AssertionEvidenceError("assertion evidence bytes are not canonical")
        length = len(value)
        padded = 4 * ((length + 3) // 4)
        decoded_bound = 3 * (padded // 4)
        reencoded_bound = 4 * ((decoded_bound + 2) // 3)
        # Defined conservative codec work, not exact Python allocation size:
        # alphabet + equality operands (2L+R), concat/ASCII/URL translation/
        # decoder input (4P), decoder output + encoder input (2D), encoder
        # output/URL translation/ASCII decode/rstrip (4R). Reserve the entire
        # canonical roundtrip before even its input scan or first allocation.
        work.shared.charge(input_bytes=2 * length + 4 * padded + 2 * decoded_bound + 5 * reencoded_bound)
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


def _equal(left: Any, right: Any, *, work: _ReceiptWork | None) -> bool:
    if work is not None:
        work.shared.prepare_comparison(left, right)
    # Original public predicates used !=, including on accepted subclasses.
    # Preserve that exact operation rather than assume __eq__/__ne__ agree.
    return not (left != right)


def _canonical(value: Any, *, work: _ReceiptWork | None) -> bytes:
    if work is not None:
        size, _ = work.shared.prepare_encoding(value)
        if size > authority_contract.MAX_REQUEST_BYTES:
            raise AssertionEvidenceError("assertion evidence exceeds its bound")
    return core.canonical_bytes(value)


def _operation_digest(request_digest: str, *, work: _ReceiptWork | None,
                      operation: str = OPERATION) -> str:
    if type(operation) is not str or operation not in ({OPERATION, STAGE_OPERATION} | publication_approval.ASSERTION_OPERATIONS):
        raise AssertionEvidenceError("assertion operation has no fixed receipt consumer")
    if work is not None:
        work.shared.prepare_utf8(operation)
        work.shared.prepare_utf8(request_digest)
        work.shared.charge(hashes=1)
    return core.framed_digest("serverware.policyAuthorityOperation/v2", operation.encode("ascii"), request_digest.encode("ascii"))


def _verify_receipt_signature(
    public_key: Ed25519PublicKey, signature: bytes, message: bytes,
    *, work: _ReceiptWork | None = None,
) -> None:
    if work is None:
        public_key.verify(signature, message)
        return
    _require_work(work)
    work._consume_signature()
    shared, limits, metrics = work.shared, work.shared.limits, work.shared.metrics
    limit_values = (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
    public_key.verify(signature, message)
    _require_work(work)
    if work.shared is not shared or work.signature_attempts != MAX_SIGNATURE_ATTEMPTS:
        raise AssertionEvidenceError("assertion receipt work changed during signature verification")
    if type(shared.limits) is not QueryReadValidationLimits:
        raise AssertionEvidenceError("assertion receipt limits changed during signature verification")
    checked = QueryReadValidationLimits(shared.limits.max_hashes,
        shared.limits.max_input_bytes, shared.limits.max_json_nodes)
    current = (shared.hash_work, shared.input_bytes, shared.json_nodes)
    maxima = (checked.max_hashes, checked.max_input_bytes, checked.max_json_nodes)
    if (any(type(value) is not int or not 0 <= value <= maximum for value, maximum in zip(current, maxima))
            or shared.limits is not limits or shared.metrics != metrics
            or maxima != limit_values):
        raise AssertionEvidenceError("assertion receipt work changed during signature verification")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for name, item in pairs:
        if name in value:
            raise AssertionEvidenceError("assertion client data has duplicate fields")
        value[name] = item
    return value


def _client_json(client_bytes: bytes, *, work: _ReceiptWork | None) -> Any:
    if work is not None:
        size = len(client_bytes)
        work.shared.charge(input_bytes=size)
        # This is a bounded lexical nesting guard, not a JSON parser. Quoted
        # brackets and escaped quotes cannot create structural nesting. The
        # actual UTF-8 decoder, JSON parser and duplicate-object hook still run.
        nesting = 0
        quoted = escaped = False
        for byte in client_bytes:
            if quoted:
                if escaped:
                    escaped = False
                elif byte == 92:
                    escaped = True
                elif byte == 34:
                    quoted = False
            elif byte == 34:
                quoted = True
            elif byte in (91, 123):
                nesting += 1
                if nesting > MAX_CLIENT_CONTAINER_NESTING:
                    raise AssertionEvidenceError("assertion client data exceeds its container nesting bound")
            elif byte in (93, 125):
                nesting -= 1
                if nesting < 0:
                    raise AssertionEvidenceError("assertion client data is invalid")
        # A valid U-byte JSON document has at most U+1 semantic nodes including
        # object keys. Reserve that conservative bound for the real parse and
        # again for the duplicate-hook dictionary construction, before either.
        # UTF-8 decode, parse and hook each charge U bytes. No unused unit is
        # refunded; later real traversals are independently charged as well.
        work.shared.charge(input_bytes=3 * size, json_nodes=2 * (size + 1))
    try:
        return json.loads(client_bytes.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError) as exc:
        raise AssertionEvidenceError("assertion client data is invalid") from exc


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
    return _verify_revoke_assertion_evidence(
        evidence, operation_id=operation_id, request_digest=request_digest,
        capability_id=capability_id, verifier_identity=verifier_identity,
        verifier_public_key=verifier_public_key, now_epoch_ns=now_epoch_ns,
        deadline_epoch_ns=deadline_epoch_ns, maximum_age_ns=maximum_age_ns,
        work=None,
    )


def _verify_revoke_assertion_evidence(
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
    work: _ReceiptWork | None,
) -> Mapping[str, Any]:
    """Preserve the original revocation-only API and accounting."""
    return _verify_operation_assertion_evidence(
        evidence, operation=OPERATION, operation_id=operation_id,
        request_digest=request_digest, capability_id=capability_id,
        verifier_identity=verifier_identity, verifier_public_key=verifier_public_key,
        now_epoch_ns=now_epoch_ns, deadline_epoch_ns=deadline_epoch_ns,
        maximum_age_ns=maximum_age_ns, work=work,
    )


def _verify_stage_assertion_evidence(
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
    work: _ReceiptWork | None,
) -> Mapping[str, Any]:
    """Verify an operation-bound receipt, not stage authorization or a grant."""
    return _verify_operation_assertion_evidence(
        evidence, operation=STAGE_OPERATION, operation_id=operation_id,
        request_digest=request_digest, capability_id=capability_id,
        verifier_identity=verifier_identity, verifier_public_key=verifier_public_key,
        now_epoch_ns=now_epoch_ns, deadline_epoch_ns=deadline_epoch_ns,
        maximum_age_ns=maximum_age_ns, work=work,
    )


def _verify_operation_assertion_evidence(
    evidence: Mapping[str, Any],
    *,
    operation: str,
    operation_id: str,
    request_digest: str,
    capability_id: str,
    verifier_identity: Mapping[str, str],
    verifier_public_key: Ed25519PublicKey,
    now_epoch_ns: int,
    deadline_epoch_ns: int,
    maximum_age_ns: int,
    work: _ReceiptWork | None,
) -> Mapping[str, Any]:
    """The actual receipt body with optional shared work, not whole-input capture.

    A measured caller must already own every evidence/binding graph and provide
    independent verifier pins and time. Signature attempts belong to its one
    persistent wrapper; constructing another wrapper is not globally prevented.
    Representation/budget failures from the shared meter propagate unchanged.
    """
    _require_work(work)
    if type(operation) is not str or operation not in ({OPERATION, STAGE_OPERATION} | publication_approval.ASSERTION_OPERATIONS):
        raise AssertionEvidenceError("assertion operation has no fixed receipt consumer")
    if work is not None and (
        type(evidence) is not dict or len(evidence) != len(EVIDENCE_FIELDS)
        or any(type(key) is not str or len(key) > 128 for key in evidence)
        or type(verifier_identity) is not dict or len(verifier_identity) != len(IDENTITY_FIELDS)
        or any(type(key) is not str or len(key) > 128 for key in verifier_identity)
    ):
        raise AssertionEvidenceError("assertion evidence or verifier pin is not closed")
    if (
        not isinstance(evidence, Mapping)
        or set(evidence) != EVIDENCE_FIELDS
        or not isinstance(verifier_identity, Mapping)
        or set(verifier_identity) != IDENTITY_FIELDS
        or not isinstance(verifier_public_key, Ed25519PublicKey)
    ):
        raise AssertionEvidenceError("assertion evidence or verifier pin is not closed")
    if work is not None:
        work.shared.prepare_copy(evidence)
    snapshot = dict(evidence)
    try:
        encoded = _canonical(snapshot, work=work)
        if len(encoded) > authority_contract.MAX_REQUEST_BYTES:
            raise AssertionEvidenceError("assertion evidence exceeds its bound")
        for field in DIGEST_FIELDS:
            core.require_digest(snapshot[field], "assertion evidence digest")
        for value in (operation_id, request_digest, capability_id, *verifier_identity.values()):
            core.require_digest(value, "assertion evidence binding")
        for field in TEXT_FIELDS:
            if work is not None:
                # Conservatively prepare the actual strip, equality and
                # character scan as well as require_text's UTF-8 encoding.
                work.shared.prepare_copy(snapshot[field])
                work.shared.prepare_comparison(snapshot[field], snapshot[field])
                work.shared.prepare_scan(snapshot[field])
                work.shared.prepare_utf8(snapshot[field])
            core.require_text(snapshot[field], "assertion evidence text", maximum_bytes=4096)
        for field in INTEGER_FIELDS:
            core.require_integer(snapshot[field], "assertion evidence integer", minimum=0, maximum=2**63 - 1)
        for value in (now_epoch_ns, deadline_epoch_ns, maximum_age_ns):
            core.require_integer(value, "assertion evidence time bound", minimum=1, maximum=2**63 - 1)
    except (core.TransitionKernelError, UnicodeError) as exc:
        raise AssertionEvidenceError("assertion evidence fields are invalid") from exc
    if (
        not _equal(snapshot["operation"], operation, work=work)
        or not _equal(snapshot["operationId"], operation_id, work=work)
        or not _equal(operation_id, _operation_digest(request_digest, work=work, operation=operation), work=work)
        or not _equal(snapshot["requestDigest"], request_digest, work=work)
        or not _equal(snapshot["capabilityId"], capability_id, work=work)
        or not _equal(snapshot["verifierSessionIdentityDigest"], verifier_identity["sessionIdentityDigest"], work=work)
        or not _equal(snapshot["verifierMeasurementDigest"], verifier_identity["measurementDigest"], work=work)
        or not _equal(snapshot["verifierAttestationReceiptDigest"], verifier_identity["attestationReceiptDigest"], work=work)
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
    signature = _decode(snapshot["verifierSignatureBase64url"], size=64, work=work)
    if work is not None:
        work.shared.prepare_copy(snapshot)
    unsigned = {name: value for name, value in snapshot.items() if name not in {
        "verifiedAssertionReceiptDigest", "verifierSignatureBase64url", "verifierSignatureDigest",
    }}
    unsigned_bytes = _canonical(unsigned, work=work)
    if work is not None:
        work.shared.charge(hashes=1)
    receipt_digest = core.framed_digest(RECEIPT_DOMAIN, unsigned_bytes)
    if (not _equal(receipt_digest, snapshot["verifiedAssertionReceiptDigest"], work=work)
            or not _equal(_sha256(signature, work=work), snapshot["verifierSignatureDigest"], work=work)):
        raise AssertionEvidenceError("assertion verifier receipt digest changed")
    if work is not None:
        work.shared.prepare_utf8(receipt_digest)
    try:
        _verify_receipt_signature(verifier_public_key, signature, receipt_digest.encode("ascii"), work=work)
    except InvalidSignature as exc:
        raise AssertionEvidenceError("assertion verifier signature is invalid") from exc

    authenticator = _decode(snapshot["authenticatorDataBase64url"], work=work)
    client_bytes = _decode(snapshot["clientDataJSONBase64url"], work=work)
    assertion_signature = _decode(snapshot["signatureBase64url"], work=work)
    if work is not None:
        work.shared.prepare_utf8(snapshot["rpId"])
        work.shared.charge(hashes=1)
    rp_hash = hashlib.sha256(snapshot["rpId"].encode("utf-8")).digest()
    client = _client_json(client_bytes, work=work)
    if (
        len(authenticator) < 37
        or authenticator[:32] != rp_hash
        or authenticator[32] != snapshot["flags"]
        or int.from_bytes(authenticator[33:37], "big") != snapshot["counter"]
        or not _equal(_sha256(authenticator, work=work), snapshot["authenticatorDataDigest"], work=work)
        or not _equal(_sha256(client_bytes, work=work), snapshot["clientDataJSONDigest"], work=work)
        or not _equal(_sha256(assertion_signature, work=work), snapshot["signatureDigest"], work=work)
        or not _equal("sha256:" + rp_hash.hex(), snapshot["rpIdHashDigest"], work=work)
        or not isinstance(client, dict)
        or len(client) != 4
        or set(client) != {"type", "challenge", "origin", "crossOrigin"}
        or not _equal(client["type"], "webauthn.get", work=work)
        or not _equal(client["origin"], snapshot["origin"], work=work)
        or client["crossOrigin"] is not False
        or not _equal(_sha256(_decode(client["challenge"], work=work), work=work), snapshot["clientChallengeDigest"], work=work)
    ):
        raise AssertionEvidenceError("assertion signed byte bindings changed")
    return MappingProxyType(snapshot)
