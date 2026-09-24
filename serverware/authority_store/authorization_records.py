"""Actual immutable assertion/projection row recipes shared with legacy v3.

The private measured route prepares each genuine JSON copy, encoding, ASCII
buffer, domain frame and receipt digest on the caller's existing work. Fixed
35/21-column dictionary scaffolding is excluded; SQL parameter/returned-row
work belongs to the enclosing store. These dictionaries are not authority.

Live configured-key loading (including its SPKI hash) and key construction
remain external configuration admission, explicitly outside these H/B/N units.
Their callbacks and the actual signature callback may not change the work.
The receipt verifier does not replace the caller's current-clock admission.
"""
from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from typing import Any

from serverware import authority_complete_query_batch as batch
from serverware import authority_contract
from serverware import authority_webauthn_assertion as assertion
from serverware.authority_query_read_work import _ValidationWork
from serverware.authority_store.planner_connection import _db_value


_ASSERTION_FIELDS = (
    "assertion_evidence_digest", "operation", "operation_id", "request_digest",
    "capability_id", "challenge_id", "challenge_digest", "client_challenge_digest",
    "credential_record_id", "credential_id", "credential_policy_digest",
    "authenticator_data_base64url", "authenticator_data_digest",
    "client_data_json_base64url", "client_data_json_digest", "signature_base64url",
    "signature_digest", "rp_id", "rp_id_hash_digest", "origin", "flags",
    "user_present", "user_verified", "prior_counter", "counter",
    "trust_high_water_digest", "metadata_publication_sequence",
    "verifier_session_identity_digest", "verifier_measurement_digest",
    "verifier_attestation_receipt_digest", "verified_assertion_receipt_digest",
    "evidence_json", "verified_at_epoch_ns", "expires_at_epoch_ns", "source_revision",
)
_PROJECTION_FIELDS = (
    "authorization_projection_digest", "planner_transaction_id", "operation",
    "operation_id", "request_digest", "capability_id", "operation_contract_digest",
    "authorization_reads_json", "authorization_reads_digest", "source_rows_json",
    "source_rows_digest", "source_high_water_digest", "approver_policy_digest",
    "assertion_evidence_digest", "projection_json", "verifier_session_identity_digest",
    "verifier_measurement_digest", "verifier_attestation_receipt_digest",
    "created_at_epoch_ns", "expires_at_epoch_ns", "source_revision",
)


def _require_work(work):
    if work is not None:
        batch._SharedLedger(work)


def _canonical(value: Any, *, work=None, maximum=None, overflow=None) -> str:
    if work is not None:
        size, _ = work.prepare_encoding(value)
        if maximum is not None and size > maximum:
            raise ValueError(overflow)
    return json.dumps(value, allow_nan=False, ensure_ascii=True,
                      separators=(",", ":"), sort_keys=True)


def _ascii(value: str, *, work=None) -> bytes:
    if work is not None:
        # This string was just produced by the actual ensure_ascii encoder.
        work.charge(input_bytes=len(value))
    return value.encode("ascii")


def _digest(domain: str, *payloads: bytes, work=None) -> str:
    if work is not None:
        work.prepare_utf8(domain)
        work.charge(hashes=1, input_bytes=1 + 8 * len(payloads)
                    + sum(len(payload) for payload in payloads))
    hasher = hashlib.sha256()
    encoded_domain = domain.encode("ascii")
    hasher.update(encoded_domain)
    hasher.update(b"\x00")
    for payload in payloads:
        hasher.update(len(payload).to_bytes(8, "big"))
        hasher.update(payload)
    return "sha256:" + hasher.hexdigest()


def _assertion_storage_row(evidence: Mapping[str, Any], *,
                           work: _ValidationWork | None = None) -> dict:
    """Materialize the original 35-column recipe; perform no admission/SQL."""
    evidence_digest, evidence_json = _assertion_storage_document(evidence, work=work)
    return _assertion_storage_row_from_document(evidence, evidence_digest, evidence_json)


def _assertion_storage_document(evidence: Mapping[str, Any], *,
                                work: _ValidationWork | None = None) -> tuple[str, str]:
    """The actual pre-writer-role JSON/digest phase, without a second recipe."""
    _require_work(work)
    if work is not None:
        work.prepare_copy(evidence)
    evidence_json = _canonical(dict(evidence), work=work,
        maximum=authority_contract.MAX_REQUEST_BYTES,
        overflow="WebAuthn assertion evidence exceeds its byte bound")
    if len(_ascii(evidence_json, work=work)) > authority_contract.MAX_REQUEST_BYTES:
        raise ValueError("WebAuthn assertion evidence exceeds its byte bound")
    evidence_digest = _digest(
        "serverware.policyAuthorityWebAuthnAssertionEvidence/v1",
        _ascii(evidence_json, work=work), work=work,
    )
    return evidence_digest, evidence_json


def _assertion_storage_row_from_document(evidence, evidence_digest, evidence_json):
    # Legacy writer admission occurs between the actual document computation
    # and these original scalar reads. Fixed column scaffolding only: no new
    # encoding, digest, authority token, work allowance or variable graph copy.
    values = (
        evidence_digest, evidence["operation"], evidence["operationId"],
        evidence["requestDigest"], evidence["capabilityId"], evidence["challengeId"],
        evidence["challengeDigest"], evidence["clientChallengeDigest"],
        evidence["credentialRecordId"], evidence["credentialId"],
        evidence["credentialPolicyDigest"], evidence["authenticatorDataBase64url"],
        evidence["authenticatorDataDigest"], evidence["clientDataJSONBase64url"],
        evidence["clientDataJSONDigest"], evidence["signatureBase64url"],
        evidence["signatureDigest"], evidence["rpId"], evidence["rpIdHashDigest"],
        evidence["origin"], evidence["flags"], 1, 1, evidence["priorCounter"],
        evidence["counter"], evidence["trustHighWaterDigest"],
        evidence["metadataPublicationSequence"], evidence["verifierSessionIdentityDigest"],
        evidence["verifierMeasurementDigest"], evidence["verifierAttestationReceiptDigest"],
        evidence["verifiedAssertionReceiptDigest"], evidence_json,
        evidence["verifiedAtEpochNs"], evidence["expiresAtEpochNs"],
        authority_contract.SOURCE_REVISION,
    )
    return dict(zip(_ASSERTION_FIELDS, values))


def _projection_storage_row(projection: Mapping[str, Any], *,
                            work: _ValidationWork | None = None) -> dict:
    """Materialize the original 21-column recipe; perform no admission/SQL."""
    _require_work(work)
    if work is not None and type(projection) is not dict:
        raise ValueError("authorization projection is not an owned exact object")
    return _projection_storage_row_from_reads(
        projection, projection["authorizationReads"], work=work)


def _projection_storage_row_from_reads(projection, authorization_reads, *, work=None):
    # Legacy admission already captured its reads tuple before validating the
    # source rows. Keep that exact snapshot without duplicating the row recipe.
    _require_work(work)
    if work is not None:
        work.prepare_copy(projection)
    projection_json = _canonical(dict(projection), work=work,
        maximum=authority_contract.MAX_REQUEST_BYTES,
        overflow="authorization projection exceeds its byte bound")
    if len(_ascii(projection_json, work=work)) > authority_contract.MAX_REQUEST_BYTES:
        raise ValueError("authorization projection exceeds its byte bound")
    projection_digest = _digest(
        "serverware.policyAuthorityAuthorizationProjection/v1",
        _ascii(projection_json, work=work), work=work,
    )
    if work is not None:
        work.prepare_copy(authorization_reads)
    authorization_reads_json = _canonical(list(authorization_reads), work=work)
    source_rows_json = _canonical(projection["sourceRows"], work=work)
    values = (
        projection_digest, projection["plannerTransactionId"], projection["operation"],
        projection["operationId"], projection["requestDigest"], projection["capabilityId"],
        authority_contract.OPERATION_MANIFEST_DIGEST, authorization_reads_json,
        _digest("serverware.policyAuthorityAuthorizationReads/v1",
                _ascii(authorization_reads_json, work=work), work=work),
        source_rows_json,
        _digest("serverware.policyAuthorityAuthorizationRows/v1",
                _ascii(source_rows_json, work=work), work=work),
        projection["sourceHighWaterDigest"], projection["approverPolicyDigest"],
        projection["assertionEvidenceDigest"], projection_json,
        projection["verifierSessionIdentityDigest"], projection["verifierMeasurementDigest"],
        projection["verifierAttestationReceiptDigest"], projection["createdAtEpochNs"],
        projection["expiresAtEpochNs"], authority_contract.SOURCE_REVISION,
    )
    return dict(zip(_PROJECTION_FIELDS, values))


def _decode_signature(value, *, work):
    if work is not None:
        if type(value) is not str or len(value) != 86:
            raise ValueError("measured verifier signature length is invalid")
        # Same bounded canonical codec inventory used by the receipt worker:
        # L=86, padded P=88, decoded bound D=66, reencoded bound R=88.
        work.charge(input_bytes=2 * 86 + 4 * 88 + 2 * 66 + 5 * 88)
    if (not isinstance(value, str) or not value
            or any(character not in
                   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                   for character in value)):
        raise ValueError("measured verifier signature is not canonical base64url")
    payload = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    if base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii") != value:
        raise ValueError("measured verifier signature base64url encoding is not exact")
    return payload


def _equal(left, right, *, work):
    if work is not None:
        work.prepare_comparison(left, right)
    return not (left != right)


def _callback(work, callback, *args):
    if work is None:
        return callback(*args)
    # Lazy import avoids a cycle when the actual retained store uses these
    # recipes. This is the existing callback guard, never a fresh allowance.
    from serverware.authority_store.revocation_retention import _callback as guarded
    return guarded(work, callback, *args)


def _verify_pinned_verifier_envelope(envelope: Mapping[str, Any], *, domain: str,
        receipt_digest_field: str, work: _ValidationWork | None = None) -> None:
    """Verify against the live database-configured key, not historical pins."""
    _require_work(work)
    if work is not None and type(envelope) is not dict:
        raise ValueError("measured verifier envelope is not an owned exact object")
    signature = _decode_signature(envelope.get("verifierSignatureBase64url"), work=work)
    if len(signature) != 64:
        raise ValueError("measured verifier signature length is invalid")
    if work is not None:
        work.prepare_copy(envelope)
    unsigned = dict(envelope)
    unsigned.pop("verifierSignatureBase64url", None)
    unsigned.pop("verifierSignatureDigest", None)
    receipt_digest = unsigned.pop(receipt_digest_field, None)
    statement_digest = _digest(domain,
        _ascii(_canonical(unsigned, work=work), work=work), work=work)
    if not _equal(receipt_digest, statement_digest, work=work):
        raise ValueError("measured verifier receipt digest is not exact")
    if work is not None:
        work.charge(hashes=1, input_bytes=len(signature))
    signature_digest = "sha256:" + hashlib.sha256(signature).hexdigest()
    if not _equal(envelope.get("verifierSignatureDigest"), signature_digest, work=work):
        raise ValueError("measured verifier receipt digest is not exact")
    invalid_signature = _db_value("InvalidSignature")
    try:
        key_constructor = _db_value("Ed25519PublicKey").from_public_bytes
        key_bytes = _callback(work, _db_value("_policy_authority_verifier_public_key"))
        public_key = _callback(work, key_constructor, key_bytes)
        if work is None:
            public_key.verify(signature, statement_digest.encode("ascii"))
        else:
            work.prepare_utf8(statement_digest)
            receipt_work = assertion._ReceiptWork(work)
            assertion._verify_receipt_signature(public_key, signature,
                statement_digest.encode("ascii"), work=receipt_work)
    except invalid_signature as exc:
        raise ValueError("measured verifier envelope signature is invalid") from exc
