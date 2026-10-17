"""Explicit public revocation authorization, separate from assertion-only v4.

The measured verifier signs this aggregate only after the dedicated cold
caller's original has been authenticated. A missing optional assertion is
represented by null, never by an invented assertion receipt. These helpers
verify originals and produce ordinary facts; no returned mapping is permission
to reserve, execute, complete, or retry a revocation.
"""
from __future__ import annotations

import base64
import hashlib
from types import MappingProxyType

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from catchplate import authority_transition_core as core
from catchplate import authority_webauthn_assertion as assertion


OPERATION = "webauthn.credential.revoke"
SCHEMA = "catchplate.publicWebAuthnRevocationAuthorization/v1"
BINDING_SCHEMA = "catchplate.publicWebAuthnRevocationBinding/v1"
MAX_BYTES = 256 * 1024
MAX_AGE_NS = 30_000_000_000
ACTOR_FIELDS = frozenset({"userId", "roles", "authMethod", "requestSha256"})
POLICY_FIELDS = frozenset({"mfaRequired", "twoPersonRequired", "credentialPolicy"})
APPROVAL_FIELDS = frozenset({"id", "approvedBy", "credentialRecordId", "originalSha256"})
FIELDS = frozenset({"schema", "operation", "operationId", "requestDigest", "capabilityId",
    "actor", "policy", "payloadDigest", "approval", "assertion", "verifierIdentity",
    "verifiedAtEpochNs", "expiresAtEpochNs", "signatureBase64Url"})
BINDING_FIELDS = frozenset({"schema", "actorId", "approvalId", "approvedBy",
    "approvalCredentialRecordId", "credentialRecordId", "challengeId"})


class PublicRevocationError(ValueError):
    pass


def _require(condition, message="public revocation original is invalid"):
    if condition is not True:
        raise PublicRevocationError(message)


def _object(value, fields):
    _require(type(value) is dict and set(value) == fields)


def _text(value, maximum=1024):
    _require(type(value) is str and 1 <= len(value) <= maximum and "\x00" not in value
        and len(value.encode("utf-8")) <= maximum)


def is_public(value):
    return type(value) in (dict, MappingProxyType) and value.get("schema") == SCHEMA


def policy_shape(value):
    _object(value, POLICY_FIELDS)
    for name in ("mfaRequired", "twoPersonRequired"):
        _require(type(value[name]) is bool)
    policy = value["credentialPolicy"]
    _require(type(policy) is dict and "userVerification" in policy
        and set(policy) <= {"userVerification", "allowedAuthenticatorClasses", "requireHardwareAttestation"}
        and policy["userVerification"] == "required")
    if "requireHardwareAttestation" in policy:
        _require(type(policy["requireHardwareAttestation"]) is bool)
    if "allowedAuthenticatorClasses" in policy:
        classes = policy["allowedAuthenticatorClasses"]
        _require(type(classes) is list and 1 <= len(classes) <= 32
            and all(type(item) is str and 1 <= len(item) <= 128 for item in classes)
            and len(set(classes)) == len(classes))


def shape(value):
    _object(value, FIELDS)
    _require(value["schema"] == SCHEMA and value["operation"] == OPERATION)
    for name in ("operationId", "requestDigest", "capabilityId", "payloadDigest"):
        core.require_digest(value[name], name)
    actor = value["actor"]
    _object(actor, ACTOR_FIELDS)
    _text(actor["userId"])
    _text(actor["authMethod"], 128)
    core.require_digest(actor["requestSha256"], "actual HTTP request")
    _require(type(actor["roles"]) is list and 1 <= len(actor["roles"]) <= 32
        and all(type(role) is str and 1 <= len(role) <= 128 for role in actor["roles"]))
    _require(actor["roles"] == sorted(set(actor["roles"])))
    _require(bool(set(actor["roles"]) & {"admin", "approver"}))
    policy_shape(value["policy"])
    approval = value["approval"]
    _require((approval is not None) == value["policy"]["twoPersonRequired"])
    if approval is not None:
        _object(approval, APPROVAL_FIELDS)
        _text(approval["id"])
        _text(approval["approvedBy"])
        if approval["credentialRecordId"] is not None:
            _text(approval["credentialRecordId"])
        core.require_digest(approval["originalSha256"], "approval original")
        _require(approval["approvedBy"] != actor["userId"])
    _require((value["assertion"] is not None) == value["policy"]["mfaRequired"])
    if value["assertion"] is not None:
        _object(value["assertion"], assertion.EVIDENCE_FIELDS)
    _object(value["verifierIdentity"], assertion.IDENTITY_FIELDS)
    for digest in value["verifierIdentity"].values():
        core.require_digest(digest, "measured verifier identity")
    start, end = value["verifiedAtEpochNs"], value["expiresAtEpochNs"]
    _require(type(start) is int and type(end) is int and 0 < start < end < 2**63
        and end - start <= MAX_AGE_NS)
    signature = value["signatureBase64Url"]
    _require(type(signature) is str and len(signature) == 86
        and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in signature))


def binding(value):
    """Source-fixed query addresses, not proof of authorization or completeness."""
    shape(value)
    approval, mfa = value["approval"], value["assertion"]
    return {"schema": BINDING_SCHEMA, "actorId": value["actor"]["userId"],
        "approvalId": None if approval is None else approval["id"],
        "approvedBy": None if approval is None else approval["approvedBy"],
        "approvalCredentialRecordId": None if approval is None else approval["credentialRecordId"],
        "credentialRecordId": None if mfa is None else mfa["credentialRecordId"],
        "challengeId": None if mfa is None else mfa["challengeId"]}


def binding_shape(value):
    _object(value, BINDING_FIELDS)
    _require(value["schema"] == BINDING_SCHEMA)
    _text(value["actorId"])
    if value["approvalCredentialRecordId"] is not None:
        _require(value["approvalId"] is not None)
        _text(value["approvalCredentialRecordId"])
    for first, second in (("approvalId", "approvedBy"), ("credentialRecordId", "challengeId")):
        _require((value[first] is None) == (value[second] is None))
        if value[first] is not None:
            _text(value[first])
            _text(value[second])


def _message(value, work):
    work.prepare_copy(value)
    unsigned = {name: item for name, item in value.items() if name != "signatureBase64Url"}
    size, _ = work.prepare_encoding(unsigned)
    _require(size <= MAX_BYTES)
    raw = core.canonical_bytes(unsigned)
    work.charge(hashes=1, input_bytes=len(raw))
    return core.framed_digest(SCHEMA, raw).encode("ascii")


def verify(value, *, operation_id, request_digest, capability_id, verifier_identity,
        verifier_public_key, now_epoch_ns, deadline_epoch_ns, maximum_age_ns, work):
    """Verify the aggregate and the real optional nested assertion on one work."""
    shape(value)
    _require(isinstance(verifier_public_key, Ed25519PublicKey))
    for supplied, expected in ((value["operationId"], operation_id),
            (value["requestDigest"], request_digest), (value["capabilityId"], capability_id),
            (value["verifierIdentity"], verifier_identity)):
        work.prepare_comparison(supplied, expected)
        _require(supplied == expected, "public revocation independently admitted scope differs")
    _require(type(now_epoch_ns) is int and type(deadline_epoch_ns) is int
        and value["verifiedAtEpochNs"] <= now_epoch_ns < value["expiresAtEpochNs"]
        and value["expiresAtEpochNs"] <= deadline_epoch_ns
        and now_epoch_ns - value["verifiedAtEpochNs"] <= min(maximum_age_ns, MAX_AGE_NS))
    message = _message(value, work)
    receipt_work = assertion._ReceiptWork(work)
    signature = assertion._decode(value["signatureBase64Url"], size=64, work=receipt_work)
    receipt_work._consume_signature()
    from catchplate import authority_webauthn_evidence_plan_production as production
    production._callback(work, lambda: verifier_public_key.verify(signature, message))
    attempts = 1
    if value["assertion"] is not None:
        nested_work = assertion._ReceiptWork(work)
        assertion._verify_revoke_assertion_evidence(value["assertion"],
            operation_id=operation_id, request_digest=request_digest,
            capability_id=capability_id, verifier_identity=verifier_identity,
            verifier_public_key=verifier_public_key, now_epoch_ns=now_epoch_ns,
            deadline_epoch_ns=deadline_epoch_ns, maximum_age_ns=maximum_age_ns, work=nested_work)
        attempts += nested_work.signature_attempts
    # The caller already jointly owns every graph; this is not an input token.
    return value, attempts


def _sign_on_verified_process(process, value, *, work):
    """Private suffix; the service first admits its genuine caller and assertion."""
    from catchplate import authority_service as service
    _require(type(process) is service.AuthorityProcess and process.role_name == "verifier"
        and process.process_mode == service.PROCESS_MODES["verifier"])
    shape(value)
    message = _message(value, work)
    from catchplate import authority_webauthn_evidence_plan_production as production
    signature = production._callback(work, lambda: process.signing_key.sign(message))
    _require(type(signature) is bytes and len(signature) == 64)
    work.charge(input_bytes=64 + 88 + 86)
    result = dict(value)
    result["signatureBase64Url"] = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return result


def original_sha256(value, *, work):
    size, _ = work.prepare_encoding(value)
    _require(size <= MAX_BYTES)
    raw = core.canonical_bytes(value)
    work.charge(hashes=1, input_bytes=len(raw))
    return "sha256:" + hashlib.sha256(raw).hexdigest()
