"""Raw JIT assertion receipt production from proved originals.

This module does no I/O and admits no successful-verification DTO. The successor
owner must authenticate every selected primary row, the current trust head,
reference uniqueness/absence, original cutoff and eligibility expansion. These
pure computations are not a runtime admission or an independent authority.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from typing import Any, Mapping

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from catchplate import authority_transition_core as core
from catchplate.authority_query_read_work import _ValidationWork

OPERATION = "jit.assertion.issue"
HANDLER = "catchplate_policy_authority_jit_assertion_issue"
RECEIPT_TABLE = "jit_webauthn_assertion_receipts"
ARGUMENT_FIELDS = frozenset({
    "approval_request_id", "approver_id", "challenge_id", "credential_record_id",
    "trust_publication_id", "decision", "assertion", "businessIntent",
})
POLICY_FIELDS = frozenset({
    "schema", "requiredRoles", "roleMatch", "allowedApproverIds",
    "allowAnyApproverId", "requireWebAuthn", "threshold", "credentialPolicy",
})
CREDENTIAL_POLICY_FIELDS = frozenset({
    "allowedCredentialRecordIds", "allowedAuthenticatorClasses", "allowedAaguids",
    "requireAttestationTrusted", "requiredTrustBundleDigest", "minimumTrustBundleSequence",
    "rpId", "origins", "requireUserPresence", "requireUserVerification",
    "counterPolicy", "maxAssertionAgeSeconds",
})


def _work(value):
    if type(value) is not _ValidationWork:
        raise core.TransitionKernelError("JIT receipt requires the original shared work meter")


def _arguments(value):
    if type(value) is not dict or set(value) != ARGUMENT_FIELDS:
        raise core.TransitionKernelError("JIT receipt arguments are not source closed")
    for field in ("approval_request_id", "approver_id", "challenge_id", "credential_record_id",
                  "trust_publication_id"):
        core.require_text(value[field], field, maximum_bytes=1024)
    if value["decision"] not in ("approve", "deny") or type(value["assertion"]) is not dict:
        raise core.TransitionKernelError("JIT receipt decision or assertion is invalid")
    return value


def _query(name, table, key, *, absent=False):
    return core.BoundedQuery(
        query_id=core.query_program_id(OPERATION, name, table), table=table,
        predicates=tuple(core.QueryPredicate(column, "eq", value)
                         for column, value in sorted(key.items())),
        order_by=tuple(core.QueryOrder(column) for column in sorted(key)),
        maximum_rows=1, absent_key=key, require_absence=absent,
    )


def queries(arguments):
    """First read stage only; the derived receipt-key absence follows verification."""
    args = _arguments(arguments)
    return (
        _query("approval", "approval_requests", {"id": args["approval_request_id"]}),
        _query("challenge", "webauthn_challenges", {"id": args["challenge_id"]}),
        _query("credential", "webauthn_credentials", {"id": args["credential_record_id"]}),
        _query("trust_high_water", "webauthn_trust_publication_high_water",
               {"authority_scope": "webauthn-metadata"}),
        _query("trust_publication", "webauthn_trust_publications",
               {"id": args["trust_publication_id"]}),
        _query("approver_role", "rbac_role_bindings", {"subject_id": args["approver_id"]}),
        _query("policy_high_water", "policy_high_water", {"scope": "global"}),
    )


def receipt_query(receipt_digest):
    """Second query key is produced from the original cutoff and verified assertion."""
    core.require_digest(receipt_digest, "JIT assertion receipt")
    return _query("receipt_absent", RECEIPT_TABLE,
                  {"assertion_receipt_digest": receipt_digest}, absent=True)


def _policy(approval, assertion_policy, *, work):
    if (type(assertion_policy) is not dict
            or set(assertion_policy) != {"rp_id", "origin", "maximum_assertion_age_seconds"}
            or type(assertion_policy["maximum_assertion_age_seconds"]) is not int
            or not 1 <= assertion_policy["maximum_assertion_age_seconds"] <= 30):
        raise core.TransitionKernelError("JIT assertion configuration is not source closed")
    for field, maximum in (("rp_id", 253), ("origin", 2048)):
        core.require_text(assertion_policy[field], field, maximum_bytes=maximum)
    raw = approval.get("approver_policy_json")
    if type(raw) is not str or len(raw) > 65536:
        raise core.TransitionKernelError("JIT stored policy exceeds its original bound")
    work.prepare_utf8(raw)
    try:
        policy = json.loads(raw)
    except ValueError as exc:
        raise core.TransitionKernelError("JIT stored policy is invalid") from exc
    work.prepare_encoding(policy)
    encoded = core.canonical_bytes(policy)
    work.charge(hashes=1, input_bytes=len(encoded))
    digest = core.framed_digest("catchplate.jitApproverPolicy/v1", encoded)
    if (encoded.decode("ascii") != raw or digest != approval.get("approver_policy_digest")
            or type(policy) is not dict or set(policy) != POLICY_FIELDS
            or policy["schema"] != "catchplate.jitApproverPolicy/v1"
            or policy["roleMatch"] != "any" or policy["requireWebAuthn"] is not True
            or type(policy["allowAnyApproverId"]) is not bool
            or type(policy["threshold"]) is not int or not 1 <= policy["threshold"] <= 16):
        raise core.TransitionKernelError("JIT stored policy binding is not exact")
    credential = policy["credentialPolicy"]
    if type(credential) is not dict or set(credential) != CREDENTIAL_POLICY_FIELDS:
        raise core.TransitionKernelError("JIT credential policy is not source closed")
    for name, source, maximum in (
            ("requiredRoles", policy, 128), ("allowedApproverIds", policy, 512),
            ("allowedCredentialRecordIds", credential, 512),
            ("allowedAuthenticatorClasses", credential, 64),
            ("allowedAaguids", credential, 128)):
        values = source[name]
        if (type(values) is not list
                or any(type(value) is not str or not value or value != value.strip()
                       or len(value.encode("utf-8")) > maximum for value in values)
                or values != sorted(set(values))):
            raise core.TransitionKernelError("JIT policy text set is not canonical")
    if (credential["rpId"] != assertion_policy["rp_id"]
            or credential["origins"] != [assertion_policy["origin"]]
            or credential["requireUserPresence"] is not True
            or credential["requireUserVerification"] is not True
            or type(credential["requireAttestationTrusted"]) is not bool
            or credential["counterPolicy"] not in ("strict", "strict-or-zero")
            or type(credential["maxAssertionAgeSeconds"]) is not int
            or not 1 <= credential["maxAssertionAgeSeconds"]
                <= assertion_policy["maximum_assertion_age_seconds"]):
        raise core.TransitionKernelError("JIT credential policy differs from pinned assertion policy")
    if credential["requiredTrustBundleDigest"] is not None:
        core.require_digest(credential["requiredTrustBundleDigest"], "JIT trust bundle")
    sequence = credential["minimumTrustBundleSequence"]
    if sequence is not None and (type(sequence) is not int or sequence < 1):
        raise core.TransitionKernelError("JIT minimum trust sequence is invalid")
    if (not policy["allowAnyApproverId"]
            and (not policy["allowedApproverIds"]
                 or policy["threshold"] > len(policy["allowedApproverIds"]))):
        raise core.TransitionKernelError("JIT approver threshold exceeds the exact set")
    return policy, digest


def derive_receipt(*, approval, approver_id, policy, policy_digest, assertion,
                   challenge_id, credential_record_id, challenge, credential, trust,
                   verified_at, decision, work):
    """Re-run the legacy raw ES256 assertion checks and produce the genuine row."""
    _work(work)
    if (type(verified_at) is not datetime or verified_at.tzinfo is None
            or verified_at.utcoffset() != timezone.utc.utcoffset(verified_at)):
        raise core.TransitionKernelError("JIT receipt cutoff is not original UTC")
    for original in (approval, policy, assertion, challenge, credential, trust):
        work.prepare_scan(original)

    def dumps(value):
        work.prepare_encoding(value)
        return core.canonical_bytes(value).decode("ascii")

    def _candidate_authority_text(label, value, *, maximum=1024):
        return core.require_text(value, label, maximum_bytes=maximum)

    def _candidate_authority_b64url_bounded(label, value, *, maximum_bytes):
        value = _candidate_authority_text(label, value,
            maximum=max(16, ((maximum_bytes + 2) // 3) * 4))
        work.prepare_utf8(value)
        work.charge(input_bytes=8 * (len(value) + 4))
        if re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
            raise core.TransitionKernelError("JIT assertion bytes are not canonical base64url")
        try:
            decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        except (ValueError, TypeError) as exc:
            raise core.TransitionKernelError("JIT assertion bytes are invalid") from exc
        if (len(decoded) > maximum_bytes
                or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value):
            raise core.TransitionKernelError("JIT assertion bytes exceed their canonical bound")
        return decoded

    def _candidate_authority_sha256(value):
        work.charge(hashes=1, input_bytes=len(value))
        return "sha256:" + hashlib.sha256(value).hexdigest()

    def _policy_authority_domain_digest(domain, *frames):
        work.charge(hashes=1, input_bytes=len(domain) + 1 + sum(8 + len(x) for x in frames))
        return core.framed_digest(domain.decode("ascii"), *frames)

    # Direct SHA calls below: RP hash and the ES256 client-data prehash.
    # Reserve before parsing/cryptography, not from a caller-reported result.
    work.charge(hashes=2, input_bytes=65536 + 253)
    if decision not in {"approve", "deny"}:
        raise core.TransitionKernelError("JIT WebAuthn decision binding is invalid")
    allowed_assertion_fields = {
        "id",
        "rawId",
        "type",
        "response",
        "clientExtensionResults",
        "authenticatorAttachment",
    }
    if (
        not isinstance(assertion, Mapping)
        or not {"id", "type", "response"} <= set(assertion)
        or not set(assertion) <= allowed_assertion_fields
        or assertion["type"] != "public-key"
        or not isinstance(assertion["response"], Mapping)
    ):
        raise core.TransitionKernelError("JIT WebAuthn assertion shape is invalid")
    assertion_value = dict(assertion)
    assertion_json = dumps(assertion_value)
    if len(assertion_json.encode("ascii")) > 1024 * 1024:
        raise core.TransitionKernelError("JIT WebAuthn assertion exceeds 1 MiB")
    credential_id = _candidate_authority_text(
        "JIT WebAuthn credential ID",
        assertion_value["id"],
        maximum=2048,
    )
    if assertion_value.get("rawId") not in {None, credential_id}:
        raise core.TransitionKernelError(
            "JIT WebAuthn assertion id and rawId do not match"
        )
    response = assertion_value["response"]
    if (
        not {"clientDataJSON", "authenticatorData", "signature"}
        <= set(response)
        or not set(response)
        <= {"clientDataJSON", "authenticatorData", "signature", "userHandle"}
    ):
        raise core.TransitionKernelError(
            "JIT WebAuthn assertion response fields are not exact"
        )
    client_data_raw = _candidate_authority_b64url_bounded(
        "JIT WebAuthn clientDataJSON",
        response["clientDataJSON"],
        maximum_bytes=64 * 1024,
    )
    authenticator_data = _candidate_authority_b64url_bounded(
        "JIT WebAuthn authenticatorData",
        response["authenticatorData"],
        maximum_bytes=4096,
    )
    assertion_signature = _candidate_authority_b64url_bounded(
        "JIT WebAuthn assertion signature",
        response["signature"],
        maximum_bytes=512,
    )
    try:
        client_data = json.loads(client_data_raw)
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise core.TransitionKernelError(
            "JIT WebAuthn client data is invalid JSON"
        ) from exc
    credential_policy = policy["credentialPolicy"]
    if (
        not isinstance(client_data, dict)
        or not {"type", "challenge", "origin"} <= set(client_data)
        or not set(client_data)
        <= {"type", "challenge", "origin", "crossOrigin", "tokenBinding"}
        or client_data["type"] != "webauthn.get"
        or client_data["origin"] not in credential_policy["origins"]
        or (client_data.get("crossOrigin") is not None
            and client_data.get("crossOrigin") is not False)
    ):
        raise core.TransitionKernelError(
            "JIT WebAuthn client data type, origin, or cross-origin state is invalid"
        )
    challenge_value = _candidate_authority_text(
        "JIT WebAuthn challenge",
        client_data["challenge"],
        maximum=2048,
    )
    if challenge["id"] != challenge_id or challenge["challenge"] != challenge_value:
        raise core.TransitionKernelError("JIT WebAuthn challenge identity differs")
    now_s = verified_at.isoformat()
    expected_scope = f"{approval['id']}:{policy_digest}:{decision}"
    expected_payload = {
        "schema": "catchplate.jitApprovalWebAuthnChallenge/v1",
        "approvalRequestId": approval["id"],
        "approverId": approver_id,
        "approverPolicyDigest": policy_digest,
        "decision": decision,
        "principalId": approval["principal_id"],
        "routeId": approval["route_id"],
        "credentialId": approval["credential_id"],
        "credentialVersion": approval["credential_version"],
        "policyHash": approval["policy_hash"],
        "requestDigest": approval["request_digest"],
        "operationDigest": approval["operation_digest"],
        "requestedAt": approval["requested_at"],
        "requestExpiresAt": approval["expires_at"],
        "challengeId": challenge_id,
    }
    expected_payload_json = dumps(expected_payload)
    if (
        challenge is None
        or challenge["challenge_type"] != "jit-approval"
        or challenge["user_id"] != approver_id
        or challenge["scope_key"] != expected_scope
        or challenge["approval_request_id"] != approval["id"]
        or challenge["used_at"] is not None
        or challenge["expires_at"] <= now_s
        or challenge["payload_json"] != expected_payload_json
    ):
        raise core.TransitionKernelError(
            "JIT WebAuthn challenge is missing, stale, consumed, or not exact"
        )
    challenge_created_at = datetime.fromisoformat(str(challenge["created_at"]))
    max_assertion_age_seconds = int(
        credential_policy["maxAssertionAgeSeconds"]
    )
    if (
        challenge_created_at.tzinfo is None
        or verified_at < challenge_created_at
        or (verified_at - challenge_created_at).total_seconds()
        > max_assertion_age_seconds
    ):
        raise core.TransitionKernelError("JIT WebAuthn challenge is not fresh")

    if credential["id"] != credential_record_id or credential["credential_id"] != credential_id:
        raise core.TransitionKernelError("JIT WebAuthn credential identity differs")
    allowed_credential_ids = credential_policy["allowedCredentialRecordIds"]
    allowed_classes = credential_policy["allowedAuthenticatorClasses"]
    allowed_aaguids = credential_policy["allowedAaguids"]
    if (
        credential is None
        or credential["user_id"] != approver_id
        or credential["revoked_at"] is not None
        or (
            allowed_credential_ids
            and credential["id"] not in allowed_credential_ids
        )
        or credential["authenticator_class"] not in allowed_classes
        or (
            allowed_aaguids
            and str(credential["aaguid"] or "") not in allowed_aaguids
        )
        or (
            credential_policy["requireAttestationTrusted"] is True
            and int(credential["attestation_trusted"] or 0) != 1
        )
        or (
            credential_policy["requiredTrustBundleDigest"] is not None
            and credential["attestation_trust_bundle_digest"]
            != credential_policy["requiredTrustBundleDigest"]
        )
        or (
            credential_policy["minimumTrustBundleSequence"] is not None
            and int(
                credential["attestation_trust_bundle_sequence"] or 0
            )
            < int(credential_policy["minimumTrustBundleSequence"])
        )
    ):
        raise core.TransitionKernelError(
            "JIT WebAuthn credential does not satisfy the immutable credential policy"
        )
    if credential_policy["requireAttestationTrusted"] is True and (
        trust is None
        or credential["attestation_trust_bundle_digest"]
        != trust["bundle_digest"]
        or int(credential["attestation_trust_bundle_sequence"] or 0)
        != int(trust["sequence"])
    ):
        raise core.TransitionKernelError(
            "JIT WebAuthn credential trust publication is no longer current"
        )
    if len(authenticator_data) < 37:
        raise core.TransitionKernelError("JIT WebAuthn authenticator data is truncated")
    expected_rp_hash = hashlib.sha256(
        credential_policy["rpId"].encode("utf-8")
    ).digest()
    flags = authenticator_data[32]
    sign_count_before = int(credential["sign_count"])
    sign_count_after = int.from_bytes(authenticator_data[33:37], "big")
    counter_valid = sign_count_after > sign_count_before
    if (
        credential_policy["counterPolicy"] == "strict-or-zero"
        and sign_count_before == 0
        and sign_count_after == 0
    ):
        counter_valid = True
    if (
        not hmac.compare_digest(authenticator_data[:32], expected_rp_hash)
        or flags & 0x01 == 0
        or flags & 0x04 == 0
        or not counter_valid
    ):
        raise core.TransitionKernelError(
            "JIT WebAuthn RP, UP, UV, or signature-counter evidence is invalid"
        )
    try:
        public_key_cose_raw = _candidate_authority_b64url_bounded(
            "JIT WebAuthn credential public key",
            credential["public_key_cose"],
            maximum_bytes=4096,
        )
        cose = cbor2.loads(public_key_cose_raw)
        if (
            not isinstance(cose, dict)
            or cose.get(1) != 2
            or cose.get(3) != -7
            or cose.get(-1) != 1
            or not isinstance(cose.get(-2), bytes)
            or not isinstance(cose.get(-3), bytes)
            or len(cose[-2]) != 32
            or len(cose[-3]) != 32
        ):
            raise ValueError("unsupported COSE key")
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            b"\x04" + cose[-2] + cose[-3],
        )
        public_key.verify(
            assertion_signature,
            authenticator_data + hashlib.sha256(client_data_raw).digest(),
            ec.ECDSA(hashes.SHA256()),
        )
    except (ValueError, TypeError, cbor2.CBORDecodeError, InvalidSignature) as exc:
        raise core.TransitionKernelError(
            "JIT WebAuthn assertion signature is invalid"
        ) from exc

    assertion_digest = _candidate_authority_sha256(
        assertion_json.encode("ascii")
    )
    client_data_digest = _candidate_authority_sha256(client_data_raw)
    authenticator_data_digest = _candidate_authority_sha256(
        authenticator_data
    )
    assertion_signature_digest = _candidate_authority_sha256(
        assertion_signature
    )
    challenge_payload_digest = _candidate_authority_sha256(
        expected_payload_json.encode("ascii")
    )
    credential_binding = {
        "schema": "catchplate.jitWebAuthnCredentialBinding/v1",
        "approverId": approver_id,
        "approverPolicyDigest": policy_digest,
        "decision": decision,
        "credentialRecordId": credential["id"],
        "credentialId": credential["credential_id"],
        "publicKeyCoseDigest": _candidate_authority_sha256(
            public_key_cose_raw
        ),
        "aaguid": credential["aaguid"],
        "authenticatorClass": credential["authenticator_class"],
        "attestationTrusted": int(credential["attestation_trusted"] or 0),
        "attestationTrustBundleDigest":
            credential["attestation_trust_bundle_digest"],
        "attestationTrustBundleSequence":
            credential["attestation_trust_bundle_sequence"],
        "rpId": credential_policy["rpId"],
        "origins": credential_policy["origins"],
        "signCountBefore": sign_count_before,
        "signCountAfter": sign_count_after,
    }
    credential_binding_digest = _policy_authority_domain_digest(
        b"catchplate.jitWebAuthnCredentialBinding/v1",
        dumps(credential_binding).encode("ascii"),
    )
    receipt_material = {
        "schema": "catchplate.jitWebAuthnAssertionReceipt/v1",
        "approvalRequestId": approval["id"],
        "approverId": approver_id,
        "approverPolicyDigest": policy_digest,
        "decision": decision,
        "assertionDigest": assertion_digest,
        "clientDataJSONDigest": client_data_digest,
        "authenticatorDataDigest": authenticator_data_digest,
        "assertionSignatureDigest": assertion_signature_digest,
        "challengeId": challenge["id"],
        "challengePayloadDigest": challenge_payload_digest,
        "credentialBindingDigest": credential_binding_digest,
        "userPresent": True,
        "userVerified": True,
        "verifiedAt": now_s,
    }
    receipt_digest = _policy_authority_domain_digest(
        b"catchplate.jitWebAuthnAssertionReceipt/v1",
        dumps(receipt_material).encode("ascii"),
    )

    delta = verified_at - datetime(1970, 1, 1, tzinfo=timezone.utc)
    verified_ns = (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000
    return {
        "assertion_receipt_digest": receipt_digest,
        "approval_request_id": approval["id"], "approver_id": approver_id,
        "approver_policy_digest": policy_digest, "decision": decision,
        "credential_record_id": credential["id"], "credential_id": credential["credential_id"],
        "challenge_id": challenge["id"], "assertion_digest": assertion_digest,
        "assertion_json": assertion_json, "client_data_json_digest": client_data_digest,
        "authenticator_data_digest": authenticator_data_digest,
        "assertion_signature_digest": assertion_signature_digest,
        "challenge_payload_digest": challenge_payload_digest,
        "credential_binding_digest": credential_binding_digest,
        "rp_id": credential_policy["rpId"], "origin": client_data["origin"],
        "authenticator_class": credential["authenticator_class"],
        "trust_bundle_digest": credential["attestation_trust_bundle_digest"],
        "trust_bundle_sequence": credential["attestation_trust_bundle_sequence"],
        "sign_count_before": sign_count_before, "sign_count_after": sign_count_after,
        "user_present": 1, "user_verified": 1,
        "attestation_trusted": int(credential["attestation_trusted"] or 0),
        "challenge_created_at": challenge["created_at"], "challenge_used_at": now_s,
        "verified_at": now_s, "verified_at_epoch_ns": verified_ns,
    }


def receipt_from_context(context, *, assertion_policy, work):
    """Actual reader and independent kernel each recompute, never trust a DTO."""
    inputs = _receipt_inputs_from_context(context, assertion_policy=assertion_policy, work=work)
    return derive_receipt(**inputs, work=work)


def _receipt_inputs_from_context(context, *, assertion_policy, work):
    """Private actual actor/policy lookup body; never a successful receipt."""
    from catchplate import authority_transition_quota as quota

    _work(work)
    if type(context) is not core.KernelContext or context.operation != OPERATION:
        raise core.TransitionKernelError("JIT assertion context is not exact")
    args = _arguments(context.arguments)
    approval = quota._row(context.exact("approval_requests",
        {"id": args["approval_request_id"]}), "JIT approval")
    policy, policy_digest = _policy(approval, assertion_policy, work=work)
    # Existing source RBAC/policy actor check, not a caller role assertion.
    quota._authorize_jit_actor(context, approval=approval,
                              actor_id=args["approver_id"], required_role=None)
    now = context.database_now.astimezone(timezone.utc)
    if approval["status"] != "pending" or approval["expires_at"] <= now.isoformat():
        raise core.TransitionKernelError("JIT approval is not live and pending")
    policy_head = quota._row(context.exact("policy_high_water",
        {"scope": "global"}), "JIT policy high water")
    if policy_head["policy_hash"] != approval["policy_hash"]:
        raise core.TransitionKernelError("JIT approval policy is no longer current")
    challenge = quota._row(context.exact("webauthn_challenges",
        {"id": args["challenge_id"]}), "JIT challenge")
    credential = quota._row(context.exact("webauthn_credentials",
        {"id": args["credential_record_id"]}), "JIT credential")
    trust_selected = context.exact("webauthn_trust_publications",
        {"id": args["trust_publication_id"]})
    trust = trust_selected["row"] if trust_selected["present"] else None
    if policy["credentialPolicy"]["requireAttestationTrusted"]:
        head = quota._row(context.exact("webauthn_trust_publication_high_water",
            {"authority_scope": "webauthn-metadata"}), "JIT trust high water")
        if (trust is None or trust["status"] != "published"
                or trust["rollback_epoch"] != head["rollback_epoch"]
                or trust["sequence"] != head["publication_sequence"]
                or trust["bundle_digest"] != head["publication_digest"]
                or trust["payload_digest"] != head["metadata_blob_digest"]):
            raise core.TransitionKernelError("JIT trust publication differs from current high water")
    return dict(approval=approval, approver_id=args["approver_id"],
        policy=policy, policy_digest=policy_digest, assertion=args["assertion"],
        challenge_id=args["challenge_id"], credential_record_id=args["credential_record_id"],
        challenge=challenge, credential=credential, trust=trust,
        verified_at=now, decision=args["decision"])


def transition(context, *, assertion_policy, work):
    """Recompute the assertion and its three explicit, inline-complete mutations."""
    from catchplate import authority_challenge_retention as retention

    row = receipt_from_context(context, assertion_policy=assertion_policy, work=work)
    mutations = _base_mutations(context, row)
    mutations = retention.expand_mutations(context, mutations, work=work)
    return _transition_result(row, mutations, work=work)


def _base_mutations(context, row):
    """Private mechanical body; callers must derive the receipt themselves."""
    receipt = context.exact(RECEIPT_TABLE,
        {"assertion_receipt_digest": row["assertion_receipt_digest"]})
    if receipt["present"] or receipt["row"] is not None:
        raise core.TransitionKernelError("JIT assertion receipt is not genuinely absent")
    challenge = context.exact("webauthn_challenges", {"id": row["challenge_id"]})
    credential = context.exact("webauthn_credentials", {"id": row["credential_record_id"]})
    return (
        core.mutation(operation=OPERATION, selected=challenge,
            row={**challenge["row"], "used_at": row["verified_at"]}),
        core.mutation(operation=OPERATION, selected=credential,
            row={**credential["row"], "sign_count": row["sign_count_after"],
                 "last_used_at": row["verified_at"], "updated_at": row["verified_at"]}),
        core.mutation(operation=OPERATION, selected=receipt, row=row),
    )


def _transition_result(row, mutations, *, work):
    """Private result construction shared by the same-call staged owner."""
    work.prepare_copy(mutations)
    return core.KernelTransition(mutations=mutations, result={
        "assertion_receipt_digest": row["assertion_receipt_digest"],
        "credential_record_id": row["credential_record_id"],
        "credential_id": row["credential_id"], "challenge_id": row["challenge_id"],
        "assertion_digest": row["assertion_digest"],
        "credential_binding_digest": row["credential_binding_digest"],
        "verified_at": row["verified_at"],
    }, work_units=64 + len(mutations))
