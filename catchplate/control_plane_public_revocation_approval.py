"""Actual public request/decision ceremonies for the fixed revocation purpose.

Each submission retains its exact options and signed caller originals, burns a
durable attempt before the protected approval writer, and never replays after
uncertain contact. Final approval consumption is not exposed here. The final
revocation verifies this genuinely created row against authenticated prestate.
"""
from __future__ import annotations

import json

from fastapi import HTTPException

from catchplate import control_plane_public_revocation as http
from catchplate import authority_public_revocation_approval as profile
from catchplate import authority_public_revocation_approval_owner as serving


OPTIONS_REQUEST = "catchplate.publicWebAuthnRevocationApprovalOptionsRequest/v1"
SUBMIT_REQUEST = "catchplate.publicWebAuthnRevocationApprovalSubmitRequest/v1"


def _row(identifier):
    profile.public._text(identifier, 256)
    with http.db.connect() as connection:
        selected = connection.execute("SELECT * FROM control_plane_approvals WHERE id = ?", (identifier,)).fetchone()
    if selected is None:
        raise HTTPException(status_code=404, detail="public revocation approval not found")
    row = dict(selected)
    original = row.get("approval_authn")
    profile.public._require(type(original) is str and len(original.encode("utf-8")) <= 16 * 1024)
    provenance = json.loads(original)
    profile.public._require(type(provenance) is dict and set(provenance) == {
        "schema", "policy", "requestDigest", "requestEvidenceDigest", "decisionDigest", "decisionEvidenceDigest"}
        and provenance["schema"] == profile.PROVENANCE_SCHEMA
        and profile.public.core.canonical_bytes(provenance).decode("ascii") == original)
    profile.public.policy_shape(provenance["policy"])
    return row, provenance


def require_approved(owner, identifier, record_id, digest, mutation):
    owner.check()
    if identifier is None:
        raise HTTPException(status_code=428, detail={"error": "public_revocation_approval_required",
            "action": profile.public.OPERATION, "resourceId": record_id, "payloadDigest": digest,
            "optionsProfile": OPTIONS_REQUEST, "automaticRetryAllowed": False})
    row, provenance = _row(identifier)
    profile.public._require(provenance["policy"] == owner.selected_policy
        and row["requester_id"] == owner.identity.user_id and row["approved_by"] != owner.identity.user_id
        and row["action"] == profile.public.OPERATION and row["resource_id"] == record_id
        and row["payload_digest"] == digest and row["status"] == "approved"
        and row["request_json"] == profile.public.core.canonical_bytes(mutation).decode("ascii"))
    http.caller.shape._digest(provenance["decisionDigest"])
    if owner.selected_policy["mfaRequired"]:
        http.caller.shape._digest(provenance["requestEvidenceDigest"])
        http.caller.shape._digest(provenance["decisionEvidenceDigest"])
        profile.public._text(row["approver_webauthn_credential_id"])
    else:
        profile.public._require(provenance["requestEvidenceDigest"] is None
            and provenance["decisionEvidenceDigest"] is None and row["approver_webauthn_credential_id"] is None)
    owner.narrow(http._epoch_ns(row["expires_at"]))
    return {"id": row["id"], "approvedBy": row["approved_by"],
        "credentialRecordId": row["approver_webauthn_credential_id"],
        "originalSha256": profile.public.original_sha256(row, work=owner.work)}


def options_on_request(request, original):
    from catchplate import app
    owner = http._Operation(request, original, schema=OPTIONS_REQUEST,
        fields={"apiVersion", "action", "resourceId", "reason", "approvalId", "credentialRecordId"})
    profile.public._require(owner.body["action"] == profile.public.OPERATION
        and owner.selected_policy["twoPersonRequired"] is True)
    target = http._target(owner, owner.body["resourceId"])
    _cascade, mutation, digest = http._arguments(owner, target, owner.body["reason"])
    identifier = owner.body["approvalId"]
    phase = "request" if identifier is None else "decide"
    if identifier is not None:
        row, provenance = _row(identifier)
        profile.public._require("admin" in owner.identity.roles and row["requester_id"] != owner.identity.user_id
            and row["status"] == "pending" and row["action"] == profile.public.OPERATION
            and row["resource_id"] == target["id"] and row["payload_digest"] == digest
            and row["request_json"] == profile.public.core.canonical_bytes(mutation).decode("ascii")
            and provenance["policy"] == owner.selected_policy)
        owner.narrow(http._epoch_ns(row["expires_at"]))
    operation = profile.operation(phase, owner.selected_policy)
    arguments = {"action": profile.public.OPERATION, "resource_id": target["id"], "payload_digest": digest,
        "actor_id": owner.identity.user_id, "actor_roles": sorted(owner.identity.roles),
        "request": mutation, "approval_id": identifier, "mutation_policy": owner.selected_policy,
        "ttl_seconds": app.CONTROL_PLANE_TWO_PERSON_TTL_SECONDS, "note": None}
    profile.arguments(operation, arguments)
    encoded = http.caller.authorization.capability._wire({"schema": profile.OPTIONS_SCHEMA,
        "operation": operation, "arguments": arguments, "actorId": owner.identity.user_id,
        "issuedAtEpochNs": owner.window[0], "expiresAtEpochNs": min(owner.window[3],
            owner.window[0] + owner.deadline - owner.window[2])},
        http.caller.capture._SharedLedger(owner.work), 64 * 1024, 8192)
    local = owner.append("options", http.ZERO, (encoded,))
    credential_id, challenge = owner.body["credentialRecordId"], None
    if operation in profile.ASSERTION_OPERATIONS:
        profile.public._text(credential_id)
        credential = http.db.get_webauthn_credential_by_record_id(credential_id)
        profile.public._require(type(credential) is dict and credential.get("user_id") == owner.identity.user_id
            and credential.get("revoked_at") is None)
        eligible = http.webauthn._credential_descriptors_for_policy(owner.identity.user_id,
            owner.selected_policy["credentialPolicy"])
        profile.public._require(any(item.get("id") == credential["credential_id"] for item in eligible))
        owner.check()
        row = http.db.issue_policy_authority_webauthn_challenge(operation=operation,
            input_value=arguments, user_id=owner.identity.user_id,
            credential_id=credential["credential_id"], deadline_ns=owner.deadline)
        owner.check()
        bound = row["payload"]
        request_digest = profile.request_digest(operation, arguments)
        operation_id = http.caller.plan._frame("catchplate.policyAuthorityOperation/v2",
            (operation.encode("ascii"), request_digest.encode("ascii")), owner.work)
        profile.public._require(row["user_id"] == owner.identity.user_id and row["used_at"] is None
            and row["challenge_type"] == "policy_authority" and bound["operationId"] == operation_id
            and bound["credentialId"] == credential["credential_id"]
            and bound["rpId"] == http.webauthn.WEBAUTHN_RP_ID and bound["origin"] == http.webauthn.WEBAUTHN_ORIGIN)
        owner.narrow(min(http._epoch_ns(row["expires_at"]), bound["expiresAtEpochNs"]))
        challenge = {"authorityChallengeId": row["id"], "credentialRecordId": credential["id"],
            "publicKey": {"challenge": row["challenge"], "rpId": bound["rpId"], "userVerification": "required",
                "allowCredentials": [{"type": "public-key", "id": credential["credential_id"]}], "timeout": 30000}}
    else:
        profile.public._require(credential_id is None)
    owner.check()
    return {"apiVersion": "catchplate.publicWebAuthnRevocationApprovalOptionsResponse/v1",
        "localDigest": local, "operation": operation, "recordId": target["id"], "payloadDigest": digest,
        "approvalId": identifier, "challenge": challenge, "automaticRetryAllowed": False}


def submit_on_request(request, record_id, original, *, approval_id=None):
    owner = http._Operation(request, original, schema=SUBMIT_REQUEST,
        fields={"apiVersion", "localDigest", "mfa"})
    retained = http.custody.ControlPlaneCustodyClient.load_public_revocation_options(owner.client, owner.body["localDigest"])
    options = http.caller.authorization.wire._decode_object(retained.originals[1], work=owner.work,
        maximum_bytes=64 * 1024, maximum_nodes=8192, maximum_depth=16)
    profile.public._object(options, frozenset({"schema", "operation", "arguments", "actorId", "issuedAtEpochNs", "expiresAtEpochNs"}))
    profile.public._require(options["schema"] == profile.OPTIONS_SCHEMA and options["actorId"] == owner.identity.user_id)
    http.caller.primitives._unchanged(retained.originals[1], options, 64 * 1024, owner.work)
    owner.narrow(options["expiresAtEpochNs"])
    operation, arguments = options["operation"], options["arguments"]
    profile.arguments(operation, arguments)
    profile.public._require(arguments["resource_id"] == record_id and arguments["approval_id"] == approval_id
        and arguments["mutation_policy"] == owner.selected_policy
        and arguments["actor_id"] == owner.identity.user_id and arguments["actor_roles"] == sorted(owner.identity.roles))
    http._target(owner, record_id)
    assertion = owner.body["mfa"]
    if operation in profile.ASSERTION_OPERATIONS:
        profile.public._object(assertion, frozenset({"authorityChallengeId", "credentialRecordId", "assertion"}))
    else:
        profile.public._require(assertion is None)
    raw = serving.sign_on_owner(owner, operation=operation, arguments=arguments, assertion=assertion)
    local = owner.append("request", owner.body["localDigest"], raw)
    try:
        owner.check()
        http.custody.ControlPlaneCustodyClient.claim_public_revocation(owner.client, local)
        owner.check()
        result_raw = owner.exchange("approval", raw)[0]
        terminal = http.caller.authorization.wire._decode_object(result_raw, work=owner.work,
            maximum_bytes=4 * 1024 * 1024, maximum_nodes=65536, maximum_depth=16)
        profile.public._object(terminal, frozenset({"result", "resultDigest", "commitReceiptDigest", "witnessCommitDigest", "fence"}))
        result = terminal["result"]
        profile.public._require(type(terminal["fence"]) is int and terminal["fence"] > 0)
        for name in ("resultDigest", "commitReceiptDigest", "witnessCommitDigest"):
            http.caller.shape._digest(terminal[name])
        profile.public._require(terminal["resultDigest"] == profile.public.original_sha256(result, work=owner.work))
        profile.public._object(result, frozenset({"ok", "approval", "operation", "requestDigest", "auditEventDigest", "idempotentReplay"}))
        profile.public._require(result["ok"] is True and result["idempotentReplay"] is False
            and result["operation"] == operation and result["requestDigest"] == profile.request_digest(operation, arguments))
        row, provenance = _row(result["approval"]["id"])
        phase_digest = "requestDigest" if approval_id is None else "decisionDigest"
        profile.public._require(provenance[phase_digest] == result["requestDigest"]
            and provenance["policy"] == owner.selected_policy
            and http.db.row_to_control_plane_approval(row) == result["approval"])
        owner.append("approval-outcome", local, (result_raw,))
        owner.check()
        return {"apiVersion": "catchplate.publicWebAuthnRevocationApprovalResult/v1", "localDigest": local,
            "approval": result["approval"], "revocationExecuted": False, "automaticRetryAllowed": False}
    except Exception:
        raise HTTPException(status_code=409, detail={"error": "public_revocation_approval_outcome_unknown",
            "localDigest": local, "revocationExecuted": False, "automaticRetryAllowed": False,
            "recoveryPath": "/api/webauthn/credentials/" + record_id + "/revocation/recover"}) from None


def observe_retained(owner, record_id, local, attempted, raw):
    """Inspect the actual row; neither absence nor a row grants execution.

    This approval-only lookup does not recreate a lost writer ACK or claim a
    terminal commit. Final revocation still proves and consumes the actual row
    in its independent authenticated v5 prestate. No approval operation is
    resubmitted, even if no row is currently visible.
    """
    from catchplate import authority_transition_public_revocation_approval as kernel
    profile.public._require(type(owner) is http._Operation)
    owner.check()
    body = serving._body(raw[4], owner.work)
    values = body["arguments"]
    if (values["resource_id"] != record_id or body["actor"]["userId"] != owner.identity.user_id
            and "admin" not in owner.identity.roles):
        raise HTTPException(status_code=403, detail="approval lookup requires its current requester or an admin")
    http.caller.plan._same(raw[:3], (owner.material.current_root_enrollment_bytes,
        owner.material.grant_enrollment_bytes, owner.material.authorization_enrollment_bytes), owner.work,
        "approval lookup cannot substitute another admitted scope")
    digest = profile.request_digest(body["operation"], values)
    identifier = kernel._item_id(body["operation"], values, digest)
    observed = None
    try:
        row, provenance = _row(identifier)
    except HTTPException as exc:
        if exc.status_code != 404:
            raise
    else:
        phase = "requestDigest" if values["approval_id"] is None else "decisionDigest"
        if provenance[phase] == digest:
            profile.public._require(row["resource_id"] == record_id
                and row["action"] == profile.public.OPERATION and row["payload_digest"] == values["payload_digest"]
                and provenance["policy"] == values["mutation_policy"])
            observed = http.db.row_to_control_plane_approval(row)
    owner.check()
    return {"apiVersion": "catchplate.publicWebAuthnRevocationApprovalObservation/v1", "localDigest": local,
        "status": "approval-row-observed" if observed is not None else (
            "outcome-unknown" if attempted else "locally-unattempted"), "approval": observed,
        "committedObserved": False, "revocationExecuted": False, "automaticRetryAllowed": False}
