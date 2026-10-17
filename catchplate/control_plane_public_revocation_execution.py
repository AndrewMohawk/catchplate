"""One live public request consumes its actual durable claim exactly once.

Prepared results and locators are independently replayed before downstream
effects. SQL observations never manufacture completion. Interrupted callers
retain their local identity; only the separate original-byte recovery reader
can later establish the committed terminal result. No path resumes execution.
"""
from __future__ import annotations

from fastapi import HTTPException

from catchplate import control_plane_public_revocation as http
from catchplate import authority_public_revocation_execution as effects
from catchplate import authority_public_revocation_recovery_authorization as recovery


def _response(owner, local_digest, result):
    from catchplate import app
    http.public._require(type(result) is dict and result.get("ok") is True
        and type(result.get("credential")) is dict)
    owner.check()
    return {"apiVersion": "catchplate.publicWebAuthnRevocationResult/v1", "status": "committed-observed",
        "localDigest": local_digest, "ok": True, "credential": app._redacted_webauthn_credential(result["credential"]),
        "revokedGrantCount": result["revoked_grant_count"],
        "revokedControlPlaneApprovalCount": result["revoked_control_plane_approval_count"],
        "revokedOidcBrowserSessionCount": result["revoked_oidc_browser_session_count"],
        "invalidatedRegistrationChallengeCount": result["invalidated_registration_challenge_count"],
        "automaticRetryAllowed": False}


def _read_authorization(owner, raw):
    authorization_digest = http.caller.plan._frame(http.caller.REQUEST_IDENTITY_DOMAIN, (raw[3],), owner.work)
    return recovery.sign_on_owner(owner.owner, actor=owner.actor,
        request_authorization_digest=authorization_digest,
        pending_decision_digest=raw[15].decode("ascii"), packet_digest=raw[16].decode("ascii"),
        live_window=owner.window, transport_deadline_ns=owner.deadline, work=owner.work)


def execute_on_request(request, record_id, original):
    owner = http._Operation(request, original, schema=http.EXECUTE_SCHEMA,
        fields={"apiVersion", "localDigest", "reason", "mfa"})
    http.caller.shape._digest(owner.body["localDigest"])
    retained = http.custody.ControlPlaneCustodyClient.load_public_revocation_options(
        owner.client, owner.body["localDigest"])
    options = http.request_wire.decode(retained.originals[1], options=True, work=owner.work)
    owner.narrow(options["expiresAtEpochNs"])
    typed = options["request"]
    arguments = http.request_wire._typed(typed, owner.work)
    http.public._require(options["actorId"] == owner.identity.user_id
        and arguments["record_id"] == record_id and arguments["reason"] == owner.body["reason"])
    http.caller.plan._same(options["policy"], owner.selected_policy, owner.work,
        "public revocation original policy changed after options")
    http._target(owner, record_id)
    mfa = owner.body["mfa"]
    assertion = None
    if owner.selected_policy["mfaRequired"]:
        http.public._object(mfa, frozenset({"authorityChallengeId", "credentialRecordId", "assertion"}))
        assertion = mfa
    else:
        http.public._require(mfa is None)
    request_original = http.request_wire.encode({"schema": http.request_wire.SCHEMA,
        "request": typed, "actor": owner.actor, "policy": options["policy"],
        "payloadDigest": options["payloadDigest"], "approval": options["approval"],
        "assertion": assertion}, work=owner.work)
    raw = owner.sign_request(request_original, typed)
    local = owner.append("request", owner.body["localDigest"], raw)
    try:
        owner.check()
        http.custody.ControlPlaneCustodyClient.claim_public_revocation(owner.client, local)
        owner.check()
        prepared = owner.exchange("prepare", raw)
        http.preparation.verify_prepared(**owner.configuration, originals=raw, prepared=prepared,
            live_window=owner.window, transport_deadline_ns=owner.deadline, work=owner.work)
        owner.append("prepared", local, prepared)
        grant = owner.exchange("grant", (*raw, *prepared))[0]
        owner.append("grant", local, (grant,))
        computed = owner.exchange("compute", (*raw, *prepared, grant))
        owner.append("computed", local, computed)
        receipt = owner.exchange("reserve", (*raw, *prepared, grant, *computed))[0]
        reserved = (*computed, receipt)
        owner.append("reserved", local, reserved)
        locators = effects.packet_locators(configuration=owner.configuration, originals=raw,
            prepared=prepared, grant=grant, reserved=reserved, live_window=owner.window,
            transport_deadline_ns=owner.deadline, work=owner.work)
        owner.append("execution-locators", local, locators)
        prefix = (*raw, *prepared, grant, *reserved)
        issued = owner.exchange("issue", prefix)
        http.caller.plan._same(issued, locators, owner.work,
            "actual issuer returned another original packet association")
        executable = (*prefix, *locators)
        read = _read_authorization(owner, executable)
        owner.begin_execution()
        observation = owner.exchange("execute", executable)
        owner.append("sql-outcome", local, observation)
        # Even a direct, observed COMMIT is not the public terminal answer.
        # Separate restricted readback and authenticated completion originals
        # must establish the exact result under the original request window.
        completed = owner.exchange("complete", (*executable, read))
        result = effects.verify_completion(configuration=owner.configuration, raw=executable,
            returned=completed, live_window=owner.window, transport_deadline_ns=owner.deadline, work=owner.work)
        owner.append("completion", local, completed)
        return _response(owner, local, result)
    except Exception:
        # This includes definite local refusals and uncertain external effects.
        # Neither exception text nor unsigned SQL status proves noncommit.
        raise HTTPException(status_code=409, detail={"error": "public_revocation_outcome_unknown",
            "localDigest": local, "status": "outcome-unknown", "automaticRetryAllowed": False,
            "recoveryPath": "/api/webauthn/credentials/" + record_id + "/revocation/recover"}) from None


def recover_on_request(request, record_id, original):
    owner = http._Operation(request, original, schema=http.RECOVERY_SCHEMA,
        fields={"apiVersion", "localDigest"})
    local = owner.body["localDigest"]
    http.caller.shape._digest(local)
    attempted, retained = http.custody.ControlPlaneCustodyClient.load_public_revocation(owner.client, local)
    records = {kind: value.originals[1:] for kind, value in retained}
    raw = records["request"]
    from catchplate import authority_public_revocation_approval_owner as approval_owner
    decoded = http.caller.authorization.wire._decode_object(raw[4], work=owner.work,
        maximum_bytes=4 * 1024 * 1024, maximum_nodes=65536, maximum_depth=16)
    if decoded.get("schema") == approval_owner.BODY_SCHEMA:
        from catchplate import control_plane_public_revocation_approval as approvals
        return approvals.observe_retained(owner, record_id, local, attempted, raw)
    body = http.request_wire.decode(raw[4], work=owner.work)
    arguments = http.request_wire._typed(body["request"], owner.work)
    if (arguments["record_id"] != record_id
            or body["actor"]["userId"] != owner.identity.user_id and "admin" not in owner.identity.roles):
        raise HTTPException(status_code=403, detail="revocation recovery requires its current requester or an admin")
    http.caller.plan._same(raw[:3], (owner.material.current_root_enrollment_bytes,
        owner.material.grant_enrollment_bytes, owner.material.authorization_enrollment_bytes), owner.work,
        "public revocation recovery cannot substitute another admitted scope")
    owner.check()
    required = {"prepared", "grant", "reserved", "execution-locators"}
    if not attempted or not required <= records.keys():
        # This is a local observation only. Missing response association is
        # never evidence of remote absence and cannot resume any prior phase.
        return {"apiVersion": "catchplate.publicWebAuthnRevocationObservation/v1", "localDigest": local,
            "status": "outcome-unknown" if attempted else "locally-unattempted",
            "committedObserved": False, "automaticRetryAllowed": False}
    executable = (*raw, *records["prepared"], *records["grant"], *records["reserved"], *records["execution-locators"])
    try:
        if "completion" in records:
            completed = records["completion"]
        else:
            read = _read_authorization(owner, executable)
            completed = owner.exchange("recover", (*executable, read))
        result = effects.verify_completion(configuration=owner.configuration, raw=executable,
            returned=completed, live_window=owner.window, transport_deadline_ns=owner.deadline, work=owner.work)
        if "completion" not in records:
            owner.append("completion", local, completed)
        return _response(owner, local, result)
    except Exception:
        raise HTTPException(status_code=409, detail={"error": "public_revocation_recovery_unresolved",
            "localDigest": local, "status": "outcome-unknown", "automaticRetryAllowed": False}) from None
