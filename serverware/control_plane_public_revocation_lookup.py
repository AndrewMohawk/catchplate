"""Authenticated read-only portal context and retained parent lookup.

Neither endpoint issues challenges, writes claims, contacts an effect endpoint
nor interprets a missing association as absence. A fresh lookup request has its
own read allowance; it cannot extend any expired options or writer authority.
"""
from __future__ import annotations

import hashlib

from fastapi import HTTPException

from serverware import control_plane_public_revocation as http
from serverware import authority_public_revocation_approval as approvals
from serverware import authority_public_revocation_approval_owner as approval_owner


CONTEXT_SCHEMA = "serverware.publicWebAuthnRevocationContextRequest/v1"
LOOKUP_SCHEMA = "serverware.publicWebAuthnRevocationLookupRequest/v1"


def context_on_request(request, original):
    owner = http._Operation(request, original, schema=CONTEXT_SCHEMA, fields={"apiVersion", "recordId"})
    target = None
    record_id = owner.body["recordId"]
    if record_id is not None:
        http.public._text(record_id)
        row = http.db.get_webauthn_credential_by_record_id(record_id, include_revoked=True)
        if row is None:
            raise HTTPException(status_code=404, detail="WebAuthn credential not found")
        if row["user_id"] != owner.identity.user_id and "admin" not in owner.identity.roles:
            raise HTTPException(status_code=403, detail="another operator's target requires a current administrator")
        target = {"recordId": row["id"], "userId": row["user_id"], "label": row["label"],
            "credentialIdSha256": "sha256:" + hashlib.sha256(row["credential_id"].encode("utf-8")).hexdigest(),
            "attestationRootSha256": row.get("attestation_root_sha256"), "revoked": row.get("revoked_at") is not None}
    eligible = []
    if owner.selected_policy["mfaRequired"]:
        rows = http.db.list_webauthn_credentials(owner.identity.user_id, limit=65)
        http.public._require(len(rows) <= 64,
            "revocation portal credential inventory exceeds its fixed capacity")
        for row in rows:
            owner.check()
            try:
                http.webauthn._allowed_authenticator(row, owner.selected_policy["credentialPolicy"])
            except http.webauthn.WebAuthnError:
                continue
            http.public._require(row["user_id"] == owner.identity.user_id and row.get("revoked_at") is None)
            eligible.append({"recordId": row["id"], "label": row["label"], "credentialId": row["credential_id"]})
    owner.check()
    result = {"apiVersion": "serverware.publicWebAuthnRevocationContext/v1",
        "actor": {"userId": owner.identity.user_id, "roles": sorted(owner.identity.roles), "authMethod": owner.identity.auth_method},
        "policy": owner.selected_policy, "eligibleCredentials": eligible, "target": target,
        "automaticRetryAllowed": False}
    http.public._require(len(http.public.core.canonical_bytes(result)) <= 192 * 1024,
        "revocation portal context exceeds its fixed response capacity")
    owner.check()
    return result


def lookup_on_request(request, record_id, original):
    owner = http._Operation(request, original, schema=LOOKUP_SCHEMA,
        fields={"apiVersion", "optionsLocalDigest"})
    local = owner.body["optionsLocalDigest"]
    http.caller.shape._digest(local)
    retained, child = http.custody.ControlPlaneCustodyClient.lookup_public_revocation_options(owner.client, local)
    encoded = retained.originals[1]
    value = http.caller.authorization.wire._decode_object(encoded, work=owner.work,
        maximum_bytes=4 * 1024 * 1024, maximum_nodes=65536, maximum_depth=16)
    if value.get("schema") == approvals.OPTIONS_SCHEMA:
        http.public._object(value, frozenset({"schema", "operation", "arguments", "actorId", "issuedAtEpochNs", "expiresAtEpochNs"}))
        arguments = approvals.arguments(value["operation"], value["arguments"])
        http.caller.primitives._unchanged(encoded, value, 64 * 1024, owner.work)
        target_id, actor_id = arguments["resource_id"], value["actorId"]
        http.public._require(actor_id == arguments["actor_id"])
        kind = "approval-request" if arguments["approval_id"] is None else "approval-decide"
    else:
        value = http.request_wire.decode(encoded, options=True, work=owner.work)
        arguments = http.request_wire._typed(value["request"], owner.work)
        target_id, actor_id, kind = arguments["record_id"], value["actorId"], "execute"
    if target_id != record_id or actor_id != owner.identity.user_id and "admin" not in owner.identity.roles:
        raise HTTPException(status_code=403, detail="revocation locator lookup requires its current requester or an admin")
    attempt = None
    if child is not None:
        raw = child.originals[1:]
        http.caller.plan._same(raw[:3], (owner.material.current_root_enrollment_bytes,
            owner.material.grant_enrollment_bytes, owner.material.authorization_enrollment_bytes), owner.work,
            "revocation lookup cannot substitute another admitted scope")
        if kind == "execute":
            body = http.request_wire.decode(raw[4], work=owner.work)
            http.caller.plan._same((body["request"], body["policy"], body["payloadDigest"], body["approval"]),
                (value["request"], value["policy"], value["payloadDigest"], value["approval"]), owner.work,
                "revocation retained child differs from its original options")
        else:
            body = approval_owner._body(raw[4], owner.work)
            http.caller.plan._same((body["operation"], body["arguments"]),
                (value["operation"], value["arguments"]), owner.work,
                "revocation approval child differs from its original options")
        http.public._require(body["actor"]["userId"] == actor_id)
        attempt = child.digest
    owner.check()
    return {"apiVersion": "serverware.publicWebAuthnRevocationLookup/v1", "recordId": record_id,
        "optionsLocalDigest": local, "attemptLocalDigest": attempt, "kind": kind,
        "status": "retained-association-observed" if attempt is not None else "outcome-unknown",
        "committedObserved": False, "automaticRetryAllowed": False}
