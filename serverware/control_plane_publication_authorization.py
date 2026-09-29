"""Real cold-custody publication approval ceremonies; no runtime metadata DML.

Only the dedicated publication resolver may consume/settle this authorization.
Options and decisions are fresh HTTP operations, not supplied verification DTOs.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time

from fastapi import HTTPException, Request

from serverware import authority_contract, auth, db, webauthn
from serverware import authority_publication_approval as profile
from serverware import control_plane_custody_startup as startup
from serverware.control_plane_approval_verification import _epoch_ns, _request_pin


def _purpose(name):
    profile.require(name in {"admin-token", "policy-file"})
    return profile.operation_profile(("publication-approval." if name == "admin-token" else "policy-file-approval.") + "request")


def _identity(request, purpose="admin-token"):
    profile.require(type(request) is Request and request.method == "POST" and not request.url.query)
    identity = auth.require_admin(request,
        x_serverware_admin_token=request.headers.get("X-Serverware-Admin-Token"))
    auth.validate_csrf_request(request)
    profile.require(identity.user_id.startswith("oidc:") and identity.has_any_role({_purpose(purpose).ROLE}))
    return identity


def _policy():
    from serverware import app
    supplied = app._control_plane_mutation_authn_policy()
    configured = set(supplied.get("allowedAuthenticatorClasses") or ("hardware", "yubikey"))
    allowed = sorted(configured & {"hardware", "yubikey"})
    # This new purpose is deliberately stronger than optional ordinary MFA;
    # no shared global or existing action policy is changed.
    return profile.policy({"rpId": webauthn.WEBAUTHN_RP_ID, "origins": [webauthn.WEBAUTHN_ORIGIN],
        "allowedAuthenticatorClasses": allowed, "hardwareRequired": True,
        "requireUserPresence": True, "requireUserVerification": True, "maxAssertionAgeSeconds": 120})


def _authenticator_policy(value):
    # The caller's closed requirement is not a supplied attestation result.
    # Translate only its fixed true gate for the genuine local trust verifier;
    # never relax the authority planner's forbidden-evidence input guard.
    translated = profile.policy(value)
    translated["requireHardwareAttestation"] = translated.pop("hardwareRequired")
    return translated


def _approval(approval_id, purpose="admin-token"):
    profile.require(type(approval_id) is str and len(approval_id) == 36)
    with db.connect() as connection:
        row = connection.execute("SELECT * FROM control_plane_approvals WHERE id = ?", (approval_id,)).fetchone()
    profile.require(row is not None)
    original = dict(row)
    provenance = json.loads(original["approval_authn"])
    profile.require(type(provenance) is dict and provenance.get("schema") == _purpose(purpose).PROVENANCE_SCHEMA)
    return original


def _arguments(phase, identity, bound, policy, approval_id=None, *, purpose="admin-token", publication=None):
    selected = _purpose(purpose)
    original = selected.request_binding(bound)
    if purpose == "policy-file":
        from serverware import control_plane_policy_genesis_maintenance as genesis_maintenance
        genesis_maintenance.require_binding(original, publication=publication)
    value = {"action": selected.action(original), "resource_id": selected.RESOURCE,
        "payload_digest": "sha256:" + hashlib.sha256(profile.canonical(original)).hexdigest(),
        "actor_id": identity.user_id, "request": original, "approval_id": approval_id,
        "credential_policy": policy}
    selected.arguments(selected.PREFIX + phase, value)
    return value


class _Ceremony:
    def __init__(self, request, *, deadline_ns=None, expires_epoch_ns=None, purpose="admin-token"):
        self.purpose, self.profile = purpose, _purpose(purpose)
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.request, self.scope, self.pin = request, request.scope, _request_pin(request)
        self.identity, self.policy = _identity(request, self.purpose), _policy()
        self.policy_original = profile.canonical(self.policy)
        self.mono, self.epoch = time.monotonic_ns(), time.time_ns()
        self.deadline = min(self.mono + 30_000_000_000, deadline_ns or self.mono + 30_000_000_000)
        self.expires = min(self.epoch + 30_000_000_000, expires_epoch_ns or self.epoch + 30_000_000_000)
        if purpose == "policy-file":
            from serverware import control_plane_policy_genesis_maintenance as genesis_maintenance
            self.deadline, self.expires = genesis_maintenance.clip_window(self.deadline, self.expires)
        self.custody = startup.require_started()
        profile.require(self.custody is not None, "publication approval requires genuine cold custody startup")
        self.credential = None
        self.attempted = False

    def check(self):
        mono, epoch = time.monotonic_ns(), time.time_ns()
        profile.require((os.getpid(), threading.get_ident()) == (self.pid, self.thread)
            and self.mono <= mono < self.deadline and self.epoch <= epoch < self.expires
            and self.request.scope is self.scope and _request_pin(self.request) == self.pin
            and self.profile is _purpose(self.purpose)
            and _identity(self.request, self.purpose) == self.identity and profile.canonical(_policy()) == self.policy_original
            and startup.require_started() is self.custody)
        if self.credential is not None:
            current = db.get_webauthn_credential_by_record_id(self.credential["id"])
            profile.require(type(current) is dict and current.get("revoked_at") is None
                and all(current.get(key) == self.credential.get(key) for key in ("id", "credential_id", "user_id", "public_key_cose")))
            trust = webauthn._allowed_authenticator(current, _authenticator_policy(self.policy))
            profile.require(trust["currently_trusted"] is True and trust["effective_authenticator_class"] in {"hardware", "yubikey"})
        closing_mono, closing_epoch = time.monotonic_ns(), time.time_ns()
        profile.require(mono <= closing_mono < self.deadline and epoch <= closing_epoch < self.expires)
        self.mono, self.epoch = closing_mono, closing_epoch

    def capture_assertion(self, mfa):
        self.check()
        profile.require(type(mfa) is dict and {"publicationProfile", "assertion"} <= set(mfa)
            and set(mfa) <= {"publicationProfile", "assertion", "approvalId"}
            and mfa.get("publicationProfile") == self.profile.OPTIONS_SCHEMA
            and len(profile.canonical(mfa)) <= 16 * 1024)
        assertion = mfa.get("assertion")
        profile.require(type(assertion) is dict and len(profile.canonical(assertion)) <= 16 * 1024)
        credential = db.get_webauthn_credential(assertion.get("id"))
        profile.require(type(credential) is dict and credential["user_id"] == self.identity.user_id
            and credential.get("revoked_at") is None)
        self.credential = credential
        self.check()
        # The actual crypto verifier checks the original signature and current
        # attestation policy again in its isolated role. This read only selects
        # a live stored challenge; it never marks an assertion verified/used.
        client, _ = webauthn._parse_client_data(assertion.get("response", {}).get("clientDataJSON"), "webauthn.get")
        challenge = db.get_unused_webauthn_challenge(client["challenge"],
            challenge_type="policy_authority", user_id=self.identity.user_id)
        profile.require(challenge is not None)
        self.expires = min(self.expires, _epoch_ns(challenge["expires_at"]))
        self.deadline = min(self.deadline, self.mono + self.expires - self.epoch)
        self.check()
        return {"challengeId": challenge["id"], "credentialRecordId": credential["id"], "assertion": assertion}

    def dispatch(self, phase, arguments, assertion=None):
        self.check()
        profile.require(not self.attempted)
        operation = self.profile.PREFIX + phase
        self.profile.arguments(operation, arguments)
        original = profile.canonical(arguments)
        expected_digest = self.profile.request_digest(operation, arguments)
        inputs = dict(arguments)
        if phase != "settle":
            profile.require(type(assertion) is dict)
            inputs["authn_evidence"] = assertion
        self.attempted = True
        # This concrete cold client makes one exchange and independently checks
        # signed response/commit bindings. No retry or development DML fallback.
        from serverware.control_plane_custody_client import ControlPlaneCustodyClient
        result = ControlPlaneCustodyClient._request_authority(self.custody,
            operation=operation, input_value={"schema": "serverware.policyAuthorityControlledWriterInput/v1",
                "handler": authority_contract.operation_spec(operation)["handler"],
                "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
                "arguments": inputs}, deadline_ns=self.deadline)
        self.check()
        profile.require(profile.canonical(arguments) == original and type(result) is dict
            and set(result) == {"ok", "approval", "operation", "requestDigest", "auditEventDigest", "idempotentReplay"}
            and result["ok"] is True and result["operation"] == operation and result["idempotentReplay"] is False
            and result["requestDigest"] == expected_digest)
        profile.digest(result["requestDigest"])
        profile.digest(result["auditEventDigest"])
        row = _approval(result["approval"]["id"], self.purpose)
        profile.require(db.row_to_control_plane_approval(row) == result["approval"]
            and row["action"] == arguments["action"] and row["resource_id"] == self.profile.RESOURCE
            and row["payload_digest"] == arguments["payload_digest"]
            and row["request_json"] == profile.canonical(arguments["request"]).decode("ascii"))
        self.expires = min(self.expires, _epoch_ns(row["expires_at"]))
        self.deadline = min(self.deadline, self.mono + self.expires - self.epoch)
        self.check()
        return result


def options_on_request(request, payload, *, purpose="admin-token"):
    owner = _Ceremony(request, purpose=purpose)
    selected = owner.profile
    bound = selected.request_binding(payload.request_binding)
    profile.require(payload.api_version == selected.OPTIONS_SCHEMA and payload.action == selected.action(bound)
        and payload.resource_id == selected.RESOURCE)
    approval_id = payload.approval_id
    phase = "request"
    if approval_id is not None:
        row = _approval(approval_id, purpose)
        profile.require(row["action"] == selected.action(bound) and row["resource_id"] == selected.RESOURCE
            and row["payload_digest"] == payload.payload_digest and json.loads(row["request_json"]) == bound)
        phase = "consume" if row["requester_id"] == owner.identity.user_id else "decide"
        profile.require(row["status"] == ("approved" if phase == "consume" else "pending"))
        owner.expires = min(owner.expires, _epoch_ns(row["expires_at"]))
        owner.deadline = min(owner.deadline, owner.mono + owner.expires - owner.epoch)
    arguments = _arguments(phase, owner.identity, bound, owner.policy, approval_id, purpose=purpose)
    profile.require(arguments["payload_digest"] == payload.payload_digest)
    descriptors = webauthn._credential_descriptors_for_policy(owner.identity.user_id, _authenticator_policy(owner.policy))
    profile.require(type(descriptors) is list and 1 <= len(descriptors) <= 64)
    credential = db.get_webauthn_credential(descriptors[0]["id"])
    profile.require(type(credential) is dict and credential["user_id"] == owner.identity.user_id)
    owner.credential = credential
    owner.check()
    operation = selected.PREFIX + phase
    challenge = db.issue_policy_authority_webauthn_challenge(operation=operation,
        input_value=arguments, user_id=owner.identity.user_id, credential_id=credential["credential_id"], deadline_ns=owner.deadline)
    owner.check()
    value = challenge["payload"]
    profile.require(challenge["challenge_type"] == "policy_authority" and challenge["user_id"] == owner.identity.user_id
        and challenge["used_at"] is None and value["credentialId"] == credential["credential_id"]
        and value["rpId"] == owner.policy["rpId"] and value["origin"] in owner.policy["origins"])
    profile.digest(value["operationId"])
    profile.digest(challenge["id"])
    profile.require(type(credential["id"]) is str and 1 <= len(credential["id"].encode("utf-8")) <= 256)
    owner.check()
    return {"publicKey": {"challenge": challenge["challenge"], "rpId": value["rpId"], "allowCredentials":
        [{"type": "public-key", "id": credential["credential_id"]}], "timeout": 120000, "userVerification": "required"},
        "serverware": {"schema": selected.OPTIONS_SCHEMA, "operation": operation, "operationId": value["operationId"],
            "challengeId": challenge["id"], "credentialRecordId": credential["id"],
            "payloadDigest": arguments["payload_digest"], "expiresAt": challenge["expires_at"]}}


def decide_on_request(request, approval_id, decision, *, purpose="admin-token"):
    owner = _Ceremony(request, purpose=purpose)
    row = _approval(approval_id, purpose)
    profile.require(decision is not None and decision.note is None and row["requester_id"] != owner.identity.user_id
        and row["status"] == "pending")
    assertion = owner.capture_assertion(decision.mfa)
    profile.require("approvalId" not in decision.mfa)
    arguments = _arguments("decide", owner.identity, json.loads(row["request_json"]), owner.policy, approval_id, purpose=purpose)
    return owner.dispatch("decide", arguments, assertion)["approval"]


class ResolutionAuthorization:
    """Retain the actual resolver, cold client and originals, never a verdict."""
    def __init__(self, resolution):
        from serverware.control_plane_admin_token_resolution import _Resolution
        profile.require(type(resolution) is _Resolution)
        self.resolution = resolution
        self.owner = _Ceremony(resolution.request, deadline_ns=resolution.deadline, expires_epoch_ns=resolution.expires)
        profile.require(self.owner.identity == resolution.identity)
        self.assertion = self.owner.capture_assertion(resolution.payload.mfa)
        self.original_mfa = profile.canonical(resolution.payload.mfa)
        self.original_bound = profile.canonical(resolution.bound)
        self.consumption = None
        self.settlement_attempted = False
        resolution.credential = tuple(self.owner.credential[key] for key in ("id", "user_id", "credential_id", "public_key_cose"))

    def check_current(self):
        self.owner.check()
        profile.require(profile.canonical(self.resolution.payload.mfa) == self.original_mfa
            and profile.canonical(self.resolution.bound) == self.original_bound)

    def negotiate(self):
        from serverware import app
        approval_id = app._control_plane_approval_id(self.resolution.payload.mfa)
        if approval_id is not None:
            row = _approval(approval_id)
            profile.require(row["requester_id"] == self.owner.identity.user_id and row["status"] == "approved"
                and row["payload_digest"] == self.resolution.payload_digest
                and row["request_json"] == self.original_bound.decode("ascii"))
            self.approval_id = approval_id
            self.owner.expires = min(self.owner.expires, _epoch_ns(row["expires_at"]))
            self.owner.deadline = min(self.owner.deadline, self.owner.mono + self.owner.expires - self.owner.epoch)
            self.check_current()
            return
        result = self.owner.dispatch("request", _arguments("request", self.owner.identity,
            self.resolution.bound, self.owner.policy), self.assertion)
        row = result["approval"]
        raise HTTPException(status_code=428, detail={"error": "control_plane_approval_required", "approvalId": row["id"],
            "status": row["status"], "action": profile.ACTION, "resourceId": profile.RESOURCE,
            "payloadDigest": row["payload_digest"], "expiresAt": row["expires_at"], "retry": {"mfa.approvalId": row["id"]}})

    def consume(self):
        self.resolution.check()
        profile.require(self.resolution.claimed and self.consumption is None)
        result = self.owner.dispatch("consume", _arguments("consume", self.owner.identity,
            self.resolution.bound, self.owner.policy, self.approval_id), self.assertion)
        profile.require(result["approval"]["status"] == "consumed")
        self.consumption = result
        self.resolution.expires = min(self.resolution.expires, self.owner.expires)
        self.resolution.deadline = min(self.resolution.deadline, self.owner.deadline)
        return result

    def consume_request_digest(self):
        self.check_current()
        return profile.request_digest(profile.PREFIX + "consume", _arguments("consume", self.owner.identity,
            self.resolution.bound, self.owner.policy, self.approval_id))

    @staticmethod
    def audit_id(phase, request_digest):
        from serverware.authority_transition_quota import _audit_identity
        return _audit_identity(profile.PREFIX + phase, request_digest)

    def settle(self):
        self.resolution.check()
        profile.require(self.consumption is not None and not self.settlement_attempted and self.resolution.authorized)
        self.settlement_attempted = True
        item = self.resolution.history[self.resolution.attempt]
        completion = item["resolution-completeSha256"]
        profile.require(item["resolution-complete"]["outcome"] == self.resolution.payload.outcome)
        # Separate fresh caller operation, but NEVER a new allowance. It owns
        # the same actual request/cold client and inherits the narrowed window.
        settlement = _Ceremony(self.resolution.request, deadline_ns=self.owner.deadline, expires_epoch_ns=self.owner.expires)
        values = _arguments("consume", self.owner.identity, self.resolution.bound, self.owner.policy, self.approval_id)
        values.pop("credential_policy")
        values.update(consumption_request_digest=self.consumption["requestDigest"], completion_sha256=completion)
        return settlement.dispatch("settle", values)
