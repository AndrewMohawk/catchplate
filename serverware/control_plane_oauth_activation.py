"""Purpose-controlled OAuth activation ceremonies under the actual cold owner.

No token plaintext, credential DML, standalone approval consumption or retry is
exposed here. The authority independently admits the enrollment original and
commits approval, credential, generation, pending removal and audit together.
"""
from __future__ import annotations

import base64
import json
import os
import threading
import time

from fastapi import HTTPException, Request

from serverware import auth, authority_contract, db, oauth, webauthn
from serverware import authority_oauth_activation as profile
from serverware import oauth_application_owner as applications
from serverware.control_plane_approval_verification import _epoch_ns, _request_pin


ORIGINAL_SCHEMA = "serverware.oauthActivationOriginal/v1"
MFA_FIELD = "oauthActivationProfile"
_PROVENANCE_FIELDS = frozenset({"schema", "requestDigest", "requestEvidenceDigest", "credentialPolicy",
    "decisionDigest", "decisionEvidenceDigest", "consumptionDigest", "consumptionEvidenceDigest"})
_APPROVAL_FIELDS = frozenset({"id", "action", "resource_id", "payload_digest", "status", "requester_id",
    "requested_at", "expires_at", "approved_by", "approved_at", "consumed_by", "consumed_at",
    "decision_note", "approver_webauthn_credential_id", "request"})
_CREDENTIAL_FIELDS = frozenset({"id", "name", "kind", "secret_kek_id", "credential_version", "secret_updated_at",
    "metadata", "lifecycle_status", "revocation_error", "revocation_requested_at", "created_at", "updated_at"})


def selected():
    """Only independently cold-selected ownership selects this HTTP profile."""
    return applications.require_started() is not None


def _identity(request, *, inspection=False):
    profile.require(type(request) is Request and request.method == ("GET" if inspection else "POST")
        and not request.url.query)
    identity = auth.require_admin(request,
        x_serverware_admin_token=request.headers.get("X-Serverware-Admin-Token"))
    auth.validate_csrf_request(request)
    # AdminIdentity.has_any_role includes an admin override; this new purpose
    # deliberately requires the actual credential_owner role for both people.
    profile.require(identity.user_id.startswith("oidc:") and "credential_owner" in identity.roles)
    return identity


def _policy():
    from serverware import app
    configured = app._control_plane_mutation_authn_policy()
    allowed = sorted(set(configured.get("allowedAuthenticatorClasses") or ("hardware", "yubikey"))
        & {"hardware", "yubikey"})
    return profile.policy({"rpId": webauthn.WEBAUTHN_RP_ID, "origins": [webauthn.WEBAUTHN_ORIGIN],
        "allowedAuthenticatorClasses": allowed, "hardwareRequired": True,
        "requireUserPresence": True, "requireUserVerification": True, "maxAssertionAgeSeconds": 120})


def _authenticator_policy(value):
    result = profile.policy(value)
    result["requireHardwareAttestation"] = result.pop("hardwareRequired")
    return result


def _mapping(original, maximum):
    profile.require(type(original) is str and len(original.encode("utf-8")) <= maximum)
    def pairs(items):
        result = {}
        for key, value in items:
            profile.require(key not in result)
            result[key] = value
        return result
    value = json.loads(original, object_pairs_hook=pairs)
    profile.require(type(value) is dict and profile.canonical(value).decode("ascii") == original)
    return value


def _pending(item_id):
    profile.require(type(item_id) is str and 1 <= len(item_id.encode("utf-8")) <= 256)
    # The legacy convenience getter expires rows. This profile only observes;
    # all lifecycle mutations belong to the fixed controlled writer.
    with db.connect() as connection:
        row = connection.execute("SELECT * FROM pending_oauth_credentials WHERE id = ?", (item_id,)).fetchone()
        setup = connection.execute("SELECT id FROM setup_sessions WHERE oauth_pending_credential_id = ? LIMIT 1",
            (item_id,)).fetchone()
    profile.require(row is not None and setup is None)
    value = dict(row)
    original = profile.pending_original(value)
    profile.require(len(original) <= 1024 * 1024 and value["id"] == item_id and value["status"] == "pending"
        and value["kind"] == "oauth2" and value["target_credential_id"] is None
        and value["target_credential_version"] is None)
    metadata = _mapping(value["metadata"], 16 * 1024)
    review = _mapping(value["review_json"], 16 * 1024)
    provider, subject, _ = db.validate_managed_oauth_account_identity(metadata)
    db._validate_oauth_activation_review(review=review, metadata=metadata, name=value["name"], kind=value["kind"],
        provider_id=provider, provider_subject=subject, target_credential_id=None, target_credential_version=None)
    return value, original, metadata, review


def _approval(item_id):
    profile.require(type(item_id) is str and 1 <= len(item_id) <= 64)
    with db.connect() as connection:
        row = connection.execute("SELECT * FROM control_plane_approvals WHERE id = ?", (item_id,)).fetchone()
    profile.require(row is not None)
    value = dict(row)
    provenance = _mapping(value["approval_authn"], 16 * 1024)
    profile.require(set(provenance) == _PROVENANCE_FIELDS and provenance["schema"] == profile.PROVENANCE_SCHEMA)
    profile.policy(provenance["credentialPolicy"])
    for field in ("requestDigest", "requestEvidenceDigest"):
        profile.digest(provenance[field])
    for phase in ("decision", "consumption"):
        digest, evidence = provenance[phase + "Digest"], provenance[phase + "EvidenceDigest"]
        profile.require((digest is None) == (evidence is None))
        if digest is not None:
            profile.digest(digest)
            profile.digest(evidence)
    return value


class _Ceremony:
    def __init__(self, request, pending_id, *, inspection=False):
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.mono, self.epoch = time.monotonic_ns(), time.time_ns()
        self.deadline, self.expires = self.mono + 30_000_000_000, self.epoch + 30_000_000_000
        self.inspection = inspection
        self.request, self.scope, self.pin = request, request.scope, _request_pin(request)
        self.identity, self.policy = _identity(request, inspection=inspection), _policy()
        self.policy_original = profile.canonical(self.policy)
        self.pending, self.pending_original, self.metadata, self.review = _pending(pending_id)
        self.application = oauth.require_application_metadata(self.metadata)
        profile.require(self.application is not None)
        self.custody = self.application.custody_owner()
        self.enrollment = self.application.enrollment_original()
        self.enrollment_encoded = base64.urlsafe_b64encode(self.enrollment).rstrip(b"=").decode("ascii")
        association = self.application.association()
        self.bound = profile.request_binding({"pendingCredentialId": pending_id,
            "pendingRowSha256": profile.pending_digest(self.pending),
            "enrollmentSha256": association["enrollmentSha256"], "payloadDigest": self.pending["payload_digest"]})
        self.bound_original = profile.canonical(self.bound)
        self.deadline = min(self.deadline, self.application.deadline_ns)
        self.expires = min(self.expires, self.application.expires_ns, _epoch_ns(self.pending["expires_at"]))
        self.deadline = min(self.deadline, self.mono + self.expires - self.epoch)
        self.credential, self.attempted, self.poisoned = None, False, False
        self.mfa, self.mfa_original = None, None
        self.check()

    def __copy__(self):
        raise ValueError("OAuth ceremony cannot be copied")

    def __deepcopy__(self, memo):
        raise ValueError("OAuth ceremony cannot be copied")

    def check(self):
        try:
            mono, epoch = time.monotonic_ns(), time.time_ns()
            profile.require(not self.poisoned and (os.getpid(), threading.get_ident()) == (self.pid, self.thread)
                and self.mono <= mono < self.deadline and self.epoch <= epoch < self.expires
                and self.request.scope is self.scope and _request_pin(self.request) == self.pin
                and _identity(self.request, inspection=self.inspection) == self.identity
                and profile.canonical(_policy()) == self.policy_original
                and profile.pending_original(self.pending) == self.pending_original
                and profile.canonical(self.bound) == self.bound_original)
            self.application.check()
            profile.require(self.application.custody_owner() is self.custody
                and self.application.enrollment_original() == self.enrollment)
            if self.mfa_original is not None:
                profile.require(profile.canonical(self.mfa) == self.mfa_original)
            if self.credential is not None:
                current = db.get_webauthn_credential_by_record_id(self.credential["id"])
                profile.require(type(current) is dict and current.get("revoked_at") is None
                    and all(current.get(key) == self.credential.get(key)
                        for key in ("id", "credential_id", "user_id", "public_key_cose")))
                trust = webauthn._allowed_authenticator(current, _authenticator_policy(self.policy))
                profile.require(trust["currently_trusted"] is True
                    and trust["effective_authenticator_class"] in {"hardware", "yubikey"})
            closing_mono, closing_epoch = time.monotonic_ns(), time.time_ns()
            profile.require(mono <= closing_mono < self.deadline and epoch <= closing_epoch < self.expires)
            self.mono, self.epoch = closing_mono, closing_epoch
        except BaseException:
            self.poisoned = True
            raise

    def current_pending(self):
        self.check()
        _, original, _, _ = _pending(self.pending["id"])
        profile.require(original == self.pending_original)
        self.check()

    def bind_approval(self, approval_id, *, phase):
        self.check()
        row = _approval(approval_id)
        self.require_approval(row)
        if phase == "decide":
            profile.require(row["status"] == "pending" and row["requester_id"] != self.identity.user_id)
        else:
            profile.require(phase == "activate" and row["status"] == "approved"
                and row["requester_id"] == self.identity.user_id and row["approved_by"] not in (None, self.identity.user_id))
        self.expires = min(self.expires, _epoch_ns(row["expires_at"]))
        self.deadline = min(self.deadline, self.mono + self.expires - self.epoch)
        self.check()
        return row

    def require_approval(self, row):
        self.check()
        provenance = _mapping(row["approval_authn"], 16 * 1024)
        profile.require(row["action"] == profile.ACTION and row["resource_id"] == self.pending["id"]
            and row["payload_digest"] == self.pending["payload_digest"]
            and row["request_json"] == self.bound_original.decode("ascii")
            and row["requester_id"] == self.pending["requester_id"]
            and row["decision_note"] is None and provenance["credentialPolicy"] == self.policy)
        self.check()

    def arguments(self, operation, approval_id):
        self.check()
        values = {"action": profile.ACTION, "resource_id": self.pending["id"],
            "payload_digest": self.pending["payload_digest"], "actor_id": self.identity.user_id,
            "request": dict(self.bound), "approval_id": approval_id, "credential_policy": dict(self.policy),
            "enrollment_original": self.enrollment_encoded}
        profile.arguments(operation, values)
        return values

    def capture_assertion(self, mfa, *, approval_id):
        self.check()
        expected = {MFA_FIELD, "assertion"} | ({"approvalId"} if approval_id is not None else set())
        profile.require(type(mfa) is dict and set(mfa) == expected and mfa.get(MFA_FIELD) == profile.OPTIONS_SCHEMA
            and (approval_id is None or mfa["approvalId"] == approval_id)
            and len(profile.canonical(mfa)) <= 16 * 1024)
        self.mfa, self.mfa_original = mfa, profile.canonical(mfa)
        assertion = mfa["assertion"]
        profile.require(type(assertion) is dict)
        credential = db.get_webauthn_credential(assertion.get("id"))
        profile.require(type(credential) is dict and credential["user_id"] == self.identity.user_id
            and credential.get("revoked_at") is None)
        self.credential = credential
        self.check()
        client, _ = webauthn._parse_client_data(assertion.get("response", {}).get("clientDataJSON"), "webauthn.get")
        challenge = db.get_unused_webauthn_challenge(client["challenge"],
            challenge_type="policy_authority", user_id=self.identity.user_id)
        profile.require(challenge is not None)
        self.expires = min(self.expires, _epoch_ns(challenge["expires_at"]))
        self.deadline = min(self.deadline, self.mono + self.expires - self.epoch)
        self.check()
        return {"challengeId": challenge["id"], "credentialRecordId": credential["id"], "assertion": assertion}

    def dispatch(self, operation, arguments, evidence):
        self.current_pending()
        profile.require(not self.attempted and operation in {profile.OP_REQUEST, profile.OP_DECIDE, profile.OP_ACTIVATE})
        original = profile.canonical(arguments)
        expected_digest = profile.request_digest(operation, arguments)
        self.attempted = True
        from serverware.control_plane_custody_client import ControlPlaneCustodyClient
        result = ControlPlaneCustodyClient._request_authority(self.custody, operation=operation,
            input_value={"schema": "serverware.policyAuthorityControlledWriterInput/v1",
                "handler": authority_contract.operation_spec(operation)["handler"],
                "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
                "arguments": {**arguments, "authn_evidence": evidence}}, deadline_ns=self.deadline)
        self.check()
        fields = {"ok", "approval", "operation", "requestDigest", "auditEventDigest", "idempotentReplay"}
        if operation == profile.OP_ACTIVATE:
            fields.add("credential")
        profile.require(profile.canonical(arguments) == original and type(result) is dict and set(result) == fields
            and result["ok"] is True and result["operation"] == operation
            and result["requestDigest"] == expected_digest and result["idempotentReplay"] is False
            and type(result["approval"]) is dict and set(result["approval"]) == _APPROVAL_FIELDS)
        profile.digest(result["auditEventDigest"])
        if operation == profile.OP_ACTIVATE:
            credential = result["credential"]
            profile.require(type(credential) is dict and set(credential) == _CREDENTIAL_FIELDS
                and credential["id"] == self.pending["id"] and credential["kind"] == "oauth2"
                and type(credential["credential_version"]) is int and credential["credential_version"] == 1
                and credential["lifecycle_status"] == "active")
        return result


def inspect_on_request(request, pending_id):
    owner = _Ceremony(request, pending_id, inspection=True)
    owner.current_pending()
    return {"apiVersion": ORIGINAL_SCHEMA, "action": profile.ACTION, "resourceId": pending_id,
        "payloadDigest": owner.pending["payload_digest"], "request": dict(owner.bound),
        "review": dict(owner.review), "requesterId": owner.pending["requester_id"],
        "expiresAt": owner.pending["expires_at"]}


def options_on_request(request, payload):
    owner = _Ceremony(request, payload.resource_id)
    profile.require(payload.api_version == profile.OPTIONS_SCHEMA and payload.action == profile.ACTION
        and payload.payload_digest == owner.pending["payload_digest"]
        and profile.canonical(profile.request_binding(payload.request_binding)) == owner.bound_original)
    approval_id, operation = payload.approval_id, profile.OP_REQUEST
    if approval_id is None:
        profile.require(owner.pending["requester_id"] == owner.identity.user_id)
    else:
        row = _approval(approval_id)
        phase = "activate" if row["requester_id"] == owner.identity.user_id else "decide"
        owner.bind_approval(approval_id, phase=phase)
        operation = profile.OP_ACTIVATE if phase == "activate" else profile.OP_DECIDE
    arguments = owner.arguments(operation, approval_id)
    descriptors = webauthn._credential_descriptors_for_policy(owner.identity.user_id, _authenticator_policy(owner.policy))
    profile.require(type(descriptors) is list and 1 <= len(descriptors) <= 64)
    owner.credential = db.get_webauthn_credential(descriptors[0]["id"])
    profile.require(type(owner.credential) is dict and owner.credential["user_id"] == owner.identity.user_id)
    owner.current_pending()
    challenge = db.issue_policy_authority_webauthn_challenge(operation=operation, input_value=arguments,
        user_id=owner.identity.user_id, credential_id=owner.credential["credential_id"], deadline_ns=owner.deadline)
    owner.current_pending()
    value = challenge["payload"]
    profile.require(challenge["challenge_type"] == "policy_authority" and challenge["user_id"] == owner.identity.user_id
        and challenge["used_at"] is None and value["credentialId"] == owner.credential["credential_id"]
        and value["rpId"] == owner.policy["rpId"] and value["origin"] in owner.policy["origins"])
    profile.digest(value["operationId"])
    profile.digest(challenge["id"])
    profile.require(type(owner.credential["id"]) is str and 1 <= len(owner.credential["id"].encode("utf-8")) <= 256)
    owner.check()
    return {"publicKey": {"challenge": challenge["challenge"], "rpId": value["rpId"], "allowCredentials":
        [{"type": "public-key", "id": owner.credential["credential_id"]}], "timeout": 120000, "userVerification": "required"},
        "serverware": {"schema": profile.OPTIONS_SCHEMA, "operation": operation, "operationId": value["operationId"],
            "challengeId": challenge["id"], "credentialRecordId": owner.credential["id"],
            "payloadDigest": owner.pending["payload_digest"], "expiresAt": challenge["expires_at"]}}


def decide_on_request(request, approval_id, decision):
    row = _approval(approval_id)
    owner = _Ceremony(request, row["resource_id"])
    profile.require(decision is not None and decision.note is None)
    owner.bind_approval(approval_id, phase="decide")
    evidence = owner.capture_assertion(decision.mfa, approval_id=None)
    result = owner.dispatch(profile.OP_DECIDE, owner.arguments(profile.OP_DECIDE, approval_id), evidence)
    owner.current_pending()
    current = _approval(approval_id)
    owner.require_approval(current)
    profile.require(current["status"] == "approved" and current["approved_by"] == owner.identity.user_id
        and db.row_to_control_plane_approval(current) == result["approval"])
    owner.check()
    return result["approval"]


def activate_on_request(request, pending_id, payload):
    profile.require(payload.setup_session_id is None and payload.setup_revision is None)
    owner = _Ceremony(request, pending_id)
    profile.require(owner.pending["requester_id"] == owner.identity.user_id and type(payload.mfa) is dict)
    approval_id = payload.mfa.get("approvalId")
    if approval_id is None:
        evidence = owner.capture_assertion(payload.mfa, approval_id=None)
        result = owner.dispatch(profile.OP_REQUEST, owner.arguments(profile.OP_REQUEST, None), evidence)
        owner.current_pending()
        row = _approval(result["approval"]["id"])
        owner.require_approval(row)
        profile.require(row["status"] == "pending" and row["requester_id"] == owner.identity.user_id
            and db.row_to_control_plane_approval(row) == result["approval"])
        owner.check()
        raise HTTPException(status_code=428, detail={"error": "control_plane_approval_required", "approvalId": row["id"],
            "status": row["status"], "action": profile.ACTION, "resourceId": pending_id,
            "payloadDigest": row["payload_digest"], "expiresAt": row["expires_at"], "retry": {"mfa.approvalId": row["id"]}})
    owner.bind_approval(approval_id, phase="activate")
    evidence = owner.capture_assertion(payload.mfa, approval_id=approval_id)
    result = owner.dispatch(profile.OP_ACTIVATE, owner.arguments(profile.OP_ACTIVATE, approval_id), evidence)
    # A definite signed response is independently checked against the exact
    # committed public result. No plaintext is decrypted or returned.
    with db.connect() as connection:
        pending = connection.execute("SELECT id FROM pending_oauth_credentials WHERE id = ?", (pending_id,)).fetchone()
        credential = connection.execute("SELECT * FROM credentials WHERE id = ?", (pending_id,)).fetchone()
    approval = _approval(approval_id)
    owner.require_approval(approval)
    profile.require(pending is None and credential is not None and approval["status"] == "consumed"
        and approval["consumed_by"] == owner.identity.user_id
        and db.row_to_credential(credential) == result["credential"]
        and db.row_to_control_plane_approval(approval) == result["approval"])
    owner.check()
    from serverware import runtime
    runtime.invalidate_secret_leases(pending_id)
    owner.check()
    return {"ok": True, "credential": result["credential"], "approval": result["approval"]}
